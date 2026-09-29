//! Specification-derived instruction transformations. No LLVM backend is linked.
//! The supported instruction class is deliberately narrow; unsupported residual
//! operations or architectural writes fail closed instead of being discarded.
use frontend::{TirFrontend, adapters::asl::AslFrontend};
use num_bigint::BigUint;
use num_traits::{Num, ToPrimitive};
use serde::{Deserialize, Serialize};
use specializer::specializer::KnownState;
use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
};
use tir::{module::Module, primitives::Primitive, syntax::*};

type Result<T> = std::result::Result<T, String>;
const CLASSES: &[&str] = &[
    "decode_aarch64_integer_arithmetic_add_sub_immediate",
    "decode_aarch64_integer_arithmetic_add_sub_shiftedreg",
    "decode_aarch64_integer_conditional_select",
    "decode_aarch64_integer_logical_immediate",
    "decode_aarch64_integer_shift_variable",
    "decode_aarch64_integer_bitfield",
];
const MAX_BITS: u32 = 128;

// Module's name tables are HashMaps. Store them in a stable order so preparing
// the same pinned specification twice produces the same cache bytes.
#[derive(Serialize, Deserialize)]
struct PreparedModule {
    entries: Vec<Decl<TypedMeta>>,
    names: BTreeMap<u32, String>,
    base_hints: BTreeMap<u32, String>,
    next_var: u32,
    arch: Option<std::sync::Arc<tir::arch::ArchProfile>>,
}
impl From<Module<TypedMeta>> for PreparedModule {
    fn from(module: Module<TypedMeta>) -> Self {
        let Module {
            entries,
            names,
            base_hints,
            next_var,
            arch,
        } = module;
        Self {
            entries,
            names: names
                .iter()
                .map(|(id, name)| (id.as_u32(), name.clone()))
                .collect(),
            base_hints: base_hints
                .iter()
                .map(|(id, name)| (id.as_u32(), name.clone()))
                .collect(),
            next_var,
            arch,
        }
    }
}
impl From<PreparedModule> for Module<TypedMeta> {
    fn from(module: PreparedModule) -> Self {
        Self {
            entries: module.entries,
            names: std::sync::Arc::new(
                module
                    .names
                    .into_iter()
                    .map(|(id, name)| (VarId::from_u32(id), name))
                    .collect(),
            ),
            base_hints: std::sync::Arc::new(
                module
                    .base_hints
                    .into_iter()
                    .map(|(id, name)| (VarId::from_u32(id), name))
                    .collect(),
            ),
            next_var: module.next_var,
            arch: module.arch,
        }
    }
}

#[derive(Clone, PartialEq, Serialize)]
struct Expression {
    bits: u32,
    #[serde(flatten)]
    node: Node,
}
#[derive(Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Node {
    Constant {
        value: String,
    },
    Register {
        name: String,
    },
    Binary {
        op: &'static str,
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Unary {
        op: &'static str,
        value: Box<Expression>,
    },
    Concat {
        high: Box<Expression>,
        low: Box<Expression>,
    },
    Slice {
        value: Box<Expression>,
        start: u32,
    },
    Ite {
        condition: Box<Expression>,
        then_value: Box<Expression>,
        else_value: Box<Expression>,
    },
}
fn constant(bits: u32, value: BigUint) -> Result<Expression> {
    if !(1..=MAX_BITS).contains(&bits) || value.bits() > u64::from(bits) {
        return Err("invalid bitvector constant".into());
    }
    Ok(Expression {
        bits,
        node: Node::Constant {
            value: format!("0x{value:x}"),
        },
    })
}
fn literal_u64(expression: &TypedExpr) -> Result<u64> {
    match &expression.kind {
        ExprKind::Lit(Lit::Int(n)) => n.to_u64().ok_or("integer out of range".into()),
        _ => Err("expected a constant integer".into()),
    }
}
fn width(typ: &TypedTyp) -> Result<u32> {
    let n = match typ {
        TypBase::Bool => 1,
        TypBase::Bits(n) => literal_u64(n)?,
        _ => return Err("expected a fixed-width scalar type".into()),
    };
    if n == 0 || n > u64::from(MAX_BITS) {
        return Err("unsupported scalar width".into());
    }
    Ok(n as u32)
}

#[derive(Clone)]
enum Value {
    Input(Vec<String>),
    Record(Box<Value>, BTreeMap<String, Value>),
    Array(Box<Value>, BTreeMap<u64, Value>),
    Scalar(Expression),
    Integer(u64),
}

fn replicate(value: Expression, count: u64) -> Result<Expression> {
    let count = u32::try_from(count).map_err(|_| "invalid bit replication")?;
    if count == 0
        || value
            .bits
            .checked_mul(count)
            .is_none_or(|bits| bits > MAX_BITS)
    {
        return Err("invalid bit replication".into());
    }
    fn balanced(value: &Expression, count: u32) -> Expression {
        if count == 1 {
            return value.clone();
        }
        let low_count = count / 2;
        let high_count = count - low_count;
        let high = balanced(value, high_count);
        let low = balanced(value, low_count);
        Expression {
            bits: high.bits + low.bits,
            node: Node::Concat {
                high: Box::new(high),
                low: Box::new(low),
            },
        }
    }
    Ok(balanced(&value, count))
}
fn scalar(value: Value) -> Result<Expression> {
    match value {
        Value::Scalar(e) => Ok(e),
        _ => Err("expected scalar residual".into()),
    }
}
fn integer(value: Value) -> Result<u64> {
    match value {
        Value::Integer(i) => Ok(i),
        _ => Err("dynamic integer is unsupported".into()),
    }
}
fn register(path: &[String], bits: u32) -> Result<Expression> {
    let name = match path {
        [field, index] if field == "_R" => {
            let n: u32 = index.parse().map_err(|_| "invalid register index")?;
            if n > 30 || bits != 64 {
                return Err("unsupported general register".into());
            }
            format!("X{n}")
        }
        [field, flag]
            if field == "PSTATE" && ["N", "Z", "C", "V"].contains(&flag.as_str()) && bits == 1 =>
        {
            flag.clone()
        }
        [field] if field == "_PC" && bits == 64 => "PC".into(),
        [field] if field == "SP_EL0" && bits == 64 => "SP".into(),
        _ => return Err(format!("unsupported architectural input {path:?}")),
    };
    Ok(Expression {
        bits,
        node: Node::Register { name },
    })
}
fn project(value: Value, key: &str, typ: &TypedTyp) -> Result<Value> {
    match value {
        Value::Input(mut path) => {
            path.push(key.to_owned());
            match typ {
                TypBase::Record(_) | TypBase::Array(..) => Ok(Value::Input(path)),
                _ => Ok(Value::Scalar(register(&path, width(typ)?)?)),
            }
        }
        Value::Record(base, mut fields) => match fields.remove(key) {
            Some(value) => Ok(value),
            None => project(*base, key, typ),
        },
        Value::Array(base, mut elements) => {
            let index = key.parse::<u64>().map_err(|_| "invalid array index")?;
            match elements.remove(&index) {
                Some(value) => Ok(value),
                None => project(*base, key, typ),
            }
        }
        _ => Err("projection from non-aggregate residual".into()),
    }
}

struct Exporter {
    primitives: HashMap<VarId, Primitive>,
    budget: usize,
    assumptions: Vec<(Expression, bool)>,
}
impl Exporter {
    fn eval(&mut self, expression: &TypedExpr, env: &mut HashMap<VarId, Value>) -> Result<Value> {
        self.budget = self
            .budget
            .checked_sub(1)
            .ok_or("residual expression budget exceeded")?;
        use ExprKind::*;
        match &expression.kind {
            Id(id) => env.get(id).cloned().ok_or(format!("unbound residual identifier {id:?}")),
            Paren(e) => self.eval(e, env),
            Lit(tir::syntax::Lit::Bits(s)) => {
                let bits = width(&expression.meta.typ)?;
                if s.len() != bits as usize { return Err("literal bitvector width mismatch".into()); }
                Ok(Value::Scalar(constant(bits, BigUint::from_str_radix(s, 2).map_err(|_| "invalid bitvector")?)?))
            }
            Lit(tir::syntax::Lit::Bool(b)) => Ok(Value::Scalar(constant(1, BigUint::from(u8::from(*b)))?)),
            Lit(tir::syntax::Lit::Int(n)) => Ok(Value::Integer(n.to_u64().ok_or("unsupported signed/dynamic integer")?)),
            Let { var: LExpr::Id(id), rhs, body, .. } => {
                let value = self.eval(rhs, env)?;
                let old = env.insert(*id, value);
                let result = self.eval(body, env);
                if let Some(old) = old { env.insert(*id, old); } else { env.remove(id); }
                result
            }
            // AArch64 ShiftReg calls the LSR helper only on its nonzero branch;
            // that helper asserts `amount > 0`. Admit the assertion only when
            // the enclosing path condition proves that exact Bits value is
            // nonzero. Every other wildcard/unit assertion still fails closed.
            Let { var: LExpr::Wildcard, typ: TypBase::Unit, rhs, body } => {
                let Assert { cond } = &rhs.kind else {
                    return Err("unsupported wildcard unit binding".into());
                };
                let App { fun, args } = &cond.kind else {
                    return Err("unsupported residual assertion".into());
                };
                let Id(id) = fun.kind else {
                    return Err("indirect residual assertion".into());
                };
                if self.primitives.get(&id) != Some(&Primitive::GtBits) || args.len() != 2 {
                    return Err("unproven residual assertion".into());
                }
                let left = scalar(self.eval(&args[0], env)?)?;
                let right = scalar(self.eval(&args[1], env)?)?;
                let zero = constant_value(&right) == Some(BigUint::from(0u8));
                let guarded_nonzero = self.assumptions.iter().rev().any(|(condition, truth)| {
                    let Node::Binary { op, left: tested, right } = &condition.node else {
                        return false;
                    };
                    tested.as_ref() == &left
                        && constant_value(right) == Some(BigUint::from(0u8))
                        && ((*op == "ne" && *truth) || (*op == "eq" && !*truth))
                });
                if left.bits != right.bits || !zero || !guarded_nonzero {
                    return Err("unproven residual assertion".into());
                }
                self.eval(body, env)
            }
            Field { base, field } => { let base = self.eval(base, env)?; project(base, field, &expression.meta.typ) }
            ArrayIndex { base, index } => {
                let base = self.eval(base, env)?;
                let index = integer(self.eval(index, env)?)?;
                project(base, &index.to_string(), &expression.meta.typ)
            }
            RecordUpdate { base, field: (name, value) } => {
                let base = self.eval(base, env)?;
                let value = self.eval(value, env)?;
                match base {
                    Value::Record(base, mut fields) => { fields.insert(name.clone(), value); Ok(Value::Record(base, fields)) }
                    Value::Input(_) => Ok(Value::Record(Box::new(base), BTreeMap::from([(name.clone(), value)]))),
                    _ => Err("record update on non-record".into()),
                }
            }
            ArrayUpdate { base, index, value } => {
                let base = self.eval(base, env)?;
                let index = integer(self.eval(index, env)?)?;
                let value = self.eval(value, env)?;
                match base {
                    Value::Array(base, mut elements) => { elements.insert(index, value); Ok(Value::Array(base, elements)) }
                    Value::Input(_) => Ok(Value::Array(Box::new(base), BTreeMap::from([(index, value)]))),
                    _ => Err("array update on non-array".into()),
                }
            }
            BitSlice { base, slice } => {
                let value = scalar(self.eval(base, env)?)?;
                let (start, length) = match slice.as_ref() {
                    Slice::Single { index } => (literal_u64(index)?, 1),
                    Slice::Range { index, length } => (literal_u64(index)?, literal_u64(length)?),
                };
                let bits = width(&expression.meta.typ)?;
                if length != u64::from(bits) || start.checked_add(length).is_none_or(|end| end > u64::from(value.bits)) {
                    return Err("invalid residual bit slice".into());
                }
                Ok(Value::Scalar(Expression { bits, node: Node::Slice { value: Box::new(value), start: start as u32 } }))
            }
            If { cond, then_body, else_body } => {
                let condition = scalar(self.eval(cond, env)?)?;
                self.assumptions.push((condition.clone(), true));
                let then_value = scalar(self.eval(then_body, env)?)?;
                self.assumptions.pop();
                self.assumptions.push((condition.clone(), false));
                let else_value = scalar(self.eval(else_body, env)?)?;
                self.assumptions.pop();
                let bits = width(&expression.meta.typ)?;
                if condition.bits != 1 || then_value.bits != bits || else_value.bits != bits { return Err("ill-typed conditional".into()); }
                Ok(Value::Scalar(Expression { bits, node: Node::Ite { condition: Box::new(condition), then_value: Box::new(then_value), else_value: Box::new(else_value) } }))
            }
            App { fun, args } => {
                let Id(id) = fun.kind else { return Err("indirect residual call".into()); };
                let primitive = self.primitives.get(&id).copied().ok_or("residual helper call is unsupported")?;
                let args = args.iter().map(|a| self.eval(a, env)).collect::<Result<Vec<_>>>()?;
                self.primitive(primitive, args, width(&expression.meta.typ)?)
            }
            _ => Err("unsupported residual operation (memory, exception, assertion, loop, or aggregate conditional)".into()),
        }
    }
    fn primitive(&self, primitive: Primitive, mut args: Vec<Value>, bits: u32) -> Result<Value> {
        use Primitive::*;
        let expression = match primitive {
            ZerosBits if args.len() == 1 => {
                if integer(args.remove(0))? != u64::from(bits) {
                    return Err("zero width mismatch".into());
                }
                constant(bits, BigUint::from(0u8))?
            }
            NotBits | NotBool if args.len() == 1 => {
                let value = scalar(args.remove(0))?;
                if value.bits != bits {
                    return Err("unary width mismatch".into());
                }
                Expression {
                    bits,
                    node: Node::Unary {
                        op: "not",
                        value: Box::new(value),
                    },
                }
            }
            AppendBits if args.len() == 2 => {
                let high = scalar(args.remove(0))?;
                let low = scalar(args.remove(0))?;
                if high.bits + low.bits != bits {
                    return Err("concatenation width mismatch".into());
                }
                Expression {
                    bits,
                    node: Node::Concat {
                        high: Box::new(high),
                        low: Box::new(low),
                    },
                }
            }
            AddBits | SubBits | EqBits | NeBits | AndBits | OrBits | EorBits | AndBool | OrBool
            | ShlBits | LshrBits | AshrBits
                if args.len() == 2 =>
            {
                let left = scalar(args.remove(0))?;
                let right = scalar(args.remove(0))?;
                let comparison = matches!(primitive, EqBits | NeBits);
                if left.bits != right.bits || bits != if comparison { 1 } else { left.bits } {
                    return Err("binary width mismatch".into());
                }
                let op = match primitive {
                    AddBits => "add",
                    SubBits => "sub",
                    EqBits => "eq",
                    NeBits => "ne",
                    AndBits | AndBool => "and",
                    OrBits | OrBool => "or",
                    EorBits => "xor",
                    ShlBits => "shl",
                    LshrBits => "lshr",
                    AshrBits => "ashr",
                    _ => unreachable!(),
                };
                Expression {
                    bits,
                    node: Node::Binary {
                        op,
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                }
            }
            ReplicateBits if args.len() == 2 => {
                let value = scalar(args.remove(0))?;
                let count = integer(args.remove(0))?;
                let replicated = replicate(value, count)?;
                if replicated.bits != bits {
                    return Err("replication width mismatch".into());
                }
                replicated
            }
            _ => return Err(format!("unsupported TIR primitive {primitive:?}")),
        };
        Ok(Value::Scalar(expression))
    }
}
fn constant_value(expression: &Expression) -> Option<BigUint> {
    match &expression.node {
        Node::Constant { value } => BigUint::from_str_radix(value.strip_prefix("0x")?, 16).ok(),
        Node::Concat { high, low } => {
            Some((constant_value(high)? << low.bits) | constant_value(low)?)
        }
        Node::Slice { value, start } => {
            let mask = (BigUint::from(1u8) << expression.bits) - BigUint::from(1u8);
            Some((constant_value(value)? >> start) & mask)
        }
        _ => None,
    }
}
fn collect(
    value: Value,
    path: &[String],
    outputs: &mut BTreeMap<String, Expression>,
    opcode: u32,
    metadata: &mut [bool; 2],
) -> Result<()> {
    match value {
        Value::Record(base, fields) => {
            match *base {
                Value::Input(ref p) if p == path => (),
                _ => return Err("record does not preserve its input state".into()),
            }
            for (name, value) in fields {
                let mut p = path.to_vec();
                p.push(name);
                collect(value, &p, outputs, opcode, metadata)?;
            }
        }
        Value::Array(base, elements) => {
            match *base {
                Value::Input(ref p) if p == path => (),
                _ => return Err("array does not preserve its input state".into()),
            }
            for (index, value) in elements {
                let mut p = path.to_vec();
                p.push(index.to_string());
                collect(value, &p, outputs, opcode, metadata)?;
            }
        }
        Value::Scalar(e) if path == ["__ThisInstr"] => {
            if e.bits != 32 || constant_value(&e) != Some(BigUint::from(opcode)) {
                return Err("specialized instruction bytes do not match request".into());
            }
            metadata[0] = true;
        }
        Value::Scalar(e) if path == ["__BranchTaken"] => {
            if e.bits != 1 || constant_value(&e) != Some(BigUint::from(0u8)) {
                return Err("unexpected branch effect".into());
            }
            metadata[1] = true;
        }
        Value::Scalar(e) => {
            let mapped = register(path, e.bits)?;
            let Node::Register { name } = mapped.node else {
                unreachable!()
            };
            if outputs.insert(name, e).is_some() {
                return Err("duplicate architectural output".into());
            }
        }
        _ => return Err(format!("unsupported architectural update {path:?}")),
    }
    Ok(())
}

fn typed_spec() -> Result<Module<TypedMeta>> {
    let ast = std::env::var("TIR_ASL_AST").map_err(|_| "missing TIR_ASL_AST")?;
    if !Path::new(&ast).is_file() {
        return Err("missing specification AST".into());
    }
    tir::typecheck::tag_with_types(&AslFrontend::new(&ast).translate())
}
fn configured_spec() -> Result<Module<TypedMeta>> {
    let path = std::env::var("FOCACCIA_TIR_MODULE")
        .map_err(|_| "missing prepared specification module")?;
    bincode::deserialize::<PreparedModule>(&std::fs::read(path).map_err(|e| e.to_string())?)
        .map(Module::from)
        .map_err(|e| e.to_string())
}
fn transform(
    typed: &Module<TypedMeta>,
    pc: u64,
    bytes: &[u8],
) -> Result<BTreeMap<String, Expression>> {
    if bytes.len() != 4 || pc % 4 != 0 || pc.checked_add(4).is_none() {
        return Err("requires one aligned AArch64 instruction".into());
    }
    let opcode = u32::from_le_bytes(bytes.try_into().unwrap());
    // KnownMemory adds profile data after program text. Reject overlap rather
    // than silently specializing a page-table descriptor as the instruction.
    for (base, data) in &typed.arch().config.known_memory {
        if pc < base.saturating_add(data.len() as u64) && *base < pc + 4 {
            return Err("instruction overlaps specification configuration memory".into());
        }
    }
    let (iclass, pruned) = specializer::specializer::prune_to_iclass(&typed, opcode);
    if !CLASSES.contains(&iclass.as_str()) {
        return Err(format!("unsupported instruction class {iclass}"));
    }
    let pins = KnownState::config_defaults(pruned.arch());
    let mut conf = pruned.clone();
    let folded: HashMap<VarId, TypedExpr> =
        specializer::evaluator::conf_fold_all(&pruned, &pins, &mut conf)
            .into_iter()
            .collect();
    for declaration in &mut conf.entries {
        if let Decl::Func { id, body, .. } = declaration {
            if let Some(folded) = folded.get(id) {
                *body = folded.clone();
            }
        }
    }
    let known = KnownState::usermode_at(conf.arch(), bytes, pc, pc);
    let mut output = conf.clone();
    let (parameter, body) =
        specializer::evaluator::specialize_state_fn(&conf, "interp", &known, &mut output)
            .ok_or("specialization failed")?;
    let primitives = output
        .get_primitives()
        .map(|(id, _, _, p)| (id, p))
        .collect();
    let mut exporter = Exporter {
        primitives,
        budget: 20_000,
        assumptions: Vec::new(),
    };
    let value = exporter.eval(
        &body,
        &mut HashMap::from([(parameter, Value::Input(vec![]))]),
    )?;
    let mut outputs = BTreeMap::new();
    let mut metadata = [false; 2];
    collect(value, &[], &mut outputs, opcode, &mut metadata)?;
    if metadata != [true; 2] || !outputs.contains_key("PC") {
        return Err("incomplete architectural transition".into());
    }
    Ok(outputs)
}
fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--help" {
        println!("usage: focaccia-tir-oracle <pc-decimal> <four-instruction-bytes-hex>");
        return Ok(());
    }
    if args.len() == 3 && args[1] == "--prepare" {
        let module = PreparedModule::from(typed_spec()?);
        std::fs::write(
            &args[2],
            bincode::serialize(&module).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        return Ok(());
    }
    if args.len() != 3 {
        return Err("usage: focaccia-tir-oracle <pc-decimal> <instruction-hex>".into());
    }
    let pc: u64 = args[1].parse().map_err(|_| "invalid PC")?;
    let raw = &args[2];
    if raw.len() != 8 || !raw.is_ascii() {
        return Err("expected four instruction bytes".into());
    }
    let bytes = (0..8)
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).map_err(|_| "invalid hex".to_string()))
        .collect::<Result<Vec<_>>>()?;
    let mut response = serde_json::json!({
        "schema": 1, "architecture": "aarch64", "endianness": "little",
        "pc": pc.to_string(), "instruction": raw.to_lowercase(),
        "tir_revision": env!("FOCACCIA_TIR_REVISION"), "profile": "aarch64-fullspec-el0",
    });
    // Missing/corrupt package data is an infrastructure failure, not unsupported ISA semantics.
    let typed = configured_spec()?;
    match transform(&typed, pc, &bytes) {
        Ok(outputs) => {
            response["status"] = "ok".into();
            response["outputs"] = serde_json::to_value(outputs).map_err(|e| e.to_string())?;
        }
        Err(reason) => {
            response["status"] = "unsupported".into();
            response["reason"] = reason.into();
        }
    }
    println!(
        "{}",
        serde_json::to_string(&response).map_err(|e| e.to_string())?
    );
    Ok(())
}
fn main() {
    // The oracle has one fixed machine profile; ambient translator tuning must
    // not silently change its semantics. The Python adapter also sanitizes it.
    if std::env::vars_os().any(|(key, _)| {
        key.to_str().is_some_and(|s| {
            s.starts_with("TIRAMISU_")
                || (s.starts_with("TIR_")
                    && !["TIR_ASL_AST", "TIR_RUNTIME_ARCHIVE", "TIR_CC"].contains(&s))
        })
    }) {
        eprintln!("oracle refuses ambient TIR configuration overrides");
        std::process::exit(2);
    }
    let result = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(run)
        .expect("oracle worker")
        .join();
    match result {
        Ok(Ok(())) => (),
        Ok(Err(message)) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
        Err(_) => {
            eprintln!("TIR oracle failed while processing the instruction");
            std::process::exit(1);
        }
    }
}
