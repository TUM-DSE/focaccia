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
    io::BufRead,
    path::Path,
};
use tir::{module::Module, primitives::Primitive, syntax::*};

type Result<T> = std::result::Result<T, String>;
// Closed-world audit of every class reached by the controlled static-musl
// #2248 execution. Adding a class requires an opcode fixture and successful
// residual export; this is not a general AArch64 support claim.
const CLASSES: &[&str] = &[
    "decode_aarch64_branch_conditional_compare",
    "decode_aarch64_branch_conditional_cond",
    "decode_aarch64_branch_conditional_test",
    "decode_aarch64_branch_unconditional_immediate",
    "decode_aarch64_branch_unconditional_register",
    "decode_aarch64_integer_arithmetic_add_sub_extendedreg",
    "decode_aarch64_integer_arithmetic_add_sub_immediate",
    "decode_aarch64_integer_arithmetic_add_sub_shiftedreg",
    "decode_aarch64_integer_arithmetic_address_pc_rel",
    "decode_aarch64_integer_arithmetic_mul_widening_64_128hi",
    "decode_aarch64_integer_bitfield",
    "decode_aarch64_integer_conditional_compare_immediate",
    "decode_aarch64_integer_conditional_select",
    "decode_aarch64_integer_ins_ext_insert_movewide",
    "decode_aarch64_integer_logical_immediate",
    "decode_aarch64_integer_logical_shiftedreg",
    "decode_aarch64_integer_shift_variable",
    "decode_aarch64_memory_pair_general_offset",
    "decode_aarch64_memory_pair_general_post_idx",
    "decode_aarch64_memory_pair_general_pre_idx",
    "decode_aarch64_memory_pair_simdfp_offset",
    "decode_aarch64_memory_pair_simdfp_pre_idx",
    "decode_aarch64_memory_single_general_immediate_signed_offset_normal",
    "decode_aarch64_memory_single_general_immediate_signed_post_idx",
    "decode_aarch64_memory_single_general_immediate_signed_pre_idx",
    "decode_aarch64_memory_single_general_immediate_unsigned",
    "decode_aarch64_memory_single_general_register",
    "decode_aarch64_memory_single_simdfp_immediate_signed_offset_normal",
    "decode_aarch64_memory_single_simdfp_immediate_unsigned",
    "decode_aarch64_system_exceptions_runtime_svc",
    "decode_aarch64_system_register_system",
    "decode_aarch64_vector_transfer_integer_dup",
];
const MAX_BITS: u32 = 2048;

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

#[derive(Clone, Debug, PartialEq, Serialize)]
struct Expression {
    bits: u32,
    #[serde(flatten)]
    node: Node,
}
#[derive(Clone, Debug, PartialEq, Serialize)]
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
    Memory {
        address: Box<Expression>,
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
        _ => return Err(format!("expected a fixed-width scalar type, got {typ:?}")),
    };
    if n == 0 || n > u64::from(MAX_BITS) {
        return Err(format!("unsupported scalar width {n}"));
    }
    Ok(n as u32)
}

#[derive(Clone, Debug)]
enum Value {
    Input(Vec<String>),
    Record(Box<Value>, BTreeMap<String, Value>),
    Array(Box<Value>, BTreeMap<u64, Value>),
    Writes(Box<Value>, Vec<(Expression, Expression)>),
    Scalar(Expression),
    Integer(u64),
    Enum(String, String),
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
        [field, index] if field == "_V" || field == "_Z" => {
            let n: u32 = index.parse().map_err(|_| "invalid vector register index")?;
            if n > 31 || (field == "_V" && bits != 128) || (field == "_Z" && bits < 128) {
                return Err("unsupported vector register".into());
            }
            format!("V{n}")
        }
        [field] if field == "_PC" && bits == 64 => "PC".into(),
        [field] if field == "SP_EL0" && bits == 64 => "SP".into(),
        [field] if field == "TPIDR_EL0" && bits == 64 => "TPIDR".into(),
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
            if path == ["BTypeNext"] {
                // regs.csv pins this fetch-local branch hint to its all-zero
                // userspace default; preserve that profile contract even when
                // the generic specializer leaves the scalar projection behind.
                return Ok(Value::Scalar(constant(width(typ)?, BigUint::from(0u8))?));
            }
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
        Value::Writes(base, writes) => {
            project(*base, key, typ).map(|value| Value::Writes(Box::new(value), writes))
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
            Lit(tir::syntax::Lit::Enum { name, variant }) => Ok(Value::Enum(name.clone(), variant.clone())),
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
                    let tested = scalar(self.eval(cond, env)?)?;
                    if tested.bits == 1
                        && constant_value(&tested) == Some(BigUint::from(1u8))
                    {
                        return self.eval(body, env);
                    }
                    return Err(format!("unproven residual assertion: {tested:?}"));
                };
                let Id(id) = fun.kind else {
                    return Err("indirect residual assertion".into());
                };
                if self.primitives.get(&id) != Some(&Primitive::GtBits) || args.len() != 2 {
                    return Err(format!(
                        "unproven residual assertion {:?} with {} arguments",
                        self.primitives.get(&id), args.len()
                    ));
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
                    Value::Input(_) | Value::Writes(..) => Ok(Value::Record(Box::new(base), BTreeMap::from([(name.clone(), value)]))),
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
                let mut args = args.iter().map(|a| self.eval(a, env)).collect::<Result<Vec<_>>>()?;
                if primitive == Primitive::CvtBitsUint && args.len() == 1 {
                    let value = scalar(args.remove(0))?;
                    return Ok(Value::Integer(
                        constant_value(&value)
                            .and_then(|value| value.to_u64())
                            .ok_or("dynamic bits-to-integer conversion is unsupported")?,
                    ));
                }
                if matches!(primitive, Primitive::AddInt | Primitive::SubInt | Primitive::MulInt
                    | Primitive::ShlInt | Primitive::ShrInt | Primitive::FdivInt | Primitive::ZdivInt)
                    && args.len() == 2
                {
                    let right = integer(args.remove(1))?;
                    let left = integer(args.remove(0))?;
                    let value = match primitive {
                        Primitive::AddInt => left.checked_add(right),
                        Primitive::SubInt => left.checked_sub(right),
                        Primitive::MulInt => left.checked_mul(right),
                        Primitive::ShlInt => left.checked_shl(u32::try_from(right).map_err(|_| "integer shift out of range")?),
                        Primitive::ShrInt => left.checked_shr(u32::try_from(right).map_err(|_| "integer shift out of range")?),
                        Primitive::FdivInt | Primitive::ZdivInt if right != 0 => Some(left / right),
                        _ => None,
                    }
                    .ok_or("integer primitive overflow or invalid operation")?;
                    return Ok(Value::Integer(value));
                }
                if primitive == Primitive::RamWrite {
                    if args.len() != 5 {
                        return Err("invalid ram_write arity".into());
                    }
                    let address_bits = integer(args.remove(0))?;
                    let byte_count = integer(args.remove(0))?;
                    let state = args.remove(0);
                    let address = scalar(args.remove(0))?;
                    let value = scalar(args.remove(0))?;
                    if address_bits != u64::from(address.bits)
                        || byte_count.checked_mul(8) != Some(u64::from(value.bits))
                    {
                        return Err("ram_write width mismatch".into());
                    }
                    return match state {
                        Value::Writes(base, mut writes) => {
                            writes.push((address, value));
                            Ok(Value::Writes(base, writes))
                        }
                        state => Ok(Value::Writes(Box::new(state), vec![(address, value)])),
                    };
                }
                let bits = width(&expression.meta.typ)
                    .map_err(|error| format!("{primitive:?}: {error}"))?;
                self.primitive(primitive, args, bits)
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
            AddBits | SubBits | MulBits | EqBits | NeBits | AndBits | OrBits | EorBits | AndBool
            | OrBool | ShlBits | LshrBits | AshrBits
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
                    MulBits => "mul",
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
            EqEnum | NeEnum if args.len() == 2 => {
                let right = args.remove(1);
                let left = args.remove(0);
                match (left, right) {
                    (Value::Enum(left_name, left_variant), Value::Enum(right_name, right_variant)) => {
                        let equal = left_name == right_name && left_variant == right_variant;
                        constant(1, BigUint::from(u8::from(if primitive == EqEnum { equal } else { !equal })))?
                    }
                    (Value::Scalar(left), Value::Scalar(right)) if left.bits == right.bits => {
                        Expression {
                            bits: 1,
                            node: Node::Binary {
                                op: if primitive == EqEnum { "eq" } else { "ne" },
                                left: Box::new(left),
                                right: Box::new(right),
                            },
                        }
                    }
                    (left, right) => return Err(format!("dynamic enum comparison is unsupported: {left:?} {right:?}")),
                }
            }
            RamRead if args.len() == 4 => {
                let address_bits = integer(args.remove(0))?;
                let byte_count = integer(args.remove(0))?;
                let _state = args.remove(0);
                let address = scalar(args.remove(0))?;
                if address_bits != u64::from(address.bits)
                    || byte_count.checked_mul(8) != Some(u64::from(bits))
                {
                    return Err("ram_read width mismatch".into());
                }
                Expression {
                    bits,
                    node: Node::Memory { address: Box::new(address) },
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
    memory_writes: &mut Vec<(Expression, Expression)>,
    opcode: u32,
    metadata: &mut [bool; 2],
) -> Result<()> {
    match value {
        Value::Input(input) if input == path => (),
        Value::Record(base, fields) => {
            collect(*base, path, outputs, memory_writes, opcode, metadata)?;
            for (name, value) in fields {
                let mut p = path.to_vec();
                p.push(name);
                collect(value, &p, outputs, memory_writes, opcode, metadata)?;
            }
        }
        Value::Array(base, elements) => {
            collect(*base, path, outputs, memory_writes, opcode, metadata)?;
            for (index, value) in elements {
                let mut p = path.to_vec();
                p.push(index.to_string());
                collect(value, &p, outputs, memory_writes, opcode, metadata)?;
            }
        }
        Value::Writes(base, writes) => {
            collect(*base, path, outputs, memory_writes, opcode, metadata)?;
            memory_writes.extend(writes);
        }
        Value::Scalar(e) if path == ["__ThisInstr"] => {
            if e.bits != 32 || constant_value(&e) != Some(BigUint::from(opcode)) {
                return Err("specialized instruction bytes do not match request".into());
            }
            metadata[0] = true;
        }
        Value::Scalar(e) if path == ["__BranchTaken"] => {
            if e.bits != 1 {
                return Err("invalid branch effect".into());
            }
            metadata[1] = true;
        }
        Value::Enum(_, _) if path == ["BTypeNext"] => {
            // Every instruction is specialized under the profile-pinned default
            // BTypeNext. Linux-user exposes no independent BTYPE register, and
            // this fetch-local branch hint cannot affect another oracle call.
        }
        Value::Scalar(_) if path == ["BTypeNext"] => {
            // See the pinned-input handling in project().
        }
        Value::Scalar(e) => {
            let mapped = register(path, e.bits)?;
            let Node::Register { name } = mapped.node else {
                unreachable!()
            };
            let e = if path.first().is_some_and(|field| field == "_Z") {
                Expression {
                    bits: 128,
                    node: Node::Slice { value: Box::new(e), start: 0 },
                }
            } else {
                e
            };
            if outputs.insert(name, e).is_some() {
                return Err("duplicate architectural output".into());
            }
        }
        _ => return Err(format!("unsupported architectural update {path:?}")),
    }
    Ok(())
}

#[derive(Serialize)]
struct Transition {
    outputs: BTreeMap<String, Expression>,
    memory_writes: Vec<MemoryWrite>,
}

#[derive(Serialize)]
struct MemoryWrite {
    address: Expression,
    value: Expression,
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
) -> Result<Transition> {
    if bytes.len() != 4 || pc % 4 != 0 {
        return Err("requires one aligned AArch64 instruction".into());
    }
    let instruction_end = pc
        .checked_add(4)
        .ok_or("instruction address exceeds the AArch64 address space")?;
    let opcode = u32::from_le_bytes(bytes.try_into().unwrap());
    // KnownMemory adds profile data after program text. Reject malformed ranges
    // and overlap rather than silently specializing profile data as instruction
    // bytes. Do not let a saturating end conceal a range crossing 2^64.
    for (base, data) in &typed.arch().config.known_memory {
        let memory_length =
            u64::try_from(data.len()).map_err(|_| "configuration memory is too large")?;
        let memory_end = base
            .checked_add(memory_length)
            .ok_or("configuration memory exceeds the AArch64 address space")?;
        if pc < memory_end && *base < instruction_end {
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
    let mut writes = Vec::new();
    let mut metadata = [false; 2];
    collect(value, &[], &mut outputs, &mut writes, opcode, &mut metadata)?;
    if metadata != [true; 2] || !outputs.contains_key("PC") {
        return Err("incomplete architectural transition".into());
    }
    Ok(Transition {
        outputs,
        memory_writes: writes
            .into_iter()
            .map(|(address, value)| MemoryWrite { address, value })
            .collect(),
    })
}
fn decode_request(pc: &str, raw: &str) -> Result<(u64, Vec<u8>)> {
    let pc = pc.parse().map_err(|_| "invalid PC")?;
    if raw.len() != 8 || !raw.is_ascii() {
        return Err("expected four instruction bytes".into());
    }
    let bytes = (0..8)
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).map_err(|_| "invalid hex".to_string()))
        .collect::<Result<Vec<_>>>()?;
    Ok((pc, bytes))
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--help" {
        println!("usage: focaccia-tir-oracle <pc-decimal> <four-instruction-bytes-hex>\n       focaccia-tir-oracle --audit-classes < newline-delimited 'pc-decimal bytes-hex'");
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
    if args.len() == 2 && matches!(args[1].as_str(), "--audit-classes" | "--export-transitions") {
        let typed = configured_spec()?;
        for (index, line) in std::io::stdin().lock().lines().enumerate() {
            let line = line.map_err(|error| error.to_string())?;
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() != 2 {
                return Err(format!("invalid batch input at line {}", index + 1));
            }
            let (pc, bytes) = decode_request(fields[0], fields[1])?;
            if bytes.len() != 4 || pc % 4 != 0 {
                return Err(format!("invalid batch instruction at line {}", index + 1));
            }
            if args[1] == "--audit-classes" {
                let opcode = u32::from_le_bytes(bytes.try_into().unwrap());
                let (class, _) = specializer::specializer::prune_to_iclass(&typed, opcode);
                println!("{pc} {} {class}", fields[1].to_ascii_lowercase());
            } else {
                let mut response = serde_json::json!({
                    "schema": 1, "architecture": "aarch64", "endianness": "little",
                    "pc": pc.to_string(), "instruction": fields[1].to_ascii_lowercase(),
                    "tir_revision": env!("FOCACCIA_TIR_REVISION"),
                    "profile": "aarch64-fullspec-el0",
                });
                match transform(&typed, pc, &bytes) {
                    Ok(transition) => {
                        response["status"] = "ok".into();
                        response["outputs"] = serde_json::to_value(transition.outputs).map_err(|e| e.to_string())?;
                        response["memory_writes"] = serde_json::to_value(transition.memory_writes).map_err(|e| e.to_string())?;
                    }
                    Err(reason) => {
                        response["status"] = "unsupported".into();
                        response["reason"] = reason.into();
                    }
                }
                println!("{}", serde_json::to_string(&response).map_err(|e| e.to_string())?);
            }
        }
        return Ok(());
    }
    if args.len() != 3 {
        return Err("usage: focaccia-tir-oracle <pc-decimal> <instruction-hex>".into());
    }
    let (pc, bytes) = decode_request(&args[1], &args[2])?;
    let raw = &args[2];
    let mut response = serde_json::json!({
        "schema": 1, "architecture": "aarch64", "endianness": "little",
        "pc": pc.to_string(), "instruction": raw.to_lowercase(),
        "tir_revision": env!("FOCACCIA_TIR_REVISION"), "profile": "aarch64-fullspec-el0",
    });
    // Missing/corrupt package data is an infrastructure failure, not unsupported ISA semantics.
    let typed = configured_spec()?;
    match transform(&typed, pc, &bytes) {
        Ok(transition) => {
            response["status"] = "ok".into();
            response["outputs"] = serde_json::to_value(transition.outputs).map_err(|e| e.to_string())?;
            response["memory_writes"] = serde_json::to_value(transition.memory_writes).map_err(|e| e.to_string())?;
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
