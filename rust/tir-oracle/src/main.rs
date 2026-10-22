//! Specification-derived instruction transformations. No LLVM backend is linked.
//! The supported instruction class is deliberately narrow; unsupported residual
//! operations or architectural writes fail closed instead of being discarded.
use frontend::{adapters::asl::AslFrontend, TirFrontend};
use num_bigint::BigUint;
use num_traits::{Num, ToPrimitive};
use serde::{Deserialize, Serialize};
use specializer::specializer::KnownState;
use std::{
    collections::{BTreeMap, HashMap},
    io::{BufRead, Write},
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
    "decode_aarch64_integer_arithmetic_mul_uniform_add_sub",
    "decode_aarch64_integer_arithmetic_mul_widening_32_64",
    "decode_aarch64_integer_arithmetic_mul_widening_64_128hi",
    "decode_aarch64_integer_bitfield",
    "decode_aarch64_integer_conditional_compare_immediate",
    "decode_aarch64_integer_conditional_compare_register",
    "decode_aarch64_integer_conditional_select",
    "decode_aarch64_integer_ins_ext_insert_movewide",
    "decode_aarch64_integer_logical_immediate",
    "decode_aarch64_integer_logical_shiftedreg",
    "decode_aarch64_integer_arithmetic_cnt",
    "decode_aarch64_integer_arithmetic_div",
    "decode_aarch64_integer_arithmetic_rbit",
    "decode_aarch64_integer_shift_variable",
    "decode_aarch64_memory_pair_general_offset",
    "decode_aarch64_memory_pair_general_post_idx",
    "decode_aarch64_memory_pair_general_pre_idx",
    "decode_aarch64_memory_pair_simdfp_offset",
    "decode_aarch64_memory_pair_simdfp_pre_idx",
    "decode_aarch64_memory_atomicops_ld",
    "decode_aarch64_memory_exclusive_single",
    "decode_aarch64_memory_single_general_immediate_signed_offset_lda_stl",
    "decode_aarch64_memory_single_general_immediate_signed_offset_normal",
    "decode_aarch64_memory_single_general_immediate_signed_post_idx",
    "decode_aarch64_memory_single_general_immediate_signed_pre_idx",
    "decode_aarch64_memory_single_general_immediate_unsigned",
    "decode_aarch64_memory_single_general_register",
    "decode_aarch64_memory_single_simdfp_immediate_signed_offset_normal",
    "decode_aarch64_memory_single_simdfp_immediate_unsigned",
    "decode_aarch64_system_exceptions_runtime_svc",
    "decode_aarch64_system_hints",
    "decode_aarch64_system_register_system",
    "decode_aarch64_system_monitors",
    "decode_aarch64_system_sysops",
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
    #[serde(skip)]
    SourceUndefined,
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
    Choice(Expression, Box<Value>, Box<Value>),
    Scalar(Expression),
    ZeroBits(u64),
    Integer(u64),
    IntegerExpr(Expression),
    Enum(String, String),
    Variant(Box<Value>, Box<Value>),
    Unit,
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
#[track_caller]
fn scalar(value: Value) -> Result<Expression> {
    match value {
        Value::Scalar(e) => Ok(e),
        _ => Err(format!("expected scalar residual at {}", std::panic::Location::caller())),
    }
}
fn integer(value: Value) -> Result<u64> {
    match value {
        Value::Integer(i) => Ok(i),
        _ => Err("dynamic integer is unsupported".into()),
    }
}
fn integer_expr(value: Value) -> Result<Expression> {
    match value {
        Value::Integer(value) => constant(64, BigUint::from(value)),
        Value::IntegerExpr(value) if value.bits == 64 => Ok(value),
        _ => Err("expected bounded unsigned 64-bit integer expression".into()),
    }
}
fn register(path: &[String], bits: u32) -> Result<Expression> {
    #[cfg(focaccia_sail)]
    if path.first().is_some_and(|field| field.starts_with('z')) {
        return sail::input(path, bits);
    }
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
fn merge_value(condition: Expression, left: Value, right: Value) -> Result<Value> {
    match (left, right) {
        (Value::Unit, Value::Unit) => Ok(Value::Unit),
        (Value::Scalar(left), Value::Scalar(right)) => {
            if condition.bits != 1 || left.bits != right.bits { return Err("ill-typed conditional values".into()); }
            if left == right { return Ok(Value::Scalar(left)); }
            Ok(Value::Scalar(Expression { bits: left.bits, node: Node::Ite {
                condition: Box::new(condition), then_value: Box::new(left), else_value: Box::new(right),
            }}))
        }
        (left, right) => Ok(Value::Choice(condition, Box::new(left), Box::new(right))),
    }
}
fn project(value: Value, key: &str, typ: &TypedTyp) -> Result<Value> {
    match value {
        Value::Choice(condition, left, right) => merge_value(condition, project(*left, key, typ)?, project(*right, key, typ)?),
        Value::Input(mut path) => {
            path.push(key.to_owned());
            #[cfg(focaccia_sail)]
            if path == ["zmem_base"] { return Ok(Value::Input(path)); }
            if path == ["BTypeNext"] {
                // regs.csv pins this fetch-local branch hint to its all-zero
                // userspace default; preserve that profile contract even when
                // the generic specializer leaves the scalar projection behind.
                return Ok(Value::Scalar(constant(width(typ)?, BigUint::from(0u8))?));
            }
            match typ {
                TypBase::Record(..) | TypBase::Array(..) => Ok(Value::Input(path)),
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

#[derive(Default)]
struct SourceTrace {
    guards: Vec<Expression>,
    reads: Vec<(Expression, u32, Expression, usize)>,
    writes: Vec<(Expression, Expression, Expression)>,
}
struct Exporter {
    source_trace: Option<SourceTrace>,
    primitives: HashMap<VarId, Primitive>,
    budget: usize,
    assumptions: Vec<(Expression, bool)>,
}
impl Exporter {
    fn source_activation(&self) -> Result<Expression> {
        let mut active = constant(1, BigUint::from(1u8))?;
        for (condition, truth) in &self.assumptions {
            let condition = if *truth { condition.clone() } else { Expression { bits: 1, node: Node::Unary { op: "not", value: Box::new(condition.clone()) } } };
            active = Expression { bits: 1, node: Node::Binary { op: "and", left: Box::new(active), right: Box::new(condition) } };
        }
        Ok(active)
    }
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
                let bit_count = match &expression.meta.typ {
                    TypBase::Bits(length) => literal_u64(length)?,
                    _ => return Err("bit literal has a non-bitvector type".into()),
                };
                if s.len() as u64 != bit_count { return Err("literal bitvector width mismatch".into()); }
                if bit_count > u64::from(MAX_BITS) {
                    if bit_count > 16_384 || bit_count % 8 != 0 || s.bytes().any(|bit| bit != b'0') {
                        return Err("unsupported oversized bitvector literal".into());
                    }
                    return Ok(Value::ZeroBits(bit_count));
                }
                let bits = bit_count as u32;
                Ok(Value::Scalar(constant(bits, BigUint::from_str_radix(s, 2).map_err(|_| "invalid bitvector")?)?))
            }
            Lit(tir::syntax::Lit::Unit) if self.source_trace.is_some() => Ok(Value::Unit),
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
                if self.source_trace.is_some() && !matches!(rhs.kind, Assert { .. }) {
                    if !matches!(self.eval(rhs, env)?, Value::Unit) { return Err("source discarded a non-unit effect".into()); }
                    return self.eval(body, env);
                }
                let Assert { cond } = &rhs.kind else {
                    return Err("unsupported wildcard unit binding".into());
                };
                let evaluated_condition = self.eval(cond, env)?;
                if self.source_trace.is_some() {
                    let tested = scalar(evaluated_condition)?;
                    if tested.bits != 1 { return Err("non-boolean source guard".into()); }
                    let active = self.source_activation()?;
                    let inactive = Expression { bits: 1, node: Node::Unary { op: "not", value: Box::new(active) } };
                    let guard = Expression { bits: 1, node: Node::Binary { op: "or", left: Box::new(inactive), right: Box::new(tested) } };
                    self.source_trace.as_mut().unwrap().guards.push(guard);
                    return self.eval(body, env);
                }
                if let Value::Scalar(tested) = &evaluated_condition {
                    if tested.bits == 1 {
                        match constant_value(tested) {
                            Some(value) if value == BigUint::from(1u8) => {
                                return self.eval(body, env);
                            }
                            Some(_) => return Err("false residual assertion".into()),
                            None => (),
                        }
                    }
                }
                let App { fun, args } = &cond.kind else {
                    let Value::Scalar(tested) = evaluated_condition else {
                        return Err("unsupported residual assertion condition".into());
                    };
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
                    Value::Input(_) | Value::Writes(..) | Value::Choice(..) => Ok(Value::Record(Box::new(base), BTreeMap::from([(name.clone(), value)]))),
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
                if condition.bits == 1 {
                    match constant_value(&condition) {
                        Some(value) if value == BigUint::from(1u8) => {
                            return self.eval(then_body, env);
                        }
                        Some(_) => {
                            return self.eval(else_body, env);
                        }
                        None => (),
                    }
                }
                self.assumptions.push((condition.clone(), true));
                let then_value = self.eval(then_body, env);
                self.assumptions.pop();
                if self.source_trace.is_none() { if let Err(reason) = &then_value { return Err(reason.clone()); } }
                self.assumptions.push((condition.clone(), false));
                let else_value = self.eval(else_body, env);
                self.assumptions.pop();
                if self.source_trace.is_some() {
                    match (&then_value, &else_value) {
                        (Err(reason), Ok(value)) if reason == "source architectural fault" => {
                            let not = Expression { bits: 1, node: Node::Unary { op: "not", value: Box::new(condition) } };
                            self.source_trace.as_mut().unwrap().guards.push(not);
                            return Ok(value.clone());
                        }
                        (Ok(value), Err(reason)) if reason == "source architectural fault" => {
                            self.source_trace.as_mut().unwrap().guards.push(condition);
                            return Ok(value.clone());
                        }
                        _ => (),
                    }
                }
                merge_value(condition, then_value?, else_value?)
            }
            App { fun, args } => {
                let Id(id) = fun.kind else { return Err("indirect residual call".into()); };
                let primitive = self.primitives.get(&id).copied().ok_or("residual helper call is unsupported")?;
                let mut args = args.iter().map(|a| self.eval(a, env)).collect::<Result<Vec<_>>>()?;
                if self.source_trace.is_some() {
                    match format!("{primitive:?}").as_str() {
                        "SailUndefined" => {
                            let bits = match (&expression.meta.typ, args.first()) {
                                (TypBase::Bits(_), Some(Value::Integer(n))) => u32::try_from(*n).map_err(|_| "undefined width overflow")?,
                                _ => width(&expression.meta.typ)?,
                            };
                            if !(1..=MAX_BITS).contains(&bits) { return Err("undefined width is unsupported".into()); }
                            return Ok(Value::Scalar(Expression { bits, node: Node::SourceUndefined }));
                        }
                        "MkVariant" if args.len() == 2 => { let payload = args.remove(1); return Ok(Value::Variant(Box::new(args.remove(0)), Box::new(payload))); }
                        "IsVariant" | "UnwrapVariant" if args.len() == 2 => {
                            let tag = args.remove(1); let value = args.remove(0);
                            let (actual, payload) = match value {
                                Value::Variant(actual, payload) => (actual, payload),
                                Value::Enum(name, variant) => (Box::new(Value::Enum(name, variant)), Box::new(Value::Unit)),
                                _ => return Err("dynamic source variant is unsupported".into()),
                            };
                            let (Value::Enum(an, av), Value::Enum(bn, bv)) = (*actual, tag) else { return Err("invalid source variant tags".into()); };
                            let equal = an == bn && av == bv;
                            if format!("{primitive:?}") == "IsVariant" { return Ok(Value::Scalar(constant(1, BigUint::from(u8::from(equal)))?)); }
                            if !equal { return Err("source variant payload tag mismatch".into()); }
                            return Ok(*payload);
                        }
                        _ => (),
                    }
                }
                if primitive == Primitive::ZerosBits && args.len() == 1 {
                    let count = integer(args.remove(0))?;
                    let value_bits = match &expression.meta.typ {
                        TypBase::Bits(length) => literal_u64(length)?,
                        _ => return Err("zero value must have a bitvector type".into()),
                    };
                    // Scalar zeros include one-bit flags and need not be byte
                    // aligned. Only the oversized store-only representation
                    // requires a whole number of bytes.
                    if count != value_bits || value_bits == 0
                        || (value_bits > u64::from(MAX_BITS) && value_bits % 8 != 0)
                        || value_bits > 16_384
                    {
                        return Err("unsupported bounded zero-store width".into());
                    }
                    if value_bits > u64::from(MAX_BITS) {
                        return Ok(Value::ZeroBits(value_bits));
                    }
                    return Ok(Value::Scalar(constant(value_bits as u32, BigUint::from(0u8))?));
                }
                if primitive == Primitive::CvtBitsUint && args.len() == 1 {
                    let value = scalar(args.remove(0))?;
                    if let Some(value) = constant_value(&value).and_then(|value| value.to_u64()) {
                        return Ok(Value::Integer(value));
                    }
                    if value.bits > 64 {
                        return Err("dynamic unsigned conversion exceeds u64 bounds".into());
                    }
                    return Ok(Value::IntegerExpr(value));
                }
                if primitive == Primitive::AlignInt && args.len() == 2 {
                    let alignment = integer(args.remove(1))?;
                    if alignment == 0 || !alignment.is_power_of_two() {
                        return Err("alignment must be a bounded power of two".into());
                    }
                    let value = integer_expr(args.remove(0))?;
                    if value.bits != 64 {
                        return Err("dynamic AlignInt supports only 64-bit unsigned values".into());
                    }
                    let mask = constant(64, BigUint::from(u64::MAX & !(alignment - 1)))?;
                    return Ok(Value::IntegerExpr(Expression {
                        bits: 64,
                        node: Node::Binary {
                            op: "and",
                            left: Box::new(value),
                            right: Box::new(mask),
                        },
                    }));
                }
                if primitive == Primitive::CvtIntBits && args.len() == 2 {
                    let output_width = integer(args.remove(1))?;
                    let value = integer_expr(args.remove(0))?;
                    let result_bits = width(&expression.meta.typ)?;
                    if output_width != 64 || value.bits != 64 || result_bits != 64 {
                        return Err("CvtIntBits supports only bounded 64-bit unsigned values".into());
                    }
                    return Ok(Value::Scalar(value));
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
                    let value = args.remove(0);
                    let value_bits = match &value {
                        Value::Scalar(expression) => u64::from(expression.bits),
                        Value::ZeroBits(bits) => *bits,
                        _ => return Err("ram_write value is not a scalar or zero block".into()),
                    };
                    if address_bits != u64::from(address.bits)
                        || byte_count.checked_mul(8) != Some(value_bits)
                    {
                        return Err("ram_write width mismatch".into());
                    }
                    let mut writes = Vec::new();
                    if let Value::Scalar(value) = value {
                        writes.push((address, value));
                    } else {
                        const CHUNK_BYTES: u64 = MAX_BITS as u64 / 8;
                        let chunks = byte_count.div_ceil(CHUNK_BYTES);
                        if chunks > 16 { return Err("zero store exceeds bounded write count".into()); }
                        if chunks > 1 && !provably_aligned(&address, byte_count) {
                            return Err("oversized zero store address is not proven block-aligned".into());
                        }
                        let mut offset = 0u64;
                        while offset < byte_count {
                            let count = (byte_count - offset).min(CHUNK_BYTES);
                            let chunk_address = if offset == 0 {
                                address.clone()
                            } else {
                                Expression {
                                    bits: address.bits,
                                    node: Node::Binary {
                                        op: "add",
                                        left: Box::new(address.clone()),
                                        right: Box::new(constant(address.bits, BigUint::from(offset))?),
                                    },
                                }
                            };
                            writes.push((chunk_address, constant((count * 8) as u32, BigUint::from(0u8))?));
                            offset += count;
                        }
                    }
                    if self.source_trace.is_some() {
                        let condition = self.source_activation()?;
                        self.source_trace.as_mut().unwrap().writes.extend(writes.iter().cloned().map(|(address, value)| (address, value, condition.clone())));
                    }
                    return match state {
                        Value::Writes(base, mut prior) => {
                            prior.extend(writes);
                            Ok(Value::Writes(base, prior))
                        }
                        state => Ok(Value::Writes(Box::new(state), writes)),
                    };
                }
                let bits = width(&expression.meta.typ)
                    .map_err(|error| format!("{primitive:?}: {error}"))?;
                self.primitive(primitive, args, bits)
            }
            Throw { .. } if self.source_trace.is_some() => Err("source architectural fault".into()),
            TryCatch { body, .. } if self.source_trace.is_some() => {
                // Only the non-faulting source path is admitted: explicit
                // throws in conditional arms become guards above. Handler
                // effects are unreachable under those guards, not discarded
                // from an admitted exceptional transition.
                self.eval(body, env)
            }
            _ => Err(format!("unsupported residual operation {:?} (memory, exception, assertion, loop, or aggregate conditional)", std::mem::discriminant(&expression.kind))),
        }
    }
    fn primitive(&mut self, primitive: Primitive, mut args: Vec<Value>, bits: u32) -> Result<Value> {
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
            AddBits | SubBits | MulBits | UdivBits | EqBits | NeBits | GtBits | LtBits | GeBits
            | LeBits | AndBits | OrBits | EorBits | AndBool | OrBool | ShlBits | LshrBits
            | AshrBits
                if args.len() == 2 =>
            {
                let left = scalar(args.remove(0))?;
                let right = scalar(args.remove(0))?;
                let comparison = matches!(
                    primitive,
                    EqBits | NeBits | GtBits | LtBits | GeBits | LeBits
                );
                if left.bits != right.bits || bits != if comparison { 1 } else { left.bits } {
                    return Err("binary width mismatch".into());
                }
                let op = match primitive {
                    AddBits => "add",
                    SubBits => "sub",
                    MulBits => "mul",
                    UdivBits => "udiv",
                    EqBits => "eq",
                    NeBits => "ne",
                    GtBits => "ugt",
                    LtBits => "ult",
                    GeBits => "uge",
                    LeBits => "ule",
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
                    (
                        Value::Enum(left_name, left_variant),
                        Value::Enum(right_name, right_variant),
                    ) => {
                        let equal = left_name == right_name && left_variant == right_variant;
                        constant(
                            1,
                            BigUint::from(u8::from(if primitive == EqEnum {
                                equal
                            } else {
                                !equal
                            })),
                        )?
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
                    (left, right) => {
                        return Err(format!(
                            "dynamic enum comparison is unsupported: {left:?} {right:?}"
                        ))
                    }
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
                if self.source_trace.is_some() {
                    let condition = self.source_activation()?;
                    let trace = self.source_trace.as_mut().unwrap();
                    // Memory-after writes needs prefix-dependent value masks;
                    // this first source subset never silently substitutes a
                    // pre-write value for a post-write read.
                    if !trace.writes.is_empty() { return Err("Sail read-after-write requires prefix-dependent masks".into()); }
                    trace.reads.push((address.clone(), bits, condition, 0));
                }
                Expression {
                    bits,
                    node: Node::Memory {
                        address: Box::new(address),
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
fn provably_aligned(expression: &Expression, alignment: u64) -> bool {
    if alignment == 0 || !alignment.is_power_of_two() {
        return false;
    }
    if alignment == 1 {
        return true;
    }
    let low_mask = BigUint::from(alignment - 1);
    if let Some(value) = constant_value(expression) {
        return (&value & &low_mask) == BigUint::from(0u8);
    }
    match &expression.node {
        Node::Slice { value, start: 0 } => provably_aligned(value, alignment),
        Node::Binary {
            op: "and",
            left,
            right,
        } => {
            let mask = constant_value(left).or_else(|| constant_value(right));
            mask.is_some_and(|mask| (&mask & &low_mask) == BigUint::from(0u8))
        }
        Node::Binary {
            op: "add",
            left,
            right,
        } => {
            if let Some(offset) = constant_value(right).and_then(|value| value.to_u64()) {
                offset % alignment == 0 && provably_aligned(left, alignment)
            } else if let Some(offset) = constant_value(left).and_then(|value| value.to_u64()) {
                offset % alignment == 0 && provably_aligned(right, alignment)
            } else {
                false
            }
        }
        _ => false,
    }
}

fn constant_value(expression: &Expression) -> Option<BigUint> {
    let mask = (BigUint::from(1u8) << expression.bits) - BigUint::from(1u8);
    match &expression.node {
        Node::Constant { value } => BigUint::from_str_radix(value.strip_prefix("0x")?, 16).ok(),
        Node::Concat { high, low } => {
            Some((constant_value(high)? << low.bits) | constant_value(low)?)
        }
        Node::Slice { value, start } => Some((constant_value(value)? >> start) & mask),
        Node::Unary { op: "not", value } => Some(mask.clone() ^ constant_value(value)?),
        Node::Binary { op, left, right } => {
            let left_value = constant_value(left)?;
            let right_value = constant_value(right)?;
            let boolean = match *op {
                "eq" => Some(left_value == right_value),
                "ne" => Some(left_value != right_value),
                "ugt" => Some(left_value > right_value),
                "ult" => Some(left_value < right_value),
                "uge" => Some(left_value >= right_value),
                "ule" => Some(left_value <= right_value),
                _ => None,
            };
            if let Some(value) = boolean {
                return Some(BigUint::from(u8::from(value)));
            }
            let value = match *op {
                "add" => left_value + right_value,
                "sub" => (left_value + (&mask + BigUint::from(1u8))) - right_value,
                "mul" => left_value * right_value,
                "and" => left_value & right_value,
                "or" => left_value | right_value,
                "xor" => left_value ^ right_value,
                "udiv" if right_value != BigUint::from(0u8) => left_value / right_value,
                "shl" | "lshr" if right_value.bits() <= 32 => {
                    let shift = right_value.to_u32()?;
                    if shift >= expression.bits {
                        BigUint::from(0u8)
                    } else if *op == "shl" {
                        left_value << shift
                    } else {
                        left_value >> shift
                    }
                }
                _ => return None,
            };
            Some(value & mask)
        }
        Node::Ite {
            condition,
            then_value,
            else_value,
        } => match constant_value(condition)?.to_u8()? {
            0 => constant_value(else_value),
            1 => constant_value(then_value),
            _ => None,
        },
        _ => None,
    }
}
fn without_fields(value: Value, names: &std::collections::BTreeSet<String>) -> Value {
    match value {
        Value::Record(base, mut fields) => {
            fields.retain(|name, _| !names.contains(name));
            Value::Record(Box::new(without_fields(*base, names)), fields)
        }
        Value::Writes(base, writes) => Value::Writes(Box::new(without_fields(*base, names)), writes),
        Value::Choice(condition, left, right) => Value::Choice(condition,
            Box::new(without_fields(*left, names)), Box::new(without_fields(*right, names))),
        other => other,
    }
}
fn collect(
    value: Value,
    path: &[String],
    outputs: &mut BTreeMap<String, Expression>,
    memory_writes: &mut Vec<(Expression, Expression)>,
    opcode: u32,
    metadata: &mut [bool; 2],
    region_projection: bool,
) -> Result<()> {
    match value {
        Value::Choice(condition, left, right) => {
            let mut left_outputs = BTreeMap::new();
            let mut right_outputs = BTreeMap::new();
            let mut left_writes = Vec::new();
            let mut right_writes = Vec::new();
            let mut left_metadata = [false; 2];
            let mut right_metadata = [false; 2];
            collect(*left, path, &mut left_outputs, &mut left_writes, opcode, &mut left_metadata, region_projection)?;
            collect(*right, path, &mut right_outputs, &mut right_writes, opcode, &mut right_metadata, region_projection)?;
            if left_writes != right_writes || left_metadata != right_metadata {
                return Err(format!("conditional aggregate changes memory or instruction identity: writes {}/{}, metadata {:?}/{:?}", left_writes.len(), right_writes.len(), left_metadata, right_metadata));
            }
            let keys: std::collections::BTreeSet<_> = left_outputs.keys().chain(right_outputs.keys()).cloned().collect();
            for name in keys {
                let bits = left_outputs.get(&name).or_else(|| right_outputs.get(&name)).unwrap().bits;
                let original = Expression { bits, node: Node::Register { name: name.clone() } };
                let left = left_outputs.remove(&name).unwrap_or_else(|| original.clone());
                let right = right_outputs.remove(&name).unwrap_or(original);
                let Value::Scalar(merged) = merge_value(condition.clone(), Value::Scalar(left), Value::Scalar(right))? else { unreachable!() };
                if outputs.insert(name, merged).is_some() { return Err("duplicate conditional output".into()); }
            }
            memory_writes.extend(left_writes);
            for i in 0..2 { metadata[i] |= left_metadata[i]; }
        }
        Value::Input(input) if input == path => (),
        Value::Record(base, fields) => {
            let shadowed = fields.keys().cloned().collect();
            collect(without_fields(*base, &shadowed), path, outputs, memory_writes, opcode, metadata, region_projection)?;
            for (name, value) in fields {
                let mut p = path.to_vec();
                p.push(name);
                collect(value, &p, outputs, memory_writes, opcode, metadata, region_projection)?;
            }
        }
        Value::Array(base, elements) => {
            collect(*base, path, outputs, memory_writes, opcode, metadata, region_projection)?;
            for (index, value) in elements {
                let mut p = path.to_vec();
                p.push(index.to_string());
                collect(value, &p, outputs, memory_writes, opcode, metadata, region_projection)?;
            }
        }
        Value::Writes(base, writes) => {
            collect(*base, path, outputs, memory_writes, opcode, metadata, region_projection)?;
            memory_writes.extend(writes);
        }
        Value::Scalar(e) if path == ["__ThisInstr"] => {
            if e.bits != 32 || constant_value(&e) != Some(BigUint::from(opcode)) {
                return Err("specialized instruction bytes do not match request".into());
            }
            metadata[0] = true;
        }
        Value::Scalar(e) if path == ["__BranchTaken"] => {
            if e.bits != 1 { return Err("invalid branch effect".into()); }
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
        Value::Scalar(_) if region_projection && (path == ["__ExclusiveMonitorAddr"] || path == ["__ExclusiveLocal"]) => {
            ()
        }
        Value::Scalar(e) => {
            let mapped = register(path, e.bits)?;
            let Node::Register { name } = mapped.node else {
                unreachable!()
            };
            let e = if path.first().is_some_and(|field| field == "_Z") {
                Expression {
                    bits: 128,
                    node: Node::Slice {
                        value: Box::new(e),
                        start: 0,
                    },
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegionRequest {
    schema: u32,
    entry_pc: String,
    instructions: Vec<RegionInstruction>,
    exit_pcs: Vec<String>,
    max_steps: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegionInstruction {
    pc: String,
    instruction: String,
}
#[derive(Serialize)]
struct RegionOutcome {
    exit_pc: String,
    activation: Expression,
    guards: Vec<Expression>,
    outputs: BTreeMap<String, Expression>,
    memory_reads: Vec<MemoryRead>,
    memory_writes: Vec<MemoryWrite>,
    monitor_event: &'static str,
}
#[derive(Serialize)]
struct MemoryRead {
    address: Expression,
    bits: u32,
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
#[derive(Default, Serialize)]
struct StageProfile {
    requests: u64,
    load_seconds: f64,
    decode_seconds: f64,
    configuration_seconds: f64,
    instruction_seconds: f64,
    export_seconds: f64,
    class_hits: u64,
    class_misses: u64,
    opcode_hits: u64,
    cache_seconds: f64,
    cached_entries_bytes_peak: u64,
}
impl StageProfile {
    fn report(&self) {
        if std::env::var_os("FOCACCIA_ORACLE_PROFILE").is_some() {
            eprintln!(
                "FOCACCIA_ORACLE_PROFILE {}",
                serde_json::to_string(self).unwrap()
            );
        }
    }
}

struct ConfigurationCache<'m> {
    // This immutable source fixes specification and configuration identity for
    // the cache lifetime. No opcode, PC or runtime operand is bound here.
    source: &'m Module<TypedMeta>,
    dczid_el0: Option<u64>,
    capacity: usize,
    classes: std::collections::VecDeque<(String, std::sync::Arc<Module<TypedMeta>>, u64)>,
    opcodes: HashMap<u32, String>,
    opcode_order: std::collections::VecDeque<u32>,
    entries_bytes: u64,
}
impl<'m> ConfigurationCache<'m> {
    fn new(source: &'m Module<TypedMeta>, dczid_el0: Option<u64>) -> Result<Self> {
        let capacity = std::env::var("FOCACCIA_ORACLE_CLASS_CACHE")
            .unwrap_or_else(|_| "16".into())
            .parse::<usize>()
            .map_err(|_| "invalid class cache capacity")?;
        if capacity > 64 {
            return Err("class cache capacity exceeds 64".into());
        }
        Ok(Self {
            source,
            dczid_el0,
            capacity,
            classes: Default::default(),
            opcodes: HashMap::new(),
            opcode_order: Default::default(),
            entries_bytes: 0,
        })
    }
    fn classify(
        &mut self,
        opcode: u32,
        profile: &mut StageProfile,
    ) -> Result<(String, Option<Module<TypedMeta>>)> {
        let start = std::time::Instant::now();
        let result = if self.capacity == 0 {
            let (name, module) = specializer::specializer::prune_to_iclass(self.source, opcode);
            (name, Some(module))
        } else if let Some(name) = self.opcodes.get(&opcode) {
            profile.opcode_hits += 1;
            (name.clone(), None)
        } else {
            // Use the specification decoder, not handwritten masks or an
            // external disassembler. Pruning is postponed until a class miss.
            let classes = specializer::specializer::classify_iclasses(self.source, [opcode]);
            if classes.len() != 1 {
                return Err("instruction class did not resolve".into());
            }
            let name = classes[0].0.clone();
            if self.opcodes.len() >= 1024 {
                let old = self.opcode_order.pop_front().unwrap();
                self.opcodes.remove(&old);
            }
            self.opcodes.insert(opcode, name.clone());
            self.opcode_order.push_back(opcode);
            (name, None)
        };
        profile.decode_seconds += start.elapsed().as_secs_f64();
        Ok(result)
    }
    fn configured(
        &mut self,
        name: &str,
        pruned: Option<Module<TypedMeta>>,
        profile: &mut StageProfile,
    ) -> Result<std::sync::Arc<Module<TypedMeta>>> {
        if let Some(index) = self.classes.iter().position(|(n, _, _)| n == name) {
            let entry = self.classes.remove(index).unwrap();
            let result = entry.1.clone();
            self.classes.push_back(entry);
            profile.class_hits += 1;
            return Ok(result);
        }
        profile.class_misses += 1;
        let start = std::time::Instant::now();
        let pruned = match pruned {
            Some(module) => module,
            None => {
                let id = self
                    .source
                    .get_id_from_name(name)
                    .ok_or("missing semantic class")?;
                specializer::specializer::prune_to_iclass_fid(self.source, id).1
            }
        };
        profile.decode_seconds += start.elapsed().as_secs_f64();
        let start = std::time::Instant::now();
        let mut conf = pruned.clone();
        if let Some(value) = self.dczid_el0 {
            let mut arch = (*pruned.arch()).clone();
            let pin = arch
                .config
                .pins
                .iter_mut()
                .find(|pin| pin.path == ["DCZID_EL0"])
                .ok_or("DCZID_EL0 pin missing from architecture profile")?;
            pin.value = tir::arch::PinValue::Literal(format!("{value:b}"));
            // In this existing EL0/no-EL2 execution profile, SCTLR_EL1.DZE
            // governs user DC ZVA access. DZP=0 permits DC ZVA; DZP=1
            // prohibits it. Derive only this effective permission bit from
            // the independently observed DCZID value; this is not a claim
            // that privileged SCTLR_EL1 was read from the tracee.
            let dze = u64::from(value & 0x10 == 0);
            let sctlr = arch
                .config
                .pins
                .iter_mut()
                .find(|pin| pin.path == ["SCTLR_EL1"])
                .ok_or("SCTLR_EL1 pin missing from architecture profile")?;
            let tir::arch::PinValue::Literal(bits) = &sctlr.value else {
                return Err(
                    "SCTLR_EL1 must have a literal pin for native EL0 configuration".into(),
                );
            };
            let mut sctlr_value =
                u64::from_str_radix(bits, 2).map_err(|_| "invalid SCTLR_EL1 profile pin")?;
            sctlr_value = (sctlr_value & !(1 << 14)) | (dze << 14);
            sctlr.value = tir::arch::PinValue::Literal(format!("{sctlr_value:064b}"));
            conf.arch = Some(std::sync::Arc::new(arch));
        }
        let pins = KnownState::config_defaults(conf.arch());
        let fold_source = conf.clone();
        let folded: HashMap<VarId, TypedExpr> =
            specializer::evaluator::conf_fold_all(&fold_source, &pins, &mut conf)
                .into_iter()
                .collect();
        for declaration in &mut conf.entries {
            if let Decl::Func { id, body, .. } = declaration {
                if let Some(folded) = folded.get(id) {
                    *body = folded.clone();
                }
            }
        }
        profile.configuration_seconds += start.elapsed().as_secs_f64();
        let start = std::time::Instant::now();
        let conf = std::sync::Arc::new(conf);
        if self.capacity > 0 {
            // Bound both class count and serialized declaration volume. This
            // is a representation budget, not an assertion about heap RSS.
            let bytes = bincode::serialized_size(&conf.entries).map_err(|e| e.to_string())?;
            const BUDGET: u64 = 32 * 1024 * 1024;
            if bytes <= BUDGET {
                while self.classes.len() >= self.capacity || self.entries_bytes + bytes > BUDGET {
                    let (_, _, size) = self.classes.pop_front().unwrap();
                    self.entries_bytes -= size;
                }
                self.entries_bytes += bytes;
                self.classes.push_back((name.into(), conf.clone(), bytes));
                profile.cached_entries_bytes_peak =
                    profile.cached_entries_bytes_peak.max(self.entries_bytes);
            }
        }
        profile.cache_seconds += start.elapsed().as_secs_f64();
        Ok(conf)
    }
}

fn transform(
    cache: &mut ConfigurationCache<'_>,
    pc: u64,
    bytes: &[u8],
    profile: &mut StageProfile,
) -> Result<Transition> {
    profile.requests += 1;
    let typed = cache.source;
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
    let (iclass, pruned) = cache.classify(opcode, profile)?;
    let native_integer_or_vector = cache.dczid_el0.is_some()
        && matches!(iclass.as_str(), "decode_aarch64_vector_logical" | "decode_aarch64_float_convert_int");
    if !CLASSES.contains(&iclass.as_str()) && !native_integer_or_vector {
        return Err(format!("unsupported instruction class {iclass}"));
    }
    if iclass == "decode_aarch64_memory_exclusive_single"
        || iclass == "decode_aarch64_system_monitors"
    {
        return Err("exclusive-monitor instruction requires a bounded source region".into());
    }
    match iclass.as_str() {
        "decode_aarch64_system_hints" if opcode != 0xd503_201f => {
            return Err("unsupported system hint outside the audited NOP fixture".into());
        }
        "decode_aarch64_integer_arithmetic_div" if cache.dczid_el0.is_none() && opcode != 0x9ad7_0843 => {
            return Err("unsupported divide outside the audited Lua UDIV fixture".into());
        }
        "decode_aarch64_integer_conditional_compare_register" if cache.dczid_el0.is_none() && opcode != 0xfa46_1062 => {
            return Err(
                "unsupported conditional compare outside the audited Lua CCMP fixture".into(),
            );
        }
        "decode_aarch64_integer_arithmetic_mul_widening_32_64"
            if cache.dczid_el0.is_none() && ![0x9bb3_7ee0, 0x9bba_7f85, 0x9ba0_7f80].contains(&opcode) =>
        {
            return Err(
                "unsupported widening multiply outside the audited Lua UMULL fixture".into(),
            );
        }
        "decode_aarch64_integer_arithmetic_mul_uniform_add_sub"
            if cache.dczid_el0.is_none() && ![0x9b00_7ec0, 0x9b19_1060].contains(&opcode) =>
        {
            return Err("unsupported multiply opcode outside the audited Lua MUL fixture".into());
        }
        "decode_aarch64_memory_atomicops_ld" if opcode != 0x3822_4020 => {
            return Err("unsupported atomic opcode outside the audited LDSMAXB fixture".into());
        }
        "decode_aarch64_memory_single_general_immediate_signed_offset_lda_stl"
            if opcode != 0xd95f_8020 =>
        {
            return Err("unsupported LDAPR/STLR opcode outside the audited LDAPUR fixture".into());
        }
        _ => {}
    }
    // Admission above is checked even on cache hits. In particular, caching
    // an audited opcode never admits its unaudited class siblings.
    let conf = cache.configured(&iclass, pruned, profile)?;
    let stage = std::time::Instant::now();
    let known = KnownState::usermode_at(conf.arch(), bytes, pc, pc);
    let mut output = (*conf).clone();
    let (parameter, body) =
        specializer::evaluator::specialize_state_fn(&conf, "interp", &known, &mut output)
            .ok_or("specialization failed")?;
    profile.instruction_seconds += stage.elapsed().as_secs_f64();
    let stage = std::time::Instant::now();
    let primitives = output
        .get_primitives()
        .map(|(id, _, _, p)| (id, p))
        .collect();
    let mut exporter = Exporter {
        source_trace: None,
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
    collect(value, &[], &mut outputs, &mut writes, opcode, &mut metadata, false)?;
    if metadata != [true; 2] || !outputs.contains_key("PC") {
        return Err("incomplete architectural transition".into());
    }
    profile.export_seconds += stage.elapsed().as_secs_f64();
    Ok(Transition {
        outputs,
        memory_writes: writes
            .into_iter()
            .map(|(address, value)| MemoryWrite { address, value })
            .collect(),
    })
}
fn expression_reads(expression: &Expression, reads: &mut Vec<MemoryRead>) {
    match &expression.node {
        Node::Memory { address } => {
            let read = MemoryRead {
                address: (**address).clone(),
                bits: expression.bits,
            };
            if !reads
                .iter()
                .any(|r| r.bits == read.bits && r.address == read.address)
            {
                reads.push(read);
            }
            expression_reads(address, reads);
        }
        Node::Binary { left, right, .. }
        | Node::Concat {
            high: left,
            low: right,
        } => {
            expression_reads(left, reads);
            expression_reads(right, reads);
        }
        Node::Unary { value, .. } | Node::Slice { value, .. } => expression_reads(value, reads),
        Node::Ite {
            condition,
            then_value,
            else_value,
        } => {
            expression_reads(condition, reads);
            expression_reads(then_value, reads);
            expression_reads(else_value, reads);
        }
        Node::Constant { .. } | Node::Register { .. } | Node::SourceUndefined => (),
    }
}
fn value_reads(value: &Value, reads: &mut Vec<MemoryRead>) {
    match value {
        Value::Choice(condition, left, right) => {
            expression_reads(condition, reads);
            value_reads(left, reads);
            value_reads(right, reads);
        }
        Value::Record(base, fields) => {
            value_reads(base, reads);
            for value in fields.values() {
                value_reads(value, reads);
            }
        }
        Value::Array(base, elements) => {
            value_reads(base, reads);
            for value in elements.values() {
                value_reads(value, reads);
            }
        }
        Value::Writes(base, writes) => {
            value_reads(base, reads);
            for (address, value) in writes {
                expression_reads(address, reads);
                expression_reads(value, reads);
            }
        }
        Value::Scalar(expression) | Value::IntegerExpr(expression) => {
            expression_reads(expression, reads)
        }
        Value::Input(_) | Value::ZeroBits(_) | Value::Integer(_) | Value::Enum(_, _) | Value::Unit | Value::Variant(..) => (),
    }
}
fn state_field(value: &Value, name: &str) -> Result<Value> {
    match value {
        Value::Record(base, fields) => fields
            .get(name)
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| state_field(base, name)),
        Value::Writes(base, _) => state_field(base, name),
        Value::Choice(condition, left, right) => merge_value(condition.clone(), state_field(left, name)?, state_field(right, name)?),
        Value::Input(path) => Ok(Value::Input({
            let mut p = path.clone();
            p.push(name.into());
            p
        })),
        _ => Err(format!("source State lacks field {name}")),
    }
}
fn state_bool(value: &Value, name: &str) -> Result<bool> {
    let Value::Scalar(expression) = state_field(value, name)? else {
        return Err(format!("source State field {name} is not scalar"));
    };
    if expression.bits != 1 {
        return Err(format!("source State field {name} is not boolean"));
    }
    match constant_value(&expression).and_then(|v| v.to_u8()) {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(format!("source State field {name} is not concrete")),
    }
}
fn clear_exclusive_monitor(state: Value) -> Value {
    Value::Record(
        Box::new(state),
        BTreeMap::from([(
            "__ExclusiveLocal".into(),
            Value::Scalar(constant(1, BigUint::from(0u8)).unwrap()),
        )]),
    )
}
fn and_expression(left: Expression, right: Expression) -> Result<Expression> {
    if constant_value(&left) == Some(BigUint::from(1u8)) { return Ok(right); }
    if constant_value(&right) == Some(BigUint::from(1u8)) { return Ok(left); }
    Ok(Expression { bits: 1, node: Node::Binary { op: "and", left: Box::new(left), right: Box::new(right) } })
}
fn not_expression(value: Expression) -> Expression {
    Expression { bits: 1, node: Node::Unary { op: "not", value: Box::new(value) } }
}
fn pc_targets(pc: &Expression, activation: &Expression) -> Result<Vec<(u64, Expression)>> {
    if let Some(value) = constant_value(pc).and_then(|v| v.to_u64()) { return Ok(vec![(value, activation.clone())]); }
    match &pc.node {
        Node::Ite { condition, then_value, else_value } => {
            if condition.bits != 1 { return Err("source branch condition is not boolean".into()); }
            let then_activation = and_expression((**condition).clone(), activation.clone())?;
            let else_activation = and_expression(not_expression((**condition).clone()), activation.clone())?;
            let mut targets = pc_targets(then_value, &then_activation)?;
            targets.extend(pc_targets(else_value, &else_activation)?);
            Ok(targets)
        }
        _ => Err("region has an unbounded or indirect control-flow target".into()),
    }
}
fn state_pc_expression(state: &Value) -> Result<Expression> {
    match state_field(state, "_PC")? {
        Value::Scalar(value) => Ok(value),
        Value::Input(path) => register(&path, 64),
        _ => Err("region input PC is not scalar".into()),
    }
}
fn split_state_choices(state: Value, activation: Expression, budget: &mut usize) -> Result<Vec<(Value, Expression)>> {
    *budget = budget.checked_sub(1).ok_or("region aggregate path budget exceeded")?;
    match state {
        Value::Choice(condition, left, right) => {
            let mut result = split_state_choices(*left, and_expression(activation.clone(), condition.clone())?, budget)?;
            result.extend(split_state_choices(*right, and_expression(activation, not_expression(condition))?, budget)?);
            Ok(result)
        }
        Value::Record(base, fields) => {
            let mut paths = split_state_choices(*base, activation, budget)?;
            for (name, value) in fields {
                let mut next = Vec::new();
                for (base, activation) in paths {
                    for (field, activation) in split_state_choices(value.clone(), activation, budget)? {
                        let updated = match base.clone() {
                            Value::Record(base, mut fields) => { fields.insert(name.clone(), field); Value::Record(base, fields) }
                            base => Value::Record(Box::new(base), BTreeMap::from([(name.clone(), field)])),
                        };
                        next.push((updated, activation));
                    }
                }
                paths = next;
            }
            Ok(paths)
        }
        Value::Writes(base, writes) => Ok(split_state_choices(*base, activation, budget)?.into_iter()
            .map(|(base, activation)| (Value::Writes(Box::new(base), writes.clone()), activation)).collect()),
        other => Ok(vec![(other, activation)]),
    }
}
#[derive(Clone)]
struct RegionPath {
    state: Value,
    pc: u64,
    activation: Expression,
    guards: Vec<Expression>,
    monitor_event: &'static str,
    visited: Vec<u64>,
    saw_store: bool,
    last_opcode: u32,
}
fn run_region(
    cache: &mut ConfigurationCache<'_>,
    request: RegionRequest,
    profile: &mut StageProfile,
) -> Result<(u64, Vec<u8>, Vec<RegionOutcome>)> {
    if request.schema != 1 || request.instructions.is_empty() || request.max_steps == 0
        || request.max_steps > 128 || request.instructions.len() > 128
        || request.exit_pcs.is_empty() || request.exit_pcs.len() > 8 {
        return Err("invalid bounded region request".into());
    }
    let entry_pc = request.entry_pc.parse::<u64>().map_err(|_| "invalid region entry_pc")?;
    let exits = request.exit_pcs.iter().map(|s| s.parse::<u64>().map_err(|_| "invalid exit_pc".to_owned())).collect::<Result<Vec<_>>>()?;
    let mut code = BTreeMap::new();
    for instruction in &request.instructions {
        let (pc, bytes) = decode_request(&instruction.pc, &instruction.instruction)?;
        if code.insert(pc, bytes).is_some() { return Err("duplicate region instruction PC".into()); }
    }
    let first = code.get(&entry_pc).cloned().ok_or("region entry instruction missing")?;
    let one = constant(1, BigUint::from(1u8))?;
    let entry_guard = Expression { bits: 1, node: Node::Binary {
        op: "eq", left: Box::new(register(&["_PC".into()], 64)?),
        right: Box::new(constant(64, BigUint::from(entry_pc))?),
    }};
    let mut pending = vec![RegionPath { state: Value::Input(vec![]), pc: entry_pc, activation: one,
        guards: vec![entry_guard], monitor_event: "none", visited: Vec::new(), saw_store: false, last_opcode: 0 }];
    let mut outcomes = Vec::new();
    let mut saw_load = false;
    let mut saw_store = false;
    let mut executed_pcs = Vec::new();
    let mut residual_budget = 1_000_000usize;
    let pure_classes = [
        "decode_aarch64_branch_conditional_cond",
        "decode_aarch64_integer_arithmetic_add_sub_immediate",
        "decode_aarch64_integer_arithmetic_add_sub_shiftedreg",
        "decode_aarch64_integer_bitfield",
        "decode_aarch64_integer_logical_shiftedreg",
        "decode_aarch64_memory_exclusive_single",
        "decode_aarch64_system_hints",
        "decode_aarch64_system_monitors",
    ];
    while let Some(mut path) = pending.pop() {
        if outcomes.len() + pending.len() > 16 { return Err("region path budget exceeded".into()); }
        if path.visited.len() >= request.max_steps { return Err("region step budget exceeded".into()); }
        if path.visited.contains(&path.pc) { return Err("region contains a loop".into()); }
        if !executed_pcs.contains(&path.pc) { executed_pcs.push(path.pc); }
        let bytes = code.get(&path.pc).ok_or("source branch leaves verified region CFG")?.clone();
        let opcode = u32::from_le_bytes(bytes.as_slice().try_into().unwrap());
        let (class, pruned) = cache.classify(opcode, profile)?;
        if !pure_classes.contains(&class.as_str()) {
            return Err(format!("region instruction is not admitted pure source class {class}"));
        }
        if (class == "decode_aarch64_system_hints" && opcode != 0xd503_201f)
            || (class == "decode_aarch64_system_monitors" && opcode != 0xd503_3f5f)
        {
            return Err("region admits only source-verified NOP or CLREX system instructions".into());
        }
        if !CLASSES.contains(&class.as_str()) {
            return Err(format!("unsupported region instruction class {class}"));
        }
        let conf = cache.configured(&class, pruned, profile)?;
        let known = KnownState::usermode_at(conf.arch(), &bytes, path.pc, path.pc);
        let mut output = (*conf).clone();
        let (parameter, body) = specializer::evaluator::specialize_state_fn(&conf, "interp", &known, &mut output)
            .ok_or("region instruction specialization failed")?;
        let primitives: HashMap<VarId, Primitive> = output.get_primitives().map(|(id, _, _, p)| (id, p)).collect();
        let incoming_pc = state_pc_expression(&path.state)?;
        let pc_guard = Expression { bits: 1, node: Node::Binary { op: "eq", left: Box::new(incoming_pc),
            right: Box::new(constant(64, BigUint::from(path.pc))?) }};
        path.guards.push(pc_guard);
        let mut exporter = Exporter { source_trace: None, primitives: primitives.clone(), budget: 50_000, assumptions: Vec::new() };
        let mut env = HashMap::from([(parameter, path.state.clone())]);
        let next_state = exporter.eval(&body, &mut env)?;
        residual_budget = residual_budget.checked_sub(50_000 - exporter.budget)
            .ok_or("region residual budget exceeded")?;
        let monitor_valid = state_bool(&next_state, "__ExclusiveLocal")?;
        if path.visited.is_empty() {
            if !class.contains("memory_exclusive") || !monitor_valid { return Err("region must begin with source-verified Load-Exclusive".into()); }
            saw_load = true;
        }
        let is_store = class.contains("memory_exclusive") && !monitor_valid;
        let mut result_states = vec![(next_state, path.monitor_event, path.saw_store)];
        if is_store {
            saw_store = true;
            if path.saw_store { return Err("region contains more than one Store-Exclusive attempt".into()); }
            result_states[0].2 = true;
            if state_bool(&path.state, "__ExclusiveLocal").unwrap_or(false) {
                let cleared = clear_exclusive_monitor(path.state.clone());
                let mut alt_exporter = Exporter { source_trace: None, primitives: primitives.clone(), budget: 50_000, assumptions: Vec::new() };
                let mut alt_env = HashMap::from([(parameter, cleared)]);
                let alt_state = alt_exporter.eval(&body, &mut alt_env)?;
                residual_budget = residual_budget.checked_sub(50_000 - alt_exporter.budget)
                    .ok_or("region residual budget exceeded")?;
                let alt_pc = state_field(&alt_state, "_PC")?;
                let Value::Scalar(alt_pc) = alt_pc else { return Err("clear alternative PC is not scalar".into()); };
                result_states.push((alt_state, "clear-before-store", true));
                if alt_pc.bits != 64 { return Err("clear alternative PC width mismatch".into()); }
            }
        }
        let mut expanded_states = Vec::new();
        let mut aggregate_budget = 4096;
        for (state, event, saw_store_path) in result_states {
            for (state, activation) in split_state_choices(state, path.activation.clone(), &mut aggregate_budget)? {
                expanded_states.push((state, event, saw_store_path, activation));
            }
        }
        for (state, event, saw_store_path, activation) in expanded_states {
            let Value::Scalar(out_pc) = state_field(&state, "_PC")? else { return Err("region PC is not scalar".into()); };
            let mut branch_targets = pc_targets(&out_pc, &activation)?;
            if branch_targets.is_empty() { return Err("source produced no region successor".into()); }
            for (target, activation) in branch_targets.drain(..) {
                if target <= path.pc && !exits.contains(&target) { return Err("region internal branch is not direct-forward".into()); }
                let mut next_path = path.clone();
                next_path.state = state.clone();
                next_path.pc = target;
                next_path.activation = activation;
                next_path.monitor_event = event;
                next_path.saw_store = saw_store_path;
                next_path.last_opcode = opcode;
                next_path.visited.push(path.pc);
                if exits.contains(&target) {
                    let mut reads = Vec::new(); value_reads(&state, &mut reads);
                    let mut outputs = BTreeMap::new(); let mut writes = Vec::new(); let mut metadata = [false; 2];
                    collect(state.clone(), &[], &mut outputs, &mut writes, opcode, &mut metadata, true)?;
                    outcomes.push(RegionOutcome { exit_pc: target.to_string(), activation: next_path.activation,
                        guards: next_path.guards, outputs, memory_reads: reads,
                        memory_writes: writes.into_iter().map(|(address,value)| MemoryWrite { address,value }).collect(),
                        monitor_event: event });
                } else {
                    if saw_store_path { return Err("region continues beyond first Store-Exclusive attempt".into()); }
                    if !code.contains_key(&target) { return Err("source branch target is not in verified CFG or exit set".into()); }
                    pending.push(next_path);
                }
            }
        }
    }
    if !saw_load || !saw_store || outcomes.is_empty() { return Err("region lacks bounded Load/Store-Exclusive outcome".into()); }
    if executed_pcs.len() != code.len() { return Err("region contains instructions unreachable from declared CFG".into()); }
    if outcomes.len() > 16 { return Err("region outcome path budget exceeded".into()); }
    Ok((entry_pc, first, outcomes))
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

#[cfg(not(focaccia_sail_only))]
mod kernel;
#[cfg(focaccia_sail)]
mod sail;

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).is_some_and(|arg| arg == "--export-sail-transitions") {
        #[cfg(focaccia_sail)]
        return sail::run(&args[2..]);
        #[cfg(not(focaccia_sail))]
        return Err("this TIR input lacks the Sail x86 source-profile API".into());
    }
    if args.len() == 2 && args[1] == "--jit-kernels" {
        #[cfg(not(focaccia_sail_only))]
        return kernel::run();
        #[cfg(focaccia_sail_only)]
        return Err("Sail-only diagnostic build has no native ARM JIT".into());
    }
    if args.len() == 2 && args[1] == "--help" {
        println!("usage: focaccia-tir-oracle <pc-decimal> <four-instruction-bytes-hex>\n       focaccia-tir-oracle --audit-classes < newline-delimited 'pc-decimal bytes-hex'\n       focaccia-tir-oracle --export-sail-transitions --module x86.tir [--pc DECIMAL --code HEX]");
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
    let (mode, dczid_el0) = if args.len() == 2
        && matches!(
            args[1].as_str(),
            "--audit-classes" | "--export-transitions" | "--export-regions"
        ) {
        (Some(args[1].as_str()), None)
    } else if args.len() == 4
        && matches!(
            args[1].as_str(),
            "--export-transitions" | "--export-regions"
        )
        && args[2] == "--dczid-el0"
    {
        let value = args[3]
            .parse::<u64>()
            .map_err(|_| "invalid --dczid-el0 value")?;
        if value > 31 || value & 0xf > 9 {
            return Err(
                "--dczid-el0 has an unsupported BS value (architectural maximum is 9)".into(),
            );
        }
        (Some(args[1].as_str()), Some(value))
    } else {
        (None, None)
    };
    if let Some(mode) = mode {
        let stage = std::time::Instant::now();
        let typed = configured_spec()?;
        let mut profile = StageProfile::default();
        profile.load_seconds = stage.elapsed().as_secs_f64();
        let mut cache = ConfigurationCache::new(&typed, dczid_el0)?;
        for (index, line) in std::io::stdin().lock().lines().enumerate() {
            let line = line.map_err(|error| error.to_string())?;
            if mode == "--export-regions" {
                let request: RegionRequest = serde_json::from_str(&line)
                    .map_err(|e| format!("invalid region request at line {}: {e}", index + 1))?;
                let echoed =
                    serde_json::from_str::<serde_json::Value>(&line).map_err(|e| e.to_string())?;
                let mut response = serde_json::json!({
                    "schema": 1, "architecture": "aarch64", "endianness": "little",
                    "tir_revision": env!("FOCACCIA_TIR_REVISION"),
                    "profile": if dczid_el0.is_some() { "aarch64-native-dczid-el0" } else { "aarch64-fullspec-el0" },
                    "request": echoed,
                });
                if let Some(value) = dczid_el0 {
                    response["configuration"] = serde_json::json!({"dczid_el0": value.to_string(), "dczva_el0_permitted": value & 0x10 == 0});
                }
                match run_region(&mut cache, request, &mut profile) {
                    Ok((pc, first, outcomes)) => {
                        response["status"] = "ok".into();
                        response["entry_pc"] = pc.to_string().into();
                        response["first_instruction"] = first
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>()
                            .into();
                        response["outcomes"] =
                            serde_json::to_value(outcomes).map_err(|e| e.to_string())?;
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
                std::io::stdout().flush().map_err(|e| e.to_string())?;
                continue;
            }
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() != 2 {
                return Err(format!("invalid batch input at line {}", index + 1));
            }
            let (pc, bytes) = decode_request(fields[0], fields[1])?;
            if bytes.len() != 4 || pc % 4 != 0 {
                return Err(format!("invalid batch instruction at line {}", index + 1));
            }
            if mode == "--audit-classes" {
                let opcode = u32::from_le_bytes(bytes.try_into().unwrap());
                let (class, _) = specializer::specializer::prune_to_iclass(&typed, opcode);
                println!("{pc} {} {class}", fields[1].to_ascii_lowercase());
            } else {
                let mut response = serde_json::json!({
                    "schema": 1, "architecture": "aarch64", "endianness": "little",
                    "pc": pc.to_string(), "instruction": fields[1].to_ascii_lowercase(),
                    "tir_revision": env!("FOCACCIA_TIR_REVISION"),
                    "profile": if dczid_el0.is_some() { "aarch64-native-dczid-el0" } else { "aarch64-fullspec-el0" },
                });
                if let Some(value) = dczid_el0 {
                    response["configuration"] = serde_json::json!({
                        "dczid_el0": value.to_string(),
                        "dczva_el0_permitted": value & 0x10 == 0,
                    });
                }
                match transform(&mut cache, pc, &bytes, &mut profile) {
                    Ok(transition) => {
                        response["status"] = "ok".into();
                        response["outputs"] =
                            serde_json::to_value(transition.outputs).map_err(|e| e.to_string())?;
                        response["memory_writes"] = serde_json::to_value(transition.memory_writes)
                            .map_err(|e| e.to_string())?;
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
                std::io::stdout().flush().map_err(|e| e.to_string())?;
            }
        }
        profile.report();
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
    let stage = std::time::Instant::now();
    let typed = configured_spec()?;
    let mut profile = StageProfile::default();
    profile.load_seconds = stage.elapsed().as_secs_f64();
    let mut cache = ConfigurationCache::new(&typed, None)?;
    match transform(&mut cache, pc, &bytes, &mut profile) {
        Ok(transition) => {
            response["status"] = "ok".into();
            response["outputs"] =
                serde_json::to_value(transition.outputs).map_err(|e| e.to_string())?;
            response["memory_writes"] =
                serde_json::to_value(transition.memory_writes).map_err(|e| e.to_string())?;
        }
        Err(reason) => {
            response["status"] = "unsupported".into();
            response["reason"] = reason.into();
        }
    }
    profile.report();
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

#[cfg(test)]
mod exporter_tests {
    use super::*;

    fn typed(typ: TypBase<TypedMeta>, kind: ExprKind<TypedMeta>) -> TypedExpr {
        TypedExpr {
            meta: TypedMeta { typ },
            kind,
        }
    }

    fn bits64() -> TypBase<TypedMeta> {
        TypBase::Bits(std::sync::Arc::new(typed(
            TypBase::Int,
            ExprKind::Lit(Lit::Int(64.into())),
        )))
    }

    fn bits_value(value: u64) -> TypedExpr {
        typed(
            bits64(),
            ExprKind::Lit(Lit::Bits(format!("{value:064b}").into())),
        )
    }

    fn assertion(value: bool, body: TypedExpr) -> TypedExpr {
        let condition = std::sync::Arc::new(typed(TypBase::Bool, ExprKind::Lit(Lit::Bool(value))));
        let rhs = std::sync::Arc::new(typed(TypBase::Unit, ExprKind::Assert { cond: condition }));
        typed(
            bits64(),
            ExprKind::Let {
                var: LExpr::Wildcard,
                typ: TypBase::Unit,
                rhs,
                body: std::sync::Arc::new(body),
            },
        )
    }

    fn exporter() -> Exporter {
        Exporter {
            source_trace: None,
            primitives: HashMap::new(),
            budget: 100,
            assumptions: Vec::new(),
        }
    }

    #[test]
    fn scalar_zero_widths_are_not_restricted_to_store_bytes() {
        for bits in [1u64, 3, 8, 64, 128, 4097] {
            let mut evaluator = exporter();
            let id = VarId::from_u32(1);
            evaluator.primitives.insert(id, Primitive::ZerosBits);
            let count =
                std::sync::Arc::new(typed(TypBase::Int, ExprKind::Lit(Lit::Int(bits.into()))));
            let expression = typed(
                TypBase::Bits(count.clone()),
                ExprKind::App {
                    fun: std::sync::Arc::new(typed(TypBase::Unit, ExprKind::Id(id))),
                    args: vec![(*count).clone()],
                },
            );
            let result = evaluator.eval(&expression, &mut HashMap::new());
            if bits > u64::from(MAX_BITS) {
                assert!(
                    result.is_err(),
                    "oversized store zeros must remain byte-aligned"
                );
            } else {
                let value = scalar(result.expect("valid scalar zero width")).unwrap();
                assert_eq!(value.bits, bits as u32);
                assert_eq!(constant_value(&value), Some(BigUint::from(0u8)));
            }
        }
    }

    #[test]
    fn constant_if_does_not_visit_false_assertion_branch() {
        let condition = std::sync::Arc::new(typed(TypBase::Bool, ExprKind::Lit(Lit::Bool(true))));
        let dead_branch = std::sync::Arc::new(assertion(false, bits_value(0)));
        let expression = typed(
            bits64(),
            ExprKind::If {
                cond: condition,
                then_body: std::sync::Arc::new(bits_value(42)),
                else_body: dead_branch,
            },
        );
        let value = exporter()
            .eval(&expression, &mut HashMap::new())
            .expect("unselected false assertion is unreachable");
        assert_eq!(
            constant_value(&scalar(value).unwrap()),
            Some(BigUint::from(42u8))
        );
    }

    #[test]
    fn source_fault_paths_are_guarded_but_unknown_semantics_are_rejected() {
        let id = VarId::from_u32(77);
        let condition = std::sync::Arc::new(typed(TypBase::Bool, ExprKind::Id(id)));
        let fault = typed(bits64(), ExprKind::Throw { exception: std::sync::Arc::new(typed(TypBase::Unit, ExprKind::Lit(Lit::Unit))) });
        let mut evaluator = exporter(); evaluator.source_trace = Some(SourceTrace::default());
        let mut env = HashMap::from([(id, Value::Scalar(Expression { bits: 1, node: Node::Register { name: "ZF".into() } }))]);
        let expression = typed(bits64(), ExprKind::If { cond: condition.clone(), then_body: std::sync::Arc::new(fault), else_body: std::sync::Arc::new(bits_value(7)) });
        let value = evaluator.eval(&expression, &mut env).unwrap();
        assert_eq!(constant_value(&scalar(value).unwrap()), Some(BigUint::from(7u8)));
        assert_eq!(evaluator.source_trace.as_ref().unwrap().guards.len(), 1);
        let unknown = typed(bits64(), ExprKind::App { fun: std::sync::Arc::new(typed(TypBase::Unit, ExprKind::Id(VarId::from_u32(78)))), args: Vec::new() });
        let expression = typed(bits64(), ExprKind::If { cond: condition, then_body: std::sync::Arc::new(unknown), else_body: std::sync::Arc::new(bits_value(7)) });
        assert!(evaluator.eval(&expression, &mut env).unwrap_err().contains("helper call"));
    }

    #[test]
    fn selected_true_assertion_is_retained_and_false_assertion_fails() {
        let mut exporter = exporter();
        let value = exporter
            .eval(&assertion(true, bits_value(9)), &mut HashMap::new())
            .expect("a proven true assertion succeeds");
        assert_eq!(
            constant_value(&scalar(value).unwrap()),
            Some(BigUint::from(9u8))
        );
        assert!(exporter
            .eval(&assertion(false, bits_value(9)), &mut HashMap::new())
            .is_err());
    }
}
