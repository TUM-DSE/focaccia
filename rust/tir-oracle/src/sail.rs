//! Source-only Sail bridge. Never consults a disassembler or trace poststate.
use super::*;

const PROFILE: &str = "sail-x86-usermode-v1";

fn profile_flag_guards(arch: &tir::arch::ArchProfile) -> Result<Vec<Expression>> {
    // These values are source-profile pins, not facts learned from poststate.
    // Make every observable RFLAGS pin a checked prestate assumption.
    let fields = [("zIF_flag", 9, 1), ("zIOPL", 12, 2), ("zTF", 8, 1),
        ("zNT", 14, 1), ("zRF", 16, 1), ("zAC_flag", 18, 1),
        ("zVIF", 19, 1), ("zVIP", 20, 1), ("zID", 21, 1)];
    let (mut mask, mut expected) = (0u64, 0u64);
    for (name, bit, width) in fields {
        let pins: Vec<_> = arch.config.pins.iter().filter(|pin| pin.path.len() == 1 && pin.path[0] == name).collect();
        if pins.len() != 1 { return Err(format!("missing/duplicate source profile flag pin {name}")); }
        let tir::arch::PinValue::Literal(value) = &pins[0].value else {
            return Err(format!("nonliteral source profile flag pin {name}"));
        };
        if value.len() != width || !value.bytes().all(|byte| matches!(byte, b'0' | b'1')) {
            return Err(format!("invalid source profile flag pin {name}"));
        }
        mask |= ((1u64 << width) - 1) << bit;
        expected |= u64::from_str_radix(value, 2).map_err(|_| "invalid profile flag literal")? << bit;
    }
    let register = |name: &str| Expression { bits: 64, node: Node::Register { name: name.into() } };
    let mask_expr = constant(64, BigUint::from(mask))?;
    Ok(vec![
        binary("eq", 1, binary("and", 64, register("__focaccia_known_RFLAGS"), mask_expr.clone()), mask_expr.clone()),
        binary("eq", 1, binary("and", 64, register("RFLAGS"), mask_expr), constant(64, BigUint::from(expected))?),
    ])
}
const GPRS: [&str; 16] = [
    "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13",
    "R14", "R15",
];

pub(super) fn input(path: &[String], bits: u32) -> Result<Expression> {
    let name = match path {
        [field, index] if field == "zGPR" && bits == 64 => {
            let index: usize = index.parse().map_err(|_| "invalid Sail GPR index")?;
            GPRS.get(index).ok_or("invalid Sail GPR index")?.to_string()
        }
        [field] if field == "zRIP" && bits == 64 => "RIP".into(),
        [bank, index, field]
            if bank == "zSegCache" && field == "zseg_base" && bits == 64 && index == "4" =>
        {
            "FS_BASE".into()
        }
        [bank, index, field]
            if bank == "zSegCache" && field == "zseg_base" && bits == 64 && index == "5" =>
        {
            "GS_BASE".into()
        }
        [field] if bits == 1 => {
            let bit = match field.as_str() {
                "zCF" => 0,
                "zPF" => 2,
                "zAF" => 4,
                "zZF" => 6,
                "zSF" => 7,
                "zDF" => 10,
                "zOF" => 11,
                _ => return Err(format!("unsupported Sail input {path:?}")),
            };
            return Ok(Expression {
                bits: 1,
                node: Node::Slice {
                    value: Box::new(Expression {
                        bits: 64,
                        node: Node::Register {
                            name: "RFLAGS".into(),
                        },
                    }),
                    start: bit,
                },
            });
        }
        _ => return Err(format!("unsupported Sail input {path:?}")),
    };
    Ok(Expression {
        bits,
        node: Node::Register { name },
    })
}

fn source(path: &str) -> Result<(Module<TypedMeta>, String)> {
    let path = path.to_owned();
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || source_inner(&path))
        .map_err(|e| e.to_string())?
        .join()
        .map_err(|_| "Sail source loading panicked".to_string())?
}
fn source_inner(path: &str) -> Result<(Module<TypedMeta>, String)> {
    // Hash the bytes actually parsed, not a mutable path or a git working tree.
    let bytes = std::fs::read(path).map_err(|e| format!("Sail module: {e}"))?;
    let mut child = std::process::Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("sha256sum: {e}"))?;
    child
        .stdin
        .take()
        .ok_or("sha256 stdin")?
        .write_all(&bytes)
        .map_err(|e| e.to_string())?;
    let digest = child.wait_with_output().map_err(|e| e.to_string())?;
    if !digest.status.success() {
        return Err("Sail source hashing failed".into());
    }
    let hash = String::from_utf8(digest.stdout)
        .map_err(|e| e.to_string())?
        .split_whitespace()
        .next()
        .ok_or("missing source hash")?
        .to_string();
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid source hash".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
    let mut seed = Module::default();
    tir::primitives::Primitives::new(&mut seed);
    let mut module =
        tir::parser::parse_module_with_seed(text, seed).map_err(|e| format!("Sail parse: {e}"))?;
    module.arch = Some(std::sync::Arc::new(
        frontend::adapters::sail::x86_64_profile(),
    ));
    let typed =
        tir::typecheck::tag_with_types(&module).map_err(|e| format!("Sail typecheck: {e}"))?;
    typed
        .arch()
        .validate(&typed)
        .map_err(|e| format!("Sail profile validation: {e:?}"))?;
    Ok((typed, hash))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    pc: String,
    code: String,
}

fn decode_buffer(pc: &str, raw: &str) -> Result<(u64, Vec<u8>)> {
    let pc = pc.parse::<u64>().map_err(|_| "invalid Sail PC")?;
    if raw.is_empty() || raw.len() > 30 || raw.len() % 2 != 0 || !raw.is_ascii() {
        return Err("Sail code buffer must contain 1..15 bytes".into());
    }
    let bytes = (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).map_err(|_| "invalid Sail hex".to_string()))
        .collect::<Result<Vec<_>>>()?;
    Ok((pc, bytes))
}
fn request(line: &str) -> Result<(u64, Vec<u8>)> {
    if line.trim_start().starts_with('{') {
        let r: Request =
            serde_json::from_str(line).map_err(|e| format!("invalid Sail request: {e}"))?;
        decode_buffer(&r.pc, &r.code)
    } else {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 2 {
            return Err("expected PC and code buffer".into());
        }
        decode_buffer(fields[0], fields[1])
    }
}

fn provenance(path: &str, hash: &str) -> Result<()> {
    let path = Path::new(path)
        .parent()
        .ok_or("Sail model has no provenance directory")?
        .join("provenance.json");
    let bytes = std::fs::read(path)
        .map_err(|_| "Sail source lacks immutable undefined-preservation provenance")?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| "invalid Sail source provenance")?;
    if value["schema"] != 1
        || value["architecture"] != "x86_64"
        || value["source"] != "sail-x86"
        || value["source_model_sha256"] != hash
        || value["undefined_values_preserved"] != true
        || value["undefined_representation"] != "sail_undefined_v1"
    {
        return Err("Sail source hash/undefined-preservation provenance mismatch".into());
    }
    Ok(())
}
fn emit(
    module: &Module<TypedMeta>,
    hash: &str,
    pc: u64,
    bytes: &[u8],
    provenance_error: Option<&str>,
) -> Result<()> {
    let mut response = serde_json::json!({
        "schema": 1, "architecture": "x86_64",
        "profile": PROFILE, "source_model_sha256": hash,
        "tir_revision": env!("FOCACCIA_TIR_REVISION"),
        "pc": pc.to_string(), "code": bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "status": "unsupported",
    });
    let result = match provenance_error {
        Some(reason) => Err(reason.to_string()),
        None => transform_source(module, pc, bytes),
    };
    match result {
        Ok(payload) => {
            response["status"] = "ok".into();
            for (key, value) in payload.as_object().ok_or("invalid Sail payload")? {
                response[key] = value.clone();
            }
        }
        Err(reason) => response["reason"] = reason.into(),
    }
    println!(
        "{}",
        serde_json::to_string(&response).map_err(|e| e.to_string())?
    );
    std::io::stdout().flush().map_err(|e| e.to_string())
}

fn transform_source(
    module: &Module<TypedMeta>,
    pc: u64,
    bytes: &[u8],
) -> Result<serde_json::Value> {
    if bytes.is_empty() || bytes.len() > 15 {
        return Err("Sail code buffer must contain 1..15 accessible bytes".into());
    }
    let end = pc
        .checked_add(bytes.len() as u64)
        .ok_or("Sail code buffer crosses address-space end")?;
    for (base, data) in &module.arch().config.known_memory {
        let config_end = base
            .checked_add(data.len() as u64)
            .ok_or("invalid Sail profile memory")?;
        if pc < config_end && *base < end {
            return Err("code buffer overlaps Sail profile memory".into());
        }
    }
    // Keep the profile's compliance checks intact. The strict shared entry
    // point disables both named-check and structural address assumptions.
    residual(module, pc, bytes)
}

fn residual(source: &Module<TypedMeta>, pc: u64, bytes: &[u8]) -> Result<serde_json::Value> {
    // Retain this one source-owned scratch output solely to certify consumed
    // bytes. This changes no execution semantics or configuration assumptions.
    let mut module = source.clone();
    let mut arch = (*source.arch()).clone();
    arch.state
        .scratch_fields
        .retain(|field| field != "zdecode_pos");
    module.arch = Some(std::sync::Arc::new(arch));
    let module = &module;
    let mut known = KnownState::usermode_at(module.arch(), bytes, pc, pc);
    // Explicit v1 execution profile: a running 64-bit Linux user process.
    // These enum pins are not expressible in the upstream scalar TOML table;
    // Validate their variants against this exact source before seeding them.
    for (field, enum_name, variant) in [
        ("zcur_mode", "ProcessorMode", "zProcessorMode_zLongMode"),
        ("zsystem_state", "SystemState", "zSystemState_zSysRunning"),
        ("zvendor", "Vendor", "zVendor_zVendor_Intel"),
        (
            "zdelivering_exc_class",
            "ExceptionClass",
            "zExceptionClass_zEC_Benign",
        ),
    ] {
        if !module
            .get_enum(enum_name)
            .ok_or("missing Sail profile enum")?
            .iter()
            .any(|(name, _)| name == variant)
        {
            return Err("Sail execution-profile enum mismatch".into());
        }
        known.pin_value(
            tir::state::StateAddr::field(field),
            specializer::specializer::KnownStateValue::Literal(variant.into()),
        );
    }
    let mut output = module.clone();
    let (parameter, body) = specializer::evaluator::specialize_state_fn_strict(
        module,
        &module.arch().code.step_fn,
        &known,
        &mut output,
    )
    .ok_or("Sail source step specialization failed")?;
    let mut exporter = Exporter {
        source_trace: Some(SourceTrace::default()),
        primitives: output
            .get_primitives()
            .map(|(id, _, _, p)| (id, p))
            .collect(),
        budget: 100_000,
        assumptions: Vec::new(),
    };
    let state = exporter.eval(
        &body,
        &mut HashMap::from([(parameter, Value::Input(vec![]))]),
    )?;
    let mut outputs = BTreeMap::new();
    let mut decoded_end = None;
    collect_source(state, &[], &mut outputs, &mut decoded_end)?;
    let decoded_end = decoded_end.ok_or("source did not certify fetch end")?;
    let length = decoded_end
        .checked_sub(pc)
        .ok_or("source fetch moved before instruction")?;
    if length == 0 || length > bytes.len() as u64 {
        return Err("source fetched outside supplied code buffer".into());
    }
    if !outputs.contains_key("RIP") {
        return Err("source omitted RIP output".into());
    }
    let mut defined_masks = BTreeMap::new();
    for (name, value) in &outputs {
        defined_masks.insert(name.clone(), definedness(value)?);
    }
    let trace = exporter
        .source_trace
        .take()
        .ok_or("missing source effect trace")?;
    let mut guards = profile_flag_guards(module.arch())?;
    for guard in trace.guards {
        guards.push(binary("eq", 1, definedness(&guard)?, full(guard.bits)?));
        guards.push(lower_unknown(guard)?);
    }
    guards.push(binary(
        "eq",
        1,
        defined_masks.get("RIP").ok_or("missing RIP mask")?.clone(),
        full(64)?,
    ));
    let mut reads = Vec::new();
    for (address, bits, condition, write_prefix) in trace.reads {
        guards.push(binary("eq", 1, definedness(&condition)?, full(1)?));
        reads.push(serde_json::json!({ "address_mask": definedness(&address)?, "address": lower_unknown(address)?,
            "bits": bits, "condition": lower_unknown(condition)?, "write_prefix": write_prefix }));
    }
    let mut writes = Vec::new();
    for (address, value, condition) in trace.writes {
        guards.push(binary("eq", 1, definedness(&condition)?, full(1)?));
        writes.push(serde_json::json!({ "address_mask": definedness(&address)?, "value_mask": definedness(&value)?,
            "address": lower_unknown(address)?, "value": lower_unknown(value)?, "condition": lower_unknown(condition)? }));
    }
    let outputs = outputs
        .into_iter()
        .map(|(name, value)| Ok((name, lower_unknown(value)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(
        serde_json::json!({ "length": length, "outputs": outputs, "defined_masks": defined_masks,
        "guards": guards, "memory_reads": reads, "memory_writes": writes,
        // This exporter admits only a complete source State->State step, not
        // an Intel micro-step or OS-service handoff. Certify that boundary in
        // the shared x86 control vocabulary so the existing TB engine can
        // consume this source without manufacturing controls in Python.
        "control": { "repeat": constant(1, BigUint::from(0u8))?,
                     "environment_cutpoint": constant(1, BigUint::from(0u8))? },
        "control_masks": { "repeat": full(1)?, "environment_cutpoint": full(1)? } }),
    )
}

fn collect_source(
    value: Value,
    path: &[String],
    outputs: &mut BTreeMap<String, Expression>,
    decoded_end: &mut Option<u64>,
) -> Result<()> {
    match value {
        // Source step resets next_rip before every read and folds it into RIP
        // before return. Its payload/conditional scratch is not boundary state.
        _ if path == ["znext_rip"] => (),
        Value::Input(input) if input == path => (),
        Value::Record(base, fields) => {
            let shadowed = fields.keys().cloned().collect();
            collect_source(without_fields(*base, &shadowed), path, outputs, decoded_end)?;
            for (field, value) in fields {
                let mut path = path.to_vec();
                path.push(field);
                collect_source(value, &path, outputs, decoded_end)?;
            }
        }
        Value::Array(base, fields) => {
            collect_source(*base, path, outputs, decoded_end)?;
            for (index, value) in fields {
                let mut path = path.to_vec();
                path.push(index.to_string());
                collect_source(value, &path, outputs, decoded_end)?;
            }
        }
        Value::Scalar(value) if path == ["zdecode_pos"] => {
            *decoded_end = Some(
                constant_value(&value)
                    .and_then(|v| v.to_u64())
                    .ok_or("dynamic source fetch end")?,
            );
        }
        Value::Scalar(value) if path == ["zinsn_start"] => {
            if constant_value(&value).is_none() {
                return Err("dynamic source instruction start".into());
            }
        }
        Value::Scalar(value) => {
            let mapped = input(path, value.bits)?;
            let (name, value) = match mapped.node {
                Node::Register { name } => (name, value),
                Node::Slice { value: base, start } if value.bits == 1 => {
                    let previous = outputs.remove("RFLAGS").unwrap_or(*base);
                    let preserve = constant(
                        64,
                        ((BigUint::from(1u8) << 64) - BigUint::from(1u8))
                            ^ (BigUint::from(1u8) << start),
                    )?;
                    let extended = Expression {
                        bits: 64,
                        node: Node::Concat {
                            high: Box::new(constant(63, BigUint::from(0u8))?),
                            low: Box::new(value),
                        },
                    };
                    let inserted = binary("shl", 64, extended, constant(64, BigUint::from(start))?);
                    (
                        "RFLAGS".into(),
                        binary("or", 64, binary("and", 64, previous, preserve), inserted),
                    )
                }
                _ => return Err("unsupported source output mapping".into()),
            };
            // Ordered RAM effects are emitted from the shared evaluator's
            // source journal, not reconstructed from output-expression order.
            outputs.insert(name, value);
        }
        Value::Writes(base, _) if path.is_empty() || path == ["zmem_base"] => {
            collect_source(*base, path, outputs, decoded_end)?
        }
        Value::Choice(condition, left, right) if path.is_empty() => {
            let mut lhs = outputs.clone();
            let mut rhs = outputs.clone();
            let mut lhs_end = *decoded_end;
            let mut rhs_end = *decoded_end;
            collect_source(*left, path, &mut lhs, &mut lhs_end)?;
            collect_source(*right, path, &mut rhs, &mut rhs_end)?;
            if lhs_end != rhs_end {
                return Err("path-dependent Sail instruction length".into());
            }
            *decoded_end = lhs_end;
            let names: std::collections::BTreeSet<_> =
                lhs.keys().chain(rhs.keys()).cloned().collect();
            for name in names {
                let identity = Expression {
                    bits: 64,
                    node: Node::Register { name: name.clone() },
                };
                let left = lhs.remove(&name).unwrap_or_else(|| identity.clone());
                let right = rhs.remove(&name).unwrap_or(identity);
                if left.bits != right.bits {
                    return Err("inconsistent source branch output widths".into());
                }
                outputs.insert(
                    name,
                    Expression {
                        bits: left.bits,
                        node: Node::Ite {
                            condition: Box::new(condition.clone()),
                            then_value: Box::new(left),
                            else_value: Box::new(right),
                        },
                    },
                );
            }
        }
        _ => return Err(format!("unsupported Sail architectural update {path:?}")),
    }
    Ok(())
}

fn lower_unknown(value: Expression) -> Result<Expression> {
    let bits = value.bits;
    let node = match value.node {
        Node::SourceUndefined => return constant(bits, BigUint::from(0u8)),
        Node::Binary { op, left, right } => Node::Binary {
            op,
            left: Box::new(lower_unknown(*left)?),
            right: Box::new(lower_unknown(*right)?),
        },
        Node::Unary { op, value } => Node::Unary {
            op,
            value: Box::new(lower_unknown(*value)?),
        },
        Node::Concat { high, low } => Node::Concat {
            high: Box::new(lower_unknown(*high)?),
            low: Box::new(lower_unknown(*low)?),
        },
        Node::Slice { value, start } => Node::Slice {
            value: Box::new(lower_unknown(*value)?),
            start,
        },
        Node::Ite {
            condition,
            then_value,
            else_value,
        } => Node::Ite {
            condition: Box::new(lower_unknown(*condition)?),
            then_value: Box::new(lower_unknown(*then_value)?),
            else_value: Box::new(lower_unknown(*else_value)?),
        },
        Node::Memory { address } => Node::Memory {
            address: Box::new(lower_unknown(*address)?),
        },
        other => other,
    };
    Ok(Expression { bits, node })
}
fn binary(op: &'static str, bits: u32, left: Expression, right: Expression) -> Expression {
    Expression {
        bits,
        node: Node::Binary {
            op,
            left: Box::new(left),
            right: Box::new(right),
        },
    }
}
fn full(bits: u32) -> Result<Expression> {
    constant(bits, (BigUint::from(1u8) << bits) - BigUint::from(1u8))
}
// Conservatively propagate source-input definedness. In particular, an
// identity GPR is not known merely because the source left it unchanged.
fn definedness(value: &Expression) -> Result<Expression> {
    // A source flag update replaces exactly one packed bit. Derive its mask
    // compositionally rather than expanding generic AND/OR dependencies over
    // the complete previous RFLAGS value (which grows exponentially).
    if value.bits == 64 {
        if let Node::Binary {
            op: "or",
            left,
            right,
        } = &value.node
        {
            if let (
                Node::Binary {
                    op: "and",
                    left: previous,
                    right: preserve,
                },
                Node::Binary {
                    op: "shl",
                    left: inserted,
                    right: amount,
                },
            ) = (&left.node, &right.node)
            {
                if let Node::Concat { high, low } = &inserted.node {
                    if let Some(shift) = constant_value(amount)
                        .and_then(|n| n.to_u32())
                        .filter(|n| *n < 64)
                    {
                        let expected = ((BigUint::from(1u8) << 64) - BigUint::from(1u8))
                            ^ (BigUint::from(1u8) << shift);
                        if high.bits == 63
                            && low.bits == 1
                            && constant_value(high) == Some(BigUint::from(0u8))
                            && constant_value(preserve) == Some(expected)
                        {
                            let inserted_mask = Expression {
                                bits: 64,
                                node: Node::Concat {
                                    high: Box::new(constant(63, BigUint::from(0u8))?),
                                    low: Box::new(definedness(low)?),
                                },
                            };
                            return Ok(binary(
                                "or",
                                64,
                                binary("and", 64, definedness(previous)?, (**preserve).clone()),
                                binary("shl", 64, inserted_mask, (**amount).clone()),
                            ));
                        }
                    }
                }
            }
        }
    }
    Ok(match &value.node {
        Node::SourceUndefined => constant(value.bits, BigUint::from(0u8))?,
        Node::Constant { .. } => full(value.bits)?,
        Node::Register { name } => Expression {
            bits: value.bits,
            node: Node::Register {
                name: format!("__focaccia_known_{name}"),
            },
        },
        Node::Slice { value: base, start } => Expression {
            bits: value.bits,
            node: Node::Slice {
                value: Box::new(definedness(base)?),
                start: *start,
            },
        },
        Node::Concat { high, low } => Expression {
            bits: value.bits,
            node: Node::Concat {
                high: Box::new(definedness(high)?),
                low: Box::new(definedness(low)?),
            },
        },
        Node::Binary { op, left, right }
            if matches!(*op, "and" | "or" | "xor")
                && left.bits == value.bits
                && right.bits == value.bits =>
        {
            let lm = definedness(left)?;
            let rm = definedness(right)?;
            let both = binary("and", value.bits, lm.clone(), rm.clone());
            if *op == "xor" {
                both
            } else {
                let mut lv = lower_unknown((**left).clone())?;
                let mut rv = lower_unknown((**right).clone())?;
                if *op == "and" {
                    lv = Expression {
                        bits: value.bits,
                        node: Node::Unary {
                            op: "not",
                            value: Box::new(lv),
                        },
                    };
                    rv = Expression {
                        bits: value.bits,
                        node: Node::Unary {
                            op: "not",
                            value: Box::new(rv),
                        },
                    };
                }
                binary(
                    "or",
                    value.bits,
                    both,
                    binary(
                        "or",
                        value.bits,
                        binary("and", value.bits, lm, lv),
                        binary("and", value.bits, rm, rv),
                    ),
                )
            }
        }
        Node::Binary { op, left, right }
            if matches!(*op, "shl" | "lshr") && constant_value(right).is_some() =>
        {
            let shifted = binary(*op, value.bits, definedness(left)?, (**right).clone());
            let occupied = binary(*op, value.bits, full(value.bits)?, (**right).clone());
            let padding = Expression {
                bits: value.bits,
                node: Node::Unary {
                    op: "not",
                    value: Box::new(occupied),
                },
            };
            binary("or", value.bits, shifted, padding)
        }
        Node::Binary { left, right, .. } => {
            let left_known = binary("eq", 1, definedness(left)?, full(left.bits)?);
            let right_known = binary("eq", 1, definedness(right)?, full(right.bits)?);
            Expression {
                bits: value.bits,
                node: Node::Ite {
                    condition: Box::new(binary("and", 1, left_known, right_known)),
                    then_value: Box::new(full(value.bits)?),
                    else_value: Box::new(constant(value.bits, BigUint::from(0u8))?),
                },
            }
        }
        Node::Unary {
            op: "not",
            value: operand,
        } if operand.bits == value.bits => definedness(operand)?,
        Node::Unary { value: operand, .. } => {
            let known = binary("eq", 1, definedness(operand)?, full(operand.bits)?);
            Expression {
                bits: value.bits,
                node: Node::Ite {
                    condition: Box::new(known),
                    then_value: Box::new(full(value.bits)?),
                    else_value: Box::new(constant(value.bits, BigUint::from(0u8))?),
                },
            }
        }
        Node::Ite {
            condition,
            then_value,
            else_value,
        } => {
            let condition_known = binary("eq", 1, definedness(condition)?, full(condition.bits)?);
            let branches = Expression {
                bits: value.bits,
                node: Node::Ite {
                    condition: Box::new(lower_unknown((**condition).clone())?),
                    then_value: Box::new(definedness(then_value)?),
                    else_value: Box::new(definedness(else_value)?),
                },
            };
            Expression {
                bits: value.bits,
                node: Node::Ite {
                    condition: Box::new(condition_known),
                    then_value: Box::new(branches),
                    else_value: Box::new(constant(value.bits, BigUint::from(0u8))?),
                },
            }
        }
        Node::Memory { address } => {
            // Captured prestate RAM is defined; the shared native pipeline
            // rejects every undefined store, so no unknown memory promotion is
            // possible. A load through an unknown address remains unknown.
            let known_address = binary("eq", 1, definedness(address)?, full(address.bits)?);
            Expression {
                bits: value.bits,
                node: Node::Ite {
                    condition: Box::new(known_address),
                    then_value: Box::new(full(value.bits)?),
                    else_value: Box::new(constant(value.bits, BigUint::from(0u8))?),
                },
            }
        }
    })
}

pub(super) fn run(args: &[String]) -> Result<()> {
    if args.len() < 2 || args[0] != "--module" {
        return Err(
            "usage: --export-sail-transitions --module x86.tir [--pc DECIMAL --code HEX]".into(),
        );
    }
    let (module, hash) = source(&args[1])?;
    let provenance_error = provenance(&args[1], &hash).err();
    if args.len() == 6 && args[2] == "--pc" && args[4] == "--code" {
        let (pc, bytes) = decode_buffer(&args[3], &args[5])?;
        return emit(&module, &hash, pc, &bytes, provenance_error.as_deref());
    }
    if args.len() != 2 {
        return Err("invalid Sail exporter arguments".into());
    }
    for line in std::io::stdin().lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        let (pc, bytes) = request(&line)?;
        emit(&module, &hash, pc, &bytes, provenance_error.as_deref())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requests_have_no_poststate_channel() {
        assert!(request(r#"{"pc":"4096","code":"4801d8","outputs":{}}"#).is_err());
        assert_eq!(
            request(r#"{"pc":"4096","code":"4801d8"}"#).unwrap(),
            (4096, vec![0x48, 1, 0xd8])
        );
    }
    #[test]
    fn identity_definedness_is_not_invented() {
        let value = input(&["zGPR".into(), "0".into()], 64).unwrap();
        assert!(
            matches!(definedness(&value).unwrap().node, Node::Register { name } if name == "__focaccia_known_RAX")
        );
        assert!(input(&["zUnknownState".into()], 64).is_err());
    }
    #[test]
    fn source_profile_never_silently_drops_checks() {
        let profile = frontend::adapters::sail::x86_64_profile();
        assert!(!profile.code.compliance_checks.is_empty());
    }
    #[test]
    fn source_backed_closed_residuals() {
        let Ok(path) = std::env::var("FOCACCIA_SAIL_TEST_MODULE") else {
            return;
        };
        let (module, hash) = source(&path).unwrap();
        assert_eq!(hash.len(), 64);
        for (bytes, reads, writes) in [
            (&[0x48, 0x01, 0xd8][..], 0, 0),
            (&[0x48, 0x31, 0xc0][..], 0, 0),
            (&[0x48, 0x8b, 0x03][..], 1, 0),
            (&[0x48, 0x89, 0x03][..], 0, 1),
            (&[0xeb, 0x00][..], 0, 0),
        ] {
            let value = transform_source(&module, 4096, bytes)
                .unwrap_or_else(|reason| panic!("source {bytes:02x?}: {reason}"));
            assert_eq!(value["length"], bytes.len());
            assert!(value["outputs"].get("RIP").is_some());
            assert_eq!(value["memory_reads"].as_array().unwrap().len(), reads);
            assert_eq!(value["memory_writes"].as_array().unwrap().len(), writes);
            if reads + writes > 0 {
                assert!(value["guards"].as_array().unwrap().len() > 1);
            }
        }
        // Constant-producing and arithmetic x87 instructions are outside this
        // source subset. Strict PE must not replace their host FP helpers with
        // hardware-derived constants that sneak past residual admission.
        for bytes in [&[0xd9, 0xe8][..], &[0xd9, 0xfa][..]] {
            assert!(transform_source(&module, 4096, bytes).is_err());
        }
    }
    #[test]
    fn source_specialization_diagnostic() {
        // Diagnostic only: this deliberately bypasses admission, never the CLI.
        // It exercises the actual shared evaluator/exporter against source.
        let Ok(path) = std::env::var("FOCACCIA_SAIL_TEST_MODULE") else {
            return;
        };
        let (module, _) = source(&path).unwrap();
        for (name, bytes) in [
            ("add", &[0x48, 0x01, 0xd8][..]),
            ("xor", &[0x48, 0x31, 0xc0][..]),
        ] {
            let value = residual(&module, 4096, bytes)
                .unwrap_or_else(|reason| panic!("source {name}: {reason}"));
            assert_eq!(value["length"], 3);
            assert!(value["outputs"].get("RAX").is_some());
            assert!(value["outputs"].get("RFLAGS").is_some());
            assert!(value["outputs"].get("RIP").is_some());
        }
    }
}
