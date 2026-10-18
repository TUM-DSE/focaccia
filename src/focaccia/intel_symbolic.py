"""Intel adapters for source-owned symbolic transition residuals.

This module intentionally contains no x86 instruction semantics. The source
exporter supplies expression DAGs; this module binds them to the shared
``SymbolicTransform``/``boundary_oracle`` pipeline and to independently
captured pre-boundary observations.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import json
import re

from miasm.expression.expression import (
    Expr, ExprCompose, ExprCond, ExprId, ExprInt, ExprMem, ExprOp, ExprSlice,
)

from .arch.x86 import ArchX86
from .miasm_util import expr_simp, expression_children, iter_expression_dag
from .boundary_oracle import (
    BoundaryPrediction, compare as compare_boundary, predict as predict_boundary,
)
from .snapshot import MemoryAccessError, ReadableProgramState, RegisterAccessError
from .symbolic import (
    MemoryWrite, SymbolEvaluationError, SymbolicCompositionError,
    SymbolicTransform, SymbolicTransformComposer, _TransformEvaluator,
    knownness_symbol,
)
from .tir_backend import _ExpressionDecoder


PROFILE = "intel-usermode-qemu64-v1"
GPR_OUTPUTS = (
    "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
)
XMM_OUTPUTS = tuple(f"XMM{i}" for i in range(16))
REQUIRED_OUTPUTS = (*GPR_OUTPUTS, "RIP", "RFLAGS", *XMM_OUTPUTS, "FS_BASE", "GS_BASE")
_REGISTER_CONTRACT = {
    **{name: 64 for name in (*GPR_OUTPUTS, "RIP", "FS_BASE", "GS_BASE")},
    "RFLAGS": 64,
    **{name: 128 for name in XMM_OUTPUTS},
}
_KNOWNNESS_REGISTER_CONTRACT = {
    **{f"__focaccia_known_{name}": 64
       for name in (*GPR_OUTPUTS, "RIP", "RFLAGS", "FS_BASE", "GS_BASE")},
    **{f"__focaccia_known_ZMM{i}": 512 for i in range(16)},
}


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate Intel residual field {key!r}")
        result[key] = value
    return result


def _fields(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("unexpected Intel residual fields")
    return value


def _slice_expr(expression: Expr, start: int, stop: int) -> Expr:
    if not 0 <= start < stop <= expression.size:
        raise ValueError("invalid expression slice")
    if start == 0 and stop == expression.size:
        return expression
    width = stop - start
    if isinstance(expression, ExprInt):
        return ExprInt((int(expression) >> start) & ((1 << width) - 1), width)
    if isinstance(expression, ExprCompose):
        parts = []
        offset = 0
        for part in expression.args:
            low, high = max(start, offset), min(stop, offset + part.size)
            if low < high:
                parts.append(_slice_expr(part, low - offset, high - offset))
            offset += part.size
        if not parts:
            raise ValueError("empty composed expression slice")
        return parts[0] if len(parts) == 1 else ExprCompose(*parts)
    return ExprSlice(expression, start, stop)


def _normalize_mask_slices(expression: Expr) -> Expr:
    """Narrow bitwise definedness expressions before Miasm constant folding.

    The Intel contract supplies whole ZMM512 knownness masks, while most
    observable XMM masks immediately project their low128 bits. Splitting a
    projected bitwise operation before evaluation avoids Miasm's unsupported
    512-bit host-width constant-folding path without changing the source DAG's
    bitvector semantics.
    """
    results: dict[int, Expr] = {}
    pending = [(expression, False)]
    while pending:
        node, expanded = pending.pop()
        key = id(node)
        if key in results:
            continue
        children = expression_children(node)
        if not expanded and children:
            pending.append((node, True))
            pending.extend((child, False) for child in reversed(children)
                           if id(child) not in results)
            continue
        args = tuple(results[id(child)] for child in children)
        if isinstance(node, (ExprId, ExprInt)):
            normalized = node
        elif isinstance(node, ExprSlice):
            source = args[0]
            if isinstance(source, ExprOp) and source.op in ("&", "|", "^"):
                if any(argument.size != source.size for argument in source.args):
                    raise ValueError("bitwise mask operation width mismatch")
                normalized = ExprOp(source.op, *(
                    _slice_expr(argument, node.start, node.stop)
                    for argument in source.args
                ))
            elif isinstance(source, ExprCond):
                normalized = ExprCond(
                    source.cond,
                    _slice_expr(source.src1, node.start, node.stop),
                    _slice_expr(source.src2, node.start, node.stop),
                )
            elif isinstance(source, ExprCompose):
                normalized = _slice_expr(source, node.start, node.stop)
            elif isinstance(source, ExprSlice):
                normalized = _slice_expr(source.arg, source.start + node.start,
                                          source.start + node.stop)
            else:
                normalized = ExprSlice(source, node.start, node.stop)
        elif isinstance(node, ExprMem):
            normalized = ExprMem(args[0], node.size)
        elif isinstance(node, ExprCond):
            normalized = ExprCond(args[0], args[1], args[2])
        elif isinstance(node, ExprCompose):
            normalized = ExprCompose(*args)
        elif isinstance(node, ExprOp):
            normalized = ExprOp(node.op, *args)
        else:
            normalized = node
        results[key] = normalized
    return results[id(expression)]


class IntelSymbolicBackend:
    """Request and cache source-specialized residuals for exact XED instructions."""

    def __init__(self, oracle, model_sha256: str):
        if not isinstance(model_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", model_sha256) is None:
            raise ValueError("Intel source model hash must be lowercase SHA-256.")
        self.oracle = oracle
        self.model_sha256 = model_sha256
        self.cache = {}
        self.requests = 0

    def specialize(self, instruction):
        code = bytes(instruction.code)
        fields = dict(instruction.fields)
        request = {
            "op": "symbolic_instruction", "profile": PROFILE,
            "pc": str(instruction.pc), "code": code.hex(),
            "iform": instruction.iform, "operand_size": instruction.operand_size,
            "address_size": instruction.address_size, "fields": fields,
        }
        cache_key = json.dumps(request, sort_keys=True, separators=(",", ":"))
        if cache_key in self.cache:
            return self.cache[cache_key]
        response = self.oracle.checked(request)
        result = response.get("result")
        if not isinstance(result, dict):
            raise SymbolEvaluationError("Intel symbolic exporter returned no residual object.")
        residual = decode_intel_residual(
            json.dumps(result, separators=(",", ":"), allow_nan=False),
            pc=instruction.pc, code=code, iform=instruction.iform,
            model_sha256=self.model_sha256,
        )
        self.cache[cache_key] = residual
        self.requests += 1
        return residual


@dataclass(frozen=True, slots=True)
class IntelOrderedEffect:
    """One ordered source store, including lazy conditional definedness."""

    address: Expr
    value: Expr
    address_mask: Expr
    value_mask: Expr
    condition: Expr | None = None

    def __post_init__(self) -> None:
        if self.address.size != 64:
            raise ValueError("Intel store addresses must be 64-bit expressions.")
        if self.value.size <= 0 or self.value.size % 8:
            raise ValueError("Intel store values must have a positive byte width.")
        if self.address_mask.size != self.address.size or self.value_mask.size != self.value.size:
            raise ValueError("Intel store definedness widths do not match their values.")
        if self.condition is not None and self.condition.size != 1:
            raise ValueError("Intel store conditions must be one-bit expressions.")


@dataclass(frozen=True, slots=True)
class IntelReadEffect:
    """A source read ordered after ``write_prefix`` prior write slots."""

    address: Expr
    address_mask: Expr
    byte_count: int
    condition: Expr
    write_prefix: int

    def __post_init__(self) -> None:
        if self.address.size != 64 or self.address_mask.size != 64:
            raise ValueError("Intel read addresses and masks must be 64-bit.")
        if type(self.byte_count) is not int or not 1 <= self.byte_count <= 512:
            raise ValueError("Intel read width must be between 1 and 512 bytes.")
        if self.condition.size != 1 or type(self.write_prefix) is not int or self.write_prefix < 0:
            raise ValueError("Invalid Intel read condition or source prefix.")


@dataclass(frozen=True, slots=True)
class IntelProjectedReadEffect:
    """One source read projected to the block source and its ordered prefix."""

    condition: Expr
    address: Expr
    address_mask: Expr
    byte_count: int
    write_prefix: int


@dataclass(frozen=True, slots=True)
class IntelInstructionResidual:
    """Decoded source outputs and metadata for one exact instruction."""

    pc: int
    length: int
    outputs: Mapping[str, Expr]
    defined_masks: Mapping[str, Expr]
    guards: tuple[Expr, ...] = ()
    effects: tuple[IntelOrderedEffect, ...] = ()
    # Non-architectural source controls stay outside SymbolicTransform. They
    # include Next_IP, repeat/cutpoint state and saved syscall-entry state.
    controls: Mapping[str, Expr] | None = None
    control_masks: Mapping[str, Expr] | None = None
    read_effects: tuple[IntelReadEffect, ...] = ()

    def __post_init__(self) -> None:
        if type(self.pc) is not int or not 0 <= self.pc < 1 << 64:
            raise ValueError("Intel residual PC must be an unsigned 64-bit address.")
        if type(self.length) is not int or not 1 <= self.length <= 15:
            raise ValueError("Intel residual instruction length must be between 1 and 15.")
        if not self.outputs:
            raise ValueError("Intel residual must contain architectural outputs.")
        if set(self.outputs) != set(self.defined_masks):
            raise ValueError("Every Intel architectural output needs an explicit source mask.")
        arch = ArchX86()
        for name, expression in self.outputs.items():
            canonical = arch.to_regname(name)
            accessor = arch.get_reg_accessor(canonical) if canonical else None
            if accessor is None or accessor.num_bits != expression.size:
                raise ValueError(f"Unsupported Intel output register/width: {name}.")
            if self.defined_masks[name].size != expression.size:
                raise ValueError(f"Intel output mask width mismatch: {name}.")
        if any(guard.size != 1 for guard in self.guards):
            raise ValueError("Intel source guards must be one-bit expressions.")
        if any(effect.write_prefix > len(self.effects) for effect in self.read_effects):
            raise ValueError("Intel read effect references a future write prefix.")
        controls = self.controls or {}
        control_masks = self.control_masks or {}
        if set(controls) != set(control_masks):
            raise ValueError("Every Intel source-control output needs an explicit mask.")
        if any(not isinstance(name, str) or not name or not isinstance(expr, Expr)
               or control_masks[name].size != expr.size
               for name, expr in controls.items()):
            raise ValueError("Invalid Intel source-control expression or mask.")

    def to_transform(self, tid: int, arch: ArchX86 | None = None) -> SymbolicTransform:
        """Build a source-owned transform while retaining ordered store entries."""
        arch = arch or ArchX86()
        registers = {}
        masks = {}
        source_outputs = dict(self.outputs)
        source_masks = dict(self.defined_masks)
        if "RIP" not in source_outputs and self.controls is not None and "next_ip" in self.controls:
            source_outputs["RIP"] = self.controls["next_ip"]
            source_masks["RIP"] = (self.control_masks or {})["next_ip"]
        for name, expression in source_outputs.items():
            canonical = arch.to_regname(name)
            if canonical is None:
                raise SymbolicCompositionError(f"Unsupported Intel output {name!r}.")
            accessor = arch.get_reg_accessor(canonical)
            if accessor is None:
                raise SymbolicCompositionError(f"Missing Intel output accessor for {name!r}.")
            identity_mask = knownness_symbol(accessor.base_reg,
                arch.get_reg_accessor(accessor.base_reg).num_bits)
            if accessor.start or accessor.end != identity_mask.size:
                identity_mask = ExprSlice(identity_mask, accessor.start, accessor.end)
            actual_mask = expr_simp(source_masks[name])
            if (expression == ExprId(canonical, expression.size)
                    and actual_mask == identity_mask):
                # An identity value with exactly inherited source knownness is
                # not a transition. Dropping it preserves all observation-view
                # projections while avoiding repeated identity register writes.
                continue
            registers[ExprId(canonical, expression.size)] = expression
            masks[canonical] = source_masks[name]
        transform = SymbolicTransform(
            tid, registers, [], arch, self.pc, self.pc + self.length,
            defined_masks=masks, guards=tuple(self.guards), source_owned=True,
        )
        # Effects are an ordered sequence, not a destination-keyed map: two
        # stores to the same symbolic address are distinct source effects.
        transform.memory_writes.extend(
            MemoryWrite(effect.address, effect.value, effect.address_mask,
                        effect.value_mask, effect.condition)
            for effect in self.effects
        )
        return transform


def decode_intel_residual(text: str, *, pc: int, code: bytes, iform: str,
                          model_sha256: str) -> IntelInstructionResidual:
    """Decode a schema-2 Intel source residual; reject identity/profile drift.

    The compiler's operation-specific wire is intentionally validated against
    the exact XED form and immutable source-model hash. This parser is kept
    separate from the live driver so synthetic fixtures exercise the same
    importer used by production.
    """
    if len(text) > 16 * 1024 * 1024:
        raise SymbolEvaluationError("Intel residual exceeds the size limit.")
    try:
        response = json.loads(text, object_pairs_hook=_pairs)
        common = {"schema", "architecture", "profile", "pc", "code", "iform", "model_sha256",
                  "status"}
        if not isinstance(response, dict):
            raise ValueError("Intel residual must be an object")
        status = response.get("status")
        if status == "unsupported":
            _fields(response, common | {"reason"})
            reason = response["reason"]
            if not isinstance(reason, str) or not reason or len(reason) > 4096:
                raise ValueError("malformed unsupported residual diagnostic")
            raise SymbolEvaluationError(f"Intel source residual unsupported: {reason}")
        if status != "ok":
            raise ValueError("Unknown Intel residual status")
        required = common | {"outputs", "defined_masks", "guards", "ordered_effects",
                             "control", "control_masks"}
        optional = {"definitions"}
        syscall_fields = {"syscall_pre", "syscall_pre_masks"}
        if (not isinstance(response, dict) or not required <= set(response)
                or set(response) - required - optional - syscall_fields
                or bool(syscall_fields & set(response))
                and not syscall_fields <= set(response)):
            raise ValueError("unexpected or incomplete Intel residual fields")
        if (type(response["schema"]) is not int or response["schema"] != 2
                or response["architecture"] != "x86_64" or response["profile"] != PROFILE
                or response["pc"] != str(pc) or response["code"] != code.hex()
                or response["iform"] != iform or response["model_sha256"] != model_sha256
                or re.fullmatch(r"[0-9a-f]{64}", model_sha256) is None):
            raise ValueError("Intel residual identity/profile does not match request")
        expression_nodes = 0
        pending_nodes = [response]
        while pending_nodes:
            node = pending_nodes.pop()
            if isinstance(node, dict):
                if "kind" in node:
                    expression_nodes += 1
                    if expression_nodes > 65_536:
                        raise ValueError("Intel residual expression budget exceeded")
                pending_nodes.extend(node.values())
            elif isinstance(node, list):
                pending_nodes.extend(node)
        effects_raw = response["ordered_effects"]
        if not isinstance(effects_raw, list) or len(effects_raw) > 4096:
            raise ValueError("Malformed Intel ordered effects")
        write_count = sum(1 for entry in effects_raw
                          if isinstance(entry, dict) and entry.get("kind") == "write")
        if write_count > 4096:
            raise ValueError("Intel residual exceeds the ordered-write limit")
        all_registers = _REGISTER_CONTRACT | _KNOWNNESS_REGISTER_CONTRACT
        decoder = _ExpressionDecoder(
            registers=all_registers, allow_vector_zero_extension=False,
            memory_prefix_limit=write_count,
            definitions=response.get("definitions"),
            definition_registers=all_registers,
            definition_memory_prefix_limit=write_count,
        )

        def decode_expression(node, prefix_limit, *, allow_knownness=False):
            decoder.registers = all_registers if allow_knownness else _REGISTER_CONTRACT
            decoder.memory_prefix_limit = prefix_limit
            expression = decoder.decode(node)
            return _normalize_mask_slices(expression) if allow_knownness else expression

        def parse_map(value, *, allowed=None, prefix_limit, allow_knownness=False):
            if not isinstance(value, dict):
                raise ValueError("Intel expression map must be an object")
            result = {}
            for name, node in value.items():
                if not isinstance(name, str) or (allowed is not None and name not in allowed):
                    raise ValueError("Unsupported Intel expression key")
                result[name] = decode_expression(node, prefix_limit,
                                                  allow_knownness=allow_knownness)
            return result

        outputs = parse_map(response["outputs"], allowed=set(_REGISTER_CONTRACT),
                            prefix_limit=write_count)
        masks = parse_map(response["defined_masks"], allowed=set(outputs),
                          prefix_limit=write_count, allow_knownness=True)
        if not outputs or set(outputs) != set(masks):
            raise ValueError("Intel outputs and masks must have identical nonempty keys")
        if "RIP" not in outputs:
            raise ValueError("Intel residual must include architectural RIP output")
        guards_raw = response["guards"]
        if not isinstance(guards_raw, list) or len(guards_raw) > 256:
            raise ValueError("Malformed Intel guard list")
        guards = tuple(decode_expression(item, write_count, allow_knownness=True)
                       for item in guards_raw)
        effects = []
        read_effects = []
        write_ordinal = 0
        for entry in effects_raw:
            if not isinstance(entry, dict) or entry.get("kind") not in ("read", "write"):
                raise ValueError("Malformed Intel ordered effect")
            kind = entry["kind"]
            expected = ({"kind", "condition", "address", "address_mask", "bytes"}
                        if kind == "read" else
                        {"kind", "condition", "address", "address_mask", "bytes", "value", "value_mask"})
            _fields(entry, expected)
            # Prefix ordinals count prior writes only. Inactive guarded stores
            # still occupy one slot; a store cannot observe its own output.
            prefix_limit = write_ordinal
            address = decode_expression(entry["address"], prefix_limit)
            address_mask = decode_expression(entry["address_mask"], prefix_limit,
                                              allow_knownness=True)
            condition = decode_expression(entry["condition"], prefix_limit,
                                          allow_knownness=True)
            byte_count = entry["bytes"]
            if type(byte_count) is not int or not 1 <= byte_count <= 512:
                raise ValueError("Invalid Intel effect byte count")
            if address.size != 64 or address_mask.size != 64 or condition.size != 1:
                raise ValueError("Intel effect address/condition width mismatch")
            if kind == "read":
                read_effects.append(IntelReadEffect(
                    address, address_mask, byte_count, condition, write_ordinal,
                ))
                continue
            value = decode_expression(entry["value"], prefix_limit)
            value_mask = decode_expression(entry["value_mask"], prefix_limit,
                                           allow_knownness=True)
            if value.size != byte_count * 8 or value_mask.size != value.size:
                raise ValueError("Intel store byte count/value width mismatch")
            effects.append(IntelOrderedEffect(address, value, address_mask, value_mask, condition))
            write_ordinal += 1
        control = parse_map(response["control"], allowed={"next_ip", "repeat", "environment_cutpoint"},
                            prefix_limit=write_count)
        control_masks = parse_map(response["control_masks"], allowed=set(control),
                                  prefix_limit=write_count, allow_knownness=True)
        if set(control) != {"next_ip", "repeat", "environment_cutpoint"} or set(control) != set(control_masks):
            raise ValueError("Missing Intel source-control output or mask")
        if control["next_ip"].size != 64 or control["repeat"].size != 1 or control["environment_cutpoint"].size != 1:
            raise ValueError("Intel source-control widths are invalid")
        syscall_pre = parse_map(response.get("syscall_pre", {}),
                                allowed=set(_REGISTER_CONTRACT), prefix_limit=write_count)
        syscall_pre_masks = parse_map(response.get("syscall_pre_masks", {}),
                                      allowed=set(syscall_pre), prefix_limit=write_count,
                                      allow_knownness=True)
        if set(syscall_pre) != set(syscall_pre_masks):
            raise ValueError("Intel syscall-prestate outputs/masks mismatch")
        controls = dict(control)
        control_masks_full = dict(control_masks)
        for name, expression in syscall_pre.items():
            controls[f"syscall_pre.{name}"] = expression
            control_masks_full[f"syscall_pre.{name}"] = syscall_pre_masks[name]
        return IntelInstructionResidual(pc, len(code), outputs, masks, guards, tuple(effects),
                                        controls, control_masks_full, tuple(read_effects))
    except SymbolEvaluationError:
        raise
    except (ValueError, KeyError, TypeError, RecursionError) as error:
        raise SymbolEvaluationError(f"Invalid Intel source residual: {error}") from error


def compose_intel_residuals(residuals, tid: int, arch: ArchX86 | None = None):
    """Compose a nonempty contiguous residual sequence with shared core logic."""
    iterator = iter(residuals)
    try:
        first = next(iterator)
    except StopIteration as error:
        raise ValueError("Cannot compose an empty Intel residual sequence.") from error
    composer = SymbolicTransformComposer(first.to_transform(tid, arch))
    for residual in iterator:
        composer.append(residual.to_transform(tid, arch))
    return composer.finish()


def _control_projection(residual: IntelInstructionResidual, name: str, tid: int,
                        *, pc: int | None = None, include_effects: bool = True):
    controls = residual.controls or {}
    masks = residual.control_masks or {}
    expression, mask = controls[name], masks[name]
    if name.startswith("syscall_pre."):
        destination = name.removeprefix("syscall_pre.")
    else:
        destination = {"next_ip": "RIP", "repeat": "CF",
                       "environment_cutpoint": "CF"}[name]
    arch = ArchX86()
    canonical = arch.to_regname(destination)
    accessor = arch.get_reg_accessor(canonical) if canonical else None
    if accessor is None or accessor.num_bits != expression.size:
        raise SymbolicCompositionError(f"Intel control width does not match {destination}.")
    transform = SymbolicTransform(
        tid, {ExprId(canonical, expression.size): expression}, [], arch,
        residual.pc if pc is None else pc,
        (residual.pc if pc is None else pc) + residual.length,
        defined_masks={canonical: mask}, guards=(), source_owned=True,
    )
    if include_effects:
        transform.memory_writes.extend(
            MemoryWrite(effect.address, effect.value, effect.address_mask,
                        effect.value_mask, effect.condition)
            for effect in residual.effects
        )
    return transform, canonical


def _contains_memory_read(expression: Expr) -> bool:
    return any(
        isinstance(node, ExprMem)
        or getattr(node, "op", None) == "focaccia_memory_byte"
        for node in iter_expression_dag(expression)
    )


def _composed_register_expressions(transform: SymbolicTransform, register: str):
    arch = transform.arch
    canonical = arch.to_regname(register)
    accessor = arch.get_reg_accessor(canonical) if canonical else None
    if accessor is None:
        raise SymbolicCompositionError(f"Unsupported projected register {register}.")
    base_accessor = arch.get_reg_accessor(accessor.base_reg)
    if base_accessor is None:
        raise SymbolicCompositionError(f"Missing base accessor for {register}.")
    base_value = transform.changed_regs.get(
        accessor.base_reg, ExprId(accessor.base_reg, base_accessor.num_bits),
    )
    base_mask = transform.defined_masks.get(
        accessor.base_reg, knownness_symbol(accessor.base_reg, base_accessor.num_bits),
    )
    value = (base_value if accessor.start == 0 and accessor.end == base_value.size
             else ExprSlice(base_value, accessor.start, accessor.end))
    mask = (base_mask if accessor.start == 0 and accessor.end == base_mask.size
            else ExprSlice(base_mask, accessor.start, accessor.end))
    return value, mask


def _evaluate_composed_register(transform: SymbolicTransform, register: str,
                                state: ReadableProgramState,
                                knownness_inputs: Mapping[str, int]) -> int:
    value, mask = _composed_register_expressions(transform, register)
    # Only an output cone containing a deferred read needs ordered-store
    # evaluation. Source guards and writes remain on the real block transform
    # and are validated before the guest advances.
    needs_memory = _contains_memory_read(value) or _contains_memory_read(mask)
    writes = transform.memory_writes if needs_memory else []
    evaluator = _TransformEvaluator(state, writes, dict(knownness_inputs))
    defined = transform._eval_source_definedness(
        mask, state, dict(knownness_inputs), evaluator, write_prefix=len(writes),
    )
    full = (1 << mask.size) - 1
    if defined != full:
        raise SymbolEvaluationError(f"Projected Intel register {canonical} has undefined mask inputs.")
    mask_value = evaluator.evaluate(mask)
    if mask_value != full:
        raise SymbolEvaluationError(f"Projected Intel register {canonical} is not fully defined.")
    return evaluator.evaluate(value)


def _compose_prefix_projection(projection: SymbolicTransform, *,
                               prefix_transforms=(), prefix_composer=None,
                               register_names=None):
    if prefix_composer is not None:
        project = getattr(prefix_composer, "source_projection", None)
        if callable(project):
            return project(projection, register_names=register_names)
        composer = prefix_composer.fork()
        composer.append(projection)
        return composer.finish()
    if not prefix_transforms:
        return projection
    composer = SymbolicTransformComposer(prefix_transforms[0])
    for previous in prefix_transforms[1:]:
        composer.append(previous)
    composer.append(projection)
    return composer.finish()


def predict_residual_register(residual: IntelInstructionResidual, register: str,
                              state: ReadableProgramState,
                              knownness_inputs: Mapping[str, int], tid: int, *,
                              prefix_transforms=(), prefix_composer=None,
                              pc: int | None = None):
    """Evaluate one architectural output from the source step, not an environment control."""
    arch = ArchX86()
    canonical = arch.to_regname(register)
    expression = next((value for name, value in residual.outputs.items()
                       if arch.to_regname(name) == canonical), None)
    mask = next((value for name, value in residual.defined_masks.items()
                 if arch.to_regname(name) == canonical), None)
    if canonical is None or expression is None or mask is None:
        raise SymbolEvaluationError(f"Intel residual omitted architectural output {register}.")
    full_mask = (1 << expression.size) - 1
    if isinstance(expression, ExprInt) and isinstance(mask, ExprInt) and int(mask) == full_mask:
        # Immediate architectural successors (e.g. fallthrough or direct
        # branches) do not depend on the composed prefix. Guards/effects remain
        # attached to the real step and are checked by final block prediction.
        return int(expression)
    start = residual.pc if pc is None else pc
    projection = SymbolicTransform(
        tid, {ExprId(canonical, expression.size): expression}, [], arch,
        start, start + residual.length, defined_masks={canonical: mask},
        guards=(), source_owned=True,
    )
    projection.memory_writes.extend(
        MemoryWrite(effect.address, effect.value, effect.address_mask,
                    effect.value_mask, effect.condition)
        for effect in residual.effects
    )
    composed = _compose_prefix_projection(
        projection, prefix_transforms=prefix_transforms,
        prefix_composer=prefix_composer, register_names=(canonical,),
    )
    composed.guards = ()
    return _evaluate_composed_register(composed, canonical, state, knownness_inputs)


def predict_residual_control(residual: IntelInstructionResidual, name: str,
                             state: ReadableProgramState, knownness_inputs: Mapping[str, int],
                             tid: int, *, prefix_transforms=(), prefix_composer=None,
                             pc: int | None = None):
    """Evaluate one source control via a temporary shared source-owned output."""
    expression = (residual.controls or {}).get(name)
    mask = (residual.control_masks or {}).get(name)
    if (isinstance(expression, ExprInt) and isinstance(mask, ExprInt)
            and int(mask) == (1 << expression.size) - 1):
        # Literal controls are prefix-invariant. The real block transform still
        # carries and validates every source guard/effect before guest advance.
        return int(expression)
    projection, canonical = _control_projection(residual, name, tid, pc=pc)
    composed = _compose_prefix_projection(
        projection, prefix_transforms=prefix_transforms,
        prefix_composer=prefix_composer, register_names=(canonical,),
    )
    composed.guards = ()
    return _evaluate_composed_register(composed, canonical, state, knownness_inputs)


def project_intel_read_effects(residual: IntelInstructionResidual, tid: int, *,
                               prefix_composer: SymbolicTransformComposer,
                               pc: int | None = None) -> tuple[IntelProjectedReadEffect, ...]:
    """Project read conditions/addresses to block roots without evaluating them."""
    if not residual.read_effects:
        return ()
    arch = ArchX86()
    pc = residual.pc if pc is None else pc
    all_writes = [
        MemoryWrite(write.address, write.value, write.address_mask,
                    write.value_mask, write.condition)
        for write in residual.effects
    ]
    projected = []
    for effect in residual.read_effects:
        local_writes = all_writes[:effect.write_prefix]
        projection = SymbolicTransform(
            tid, {ExprId("RAX", 64): effect.address,
                  ExprId("CF", 1): effect.condition}, [], arch, pc,
            pc + residual.length,
            defined_masks={"RAX": effect.address_mask, "CF": ExprInt(1, 1)},
            guards=(), source_owned=True,
        )
        projection.memory_writes.extend(local_writes)
        result = prefix_composer.source_projection(
            projection, register_names=("RAX", "CF"),
        )
        condition, _condition_mask = _composed_register_expressions(result, "CF")
        address, address_mask = _composed_register_expressions(result, "RAX")
        projected.append(IntelProjectedReadEffect(
            condition, address, address_mask, effect.byte_count,
            len(result.memory_writes),
        ))
    return tuple(projected)


def capture_projected_intel_read_effects(transform: SymbolicTransform,
                                         effects: Sequence[IntelProjectedReadEffect],
                                         state: ReadableProgramState,
                                         knownness_inputs: Mapping[str, int]) -> None:
    """Validate/capture projected reads once, using the complete block history."""
    if not effects:
        return
    evaluator = _TransformEvaluator(
        state, transform.memory_writes, dict(knownness_inputs),
    )
    for effect in effects:
        if effect.write_prefix > len(transform.memory_writes):
            raise SymbolEvaluationError("Projected Intel read references a future write prefix.")
        condition_mask = transform._eval_source_definedness(
            effect.condition, state, dict(knownness_inputs), evaluator,
            write_prefix=effect.write_prefix,
        )
        if condition_mask != 1:
            raise SymbolEvaluationError("Intel read-effect condition is not fully defined.")
        if evaluator.evaluate(effect.condition) == 0:
            continue
        address_mask_definedness = transform._eval_source_definedness(
            effect.address_mask, state, dict(knownness_inputs), evaluator,
            write_prefix=effect.write_prefix,
        )
        if address_mask_definedness != (1 << effect.address_mask.size) - 1:
            raise SymbolEvaluationError("Intel read-effect address mask is undefined.")
        address_mask = evaluator.evaluate(effect.address_mask)
        if address_mask != (1 << effect.address.size) - 1:
            raise SymbolEvaluationError("Intel read effect has an undefined address.")
        address = evaluator.evaluate(effect.address)
        state.read_memory(address, effect.byte_count)


def predict_syscall_prestate(residual: IntelInstructionResidual,
                             state: ReadableProgramState,
                             knownness_inputs: Mapping[str, int], tid: int, *,
                             prefix_transforms=(), prefix_composer=None,
                             pc: int | None = None):
    """Evaluate source-saved syscall CPU prestate after the preceding block prefix."""
    controls = residual.controls or {}
    names = sorted(name for name in controls if name.startswith("syscall_pre."))
    if not names:
        raise SymbolEvaluationError("Intel syscall residual omitted saved prestate outputs.")
    arch = ArchX86()
    outputs, masks = {}, {}
    for name in names:
        destination = name.removeprefix("syscall_pre.")
        canonical = arch.to_regname(destination)
        accessor = arch.get_reg_accessor(canonical) if canonical else None
        expression = controls[name]
        if accessor is None or accessor.num_bits != expression.size:
            raise SymbolicCompositionError(f"Invalid syscall prestate field {destination}.")
        outputs[ExprId(canonical, expression.size)] = expression
        masks[canonical] = (residual.control_masks or {})[name]
    pc = residual.pc if pc is None else pc
    projection = SymbolicTransform(
        tid, outputs, [], arch, pc, pc + residual.length,
        defined_masks=masks, guards=tuple(residual.guards), source_owned=True,
    )
    composed = _compose_prefix_projection(
        projection, prefix_transforms=prefix_transforms,
        prefix_composer=prefix_composer, register_names=tuple(
            arch.to_regname(name.removeprefix("syscall_pre.")) for name in names
        ),
    )
    return predict_boundary(composed, state,
        knownness_inputs=dict(knownness_inputs), register_names=tuple(
            arch.to_regname(name.removeprefix("syscall_pre.")) for name in names
        ))


def predict_intel_transform(transform: SymbolicTransform, state: ReadableProgramState,
                             knownness_inputs: Mapping[str, int]) -> BoundaryPrediction:
    """Predict the complete observed Intel register view, including identities."""
    return predict_boundary(
        transform, state, knownness_inputs=dict(knownness_inputs),
        register_names=REQUIRED_OUTPUTS,
    )


def compare_intel_boundary(prediction: BoundaryPrediction,
                           observed_registers: Mapping[str, int],
                           observed_memory: Mapping[int, bytes],
                           actual_store_addresses=None, *, require_store_coverage=True):
    """Apply Intel's required-known and exact-store policy through shared compare."""
    width_masks = {name: (1 << 64) - 1 for name in (*GPR_OUTPUTS, "RIP")}
    width_masks.update({name: (1 << 128) - 1 for name in XMM_OUTPUTS})
    width_masks.update({"FS_BASE": (1 << 64) - 1, "GS_BASE": (1 << 64) - 1})
    return compare_boundary(
        prediction, observed_registers, observed_memory,
        required_masks=width_masks, actual_store_addresses=actual_store_addresses,
        require_store_coverage=require_store_coverage,
    )


class IntelPreBoundaryState(ReadableProgramState):
    """Read-only QEMU boundary observations plus permission-checked lazy bytes.

    Memory is fetched only when the shared evaluator reaches a true access path;
    no static dependency walk/capture is performed. The callback must run while
    QEMU remains paused at this boundary.
    """

    def __init__(self, observations: Mapping[str, int], read_memory: Callable[[int, int], bytes],
                 memory_permissions: Callable[[int, int], int], *, guest_limit: int | None = None):
        super().__init__(ArchX86())
        self._values = {str(name).upper(): value for name, value in observations.items()}
        self._read_memory_callback = read_memory
        self._permissions_callback = memory_permissions
        self._guest_limit = guest_limit
        self.memory: dict[int, int] = {}
        self.permission_evidence: dict[int, tuple[bool, bool]] = {}
        for name, value in self._values.items():
            accessor = self.arch.get_reg_accessor(name)
            if accessor is None or type(value) is not int or not 0 <= value < 1 << accessor.num_bits:
                raise ValueError(f"Invalid Intel pre-boundary register observation: {name}.")

    def read_register(self, regname: str) -> int:
        canonical = self.arch.to_regname(regname)
        accessor = self.arch.get_reg_accessor(canonical) if canonical else None
        if accessor is None:
            raise RegisterAccessError(regname, f"Unsupported Intel register {regname}.")
        base = self._values.get(accessor.base_reg)
        if base is None:
            # QEMU exposes XMM, not unobserved upper YMM/ZMM lanes.
            alias = self._values.get(regname.upper())
            if alias is not None and accessor.start == 0 and alias < 1 << accessor.num_bits:
                return alias
            raise RegisterAccessError(regname, f"Intel register {regname} was not observed.")
        if accessor.end > base.bit_length() and accessor.base_reg.startswith("ZMM"):
            raise RegisterAccessError(regname, f"Unobserved vector upper lane for {regname}.")
        return (base >> accessor.start) & ((1 << accessor.num_bits) - 1)

    def check_store_permissions(self, ordered_writes) -> None:
        """Require pre-boundary mapped+writable evidence for active stores."""
        for address, data in ordered_writes:
            if self._guest_limit is not None and address > self._guest_limit - len(data):
                raise MemoryAccessError(address, len(data), "Intel store exceeds the guest profile.")
            for byte_address in range(address, address + len(data)):
                flags = self._permissions_callback(byte_address, 1)
                if type(flags) is not int or flags < 0 or flags & ~15:
                    raise MemoryAccessError(byte_address, 1, "Invalid guest write permission evidence.")
                readable, writable = bool(flags & 1), bool(flags & 2)
                if not flags & 8 or not writable:
                    raise MemoryAccessError(byte_address, 1, "No pre-boundary guest write permission.")
                self.permission_evidence[byte_address] = (readable, writable)

    def read_memory(self, addr: int, size: int) -> bytes:
        if type(addr) is not int or type(size) is not int or addr < 0 or size < 0:
            raise MemoryAccessError(addr, size, "Invalid Intel guest memory range.")
        if self._guest_limit is not None and (size == 0 or addr > self._guest_limit - size):
            raise MemoryAccessError(addr, size, "Intel guest memory range exceeds the profile.")
        result = bytearray()
        for address in range(addr, addr + size):
            if address not in self.memory:
                flags = self._permissions_callback(address, 1)
                if type(flags) is not int or flags < 0 or flags & ~15:
                    raise MemoryAccessError(address, 1, "Invalid guest permission evidence.")
                readable, writable = bool(flags & 1), bool(flags & 2)
                if not flags & 8 or not readable:
                    raise MemoryAccessError(address, 1, "No pre-boundary guest read permission.")
                data = self._read_memory_callback(address, 1)
                if not isinstance(data, bytes) or len(data) != 1:
                    raise MemoryAccessError(address, 1, "Incomplete pre-boundary memory evidence.")
                self.memory[address] = data[0]
                self.permission_evidence[address] = (readable, writable)
            result.append(self.memory[address])
        return bytes(result)


def normalize_observed_registers(observations: Mapping[str, int]) -> dict[str, int]:
    """Map transport register names to the canonical comparison view."""
    result = {}
    for name, value in observations.items():
        text = str(name)
        canonical = {"pc": "RIP", "eflags": "RFLAGS", "fs_base": "FS_BASE",
                    "gs_base": "GS_BASE"}.get(text.lower())
        if canonical is None and text.upper() in (*GPR_OUTPUTS, "RIP", "RFLAGS", *XMM_OUTPUTS,
                                                   "FS_BASE", "GS_BASE"):
            canonical = text.upper()
        if canonical is None:
            lowered = str(name).lower()
            canonical = next((register for register in (*GPR_OUTPUTS, *XMM_OUTPUTS)
                              if register.lower() == lowered), None)
        if canonical is not None:
            if type(value) is not int:
                raise ValueError(f"Invalid observed Intel register value for {name}.")
            result[canonical] = value
    return result


class SymbolicIntelLiveModel:
    """Specialize/compose one observed TB entirely from source residuals.

    Every fetch, lazy data read, and permission query occurs while the live
    process is paused at the TB-entry boundary. No per-instruction QEMU callback
    or post-boundary memory is used as prediction input.
    """

    def __init__(self, backend: IntelSymbolicBackend, decoder, transport, tid: int,
                 *, guest_limit: int | None = None, step_limit: int = 10_000_000):
        self.backend, self.decoder, self.transport, self.tid = backend, decoder, transport, tid
        self.guest_limit, self.step_limit = guest_limit, step_limit
        self.instructions = 0
        self.forms = set()
        self.memory = {}
        self.memory_permissions = {}
        self.decoded = []
        self.state = None
        self.knownness_inputs = {}
        self.prediction = None
        self.syscall_prestate = None
        self.environment_cutpoint = False
        self.next_ip = None

    def boundary(self, observed: Mapping[str, int]):
        registers = normalize_observed_registers(observed)
        self.state = IntelPreBoundaryState(
            registers, self.transport.read_memory, self.transport.memory_permissions,
            guest_limit=self.guest_limit,
        )
        self.knownness_inputs = knownness_inputs_for_observation(registers)
        self.memory, self.memory_permissions, self.decoded = {}, {}, []
        self.prediction = self.syscall_prestate = None
        self.environment_cutpoint = False
        self.next_ip = None

    def _instruction_bytes(self, pc: int) -> bytes:
        if self.guest_limit is not None and not 0 <= pc < self.guest_limit:
            raise SymbolEvaluationError("Intel instruction fetch is outside the guest profile.")
        window = min(15, self.guest_limit - pc) if self.guest_limit is not None else 15
        try:
            return self.transport.read_memory(pc, window)
        except MemoryAccessError:
            data = bytearray()
            for offset in range(window):
                try:
                    data.extend(self.transport.read_memory(pc + offset, 1))
                except MemoryAccessError:
                    if not data:
                        raise
                    break
            return bytes(data)

    def predict(self, event):
        if self.state is None:
            raise RuntimeError("Intel symbolic boundary was not initialized.")
        if (type(event.size) is not int or not 1 <= event.size <= 4096
                or type(event.pc) is not int or type(event.address) is not int):
            raise SymbolEvaluationError("Malformed Intel translation-block boundary.")
        block_composer = SymbolicTransformComposer(SymbolicTransform(
            self.tid, {}, [], ArchX86(), event.pc, event.pc,
            defined_masks={}, source_owned=True,
        ))
        projected_reads = []
        pc = event.pc
        for index in range(event.size):
            code = self._instruction_bytes(pc)
            instruction = self.decoder.decode(pc, code)
            if instruction.pc != pc or not instruction.code or len(instruction.code) > len(code):
                raise SymbolEvaluationError("Intel decoder returned mismatched instruction bytes.")
            permissions = self.transport.memory_permissions(pc, len(instruction.code))
            if type(permissions) is not int or permissions & ~15 or permissions & 12 != 12:
                raise SymbolEvaluationError(f"No guest execute permission for instruction at {pc:#x}.")
            if index == event.size - 1 and pc != event.address:
                raise SymbolEvaluationError("Decoded final instruction does not match TB extent.")
            residual = self.backend.specialize(instruction)
            if residual.pc != instruction.pc or residual.length != len(instruction.code):
                raise SymbolEvaluationError("Intel residual instruction identity/length mismatch.")
            prefix_composer = block_composer
            is_rep = instruction.iform.startswith("REP")
            current = residual.to_transform(self.tid)
            if is_rep:
                rep_steps = []
                full_prefix = block_composer.finish()
                rep_registers = _rep_control_output_names(residual)
                rep_scratch = _rep_control_scratch(residual)
                projected_prefix = _rep_prefix_projection(full_prefix, rep_registers, self.tid)
                rep_state_composer = SymbolicTransformComposer(projected_prefix)
                virtual_pc = pc
                final_cutpoint = 0
                final_next_ip = None
                final_architectural_rip = None
                repeat_scratch = _rep_control_scratch(residual)
                for _ in range(self.step_limit - self.instructions):
                    projected_reads.extend(project_intel_read_effects(
                        residual, self.tid, prefix_composer=rep_state_composer,
                        pc=virtual_pc,
                    ))
                    step_transform = residual.to_transform(self.tid)
                    step_transform.range = (virtual_pc, virtual_pc + residual.length)
                    step_transform.addr = virtual_pc
                    control_step = _rep_control_transform(
                        residual, self.tid, rep_scratch, virtual_pc, rep_registers,
                    )
                    control_composer = rep_state_composer.fork()
                    control_composer.append(control_step)
                    control_state = control_composer.finish()
                    repeat = _evaluate_composed_register(
                        control_state, rep_scratch, self.state, self.knownness_inputs,
                    )
                    final_cutpoint = predict_residual_control(
                        residual, "environment_cutpoint", self.state, self.knownness_inputs,
                        self.tid, prefix_composer=rep_state_composer, pc=virtual_pc,
                    )
                    final_architectural_rip = predict_residual_register(
                        residual, "RIP", self.state, self.knownness_inputs,
                        self.tid, prefix_composer=rep_state_composer, pc=virtual_pc,
                    )
                    if repeat not in (0, 1) or final_cutpoint not in (0, 1):
                        raise SymbolEvaluationError("Invalid Intel source control value.")
                    rep_steps.append(step_transform)
                    if not repeat:
                        final_next_ip = predict_residual_control(
                            residual, "next_ip", self.state, self.knownness_inputs,
                            self.tid, prefix_composer=rep_state_composer, pc=virtual_pc,
                        )
                        break
                    if final_architectural_rip != residual.pc:
                        raise SymbolEvaluationError("Repeating Intel source step did not retain its instruction RIP.")
                    rep_state_composer.append(control_step)
                    virtual_pc += residual.length
                else:
                    raise SymbolEvaluationError("Intel source REP safety limit exceeded.")
                rep_composer = SymbolicTransformComposer(rep_steps[0])
                for step in rep_steps[1:]:
                    rep_composer.append(step)
                current = rep_composer.finish()
                current.range = (pc, pc + residual.length)
                current.addr = pc
                cutpoint, source_next_ip = final_cutpoint, final_next_ip
                architectural_rip = final_architectural_rip
                self.decoded.append({"pc": pc, "bytes": instruction.code.hex(),
                                     "iform": instruction.iform, "guest_permissions": permissions,
                                     "source_iterations": len(rep_steps)})
                self.instructions += len(rep_steps)
            else:
                projected_reads.extend(project_intel_read_effects(
                    residual, self.tid, prefix_composer=prefix_composer,
                ))
                cutpoint = predict_residual_control(
                    residual, "environment_cutpoint", self.state, self.knownness_inputs,
                    self.tid, prefix_composer=prefix_composer,
                )
                repeat = predict_residual_control(
                    residual, "repeat", self.state, self.knownness_inputs,
                    self.tid, prefix_composer=prefix_composer,
                )
                if cutpoint not in (0, 1) or repeat != 0:
                    raise SymbolEvaluationError("Unexpected source repeat/cutpoint control.")
                source_next_ip = None
                if cutpoint:
                    source_next_ip = predict_residual_control(
                        residual, "next_ip", self.state, self.knownness_inputs, self.tid,
                        prefix_composer=prefix_composer,
                    )
                architectural_rip = predict_residual_register(
                    residual, "RIP", self.state, self.knownness_inputs, self.tid,
                    prefix_composer=prefix_composer,
                )
                self.decoded.append({"pc": pc, "bytes": instruction.code.hex(),
                                     "iform": instruction.iform, "guest_permissions": permissions,
                                     "source_iterations": 1})
                self.instructions += 1
            if index != event.size - 1 and architectural_rip != instruction.pc + len(instruction.code):
                raise SymbolEvaluationError("Source control transfer inside observed Intel TB.")
            if cutpoint and index != event.size - 1:
                raise SymbolEvaluationError("Source environment cutpoint inside Intel TB.")
            if instruction.iform == "SYSCALL" and not cutpoint:
                raise SymbolEvaluationError("Source omitted the SYSCALL environment cutpoint.")
            if cutpoint:
                if instruction.iform != "SYSCALL" or self.syscall_prestate is not None:
                    raise SymbolEvaluationError("Unexpected or duplicate Intel syscall cutpoint.")
                self.syscall_prestate = predict_syscall_prestate(
                    residual, self.state, self.knownness_inputs, self.tid,
                    prefix_composer=prefix_composer,
                )
            self.environment_cutpoint = bool(cutpoint)
            self.next_ip = source_next_ip
            block_composer.append(current)
            pc = architectural_rip
            self.forms.add(instruction.iform)
        whole_transform = block_composer.finish()
        self.prediction = predict_intel_transform(
            whole_transform, self.state, self.knownness_inputs,
        )
        capture_projected_intel_read_effects(
            whole_transform, projected_reads, self.state, self.knownness_inputs,
        )
        pc_prediction = self.prediction.registers["RIP"]
        if pc_prediction.mask != (1 << 64) - 1:
            raise SymbolEvaluationError("Intel source RIP output is undefined.")
        if pc_prediction.value != architectural_rip:
            raise SymbolEvaluationError(
                "Intel composed RIP disagrees with source architectural successor "
                f"({pc_prediction.value:#x} != {architectural_rip:#x})."
            )
        self.state.check_store_permissions(self.prediction.ordered_writes)
        self.memory = dict(self.state.memory)
        self.memory_permissions = dict(self.state.permission_evidence)
        return self.prediction


def _rep_control_output_names(residual: IntelInstructionResidual) -> tuple[str, ...]:
    """Find the source-register closure needed to carry REP predicates forward."""
    arch = ArchX86()
    controls, control_masks = residual.controls or {}, residual.control_masks or {}
    roots = [
        controls[name] for name in ("repeat", "environment_cutpoint", "next_ip")
        if name in controls
    ]
    roots.extend(
        control_masks[name] for name in ("repeat", "environment_cutpoint", "next_ip")
        if name in control_masks
    )
    for effect in residual.effects:
        roots.extend((effect.address, effect.value, effect.address_mask, effect.value_mask))
        if effect.condition is not None:
            roots.append(effect.condition)
    for effect in residual.read_effects:
        roots.extend((effect.address, effect.address_mask, effect.condition))

    needed_bases = set()

    def add_register_dependencies(expression):
        for node in iter_expression_dag(expression):
            if isinstance(node, ExprId) and isinstance(node.name, str):
                canonical = arch.to_regname(node.name)
                accessor = arch.get_reg_accessor(canonical) if canonical else None
                if accessor is not None:
                    needed_bases.add(accessor.base_reg)

    for root in roots:
        add_register_dependencies(root)
    selected = set()
    while True:
        previous = len(needed_bases), len(selected)
        for name, expression in residual.outputs.items():
            canonical = arch.to_regname(name)
            accessor = arch.get_reg_accessor(canonical) if canonical else None
            if accessor is None or accessor.base_reg not in needed_bases:
                continue
            mask = residual.defined_masks[name]
            identity = ExprId(canonical, expression.size)
            base_accessor = arch.get_reg_accessor(accessor.base_reg)
            assert base_accessor is not None
            identity_mask = knownness_symbol(accessor.base_reg, base_accessor.num_bits)
            if accessor.start or accessor.end != base_accessor.num_bits:
                identity_mask = ExprSlice(identity_mask, accessor.start, accessor.end)
            if expression != identity or mask != identity_mask:
                selected.add(name)
                add_register_dependencies(expression)
                add_register_dependencies(mask)
        if previous == (len(needed_bases), len(selected)):
            break
    return tuple(sorted(selected))


def _rep_control_scratch(residual: IntelInstructionResidual) -> str:
    """Find a GPR unused by this source step for the REP control projection."""
    arch = ArchX86()
    used = set()
    expressions = [*residual.guards, *(residual.control_masks or {}).values()]
    expressions.extend((residual.controls or {}).values())
    for name, expression in residual.outputs.items():
        canonical = arch.to_regname(name)
        if canonical is not None and expression == ExprId(canonical, expression.size):
            continue
        expressions.append(expression)
    for name, mask in residual.defined_masks.items():
        canonical = arch.to_regname(name)
        if canonical is not None and mask == knownness_symbol(
            canonical, arch.get_reg_accessor(canonical).num_bits,
        ):
            continue
        expressions.append(mask)
    for effect in residual.effects:
        expressions.extend((effect.address, effect.value, effect.address_mask, effect.value_mask))
        if effect.condition is not None:
            expressions.append(effect.condition)
    for effect in residual.read_effects:
        expressions.extend((effect.address, effect.address_mask, effect.condition))
    for expression in expressions:
        for node in iter_expression_dag(expression):
            if isinstance(node, ExprId) and isinstance(node.name, str):
                canonical = arch.to_regname(node.name)
                if canonical is not None:
                    used.add(canonical)
    for candidate in reversed(GPR_OUTPUTS):
        output = next((expr for name, expr in residual.outputs.items()
                       if arch.to_regname(name) == candidate), None)
        if output is not None and output != ExprId(candidate, 64):
            continue
        if candidate not in used:
            return candidate
    raise SymbolEvaluationError("No source-unused GPR for REP control projection.")


def _rep_prefix_projection(prefix_state: SymbolicTransform,
                           register_names: tuple[str, ...], tid: int):
    """Retain only the register slice closure needed by REP predicates/effects."""
    arch = prefix_state.arch
    outputs, masks = {}, {}
    for name in register_names:
        canonical = arch.to_regname(name)
        accessor = arch.get_reg_accessor(canonical) if canonical else None
        if accessor is None:
            raise SymbolicCompositionError(f"Invalid REP dependency register {name}.")
        base_accessor = arch.get_reg_accessor(accessor.base_reg)
        assert base_accessor is not None
        base_value = prefix_state.changed_regs.get(
            accessor.base_reg, ExprId(accessor.base_reg, base_accessor.num_bits),
        )
        base_mask = prefix_state.defined_masks.get(
            accessor.base_reg, knownness_symbol(accessor.base_reg, base_accessor.num_bits),
        )
        value = (base_value if accessor.start == 0 and accessor.end == base_value.size
                 else ExprSlice(base_value, accessor.start, accessor.end))
        mask = (base_mask if accessor.start == 0 and accessor.end == base_mask.size
                else ExprSlice(base_mask, accessor.start, accessor.end))
        identity_value = ExprId(canonical, accessor.num_bits)
        identity_mask = knownness_symbol(accessor.base_reg, base_accessor.num_bits)
        if accessor.start or accessor.end != base_accessor.num_bits:
            identity_mask = ExprSlice(identity_mask, accessor.start, accessor.end)
        if value != identity_value or mask != identity_mask:
            outputs[ExprId(canonical, accessor.num_bits)] = value
            masks[canonical] = mask
    projected = SymbolicTransform(
        tid, outputs, [], arch, prefix_state.range[0], prefix_state.range[1],
        defined_masks=masks, guards=(), source_owned=True,
    )
    # Keep prior ordered writes for load forwarding; output cones which do not
    # mention them will avoid evaluating them in the projected evaluator.
    projected.memory_writes = list(prefix_state.memory_writes)
    return projected


def _rep_control_transform(residual: IntelInstructionResidual, tid: int,
                            scratch: str, pc: int,
                            register_names: tuple[str, ...]):
    """Project only source state needed for REP controls plus the scratch bit."""
    arch = ArchX86()
    outputs, masks = {}, {}
    for name in register_names:
        expression = residual.outputs.get(name)
        if expression is None:
            continue
        canonical = arch.to_regname(name)
        assert canonical is not None
        outputs[ExprId(canonical, expression.size)] = expression
        masks[canonical] = residual.defined_masks[name]
    expression = (residual.controls or {})["repeat"]
    mask = (residual.control_masks or {})["repeat"]
    accessor = arch.get_reg_accessor(scratch)
    assert accessor is not None and accessor.num_bits == 64 and expression.size == 1
    outputs[ExprId(scratch, 64)] = expression.zeroExtend(64)
    masks[scratch] = ExprCompose(mask, ExprInt((1 << 63) - 1, 63))
    transform = SymbolicTransform(
        tid, outputs, [], arch, pc, pc + residual.length,
        defined_masks=masks, guards=(), source_owned=True,
    )
    transform.memory_writes.extend(
        MemoryWrite(effect.address, effect.value, effect.address_mask,
                    effect.value_mask, effect.condition)
        for effect in residual.effects
    )
    return transform


def knownness_inputs_for_observation(observations: Mapping[str, int]) -> dict[str, int]:
    """Construct independent source knownness for QEMU's observable ABI.

    The runtime supplies GPR/RFLAGS/FS/GS and XMM values. Vector bits above
    XMM remain unknown unless the source contract explicitly observed them.
    """
    arch = ArchX86()
    knownness: dict[str, int] = {}
    normalized = {str(name).upper(): value for name, value in observations.items()}
    for name in (*GPR_OUTPUTS, "RIP", "RFLAGS", "FS_BASE", "GS_BASE"):
        if name not in normalized:
            raise ValueError(f"Missing independently observed Intel register {name}.")
        accessor = arch.get_reg_accessor(name)
        assert accessor is not None
        knownness[name] = (1 << accessor.num_bits) - 1
    for index in range(16):
        name = f"XMM{index}"
        if name not in normalized:
            raise ValueError(f"Missing independently observed Intel register {name}.")
        knownness[f"ZMM{index}"] = (1 << 128) - 1
    return knownness
