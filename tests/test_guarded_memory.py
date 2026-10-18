import pytest
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import ExprCond, ExprId, ExprInt, ExprMem, ExprOp, ExprSlice

from focaccia.arch import x86
from focaccia.miasm_util import MiasmSymbolResolver, eval_expr
from focaccia.snapshot import ProgramState
from focaccia.symbolic import (
    MemoryWrite, SymbolEvaluationError, SymbolicTransform, SymbolicTransformComposer,
    _TransformEvaluator,
    knownness_symbol,
)

X86 = x86.ArchX86()


def make_store(condition):
    destination = ExprMem(ExprId("RAX", 64), 8)
    return SymbolicTransform(
        1, {destination: ExprMem(ExprId("RBX", 64), 8)}, [], X86, 0, 1,
        source_owned=True, defined_masks={},
        memory_defined_masks={destination: (ExprInt((1 << 64) - 1, 64), ExprInt(0xFF, 8))},
        memory_write_conditions={destination: condition},
    )


def test_wide_nonzero_condition_requires_all_selector_bits_known():
    # Miasm represents equality as a conditional over a full-width XOR.
    guard = ExprCond(ExprId("RIP", 64) ^ ExprInt(0x1000, 64), ExprInt(0, 1), ExprInt(1, 1))
    transform = SymbolicTransform(1, {ExprId("RAX", 64): ExprInt(7, 64)}, [], X86, 0, 1,
                                  source_owned=True, defined_masks={"RAX": ExprInt(2**64 - 1, 64)},
                                  guards=(guard,))
    state = ProgramState(X86)
    state.write_register("RIP", 0x1000)
    assert transform.eval_validation_register_transforms_with_masks(
        state, {"RIP": 2**64 - 1})["RAX"] == (7, 2**64 - 1)
    with pytest.raises(SymbolEvaluationError, match="definedness|undefined"):
        transform.eval_validation_register_transforms_with_masks(state, {"RIP": 1})
    state.write_register("RIP", 0x1001)
    with pytest.raises(SymbolEvaluationError, match="false"):
        transform.eval_validation_register_transforms_with_masks(state, {"RIP": 2**64 - 1})


def test_exprcond_value_evaluation_does_not_visit_inactive_unmapped_memory():
    state = ProgramState(X86)
    resolver = MiasmSymbolResolver(state, LocationDB())
    expression = ExprCond(ExprInt(0, 1), ExprMem(ExprInt(0xdead000, 64), 8), ExprInt(0x5a, 8))
    assert eval_expr(expression, resolver) == ExprInt(0x5a, 8)
    assert _TransformEvaluator(state, []).evaluate(expression) == 0x5a


def test_false_conditional_store_skips_address_value_and_masks_and_roundtrips():
    store = make_store(ExprSlice(ExprId("RCX", 64), 0, 1))
    restored = SymbolicTransform.from_json(store.to_json())
    assert restored.memory_writes[0].condition == store.memory_writes[0].condition
    state = ProgramState(X86)
    state.write_register("RAX", 0xdead000)
    state.write_register("RBX", 0xbeef000)
    state.write_register("RCX", 0)
    known = {"RAX": (1 << 64) - 1, "RBX": (1 << 64) - 1, "RCX": (1 << 64) - 1}
    assert restored.eval_source_ordered_memory_transforms(state, known) == ()


def test_true_conditional_store_needs_value_evidence_and_writes_in_order():
    store = make_store(ExprSlice(ExprId("RCX", 64), 0, 1))
    state = ProgramState(X86)
    state.write_register("RAX", 0x2000)
    state.write_register("RBX", 0x3000)
    state.write_register("RCX", 1)
    with pytest.raises(Exception, match="unknown in sparse memory"):
        store.eval_source_ordered_memory_transforms(
            state, {"RAX": (1 << 64) - 1, "RBX": (1 << 64) - 1, "RCX": (1 << 64) - 1}
        )
    state.write_memory(0x3000, bytes.fromhex("A5"))
    assert store.eval_source_ordered_memory_transforms(
        state, {"RAX": (1 << 64) - 1, "RBX": (1 << 64) - 1, "RCX": (1 << 64) - 1}
    ) == ((0x2000, bytes.fromhex("A5")),)


def test_conditional_selector_must_be_defined_even_when_false():
    store = make_store(ExprSlice(ExprId("RCX", 64), 0, 1))
    state = ProgramState(X86)
    state.write_register("RAX", 0xdead000)
    state.write_register("RBX", 0xbeef000)
    state.write_register("RCX", 0)
    with pytest.raises(SymbolEvaluationError, match="undefined condition"):
        store.eval_source_ordered_memory_transforms(
            state, {"RAX": (1 << 64) - 1, "RBX": (1 << 64) - 1, "RCX": 0}
        )


def test_false_conditional_store_keeps_prefix_ordinal_for_later_forwarding():
    destination = ExprMem(ExprId("RAX", 64), 8)
    false_store = SymbolicTransform(
        1, {destination: ExprInt(0x11, 8)}, [], X86, 0, 1,
        source_owned=True, defined_masks={},
        memory_defined_masks={destination: (ExprInt((1 << 64) - 1, 64), ExprInt(0xFF, 8))},
        memory_write_conditions={destination: ExprSlice(ExprId("RCX", 64), 0, 1)},
    )
    following_destination = ExprMem(ExprId("RDX", 64), 8)
    following = SymbolicTransform(
        1, {following_destination: ExprMem(ExprId("RAX", 64), 8)}, [], X86, 1, 2,
        source_owned=True, defined_masks={},
        memory_defined_masks={following_destination: (ExprInt((1 << 64) - 1, 64), ExprInt(0xFF, 8))},
    )
    composed = false_store.composed_with(following)
    state = ProgramState(X86)
    state.write_register("RAX", 0x4000)
    state.write_register("RDX", 0x5000)
    state.write_register("RCX", 0)
    state.write_memory(0x4000, bytes.fromhex("33"))
    known = {name: (1 << 64) - 1 for name in ("RAX", "RDX", "RCX")}
    assert composed.eval_source_ordered_memory_transforms(state, known) == (
        (0x5000, bytes.fromhex("33")),
    )


def test_requested_register_projection_includes_unchanged_aliases_and_combines_flags():
    source = SymbolicTransform(
        1, {ExprId("CF", 1): ExprInt(1, 1), ExprId("EAX", 32): ExprInt(7, 32)},
        [], X86, 0, 1, source_owned=True,
        defined_masks={"CF": ExprInt(1, 1), "EAX": ExprInt((1 << 32) - 1, 32)},
    )
    projected = source.validation_register_outputs_with_masks(["RFLAGS", "RAX", "RBX"])
    assert projected["RFLAGS"][0].size == 64
    assert projected["RAX"][0].size == 64
    assert projected["RBX"] == (ExprId("RBX", 64), knownness_symbol("RBX", 64))
    state = ProgramState(X86)
    state.write_register("RAX", 0)
    state.write_register("RBX", 9)
    state.write_register("RFLAGS", 0)
    values = source.eval_validation_register_transforms_with_masks(
        state,
        {"RAX": (1 << 64) - 1, "RBX": (1 << 64) - 1, "RFLAGS": (1 << 64) - 1},
        ["RFLAGS", "RAX", "RBX"],
    )
    assert values["RAX"] == (7, (1 << 64) - 1)
    assert values["RBX"] == (9, (1 << 64) - 1)
    assert values["RFLAGS"][0] & 1 == 1


def test_register_guard_api_rejects_deferred_read_through_unknown_conditional_store():
    destination = ExprMem(ExprId("RAX", 64), 8)
    conditional = SymbolicTransform(
        1, {destination: ExprInt(0x11, 8)}, [], X86, 0, 1,
        source_owned=True, defined_masks={},
        memory_defined_masks={destination: (ExprInt((1 << 64) - 1, 64), ExprInt(0xFF, 8))},
        memory_write_conditions={destination: ExprSlice(ExprId("RCX", 64), 0, 1)},
    )
    consumer = SymbolicTransform(
        1, {ExprId("RBX", 64): ExprInt(1, 64)}, [], X86, 1, 2,
        source_owned=True, defined_masks={"RBX": ExprInt((1 << 64) - 1, 64)},
        guards=(ExprSlice(ExprMem(ExprId("RAX", 64), 8), 0, 1),),
    )
    composed = conditional.composed_with(consumer)
    state = ProgramState(X86)
    state.write_register("RAX", 0x4000)
    state.write_register("RBX", 0)
    state.write_register("RCX", 1)
    state.write_memory(0x4000, b"\\x01")
    known = {"RAX": (1 << 64) - 1, "RBX": (1 << 64) - 1, "RCX": 0}
    with pytest.raises(SymbolEvaluationError, match="undefined condition"):
        composed.eval_validation_register_transforms_with_masks(state, known)


def test_register_guard_api_rejects_deferred_read_through_unknown_store_value():
    destination = ExprMem(ExprId("RAX", 64), 8)
    source_store = SymbolicTransform(
        1, {destination: ExprId("BL", 8)}, [], X86, 0, 1,
        source_owned=True, defined_masks={},
        memory_defined_masks={destination: (
            ExprInt((1 << 64) - 1, 64), ExprSlice(knownness_symbol("RBX", 64), 0, 8),
        )},
        memory_write_conditions={destination: ExprSlice(ExprId("RCX", 64), 0, 1)},
    )
    consumer = SymbolicTransform(
        1, {ExprId("RDX", 64): ExprInt(1, 64)}, [], X86, 1, 2,
        source_owned=True, defined_masks={"RDX": ExprInt((1 << 64) - 1, 64)},
        guards=(ExprSlice(ExprMem(ExprId("RAX", 64), 8), 0, 1),),
    )
    composed = source_store.composed_with(consumer)
    state = ProgramState(X86)
    for name, value in {"RAX": 0x4000, "RBX": 0xA5, "RCX": 1, "RDX": 0}.items():
        state.write_register(name, value)
    known = {"RAX": (1 << 64) - 1, "RBX": 0, "RCX": 1, "RDX": (1 << 64) - 1}
    with pytest.raises(SymbolEvaluationError, match="undefined value bit"):
        composed.eval_validation_register_transforms_with_masks(state, known)


def test_condition_only_dependencies_include_register_and_memory_inputs():
    destination = ExprMem(ExprInt(0x5000, 64), 8)
    condition = ExprSlice(ExprMem(ExprId("RSP", 64), 8), 0, 1)
    source = SymbolicTransform(
        1, {destination: ExprInt(0xA5, 8)}, [], X86, 0, 1,
        source_owned=True, defined_masks={},
        memory_defined_masks={destination: (ExprInt((1 << 64) - 1, 64), ExprInt(0xFF, 8))},
        memory_write_conditions={destination: condition},
    )
    assert "RSP" in source.get_used_registers()
    assert "RSP" in source.get_validation_input_registers()
    assert any(memory.ptr == ExprId("RSP", 64) for memory in source.get_used_memory_addresses())
    composer = SymbolicTransformComposer(source, track_dependencies=True)
    dependencies = composer.dependencies()
    assert "RSP" in dependencies.registers
    assert any(memory.ptr == ExprId("RSP", 64) for memory in dependencies.memory)


def test_transform_evaluator_cache_is_scoped_to_state_and_ordered_prefix():
    base = 0x6000
    deferred = ExprOp("focaccia_memory_byte", ExprInt(base, 64), ExprInt(1, 64))
    inactive = MemoryWrite(ExprInt(base, 64), ExprInt(0xAA, 8),
                           condition=ExprInt(0, 1))
    active = MemoryWrite(ExprInt(base, 64), ExprInt(0xBB, 8),
                         condition=ExprInt(1, 1))

    first_state = ProgramState(X86)
    first_state.write_memory(base, bytes((0x11,)))
    first_eval = _TransformEvaluator(first_state, [inactive])
    assert first_eval.evaluate(deferred) == 0x11
    assert first_eval.evaluate(deferred) == 0x11  # successful identical value is memoized

    second_state = ProgramState(X86)
    second_state.write_memory(base, bytes((0x22,)))
    second_eval = _TransformEvaluator(second_state, [inactive])
    assert second_eval.evaluate(deferred) == 0x22  # no cross-state cache hit

    forwarding_eval = _TransformEvaluator(first_state, [active])
    assert forwarding_eval.evaluate(deferred) == 0xBB  # prefix1 sees the active prior write


def test_composer_fork_reuses_prefix_without_mutating_sibling_suffixes():
    prefix = SymbolicTransform(
        1, {ExprId("RAX", 64): ExprInt(7, 64)}, [], X86, 0, 1,
        source_owned=True, defined_masks={"RAX": ExprInt((1 << 64) - 1, 64)},
    )
    composer = SymbolicTransformComposer(prefix)
    first = SymbolicTransform(
        1, {ExprId("RBX", 64): ExprId("RAX", 64) + ExprInt(1, 64)}, [], X86, 1, 2,
        source_owned=True, defined_masks={"RBX": ExprInt((1 << 64) - 1, 64)},
    )
    second = SymbolicTransform(
        1, {ExprId("RCX", 64): ExprId("RAX", 64) + ExprInt(2, 64)}, [], X86, 1, 2,
        source_owned=True, defined_masks={"RCX": ExprInt((1 << 64) - 1, 64)},
    )
    left, right = composer.fork(), composer.fork()
    left.append(first)
    right.append(second)
    state = ProgramState(X86)
    known = {name: (1 << 64) - 1 for name in ("RAX", "RBX", "RCX")}
    assert left.finish().eval_validation_register_transforms_with_masks(
        state, known, ["RAX", "RBX"],
    )["RBX"] == (8, (1 << 64) - 1)
    assert right.finish().eval_validation_register_transforms_with_masks(
        state, known, ["RAX", "RCX"],
    )["RCX"] == (9, (1 << 64) - 1)
    assert composer.finish().eval_validation_register_transforms_with_masks(
        state, known, ["RAX"],
    )["RAX"] == (7, (1 << 64) - 1)


def test_memory_write_rejects_non_one_bit_condition():
    with pytest.raises(ValueError, match="one-bit"):
        MemoryWrite(ExprId("RAX", 64), ExprInt(0, 8), condition=ExprInt(0, 2))
