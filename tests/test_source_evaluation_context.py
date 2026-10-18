import pytest
from miasm.expression.expression import ExprId, ExprInt, ExprMem, ExprOp, ExprSlice

from focaccia.arch import aarch64, x86
from focaccia.snapshot import ProgramState
from focaccia.symbolic import (
    MemoryWrite, SymbolEvaluationError, SymbolicTransform, SymbolicTransformComposer,
    _DEFERRED_MEMORY_BYTE_OP, _TransformEvaluator,
)


X86 = x86.ArchX86()
FULL = (1 << 64) - 1


def transition():
    destination = ExprMem(ExprId("RAX", 64), 8)
    return SymbolicTransform(
        1,
        {ExprId("RDX", 64): ExprId("RBX", 64), destination: ExprInt(0xA5, 8)},
        [], X86, 0, 1, source_owned=True,
        defined_masks={"RDX": ExprInt(FULL, 64)},
        memory_defined_masks={destination: (ExprInt(FULL, 64), ExprInt(0xFF, 8))},
        memory_write_conditions={destination: ExprSlice(ExprId("RCX", 64), 0, 1)},
        guards=(ExprSlice(ExprId("RSI", 64), 0, 1),),
    )


def state():
    result = ProgramState(X86)
    for name, value in {"RAX": 0x4000, "RBX": 0x1234, "RCX": 1, "RSI": 1}.items():
        result.write_register(name, value)
    return result


def known():
    return {name: FULL for name in ("RAX", "RBX", "RCX", "RSI", "RDX")}


def test_shared_source_transition_matches_register_and_ordered_store_apis():
    transform = transition()
    before = state()
    pairs, stores = transform.eval_source_transition(before, known())
    assert pairs == transform.eval_validation_register_transforms_with_masks(before, known())
    assert stores == transform.eval_source_ordered_memory_transforms(before, known())
    assert pairs["RDX"] == (0x1234, FULL)
    assert stores == ((0x4000, b"\xA5"),)


def test_shared_context_skips_inactive_store_payload_and_preserves_prefix_slot():
    transform = transition()
    before = state()
    before.write_register("RCX", 0)
    # Inactive memory writes are lazy: their address/value obligations are not read.
    before.write_register("RAX", 0xDEAD000)
    pairs, stores = transform.eval_source_transition(before, known())
    assert pairs["RDX"] == (0x1234, FULL)
    assert stores == ()
    assert transform.eval_source_ordered_memory_transforms(before, known()) == stores


@pytest.mark.parametrize(("register", "value", "message"), [
    ("RSI", 0, "false"),
    ("RSI", 1, "undefined"),
])
def test_shared_context_rejects_false_or_undefined_guards(register, value, message):
    transform = transition()
    before = state()
    before.write_register(register, value)
    evidence = known()
    if message == "undefined":
        evidence[register] = 0
    with pytest.raises(SymbolEvaluationError, match=message):
        transform.eval_source_transition(before, evidence)


def test_shared_context_preserves_store_prefix_forwarding():
    first_destination = ExprMem(ExprId("RAX", 64), 8)
    first = SymbolicTransform(
        1, {first_destination: ExprInt(0x33, 8)}, [], X86, 0, 1,
        source_owned=True, defined_masks={},
        memory_defined_masks={first_destination: (ExprInt(FULL, 64), ExprInt(0xFF, 8))},
    )
    second_destination = ExprMem(ExprId("RDX", 64), 8)
    second = SymbolicTransform(
        1, {second_destination: ExprMem(ExprId("RAX", 64), 8)}, [], X86, 1, 2,
        source_owned=True, defined_masks={},
        memory_defined_masks={second_destination: (ExprInt(FULL, 64), ExprInt(0xFF, 8))},
    )
    composed = first.composed_with(second)
    before = state()
    before.write_register("RDX", 0x5000)
    pairs, stores = composed.eval_source_transition(before, known())
    assert pairs == {}
    assert stores == ((0x4000, b"\x33"), (0x5000, b"\x33"))


def test_source_projection_matches_full_composition_and_preserves_parent():
    prefix = transition()
    first = SymbolicTransformComposer(prefix)
    before = first.finish()
    local_destination = ExprMem(ExprId("RDX", 64), 8)
    local = SymbolicTransform(
        1,
        {ExprId("R8", 64): ExprId("RDX", 64),
         local_destination: ExprMem(ExprId("RAX", 64), 8)},
        [], X86, 1, 2, source_owned=True,
        defined_masks={"R8": ExprInt(FULL, 64)},
        memory_defined_masks={local_destination: (ExprInt(FULL, 64), ExprInt(0xFF, 8))},
    )
    projected = first.source_projection(local, ("RDX", "R8", "EAX"))
    reference = prefix.composed_with(local)

    requested = ("RDX", "R8", "EAX")
    assert projected.validation_register_outputs_with_masks(requested) == (
        reference.validation_register_outputs_with_masks(requested)
    )
    assert projected.memory_writes == reference.memory_writes
    assert projected.guards == reference.guards
    assert projected.range == reference.range == (0, 2)
    # The second store reads the prefix's first store through the write history.
    before_state = state()
    projected_pairs, projected_writes = projected.eval_source_transition(
        before_state, known(), register_names=requested,
    )
    reference_pairs, reference_writes = reference.eval_source_transition(
        before_state, known(), register_names=requested,
    )
    assert projected_pairs == reference_pairs
    assert projected_writes == reference_writes == (
        (0x4000, bytes([0xA5])), (0x1234, bytes([0xA5])),
    )
    after = first.finish()
    assert after.range == before.range
    assert after.changed_regs == before.changed_regs
    assert after.defined_masks == before.defined_masks
    assert after.memory_writes == before.memory_writes
    assert after.guards == before.guards


def test_source_projection_rejects_false_guards_and_discontinuous_suffix():
    prefix = SymbolicTransformComposer(transition())
    local = SymbolicTransform(
        1, {ExprId("R8", 64): ExprInt(1, 64)}, [], X86, 1, 2,
        source_owned=True, defined_masks={"R8": ExprInt(FULL, 64)},
    )
    projected = prefix.source_projection(local, ("R8",))
    before = state()
    before.write_register("RSI", 0)
    with pytest.raises(SymbolEvaluationError, match="false"):
        projected.eval_source_transition(before, known())
    discontinuous = SymbolicTransform(
        1, {ExprId("R9", 64): ExprInt(1, 64)}, [], X86, 3, 4,
        source_owned=True, defined_masks={"R9": ExprInt(FULL, 64)},
    )
    with pytest.raises(Exception, match="discontinuous"):
        prefix.source_projection(discontinuous, ("R9",))
    wrong_tid = SymbolicTransform(
        2, {ExprId("R9", 64): ExprInt(1, 64)}, [], X86, 1, 2,
        source_owned=True, defined_masks={"R9": ExprInt(FULL, 64)},
    )
    with pytest.raises(Exception, match="thread"):
        prefix.source_projection(wrong_tid, ("R9",))
    wrong_arch = SymbolicTransform(
        1, {ExprId("X0", 64): ExprInt(1, 64)}, [], aarch64.ArchAArch64("little"), 1, 2,
        source_owned=True, defined_masks={"X0": ExprInt(FULL, 64)},
    )
    with pytest.raises(Exception, match="architectures"):
        prefix.source_projection(wrong_arch, ("R9",))
    legacy = SymbolicTransform(
        1, {ExprId("R9", 64): ExprInt(1, 64)}, [], X86, 1, 2,
    )
    with pytest.raises(Exception, match="source-owned"):
        prefix.source_projection(legacy, ("R9",))


def test_fork_append_does_not_mutate_parent_composer():
    parent = SymbolicTransformComposer(transition())
    before = parent.finish()
    child = parent.fork()
    child.append(SymbolicTransform(
        1, {ExprId("R8", 64): ExprInt(9, 64)}, [], X86, 1, 2,
        source_owned=True, defined_masks={"R8": ExprInt(FULL, 64)},
    ))
    assert child.finish().range == (0, 2)
    after = parent.finish()
    assert after.range == before.range
    assert after.changed_regs == before.changed_regs
    assert after.memory_writes == before.memory_writes
    assert after.guards == before.guards


def test_definedness_and_deferred_rewrite_memos_are_write_prefix_scoped():
    transform = transition()
    transform.memory_writes.append(
        MemoryWrite(ExprInt(0x6000, 64), ExprInt(0x77, 8))
    )  # Deliberately lacks required source masks.
    before = state()
    evidence = known()
    evaluator = _TransformEvaluator(before, transform.memory_writes, evidence)
    deferred = ExprOp(
        _DEFERRED_MEMORY_BYTE_OP, ExprInt(0x4000, 64), ExprInt(1, 64),
    )
    assert transform._eval_source_definedness(
        deferred, before, evidence, evaluator, write_prefix=1,
    ) == FULL
    cache_size = len(evaluator._source_definedness_cache)
    assert transform._eval_source_definedness(
        deferred, before, evidence, evaluator, write_prefix=1,
    ) == FULL
    assert len(evaluator._source_definedness_cache) == cache_size
    with pytest.raises(SymbolEvaluationError, match="exceeds checked write prefix"):
        transform._eval_source_definedness(
            deferred, before, evidence, evaluator, write_prefix=0,
        )
    deferred_through_second = ExprOp(
        _DEFERRED_MEMORY_BYTE_OP, ExprInt(0x4000, 64), ExprInt(2, 64),
    )
    with pytest.raises(SymbolEvaluationError, match="lacks definedness metadata"):
        transform._eval_source_definedness(
            deferred_through_second, before, evidence, evaluator, write_prefix=2,
        )

    rewritten = evaluator._rewrite_deferred_memory(deferred)
    assert evaluator.evaluate(deferred) == 0xA5
    assert evaluator._evaluation_cache[id(deferred)][0] is deferred
    rewrite_cache_size = len(evaluator._deferred_rewrite_cache)
    assert evaluator._rewrite_deferred_memory(deferred) is rewritten
    assert len(evaluator._deferred_rewrite_cache) == rewrite_cache_size


def test_definedness_cache_rejects_mutated_runtime_knownness_evidence():
    transform = transition()
    before = state()
    evidence = known()
    evaluator = _TransformEvaluator(before, transform.memory_writes, evidence)
    expression = ExprSlice(ExprId("RSI", 64), 0, 1)
    assert transform._eval_source_definedness(
        expression, before, evidence, evaluator, write_prefix=0,
    ) == 1
    evidence["RSI"] = 0
    with pytest.raises(SymbolEvaluationError, match="runtime knownness evidence"):
        transform._eval_source_definedness(
            expression, before, evidence, evaluator, write_prefix=0,
        )


def test_evaluation_context_does_not_reuse_values_across_states():
    transform = transition()
    first = state()
    second = state()
    second.write_register("RBX", 0x5678)
    first_pairs, _ = transform.eval_source_transition(first, known())
    second_pairs, _ = transform.eval_source_transition(second, known())
    assert first_pairs["RDX"][0] == 0x1234
    assert second_pairs["RDX"][0] == 0x5678
