import pytest
from miasm.expression.expression import ExprCond, ExprId, ExprInt, ExprMem, ExprOp

from focaccia.arch.aarch64 import ArchAArch64
from focaccia.reduction import MemoryRequest, ReductionSession
from focaccia.snapshot import ProgramState
from focaccia.symbolic import MemoryWrite, SymbolEvaluationError, _TransformEvaluator


def state():
    result = ProgramState(ArchAArch64("little"))
    result.write_register("X0", 0x1000)
    return result


def deferred(address, prefix):
    return ExprOp("focaccia_memory_byte", ExprInt(address, 64), ExprInt(prefix, 64))


def finish(generator, data):
    with pytest.raises(StopIteration) as done:
        generator.send(data)
    return done.value.value


def test_pointer_chase_resumes_without_replaying_completed_nodes():
    p = ExprMem(ExprId("X0", 64), 64)
    expression = ExprMem(p + ExprInt(8, 64), 64)
    session = ReductionSession([expression], state())
    run = session.run()
    assert next(run) == MemoryRequest(0x1000, 8)
    assert run.send((0x2000).to_bytes(8, "little")) == MemoryRequest(0x2008, 8)
    count = session.nodes_evaluated
    assert finish(run, (7).to_bytes(8, "little")) == (7,)
    assert session.nodes_evaluated == count + 1
    assert session.closed


def test_overlap_and_same_dag_reuse():
    a = ExprMem(ExprInt(0x1000, 64), 16)
    b = ExprMem(ExprInt(0x1001, 64), 16)
    session = ReductionSession([a, b, a], state())
    run = session.run()
    assert next(run) == MemoryRequest(0x1000, 2)
    assert run.send(b"\x01\x02") == MemoryRequest(0x1002, 1)
    assert finish(run, b"\x03") == (513, 770, 513)
    assert session.bytes_captured == 3


def test_conditional_only_reads_selected_arm():
    expression = ExprCond(ExprInt(1, 1), ExprInt(7, 64), ExprMem(ExprInt(0, 64), 64))
    session = ReductionSession([expression], state())
    assert finish(session.run(), None) == (7,)
    assert session.requests == 0


def test_ordered_versions_and_original_entry_are_distinct():
    writes = [MemoryWrite(ExprInt(0x1000, 64), ExprInt(0x2211, 16)),
              MemoryWrite(ExprInt(0x1001, 64), ExprInt(0x33, 8))]
    session = ReductionSession([deferred(0x1001, 2), deferred(0x1001, 1),
                                deferred(0x1001, 0), deferred(0x1002, 2)], state(), writes)
    run = session.run()
    assert next(run) == MemoryRequest(0x1001, 1)
    assert run.send(b"\x44") == MemoryRequest(0x1002, 1)
    assert finish(run, b"\x55") == (0x33, 0x22, 0x44, 0x55)


def test_store_value_can_depend_on_entry_memory():
    writes = [MemoryWrite(ExprInt(0x2000, 64), deferred(0x1000, 0))]
    session = ReductionSession([deferred(0x2000, 1)], state(), writes)
    run = session.run()
    assert next(run) == MemoryRequest(0x1000, 1)
    assert finish(run, b"\x09") == (9,)


def test_cycle_fails_closed():
    writes = [MemoryWrite(ExprInt(0x1000, 64), deferred(0x1000, 1))]
    with pytest.raises(SymbolEvaluationError, match="Cyclic"):
        next(ReductionSession([deferred(0x1000, 1)], state(), writes).run())


@pytest.mark.parametrize("data", [None, b"", b"12", bytearray(b"1")])
def test_invalid_evidence(data):
    run = ReductionSession([deferred(0, 0)], state()).run()
    next(run)
    with pytest.raises(SymbolEvaluationError, match="evidence"):
        run.send(data)


def test_no_reads_after_sealing():
    session = ReductionSession([deferred(0, 0)], state())
    run = session.run()
    next(run)
    session.close()
    with pytest.raises(SymbolEvaluationError, match="sealing"):
        run.send(b"1")


@pytest.mark.parametrize("limits", [{"max_bytes": 0}, {"max_requests": 0}])
def test_memory_budget(limits):
    with pytest.raises(SymbolEvaluationError):
        next(ReductionSession([deferred(0, 0)], state(), **limits).run())


def test_registers_frozen_and_residual_reusable():
    source = state()
    x = ExprId("X0", 64)
    session = ReductionSession([x], source)
    source.write_register("X0", 9)
    assert finish(session.run(), None) == (0x1000,)
    assert finish(ReductionSession([x], source).run(), None) == (9,)
    with pytest.raises(SymbolEvaluationError):
        next(session.run())


def test_randomized_residuals_agree_with_existing_evaluator():
    import random

    rng = random.Random(719)
    x = ExprId("X0", 64)
    for _ in range(100):
        source = state()
        source.write_register("X0", rng.getrandbits(64))
        expression = ((x + ExprInt(rng.getrandbits(64), 64))
                      ^ ExprInt(rng.getrandbits(64), 64))
        expected = _TransformEvaluator(source, []).evaluate(expression)
        assert finish(ReductionSession([expression], source).run(), None) == (expected,)


def test_forwarded_pointer_discovers_source_read():
    pointer = ExprOp("focaccia_memory_byte", ExprInt(0x1000, 64), ExprInt(1, 64))
    writes = [MemoryWrite(ExprInt(0x1000, 64), ExprInt(0x80, 8))]
    session = ReductionSession([ExprMem(pointer, 8)], state(), writes)
    run = session.run()
    assert next(run) == MemoryRequest(0x80, 1)
    assert finish(run, b"\x07") == (7,)


def test_invalid_prefix_and_write_budget():
    with pytest.raises(SymbolEvaluationError, match="prefix"):
        next(ReductionSession([deferred(0, 1)], state()).run())
    writes = [MemoryWrite(ExprInt(0, 64), ExprInt(0, 64))]
    with pytest.raises(SymbolEvaluationError, match="byte budget"):
        next(ReductionSession([deferred(0, 1)], state(), writes, max_bytes=1).run())


def test_node_budget():
    with pytest.raises(SymbolEvaluationError, match="node budget"):
        ReductionSession([ExprInt(0, 64)], state(), max_nodes=0)
