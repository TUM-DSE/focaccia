"""Executed native TIR reduction/JIT tests; require the opt-in oracle package."""
import os
import random

import pytest
from miasm.expression.expression import ExprCompose, ExprId, ExprInt, ExprMem, ExprOp, ExprSlice

from focaccia.native_oracle import NativeOracle
from focaccia.reduction import ReductionSession, MemoryRequest
from focaccia.arch.aarch64 import ArchAArch64
from focaccia.snapshot import ProgramState


@pytest.fixture
def native():
    path = os.environ.get("FOCACCIA_NATIVE_ORACLE")
    if not path:
        pytest.skip("set FOCACCIA_NATIVE_ORACLE to exercise LLVM JIT")
    client = NativeOracle(path, hot_after=1)
    try:
        yield client
    finally:
        client.close()


def complete(run, data=None):
    with pytest.raises(StopIteration) as done:
        run.send(data)
    return done.value.value


def test_native_randomized_widths_and_reuse(native):
    rng = random.Random(192)
    for width in (1, 8, 16, 32, 64, 128):
        mask = (1 << width) - 1
        x, y = ExprId("a", width), ExprId("b", width)
        for op, operation in [("+", lambda a,b:a+b), ("-", lambda a,b:a-b),
                              ("*", lambda a,b:a*b), ("&", lambda a,b:a&b),
                              ("|", lambda a,b:a|b), ("^", lambda a,b:a^b)]:
            expression = ExprOp(op, x, y)
            plan = native.plan(expression)
            for _ in range(12):
                a, b = rng.getrandbits(width), rng.getrandbits(width)
                assert native.evaluate(plan, [a,b], (0x4000,op,width)) == operation(a,b) & mask
    assert native.stats["variant_hits"] > 0
    assert native.stats["guarded_calls"] > 0
    assert native.stats["compilations"] < native.stats["native_calls"]


def test_native_pointer_chase_and_multioperation_kernel(native):
    state = ProgramState(ArchAArch64("little"))
    state.write_register("X0", 0x1000)
    pointer = ExprMem(ExprId("X0", 64), 64)
    value = ExprMem(pointer, 64)
    expression = (value + ExprInt(3, 64)) * ExprInt(2, 64)
    for data, expected in [(7,20), (8,22)]:
        run = ReductionSession([expression], state, native=native,
                               native_context=(0x4000, "immutable-code")).run()
        assert next(run) == MemoryRequest(0x1000,8)
        assert run.send((0x2000).to_bytes(8,"little")) == MemoryRequest(0x2000,8)
        assert complete(run, data.to_bytes(8,"little")) == (expected,)
    assert native.stats["variant_hits"] >= 1


def test_guarded_variants_do_not_reuse_stale_runtime_bits(native):
    a, b = ExprId("a",1), ExprId("b",1)
    plan = native.plan(ExprOp("^",a,b))
    for values, expected in [([0,0],0), ([0,1],1), ([1,1],0), ([0,0],0)]:
        assert native.evaluate(plan,values,"same-code") == expected
    assert native.stats["compilations"] == 3
    assert native.stats["variant_hits"] == 1


def test_runtime_carry_reduction_and_guard_changes(native):
    x, y = ExprId("X0",64), ExprId("X1",64)
    carry = ExprSlice(ExprId("CPSR",32),29,30)
    expression = x + y + ExprCompose(carry,ExprInt(0,63))
    state = ProgramState(ArchAArch64("little"))
    state.write_register("X0", 3)
    state.write_register("X1", 4)
    for flag in (0,1,0,1):
        state.write_register("CPSR",flag << 29)
        run = ReductionSession([expression],state,native=native,native_context="adc").run()
        assert complete(run) == (7+flag,)
    assert native.stats["guarded_calls"] == 4
    assert native.stats["compilations"] == 2
    assert native.stats["variant_hits"] == 2


def test_bounded_cache_eviction_recompiles_safely(native):
    plan = native.plan(ExprId("a",64) + ExprInt(1,64))
    for index in range(260):
        assert native.evaluate(plan,[index],f"pc-{index}") == index+1
    assert native.evaluate(plan,[7],"pc-0") == 8
    assert native.stats["compilations"] == 261


def test_plan_budget_and_cold_policy():
    # Plan construction has no dependency on an oracle subprocess.
    from collections import OrderedDict
    client = object.__new__(NativeOracle)
    client.plans = OrderedDict()
    client.hits = OrderedDict()
    client.hot_after = 2
    expression = ExprId("a",64) + ExprInt(1,64)
    plan = client.plan(expression)
    assert not client.hot(plan,"pc1")
    assert client.hot(plan,"pc1")
    assert not client.hot(plan,"pc2")
    assert client.plan(ExprMem(ExprId("a",64),64)) is None
