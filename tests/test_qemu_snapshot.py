import pytest
from miasm.expression.expression import ExprId, ExprInt, ExprMem

from focaccia.arch import aarch64, x86
from focaccia.qemu.snapshot import (
    SnapshotPlanningError,
    collect_minimal_snapshot,
    plan_minimal_snapshot,
)
from focaccia.snapshot import MemoryAccessError, ProgramState, RegisterAccessError
from focaccia.symbolic import SymbolicTransform


ARCH = x86.ArchX86()


def state(pc: int, **registers: int) -> ProgramState:
    result = ProgramState(ARCH)
    result.write_register("PC", pc)
    for name, value in registers.items():
        result.write_register(name, value)
    return result


def incoming_transform() -> SymbolicTransform:
    return SymbolicTransform(
        1,
        {
            ExprId("RAX", 64): ExprInt(7, 64),
            ExprMem(ExprId("RDI", 64), 8): ExprInt(0xAA, 8),
        },
        [],
        ARCH,
        0x1000,
        0x1001,
    )


def outgoing_transform() -> SymbolicTransform:
    return SymbolicTransform(
        1,
        {
            ExprId("RAX", 64): ExprMem(ExprId("RSI", 64), 64),
        },
        [],
        ARCH,
        0x1001,
        0x1002,
    )


def test_shared_snapshot_plan_covers_incoming_outputs_and_outgoing_inputs():
    current = state(0x1001)

    plan = plan_minimal_snapshot(
        current,
        incoming_transform(),
        outgoing_transform(),
    )

    assert set(plan.registers) == {"RAX", "RSI"}
    assert {(item.address_state, item.expression.size) for item in plan.memory} == {
        ("previous", 8),
        ("current", 64),
    }


def test_snapshot_uses_previous_state_for_incoming_write_addresses():
    previous = state(0x1000, RDI=0x2000)
    current = state(0x1001, RAX=7, RSI=0x3000, RDI=0xDEAD)
    current.write_memory(0x2000, b"\xAA")
    current.write_memory(0x3000, b"abcdefgh")

    collection = collect_minimal_snapshot(
        previous,
        current,
        incoming_transform(),
        outgoing_transform(),
    )

    assert collection.issues == ()
    assert collection.state.read_pc() == 0x1001
    assert collection.state.read_register("RAX") == 7
    assert collection.state.read_register("RSI") == 0x3000
    assert collection.state.read_memory(0x2000, 1) == b"\xAA"
    assert collection.state.read_memory(0x3000, 8) == b"abcdefgh"
    with pytest.raises(MemoryAccessError):
        collection.state.read_memory(0xDEAD, 1)


def test_unavailable_snapshot_values_remain_unknown_with_diagnostics():
    previous = state(0x1000)
    current = state(0x1001, RSI=0x3000)

    collection = collect_minimal_snapshot(
        previous,
        current,
        incoming_transform(),
        outgoing_transform(),
    )

    kinds = {issue.kind for issue in collection.issues}
    assert kinds == {
        "register-unavailable",
        "memory-address-unavailable",
        "memory-unavailable",
    }
    with pytest.raises(RegisterAccessError):
        collection.state.read_register("RAX")
    with pytest.raises(MemoryAccessError):
        collection.state.read_memory(0x3000, 8)


def test_mmx_source_planning_does_not_request_simd_state():
    current = state(0x1000)
    transform = SymbolicTransform(
        1,
        {ExprId("R8", 64): ExprId("MM0", 64)},
        [],
        ARCH,
        0x1000,
        0x1004,
    )

    plan = plan_minimal_snapshot(current, None, transform)

    assert set(plan.registers) == {"MM0"}
    assert "ZMM0" not in plan.registers


def test_terminal_snapshot_collects_incoming_outputs_without_outgoing_transform():
    previous = state(0x1000, RDI=0x2000)
    current = state(0x1001, RAX=9)
    current.write_memory(0x2000, b"\xBB")

    collection = collect_minimal_snapshot(
        previous,
        current,
        incoming_transform(),
        None,
    )

    assert collection.state.read_pc() == 0x1001
    assert collection.state.read_register("RAX") == 9
    assert collection.state.read_memory(0x2000, 1) == b"\xBB"


def test_snapshot_planner_rejects_concrete_architecture_mismatch():
    current = ProgramState(aarch64.ArchAArch64("little"))
    current.write_register("PC", 0x1001)

    with pytest.raises(SnapshotPlanningError, match="does not match"):
        plan_minimal_snapshot(current, incoming_transform(), None)
