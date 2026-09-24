import pytest
from miasm.expression.expression import ExprId, ExprMem
from focaccia.arch.aarch64 import ArchAArch64
from focaccia.arch.x86 import ArchX86
from focaccia.snapshot import ProgramState, RegisterAccessError
from focaccia.qemu.snapshot import (
    SnapshotPlan, MemoryDependency, SnapshotPlanningError,
    collect_snapshot_plan, plan_aarch64_scalar_context,
)


def state():
    result = ProgramState(ArchAArch64('little'))
    for i in range(31):
        result.write_register(f'X{i}', i)
    for name, value in [('PC', 0x1000), ('SP', 0x8000), ('CPSR', 0), ('X4', 0x2000)]:
        result.write_register(name, value)
    return result


def test_cross_block_store_address_uses_frozen_source_register_not_live_value():
    original = state()
    frozen = collect_snapshot_plan(original, original, plan_aarch64_scalar_context(original))
    assert not frozen.issues
    original.write_register('X4', 0x9000)
    original.write_memory(0x2000, b'abcd')
    incoming = SnapshotPlan(original.arch, (), (MemoryDependency(ExprMem(ExprId('X4', 64), 32), 'previous'),))
    destination = collect_snapshot_plan(frozen.state, original, incoming)
    assert not destination.issues
    assert destination.state.read_memory(0x2000, 4) == b'abcd'
    assert frozen.state.read_register('X4') == 0x2000


def test_unavailable_scalar_context_is_not_zero_filled():
    original = ProgramState(ArchAArch64('little'))
    original.write_register('PC', 0x1000)
    frozen = collect_snapshot_plan(original, original, plan_aarch64_scalar_context(original))
    assert frozen.issues
    with pytest.raises(RegisterAccessError):
        frozen.state.read_register('X4')


def test_output_address_keeps_ordered_store_context():
    from miasm.expression.expression import ExprInt
    from focaccia.symbolic import SymbolicTransform
    from focaccia.qemu.snapshot import plan_minimal_snapshot
    before, after = state(), state()
    for current in (before, after):
        current.write_register('X0', 0x1000)
        current.write_register('X1', 0x1000)
    before.write_memory(0x1000, (0x9000).to_bytes(8, 'little'))
    after.write_memory(0x1000, (0x2000).to_bytes(8, 'little'))
    after.write_memory(0x2000, b'\xaa')
    first = SymbolicTransform(1, {ExprMem(ExprId('X0', 64), 64): ExprInt(0x2000, 64)}, [], before.arch, 0x1000, 0x1004)
    second = SymbolicTransform(1, {ExprMem(ExprMem(ExprId('X1', 64), 64), 8): ExprInt(0xaa, 8)}, [], before.arch, 0x1004, 0x1008)
    combined = first.composed_with(second)
    collected = collect_snapshot_plan(before, after, plan_minimal_snapshot(after, combined, None))
    assert not collected.issues
    assert collected.state.read_memory(0x2000, 1) == b'\xaa'


def test_explicit_environment_context_is_retained_without_fabricating_missing_values():
    original = state()
    plan = plan_aarch64_scalar_context(original, include_dczid=True)
    unknown = collect_snapshot_plan(original, original, plan)
    assert any(issue.register == 'DCZID_EL0' for issue in unknown.issues)
    original.write_register('DCZID_EL0', 4)
    observed = collect_snapshot_plan(original, original, plan)
    assert not observed.issues
    assert observed.state.read_register('DCZID_EL0') == 4


def test_scalar_context_is_architecture_specific():
    with pytest.raises(SnapshotPlanningError):
        plan_aarch64_scalar_context(ProgramState(ArchX86()))
