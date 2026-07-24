from __future__ import annotations

from collections.abc import Sequence
from typing import cast

import pytest
from miasm.expression.expression import ExprInt, ExprMem

from focaccia.arch import x86
from focaccia.reproducer import (
    FixedMemoryMapping,
    MemoryInitialization,
    RegisterRestore,
    Reproducer,
    ReproducerMemoryError,
    ReproducerRegisterError,
    plan_reproducer_memory,
    plan_x86_state_restore,
)
from focaccia.snapshot import ProgramState
from focaccia.symbolic import SymbolicTransform


class FakeReproducerTarget:
    def get_basic_block_inst(self, addr: int) -> list[str]:
        assert addr == 0x4000
        return ["nop", "ret"]

    def get_symbol_limit(self) -> int:
        return 0x8000


class FakeMemoryWrite:
    def __init__(self, address: ExprInt, size_bytes: int) -> None:
        self.address = address
        self.size_bytes = size_bytes


class FakeSymbolicInputs:
    def __init__(
        self,
        memory: Sequence[ExprMem] = (),
        registers: Sequence[str] = (),
        memory_writes: Sequence[FakeMemoryWrite] = (),
    ) -> None:
        self._memory = list(memory)
        self._registers = list(registers)
        self.memory_writes = list(memory_writes)

    def get_used_memory_addresses(self) -> list[ExprMem]:
        return list(self._memory)

    def get_used_registers(self) -> list[str]:
        return list(self._registers)


def make_reproducer(
    snapshot: ProgramState,
    symbolic: FakeSymbolicInputs,
) -> Reproducer:
    return Reproducer(
        "/tmp/oracle",
        [],
        snapshot,
        cast(SymbolicTransform, symbolic),
        lambda _oracle, _argv: FakeReproducerTarget(),
    )


def test_reproducer_memory_plan_aligns_merges_and_covers_cross_page_ranges():
    plan = plan_reproducer_memory(
        (
            (0x1FF8, b"abcdefghijklmnop"),
            (0x2008, b"qrst"),
            (0x5004, b"z"),
        )
    )

    assert plan.mappings == (
        FixedMemoryMapping(0x1000, 0x2000),
        FixedMemoryMapping(0x5000, 0x1000),
    )
    assert plan.initializations == (
        MemoryInitialization(0x1FF8, b"abcdefghijklmnopqrst"),
        MemoryInitialization(0x5004, b"z"),
    )


def test_reproducer_memory_plan_merges_consistent_overlaps_and_rejects_conflicts():
    plan = plan_reproducer_memory(((0x2000, b"abcd"), (0x2002, b"cdef"), (0x2010, b"x")))

    assert plan.mappings == (FixedMemoryMapping(0x2000, 0x1000),)
    assert plan.initializations == (
        MemoryInitialization(0x2000, b"abcdef"),
        MemoryInitialization(0x2010, b"x"),
    )

    with pytest.raises(ReproducerMemoryError, match="Conflicting values.*0x2002"):
        plan_reproducer_memory(((0x2000, b"abc"), (0x2002, b"X")))


def test_reproducer_memory_emission_uses_checked_exact_runtime_mappings():
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    snapshot.write_memory(0x1FFC, b"crossing")
    symbolic = FakeSymbolicInputs((ExprMem(ExprInt(0x1FFC, 64), 64),))
    reproducer = make_reproducer(snapshot, symbolic)

    plan = reproducer.memory_plan()
    setup = reproducer.get_dyn()
    allocator = reproducer.get_alloc()

    assert plan.mappings == (FixedMemoryMapping(0x1000, 0x2000),)
    assert "movabsq $0x1000, %rdi" in setup
    assert "movabsq $0x2000, %rsi" in setup
    assert "MAP_FIXED_NOREPLACE" in allocator
    assert "cmpq %rdi, %rax" in allocator
    assert "jne _reproducer_fail" in allocator
    assert ".org" not in reproducer.get_data()
    assert "movabsq $0x1ffc, %rax" in setup
    assert setup.count("movb $") == len(b"crossing")


def test_reproducer_memory_plan_maps_write_destinations_without_inventing_bytes():
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    symbolic = FakeSymbolicInputs(memory_writes=(FakeMemoryWrite(ExprInt(0x8FFC, 64), 8),))

    plan = make_reproducer(snapshot, symbolic).memory_plan()

    assert plan.mappings == (FixedMemoryMapping(0x8000, 0x2000),)
    assert plan.initializations == ()


def test_reproducer_memory_plan_fails_when_snapshot_bytes_are_unknown():
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    symbolic = FakeSymbolicInputs((ExprMem(ExprInt(0x3000, 64), 8),))

    with pytest.raises(ReproducerMemoryError, match="Unable to plan memory"):
        make_reproducer(snapshot, symbolic).memory_plan()


def test_reproducer_state_restore_plan_canonicalizes_inputs_and_masks_flags():
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    snapshot.write_register("RAX", 0x1122334455667788)
    snapshot.write_register("RSP", 0x7FFF0000)
    snapshot.write_register("RFLAGS", 0x243)

    plan = plan_x86_state_restore(
        snapshot,
        ("AL", "RSP", "CF", "ZF", "RIP"),
        target_pc=0x4000,
    )

    assert plan.registers == (RegisterRestore("RAX", 0x1122334455667788),)
    assert plan.stack_pointer == RegisterRestore("RSP", 0x7FFF0000)
    assert plan.flags_mask == 0x41
    assert plan.flags_value == 0x41


def test_reproducer_state_restoration_is_call_free_and_restores_stack_last():
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    snapshot.write_register("RAX", 0x1234)
    snapshot.write_register("RSP", 0x7FFF1000)
    snapshot.write_register("RFLAGS", 0x243)
    reproducer = make_reproducer(
        snapshot,
        FakeSymbolicInputs(registers=("RAX", "RSP", "CF", "ZF")),
    )

    start = reproducer.get_start()
    restoration = reproducer.get_regs()
    block = reproducer.get_bb()

    assert start == "_start:\ncall _setup_dyn\njmp _restore_state\n"
    assert "pushfq $" not in restoration
    assert "pushfd" not in restoration
    assert "popfq" in restoration
    assert "call" not in restoration
    assert restoration.index("popfq") < restoration.index("%rax")
    assert restoration.index("%rax") < restoration.index("%rsp")
    assert restoration.rstrip().endswith("jmp _bb_0x4000")
    assert block == "_bb_0x4000:\nnop\njmp _exit\n"


def test_reproducer_state_restore_rejects_unsafe_or_unsupported_register_inputs():
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    snapshot.write_register("RFLAGS", 0x202)
    snapshot.write_register("XMM0", 0)

    with pytest.raises(ReproducerRegisterError, match="cannot be safely restored"):
        plan_x86_state_restore(snapshot, ("TF",), target_pc=0x4000)
    with pytest.raises(ReproducerRegisterError, match="unsupported register class ZMM0"):
        plan_x86_state_restore(snapshot, ("XMM0",), target_pc=0x4000)


def test_reproducer_state_restore_does_not_invent_unknown_base_register_bits():
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    snapshot.write_register("AL", 0x5A)

    with pytest.raises(ReproducerRegisterError, match="complete base-register.*RAX"):
        plan_x86_state_restore(snapshot, ("AL",), target_pc=0x4000)
