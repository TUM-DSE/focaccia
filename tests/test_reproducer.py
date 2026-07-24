from __future__ import annotations

from collections.abc import Sequence
from typing import cast

import pytest
from miasm.expression.expression import ExprInt, ExprMem

from focaccia.arch import x86
from focaccia.reproducer import (
    FixedMemoryMapping,
    MemoryInitialization,
    Reproducer,
    ReproducerMemoryError,
    plan_reproducer_memory,
)
from focaccia.snapshot import ProgramState
from focaccia.symbolic import SymbolicTransform


class FakeReproducerTarget:
    def get_basic_block_inst(self, addr: int) -> list[str]:
        assert addr == 0x4000
        return ["nop", "ret"]

    def get_symbol_limit(self) -> int:
        return 0x8000


class FakeSymbolicInputs:
    def __init__(
        self,
        memory: Sequence[ExprMem] = (),
        registers: Sequence[str] = (),
    ) -> None:
        self._memory = list(memory)
        self._registers = list(registers)

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
    plan = plan_reproducer_memory(
        ((0x2000, b"abcd"), (0x2002, b"cdef"), (0x2010, b"x"))
    )

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


def test_reproducer_memory_plan_fails_when_snapshot_bytes_are_unknown():
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    symbolic = FakeSymbolicInputs((ExprMem(ExprInt(0x3000, 64), 8),))

    with pytest.raises(ReproducerMemoryError, match="Unable to plan memory"):
        make_reproducer(snapshot, symbolic).memory_plan()
