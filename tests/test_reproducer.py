from __future__ import annotations

from collections.abc import Sequence
from typing import cast

import pytest
from miasm.expression.expression import ExprInt, ExprMem

from focaccia.arch import x86
from focaccia.reproducer import (
    EntryPrefix,
    ExecutableFragment,
    FixedMemoryMapping,
    MemoryInitialization,
    RegisterRestore,
    Reproducer,
    ReproducerFragmentError,
    ReproducerMemoryError,
    ReproducerRegisterError,
    plan_reproducer_memory,
    plan_x86_state_restore,
    single_transition_reproducer_trace,
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
        validation_registers: Sequence[str] | None = None,
    ) -> None:
        self._memory = list(memory)
        self._registers = list(registers)
        self._validation_registers = list(
            registers if validation_registers is None else validation_registers
        )
        self.memory_writes = list(memory_writes)

    def get_used_memory_addresses(self) -> list[ExprMem]:
        return list(self._memory)

    def get_used_registers(self) -> list[str]:
        return list(self._registers)

    def get_validation_input_registers(self) -> list[str]:
        return list(self._validation_registers)


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
    assert block == (
        "_bb_0x4000:\n"
        ".global focaccia_reproducer_transition\n"
        "focaccia_reproducer_transition:\n"
        "nop\n"
        "jmp _exit\n"
    )


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


def test_exact_fragment_emission_preserves_bytes_and_uses_only_validation_inputs():
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x40105F)
    snapshot.write_register("RBP", 0x7000)
    symbolic = FakeSymbolicInputs(
        registers=("ZMM0", "RBP"),
        validation_registers=("RBP",),
    )
    reproducer = Reproducer(
        "/tmp/oracle",
        [],
        snapshot,
        cast(SymbolicTransform, symbolic),
        fragment=ExecutableFragment(0x40105F, 0x401064, b"\xc4\xe2\x70\xf7\xc3"),
    )

    source = reproducer.asm()

    assert reproducer.link_address == 0x40105F
    assert ".org" not in source
    assert ".global focaccia_reproducer_transition" in source
    assert ".byte 0xc4, 0xe2, 0x70, 0xf7, 0xc3" in source
    assert "movabsq $0x7000, %rbp" in source
    assert "%zmm0" not in source.lower()


def test_condition_code_seed_is_emitted_after_inputs_and_rejects_flag_dependencies():
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    snapshot.write_register("RAX", 1)
    symbolic = FakeSymbolicInputs(registers=("RAX",))
    reproducer = Reproducer(
        "/tmp/oracle",
        [],
        snapshot,
        cast(SymbolicTransform, symbolic),
        fragment=ExecutableFragment(0x4000, 0x4001, b"\x90"),
        condition_code_seed=1,
    )

    restoration = reproducer.get_regs()

    assert restoration.index("%rax") < restoration.index("cmpq $0x1, %r11")
    assert restoration.index("cmpq $0x1, %r11") < restoration.index("jmp _bb_0x4000")

    snapshot.write_register("RFLAGS", 1)
    flag_symbolic = FakeSymbolicInputs(registers=("CF",))
    with pytest.raises(ReproducerRegisterError, match="overwrite required input flags"):
        Reproducer(
            "/tmp/oracle",
            [],
            snapshot,
            cast(SymbolicTransform, flag_symbolic),
            fragment=ExecutableFragment(0x4000, 0x4001, b"\x90"),
            condition_code_seed=1,
        ).get_regs()


def test_exact_fragment_rejects_snapshot_or_symbolic_range_mismatch():
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    symbolic = FakeSymbolicInputs()

    with pytest.raises(ReproducerFragmentError, match="snapshot PC"):
        Reproducer(
            "/tmp/oracle",
            [],
            snapshot,
            cast(SymbolicTransform, symbolic),
            fragment=ExecutableFragment(0x4010, 0x4011, b"\x90"),
        )


def test_straight_line_entry_prefix_retains_original_transition_address():
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x401014)
    symbolic = FakeSymbolicInputs()
    reproducer = Reproducer(
        "/tmp/oracle",
        [],
        snapshot,
        cast(SymbolicTransform, symbolic),
        fragment=ExecutableFragment(0x401014, 0x401018, b"\x0f\x03\xc3\x90"),
        entry_prefix=EntryPrefix(0x401000, bytes(range(20))),
    )

    source = reproducer.asm()

    assert reproducer.link_address == 0x401000
    assert source.index("_start:") < source.index("_bb_0x401014:")
    assert "_restore_state:" not in source
    assert "_setup_dyn:" not in source


def test_single_transition_trace_binds_generated_binary_and_exact_bounds(tmp_path):
    binary = tmp_path / "reproducer"
    binary.write_bytes(b"generated executable")
    transform = SymbolicTransform(1, {}, [], x86.ArchX86(), 0x401000, 0x401005)

    trace = single_transition_reproducer_trace(transform, binary)

    assert tuple(trace) == (transform,)
    assert trace.require_addresses() == (0x401000,)
    assert trace.env.binary_name == str(binary)
    assert trace.env.binary_hash is not None
    assert trace.env.start_address == 0x401000
    assert trace.env.stop_address == 0x401005
    assert trace.env.architecture == x86.ArchX86().key
