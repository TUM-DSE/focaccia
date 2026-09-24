from __future__ import annotations

from collections.abc import Sequence
import struct
from typing import cast

import pytest
from miasm.expression.expression import ExprInt, ExprMem

from focaccia.arch import x86
from focaccia.reproducer import (
    EntryPrefix,
    ExecutableFragment,
    FixedMemoryMapping,
    MemoryInitialization,
    PackedRegisterRestore,
    RegisterRestore,
    Reproducer,
    ReproducerFragmentError,
    ReproducerMemoryError,
    ReproducerRegisterError,
    X86StateRestorePlan,
    extract_executable_fragment,
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
    assert "cmpq $-17, %rax" in allocator
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
        plan_x86_state_restore(snapshot, ("ZMM0",), target_pc=0x4000)


@pytest.mark.parametrize("index", [0, 7, 8, 15])
def test_simd_mmx_restores_canonical_known_xmm_without_zeroing_upper_bits(index):
    from miasm.arch.x86.arch import mn_x86
    from miasm.core.locationdb import LocationDB

    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    value = 0xFFEEDDCCBBAA99887766554433221100
    snapshot.write_register_bits(f"ZMM{index}", value, (1 << 128) - 1)
    name = f"XMM{index}"
    reproducer = make_reproducer(snapshot, FakeSymbolicInputs(registers=(name,)))

    assert reproducer.register_plan().packed_registers == (PackedRegisterRestore(name, value),)
    assert f"movdqu _restore_xmm{index}(%rip), %xmm{index}" in reproducer.get_regs()
    assert "vmov" not in reproducer.get_regs()
    assert "xor" not in reproducer.get_regs()
    expected = Reproducer._byte_directives(value.to_bytes(16, "little"))[0]
    assert f"_restore_xmm{index}:\n{expected}\n" in reproducer.get_data()
    assert snapshot.known_register_bits()[f"ZMM{index}"][1] == (1 << 128) - 1
    instruction = mn_x86.fromstring(
        f"MOVDQU {name}, XMMWORD PTR [RIP + 0x10]", LocationDB(), 64
    )
    encodings = mn_x86.asm(instruction)
    assert encodings
    assert all(b"\x0f\x6f" in encoding for encoding in encodings)  # legacy opcode


@pytest.mark.parametrize("index", [0, 7])
def test_simd_mmx_restores_exact_mmx_with_valid_instruction(index):
    from miasm.arch.x86.arch import mn_x86
    from miasm.core.locationdb import LocationDB

    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    value = 0xFEDCBA9876543210
    name = f"MM{index}"
    snapshot.write_register(name, value)
    reproducer = make_reproducer(snapshot, FakeSymbolicInputs(registers=(name,)))

    assert reproducer.register_plan().packed_registers == (PackedRegisterRestore(name, value),)
    assert f"movq _restore_mm{index}(%rip), %mm{index}" in reproducer.get_regs()
    assert "emms" not in reproducer.get_regs()
    assert Reproducer._byte_directives(value.to_bytes(8, "little"))[0] in reproducer.get_data()
    # Assemble the emitted operation with a resolved RIP-relative displacement.
    instruction = mn_x86.fromstring(f"MOVQ {name}, QWORD PTR [RIP + 0x10]", LocationDB(), 64)
    assert mn_x86.asm(instruction)


@pytest.mark.parametrize("name,value", [("XMM16", 0), ("MM8", 0), ("MM0", -1), ("XMM0", 1 << 128)])
def test_simd_mmx_restore_values_are_validated(name, value):
    with pytest.raises(ValueError):
        PackedRegisterRestore(name, value)


@pytest.mark.parametrize("name,width", [("XMM0", 128), ("MM0", 64)])
def test_simd_mmx_unknown_required_bits_fail_closed(name, width):
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    snapshot.write_register_bits(name, 0, (1 << (width - 1)) - 1)
    with pytest.raises(ReproducerRegisterError, match="known value.*unknown bit mask"):
        plan_x86_state_restore(snapshot, (name,), target_pc=0x4000)


@pytest.mark.parametrize("upper_mask", [1 << 128, ((1 << 512) - 1) ^ ((1 << 128) - 1)])
def test_simd_mmx_observed_upper_context_fails_closed(upper_mask):
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    snapshot.write_register_bits("ZMM0", 0, ((1 << 128) - 1) | upper_mask)
    with pytest.raises(ReproducerRegisterError, match="observed upper context"):
        plan_x86_state_restore(snapshot, ("XMM0",), target_pc=0x4000)


@pytest.mark.parametrize("index", range(16))
def test_ymm_restore_exact_known_256_bits(index):
    name = f"YMM{index}"
    value = int.from_bytes(bytes(range(32)), "little")
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    snapshot.write_register(name, value)
    plan = plan_x86_state_restore(snapshot, (name,), target_pc=0x4000)
    assert plan.packed_registers == (PackedRegisterRestore(name, value),)
    assert plan.packed_registers[0].size_bytes == 32
    reproducer = make_reproducer(snapshot, FakeSymbolicInputs(registers=(name,)))
    assert f"vmovdqu _restore_ymm{index}(%rip), %ymm{index}" in reproducer.get_regs()
    expected = "\n".join(Reproducer._byte_directives(bytes(range(32))))
    assert f"_restore_ymm{index}:\n{expected}\n" in reproducer.get_data()
    assert snapshot.known_register_bits()[f"ZMM{index}"][1] == (1 << 256) - 1


@pytest.mark.parametrize("mask", [(1 << 255) - 1, ((1 << 256) - 1) | (1 << 256)])
def test_ymm_restore_unknown_or_avx512_context_fails_closed(mask):
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    snapshot.write_register_bits("ZMM0", 0, mask)
    with pytest.raises(ReproducerRegisterError):
        plan_x86_state_restore(snapshot, ("YMM0",), target_pc=0x4000)


@pytest.mark.parametrize("name", ["YMM16", "ZMM0", "XMM16"])
def test_simd_mmx_unsupported_widths_do_not_zero_unknown_context(name):
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    snapshot.write_register(name, 1)
    with pytest.raises(ReproducerRegisterError, match="unsupported register class"):
        plan_x86_state_restore(snapshot, (name,), target_pc=0x4000)


def test_reproducer_state_restore_does_not_invent_unknown_base_register_bits():
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    snapshot.write_register("AL", 0x5A)

    with pytest.raises(ReproducerRegisterError, match="complete base-register.*RAX"):
        plan_x86_state_restore(snapshot, ("AL",), target_pc=0x4000)


def test_reproducer_state_restore_uses_known_32_bit_alias_without_inventing_upper_bits():
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    snapshot.write_register("EDI", 0xDEADBEEF)

    plan = plan_x86_state_restore(snapshot, ("EDI",), target_pc=0x4000)

    assert plan.registers == (RegisterRestore("EDI", 0xDEADBEEF),)
    reproducer = make_reproducer(snapshot, FakeSymbolicInputs(registers=("EDI",)))
    assert "movl $0xdeadbeef, %edi" in reproducer.get_regs()
    with pytest.raises(ReproducerRegisterError, match="complete base-register.*RDI"):
        plan_x86_state_restore(snapshot, ("RDI",), target_pc=0x4000)


def test_reproducer_narrow_input_preserves_observed_upper_context():
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    snapshot.write_register("RBX", 0xA5A5A5A5DEADBEEF)
    snapshot.write_register("RCX", 0x5A5A5A5ACAFEBABE)

    plan = plan_x86_state_restore(snapshot, ("EBX", "ECX"), target_pc=0x4000)

    assert plan.registers == (
        RegisterRestore("RBX", 0xA5A5A5A5DEADBEEF),
        RegisterRestore("RCX", 0x5A5A5A5ACAFEBABE),
    )
    reproducer = make_reproducer(snapshot, FakeSymbolicInputs(registers=("EBX", "ECX")))
    restoration = reproducer.get_regs()
    assert "movabsq $0xa5a5a5a5deadbeef, %rbx" in restoration
    assert "movabsq $0x5a5a5a5acafebabe, %rcx" in restoration
    assert "%ebx" not in restoration
    assert "%ecx" not in restoration


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


@pytest.fixture
def fragment_elf(tmp_path):
    """An inert ELF fixture: no compiler, debugger, or guest execution."""
    binary = tmp_path / "fragment.elf"
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH", ident, 2, 62, 1, 0x4000, 64, 0, 0, 64, 56, 1, 64, 0, 0
    )
    code = b"\x90\x48\x89\xd8\xc3"
    segment = struct.pack("<IIQQQQQQ", 1, 5, 0x1000, 0x4000, 0x4000, len(code), len(code), 0x1000)
    binary.write_bytes((header + segment).ljust(0x1000, b"\x00") + code)
    return binary


def test_fragment_extraction_preserves_virtual_address_bytes(fragment_elf):
    assert extract_executable_fragment(fragment_elf, 0x4000, 0x4005) == ExecutableFragment(
        0x4000, 0x4005, b"\x90\x48\x89\xd8\xc3"
    )
    assert extract_executable_fragment(
        fragment_elf, 0x4000, 0x4004, require_fallthrough=True
    ) == ExecutableFragment(0x4000, 0x4004, b"\x90\x48\x89\xd8")


@pytest.mark.parametrize(
    ("end", "diagnostic"),
    [(0x4002, "not instruction-aligned"), (0x4005, "changes control flow")],
)
def test_fragment_extraction_rejects_unsafe_entry_prefix(fragment_elf, end, diagnostic):
    with pytest.raises(ReproducerFragmentError, match=diagnostic):
        extract_executable_fragment(fragment_elf, 0x4000, end, require_fallthrough=True)


@pytest.mark.parametrize("start,end", [(-1, 1), (1, 1), (2, 1), (0, (1 << 64) + 1)])
def test_fragment_extraction_rejects_invalid_ranges_before_io(tmp_path, start, end):
    with pytest.raises(ReproducerFragmentError, match="Invalid executable fragment range"):
        extract_executable_fragment(tmp_path / "absent", start, end)


def test_fragment_extraction_reports_io_failure_with_cause(tmp_path):
    with pytest.raises(ReproducerFragmentError, match="Unable to extract executable range") as exc:
        extract_executable_fragment(tmp_path / "absent", 0x4000, 0x4001)
    assert isinstance(exc.value.__cause__, FileNotFoundError)


@pytest.mark.parametrize(
    "factory,args,diagnostic",
    [
        (ExecutableFragment, (-1, 1, b"xx"), "non-empty address range"),
        (ExecutableFragment, (1, 1, b""), "non-empty address range"),
        (ExecutableFragment, ((1 << 64) - 1, (1 << 64) + 1, b"xx"), "address width"),
        (ExecutableFragment, (0, 2, b"x"), "byte length"),
        (EntryPrefix, (-1, b"x"), "start does not fit"),
        (EntryPrefix, (1 << 64, b"x"), "start does not fit"),
        (EntryPrefix, (0, b""), "cannot be empty"),
        (EntryPrefix, ((1 << 64) - 1, b"xx"), "address width"),
        (RegisterRestore, ("RIP", 0), "Unsupported"),
        (RegisterRestore, ("RAX", -1), "does not fit"),
        (RegisterRestore, ("RAX", 1 << 64), "does not fit"),
        (X86StateRestorePlan, (-1, (), None, 0, 0), "target PC"),
        (X86StateRestorePlan, (1 << 64, (), None, 0, 0), "target PC"),
        (X86StateRestorePlan, (0, (), None, -1, 0), "flag mask"),
        (X86StateRestorePlan, (0, (), None, 1 << 64, 0), "flag mask"),
        (X86StateRestorePlan, (0, (), None, 1, 2), "unrequested bits"),
    ],
)
def test_fragment_and_state_plan_reject_invalid_contracts(factory, args, diagnostic):
    with pytest.raises(ValueError, match=diagnostic):
        factory(*args)


def test_fragment_contracts_copy_mutable_bytes_and_accept_address_limit():
    data = bytearray(b"\x90")
    # Exercise defensive normalization at an untyped caller boundary.
    fragment = ExecutableFragment((1 << 64) - 1, 1 << 64, cast(bytes, data))
    prefix = EntryPrefix((1 << 64) - 1, cast(bytes, data))
    data[0] = 0xCC
    assert fragment.data == prefix.data == b"\x90"
    assert prefix.end == fragment.end == 1 << 64


@pytest.mark.parametrize(
    "prefix,fragment,seed,diagnostic,error",
    [
        (None, None, -1, "signed immediate", ReproducerRegisterError),
        (None, None, 1 << 31, "signed immediate", ReproducerRegisterError),
        (EntryPrefix(0x3FFF, b"\x90"), None, 1, "exact entry prefix", ReproducerRegisterError),
        (EntryPrefix(0x3FFF, b"\x90"), None, None, "requires an exact", ReproducerFragmentError),
        (
            EntryPrefix(0x3FFE, b"\x90"),
            ExecutableFragment(0x4000, 0x4001, b"\x90"),
            None,
            "Entry prefix ends",
            ReproducerFragmentError,
        ),
    ],
)
def test_fragment_constructor_rejects_incompatible_context(
    prefix, fragment, seed, diagnostic, error
):
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    with pytest.raises(error, match=diagnostic):
        Reproducer(
            "/unused",
            [],
            snapshot,
            cast(SymbolicTransform, FakeSymbolicInputs()),
            fragment=fragment,
            entry_prefix=prefix,
            condition_code_seed=seed,
        )


def test_fragment_constructor_rejects_symbolic_end_mismatch():
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("RIP", 0x4000)
    transform = SymbolicTransform(1, {}, [], snapshot.arch, 0x4000, 0x4002)
    with pytest.raises(ReproducerFragmentError, match="differs from symbolic range"):
        Reproducer(
            "/unused",
            [],
            snapshot,
            transform,
            fragment=ExecutableFragment(0x4000, 0x4001, b"\x90"),
        )
