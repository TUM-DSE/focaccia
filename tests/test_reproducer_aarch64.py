"""Source-only AArch64 exact-context regressions; no guest execution required."""

import pytest

from focaccia.arch.aarch64 import ArchAArch64
from focaccia.arch.x86 import ArchX86
from focaccia.reproducer_aarch64 import (
    AArch64Block,
    AArch64ReproducerError,
    generate_aarch64_reproducer,
)
from focaccia.snapshot import ProgramState


NOP = bytes.fromhex("1f2003d5")


def state(pc=0x400000):
    result = ProgramState(ArchAArch64("little"))
    result.write_register("PC", pc)
    return result


def generate(snapshot=None, block=None, **kwargs):
    return generate_aarch64_reproducer(
        state() if snapshot is None else snapshot,
        AArch64Block(0x400000, NOP, 0x400000) if block is None else block,
        required_registers=kwargs.pop("required_registers", ()), **kwargs,
    )


def test_complete_gprs_sp_and_nzcv_are_restored_without_clobber():
    snapshot = state()
    names = [f"X{i}" for i in range(31)]
    for i, name in enumerate(names):
        snapshot.write_register(name, 0x123456789ABC0000 + i)
    snapshot.write_register("SP", 0x876543210000)
    for name, value in zip("NZCV", (1, 0, 1, 1)):
        snapshot.write_register(name, value)
    source = generate(snapshot, required_registers=names + ["SP", "NZCV"])
    asm = source.assembly
    assert "mrs x16, nzcv" in asm
    assert "bfi x16, x17, #31, #1" in asm
    assert "movz x17, #0\n    bfi x16, x17, #30, #1" in asm
    assert asm.index("msr nzcv, x16") < asm.index("mov sp, x16")
    assert asm.index("mov sp, x16") < asm.index("movz x16, #0x10")
    assert "movk x30, #0x1234, lsl #48" in asm
    assert "    b reproduced_entry" in asm
    assert "br x" not in asm and "ret" not in asm and "push" not in asm


def test_only_requested_flag_bits_are_overwritten():
    snapshot = state()
    snapshot.write_register("Z", 1)
    asm = generate(snapshot, required_registers=["Z"]).assembly
    assert "mrs x16, nzcv" in asm
    assert "bfi x16, x17, #30, #1" in asm
    assert "#31, #1" not in asm and "#29, #1" not in asm
    with pytest.raises(AArch64ReproducerError, match="Unknown required input"):
        generate(snapshot, required_registers=["NZCV"])


@pytest.mark.parametrize("name", ["X0", "SP", "N", "W4", "LR"])
def test_unknown_required_register_fails_closed(name):
    with pytest.raises(AArch64ReproducerError, match="Unknown required input"):
        generate(required_registers=[name])


def test_known_w_alias_does_not_invent_unknown_upper_bits():
    snapshot = state()
    snapshot.write_register("W4", 42)
    with pytest.raises(AArch64ReproducerError, match="Unknown required input"):
        generate(snapshot, required_registers=["W4"])
    snapshot.write_register("X4", 0xFEDCBA980000002A)
    asm = generate(snapshot, required_registers=["W4"]).assembly
    assert "movz x4, #0x2a" in asm
    assert "movk x4, #0xfedc, lsl #48" in asm


@pytest.mark.parametrize("name", ["V0", "CPSR", "TPIDR", "DCZID_EL0", "not-a-register"])
def test_unsupported_register_classes_fail_closed(name):
    with pytest.raises(AArch64ReproducerError, match="Unsupported register"):
        generate(required_registers=[name])


def test_zero_register_and_pc_require_no_setup():
    asm = generate(required_registers=["XZR", "WZR", "PC"]).assembly
    assert "movz" not in asm


def test_memory_exact_address_order_overlap_and_cross_page():
    snapshot = state()
    snapshot.write_memory(0x80FFFE, bytes.fromhex("123456789abc"))
    source = generate(snapshot, memory_ranges=[(0x80FFFE, 4), (0x810000, 4)])
    assert source.memory == ((0x80FFFE, bytes.fromhex("123456789abc")),)
    assert ".memory_0 0x80fffe" in source.linker_script
    assert ".byte 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc" in source.assembly
    assert "PT_LOAD FLAGS(6)" in source.linker_script
    assert ".org" not in source.assembly


def test_unknown_memory_is_not_zero_filled():
    snapshot = state()
    snapshot.write_memory(0x800000, b"\x12")
    with pytest.raises(AArch64ReproducerError, match="Unknown required input"):
        generate(snapshot, memory_ranges=[(0x800000, 2)])


def test_destination_pc_has_unique_mapped_stop_landing_instruction():
    source = generate(block=AArch64Block(0x400000, NOP, 0x400000))
    assert source.entry_pc == source.transition_pc == 0x400000
    assert 'SIZEOF(.fragment) == 8' in source.linker_script
    assert source.assembly.count("reproduced_stop:") == 1
    assert "reproduced_stop:\n    .byte 0x1f, 0x20, 0x03, 0xd5" in source.assembly


def test_prefix_and_full_optimizer_block_are_retained_at_original_addresses():
    # A complete multi-instruction block, not merely the localized instruction.
    data = bytes.fromhex("200080d221fc40d3220041d3")
    block = AArch64Block(0x400000, data, 0x400004)
    source = generate(block=block)
    assert source.entry_pc == 0x400000 and source.transition_pc == 0x400004
    assert ".fragment 0x400000" in source.linker_script
    assert 'SIZEOF(.fragment) == 16' in source.linker_script
    assert ".byte 0x20, 0x00, 0x80, 0xd2" in source.assembly
    assert "reproduced_transition:\n    .byte 0x21, 0xfc, 0x40, 0xd3, 0x22, 0x00, 0x41, 0xd3" in source.assembly
    with pytest.raises(AArch64ReproducerError, match="block entry"):
        generate(state(0x400004), block)


@pytest.mark.parametrize("data", [bytes.fromhex("2000a1b8"), bytes.fromhex("200040d9")])
def test_atomic_and_ldapur_bytes_are_not_reassembled(data):
    source = generate(block=AArch64Block(0x400000, data, 0x400000))
    assert ".byte " + ", ".join(f"0x{v:02x}" for v in data) in source.assembly


@pytest.mark.parametrize("start,data,pc", [
    (-4, NOP, 0), (0x400001, NOP, 0x400001), (0x400000, b"", 0x400000),
    (0x400000, b"\x00", 0x400000), (0x400000, NOP, 0x400004),
    (0x400000, NOP, 0x400002), ((1 << 64) - 4, NOP * 2, (1 << 64) - 4),
])
def test_malformed_fragment_fails_closed(start, data, pc):
    with pytest.raises(AArch64ReproducerError):
        AArch64Block(start, data, pc)


def test_architecture_and_unknown_pc_rejected():
    for snapshot in [ProgramState(ArchX86()), ProgramState(ArchAArch64("big")), state()]:
        if snapshot.arch.isa == "aarch64" and snapshot.arch.endianness == "little":
            snapshot.strict = False
        with pytest.raises(AArch64ReproducerError):
            generate(snapshot)
    with pytest.raises(AArch64ReproducerError, match="Unknown required input"):
        generate(ProgramState(ArchAArch64("little")))


def test_far_branch_and_overlapping_pages_fail_closed():
    with pytest.raises(AArch64ReproducerError, match="branch range"):
        generate(state(0x9000000), AArch64Block(0x9000000, NOP, 0x9000000))
    with pytest.raises(AArch64ReproducerError, match="Load pages overlap"):
        generate(bootstrap_address=0x400000)
    snapshot = state()
    snapshot.write_memory(0x400100, b"x")
    with pytest.raises(AArch64ReproducerError, match="Load pages overlap"):
        generate(snapshot, memory_ranges=[(0x400100, 1)])


@pytest.mark.parametrize("data", [NOP, b"abcd"])
def test_code_data_aliasing_rejected_even_when_bytes_agree(data):
    snapshot = state()
    snapshot.write_memory(0x400000, data)
    with pytest.raises(AArch64ReproducerError, match="aliasing|conflicts"):
        generate(snapshot, memory_ranges=[(0x400000, 4)])


@pytest.mark.parametrize("kwargs", [
    {"page_size": 0}, {"page_size": 8193}, {"bootstrap_address": 3},
    {"memory_ranges": [(-1, 1)]}, {"memory_ranges": [(0x800000, 0)]},
    {"memory_ranges": [((1 << 64) - 1, 2)]},
])
def test_invalid_layout_rejected(kwargs):
    with pytest.raises(AArch64ReproducerError):
        generate(**kwargs)
