import pytest

from focaccia.arch import aarch64, x86
from focaccia.snapshot import MemoryAccessError, ProgramState, RegisterAccessError

@pytest.fixture
def arch():
    return x86.ArchX86()

@pytest.fixture
def state(arch):
    return ProgramState(arch)

@pytest.mark.parametrize("reg", x86.regnames)
def test_register_access_empty_state(state, reg):
    with pytest.raises(RegisterAccessError):
        state.read_register(reg)

def test_register_read_write(arch):
    state = ProgramState(arch)
    for reg in x86.regnames:
        state.write_register(reg, 0x42)
    for reg in x86.regnames:
        val = state.read_register(reg)
        assert val == 0x42

def test_register_aliases_empty_state(arch):
    state = ProgramState(arch)
    for reg in arch.all_regnames:
        with pytest.raises(RegisterAccessError): 
            state.read_register(reg)

def test_register_aliases_read_write(arch):
    state = ProgramState(arch)
    for reg in ['EAX', 'EBX', 'ECX', 'EDX']:
        state.write_register(reg, 0xa0ff0)

    for reg in ['AH', 'BH', 'CH', 'DH']:
        assert state.read_register(reg) == 0xf, reg
    for reg in ['AL', 'BL', 'CL', 'DL']:
        assert state.read_register(reg) == 0xf0, reg
    for reg in ['AX', 'BX', 'CX', 'DX']:
        assert state.read_register(reg) == 0x0ff0, reg
    for reg in ['EAX', 'EBX', 'ECX', 'EDX']:
        assert state.read_register(reg) == 0xa0ff0, reg
    for reg in ['RAX', 'RBX', 'RCX', 'RDX']:
        with pytest.raises(RegisterAccessError):
            state.read_register(reg)

def test_partial_register_validity():
    state = ProgramState(x86.ArchX86())
    state.write_register('AH', 0xab)

    assert state.test_register('AH')
    assert state.read_register('AH') == 0xab
    assert not state.test_register('AL')
    assert not state.test_register('AX')
    assert not state.test_register('RAX')
    with pytest.raises(RegisterAccessError):
        state.read_register('AL')
    with pytest.raises(RegisterAccessError):
        state.read_register('RAX')

    state.write_register('AL', 0xcd)
    assert state.read_register('AX') == 0xabcd
    with pytest.raises(RegisterAccessError):
        state.read_register('EAX')

def test_explicit_zero_extended_register_write():
    state = ProgramState(x86.ArchX86())
    state.write_register_zero_extended('EAX', 0x89abcdef)

    assert state.read_register('EAX') == 0x89abcdef
    assert state.read_register('RAX') == 0x89abcdef

def test_aarch64_observed_and_zero_extended_writes_are_distinct():
    state = ProgramState(aarch64.ArchAArch64('little'))
    state.write_register('W0', 0x89abcdef)

    assert state.read_register('W0') == 0x89abcdef
    with pytest.raises(RegisterAccessError):
        state.read_register('X0')

    state.write_register_zero_extended('W0', 0x12345678)
    assert state.read_register('X0') == 0x12345678

def test_drop_registers_clears_values_and_validity():
    state = ProgramState(x86.ArchX86())
    state.write_register('RAX', 42)
    state.drop_registers()

    assert not state.test_register('RAX')
    with pytest.raises(RegisterAccessError):
        state.read_register('RAX')


def test_single_flag_does_not_initialize_rflags():
    state = ProgramState(x86.ArchX86())
    state.write_register('ZF', 1)

    assert state.read_register('ZF') == 1
    with pytest.raises(RegisterAccessError):
        state.read_register('RFLAGS')


def test_flag_aliases(arch):
    flags = ['CF', 'PF', 'AF', 'ZF', 'SF', 'TF', 'IF', 'DF', 'OF',
             'IOPL', 'NT', 'RF', 'VM', 'AC', 'VIF', 'VIP', 'ID']
    state = ProgramState(arch)

    state.write_register('RFLAGS', 0)
    for flag in flags:
        assert state.read_register(flag) == 0

    state.write_register('RFLAGS',
                         x86.compose_rflags({'ZF': 1, 'PF': 1, 'OF': 0}))
    assert state.read_register('ZF') == 1, arch.get_reg_accessor('ZF')
    assert state.read_register('PF') == 1
    assert state.read_register('OF') == 0
    assert state.read_register('AF') == 0
    assert state.read_register('ID') == 0
    assert state.read_register('SF') == 0

    for flag in flags:
        state.write_register(flag, 1)
    for flag in flags:
        assert state.read_register(flag) == 1

    state.write_register('OF', 1)
    state.write_register('AF', 1)
    state.write_register('SF', 1)
    assert state.read_register('OF') == 1
    assert state.read_register('AF') == 1
    assert state.read_register('SF') == 1


def test_unknown_register_names_fail_at_every_state_boundary():
    state = ProgramState(x86.ArchX86())

    with pytest.raises(RegisterAccessError, match="Not a register name"):
        state.test_register("NOT_A_REGISTER")
    with pytest.raises(RegisterAccessError, match="Not a register name"):
        state.read_register("NOT_A_REGISTER")
    with pytest.raises(RegisterAccessError, match="Not a register name"):
        state.write_register("NOT_A_REGISTER", 0)
    with pytest.raises(RegisterAccessError, match="Not a register name"):
        state.write_register_bits("NOT_A_REGISTER", 0, 0)
    with pytest.raises(RegisterAccessError, match="Not a register name"):
        state.write_register_zero_extended("NOT_A_REGISTER", 0)


def test_selected_register_bits_accumulate_without_inventing_unknown_bits():
    state = ProgramState(x86.ArchX86())

    state.write_register_bits("RAX", 0x05, 0x0F)
    assert state.known_register_bits()["RAX"] == (0x05, 0x0F)
    assert not state.test_register("AL")
    assert state.known_register_values() == {}
    assert state.known_register_values(include_partial=True) == {}

    state.write_register_bits("RAX", 0xA0, 0xF0)
    assert state.read_register("AL") == 0xA5
    assert not state.test_register("AX")
    assert state.known_register_bits()["RAX"] == (0xA5, 0xFF)
    assert state.known_register_values(include_partial=True)["AL"] == 0xA5


def test_register_bit_writes_validate_values_and_masks_before_mutation():
    state = ProgramState(x86.ArchX86())

    for value in (-1, 1 << 64):
        with pytest.raises(ValueError, match="Value does not fit"):
            state.write_register_bits("RAX", value, 1)
    for valid_mask in (-1, 1 << 64):
        with pytest.raises(ValueError, match="Validity mask does not fit"):
            state.write_register_bits("RAX", 0, valid_mask)

    state.write_register_bits("RAX", 0xFFFF, 0)
    assert state.known_register_bits() == {}
    assert not state.test_register("RAX")


def test_zero_extension_rejects_high_slices_and_masks_to_the_observed_width():
    state = ProgramState(x86.ArchX86())

    with pytest.raises(ValueError, match="low-bit slice"):
        state.write_register_zero_extended("AH", 0x12)

    state.write_register_zero_extended("EAX", 0x1_1234_5678)
    assert state.read_register("RAX") == 0x1234_5678
    assert state.known_register_bits()["RAX"] == (0x1234_5678, (1 << 64) - 1)


def test_constant_register_writes_do_not_create_mutable_state():
    state = ProgramState(aarch64.ArchAArch64("little"))

    state.write_register("XZR", (1 << 64) - 1)
    state.write_register_bits("WZR", (1 << 32) - 1, (1 << 32) - 1)
    state.write_register_zero_extended("WZR", (1 << 32) - 1)

    assert state.test_register("XZR")
    assert state.read_register("XZR") == 0
    assert state.read_register("WZR") == 0
    assert "XZR" not in state.known_register_bits()


def test_known_register_views_and_repr_preserve_partial_aliases():
    state = ProgramState(x86.ArchX86())
    state.write_register("AH", 0xAB)
    state.write_register("RBX", 0x42)

    assert state.known_register_values() == {"RBX": 0x42}
    assert state.known_register_values(include_partial=True) == {
        "AH": 0xAB,
        "RBX": 0x42,
    }
    rendered = repr(state)
    assert "Snapshot (x86_64)" in rendered
    assert "'AH': '0xab'" in rendered
    assert "'RBX': '0x42'" in rendered


def test_program_state_memory_methods_preserve_address_order():
    state = ProgramState(aarch64.ArchAArch64("big"))

    state.write_memory(0x1000, b"\x01\x02\x03\x04")

    assert state.read_memory(0x1000, 4) == b"\x01\x02\x03\x04"
    with pytest.raises(MemoryAccessError) as raised:
        state.read_memory(0x1004, 1)
    assert raised.value.mem_addr == 0x1004

