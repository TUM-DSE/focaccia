import pytest

from focaccia.arch import aarch64, x86
from focaccia.snapshot import ProgramState, RegisterAccessError

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

