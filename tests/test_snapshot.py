import unittest
import pytest

from focaccia.arch import x86
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

def test_register_read_write(self):
    state = ProgramState(self.arch)
    for reg in x86.regnames:
        state.set_register(reg, 0x42)
    for reg in x86.regnames:
        val = state.read_register(reg)
        assert val == 0x42

def test_register_aliases_empty_state(self):
    state = ProgramState(self.arch)
    for reg in self.arch.all_regnames:
        with pytest.raises(RegisterAccessError): state.read_register(reg)

def test_register_aliases_read_write(self):
    state = ProgramState(self.arch)
    for reg in ['EAX', 'EBX', 'ECX', 'EDX']:
        state.set_register(reg, 0xa0ff0)

    for reg in ['AH', 'BH', 'CH', 'DH']:
        assert state.read_register(reg) == 0xf, reg
    for reg in ['AL', 'BL', 'CL', 'DL']:
        assert state.read_register(reg) == 0xf0, reg
    for reg in ['AX', 'BX', 'CX', 'DX']:
        assert state.read_register(reg) == 0x0ff0, reg
    for reg in ['EAX', 'EBX', 'ECX', 'EDX',
                'RAX', 'RBX', 'RCX', 'RDX']:
        assert state.read_register(reg) == 0xa0ff0, reg

def test_flag_aliases(self):
    flags = ['CF', 'PF', 'AF', 'ZF', 'SF', 'TF', 'IF', 'DF', 'OF',
             'IOPL', 'NT', 'RF', 'VM', 'AC', 'VIF', 'VIP', 'ID']
    state = ProgramState(self.arch)

    state.set_register('RFLAGS', 0)
    for flag in flags:
        assert state.read_register(flag) == 0

    state.set_register('RFLAGS',
                       x86.compose_rflags({'ZF': 1, 'PF': 1, 'OF': 0}))
    assert state.read_register('ZF') == 1, self.arch.get_reg_accessor('ZF')
    assert state.read_register('PF') == 1
    assert state.read_register('OF') == 0
    assert state.read_register('AF') == 0
    assert state.read_register('ID') == 0
    assert state.read_register('SF') == 0

    for flag in flags:
        state.set_register(flag, 1)
    for flag in flags:
        assert state.read_register(flag) == 1

    state.set_register('OF', 1)
    state.set_register('AF', 1)
    state.set_register('SF', 1)
    assert state.read_register('OF') == 1
    assert state.read_register('AF') == 1
    assert state.read_register('SF') == 1

