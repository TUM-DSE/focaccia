import hashlib
import sys

import pytest

from focaccia.arch.x86 import ArchX86
from focaccia.qemu import transport_profile as profile
from focaccia.snapshot import RegisterAccessError
from test_gdb_program_state import (
    FakeFrame, FakeInferior, FakeValue, FakeVectorValue, load_target_module,
)


def legacy_stub_packet(low, high):
    # Independent transcription of v6.1.0's call (Q0,Q1) and helper's
    # little-endian emission (val_lo,val_hi), not the production inverse.
    val_hi, val_lo = low, high
    return val_lo.to_bytes(8, 'little') + val_hi.to_bytes(8, 'little')


@pytest.mark.parametrize('low,high', [
    (0x474D20, 0x44CBB0), (1, 0), (0, 1),
    (0xFEDCBA9876543210, 0x0123456789ABCDEF),
])
def test_exact_legacy_stub_mapping_and_current_path(monkeypatch, low, high):
    target = load_target_module(monkeypatch)
    architectural = low | high << 64
    wire = int.from_bytes(legacy_stub_packet(low, high), 'little')
    state = target.GDBProgramState(FakeInferior({}), FakeFrame({'xmm0': FakeVectorValue(wire, 128)}), ArchX86())
    state._xmm_read_transport = True
    assert state.read_register('XMM0') == architectural
    ordinary = target.GDBProgramState(FakeInferior({}), FakeFrame({'xmm0': FakeVectorValue(architectural, 128)}), ArchX86())
    assert ordinary.read_register('XMM0') == architectural
    sys.modules.pop('focaccia.qemu.target', None)


def test_profile_rejects_unknown_wide_observation(monkeypatch):
    target = load_target_module(monkeypatch)
    state = target.GDBProgramState(FakeInferior({}), FakeFrame({'ymm0': FakeVectorValue(1, 256)}), ArchX86())
    state._xmm_read_transport = True
    with pytest.raises(RegisterAccessError, match='128-bit XMM'):
        state.read_register('YMM0')
    sys.modules.pop('focaccia.qemu.target', None)


def test_profile_does_not_modify_scalar_or_memory(monkeypatch):
    target = load_target_module(monkeypatch)
    state = target.GDBProgramState(FakeInferior({0x1000: 0x12}), FakeFrame({'rax': FakeValue(0x1234, 8)}), ArchX86())
    state._xmm_read_transport = True
    assert state.read_register('RAX') == 0x1234
    assert state.read_memory(0x1000, 1) == b'\x12'
    sys.modules.pop('focaccia.qemu.target', None)


@pytest.mark.parametrize('register,size,value', [('YMM0', 256, 0), ('XMM32', 128, 0), ('XMM0', 128, -1), ('XMM0', 128, 1 << 128)])
def test_inverse_rejects_unidentified_shapes(register, size, value):
    with pytest.raises(ValueError):
        profile.normalize_xmm_read(value, register, size)


def test_binding_rejects_missing_local_process(tmp_path):
    with pytest.raises(OSError):
        profile.bind_xmm_read_transport(profile.XMM_READ_PROFILE, 17, 'x86_64', 'little', proc_root=tmp_path)
    with pytest.raises(ValueError, match='local QEMU'):
        profile.bind_xmm_read_transport(profile.XMM_READ_PROFILE, 0, 'x86_64', 'little', proc_root=tmp_path)


def test_binding_rejects_unknown_executable(tmp_path):
    task = tmp_path / '17'
    task.mkdir()
    (task / 'exe').write_bytes(b'not the audited emulator')
    with pytest.raises(ValueError, match='unaudited'):
        profile.bind_xmm_read_transport(profile.XMM_READ_PROFILE, 17, 'x86_64', 'little', proc_root=tmp_path)


def test_binding_verifies_identity_and_detects_replacement(tmp_path, monkeypatch):
    task = tmp_path / '17'
    task.mkdir()
    executable = task / 'exe'
    executable.write_bytes(b'fixture executable')
    monkeypatch.setattr(profile, 'XMM_READ_EXECUTABLE_SHA256', hashlib.sha256(executable.read_bytes()).hexdigest())
    binding = profile.bind_xmm_read_transport(profile.XMM_READ_PROFILE, 17, 'x86_64', 'little', proc_root=tmp_path)
    binding.verify_identity(17, proc_root=tmp_path)
    with pytest.raises(ValueError, match='process changed'):
        binding.verify_identity(18, proc_root=tmp_path)
    replacement = task / 'replacement'
    replacement.write_bytes(b'other executable')
    replacement.replace(executable)
    with pytest.raises(ValueError, match='executable changed'):
        binding.verify_identity(17, proc_root=tmp_path)


@pytest.mark.parametrize('name,isa,endian', [
    ('unknown', 'x86_64', 'little'),
    (profile.XMM_READ_PROFILE, 'aarch64', 'little'),
    (profile.XMM_READ_PROFILE, 'x86_64', 'big'),
])
def test_binding_rejects_wrong_profile_or_guest(name, isa, endian):
    with pytest.raises(ValueError, match='Unsupported'):
        profile.bind_xmm_read_transport(name, 17, isa, endian)


def test_profile_cannot_select_plugin_backend():
    from focaccia.tools.validate_qemu import make_argparser, validate_backend_options
    parser = make_argparser()
    args = parser.parse_args(['--symb-trace', 'oracle', '--use-socket', '--guest-arch', 'x86_64', '--qemu-xmm-read-profile', profile.XMM_READ_PROFILE])
    with pytest.raises(SystemExit):
        validate_backend_options(parser, args)
