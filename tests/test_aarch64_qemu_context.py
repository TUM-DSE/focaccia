"""Independent configured CPU identity, never native/emulated MRS outputs."""
from types import SimpleNamespace
import pytest
from focaccia.arch.aarch64 import ArchAArch64
from focaccia.snapshot import RegisterAccessError
from test_gdb_program_state import load_target_module, FakeFrame, FakeInferior, FakeValue, FakeRawValue, FakeVectorValue


@pytest.mark.parametrize('data', [bytes(16), bytes(range(16)), b'\xff' * 16])
def test_arm_vector_uses_exact_bytes_not_rendered_lane_arrays(monkeypatch, data):
    module = load_target_module(monkeypatch)
    state = module.GDBProgramState(FakeInferior({}), FakeFrame({'v0': FakeRawValue(data)}), ArchAArch64('little'))
    assert state.read_register('V0') == int.from_bytes(data, 'little')


def test_arm_vector_short_observation_rejects(monkeypatch):
    module = load_target_module(monkeypatch)
    value = FakeRawValue(bytes(15))
    value.type.sizeof = 16
    state = module.GDBProgramState(FakeInferior({}), FakeFrame({'v0': value}), ArchAArch64('little'))
    with pytest.raises(RegisterAccessError):
        state.read_register('V0')


@pytest.mark.parametrize('failure', [None, 'unbound', 'model', 'midr', 'el', 'absent'])
@pytest.mark.parametrize('permitted', [False, True])
def test_model_dczid_requires_independent_identity_and_controls(monkeypatch, failure, permitted):
    module = load_target_module(monkeypatch)
    values: dict[str, FakeValue | FakeRawValue | FakeVectorValue] = {'MIDR_EL1': FakeValue(0x411fd402, 8), 'SCTLR': FakeValue((1 << 14) if permitted else 0, 8),
              'cpsr': FakeValue(0x40000000, 4), 'x5': FakeValue(12345, 8)}
    if failure == 'midr':
        values['MIDR_EL1'] = FakeValue(0, 8)
    elif failure == 'el':
        values['cpsr'] = FakeValue(4, 4)
    elif failure == 'absent':
        del values['MIDR_EL1']
    frame = FakeFrame(values)
    state = module.GDBProgramState(FakeInferior({}), frame, ArchAArch64('little'))
    state._aarch64_cpu_context = None if failure == 'unbound' else 'max' if failure == 'model' else 'neoverse-v1'
    if failure:
        with pytest.raises(RegisterAccessError):
            state.read_register('DCZID_EL0')
    else:
        assert state.read_register('DCZID_EL0') == (4 if permitted else 20)
    assert 'x5' not in frame.reads  # no circular expected-value inference


@pytest.mark.parametrize('failure', [None, 'missing', 'exe', 'cpu', 'overrides', 'duplicate', 'unguarded'])
def test_configured_cpu_is_bound_to_actual_local_qemu_arguments(monkeypatch, tmp_path, failure):
    module = load_target_module(monkeypatch)
    executable = tmp_path / ('python' if failure == 'exe' else 'qemu-aarch64')
    executable.write_text('fixture')
    root = tmp_path / '71'
    root.mkdir()
    (root / 'exe').symlink_to(executable)
    cpu = 'max' if failure == 'cpu' else 'neoverse-v1,sve=off' if failure == 'overrides' else 'neoverse-v1'
    argv = ['qemu-aarch64', '-cpu', cpu, '-g', '1234', '/guest']
    if failure == 'duplicate':
        argv += ['-cpu', 'neoverse-v1']
    if failure != 'missing':
        (root / 'cmdline').write_bytes(b'\0'.join(s.encode() for s in argv) + b'\0')
    monkeypatch.setattr(module, 'Path', lambda path: root)
    target = module.GDBServerStateIterator.__new__(module.GDBServerStateIterator)
    target.arch = ArchAArch64('little')
    target._no_replay_exit_only = None if failure == 'unguarded' else object()
    target._independent_task_tid = lambda: 71
    target.current_state = lambda: SimpleNamespace(read_register=lambda name: 4)
    if failure:
        with pytest.raises(module.UnsupportedReplayEffect):
            target.configure_aarch64_cpu_context('neoverse-v1')
    else:
        target.configure_aarch64_cpu_context('neoverse-v1')
        assert target._aarch64_cpu_context_tid == 71
