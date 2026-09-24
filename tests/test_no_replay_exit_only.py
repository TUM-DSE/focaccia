"""Exit-only native/consumer transactions with independent fake executions.

No native debugger, RR, emulator or guest is launched by these tests.
"""
from dataclasses import replace
from types import SimpleNamespace
import struct

import pytest

from focaccia.arch.arch import ArchitectureKey
from focaccia.deterministic import DeterministicCursor, EventSynchronizationError
from focaccia.execution import ExecutionOutcome, ExecutionState
from focaccia.native import tracer as native
from focaccia.no_replay import (
    ExitAction, ExitScope, NoReplayActionMismatch, UnsupportedNoReplayAction,
    require_exit_only_entry,
)
from focaccia.qemu.syscall import UnsupportedReplayEffect
from focaccia.utils import file_hash
from focaccia.trace import TraceEnvironment
from test_native_whole_program import Target, make_capture
from test_qemu_whole_program import terminal_target


def elf(tmp_path):
    data = bytearray(120)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HH', data, 16, 2, 62)
    struct.pack_into('<QQ', data, 24, 0x1000, 64)
    struct.pack_into('<HH', data, 54, 56, 1)
    struct.pack_into('<I', data, 64, 1)
    path = tmp_path / 'exit-only.elf'
    path.write_bytes(data)
    return path


@pytest.mark.parametrize('failure', [None, 'missing', 'arch', 'entry', 'hash', 'short', 'type', 'headers', 'interpreter'])
def test_exit_only_entry_contract(tmp_path, failure):
    path = elf(tmp_path)
    if failure in ('short', 'type', 'headers', 'interpreter'):
        data = bytearray(path.read_bytes())
        if failure == 'short':
            data = data[:32]
        elif failure == 'type':
            struct.pack_into('<H', data, 16, 3)
        elif failure == 'headers':
            struct.pack_into('<H', data, 56, 2)
        else:
            struct.pack_into('<I', data, 64, 3)
        path.write_bytes(data)
    args = (
        None if failure == 'missing' else str(path),
        'bad' if failure == 'hash' else file_hash(str(path)),
        0x1001 if failure == 'entry' else 0x1000,
        ArchitectureKey('aarch64' if failure == 'arch' else 'x86_64', 'little'),
    )
    if failure:
        with pytest.raises(UnsupportedNoReplayAction):
            require_exit_only_entry(*args)
    else:
        require_exit_only_entry(*args)


def capture(monkeypatch, tmp_path, *, target=None):
    target = target or Target()
    target.process = SimpleNamespace(GetNumThreads=lambda: 1)
    tracer = make_capture(monkeypatch, target, log=False, cross_validate=True)
    path = elf(tmp_path)
    tracer.env = TraceEnvironment(str(path), (), ())
    return tracer, target


@pytest.mark.parametrize('number,scope', [(60, ExitScope.THREAD), (231, ExitScope.GROUP)])
def test_native_no_rr_final_action_preserves_full_evidence(monkeypatch, tmp_path, number, scope):
    tracer, target = capture(monkeypatch, tmp_path)
    original = target.read_register
    target.read_register = lambda name: number if name == 'RAX' else original(name)
    trace = tracer.trace()
    assert trace.completion is not None
    assert trace.completion.no_replay_exit == ExitAction(0, scope)
    assert trace.completion.transform_count == 1
    assert trace.completion.state_count == 2
    assert trace.env.detlog is None
    assert target.runs == 1


@pytest.mark.parametrize('failure', ['threads', 'force', 'syscall', 'outcome', 'status', 'opcode'])
def test_native_exit_only_fails_closed(monkeypatch, tmp_path, failure):
    tracer, target = capture(monkeypatch, tmp_path)
    if failure == 'threads':
        target.process.GetNumThreads = lambda: 2
    elif failure == 'force':
        tracer.force = True
    elif failure == 'syscall':
        original = target.read_register
        target.read_register = lambda name: 999 if name == 'RAX' else original(name)
    elif failure == 'outcome':
        target.outcome = ExecutionOutcome(ExecutionState.EXITED)
    elif failure == 'status':
        target.outcome = ExecutionOutcome(ExecutionState.EXITED, exit_status=7)
    else:
        target.read_memory = lambda address, size: b'\x90' * size
    with pytest.raises((UnsupportedNoReplayAction, NoReplayActionMismatch)):
        tracer.trace()
    assert target.runs == (1 if failure in ('outcome', 'status') else 0)


def test_native_exit_only_accepts_fresh_remote_entry(monkeypatch, tmp_path):
    tracer, target = capture(monkeypatch, tmp_path)
    tracer.remote = 'native-gdbserver:123'
    trace = tracer.trace()
    assert trace.completion is not None
    assert trace.completion.no_replay_exit == ExitAction(0, ExitScope.THREAD)
    assert target.runs == 1


@pytest.mark.parametrize('number', [218])
def test_libc_registration_rejects_unproven_private_storage(monkeypatch, tmp_path, number):
    tracer, target = capture(monkeypatch, tmp_path)
    original = target.read_register
    registers = {'RAX': number, 'RDI': 0x1002, 'RSI': 0x2000}
    target.read_register = lambda name: registers[name] if name in registers else original(name)
    with pytest.raises(UnsupportedNoReplayAction, match='private writable static ELF storage'):
        tracer.trace()
    assert target.runs == 0


def no_rr_consumer(monkeypatch, **kwargs):
    target, expected, fake = terminal_target(monkeypatch, **kwargs)
    target._replay = None
    target._events = DeterministicCursor((), native.match_event)
    target._process = SimpleNamespace(threads=lambda: (object(),))
    expected = replace(expected, no_replay_exit=ExitAction(0, ExitScope.THREAD))
    target.enable_no_replay_exit_only(expected)
    return target, expected, fake


@pytest.mark.parametrize('status', [0, 7])
def test_qemu_exit_without_rr_never_substitutes_output(monkeypatch, status):
    target, expected, fake = no_rr_consumer(monkeypatch, status=status)
    before = fake.state.read_register('RDI')
    observed, action = target.execute_terminal_action(expected, retained_transform_count=2)
    assert observed.no_replay_exit == expected.no_replay_exit
    assert observed.outcome.exit_status == status
    assert action.expected == action.observed
    assert fake.state.read_register('RDI') == before
    assert target.steps == 1
    assert target.replay_coverage_report() is None


def test_qemu_exit_argument_mismatch_is_observed_without_substitution(monkeypatch):
    from focaccia.execution import TerminalComparison

    target, expected, fake = no_rr_consumer(monkeypatch)
    fake.state.write_register('RDI', 256)  # Same low-byte status remains a mismatch.
    observed, action = target.execute_terminal_action(expected, retained_transform_count=2)
    assert action.comparison is TerminalComparison.MISMATCH
    assert observed.no_replay_exit == action.observed == ExitAction(256, ExitScope.THREAD)
    assert target.steps == 1


@pytest.mark.parametrize('failure', ['unguarded', 'live', 'log', 'threads', 'missing-evidence'])
def test_qemu_exit_only_failures(monkeypatch, failure):
    target, expected, fake = no_rr_consumer(monkeypatch)
    if failure == 'unguarded':
        target._no_replay_exit_only = None
    elif failure == 'live':
        target.execute_replay_instruction = lambda: fake.state
    elif failure == 'log':
        target._replay = object()
    elif failure == 'threads':
        target._process.threads = lambda: (object(), object())
    else:
        expected = replace(expected, no_replay_exit=None)
    with pytest.raises((UnsupportedReplayEffect, EventSynchronizationError)):
        if failure in ('threads', 'missing-evidence'):
            target.enable_no_replay_exit_only(expected)
        else:
            target.execute_terminal_action(expected, retained_transform_count=2)
    assert target.steps == 0


@pytest.mark.parametrize('opcode', [b'\x0f\x05', b'\x0f\x34', b'\xcd\x80', b'\x48\x0f\x05', b'\x66\xcd\x80'])
def test_qemu_ordinary_prefix_cannot_cross_action(monkeypatch, opcode):
    target, expected, fake = no_rr_consumer(monkeypatch)
    fake.state.write_memory(expected.final_pc, opcode)
    with pytest.raises(UnsupportedReplayEffect, match='action boundary'):
        target._guard_no_replay_step()
    with pytest.raises(UnsupportedReplayEffect, match='run-until'):
        target.run_until(expected.final_pc + 2)
    assert target.steps == 0


def test_qemu_ordinary_prefix_allows_pure_instruction(monkeypatch):
    target, expected, fake = no_rr_consumer(monkeypatch)
    fake.state.write_memory(expected.final_pc, b'\x90\x90')
    target._guard_no_replay_step()
    assert target.steps == 0


@pytest.mark.parametrize('status', [0, 7])
def test_no_log_main_persists_independent_terminal_report(monkeypatch, tmp_path, status):
    import json
    from focaccia.trace import MaterializedTrace
    from test_qemu_report import load_qemu_tool
    from test_qemu_matching import state, trace, transform

    target, _, fake = no_rr_consumer(monkeypatch, status=status)
    tool = load_qemu_tool(monkeypatch)
    path = elf(tmp_path)
    # The ELF starts at 0x1000; one ordinary instruction precedes exit.
    fake.state.write_register('RIP', 0x1001)
    fake.state.write_memory(0x1001, b'\x0f\x05')
    from focaccia.no_replay import describe_no_replay_action
    from focaccia.completion import TraceCompletion, TraceScope
    expected = TraceCompletion(
        0x1001, 1, 2, ExecutionOutcome(ExecutionState.EXITED, exit_status=0),
        describe_no_replay_action(fake.state), no_replay_exit=ExitAction(0, ExitScope.THREAD),
    )
    target.enable_no_replay_exit_only(expected)
    ordinary = trace(transform(0x1000, 0x1001))
    oracle = MaterializedTrace(
        ordinary, TraceEnvironment(str(path), (), ()), ordinary.require_addresses(),
        scope=TraceScope.WHOLE_PROGRAM, completion=expected,
    )

    from focaccia.qemu.snapshot import plan_x86_scalar_context
    from focaccia.snapshot import RegisterAccessError

    source_state = state(0x1000)
    for concrete in (source_state, fake.state):
        for register in plan_x86_scalar_context(concrete).registers:
            try:
                concrete.read_register(register)
            except RegisterAccessError:
                concrete.write_register(register, 0)

    class Server:
        binary = str(path)
        arch = fake.arch

        def __iter__(self):
            return iter((source_state, fake.state))

        def current_state(self):
            return source_state

        def enable_no_replay_exit_only(self, value):
            assert value == expected

        def replay_coverage_report(self):
            return None

        def terminal_reason(self):
            return None

        def execute_terminal_action(self, *args, **kwargs):
            return target.execute_terminal_action(*args, **kwargs)

    source = tmp_path / 'oracle.json'
    source.write_text('{}')
    report = tmp_path / 'report.json'
    monkeypatch.setattr(tool, 'decode_gdb_arguments', lambda _: [
        '--symb-trace', str(source), '--remote', 'fake:123', '--quiet', '--report', str(report),
    ])
    monkeypatch.setattr(tool, 'DeterministicLog', lambda _: SimpleNamespace(events=lambda: ()))
    monkeypatch.setattr(tool.parser, 'parse_transformations', lambda _: oracle)
    monkeypatch.setattr(tool, 'GDBServerStateIterator', lambda *_: Server())
    tool.main()
    document = json.loads(report.read_text())
    assert document['completion']['complete'] is (status == 0)
    assert document['status'] == ('accepted' if status == 0 else 'mismatch')
    assert target.steps == 1


def test_terminal_report_binds_persisted_action_argument():
    from test_whole_program_report import evidence
    from focaccia.qemu.report import validation_report_document
    from focaccia.compare import ValidationReport
    kwargs = evidence()
    kwargs['expected_completion'] = replace(
        kwargs['expected_completion'], no_replay_exit=ExitAction(256, ExitScope.GROUP),
    )
    assert not validation_report_document(ValidationReport(), None, **kwargs)['completion']['complete']
