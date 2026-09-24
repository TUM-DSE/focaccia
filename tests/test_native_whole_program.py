"""Fake-only production capture regressions; no debugger, RR or guest launch."""
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast

import pytest

from focaccia.arch.x86 import ArchX86
from focaccia.completion import TraceScope
from focaccia.deterministic import (
    DeterministicCursor, Event, EventSynchronizationError, ExecTask, SyscallEvent,
)
from focaccia.execution import ExecutionOutcome, ExecutionState
from focaccia.native import tracer as module
from focaccia.native.tracer import SpeculativeTracer, SymbolicTracer, ValidationError
from focaccia.no_replay import NoReplayActionKind, UnsupportedNoReplayAction
from focaccia.symbolic import Instruction
from focaccia.tools.capture_transforms import create_symbolic_tracer, make_argparser
from focaccia.trace import TraceEnvironment


class Target:
    arch = ArchX86()

    def __init__(self, *, premature=False, wrong=False, outcome=None):
        self.pc = 0x1000
        self.process = SimpleNamespace(GetNumThreads=lambda: 1)
        self.exited = False
        self.premature = premature
        self.wrong = wrong
        self.outcome = outcome or ExecutionOutcome(ExecutionState.EXITED, exit_status=0)
        self.runs = 0
        self.reads = []

    def is_exited(self):
        return self.exited

    def read_pc(self):
        assert not self.exited, 'post-exit PC read'
        return self.pc

    def read_register(self, name):
        assert not self.exited, 'post-exit register read'
        self.reads.append((self.pc, name))
        return {'RIP': self.pc, 'RAX': 60, 'RDI': 0}[name]

    def read_memory(self, address, size):
        assert not self.exited, 'post-exit memory read'
        return b'\x90\x0f\x05'[address - 0x1000:address - 0x1000 + size]

    def get_current_tid(self):
        assert not self.exited
        return 1

    def step(self):
        self.pc += 2 if self.wrong else 1
        self.exited = self.premature

    def run(self):
        self.runs += 1
        self.exited = True

    def execution_outcome(self):
        assert self.exited
        return self.outcome


def make_capture(monkeypatch, target, *, events=None, log=True, cross_validate=False):
    arch = target.arch
    pre = SyscallEvent(0x1001, 1, arch, {'RIP': 0x1001, 'RAX': 60, 'RDI': 0},
                       (), arch, 60, 'entering', False, event_count=1)
    terminal = Event(None, 1, arch, {}, (), event_type='exit', event_count=2)
    records = (pre, terminal) if events is None else events(pre, terminal)
    detlog = SimpleNamespace(base_directory='/rr/fixture', events=lambda: records) if log else None
    env = TraceEnvironment(None, (), (), binary_hash=None, nondeterminism_log=cast(Any, detlog))
    monkeypatch.setattr(SymbolicTracer, 'create_debug_target', lambda self: target)
    monkeypatch.setattr(module, '_disassemble_instruction', lambda ctx, target, pc, cache:
                        Instruction.from_string('NOP' if pc == 0x1000 else 'SYSCALL',
                                                arch, pc, 1 if pc == 0x1000 else 2))
    return SymbolicTracer(env, whole_program=True, cross_validate=cross_validate)


@pytest.mark.parametrize('cross_validate', [False, True])
def test_whole_program_final_ordinary_transition_and_no_post_exit_reads(monkeypatch, cross_validate):
    target = Target()
    trace = make_capture(monkeypatch, target, cross_validate=cross_validate).trace()
    assert len(trace) == 1
    assert trace[0].range == (0x1000, 0x1001)
    assert trace.scope is TraceScope.WHOLE_PROGRAM
    assert trace.completion is not None
    assert trace.completion.final_pc == 0x1001
    assert trace.completion.state_count == 2
    assert trace.completion.terminal_action is not None
    assert trace.completion.terminal_action.kind is NoReplayActionKind.EXIT
    assert target.runs == 1
    assert target.exited


@pytest.mark.parametrize('cross_validate', [False, True])
@pytest.mark.parametrize('failure', ['premature', 'wrong'])
def test_whole_program_rejects_bad_final_ordinary_transition(monkeypatch, cross_validate, failure):
    target = Target(**{failure: True})
    capture = make_capture(monkeypatch, target, cross_validate=cross_validate)
    with pytest.raises(module.SpeculativeDivergenceError):
        capture.trace()
    assert target.runs == 0


@pytest.mark.parametrize('outcome', [
    ExecutionOutcome(ExecutionState.EXITED),
    ExecutionOutcome(ExecutionState.EXITED, backend_status=7),
    ExecutionOutcome(ExecutionState.UNKNOWN),
    ExecutionOutcome(ExecutionState.EXITED, termination_signal=15),
])
def test_whole_program_rejects_missing_or_ambiguous_outcome(monkeypatch, outcome):
    with pytest.raises((ValidationError, UnsupportedNoReplayAction)):
        make_capture(monkeypatch, Target(outcome=outcome)).trace()


@pytest.mark.parametrize('invalid', [None, 'filename', 'argv', 'task-count', 'tid', 'interpreter', 'entry', 'hash', 'state'])
def test_whole_program_exec_bootstrap_identity(monkeypatch, tmp_path, invalid):
    from miasm.analysis.binary import Container
    target = Target()
    binary = tmp_path / 'fixture'
    binary.write_bytes(b'bound executable fixture')
    bootstrap = Event(0x900, 1, target.arch, {}, (), 'instructionTrap', event_count=1)
    pre = SyscallEvent(0x902, 1, target.arch, {}, (), target.arch, 59, 'entering', False, event_count=2)
    post = SyscallEvent(0x1000, 1, target.arch,
                        {'RIP': 0x1000, 'RAX': 7 if invalid == 'state' else 60}, (),
                        target.arch, 59, 'exiting', False, event_count=3)
    pending = Event(0x1001, 1, target.arch, {}, (), 'instructionTrap', event_count=4)
    task = ExecTask(
        8 if invalid == 'task-count' else 3,
        2 if invalid == 'tid' else 1,
        bytes(tmp_path / 'other') if invalid == 'filename' else bytes(binary),
        (bytes(binary), b'bad' if invalid == 'argv' else b'input'),
        0x1000, 0, b'ld.so' if invalid == 'interpreter' else b'',
    )
    log = SimpleNamespace(base_directory='/rr/fixture', tasks=lambda: (task,))
    env = TraceEnvironment(str(binary), ('input',), (), nondeterminism_log=cast(Any, log))
    if invalid == 'hash':
        binary.write_bytes(b'changed after environment capture')
    monkeypatch.setattr(Container, 'from_stream', lambda *args:
                        SimpleNamespace(arch='x86_64', entry_point=0x999 if invalid == 'entry' else 0x1000))
    cursor = DeterministicCursor((bootstrap, pre, post, pending), module.match_event)
    if invalid:
        with pytest.raises(EventSynchronizationError):
            module._consume_native_exec_bootstrap(env, cast(Any, target), cursor)
        assert cursor.event_position == 0
    else:
        module._consume_native_exec_bootstrap(env, cast(Any, target), cursor)
        assert cursor.event_position == 3
        assert cursor.peek() is pending  # Unsupported post-entry effects are NOT skipped.


def test_whole_program_rejects_missing_outcome_api(monkeypatch):
    target = Target()
    monkeypatch.setattr(target, 'execution_outcome', None)
    with pytest.raises(ValidationError, match='observation API'):
        make_capture(monkeypatch, target).trace()


def test_whole_program_rejects_rr_tail_before_exit(monkeypatch):
    target = Target()
    def records(pre, terminal):
        return pre, terminal, Event(None, 1, target.arch, {}, (), event_type='exit', event_count=3)
    with pytest.raises(EventSynchronizationError, match='Unconsumed'):
        make_capture(monkeypatch, target, events=records).trace()
    assert target.runs == 0


def test_whole_program_rejects_rr_prefix(monkeypatch):
    target = Target()
    def records(pre, terminal):
        prefix = Event(0x999, 1, target.arch, {}, (), event_type='instructionTrap', event_count=1)
        shifted_pre = SyscallEvent(pre.pc, pre.tid, pre.arch, pre.registers, (),
                                   pre.arch, 60, 'entering', False, event_count=2)
        return prefix, shifted_pre, replace(terminal, event_count=3)
    with pytest.raises(EventSynchronizationError, match='prefix'):
        make_capture(monkeypatch, target, events=records).trace()
    assert target.runs == 0


def test_whole_program_no_log_syscalls_fail_before_execution(monkeypatch):
    target = Target()
    with pytest.raises(UnsupportedNoReplayAction, match='bound executable hash'):
        make_capture(monkeypatch, target, log=False).trace()
    assert target.runs == 0


@pytest.mark.parametrize('bound', ['start_address', 'stop_address'])
def test_whole_program_bounds_reject_before_target_creation(bound):
    env = TraceEnvironment(None, (), (), binary_hash=None, **cast(Any, {bound: 0x1000}))
    with pytest.raises(ValueError, match='bounds'):
        SymbolicTracer(env, whole_program=True)
    args = make_argparser().parse_args(['--whole-program', 'fixture'])
    with pytest.raises(ValueError, match='bounds'):
        create_symbolic_tracer(args, env, lambda *args, **kwargs: pytest.fail('target launched'))


def test_whole_program_cli_is_explicit():
    env = TraceEnvironment(None, (), (), binary_hash=None)
    args = make_argparser().parse_args(['--whole-program', 'fixture'])
    options = create_symbolic_tracer(args, env, lambda *args, **kwargs: kwargs)
    assert options['whole_program'] is True
    args = make_argparser().parse_args(['fixture'])
    options = create_symbolic_tracer(args, env, lambda *args, **kwargs: kwargs)
    assert 'whole_program' not in options


def test_old_unbounded_trace_does_not_claim_completion(monkeypatch):
    target = Target(premature=True)
    capture = make_capture(monkeypatch, target)
    capture.whole_program = False
    capture.target = cast(SpeculativeTracer, SimpleNamespace(
        is_exited=lambda: True, arch=target.arch,
    ))
    trace = capture.trace()
    assert trace.scope is TraceScope.UNSPECIFIED
    assert trace.completion is None


def test_native_no_log_exit_only_without_recorded_returns(monkeypatch):
    target = Target()
    target.process = SimpleNamespace(GetNumThreads=lambda: 1)
    monkeypatch.setattr(module, 'require_exit_only_entry', lambda *args: None)
    trace = make_capture(monkeypatch, target, log=False, cross_validate=True).trace()
    assert trace.completion is not None
    assert trace.completion.no_replay_exit is not None
    assert trace.completion.no_replay_exit.argument == 0
    assert trace.completion.no_replay_set_fs == ()
    assert target.runs == 1


@pytest.mark.parametrize('tid_return', [None, 1, 2])
def test_native_no_replay_set_fs_then_exit(monkeypatch, tid_return):
    from test_no_replay import set_fs_states
    from focaccia.no_replay import ExitAction, ExitScope
    before, after = set_fs_states()
    if tid_return is not None:
        before.write_register('RAX', 218)
        before.write_register('RDI', 0x4042b0)
        before.write_register('FS_BASE', 0x404178)
        after.write_register('RAX', tid_return)
        after.write_register('RDI', 0x4042b0)
        before.write_memory(0x4042b0, b'\x78\x56\x34\x12')
        after.write_memory(0x4042b0, b'\x78\x56\x34\x12')
    entry = before.read_pc()

    class SetFsTarget:
        arch = before.arch
        process = SimpleNamespace(GetNumThreads=lambda: 1)

        def __init__(self):
            self.state = before
            self.exited = False
            self.runs = 0

        def __getattr__(self, name):
            return getattr(self.state, name)

        def is_exited(self):
            return self.exited

        def get_current_tid(self):
            return 1

        def read_memory(self, address, size):
            if size == 2:
                return b'\x0f\x05'
            return self.state.read_memory(address, size)

        def step(self):
            pc = self.state.read_pc()
            if pc == entry:
                self.state = after
            elif pc == entry + 2:
                self.state.write_register('RAX', 60)
                self.state.write_register('RIP', entry + 9)
            elif pc == entry + 9:
                self.state.write_register('RDI', 0)
                self.state.write_register('RIP', entry + 16)
            else:
                pytest.fail('unexpected native instruction')

        def run_until(self, address):
            while self.state.read_pc() != address:
                self.step()

        def run(self):
            assert self.state.read_pc() == entry + 16
            self.runs += 1
            self.exited = True

        def execution_outcome(self):
            return ExecutionOutcome(ExecutionState.EXITED, exit_status=0)

    target = SetFsTarget()
    capture = make_capture(monkeypatch, target, log=False, cross_validate=True)
    monkeypatch.setattr(module, 'require_exit_only_entry', lambda *args: None)
    monkeypatch.setattr(module, 'require_private_tid_storage', lambda *args: None)
    instructions = {entry: ('SYSCALL', 2), entry + 2: ('MOV RAX, 0x3C', 7),
                    entry + 9: ('MOV RDI, 0x0', 7), entry + 16: ('SYSCALL', 2)}
    monkeypatch.setattr(module, '_disassemble_instruction', lambda ctx, target, pc, cache:
                        Instruction.from_string(instructions[pc][0], target.arch, pc, instructions[pc][1]))
    if tid_return == 2:
        from focaccia.no_replay import NoReplayActionMismatch
        with pytest.raises(NoReplayActionMismatch, match='Expected execution-context TID 1'):
            capture.trace()
        assert target.runs == 0
        return
    trace = capture.trace()
    assert len(trace) == 3
    assert trace.completion is not None
    assert trace.completion.no_replay_exit == ExitAction(0, ExitScope.THREAD)
    if tid_return is None:
        assert len(trace.completion.no_replay_set_fs) == 1
        boundary = trace.completion.no_replay_set_fs[0]
        assert boundary.base == 0x404178
    else:
        assert len(trace.completion.no_replay_set_tid) == 1
        boundary = trace.completion.no_replay_set_tid[0]
        assert boundary.address == 0x4042b0
        assert boundary.expected_tid == 1
        from focaccia.symbolic import EXECUTION_TID, SymbolicTransform
        first = trace[0]
        assert isinstance(first, SymbolicTransform)
        assert first.changed_regs['RAX'] == EXECUTION_TID
    assert boundary.transform_index == 0
    assert boundary.descriptor.pc == entry
    assert target.runs == 1


@pytest.mark.parametrize('failure', [None, 'missing', 'header', 'table', 'interpreter', 'readonly', 'range', 'end'])
def test_private_tid_storage_requires_static_writable_lifetime(tmp_path, failure):
    import struct
    from focaccia.no_replay import require_private_tid_storage, UnsupportedNoReplayAction
    data = bytearray(120)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HH', data, 16, 2, 62)
    struct.pack_into('<Q', data, 32, 64)
    struct.pack_into('<HH', data, 54, 56, 1)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 6, 0, 0x404000, 0, 0x100, 0x1000, 0x1000)
    address = 0x4042b0
    if failure == 'header':
        data[0] = 0
    elif failure == 'table':
        struct.pack_into('<H', data, 54, 55)
    elif failure == 'interpreter':
        struct.pack_into('<I', data, 64, 3)
    elif failure == 'readonly':
        struct.pack_into('<I', data, 68, 4)
    elif failure == 'range':
        address = 0x403fff
    elif failure == 'end':
        address = 0x404ffd
    binary = tmp_path / 'guest'
    binary.write_bytes(data)
    if failure:
        with pytest.raises(UnsupportedNoReplayAction):
            require_private_tid_storage(None if failure == 'missing' else str(binary), address)
    else:
        require_private_tid_storage(str(binary), address)


@pytest.mark.parametrize('register', [None, 'memory', 'RAX', 'FS_BASE', 'FS', 'RCX', 'R11', 'RFLAGS', 'RIP', 'RBX', 'RDI'])
def test_context_tid_transition_checks_independent_return_and_preserved_state(register):
    from test_no_replay import set_fs_states
    from focaccia.no_replay import snapshot_set_tid_inputs, validate_set_tid_transition, NoReplayActionMismatch
    before, after = set_fs_states()
    before.write_register('RAX', 218)
    before.write_register('FS_BASE', 0x404178)
    after.write_register('RAX', 11399)
    before.write_memory(before.read_register('RDI'), b'\x78\x56\x34\x12')
    after.write_memory(after.read_register('RDI'), b'\x78\x56\x34\x12')
    frozen = snapshot_set_tid_inputs(before)
    if register is not None:
        if register == 'memory':
            after.write_memory(after.read_register('RDI'), bytes(4))
        else:
            after.write_register(register, after.read_register(register) ^ 1)
        with pytest.raises(NoReplayActionMismatch):
            validate_set_tid_transition(frozen, after, 11399)
    else:
        assert validate_set_tid_transition(frozen, after, 11399).expected_tid == 11399


@pytest.mark.parametrize('failure', ['policy', 'flags', 'descriptor'])
def test_context_tid_contract_rejects_unsupported_context(failure):
    from test_no_replay import set_fs_states
    from focaccia.no_replay import (
        NoReplaySetTidBoundary, describe_no_replay_action,
        validate_set_tid_transition, UnsupportedNoReplayAction,
    )
    before, after = set_fs_states()
    if failure == 'descriptor':
        with pytest.raises(ValueError, match='SET_TID_ADDRESS descriptor'):
            NoReplaySetTidBoundary(0, describe_no_replay_action(before), 0x4042b0, 11399)
        return
    if failure == 'flags':
        before.write_register('RAX', 218)
        before.write_register('RFLAGS', 0x302)
    with pytest.raises(UnsupportedNoReplayAction):
        validate_set_tid_transition(before, after, 11399)
