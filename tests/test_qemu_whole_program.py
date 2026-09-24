"""RR-backed whole-program runtime wiring, with fake inferior execution only."""
from dataclasses import replace

import pytest

from focaccia.completion import TraceCompletion, TraceScope
from focaccia.deterministic import DeterministicCursor, Event, EventPairError, EventSynchronizationError
from focaccia.qemu.syscall import UnsupportedReplayEffect
from focaccia.execution import ExecutionOutcome, ExecutionState, TerminalComparison
from focaccia.no_replay import describe_no_replay_action
from focaccia.qemu.replay import X86ReplayEngine
from focaccia.qemu.report import validation_report_document
from focaccia.compare import ValidationReport
from test_gdb_program_state import load_target_module
from test_qemu_report import load_qemu_tool
from test_whole_program_report import evidence
from test_x86_replay import make_syscall_pair, make_target_for_event, full_write


def terminal_target(monkeypatch, *, argument=0, status=0, marker=True, cleanup=False):
    module = load_target_module(monkeypatch)
    pre, _ = make_syscall_pair(60, arguments={"rdi": argument})
    assert pre.pc is not None
    fake = make_target_for_event(pre)
    fake.state.write_memory(pre.pc, b"\x0f\x05")
    terminal = Event(None, pre.tid, pre.arch, {},
                     (full_write(pre.tid, 0x2000, b"\0"),) if cleanup else (),
                     event_type="exit", event_count=pre.event_count + 1)
    target = module.GDBServerStateIterator.__new__(module.GDBServerStateIterator)
    target.arch = fake.arch
    target._replay = X86ReplayEngine(fake.arch)
    target._replay_tid = pre.tid
    target._events = DeterministicCursor((pre, terminal) if marker else (pre,), module.match_event)
    target._events.synchronize(fake.state)
    target.steps = 0
    target.breakpoints = []

    class Breakpoint:
        def __init__(self, location, *, internal=False):
            self.location = location
            self.internal = internal
            self.deleted = False
            target.breakpoints.append(self)

        def delete(self):
            self.deleted = True

    monkeypatch.setattr(module.gdb, 'Breakpoint', Breakpoint)
    target.current_state = lambda: fake.state if not target.steps else pytest.fail("post-exit state read")
    target.is_exited = lambda: bool(target.steps)
    target.execution_outcome = lambda: ExecutionOutcome(ExecutionState.EXITED, exit_status=status)

    def execute(expected_pc=None):
        target.steps += 1
        return None

    target.execute_replay_instruction = execute
    expected = TraceCompletion(pre.pc, 2, 3, ExecutionOutcome(ExecutionState.EXITED, exit_status=0),
                               describe_no_replay_action(fake.state))
    return target, expected, fake


@pytest.mark.parametrize("status", [0, 7])
def test_runtime_exit_observes_independent_outcome_and_consumes_marker(monkeypatch, status):
    target, expected, _ = terminal_target(monkeypatch, status=status)
    observed, action = target.execute_terminal_action(expected, retained_transform_count=1)
    assert target.steps == 1
    assert target._events.peek() is None
    assert observed.outcome.exit_status == status
    assert observed.transform_count == 1
    assert expected.transform_count == 2
    assert action.expected == action.observed
    assert target.replay_coverage_report().records[-1].effect == "syscall:exit"


@pytest.mark.parametrize("failure", ["missing_marker", "cleanup", "opcode", "argument", "descriptor", "trailing"])
def test_unsupported_terminal_never_executes(monkeypatch, failure):
    target, expected, fake = terminal_target(monkeypatch, marker=failure != "missing_marker", cleanup=failure == "cleanup")
    if failure == "opcode":
        fake.state.write_memory(expected.final_pc, b"\x90\x90")
    elif failure == "argument":
        fake.state.write_register("RDI", 256)
    elif failure == "descriptor":
        fake.state.write_register("RAX", 231)
    elif failure == "trailing":
        target._events.events = (*target._events.events, target._events.events[-1])
    with pytest.raises((EventPairError, EventSynchronizationError, UnsupportedReplayEffect)):
        target.execute_terminal_action(expected, retained_transform_count=2)
    assert target.steps == 0


@pytest.mark.parametrize(
    "field",
    ["no_replay_set_fs", "no_replay_set_tid", "no_replay_mmap", "no_replay_mprotect"],
)
def test_gdb_collector_authorizes_every_interior_no_replay_action_kind(monkeypatch, field):
    tool = load_qemu_tool(monkeypatch)
    from types import SimpleNamespace
    from typing import Any, cast

    fields: dict[str, tuple[object, ...]] = dict(
        no_replay_set_fs=(),
        no_replay_set_tid=(),
        no_replay_mmap=(),
        no_replay_mprotect=(),
    )
    fields[field] = (object(),)
    assert tool._has_interior_no_replay_actions(cast(Any, SimpleNamespace(**fields)))
    fields[field] = ()
    assert not tool._has_interior_no_replay_actions(cast(Any, SimpleNamespace(**fields)))


def test_plugin_terminal_evidence_binds_process_binary_and_final_boundary(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from typing import Any, cast
    from focaccia.arch.x86 import ArchX86
    from focaccia.completion import TraceCompletion
    from focaccia.execution import ExecutionOutcome, ExecutionState, TerminalComparison
    from focaccia.match import MatchResult
    from focaccia.no_replay import ExitAction, ExitScope, NoReplayActionDescriptor, NoReplayActionKind
    from focaccia.qemu import validation_server
    from focaccia.snapshot import ProgramState
    from focaccia.trace import TraceEnvironment, TransitionTrace

    arch = ArchX86()
    state = ProgramState(arch)
    state.write_register("RIP", 0x1000)
    state.write_register("RAX", 231)
    state.write_register("RDI", 7)
    state.write_memory(0x1000, b"\x0f\x05")
    action = ExitAction(7, ExitScope.GROUP)
    completion = TraceCompletion(
        0x1000, 2, 3, ExecutionOutcome(ExecutionState.EXITED, exit_status=7),
        NoReplayActionDescriptor(arch.key, 0x1000, NoReplayActionKind.EXIT_GROUP),
        no_replay_exit=action,
    )
    env = TraceEnvironment("guest", (), (), binary_hash="a" * 64, architecture=arch.key)
    symbolic = SimpleNamespace(completion=completion, env=env)
    # The retained trace is a single composed terminal cutpoint, while two
    # oracle transforms have been semantically consumed.
    matched = MatchResult(TransitionTrace([state], (), env), (), consumed_transform_count=2)
    ready = tmp_path / "ready.json"
    evidence = tmp_path / "evidence.json"
    qemu = SimpleNamespace(pid=123, state=state, finish=lambda: None)

    def publish_evidence(_delay):
        import json
        binding = json.loads(ready.read_text())
        evidence.write_text(json.dumps({
            "schema": "focaccia-plugin-terminal-evidence-v1",
            "nonce": binding["nonce"], "pid": 123,
            "binarySha256": "a" * 64, "returncode": 7,
        }))

    monkeypatch.setattr(validation_server.time, "sleep", publish_evidence)
    observed, validation = validation_server._plugin_terminal_completion(
        cast(Any, qemu), cast(Any, symbolic), matched, str(ready), str(evidence), 1.0
    )
    assert observed.outcome.exit_status == 7
    assert observed.final_pc == state.read_pc()
    assert observed.transform_count == 2
    assert observed.state_count == 3
    assert validation.comparison is TerminalComparison.MATCH


def test_plugin_whole_program_rejects_before_connecting(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from focaccia.qemu import validation_server
    from focaccia.tools.validate_qemu import make_plugin_trace_environment
    from focaccia.compare import ErrorTypes
    source = tmp_path / "oracle.json"
    source.write_text("{}")
    monkeypatch.setattr(validation_server.parser, "parse_transformations", lambda _: SimpleNamespace(scope=TraceScope.WHOLE_PROGRAM))
    monkeypatch.setattr(validation_server, "PluginStateIterator", lambda *_: pytest.fail("must not connect"))
    with pytest.raises(ValueError, match="requires typed terminal evidence paths"):
        validation_server.start_validation_server(
            str(source), None, "unused", "x86_64", make_plugin_trace_environment("x86_64"), ErrorTypes.INFO
        )


def test_terminal_step_never_retries_an_unchanged_pc(monkeypatch):
    target, _, fake = terminal_target(monkeypatch)
    target._executing_terminal_action = True
    target._terminal_reason = None
    target._require_stopped = lambda: None
    resumes = []
    target._resume = lambda command: resumes.append(command)
    target.is_exited = lambda: False
    result = type(target).execute_replay_instruction(target)
    assert result is fake.state
    assert resumes == ["si"]


def test_report_accepts_composed_prefix_only_with_consumption_proof():
    kwargs = evidence()
    kwargs["expected_completion"] = replace(kwargs["expected_completion"], transform_count=2, state_count=3)
    assert not validation_report_document(ValidationReport(), None, **kwargs)["completion"]["complete"]
    kwargs["match_result"] = replace(kwargs["match_result"], consumed_transform_count=2)
    assert validation_report_document(ValidationReport(), None, **kwargs)["completion"]["complete"]


def test_collector_dispatches_terminal_after_consumed_prefix_with_coverage_gaps(monkeypatch):
    tool = load_qemu_tool(monkeypatch)
    kwargs = evidence()
    from types import SimpleNamespace
    trace = SimpleNamespace(scope=TraceScope.WHOLE_PROGRAM, completion=kwargs["expected_completion"])
    matched = replace(kwargs["match_result"], consumed_transform_count=1)
    calls = []
    backend = SimpleNamespace(execute_terminal_action=lambda *a, **k: calls.append((a, k)) or (None, None))
    tool.collect_terminal_completion(backend, trace, matched)
    assert len(calls) == 1
    # Comparison incompleteness is retained in reporting but does not erase
    # independently established final-boundary/action evidence.
    incomplete = replace(
        matched, diagnostics=(SimpleNamespace(level='incomplete'),)
    )
    assert not incomplete.complete
    tool.collect_terminal_completion(backend, trace, incomplete)
    assert len(calls) == 2
    tool.collect_terminal_completion(backend, trace, replace(matched, consumed_transform_count=0))
    trace.scope = TraceScope.WITNESS
    tool.collect_terminal_completion(backend, trace, matched)
    assert len(calls) == 2


@pytest.mark.parametrize("status", [0, 7])
def test_main_collects_composed_prefix_executes_exit_and_persists_report(monkeypatch, tmp_path, status):
    import json
    from focaccia.trace import MaterializedTrace
    from test_qemu_matching import state, trace, transform
    target, expected, fake = terminal_target(monkeypatch, status=status)
    tool = load_qemu_tool(monkeypatch)
    ordinary = trace(transform(0xffe, 0xfff), transform(0xfff, 0x1000))
    oracle = MaterializedTrace(ordinary, ordinary.env, ordinary.require_addresses(),
                               scope=TraceScope.WHOLE_PROGRAM, completion=expected)

    class Server:
        binary = "/guest"

        def __iter__(self):
            return iter((state(0xffe), fake.state))

        def replay_coverage_report(self):
            return target.replay_coverage_report()

        def terminal_reason(self):
            return None

        def execute_terminal_action(self, *args, **kwargs):
            return target.execute_terminal_action(*args, **kwargs)

    source = tmp_path / "oracle.json"
    source.write_text("{}")
    report = tmp_path / "report.json"
    snapshots = tmp_path / "states.json"
    monkeypatch.setattr(tool, "decode_gdb_arguments", lambda _: [
        "--symb-trace", str(source), "--remote", "fake:123", "--quiet",
        "--report", str(report), "--output", str(snapshots),
    ])
    from types import SimpleNamespace
    monkeypatch.setattr(tool, "DeterministicLog", lambda _: SimpleNamespace(events=lambda: (object(),)))
    monkeypatch.setattr(tool.parser, "parse_transformations", lambda _: oracle)
    monkeypatch.setattr(tool, "GDBServerStateIterator", lambda *_: Server())
    tool.main()
    document = json.loads(report.read_text())
    assert document["completion"]["complete"] is (status == 0)
    assert document["status"] == ("accepted" if status == 0 else "mismatch")
    assert document["trace"]["state_count"] == 2
    assert target.steps == 1
    # Use the real persistence reader, not the patched oracle reader.
    from focaccia.persistence import parse_snapshots
    with snapshots.open() as stream:
        restored = parse_snapshots(stream)
    assert restored.completion is not None
    assert restored.completion.outcome.exit_status == status
    assert restored.completion.transform_count == 1


@pytest.mark.parametrize('context_tid,tid_failure,syscall_clobber', [
    (None, None, False), (None, None, True), (222, None, False), (222, None, True),
    (222, 'return', False), (222, 'memory', False), (222, 'address', False),
    (222, 'order', False), (222, 'identity', False), (222, 'signal', False),
])
def test_collector_executes_and_validates_ordered_set_fs(
    monkeypatch, context_tid, tid_failure, syscall_clobber
):
    from types import SimpleNamespace
    from miasm.expression.expression import ExprId, ExprInt
    from focaccia.no_replay import ExitAction, ExitScope, NoReplayActionDescriptor, NoReplayActionKind, NoReplaySetFsBoundary
    from focaccia.symbolic import Instruction, SymbolicTransform
    from focaccia.trace import MaterializedTrace, TraceEnvironment
    from focaccia.compare import compare_symbolic
    from test_no_replay import set_fs_states
    target, _, _ = terminal_target(monkeypatch)
    before, after = set_fs_states()
    if syscall_clobber:
        after.write_register('R11', 0)
    pc = before.read_pc()
    action = NoReplaySetFsBoundary(0, describe_no_replay_action(before), 0x404178)
    if context_tid is not None:
        before.write_register('RAX', 218)
        before.write_register('RDI', 0x4042b0)
        before.write_register('FS_BASE', 0x404178)
        after.write_register('RAX', context_tid)
        after.write_register('RDI', 0x4042b0)
        before.execution_tid = after.execution_tid = context_tid
        before.write_memory(0x4042b0, b'\x78\x56\x34\x12')
        after.write_memory(0x4042b0, b'\x78\x56\x34\x12')
    expected = TraceCompletion(pc + 2, 1, 2, ExecutionOutcome(ExecutionState.EXITED, exit_status=0),
                               NoReplayActionDescriptor(before.arch.key, pc + 2, NoReplayActionKind.EXIT),
                               ExitAction(0, ExitScope.THREAD), (action,))
    transform = SymbolicTransform(
        1, {ExprId('RAX', 64): ExprInt(0, 64), ExprId('FS_BASE', 64): ExprId('RSI', 64),
            ExprId('RCX', 64): ExprInt(pc + 2, 64), ExprId('R11', 64): ExprId('RFLAGS', 64)},
        [Instruction.from_string('SYSCALL', before.arch, pc, 2)], before.arch, pc, pc + 2,
    )
    if context_tid is not None:
        from focaccia.no_replay import NoReplaySetTidBoundary
        from focaccia.symbolic import EXECUTION_TID
        native_action = NoReplaySetTidBoundary(0, describe_no_replay_action(before), 0x4042b0, 111)
        expected = replace(expected, no_replay_set_fs=(), no_replay_set_tid=(native_action,))
        transform = SymbolicTransform(
            111, {ExprId('RAX', 64): EXECUTION_TID,
                  ExprId('RCX', 64): ExprInt(pc + 2, 64), ExprId('R11', 64): ExprId('RFLAGS', 64)},
            [Instruction.from_string('SYSCALL', before.arch, pc, 2)], before.arch, pc, pc + 2,
        )
        action = replace(native_action, expected_tid=context_tid)
        import focaccia.qemu.target as target_module
        monkeypatch.setattr(target_module, 'require_private_tid_storage', lambda *args: None)
        target.binary = None
    oracle = MaterializedTrace((transform,), TraceEnvironment(None, (), (), binary_hash=None),
                               (pc,), scope=TraceScope.WHOLE_PROGRAM, completion=expected)
    target._replay = None
    target._events = DeterministicCursor((), lambda *_: False)
    target._process = SimpleNamespace(threads=lambda: (SimpleNamespace(ptid=(1, context_tid, 0)),))
    target._terminal_reason = None
    target._first_next = True
    target._require_stopped = lambda: None
    target.current_state = lambda: after if target.steps else before
    target.is_exited = lambda: False
    target._resume = lambda command: setattr(target, 'steps', target.steps + 1)
    target.enable_no_replay_exit_only(expected)
    if tid_failure == 'return':
        after.write_register('RAX', 223)
    elif tid_failure == 'memory':
        after.write_memory(0x4042b0, bytes(4))
    elif tid_failure == 'address':
        before.write_register('RDI', 0x4042b4)
    elif tid_failure == 'order':
        target.authorize_no_replay_source = lambda *args: None
    elif tid_failure == 'identity':
        target._no_replay_context_tid = 333
    elif tid_failure == 'signal':
        target._terminal_reason = object()
    tool = load_qemu_tool(monkeypatch)
    if tid_failure:
        from focaccia.no_replay import NoReplayActionMismatch
        with pytest.raises((UnsupportedReplayEffect, NoReplayActionMismatch)):
            tool.collect_conc_trace(target, oracle)
        assert target._observed_no_replay_set_tid == []
        return
    result = tool.collect_conc_trace(target, oracle)
    assert result.complete
    assert result.consumed_transform_count == 1
    assert target.steps == 1
    if context_tid is None:
        assert target._observed_no_replay_set_fs == [action]
    else:
        assert target._observed_no_replay_set_tid == [action]
    report = validation_report_document(compare_symbolic(result.trace, diagnostics=result.diagnostics), None)
    assert report['status'] == ('mismatch' if syscall_clobber else 'accepted'), str(report)
    if syscall_clobber:
        assert report['validation']['severity_counts']['confirmed'] >= 1
        assert result.complete  # Continued through the verified successor.


@pytest.mark.parametrize('ptid,expected', [((1, 222, 0), 222), ((1, 0, 333), 333),
                                        ((1, 0, 0), None), ((1, 2, 3), None),
                                        ((1, True, 0), None), ((1, -1, 0), None),
                                        ((1, 1 << 31, 0), None), ((1, 2), None)])
def test_context_tid_uses_independent_rsp_task_not_process_id(monkeypatch, ptid, expected):
    from types import SimpleNamespace
    target, _, _ = terminal_target(monkeypatch)
    target._process = SimpleNamespace(threads=lambda: (SimpleNamespace(ptid=ptid),))
    if expected is None:
        with pytest.raises(UnsupportedReplayEffect):
            target._independent_task_tid()
    else:
        assert target._independent_task_tid() == expected


def test_report_retains_independent_ordered_no_replay_action_values():
    from focaccia.no_replay import NoReplayActionDescriptor, NoReplayActionKind, NoReplaySetFsBoundary
    kwargs = evidence()
    exit_action = kwargs['terminal_action_validation'].expected
    expected = kwargs['expected_completion']
    action = NoReplaySetFsBoundary(0, NoReplayActionDescriptor(
        expected.terminal_action.architecture, 0x1000, NoReplayActionKind.SET_FS), 0x404178)
    for name in ('expected_completion', 'observed_completion'):
        kwargs[name] = replace(kwargs[name], no_replay_exit=exit_action, no_replay_set_fs=(action,))
    document = validation_report_document(ValidationReport(), None, **kwargs)
    evidence_document = document['completion']['no_replay_actions']
    assert evidence_document['expected'] == evidence_document['observed']
    assert evidence_document['expected'][0] == {
        'kind': 'arch_prctl_set_fs', 'pc': '0x1000', 'transform_index': 0, 'base': '0x404178',
    }
    assert evidence_document['expected'][1]['argument'] == hex(exit_action.argument)
    kwargs['observed_completion'] = replace(kwargs['observed_completion'], no_replay_set_fs=())
    assert not validation_report_document(ValidationReport(), None, **kwargs)['completion']['complete']


def test_no_replay_matcher_exposes_ordered_action_occurrence():
    from focaccia.match import TransitionMatcher
    from test_qemu_matching import trace, transform
    matcher = TransitionMatcher(trace(transform(0x1000, 0x1002), transform(0x1002, 0x1000)))
    assert matcher.current_transform_index is None
    matcher.observe(0x1000)
    assert matcher.current_transform_index == 0
    matcher.observe(0x1002)
    assert matcher.current_transform_index == 1
    matcher.observe(0x1000)
    assert matcher.current_transform_index is None


@pytest.mark.parametrize('failure', [None, 'order', 'base', 'selector', 'effect', 'successor', 'early-exit'])
def test_no_replay_set_fs_executes_locally_with_ordered_evidence(monkeypatch, failure):
    from types import SimpleNamespace
    from focaccia.no_replay import (
        ExitAction, ExitScope, NoReplaySetFsBoundary, UnsupportedNoReplayAction,
        NoReplayActionMismatch,
    )
    from test_no_replay import set_fs_states
    target, expected, _ = terminal_target(monkeypatch)
    before, after = set_fs_states()
    descriptor = describe_no_replay_action(before)
    expected = replace(expected, no_replay_exit=ExitAction(0, ExitScope.THREAD),
                       no_replay_set_fs=(NoReplaySetFsBoundary(0, descriptor, 0x404178),))
    target._replay = None
    target._events = DeterministicCursor((), lambda *_: False)
    target._process = SimpleNamespace(threads=lambda: (object(),))
    target._terminal_reason = None
    target._require_stopped = lambda: None
    target.current_state = lambda: after if target.steps else before
    target.is_exited = lambda: failure == 'early-exit' and bool(target.steps)

    def resume(command):
        assert command == 'continue'
        assert len(target.breakpoints) == 1
        breakpoint = target.breakpoints[0]
        assert breakpoint.location == f'*{before.read_pc() + 2:#x}'
        assert breakpoint.internal and not breakpoint.deleted
        target.steps += 1

    target._resume = resume
    target.enable_no_replay_exit_only(expected)
    target.authorize_no_replay_source(before.read_pc(), 1 if failure == 'order' else 0, 0)
    if failure == 'base':
        before.write_register('RSI', 0x504178)
    elif failure == 'selector':
        before.write_register('FS', 1)
    elif failure == 'effect':
        after.write_register('FS_BASE', 0x504178)
    elif failure == 'successor':
        after.write_register('RIP', before.read_pc() + 3)
    if failure:
        with pytest.raises((UnsupportedReplayEffect, UnsupportedNoReplayAction, NoReplayActionMismatch)):
            target._execute_no_replay_set_fs()
        assert target.steps == (1 if failure in ('effect', 'successor', 'early-exit') else 0)
        assert target._no_replay_set_fs_position == 0
    else:
        assert target._execute_no_replay_set_fs() is after
        assert target.steps == 1
        assert target._observed_no_replay_set_fs == list(expected.no_replay_set_fs)
        assert target._execute_no_replay_set_fs() is None
        assert before.read_register('RAX') == 158  # No native return substitution.
    assert all(breakpoint.deleted for breakpoint in target.breakpoints)
    assert len(target.breakpoints) == target.steps


def test_no_replay_set_fs_register_mismatch_returns_actual_successor(monkeypatch):
    """Known instruction semantics remain matcher-visible and do not abort."""
    from types import SimpleNamespace
    from focaccia.no_replay import ExitAction, ExitScope, NoReplaySetFsBoundary
    from test_no_replay import set_fs_states

    target, expected, _ = terminal_target(monkeypatch)
    before, after = set_fs_states()
    after.write_register('R11', 0)  # Known SYSCALL semantic mismatch.
    descriptor = describe_no_replay_action(before)
    expected = replace(expected, no_replay_exit=ExitAction(0, ExitScope.THREAD),
                       no_replay_set_fs=(NoReplaySetFsBoundary(0, descriptor, 0x404178),))
    target._replay = None
    target._events = DeterministicCursor((), lambda *_: False)
    target._process = SimpleNamespace(threads=lambda: (object(),))
    target._terminal_reason = None
    target._require_stopped = lambda: None
    target.current_state = lambda: after if target.steps else before
    target.is_exited = lambda: False
    target._resume = lambda command: setattr(target, 'steps', target.steps + 1)
    target.enable_no_replay_exit_only(expected)
    target.authorize_no_replay_source(before.read_pc(), 0, 0)

    assert target._execute_no_replay_set_fs() is after
    assert after.read_register('R11') == 0  # No expected-state injection.
    assert target._no_replay_set_fs_position == 1
    assert target._observed_no_replay_set_fs == list(expected.no_replay_set_fs)


@pytest.mark.parametrize('argument', [0, 256])
def test_no_replay_exit_requires_full_argument_without_replay_writes(monkeypatch, argument):
    from types import SimpleNamespace
    from focaccia.no_replay import ExitAction, ExitScope
    target, expected, _ = terminal_target(monkeypatch, argument=argument)
    expected = replace(expected, no_replay_exit=ExitAction(0, ExitScope.THREAD))
    target._replay = None
    target._events = DeterministicCursor((), lambda *_: False)
    target._process = SimpleNamespace(threads=lambda: (object(),))
    target.enable_no_replay_exit_only(expected)
    observed, action = target.execute_terminal_action(expected, retained_transform_count=2)
    assert action.expected == ExitAction(0, ExitScope.THREAD)
    assert action.observed == observed.no_replay_exit == ExitAction(argument, ExitScope.THREAD)
    assert action.comparison is (
        TerminalComparison.MATCH if argument == 0 else TerminalComparison.MISMATCH
    )
    assert observed.outcome.exit_status == 0
    assert target.steps == 1
    assert target.replay_coverage_report() is None


def test_unconsumed_no_replay_set_fs_blocks_exit(monkeypatch):
    from types import SimpleNamespace
    from focaccia.no_replay import ExitAction, ExitScope, NoReplaySetFsBoundary
    from test_no_replay import set_fs_states
    target, expected, _ = terminal_target(monkeypatch)
    before, _ = set_fs_states()
    expected = replace(expected, no_replay_exit=ExitAction(0, ExitScope.THREAD),
                       no_replay_set_fs=(NoReplaySetFsBoundary(0, describe_no_replay_action(before), 0x404178),))
    target._replay = None
    target._events = DeterministicCursor((), lambda *_: False)
    target._process = SimpleNamespace(threads=lambda: (object(),))
    target.enable_no_replay_exit_only(expected)
    with pytest.raises(UnsupportedReplayEffect, match='Unconsumed'):
        target.execute_terminal_action(expected, retained_transform_count=2)
    assert target.steps == 0
