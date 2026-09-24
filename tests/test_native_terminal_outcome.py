"""Deterministic backend fixtures; no debugger, inferior, RR, or ptrace execution."""

import subprocess
import sys
from types import SimpleNamespace
from typing import Any, cast

import pytest

from focaccia.arch import x86
from focaccia.native import lldb_target as backend
from focaccia.execution import (
    ExecutionOutcome,
    ExecutionState,
    TerminalComparison,
    compare_terminal_outcomes,
)


def test_outcome_contract_import_does_not_load_lldb():
    subprocess.run(
        [sys.executable, "-c", (
            "import sys; import focaccia.execution; "
            "assert 'lldb' not in sys.modules; "
            "assert 'focaccia.native.lldb_target' not in sys.modules"
        )],
        check=True,
        timeout=10,
    )


def target(state: int, status: int = 0, signal: int | None = None):
    def unexpected(*_args):
        raise AssertionError("Exited/non-stopped process must not access thread or memory.")

    process = SimpleNamespace(
        IsValid=lambda: True,
        GetState=lambda: state,
        GetExitStatus=lambda: status,
        GetExitDescription=lambda: None,
        GetSelectedThread=unexpected,
        ReadMemory=unexpected,
    )
    if state in (backend.lldb.eStateStopped, backend.lldb.eStateCrashed):
        process.GetSelectedThread = lambda: SimpleNamespace(
            IsValid=lambda: signal is not None,
            GetStopReason=lambda: backend.lldb.eStopReasonSignal,
            GetStopReasonDataCount=lambda: 1,
            GetStopReasonDataAtIndex=lambda _index: signal,
        )
    result = object.__new__(backend.LLDBConcreteTarget)
    result.process = cast(Any, process)
    result.arch = x86.ArchX86()
    result.archname = "x86_64"
    return result


def test_lldb_exit_zero_has_typed_outcome_without_reading_threads():
    observed = target(backend.lldb.eStateExited).execution_outcome()
    assert observed == ExecutionOutcome(ExecutionState.EXITED, exit_status=0, backend_status=0)
    assert observed.terminal_known


@pytest.mark.parametrize("status", [7, 15, 255, -1])
def test_lldb_ambiguous_nonzero_exit_status_is_not_normal_exit_or_signal(status):
    # River LLDB 19: _exit(7) reports 7; SIGTERM reports 15, description=None.
    # Numeric status alone cannot distinguish _exit(15) from SIGTERM.
    observed = target(backend.lldb.eStateExited, status).execution_outcome()
    assert observed.state == ExecutionState.EXITED
    assert observed.backend_status == status
    assert observed.exit_status is None
    assert observed.termination_signal is None
    assert not observed.terminal_known
    assert compare_terminal_outcomes(observed, observed) == TerminalComparison.INCOMPLETE


@pytest.mark.parametrize("state", [backend.lldb.eStateStopped, backend.lldb.eStateCrashed])
def test_lldb_signal_stop_is_not_termination(state):
    concrete = target(state, signal=15)
    assert concrete.execution_outcome() == ExecutionOutcome(ExecutionState.STOPPED, stop_signal=15)
    assert not concrete.is_exited()
    # Even after resume/exit, a preceding signal stop cannot classify its cause:
    # a signal handler could have called _exit(15).
    cast(Any, concrete.process).GetState = lambda: backend.lldb.eStateExited
    cast(Any, concrete.process).GetExitStatus = lambda: 15
    assert not concrete.execution_outcome().terminal_known


def test_lldb_missing_thread_is_stopped_not_exit():
    concrete = target(backend.lldb.eStateStopped)
    assert concrete.execution_outcome() == ExecutionOutcome(ExecutionState.STOPPED)
    assert not concrete.is_exited()


@pytest.mark.parametrize("state", [backend.lldb.eStateRunning, backend.lldb.eStateStepping])
def test_lldb_running_observation_does_not_read_threads(state):
    assert target(state).execution_outcome() == ExecutionOutcome(ExecutionState.RUNNING)


@pytest.mark.parametrize("state", [backend.lldb.eStateDetached, backend.lldb.eStateInvalid, 999])
def test_lldb_lost_process_is_unknown_not_exit(state):
    concrete = target(state)
    assert concrete.execution_outcome().state == ExecutionState.UNKNOWN
    assert not concrete.is_exited()


def test_lldb_invalid_handle_does_not_trust_stale_exited_state():
    concrete = target(backend.lldb.eStateExited)
    cast(Any, concrete.process).IsValid = lambda: False
    assert concrete.execution_outcome().state == ExecutionState.UNKNOWN
    assert not concrete.is_exited()


@pytest.mark.parametrize("operation", [
    lambda concrete: concrete.read_pc(),
    lambda concrete: concrete.read_register("RAX"),
    lambda concrete: concrete.read_flags(),
    lambda concrete: concrete.read_memory(0x1000, 8),
    lambda concrete: concrete.record_snapshot(),
])
def test_exited_target_rejects_state_observation_before_backend_access(operation):
    with pytest.raises(backend.ConcreteExecutionError, match="no readable state"):
        operation(target(backend.lldb.eStateExited))


@pytest.mark.parametrize("status", [0, 7, 15, 255])
def test_known_normal_exit_requires_exact_status(status):
    expected = ExecutionOutcome(ExecutionState.EXITED, exit_status=status)
    assert compare_terminal_outcomes(expected, expected) == TerminalComparison.MATCH
    wrong = ExecutionOutcome(ExecutionState.EXITED, exit_status=(status + 1) % 256)
    assert compare_terminal_outcomes(expected, wrong) == TerminalComparison.MISMATCH
    signal = ExecutionOutcome(ExecutionState.EXITED, termination_signal=15)
    assert compare_terminal_outcomes(expected, signal) == TerminalComparison.MISMATCH


def test_typed_signal_terminal_requires_exact_signal():
    expected = ExecutionOutcome(ExecutionState.EXITED, termination_signal=15)
    assert compare_terminal_outcomes(expected, expected) == TerminalComparison.MATCH
    wrong = ExecutionOutcome(ExecutionState.EXITED, termination_signal=11)
    assert compare_terminal_outcomes(expected, wrong) == TerminalComparison.MISMATCH


@pytest.mark.parametrize("unknown", [
    ExecutionOutcome(ExecutionState.RUNNING),
    ExecutionOutcome(ExecutionState.STOPPED, stop_signal=15),
    ExecutionOutcome(ExecutionState.UNKNOWN, description="EOF"),
    ExecutionOutcome(ExecutionState.EXITED),
])
def test_missing_terminal_evidence_never_matches(unknown):
    known = ExecutionOutcome(ExecutionState.EXITED, exit_status=0)
    for expected, observed in ((known, unknown), (unknown, known), (unknown, unknown)):
        assert compare_terminal_outcomes(expected, observed) == TerminalComparison.INCOMPLETE


@pytest.mark.parametrize("fields", [
    {"state": "exited"},
    {"state": ExecutionState.EXITED, "exit_status": True},
    {"state": ExecutionState.EXITED, "exit_status": -1},
    {"state": ExecutionState.EXITED, "exit_status": 256},
    {"state": ExecutionState.EXITED, "exit_status": 0, "termination_signal": 15},
    {"state": ExecutionState.STOPPED, "exit_status": 0},
    {"state": ExecutionState.RUNNING, "termination_signal": 15},
    {"state": ExecutionState.EXITED, "stop_signal": 15},
    {"state": ExecutionState.STOPPED, "stop_signal": 0},
    {"state": ExecutionState.EXITED, "termination_signal": -1},
    {"state": ExecutionState.UNKNOWN, "description": 15},
    {"state": ExecutionState.EXITED, "backend_status": "15"},
])
def test_outcome_contract_rejects_contradictory_or_malformed_evidence(fields):
    with pytest.raises(ValueError):
        ExecutionOutcome(**fields)
