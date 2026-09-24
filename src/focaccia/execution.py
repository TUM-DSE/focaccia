"""Process observations, separate from readable register/memory boundaries.

An exited process need not have a known termination cause. In particular, a
signal stop is not signal termination, and transport loss is not process exit.
These contracts do not establish trace coverage or model a terminal action.
"""

from dataclasses import dataclass
from enum import Enum


class ExecutionState(str, Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    EXITED = "exited"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    state: ExecutionState
    exit_status: int | None = None
    termination_signal: int | None = None
    stop_signal: int | None = None
    description: str | None = None
    backend_status: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.state, ExecutionState):
            raise ValueError("Execution state must be an ExecutionState.")
        for name in ("exit_status", "termination_signal", "stop_signal", "backend_status"):
            value = getattr(self, name)
            if value is not None and type(value) is not int:
                raise ValueError(f"{name} must be an integer or None.")
        if self.description is not None and not isinstance(self.description, str):
            raise ValueError("Outcome description must be a string or None.")
        if self.exit_status is not None and not 0 <= self.exit_status <= 255:
            raise ValueError("Exit status must be in [0, 255].")
        if self.exit_status is not None and self.termination_signal is not None:
            raise ValueError("Exit status and termination signal are mutually exclusive.")
        if self.state != ExecutionState.EXITED and (
            self.exit_status is not None or self.termination_signal is not None
        ):
            raise ValueError("Only an exited process has a terminal outcome.")
        if self.stop_signal is not None and self.state != ExecutionState.STOPPED:
            raise ValueError("Only a stopped process has a stop signal.")
        for signal in (self.stop_signal, self.termination_signal):
            if signal is not None and signal <= 0:
                raise ValueError("Signal numbers must be positive.")

    @property
    def terminal_known(self) -> bool:
        return self.state == ExecutionState.EXITED and (
            self.exit_status is not None or self.termination_signal is not None
        )


class TerminalComparison(str, Enum):
    MATCH = "match"
    MISMATCH = "mismatch"
    INCOMPLETE = "incomplete"


def compare_terminal_outcomes(
    expected: ExecutionOutcome, observed: ExecutionOutcome
) -> TerminalComparison:
    """Compare known termination causes, never treating absence as agreement.

    MATCH establishes only terminal-outcome equality, not transition validity,
    whole-program coverage, or equality of preceding external actions.
    """
    if not expected.terminal_known or not observed.terminal_known:
        return TerminalComparison.INCOMPLETE
    if (expected.exit_status, expected.termination_signal) == (
        observed.exit_status, observed.termination_signal
    ):
        return TerminalComparison.MATCH
    return TerminalComparison.MISMATCH
