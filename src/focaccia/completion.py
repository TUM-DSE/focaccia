"""Trace-local termination evidence, not register state or validation success.

A terminal action follows N ordinary transforms and N+1 live boundaries. No
post-exit state is implied. Coverage and action equality require independent
producer/consumer validation; this metadata alone never proves correctness.
"""

from dataclasses import dataclass
from enum import Enum

from .execution import ExecutionOutcome, ExecutionState
from .no_replay import (
    ExitAction, ExitScope, NoReplayActionDescriptor, NoReplayActionKind,
    NoReplayMmapBoundary, NoReplayMprotectBoundary,
    NoReplaySetFsBoundary, NoReplaySetTidBoundary,
)


class TraceScope(str, Enum):
    UNSPECIFIED = "unspecified"
    WITNESS = "witness"
    WHOLE_PROGRAM = "whole-program"


@dataclass(frozen=True, slots=True)
class TraceCompletion:
    final_pc: int
    transform_count: int
    state_count: int
    outcome: ExecutionOutcome
    terminal_action: NoReplayActionDescriptor | None = None
    # Full pre-call effect label at (final_pc, transform_count), not RR outputs.
    # Absence means unobserved; descriptor identity alone cannot fill it in.
    no_replay_exit: ExitAction | None = None
    # Ordered interior actions retain full scalar input evidence, not RR outputs.
    no_replay_set_fs: tuple[NoReplaySetFsBoundary, ...] = ()
    no_replay_set_tid: tuple[NoReplaySetTidBoundary, ...] = ()
    no_replay_mmap: tuple[NoReplayMmapBoundary, ...] = ()
    no_replay_mprotect: tuple[NoReplayMprotectBoundary, ...] = ()

    def __post_init__(self) -> None:
        for name in ("final_pc", "transform_count", "state_count"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer.")
        if self.final_pc >= 1 << 64:
            raise ValueError("final_pc exceeds the address range.")
        if self.state_count != self.transform_count + 1:
            raise ValueError("Completion requires N transforms and N+1 live states.")
        if not isinstance(self.outcome, ExecutionOutcome):
            raise ValueError("Completion requires a typed execution outcome.")
        if self.outcome.state not in (ExecutionState.EXITED, ExecutionState.UNKNOWN):
            raise ValueError("Completion must be exited or explicitly unknown.")
        if self.terminal_action is not None:
            if not isinstance(self.terminal_action, NoReplayActionDescriptor):
                raise ValueError("Terminal action must be a typed descriptor.")
            if self.terminal_action.kind not in (
                NoReplayActionKind.EXIT,
                NoReplayActionKind.EXIT_GROUP,
            ):
                raise ValueError("Completion requires an exit or exit_group descriptor.")
            if self.terminal_action.pc != self.final_pc:
                raise ValueError("Terminal action must originate at the final live PC.")

        if self.no_replay_exit is not None:
            if not isinstance(self.no_replay_exit, ExitAction):
                raise ValueError("No-replay exit evidence must be a typed ExitAction.")
            if self.terminal_action is None:
                raise ValueError("No-replay exit evidence requires a terminal descriptor.")
            expected_scope = (
                ExitScope.THREAD
                if self.terminal_action.kind is NoReplayActionKind.EXIT
                else ExitScope.GROUP
            )
            if self.no_replay_exit.scope is not expected_scope:
                raise ValueError("No-replay exit scope must match the terminal descriptor.")

        if type(self.no_replay_set_fs) is not tuple:
            raise ValueError("No-replay SET_FS evidence must be a tuple.")
        previous_index = -1
        for boundary in self.no_replay_set_fs:
            if not isinstance(boundary, NoReplaySetFsBoundary):
                raise ValueError("No-replay SET_FS evidence requires typed boundaries.")
            if not previous_index < boundary.transform_index < self.transform_count:
                raise ValueError("No-replay SET_FS indices must increase within the trace.")
            if self.no_replay_exit is None or self.terminal_action is None:
                raise ValueError("No-replay SET_FS evidence requires no-replay exit evidence.")
            if boundary.descriptor.architecture != self.terminal_action.architecture:
                raise ValueError("No-replay SET_FS and exit architectures must match.")
            previous_index = boundary.transform_index

        if type(self.no_replay_set_tid) is not tuple:
            raise ValueError("No-replay SET_TID_ADDRESS evidence must be a tuple.")
        previous_index = -1
        fs_indices = {boundary.transform_index for boundary in self.no_replay_set_fs}
        context_tid = None
        for boundary in self.no_replay_set_tid:
            if not isinstance(boundary, NoReplaySetTidBoundary):
                raise ValueError("No-replay SET_TID_ADDRESS evidence requires typed boundaries.")
            if context_tid is not None and boundary.expected_tid != context_tid:
                raise ValueError("No-replay task context must remain constant throughout execution.")
            context_tid = boundary.expected_tid
            if not previous_index < boundary.transform_index < self.transform_count:
                raise ValueError("No-replay SET_TID_ADDRESS indices must increase within the trace.")
            if boundary.transform_index in fs_indices:
                raise ValueError("No-replay action indices must not collide.")
            if self.no_replay_exit is None or self.terminal_action is None:
                raise ValueError("No-replay SET_TID_ADDRESS evidence requires no-replay exit evidence.")
            if boundary.descriptor.architecture != self.terminal_action.architecture:
                raise ValueError("No-replay SET_TID_ADDRESS and exit architectures must match.")
            previous_index = boundary.transform_index

        if type(self.no_replay_mmap) is not tuple:
            raise ValueError("No-replay mmap evidence must be a tuple.")
        previous_index = -1
        occupied = fs_indices | {item.transform_index for item in self.no_replay_set_tid}
        for occurrence, boundary in enumerate(self.no_replay_mmap):
            if not isinstance(boundary, NoReplayMmapBoundary):
                raise ValueError("No-replay mmap evidence requires typed boundaries.")
            if boundary.occurrence != occurrence:
                raise ValueError("No-replay mmap occurrences must be contiguous and ordered.")
            if not previous_index < boundary.transform_index < self.transform_count:
                raise ValueError("No-replay mmap indices must increase within the trace.")
            if boundary.transform_index in occupied:
                raise ValueError("No-replay action indices must not collide.")
            if self.no_replay_exit is None or self.terminal_action is None:
                raise ValueError("No-replay mmap evidence requires no-replay exit evidence.")
            previous_index = boundary.transform_index

        if type(self.no_replay_mprotect) is not tuple:
            raise ValueError("No-replay mprotect evidence must be a tuple.")
        previous_index = -1
        occupied.update(item.transform_index for item in self.no_replay_mmap)
        for boundary in self.no_replay_mprotect:
            if not isinstance(boundary, NoReplayMprotectBoundary):
                raise ValueError("No-replay mprotect evidence requires typed boundaries.")
            if boundary.occurrence >= len(self.no_replay_mmap):
                raise ValueError("mprotect must reference a preceding allocation occurrence.")
            allocation = self.no_replay_mmap[boundary.occurrence]
            if allocation.transform_index >= boundary.transform_index:
                raise ValueError("mprotect must follow its allocation.")
            if not previous_index < boundary.transform_index < self.transform_count:
                raise ValueError("No-replay mprotect indices must increase within the trace.")
            if boundary.transform_index in occupied:
                raise ValueError("No-replay action indices must not collide.")
            previous_index = boundary.transform_index

    def validate_binding(self, kind: str, count: int, final_pc: int | None) -> None:
        expected = self.state_count if kind == "states" else self.transform_count
        if count != expected:
            raise ValueError("Completion cardinality does not match trace items.")
        if final_pc is None or final_pc != self.final_pc:
            raise ValueError("Completion does not match the final live PC.")


def validate_trace_metadata(scope: TraceScope, completion: TraceCompletion | None) -> None:
    if not isinstance(scope, TraceScope):
        raise ValueError("Trace scope must be a TraceScope.")
    if completion is not None and not isinstance(completion, TraceCompletion):
        raise ValueError("Trace completion must be a TraceCompletion or None.")
    if completion is not None and scope is TraceScope.UNSPECIFIED:
        raise ValueError("Completion evidence requires explicit trace scope.")
