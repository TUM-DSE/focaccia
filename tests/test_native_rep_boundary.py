from types import SimpleNamespace
from typing import cast

from focaccia.arch import Arch

import pytest

from focaccia.execution import ExecutionOutcome, ExecutionState
from focaccia.native.lldb_target import ConcreteExecutionError, LLDBLocalTarget
from focaccia.native.spec_target import NativeSpecTarget


def target_with_stops(stops):
    target = object.__new__(NativeSpecTarget)
    # Partial fixtures expose only the fields used by boundary stepping.
    target.arch = cast(Arch, SimpleNamespace(archname="x86_64"))
    target._closed = False
    state = {"pc": 0x1000, "steps": 0}
    target._target = cast(LLDBLocalTarget, SimpleNamespace(read_pc=lambda: state["pc"]))
    iterator = iter(stops)

    def step():
        pc, outcome = next(iterator)
        state["pc"] = pc
        state["steps"] += 1
        return outcome

    target.step = step
    return target, state


@pytest.mark.parametrize("pcs", [[0x1002], [0x1000, 0x1000, 0x1002]])
def test_whole_rep_boundary_does_not_depend_on_debugger_step_granularity(pcs):
    stopped = ExecutionOutcome(ExecutionState.STOPPED)
    target, state = target_with_stops([(pc, stopped) for pc in pcs])
    assert target.step_complete_instruction(repeat_pc=0x1000) == stopped
    assert state == {"pc": 0x1002, "steps": len(pcs)}


def test_wrong_successor_is_observed_not_replaced_by_prediction():
    stopped = ExecutionOutcome(ExecutionState.STOPPED)
    target, state = target_with_stops([(0xDEAD, stopped)])
    target.step_complete_instruction(repeat_pc=0x1000)
    assert state["pc"] == 0xDEAD


def test_rep_does_not_hide_signal_or_runaway():
    signal = ExecutionOutcome(ExecutionState.STOPPED, stop_signal=11)
    target, state = target_with_stops([(0x1000, signal)])
    assert target.step_complete_instruction(repeat_pc=0x1000) == signal
    assert state["steps"] == 1
    stopped = ExecutionOutcome(ExecutionState.STOPPED)
    target, _ = target_with_stops([(0x1000, stopped)] * 2)
    with pytest.raises(ConcreteExecutionError, match="budget"):
        target.step_complete_instruction(repeat_pc=0x1000, max_micro_steps=2)


def test_rep_entry_must_match_and_default_step_is_not_coalesced():
    stopped = ExecutionOutcome(ExecutionState.STOPPED)
    target, state = target_with_stops([(0x1000, stopped)])
    with pytest.raises(ConcreteExecutionError, match="entry PC"):
        target.step_complete_instruction(repeat_pc=0x1001)
    assert state["steps"] == 0
    assert target.step_complete_instruction() == stopped
    assert state["steps"] == 1
