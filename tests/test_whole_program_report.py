"""Pure report fixtures: no debugger, emulator, socket, or native tracing."""

from dataclasses import replace
import json
from typing import Any, cast

import pytest

from focaccia.arch.x86 import ArchX86
from focaccia.compare import Error, ErrorTypes, ValidationReport
from focaccia.completion import TraceCompletion, TraceScope
from focaccia.match import MatchResult
from focaccia.execution import ExecutionOutcome, ExecutionState, TerminalComparison
from focaccia.no_replay import (
    ExitAction,
    ExitScope,
    NoReplayActionDescriptor,
    NoReplayActionKind,
    NoReplayMmapBoundary,
    NoReplayMprotectBoundary,
)
from focaccia.qemu.report import (
    TerminalActionValidation,
    validation_report_document,
    write_validation_report,
    _no_replay_actions_document,
)
from focaccia.snapshot import ProgramState
from focaccia.symbolic import SymbolicTransform
from focaccia.trace import TraceDiagnostic, TraceEnvironment, TransitionTrace


def evidence() -> dict[str, Any]:
    arch = ArchX86()
    states = [ProgramState(arch), ProgramState(arch)]
    for state, pc in zip(states, (0x1000, 0x1002), strict=True):
        state.write_register("RIP", pc)
    transform = SymbolicTransform(1, {}, [], arch, 0x1000, 0x1002)
    env = TraceEnvironment(None, (), (), binary_hash=None, architecture=arch.key)
    matched = MatchResult(TransitionTrace(states, (transform,), env), ())
    expected = TraceCompletion(
        0x1002,
        1,
        2,
        ExecutionOutcome(ExecutionState.EXITED, exit_status=0),
        NoReplayActionDescriptor(arch.key, 0x1002, NoReplayActionKind.EXIT_GROUP),
    )
    # Separate observations, not the oracle object supplied as its own evidence.
    observed = replace(expected, outcome=ExecutionOutcome(ExecutionState.EXITED, exit_status=0))
    action = TerminalActionValidation(
        ExitAction(0, ExitScope.GROUP), ExitAction(0, ExitScope.GROUP), TerminalComparison.MATCH
    )
    return dict(
        match_result=matched,
        scope=TraceScope.WHOLE_PROGRAM,
        expected_completion=expected,
        observed_completion=observed,
        terminal_action_validation=action,
    )


def test_report_preserves_all_ordered_local_mapping_actions():
    expected = evidence()["expected_completion"]
    arch = expected.terminal_action.architecture
    mmap_descriptor = NoReplayActionDescriptor(
        arch, 0x1010, NoReplayActionKind.MMAP_ANONYMOUS_PRIVATE
    )
    protect_descriptor = NoReplayActionDescriptor(
        arch, 0x1020, NoReplayActionKind.MPROTECT_NONE_PAGE
    )
    completion = replace(
        expected,
        transform_count=3,
        state_count=4,
        no_replay_exit=ExitAction(0, ExitScope.GROUP),
        no_replay_mmap=(NoReplayMmapBoundary(0, mmap_descriptor, 8192, 0),),
        no_replay_mprotect=(
            NoReplayMprotectBoundary(1, protect_descriptor, 0, 4096, 4096),
        ),
    )
    actions = _no_replay_actions_document(completion)
    assert actions is not None
    assert [item["kind"] for item in actions] == [
        "mmap_anonymous_private",
        "mprotect_none_page",
        "exit_group",
    ]
    assert actions[0]["length"] == 8192
    assert actions[1]["offset"] == 4096


def test_whole_program_requires_independent_terminal_validation(tmp_path):
    kwargs = evidence()
    document = validation_report_document(ValidationReport(), None, **kwargs)
    assert document["status"] == "accepted"
    assert document["completion"]["complete"]
    assert document["trace"]["state_count"] == 2
    assert document["trace"]["terminal_pc"] == 0x1002
    path = tmp_path / "report.json"
    write_validation_report(path, ValidationReport(), None, **kwargs)
    assert json.loads(path.read_text()) == document


@pytest.mark.parametrize(
    "missing",
    ["expected_completion", "observed_completion", "terminal_action_validation", "match_result"],
)
def test_missing_evidence_never_accepts(missing):
    kwargs = evidence()
    kwargs[missing] = None
    doc = validation_report_document(ValidationReport(), None, **kwargs)
    assert doc["status"] == "incomplete"
    assert not doc["completion"]["full_run_timing_eligible"]


@pytest.mark.parametrize("side", ["expected_completion", "observed_completion"])
@pytest.mark.parametrize("change", ["unknown", "wrong_pc", "truncated", "missing_action"])
def test_unknown_or_unbound_completion_never_accepts(side, change):
    kwargs = evidence()
    completion = kwargs[side]
    if change == "unknown":
        completion = replace(completion, outcome=ExecutionOutcome(ExecutionState.UNKNOWN))
    elif change == "wrong_pc":
        completion = replace(
            completion,
            final_pc=0x2000,
            terminal_action=replace(completion.terminal_action, pc=0x2000),
        )
    elif change == "truncated":
        completion = replace(completion, transform_count=2, state_count=3)
    else:
        completion = replace(completion, terminal_action=None)
    kwargs[side] = completion
    doc = validation_report_document(ValidationReport(), None, **kwargs)
    assert doc["status"] != "accepted"
    assert not doc["completion"]["complete"]


@pytest.mark.parametrize(
    "outcome",
    [
        ExecutionOutcome(ExecutionState.EXITED, exit_status=7),
        ExecutionOutcome(ExecutionState.EXITED, termination_signal=11),
    ],
)
def test_wrong_terminal_outcome_is_mismatch(outcome):
    kwargs = evidence()
    kwargs["observed_completion"] = replace(kwargs["observed_completion"], outcome=outcome)
    doc = validation_report_document(ValidationReport(), None, **kwargs)
    assert doc["status"] == "mismatch"
    assert doc["completion"]["terminal_outcome"] == "mismatch"
    assert not doc["completion"]["complete"]


@pytest.mark.parametrize(
    "action",
    [
        TerminalActionValidation(
            ExitAction(0, ExitScope.GROUP),
            ExitAction(256, ExitScope.GROUP),
            TerminalComparison.MATCH,
        ),
        TerminalActionValidation(
            ExitAction(0, ExitScope.GROUP),
            ExitAction(0, ExitScope.THREAD),
            TerminalComparison.MATCH,
        ),
        TerminalActionValidation(
            ExitAction(0, ExitScope.GROUP),
            ExitAction(0, ExitScope.GROUP),
            TerminalComparison.MISMATCH,
        ),
        TerminalActionValidation(
            ExitAction(0, ExitScope.GROUP),
            ExitAction(0, ExitScope.GROUP),
            TerminalComparison.INCOMPLETE,
        ),
    ],
)
def test_metadata_and_equal_status_do_not_prove_terminal_action(action):
    kwargs = evidence()
    kwargs["terminal_action_validation"] = action
    doc = validation_report_document(ValidationReport(), None, **kwargs)
    assert doc["status"] != "accepted"
    assert not doc["completion"]["complete"]


@pytest.mark.parametrize("pending", [False, True])
def test_truncated_ordinary_prefix_never_accepts(pending):
    kwargs = evidence()
    matched = kwargs["match_result"]
    kwargs["match_result"] = (
        replace(matched, pending_transform=matched.trace.transforms[0])
        if pending
        else replace(
            matched, diagnostics=(TraceDiagnostic("incomplete", "truncated", "Missing prefix"),)
        )
    )
    doc = validation_report_document(ValidationReport(), None, **kwargs)
    assert doc["status"] == "incomplete"
    assert not doc["completion"]["ordinary_prefix_complete"]


def test_confirmed_earlier_mismatch_does_not_certify_full_run_timing():
    kwargs = evidence()
    kwargs["observed_completion"] = None
    state = kwargs["match_result"].trace.state_boundaries[0]
    report = ValidationReport(
        (
            dict(
                pc=0x1000,
                txl=state,
                ref=state,
                snap=state,
                errors=[Error(ErrorTypes.CONFIRMED, "Mismatch")],
            ),
        )
    )
    doc = validation_report_document(report, None, **kwargs)
    assert doc["status"] == "mismatch"
    assert not doc["completion"]["full_run_timing_eligible"]


def test_semantic_gap_does_not_erase_independent_execution_completion():
    report = ValidationReport(diagnostics=(TraceDiagnostic("incomplete", "gap", "Unknown"),))
    doc = validation_report_document(report, None, **evidence())
    assert doc["status"] == "incomplete"
    assert not doc["completion"]["complete"]
    assert doc["completion"]["execution_complete"]
    assert doc["completion"]["full_run_timing_eligible"]


@pytest.mark.parametrize("scope", [TraceScope.UNSPECIFIED, TraceScope.WITNESS])
def test_legacy_and_witness_report_behavior_preserved(scope):
    doc = validation_report_document(ValidationReport(), None, scope=scope)
    assert doc["status"] == "accepted"
    if scope is TraceScope.WITNESS:
        assert not doc["completion"]["complete"]
    else:
        assert "completion" not in doc


@pytest.mark.parametrize(
    "field,value", [("expected", None), ("observed", None), ("comparison", "match")]
)
def test_action_validation_rejects_untyped_evidence(field, value):
    with pytest.raises(ValueError):
        replace(evidence()["terminal_action_validation"], **{field: value})


def tid_evidence():
    from focaccia.no_replay import NoReplaySetTidBoundary
    kwargs = evidence()
    for side, tid in (("expected_completion", 123), ("observed_completion", 456)):
        completion = kwargs[side]
        kwargs[side] = replace(
            completion, no_replay_exit=ExitAction(0, ExitScope.GROUP),
            no_replay_set_tid=(NoReplaySetTidBoundary(
                0, NoReplayActionDescriptor(ArchX86().key, 0x1000, NoReplayActionKind.SET_TID_ADDRESS),
                0x3000, tid,
            ),),
        )
    return kwargs


def test_tid_report_accepts_context_relative_identity_and_reports_both_tids():
    doc = validation_report_document(ValidationReport(), None, **tid_evidence())
    assert doc["status"] == "accepted"
    assert doc["completion"]["complete"]
    actions = doc["completion"]["no_replay_actions"]
    assert actions["expected"][0]["expected_tid"] == 123
    assert actions["observed"][0]["expected_tid"] == 456
    assert actions["observed"][0]["address"] == "0x3000"


@pytest.mark.parametrize("change", ["missing", "extra", "address", "descriptor", "order"])
def test_tid_report_requires_all_ordered_action_evidence(change):
    kwargs = tid_evidence()
    expected = kwargs["expected_completion"]
    observed = kwargs["observed_completion"]
    boundary = observed.no_replay_set_tid[0]
    if change == "missing":
        observed = replace(observed, no_replay_set_tid=())
    elif change == "extra":
        expected = replace(expected, no_replay_set_tid=())
    elif change == "address":
        observed = replace(observed, no_replay_set_tid=(replace(boundary, address=0x4000),))
    elif change == "descriptor":
        observed = replace(observed, no_replay_set_tid=(replace(boundary, descriptor=replace(boundary.descriptor, pc=0x999)),))
    else:
        from focaccia.no_replay import NoReplaySetFsBoundary
        fs = NoReplaySetFsBoundary(1, replace(boundary.descriptor, kind=NoReplayActionKind.SET_FS), 0x4000)
        expected = replace(expected, transform_count=2, state_count=3, no_replay_set_fs=(fs,))
        observed = replace(observed, transform_count=2, state_count=3,
                           no_replay_set_fs=(replace(fs, transform_index=0),),
                           no_replay_set_tid=(replace(boundary, transform_index=1),))
    kwargs.update(expected_completion=expected, observed_completion=observed)
    doc = validation_report_document(ValidationReport(), None, **kwargs)
    assert doc["status"] == "mismatch"
    assert doc["completion"]["terminal_action"] == "mismatch"
    assert not doc["completion"]["complete"]


def test_report_rejects_untyped_scope():
    with pytest.raises(ValueError, match="scope"):
        validation_report_document(ValidationReport(), None, scope=cast(Any, "whole-program"))
