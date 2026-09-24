"""Structured, versioned output for QEMU validation and replay coverage."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from focaccia.compare import ErrorTypes, ValidationReport
from focaccia.completion import TraceCompletion, TraceScope
from focaccia.execution import (
    ExecutionOutcome,
    TerminalComparison,
    compare_terminal_outcomes,
)
from focaccia.no_replay import ExitAction, ExitScope, NoReplayActionKind
from focaccia.match import MatchResult
from focaccia.qemu.syscall import ReplayCoverageReport


QEMU_VALIDATION_REPORT_SCHEMA = "focaccia-qemu-validation-v1"


@dataclass(frozen=True, slots=True)
class TerminalReason:
    """Structured stop and optional one-shot signal-delivery observation."""

    kind: str
    signal: str
    pc: int | None
    delivered: bool = False
    outcome: ExecutionOutcome | None = None

    def __post_init__(self) -> None:
        if self.outcome is not None and not self.delivered:
            raise ValueError("A signal outcome requires an actual delivery attempt.")


def _terminal_reason_document(reason: TerminalReason | None) -> dict[str, object] | None:
    if reason is None:
        return None
    outcome = reason.outcome
    return {
        "kind": reason.kind,
        "signal": reason.signal,
        "pc": reason.pc,
        "delivery": {
            "attempted": reason.delivered,
            "state": outcome.state.value if outcome is not None else None,
            "exit_status": outcome.exit_status if outcome is not None else None,
            "termination_signal": (
                outcome.termination_signal if outcome is not None else None
            ),
            "stop_signal": outcome.stop_signal if outcome is not None else None,
            "known_terminated": bool(outcome is not None and outcome.terminal_known),
            "description": outcome.description if outcome is not None else None,
        },
    }


def _error_document(error: object) -> dict[str, object]:
    severity = getattr(error, "severity", None)
    name = getattr(severity, "name", type(severity).__name__)
    if severity == ErrorTypes.CONFIRMED:
        classification = "confirmed"
    elif severity == ErrorTypes.POSSIBLE:
        classification = "possible"
    elif severity == ErrorTypes.INCOMPLETE:
        classification = "incomplete"
    else:
        classification = "info"
    message = getattr(error, "error_msg", str(error))
    return {
        "severity": classification,
        "severity_label": str(name),
        "code": getattr(error, "code", None),
        "subject": getattr(error, "subject", None),
        "message": str(message),
    }


def _transition_range(reference: object) -> list[int] | None:
    value = getattr(reference, "range", None)
    if (
        isinstance(value, tuple)
        and len(value) == 2
        and all(isinstance(item, int) for item in value)
    ):
        return [value[0], value[1]]
    return None


def _trace_document(result: MatchResult | None) -> dict[str, object]:
    if result is None or result.trace is None:
        return {
            "available": False,
            "complete": False,
            "state_count": 0,
            "transform_count": 0,
            "terminal_pc": None,
            "expected_terminal_pc": None,
            "terminal_reached": False,
        }
    states = result.trace.state_boundaries
    transforms = result.trace.transforms
    terminal_pc = states[-1].read_pc() if states else None
    expected_terminal_pc = result.trace.env.stop_address
    return {
        "available": True,
        "complete": result.complete,
        "state_count": len(states),
        "transform_count": len(transforms),
        "terminal_pc": terminal_pc,
        "expected_terminal_pc": expected_terminal_pc,
        "terminal_reached": (
            expected_terminal_pc is not None and terminal_pc == expected_terminal_pc
        ),
    }


@dataclass(frozen=True, slots=True)
class TerminalActionValidation:
    """Collector evidence from independently instantiated terminal actions.

    ``comparison`` must come from validation of the terminal instruction and
    its control/effect obligations, NOT descriptor equality or process exit.
    Actions retain full arguments: matching low-byte exit statuses is not enough.
    This result is live evidence, never reconstructed from completion metadata.
    """

    expected: ExitAction
    observed: ExitAction
    comparison: TerminalComparison

    def __post_init__(self) -> None:
        if not isinstance(self.expected, ExitAction) or not isinstance(self.observed, ExitAction):
            raise ValueError("Terminal action evidence requires instantiated exit actions.")
        if not isinstance(self.comparison, TerminalComparison):
            raise ValueError("Terminal action evidence requires a typed comparison.")


def _no_replay_actions_document(completion: TraceCompletion | None) -> list[dict[str, object]] | None:
    if completion is None or completion.no_replay_exit is None:
        return None
    actions: list[dict[str, object]] = [
        {"kind": item.descriptor.kind.value, "pc": hex(item.descriptor.pc),
         "transform_index": item.transform_index, "base": hex(item.base)}
        for item in completion.no_replay_set_fs
    ]
    actions.extend(
        {"kind": item.descriptor.kind.value, "pc": hex(item.descriptor.pc),
         "transform_index": item.transform_index, "address": hex(item.address),
         "expected_tid": item.expected_tid}
        for item in completion.no_replay_set_tid
    )
    actions.extend(
        {
            "kind": item.descriptor.kind.value,
            "pc": hex(item.descriptor.pc),
            "transform_index": item.transform_index,
            "occurrence": item.occurrence,
            "length": item.length,
        }
        for item in completion.no_replay_mmap
    )
    actions.extend(
        {
            "kind": item.descriptor.kind.value,
            "pc": hex(item.descriptor.pc),
            "transform_index": item.transform_index,
            "occurrence": item.occurrence,
            "offset": item.offset,
            "length": item.length,
        }
        for item in completion.no_replay_mprotect
    )
    actions.sort(key=lambda item: cast(int, item["transform_index"]))
    actions.append({"kind": "exit" if completion.no_replay_exit.scope is ExitScope.THREAD else "exit_group",
                    "pc": hex(completion.final_pc), "transform_index": completion.transform_count,
                    "argument": hex(completion.no_replay_exit.argument)})
    return actions


def _interior_action_identity(completion: TraceCompletion) -> list[tuple[object, int]]:
    # Indices are local to each trace's cutpoints. Compare merged action order,
    # not raw indices. TIDs identify each independently observed OS context.
    ordered = [
        (item.transform_index, item.descriptor, item.base)
        for item in completion.no_replay_set_fs
    ] + [
        (item.transform_index, item.descriptor, item.address)
        for item in completion.no_replay_set_tid
    ] + [
        (item.transform_index, item.descriptor, (item.occurrence, item.length))
        for item in completion.no_replay_mmap
    ] + [
        (
            item.transform_index,
            item.descriptor,
            (item.occurrence, item.offset, item.length),
        )
        for item in completion.no_replay_mprotect
    ]
    return [(descriptor, argument) for _, descriptor, argument in sorted(ordered, key=lambda item: item[0])]


def _whole_program_document(
    scope: TraceScope,
    expected: TraceCompletion | None,
    observed: TraceCompletion | None,
    action: TerminalActionValidation | None,
    matched: MatchResult | None,
) -> dict[str, object]:
    consumed_count = (
        matched.consumed_transform_count
        if matched is not None and matched.consumed_transform_count is not None
        else (
            len(matched.trace.transforms)
            if matched is not None and matched.trace is not None
            else None
        )
    )
    prefix_complete = bool(
        expected is not None
        and matched is not None
        and matched.trace is not None
        and matched.complete
        and matched.pending_transform is None
        and consumed_count == expected.transform_count
    )
    bound = False
    if expected is not None and observed is not None and matched is not None:
        trace = matched.trace
        if trace is not None and trace.state_boundaries:
            # Adaptive matching can compose several oracle transforms between
            # retained concrete cutpoints.  Bind completion to proof that all
            # semantic transforms were consumed, while the retained trace
            # independently preserves its own N+1 cardinality.
            bound = (
                expected.final_pc == observed.final_pc == trace.state_boundaries[-1].read_pc()
                and consumed_count == expected.transform_count
                and (
                    (
                        observed.transform_count == consumed_count
                        and observed.state_count == consumed_count + 1
                    )
                    or (
                        observed.transform_count == len(trace.transforms)
                        and observed.state_count == len(trace.state_boundaries)
                    )
                )
                and len(trace.state_boundaries) == len(trace.transforms) + 1
            )
    outcome = (
        compare_terminal_outcomes(expected.outcome, observed.outcome)
        if expected is not None and observed is not None
        else TerminalComparison.INCOMPLETE
    )
    action_comparison = TerminalComparison.INCOMPLETE
    if (
        action is not None
        and expected is not None
        and observed is not None
        and expected.outcome.terminal_known
        and observed.outcome.terminal_known
        and expected.terminal_action is not None
        and observed.terminal_action is not None
    ):
        action_comparison = action.comparison
        if action_comparison is not TerminalComparison.INCOMPLETE:
            descriptors_match = expected.terminal_action == observed.terminal_action
            expected_kind = (
                NoReplayActionKind.EXIT
                if action.expected.scope is ExitScope.THREAD
                else NoReplayActionKind.EXIT_GROUP
            )
            observed_kind = (
                NoReplayActionKind.EXIT
                if action.observed.scope is ExitScope.THREAD
                else NoReplayActionKind.EXIT_GROUP
            )
            if (
                not descriptors_match
                or action.expected != action.observed
                or expected.terminal_action.kind is not expected_kind
                or observed.terminal_action.kind is not observed_kind
                or _interior_action_identity(expected) != _interior_action_identity(observed)
                or expected.outcome.exit_status != action.expected.status
                or observed.outcome.exit_status != action.observed.status
                or (
                    (expected.no_replay_exit is not None or observed.no_replay_exit is not None)
                    and (
                        expected.no_replay_exit != action.expected
                        or observed.no_replay_exit != action.observed
                    )
                )
            ):
                action_comparison = TerminalComparison.MISMATCH
    execution_complete = (
        scope is TraceScope.WHOLE_PROGRAM
        and bound
        and observed is not None
        and observed.outcome.terminal_known
        and action is not None
        and action_comparison is not TerminalComparison.INCOMPLETE
    )
    complete = (
        execution_complete
        and prefix_complete
        and outcome is TerminalComparison.MATCH
        and action_comparison is TerminalComparison.MATCH
    )
    return {
        "scope": scope.value,
        "ordinary_prefix_complete": prefix_complete,
        "expected_completion_available": expected is not None,
        "observed_completion_available": observed is not None,
        "final_live_boundary_bound": bound,
        "terminal_outcome": outcome.value,
        "terminal_action": action_comparison.value,
        "no_replay_actions": {"expected": _no_replay_actions_document(expected),
                              "observed": _no_replay_actions_document(observed)},
        "execution_complete": execution_complete,
        "complete": complete,
        "full_run_timing_eligible": execution_complete,
    }


def validation_report_document(
    report: ValidationReport,
    replay_coverage: ReplayCoverageReport | None,
    match_result: MatchResult | None = None,
    terminal_reason: TerminalReason | None = None,
    *,
    scope: TraceScope = TraceScope.UNSPECIFIED,
    expected_completion: TraceCompletion | None = None,
    observed_completion: TraceCompletion | None = None,
    terminal_action_validation: TerminalActionValidation | None = None,
) -> dict[str, Any]:
    """Convert validation and replay results to the stable JSON schema.

    Whole-program callers must pass the oracle's explicit scope/completion,
    the collector's independent observed completion, and live terminal-action
    validation. Neither EOF nor copying the oracle into ``observed_completion``
    is observation. ``trace.complete`` remains ordinary-prefix matching only;
    ``completion.complete`` additionally gates whole-program terminal evidence.
    """
    severity_counts: Counter[str] = Counter()
    entries: list[dict[str, object]] = []
    for entry in report.entries:
        errors = [_error_document(error) for error in entry["errors"]]
        severity_counts.update(str(error["severity"]) for error in errors)
        entries.append(
            {
                "pc": entry["pc"],
                "transition_range": _transition_range(entry["ref"]),
                "errors": errors,
            }
        )

    diagnostic_counts: Counter[str] = Counter()
    diagnostics: list[dict[str, object]] = []
    for diagnostic in report.diagnostics:
        level = str(diagnostic.level)
        diagnostic_counts[level] += 1
        diagnostics.append(
            {
                "level": level,
                "code": diagnostic.code,
                "message": diagnostic.message,
                "concrete_index": diagnostic.concrete_index,
                "transform_index": diagnostic.transform_index,
            }
        )

    replay = _replay_document(replay_coverage)
    status = _validation_status(severity_counts, diagnostic_counts, replay)
    if not isinstance(scope, TraceScope):
        raise ValueError("Report scope must be a TraceScope.")
    completion = (
        _whole_program_document(
            scope, expected_completion, observed_completion, terminal_action_validation, match_result
        )
        if scope is not TraceScope.UNSPECIFIED
        else {}
    )
    if scope is TraceScope.WHOLE_PROGRAM:
        if status == "accepted" and not completion["complete"]:
            status = (
                "mismatch"
                if TerminalComparison.MISMATCH.value
                in (completion["terminal_action"], completion["terminal_outcome"])
                else "incomplete"
            )
        # An earlier confirmed mismatch remains visible, but cannot certify a
        # full-run sample when ordinary validation contains gaps.
        if (
            severity_counts["incomplete"]
            or severity_counts["possible"]
            or diagnostic_counts["error"]
            or diagnostic_counts["incomplete"]
            or status == "replay-error"
        ):
            completion["complete"] = False
            if status == "accepted":
                status = "incomplete"
    return {
        "schema": QEMU_VALIDATION_REPORT_SCHEMA,
        "status": status,
        "validation": {
            "entry_count": len(entries),
            "entries": entries,
            "diagnostics": diagnostics,
            "severity_counts": dict(sorted(severity_counts.items())),
            "diagnostic_counts": dict(sorted(diagnostic_counts.items())),
        },
        "replay": replay,
        "trace": _trace_document(match_result),
        "terminal_reason": _terminal_reason_document(terminal_reason),
        **({"completion": completion} if scope is not TraceScope.UNSPECIFIED else {}),
    }


def _replay_document(report: ReplayCoverageReport | None) -> dict[str, object]:
    if report is None:
        return {
            "active": False,
            "record_count": 0,
            "records": [],
            "by_strategy": {},
            "by_outcome": {},
        }
    records = [
        {
            "event_count": record.event_count,
            "effect": record.effect,
            "strategy": record.strategy.value,
            "outcome": record.outcome.value,
            "detail": record.detail,
        }
        for record in report.records
    ]
    return {
        "active": True,
        "record_count": len(records),
        "records": records,
        "by_strategy": {
            strategy.value: count
            for strategy, count in sorted(
                report.by_strategy.items(), key=lambda item: item[0].value
            )
        },
        "by_outcome": {
            outcome.value: count
            for outcome, count in sorted(report.by_outcome.items(), key=lambda item: item[0].value)
        },
    }


def _validation_status(
    severities: Counter[str],
    diagnostics: Counter[str],
    replay: dict[str, object],
) -> str:
    outcomes = replay["by_outcome"]
    if isinstance(outcomes, dict) and any(
        int(outcomes.get(name, 0)) for name in ("rejected", "failed")
    ):
        return "replay-error"
    if severities["confirmed"]:
        return "mismatch"
    if severities["incomplete"] or diagnostics["error"] or diagnostics["incomplete"]:
        return "incomplete"
    if severities["possible"]:
        return "possible-mismatch"
    return "accepted"


def validation_failure_document(
    error: Exception,
    replay_coverage: ReplayCoverageReport | None,
    *,
    stage: str = "validation",
) -> dict[str, Any]:
    """Describe a failed run without converting the failure into success."""
    replay = _replay_document(replay_coverage)
    outcomes = replay["by_outcome"]
    if isinstance(outcomes, dict) and outcomes.get("rejected", 0):
        status = "replay-rejected"
    elif isinstance(outcomes, dict) and outcomes.get("failed", 0):
        status = "replay-failed"
    else:
        status = "failed"
    return {
        "schema": QEMU_VALIDATION_REPORT_SCHEMA,
        "status": status,
        "failure": {
            "stage": stage,
            "type": type(error).__name__,
            "message": str(error),
        },
        "validation": {
            "entry_count": 0,
            "entries": [],
            "diagnostics": [],
            "severity_counts": {},
            "diagnostic_counts": {},
        },
        "replay": replay,
        "trace": _trace_document(None),
    }


def _write_document(path: str | Path, document: dict[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)


def write_validation_report(
    path: str | Path,
    report: ValidationReport,
    replay_coverage: ReplayCoverageReport | None,
    match_result: MatchResult | None = None,
    terminal_reason: TerminalReason | None = None,
    *,
    scope: TraceScope = TraceScope.UNSPECIFIED,
    expected_completion: TraceCompletion | None = None,
    observed_completion: TraceCompletion | None = None,
    terminal_action_validation: TerminalActionValidation | None = None,
) -> None:
    """Atomically persist validation, replay, and terminal trace evidence."""
    _write_document(
        path,
        validation_report_document(
            report,
            replay_coverage,
            match_result,
            terminal_reason,
            scope=scope,
            expected_completion=expected_completion,
            observed_completion=observed_completion,
            terminal_action_validation=terminal_action_validation,
        ),
    )


def write_validation_failure_report(
    path: str | Path,
    error: Exception,
    replay_coverage: ReplayCoverageReport | None,
    *,
    stage: str = "validation",
) -> None:
    """Persist a failure report and leave raising/exit handling to the caller."""
    _write_document(
        path,
        validation_failure_document(error, replay_coverage, stage=stage),
    )
