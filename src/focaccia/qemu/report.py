"""Structured, versioned output for QEMU validation and replay coverage."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from focaccia.compare import ErrorTypes, ValidationReport
from focaccia.qemu.syscall import ReplayCoverageReport


QEMU_VALIDATION_REPORT_SCHEMA = "focaccia-qemu-validation-v1"


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


def validation_report_document(
    report: ValidationReport,
    replay_coverage: ReplayCoverageReport | None,
) -> dict[str, Any]:
    """Convert validation and replay results to the stable JSON schema."""
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
) -> None:
    """Atomically persist one structured validation report."""
    _write_document(path, validation_report_document(report, replay_coverage))


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
