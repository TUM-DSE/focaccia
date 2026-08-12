from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from focaccia.arch import x86
from focaccia.compare import Error, ErrorTypes, ValidationReport
from focaccia.qemu.report import (
    QEMU_VALIDATION_REPORT_SCHEMA,
    validation_failure_document,
    validation_report_document,
    write_validation_report,
)
from focaccia.qemu.syscall import (
    CoverageOutcome,
    ReplayCoverage,
    ReplayStrategy,
)
from focaccia.snapshot import ProgramState
from focaccia.trace import TraceDiagnostic, TraceEnvironment


def load_qemu_tool(monkeypatch):
    fake_gdb = ModuleType("gdb")
    for name in ("Breakpoint", "Frame", "Inferior", "Value"):
        setattr(fake_gdb, name, object)
    setattr(fake_gdb, "MemoryError", RuntimeError)
    monkeypatch.setitem(sys.modules, "gdb", fake_gdb)
    sys.modules.pop("focaccia.qemu.target", None)
    sys.modules.pop("focaccia.qemu._qemu_tool", None)
    return importlib.import_module("focaccia.qemu._qemu_tool")


@pytest.mark.parametrize("quiet", [False, True])
def test_gdb_validation_avoids_timing_output_and_writes_report(
    tmp_path,
    monkeypatch,
    capsys,
    quiet: bool,
):
    qemu_tool = load_qemu_tool(monkeypatch)
    oracle = tmp_path / "oracle.json"
    output = tmp_path / "report.json"
    oracle.write_text("{}")
    trace = SimpleNamespace(
        env=TraceEnvironment(None, (), (), binary_hash=None, architecture=x86.ArchX86().key)
    )
    server = SimpleNamespace(
        binary="/guest",
        replay_coverage_report=lambda: None,
    )
    comparison = ValidationReport()
    writes = []
    arguments = [
        "--symb-trace",
        str(oracle),
        "--remote",
        "localhost:1234",
        "--report",
        str(output),
    ]
    if quiet:
        arguments.append("--quiet")
    monkeypatch.setattr(
        qemu_tool,
        "decode_gdb_arguments",
        lambda _environment: arguments,
    )
    monkeypatch.setattr(qemu_tool, "DeterministicLog", lambda _path: object())
    monkeypatch.setattr(qemu_tool.parser, "parse_transformations", lambda _file: trace)
    monkeypatch.setattr(qemu_tool, "GDBServerStateIterator", lambda _remote, _log: server)
    monkeypatch.setattr(
        qemu_tool,
        "collect_conc_trace",
        lambda _server, _trace, **_kwargs: SimpleNamespace(
            trace=None,
            diagnostics=(),
            pending_transform=None,
        ),
    )
    monkeypatch.setattr(qemu_tool, "compare_symbolic", lambda *_args, **_kwargs: comparison)
    monkeypatch.setattr(qemu_tool, "print_result", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        qemu_tool,
        "write_validation_report",
        lambda path, report, coverage: writes.append((path, report, coverage)),
    )

    try:
        qemu_tool.main()
    finally:
        sys.modules.pop("focaccia.qemu._qemu_tool", None)
        sys.modules.pop("focaccia.qemu.target", None)

    assert "time" not in capsys.readouterr().out.lower()
    assert writes == [(str(output), comparison, None)]


def test_structured_qemu_report_preserves_validation_and_replay_coverage(tmp_path):
    arch = x86.ArchX86()
    state = ProgramState(arch)
    state.write_register("rip", 0x401000)
    coverage = ReplayCoverage()
    coverage.record(
        event_count=12,
        effect="read",
        strategy=ReplayStrategy.RECORDED,
        outcome=CoverageOutcome.HANDLED,
    )
    report = ValidationReport(
        (
            {
                "pc": 0x401000,
                "txl": state,
                "ref": state,
                "errors": [Error(ErrorTypes.CONFIRMED, "RAX differs")],
                "snap": state,
            },
        ),
        (TraceDiagnostic("info", "cutpoint", "Cutpoint selected", 2, 1),),
    )

    document = validation_report_document(report, coverage.report())

    assert document["schema"] == QEMU_VALIDATION_REPORT_SCHEMA
    assert document["status"] == "mismatch"
    assert document["validation"]["entries"][0]["errors"] == [
        {
            "severity": "confirmed",
            "severity_label": "ERROR",
            "code": None,
            "subject": None,
            "message": "RAX differs",
        }
    ]
    assert document["validation"]["diagnostics"][0]["concrete_index"] == 2
    assert document["replay"]["records"] == [
        {
            "event_count": 12,
            "effect": "read",
            "strategy": "recorded-replay",
            "outcome": "handled",
            "detail": None,
        }
    ]
    assert document["replay"]["by_strategy"] == {"recorded-replay": 1}

    classified = ValidationReport(
        (
            {
                "pc": 0x401000,
                "txl": state,
                "ref": state,
                "errors": [
                    Error(
                        ErrorTypes.CONFIRMED,
                        "RAX differs",
                        code="register-content-mismatch",
                        subject="RAX",
                    )
                ],
                "snap": state,
            },
        )
    )
    classified_error = validation_report_document(classified, None)["validation"]["entries"][0][
        "errors"
    ][0]
    assert classified_error["code"] == "register-content-mismatch"
    assert classified_error["subject"] == "RAX"

    path = tmp_path / "report.json"
    write_validation_report(path, report, coverage.report())
    assert json.loads(path.read_text()) == document


def test_gdb_validation_persists_artifacts_before_renderer_failure(
    tmp_path,
    monkeypatch,
):
    qemu_tool = load_qemu_tool(monkeypatch)
    oracle = tmp_path / "oracle.json"
    report_path = tmp_path / "validation.json"
    states_path = tmp_path / "states.trace"
    oracle.write_text("{}")
    trace = SimpleNamespace(
        env=TraceEnvironment(None, (), (), binary_hash=None, architecture=x86.ArchX86().key)
    )
    state = ProgramState(x86.ArchX86())
    state.write_register("RIP", 0x401000)
    matched = SimpleNamespace(
        trace=SimpleNamespace(state_boundaries=(state,)),
        diagnostics=(),
        pending_transform=None,
    )
    server = SimpleNamespace(
        binary="/guest",
        replay_coverage_report=lambda: None,
    )
    arguments = [
        "--symb-trace",
        str(oracle),
        "--remote",
        "localhost:1234",
        "--report",
        str(report_path),
        "--output",
        str(states_path),
    ]
    monkeypatch.setattr(qemu_tool, "decode_gdb_arguments", lambda _environment: arguments)
    monkeypatch.setattr(qemu_tool, "DeterministicLog", lambda _path: object())
    monkeypatch.setattr(qemu_tool.parser, "parse_transformations", lambda _file: trace)
    monkeypatch.setattr(qemu_tool, "GDBServerStateIterator", lambda _remote, _log: server)
    monkeypatch.setattr(qemu_tool, "collect_conc_trace", lambda *_args, **_kwargs: matched)
    monkeypatch.setattr(qemu_tool, "compare_symbolic", lambda *_args, **_kwargs: ValidationReport())

    def renderer_failure(*_args, **_kwargs):
        assert report_path.is_file()
        assert states_path.is_file()
        raise RuntimeError("renderer failed")

    monkeypatch.setattr(qemu_tool, "print_result", renderer_failure)

    with pytest.raises(RuntimeError, match="renderer failed"):
        qemu_tool.main()

    assert Path(report_path).is_file()
    assert json.loads(report_path.read_text())["status"] == "accepted"
    assert states_path.is_file()


def test_structured_qemu_failure_preserves_rejected_coverage():
    coverage = ReplayCoverage()
    coverage.record(
        event_count=19,
        effect="unknown-syscall-999",
        strategy=ReplayStrategy.REJECT,
        outcome=CoverageOutcome.REJECTED,
        detail="No replay policy",
    )

    document = validation_failure_document(RuntimeError("replay stopped"), coverage.report())

    assert document["status"] == "replay-rejected"
    assert document["failure"] == {
        "stage": "validation",
        "type": "RuntimeError",
        "message": "replay stopped",
    }
    assert document["replay"]["by_outcome"] == {"rejected": 1}


def test_structured_qemu_report_marks_incomplete_and_inactive_replay():
    report = ValidationReport(
        diagnostics=(TraceDiagnostic("incomplete", "trace-gap", "Unknown semantics"),)
    )

    document = validation_report_document(report, None)

    assert document["status"] == "incomplete"
    assert document["replay"] == {
        "active": False,
        "record_count": 0,
        "records": [],
        "by_strategy": {},
        "by_outcome": {},
    }
