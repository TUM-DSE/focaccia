from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from focaccia.tools import rr_qemu_smoke as smoke


def make_plan(tmp_path: Path) -> smoke.SmokePlan:
    return smoke.SmokePlan(
        tmp_path / "file-read",
        tmp_path / "input.txt",
        0x401000,
        0x401040,
        23451,
        23452,
        1.0,
        1.0,
        smoke.SmokeToolchain(
            "/tools/rr",
            "/tools/qemu-x86_64",
            "/tools/capture-transforms",
            "/tools/validate-qemu",
            "/tools/nm",
        ),
        smoke.SmokeArtifacts.under(tmp_path / "run"),
    )


def test_smoke_plan_uses_native_rr_oracle_and_separate_qemu_consumer(tmp_path):
    plan = make_plan(tmp_path)
    commands = plan.commands()

    assert commands["rr-record"] == (
        "/tools/rr",
        "record",
        "-n",
        "-o",
        str(plan.artifacts.rr_trace),
        str(plan.binary),
        str(plan.input_file),
    )
    assert commands["capture-oracle"][-2:] == (
        str(plan.binary),
        str(plan.input_file),
    )
    assert "--deterministic-log" in commands["capture-oracle"]
    assert commands["qemu"] == (
        "/tools/qemu-x86_64",
        "-g",
        "23452",
        str(plan.binary),
        str(plan.input_file),
    )
    assert "--run-manifest" in commands["validate"]
    assert "input=" + str(plan.input_file) in commands["validate"]
    assert commands["validate"][commands["validate"].index("--report") + 1] == str(
        plan.artifacts.validation_report
    )

    document = plan.to_json()
    assert document["schema"] == smoke.SMOKE_PLAN_SCHEMA
    assert document["guest"]["architecture"] == "x86_64-linux"
    assert document["limits_seconds"] == {"command": 1.0, "server_startup": 1.0}
    assert "same-user ptrace" in document["capabilities"]


def test_smoke_harness_refuses_to_overwrite_a_run_directory(tmp_path):
    plan = make_plan(tmp_path)
    plan.artifacts.run_directory.mkdir(parents=True)

    with pytest.raises(smoke.SmokeRunError, match="refusing to overwrite"):
        smoke.execute_smoke_plan(plan)


def test_smoke_harness_records_stage_order_and_requires_accepted_coverage(tmp_path, monkeypatch):
    plan = make_plan(tmp_path)
    calls: list[str] = []

    monkeypatch.setattr(smoke, "_preflight", lambda _plan: {"machine": "x86_64"})
    monkeypatch.setattr(smoke, "_wait_for_listener", lambda *args, **kwargs: None)

    class FakeManagedProcess:
        def __init__(self, command, _log_path):
            self.stage = "rr-replay" if "replay" in command else "qemu"

        def __enter__(self):
            calls.append(self.stage)
            return cast(Any, SimpleNamespace(poll=lambda: None))

        def __exit__(self, _type, _value, _traceback):
            return None

    monkeypatch.setattr(smoke, "_ManagedProcess", FakeManagedProcess)

    def fake_run(command, _log_path, *, timeout):
        del timeout
        if command[0].endswith("rr"):
            calls.append("rr-record")
        elif command[0].endswith("capture-transforms"):
            calls.append("capture-oracle")
        else:
            calls.append("validate")
            plan.artifacts.validation_report.write_text(
                json.dumps(
                    {
                        "schema": smoke.QEMU_VALIDATION_REPORT_SCHEMA,
                        "status": "accepted",
                        "replay": {
                            "active": True,
                            "record_count": 4,
                            "records": [{}, {}, {}, {}],
                            "by_outcome": {"handled": 4},
                        },
                    }
                )
            )

    monkeypatch.setattr(smoke, "_run_logged", fake_run)

    def fake_manifest(_plan):
        calls.append("run-manifest")
        plan.artifacts.run_manifest.write_text("{}")

    monkeypatch.setattr(smoke, "_make_manifest", fake_manifest)

    result = smoke.execute_smoke_plan(plan)

    assert result["status"] == "accepted"
    assert result["completed_stages"] == [
        "preflight",
        "rr-record",
        "rr-replay",
        "capture-oracle",
        "run-manifest",
        "qemu",
        "validate",
    ]
    assert calls == [
        "rr-record",
        "rr-replay",
        "capture-oracle",
        "run-manifest",
        "qemu",
        "validate",
    ]
    persisted = json.loads(plan.artifacts.result.read_text())
    assert persisted["status"] == "accepted"
    assert len(persisted["artifacts"]["run_manifest"]["sha256"]) == 64
    assert len(persisted["artifacts"]["validation_report"]["sha256"]) == 64


def test_timed_command_terminates_its_process_group(tmp_path, monkeypatch):
    waits: list[float] = []
    signals: list[tuple[int, int]] = []

    class FakeProcess:
        pid = 4242

        def poll(self):
            return None

        def wait(self, timeout):
            waits.append(timeout)
            if len(waits) == 1:
                raise smoke.subprocess.TimeoutExpired(("tool",), timeout)
            return -15

    monkeypatch.setattr(smoke.subprocess, "Popen", lambda *args, **kwargs: FakeProcess())
    monkeypatch.setattr(
        smoke.os,
        "killpg",
        lambda pid, selected_signal: signals.append((pid, selected_signal)),
    )

    with pytest.raises(smoke.SmokeRunError, match="timed out"):
        smoke._run_logged(("tool",), tmp_path / "tool.log", timeout=1)

    assert waits == [1, 3]
    assert signals == [(4242, smoke.signal.SIGTERM)]


def test_smoke_harness_fails_when_validator_reports_rejected_effects(tmp_path, monkeypatch):
    plan = make_plan(tmp_path)
    monkeypatch.setattr(smoke, "_preflight", lambda _plan: {})
    monkeypatch.setattr(smoke, "_wait_for_listener", lambda *args, **kwargs: None)

    class FakeManagedProcess:
        def __init__(self, _command, _log_path):
            pass

        def __enter__(self):
            return cast(Any, SimpleNamespace(poll=lambda: None))

        def __exit__(self, _type, _value, _traceback):
            return None

    monkeypatch.setattr(smoke, "_ManagedProcess", FakeManagedProcess)
    monkeypatch.setattr(smoke, "_make_manifest", lambda _plan: None)

    def fake_run(command, _log_path, *, timeout):
        del timeout
        if command[0].endswith("validate-qemu"):
            plan.artifacts.validation_report.write_text(
                json.dumps(
                    {
                        "schema": smoke.QEMU_VALIDATION_REPORT_SCHEMA,
                        "status": "accepted",
                        "replay": {
                            "active": True,
                            "record_count": 1,
                            "records": [{}],
                            "by_outcome": {"rejected": 1},
                        },
                    }
                )
            )

    monkeypatch.setattr(smoke, "_run_logged", fake_run)

    with pytest.raises(smoke.SmokeRunError, match="rejected or failed"):
        smoke.execute_smoke_plan(plan)

    result = json.loads(plan.artifacts.result.read_text())
    assert result["status"] == "failed"
    assert result["failure"]["type"] == "SmokeRunError"
