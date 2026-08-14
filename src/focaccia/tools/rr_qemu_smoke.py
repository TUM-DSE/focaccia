"""Bounded native x86-64 RR-oracle to QEMU-consumer smoke harness."""

from __future__ import annotations

import argparse
import json
import os
import platform
import signal
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

from focaccia import parser as trace_parser
from focaccia.deterministic import DeterministicLog
from focaccia.qemu.integration import (
    create_replay_run_manifest,
    write_replay_run_manifest,
)
from focaccia.qemu.report import QEMU_VALIDATION_REPORT_SCHEMA
from focaccia.utils import file_hash


SMOKE_PLAN_SCHEMA = "focaccia-rr-qemu-smoke-plan-v1"
SMOKE_RESULT_SCHEMA = "focaccia-rr-qemu-smoke-result-v1"


class SmokeRunError(RuntimeError):
    """A bounded smoke-run stage failed or produced an unacceptable result."""


@dataclass(frozen=True, slots=True)
class SmokeToolchain:
    rr: str
    qemu: str
    capture: str
    validate: str
    nm: str


@dataclass(frozen=True, slots=True)
class SmokeArtifacts:
    run_directory: Path
    rr_trace: Path
    oracle_trace: Path
    run_manifest: Path
    validation_report: Path
    result: Path

    @classmethod
    def under(cls, run_directory: str | Path) -> SmokeArtifacts:
        root = Path(run_directory).resolve()
        return cls(
            root,
            root / "rr-trace",
            root / "oracle.trace.json",
            root / "run-manifest.json",
            root / "validation-report.json",
            root / "result.json",
        )


@dataclass(frozen=True, slots=True)
class SmokePlan:
    binary: Path
    input_file: Path
    start_address: int
    stop_address: int
    rr_port: int
    qemu_port: int
    command_timeout: float
    startup_timeout: float
    tools: SmokeToolchain
    artifacts: SmokeArtifacts

    @property
    def guest_argv(self) -> tuple[str, ...]:
        return (str(self.input_file),)

    def commands(self) -> dict[str, tuple[str, ...]]:
        guest = (str(self.binary), *self.guest_argv)
        remote_rr = f"127.0.0.1:{self.rr_port}"
        remote_qemu = f"127.0.0.1:{self.qemu_port}"
        return {
            "rr-record": (
                self.tools.rr,
                "record",
                "-n",
                "-o",
                str(self.artifacts.rr_trace),
                *guest,
            ),
            "rr-replay": (
                self.tools.rr,
                "replay",
                "-s",
                str(self.rr_port),
                str(self.artifacts.rr_trace),
            ),
            "capture-oracle": (
                self.tools.capture,
                "--remote",
                remote_rr,
                "--deterministic-log",
                str(self.artifacts.rr_trace),
                "--output",
                str(self.artifacts.oracle_trace),
                "--start-address",
                hex(self.start_address),
                "--stop-address",
                hex(self.stop_address),
                str(self.binary),
                *self.guest_argv,
            ),
            "qemu": (
                self.tools.qemu,
                "-g",
                str(self.qemu_port),
                *guest,
            ),
            "validate": (
                self.tools.validate,
                "--symb-trace",
                str(self.artifacts.oracle_trace),
                "--remote",
                remote_qemu,
                "--deterministic-log",
                str(self.artifacts.rr_trace),
                "--executable",
                str(self.binary),
                "--run-manifest",
                str(self.artifacts.run_manifest),
                "--run-input",
                f"input={self.input_file}",
                "--report",
                str(self.artifacts.validation_report),
                "--error-level",
                "info",
            ),
        }

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": SMOKE_PLAN_SCHEMA,
            "guest": {
                "architecture": "x86_64-linux",
                "binary": str(self.binary),
                "argv": list(self.guest_argv),
                "input": str(self.input_file),
                "start_address": self.start_address,
                "stop_address": self.stop_address,
            },
            "ports": {"rr": self.rr_port, "qemu": self.qemu_port},
            "limits_seconds": {
                "command": self.command_timeout,
                "server_startup": self.startup_timeout,
            },
            "commands": {name: list(command) for name, command in self.commands().items()},
            "artifacts": {
                "directory": str(self.artifacts.run_directory),
                "rr_trace": str(self.artifacts.rr_trace),
                "oracle_trace": str(self.artifacts.oracle_trace),
                "run_manifest": str(self.artifacts.run_manifest),
                "validation_report": str(self.artifacts.validation_report),
                "result": str(self.artifacts.result),
            },
            "capabilities": [
                "native x86-64 execution",
                "same-user ptrace",
                "usable perf events",
                "personality/ASLR control",
                "process_vm_readv/process_vm_writev",
                "two loopback TCP listeners",
            ],
        }


class _ManagedProcess:
    def __init__(self, command: tuple[str, ...], log_path: Path) -> None:
        self.command = command
        self.log_path = log_path
        self._log: TextIO | None = None
        self.process: subprocess.Popen[str] | None = None

    def start(self) -> subprocess.Popen[str]:
        self._log = self.log_path.open("w", encoding="utf-8")
        try:
            self.process = subprocess.Popen(
                self.command,
                stdout=self._log,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
        except OSError:
            self._log.close()
            self._log = None
            raise
        return self.process

    def stop(self) -> None:
        process = self.process
        try:
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=3)
        finally:
            if self._log is not None:
                self._log.close()

    def __enter__(self) -> subprocess.Popen[str]:
        return self.start()

    def __exit__(self, _type, _value, _traceback) -> None:
        self.stop()


def _run_logged(
    command: tuple[str, ...],
    log_path: Path,
    *,
    timeout: float,
) -> None:
    managed = _ManagedProcess(command, log_path)
    with managed as process:
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise SmokeRunError(
                f"Command timed out after {timeout:g}s: {list(command)!r}."
            ) from error
        if returncode != 0:
            raise SmokeRunError(
                f"Command exited with status {returncode}: {list(command)!r}; " f"see {log_path}."
            )


def _is_listening(port: int) -> bool:
    encoded = f"{port:04X}"
    for table in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        try:
            lines = table.read_text(encoding="ascii").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) >= 4 and fields[1].rsplit(":", 1)[-1] == encoded:
                if fields[3] == "0A":
                    return True
    return False


def _wait_for_listener(
    process: subprocess.Popen[str],
    port: int,
    *,
    timeout: float,
    stage: str,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        returncode = process.poll()
        if returncode is not None:
            raise SmokeRunError(
                f"{stage} exited with status {returncode} before listening on port {port}."
            )
        if _is_listening(port):
            return
        time.sleep(0.05)
    raise SmokeRunError(f"{stage} did not listen on port {port} within {timeout:g}s.")


def _require_free_port(port: int) -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
            candidate.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            candidate.bind(("127.0.0.1", port))
    except OSError as error:
        raise SmokeRunError(f"Loopback port {port} is unavailable: {error}.") from error


def read_fixture_symbols(nm: str, binary: str | Path) -> tuple[int, int]:
    """Read the fixture's explicit trace bounds without executing the guest."""
    completed = subprocess.run(
        (nm, "-n", str(binary)),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if completed.returncode != 0:
        raise SmokeRunError(
            f"Unable to inspect fixture symbols with {nm}: {completed.stderr.strip()}."
        )
    symbols: dict[str, int] = {}
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[-1] in (
            "_focaccia_trace_start",
            "_focaccia_trace_stop",
        ):
            try:
                symbols[fields[-1]] = int(fields[0], 16)
            except ValueError as error:
                raise SmokeRunError(f"Invalid fixture symbol line: {line!r}.") from error
    try:
        start = symbols["_focaccia_trace_start"]
        stop = symbols["_focaccia_trace_stop"]
    except KeyError as error:
        raise SmokeRunError(f"Fixture lacks required trace symbol {error.args[0]}.") from error
    if stop <= start:
        raise SmokeRunError("Fixture trace-stop symbol must follow trace-start.")
    return start, stop


def _preflight(plan: SmokePlan) -> dict[str, object]:
    machine = platform.machine().lower()
    if machine not in ("x86_64", "amd64"):
        raise SmokeRunError(
            f"Native RR oracle generation requires x86-64 hardware, not {machine!r}."
        )
    for name, path in (
        ("rr", plan.tools.rr),
        ("qemu", plan.tools.qemu),
        ("capture", plan.tools.capture),
        ("validate", plan.tools.validate),
        ("nm", plan.tools.nm),
    ):
        tool = Path(path)
        if not tool.is_file() or not os.access(tool, os.X_OK):
            raise SmokeRunError(f"Configured {name} tool is not executable: {tool}.")
    if not plan.binary.is_file() or not os.access(plan.binary, os.X_OK):
        raise SmokeRunError(f"Fixture binary is not executable: {plan.binary}.")
    if not plan.input_file.is_file():
        raise SmokeRunError(f"Fixture input does not exist: {plan.input_file}.")
    if not any(os.access(path, os.R_OK) for path in ("/proc/net/tcp", "/proc/net/tcp6")):
        raise SmokeRunError("The harness requires readable Linux /proc TCP tables.")
    _require_free_port(plan.rr_port)
    _require_free_port(plan.qemu_port)
    if plan.rr_port == plan.qemu_port:
        raise SmokeRunError("RR and QEMU must use different ports.")

    kernel_values: dict[str, str | None] = {}
    for name, path in {
        "perf_event_paranoid": Path("/proc/sys/kernel/perf_event_paranoid"),
        "ptrace_scope": Path("/proc/sys/kernel/yama/ptrace_scope"),
        "randomize_va_space": Path("/proc/sys/kernel/randomize_va_space"),
    }.items():
        try:
            kernel_values[name] = path.read_text(encoding="ascii").strip()
        except OSError:
            kernel_values[name] = None
    perf_value = kernel_values["perf_event_paranoid"]
    if perf_value is not None:
        try:
            if int(perf_value) > 3:
                raise SmokeRunError(
                    "RR requires usable perf events; kernel.perf_event_paranoid is "
                    f"{perf_value} (> 3)."
                )
        except ValueError as error:
            raise SmokeRunError(
                f"Invalid kernel.perf_event_paranoid value {perf_value!r}."
            ) from error
    return {"machine": machine, "kernel": kernel_values}


def _make_manifest(plan: SmokePlan) -> None:
    with plan.artifacts.oracle_trace.open("r", encoding="utf-8") as oracle_file:
        symbolic_trace = trace_parser.parse_transformations(oracle_file)
    deterministic_log = DeterministicLog(plan.artifacts.rr_trace)
    manifest = create_replay_run_manifest(
        binary_path=plan.binary,
        input_paths={"input": plan.input_file},
        argv=plan.guest_argv,
        oracle_path=plan.artifacts.oracle_trace,
        trace_environment=symbolic_trace.env,
        deterministic_log=deterministic_log,
    )
    write_replay_run_manifest(plan.artifacts.run_manifest, manifest)


def _artifact_summary(plan: SmokePlan) -> dict[str, object]:
    summary: dict[str, object] = {
        "rr_trace": {"path": str(plan.artifacts.rr_trace)},
    }
    for name, path in (
        ("plan", plan.artifacts.run_directory / "plan.json"),
        ("oracle_trace", plan.artifacts.oracle_trace),
        ("run_manifest", plan.artifacts.run_manifest),
        ("validation_report", plan.artifacts.validation_report),
    ):
        if path.is_file():
            summary[name] = {"path": str(path), "sha256": file_hash(path)}
    return summary


def _load_accepted_validation(plan: SmokePlan) -> dict[str, Any]:
    document = json.loads(plan.artifacts.validation_report.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise SmokeRunError("Validation report must be a JSON object.")
    if document.get("schema") != QEMU_VALIDATION_REPORT_SCHEMA:
        raise SmokeRunError(f"Validation report has unsupported schema {document.get('schema')!r}.")
    if document.get("status") != "accepted":
        raise SmokeRunError(
            "QEMU validation did not accept the reference fixture; see "
            f"{plan.artifacts.validation_report}."
        )
    replay = document.get("replay")
    if not isinstance(replay, dict) or replay.get("active") is not True:
        raise SmokeRunError("Validation report does not contain active replay coverage.")
    records = replay.get("records")
    record_count = replay.get("record_count")
    if (
        not isinstance(records, list)
        or not isinstance(record_count, int)
        or isinstance(record_count, bool)
        or record_count <= 0
        or record_count != len(records)
    ):
        raise SmokeRunError("Validation report contains invalid or empty replay records.")
    outcomes = replay.get("by_outcome")
    if not isinstance(outcomes, dict) or any(
        outcomes.get(name, 0) for name in ("rejected", "failed")
    ):
        raise SmokeRunError("Validation report contains rejected or failed replay effects.")
    return document


def execute_smoke_plan(plan: SmokePlan) -> dict[str, Any]:
    """Execute every stage with bounded waits and process-group cleanup."""
    if plan.artifacts.run_directory.exists():
        raise SmokeRunError(
            f"Run directory already exists; refusing to overwrite it: "
            f"{plan.artifacts.run_directory}."
        )
    plan.artifacts.run_directory.mkdir(parents=True)
    plan.artifacts.run_directory.joinpath("plan.json").write_text(
        json.dumps(plan.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    commands = plan.commands()
    stages: list[str] = []
    preflight: dict[str, object] | None = None
    try:
        preflight = _preflight(plan)
        stages.append("preflight")
        _run_logged(
            commands["rr-record"],
            plan.artifacts.run_directory / "rr-record.log",
            timeout=plan.command_timeout,
        )
        stages.append("rr-record")

        rr_server = _ManagedProcess(
            commands["rr-replay"],
            plan.artifacts.run_directory / "rr-replay.log",
        )
        with rr_server as rr_process:
            _wait_for_listener(
                rr_process,
                plan.rr_port,
                timeout=plan.startup_timeout,
                stage="RR replay server",
            )
            stages.append("rr-replay")
            _run_logged(
                commands["capture-oracle"],
                plan.artifacts.run_directory / "capture-oracle.log",
                timeout=plan.command_timeout,
            )
            stages.append("capture-oracle")
        _make_manifest(plan)
        stages.append("run-manifest")

        qemu_server = _ManagedProcess(
            commands["qemu"],
            plan.artifacts.run_directory / "qemu.log",
        )
        with qemu_server as qemu_process:
            _wait_for_listener(
                qemu_process,
                plan.qemu_port,
                timeout=plan.startup_timeout,
                stage="QEMU GDB server",
            )
            stages.append("qemu")
            _run_logged(
                commands["validate"],
                plan.artifacts.run_directory / "validate.log",
                timeout=plan.command_timeout,
            )
            stages.append("validate")

        _load_accepted_validation(plan)
        result = {
            "schema": SMOKE_RESULT_SCHEMA,
            "status": "accepted",
            "completed_stages": stages,
            "preflight": preflight,
            "artifacts": _artifact_summary(plan),
        }
        plan.artifacts.result.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return result
    except Exception as error:
        result = {
            "schema": SMOKE_RESULT_SCHEMA,
            "status": "failed",
            "completed_stages": stages,
            "failure": {"type": type(error).__name__, "message": str(error)},
            "artifacts": _artifact_summary(plan),
        }
        plan.artifacts.result.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        raise


def make_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a bounded native x86-64 RR-to-QEMU Focaccia smoke test."
    )
    parser.add_argument("--run-directory", required=True)
    parser.add_argument("--rr", default=os.environ.get("FOCACCIA_RR"))
    parser.add_argument("--qemu", default=os.environ.get("FOCACCIA_QEMU_X86_64"))
    parser.add_argument("--capture", default=os.environ.get("FOCACCIA_CAPTURE_TRANSFORMS"))
    parser.add_argument("--validate", default=os.environ.get("FOCACCIA_VALIDATE_QEMU"))
    parser.add_argument("--nm", default=os.environ.get("FOCACCIA_NM"))
    parser.add_argument("--binary", default=os.environ.get("FOCACCIA_SMOKE_BINARY"))
    parser.add_argument("--input", default=os.environ.get("FOCACCIA_SMOKE_INPUT"))
    parser.add_argument("--rr-port", type=int, default=12345)
    parser.add_argument("--qemu-port", type=int, default=12346)
    parser.add_argument("--command-timeout", type=float, default=120.0)
    parser.add_argument("--startup-timeout", type=float, default=15.0)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the exact plan without creating files or launching targets.",
    )
    return parser


def _required_path(parser: argparse.ArgumentParser, value: str | None, name: str) -> str:
    if not value:
        parser.error(f"{name} must be supplied by the flake app or command line")
    return value


def main() -> None:
    argument_parser = make_argparser()
    args = argument_parser.parse_args()
    if args.command_timeout <= 0 or args.startup_timeout <= 0:
        argument_parser.error("timeouts must be positive")
    for name, port in (("--rr-port", args.rr_port), ("--qemu-port", args.qemu_port)):
        if not 1 <= port <= 65535:
            argument_parser.error(f"{name} must be between 1 and 65535")

    tools = SmokeToolchain(
        _required_path(argument_parser, args.rr, "--rr"),
        _required_path(argument_parser, args.qemu, "--qemu"),
        _required_path(argument_parser, args.capture, "--capture"),
        _required_path(argument_parser, args.validate, "--validate"),
        _required_path(argument_parser, args.nm, "--nm"),
    )
    binary = Path(_required_path(argument_parser, args.binary, "--binary")).resolve()
    input_file = Path(_required_path(argument_parser, args.input, "--input")).resolve()
    start_address, stop_address = read_fixture_symbols(tools.nm, binary)
    plan = SmokePlan(
        binary,
        input_file,
        start_address,
        stop_address,
        args.rr_port,
        args.qemu_port,
        args.command_timeout,
        args.startup_timeout,
        tools,
        SmokeArtifacts.under(args.run_directory),
    )
    if args.dry_run:
        print(json.dumps(plan.to_json(), indent=2, sort_keys=True))
        return
    result = execute_smoke_plan(plan)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
