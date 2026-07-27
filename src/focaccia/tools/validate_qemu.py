#!/usr/bin/env python3

"""Launch the fake-testable QEMU GDB or plugin validation backend."""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import sysconfig
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import focaccia
import focaccia.qemu
from focaccia.arch import supported_architectures
from focaccia.compare import ErrorTypes
from focaccia.qemu.validation_server import start_validation_server
from focaccia.trace import TraceEnvironment


verbosity = {
    "debug": ErrorTypes.INFO,
    "info": ErrorTypes.INFO,
    "warning": ErrorTypes.POSSIBLE,
    "error": ErrorTypes.CONFIRMED,
}

GDB_ARGUMENTS_ENV = "FOCACCIA_GDB_ARGUMENTS_V1"
GDB_ARGUMENTS_VERSION = 1
MAX_GDB_ARGUMENTS_PAYLOAD = 1024 * 1024


class GDBLaunchError(RuntimeError):
    def __init__(self, returncode: int, command: Sequence[str]):
        self.returncode = returncode
        self.command = tuple(command)
        super().__init__(
            f"GDB validation process exited with status {returncode}: "
            f"{list(command)!r}."
        )


@dataclass(frozen=True, slots=True)
class GDBLaunch:
    command: tuple[str, ...]
    environment: Mapping[str, str]


def make_argparser() -> argparse.ArgumentParser:
    """Build the parser shared with the script loaded inside GDB."""
    parser = argparse.ArgumentParser()
    parser.description = """Use Focaccia to test QEMU.

Uses either QEMU's GDB remote interface or the project plugin interface to
observe guest state and validate it against a symbolic native trace.
"""
    parser.add_argument(
        "--symb-trace",
        required=True,
        help="A pre-computed symbolic transformation trace.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        default=False,
        action="store_true",
        help="Do not print a verification result.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Write recorded emulator states to this file.",
    )
    parser.add_argument(
        "--error-level",
        default="warning",
        choices=list(verbosity),
    )
    parser.add_argument(
        "--executable",
        default=None,
        help="Guest executable, overriding GDB auto-detection.",
    )
    parser.add_argument(
        "--use-socket",
        type=str,
        nargs="?",
        const="/tmp/focaccia.sock",
        help="Use the QEMU plugin at this Unix socket instead of GDB.",
    )
    parser.add_argument(
        "--guest-arch",
        type=str,
        choices=supported_architectures.keys(),
        help="Emulated guest architecture (required for the plugin backend).",
    )
    parser.add_argument(
        "--remote",
        type=str,
        help="QEMU GDB server hostname:port.",
    )
    parser.add_argument(
        "--gdb",
        type=str,
        default="gdb",
        help="GDB binary to invoke.",
    )
    parser.add_argument(
        "--deterministic-log",
        default=None,
        help="Directory containing an RR deterministic log.",
    )
    parser.add_argument(
        "--trace-type",
        default="json",
        choices=["msgpack", "json"],
        help="Input symbolic trace format.",
    )
    parser.add_argument(
        "--report",
        help="Write a versioned JSON validation and replay-coverage report.",
    )
    parser.add_argument(
        "--run-manifest",
        help="Verify this content-bound RR/QEMU run manifest before validation.",
    )
    parser.add_argument(
        "--run-input",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="Bind a named input file required by --run-manifest (repeatable).",
    )
    return parser


def validate_backend_options(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
) -> None:
    if args.use_socket is not None:
        if args.remote is not None:
            parser.error("--remote and --use-socket select different backends")
        if args.guest_arch is None:
            parser.error("--guest-arch is required with --use-socket")
        if args.report is not None or args.run_manifest is not None or args.run_input:
            parser.error(
                "--report and run-manifest verification currently require the GDB backend"
            )
    elif args.remote is None:
        parser.error("--remote is required unless --use-socket is specified")
    if args.run_manifest is not None:
        if args.deterministic_log is None:
            parser.error("--run-manifest requires --deterministic-log")
        if args.executable is None:
            parser.error("--run-manifest requires --executable")
    elif args.run_input:
        parser.error("--run-input requires --run-manifest")


def make_gdb_trace_environment(executable: str | None) -> TraceEnvironment:
    return TraceEnvironment(
        executable,
        (),
        (),
        binary_hash=None,
    )


def make_plugin_trace_environment(guest_arch: str) -> TraceEnvironment:
    arch = supported_architectures[guest_arch]
    return TraceEnvironment(
        None,
        (),
        (),
        binary_hash=None,
        architecture=arch.key,
    )


def encode_gdb_arguments(arguments: Sequence[str]) -> str:
    payload = json.dumps(
        {
            "version": GDB_ARGUMENTS_VERSION,
            "arguments": list(arguments),
        },
        ensure_ascii=True,
        separators=(",", ":"),
    )
    if len(payload.encode("utf-8")) > MAX_GDB_ARGUMENTS_PAYLOAD:
        raise ValueError("GDB argument payload exceeds the configured limit.")
    return payload


def decode_gdb_arguments(environment: Mapping[str, str]) -> list[str] | None:
    payload = environment.get(GDB_ARGUMENTS_ENV)
    if payload is None:
        return None
    if len(payload.encode("utf-8")) > MAX_GDB_ARGUMENTS_PAYLOAD:
        raise ValueError("GDB argument payload exceeds the configured limit.")
    try:
        document = json.loads(payload)
    except json.JSONDecodeError as error:
        raise ValueError("Malformed GDB argument payload.") from error
    if not isinstance(document, dict) or document.get("version") != GDB_ARGUMENTS_VERSION:
        raise ValueError("Unsupported GDB argument payload version.")
    arguments = document.get("arguments")
    if not isinstance(arguments, list) or not all(
        isinstance(argument, str) for argument in arguments
    ):
        raise ValueError("GDB argument payload must contain a string list.")
    return arguments


def _default_python_paths() -> list[str]:
    package_root = str(Path(focaccia.__file__).resolve().parent.parent)
    paths = sysconfig.get_paths()
    candidates = [package_root, paths.get("purelib"), paths.get("platlib")]
    return [path for path in candidates if path and os.path.isdir(path)]


def _merge_pythonpath(
    selected: Sequence[str],
    existing: str | None,
) -> str:
    entries = list(selected)
    if existing:
        entries.extend(existing.split(os.pathsep))
    unique: list[str] = []
    for entry in entries:
        if entry and entry not in unique:
            unique.append(entry)
    return os.pathsep.join(unique)


def build_gdb_launch(
    args: argparse.Namespace,
    forwarded_arguments: Sequence[str],
    *,
    environment: Mapping[str, str] | None = None,
    qemu_tool_path: str | None = None,
    python_paths: Sequence[str] | None = None,
) -> GDBLaunch:
    """Build a shell-free GDB launch without mutating caller arguments."""
    if args.remote is None or args.use_socket is not None:
        raise ValueError("A GDB launch requires the remote backend.")
    child_environment = dict(os.environ if environment is None else environment)
    child_environment[GDB_ARGUMENTS_ENV] = encode_gdb_arguments(
        tuple(forwarded_arguments)
    )
    selected_paths = (
        list(python_paths) if python_paths is not None else _default_python_paths()
    )
    child_environment["PYTHONPATH"] = _merge_pythonpath(
        selected_paths,
        child_environment.get("PYTHONPATH"),
    )

    if qemu_tool_path is None:
        script_dir = Path(focaccia.qemu.__file__).resolve().parent
        qemu_tool_path = str(script_dir / "_qemu_tool.py")
    command = (
        args.gdb,
        "-nx",
        "--batch",
        "-x",
        qemu_tool_path,
    )
    return GDBLaunch(command, child_environment)


def execute_gdb_launch(
    launch: GDBLaunch,
    *,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> None:
    completed = runner(
        list(launch.command),
        env=dict(launch.environment),
        check=False,
    )
    if completed.returncode != 0:
        raise GDBLaunchError(completed.returncode, launch.command)


def main() -> None:
    parser = make_argparser()
    args = parser.parse_args()
    validate_backend_options(parser, args)

    if args.use_socket is not None:
        logging_level = getattr(logging, args.error_level.upper(), logging.INFO)
        logging.basicConfig(level=logging_level, force=True)
        trace_env = make_plugin_trace_environment(args.guest_arch)
        start_validation_server(
            args.symb_trace,
            args.output,
            args.use_socket,
            args.guest_arch,
            trace_env,
            verbosity[args.error_level],
            args.quiet,
            args.trace_type,
        )
        return

    forwarded_arguments = list(sys.argv[1:])
    launch = build_gdb_launch(args, forwarded_arguments)
    execute_gdb_launch(launch)


if __name__ == "__main__":
    main()
