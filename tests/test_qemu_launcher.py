import os
from types import SimpleNamespace
from typing import Any, cast

import pytest

from focaccia.tools.validate_qemu import (
    GDB_ARGUMENTS_ENV,
    GDBLaunchError,
    build_gdb_launch,
    decode_gdb_arguments,
    execute_gdb_launch,
    make_argparser,
    validate_backend_options,
)


def parsed(*arguments: str):
    return make_argparser().parse_args(["--symb-trace", "/tmp/trace", *arguments])


def test_unmatched_skipping_is_explicitly_opt_in():
    default = parsed("--remote", "localhost:1234")
    enabled = parsed("--remote", "localhost:1234", "--skip-unmatched")

    assert default.skip_unmatched is False
    assert enabled.skip_unmatched is True


def test_backend_selection_requires_remote_or_plugin_configuration():
    parser = make_argparser()
    args = parser.parse_args(["--symb-trace", "/tmp/trace"])

    with pytest.raises(SystemExit):
        validate_backend_options(parser, args)


def test_plugin_backend_requires_guest_arch_and_rejects_remote():
    parser = make_argparser()
    missing_arch = parser.parse_args(
        ["--symb-trace", "/tmp/trace", "--use-socket", "/tmp/plugin.sock"]
    )
    with pytest.raises(SystemExit):
        validate_backend_options(parser, missing_arch)

    ambiguous = parser.parse_args(
        [
            "--symb-trace",
            "/tmp/trace",
            "--use-socket",
            "/tmp/plugin.sock",
            "--guest-arch",
            "x86_64",
            "--remote",
            "localhost:1234",
        ]
    )
    with pytest.raises(SystemExit):
        validate_backend_options(parser, ambiguous)


def test_plugin_report_is_supported_without_enabling_replay_options():
    parser = make_argparser()
    plugin = parser.parse_args(
        [
            "--symb-trace",
            "/tmp/trace",
            "--use-socket",
            "/tmp/plugin",
            "--guest-arch",
            "aarch64l",
            "--report",
            "/tmp/report",
        ]
    )

    validate_backend_options(parser, plugin)


def test_run_manifest_requires_gdb_replay_artifacts():
    parser = make_argparser()
    missing = parser.parse_args(
        [
            "--symb-trace",
            "/tmp/trace",
            "--remote",
            "localhost:1234",
            "--run-manifest",
            "/tmp/manifest",
        ]
    )
    with pytest.raises(SystemExit):
        validate_backend_options(parser, missing)

    complete = parser.parse_args(
        [
            "--symb-trace",
            "/tmp/trace",
            "--remote",
            "localhost:1234",
            "--run-manifest",
            "/tmp/manifest",
            "--run-input",
            "input=/tmp/input",
            "--deterministic-log",
            "/tmp/rr",
            "--executable",
            "/tmp/program",
            "--report",
            "/tmp/report",
        ]
    )
    validate_backend_options(parser, complete)

    plugin = parser.parse_args(
        [
            "--symb-trace",
            "/tmp/trace",
            "--use-socket",
            "/tmp/plugin",
            "--guest-arch",
            "x86_64",
            "--run-manifest",
            "/tmp/manifest",
        ]
    )
    with pytest.raises(SystemExit):
        validate_backend_options(parser, plugin)


def test_gdb_argument_payload_round_trips_spaces_quotes_and_backslashes():
    arguments = [
        "--symb-trace",
        "/tmp/a trace.json",
        "--remote",
        "localhost:1234",
        "--executable",
        'C:\\guest path\\"quoted"',
    ]
    original = list(arguments)
    args = make_argparser().parse_args(arguments)
    launch = build_gdb_launch(
        args,
        arguments,
        environment={"PYTHONPATH": "/existing"},
        qemu_tool_path="/tmp/qemu tool.py",
        python_paths=["/one space", "/two"],
    )

    assert arguments == original
    assert decode_gdb_arguments(launch.environment) == arguments
    assert launch.command == (
        "gdb",
        "-nx",
        "--batch",
        "-x",
        "/tmp/qemu tool.py",
    )
    assert launch.environment["PYTHONPATH"].split(os.pathsep) == [
        "/one space",
        "/two",
        "/existing",
    ]
    assert GDB_ARGUMENTS_ENV not in " ".join(launch.command)


def test_gdb_launcher_propagates_subprocess_failure_without_shell_encoding():
    args = parsed("--remote", "localhost:1234", "--gdb", "/tmp/g db")
    launch = build_gdb_launch(
        args,
        ["--symb-trace", "/tmp/trace", "--remote", "localhost:1234"],
        environment={},
        qemu_tool_path="/tmp/tool.py",
        python_paths=["/tmp/site"],
    )
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=17)

    with pytest.raises(GDBLaunchError) as raised:
        execute_gdb_launch(launch, runner=cast(Any, runner))

    assert raised.value.returncode == 17
    assert calls == [
        (
            ["/tmp/g db", "-nx", "--batch", "-x", "/tmp/tool.py"],
            {
                "env": {
                    GDB_ARGUMENTS_ENV: launch.environment[GDB_ARGUMENTS_ENV],
                    "PYTHONPATH": "/tmp/site",
                },
                "check": False,
            },
        )
    ]
