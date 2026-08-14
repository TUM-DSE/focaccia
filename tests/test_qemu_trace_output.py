from types import SimpleNamespace

import pytest

from focaccia.arch import supported_architectures
from focaccia.compare import ErrorTypes, ValidationReport
from focaccia.qemu import validation_server
from focaccia.tools.validate_qemu import (
    make_gdb_trace_environment,
    make_plugin_trace_environment,
)
from focaccia.trace import TraceEnvironment


def test_gdb_output_uses_none_for_unavailable_hash_and_arguments():
    env = make_gdb_trace_environment("/guest/program")

    assert isinstance(env, TraceEnvironment)
    assert env.binary_name == "/guest/program"
    assert env.binary_hash is None
    assert env.argv == ()
    assert env.envp == ()


def test_plugin_output_uses_typed_guest_trace_environment():
    env = make_plugin_trace_environment("aarch64b")

    assert isinstance(env, TraceEnvironment)
    assert env.binary_name is None
    assert env.binary_hash is None
    assert env.argv == ()
    assert env.envp == ()
    assert env.architecture == supported_architectures["aarch64b"].key


class FakePluginIterator:
    def __init__(self):
        self.finished = False
        self.aborted = False

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        pass

    def finish(self) -> None:
        self.finished = True

    def abort(self) -> None:
        self.aborted = True


def test_plugin_validation_writes_component_profile(
    tmp_path,
    monkeypatch,
):
    oracle = tmp_path / "oracle.json"
    oracle.write_text("{}")
    environment = make_plugin_trace_environment("aarch64l")
    symbolic = SimpleNamespace(env=environment)
    matched = SimpleNamespace(
        trace=None,
        diagnostics=(),
        pending_transform=None,
        complete=True,
    )
    iterator = FakePluginIterator()

    monkeypatch.setattr(
        validation_server.parser,
        "parse_transformations",
        lambda _file: symbolic,
    )
    monkeypatch.setattr(
        validation_server,
        "PluginStateIterator",
        lambda *_args, **_kwargs: iterator,
    )
    monkeypatch.setattr(
        validation_server,
        "collect_conc_trace",
        lambda *_args, **_kwargs: matched,
    )
    monkeypatch.setattr(
        validation_server,
        "compare_symbolic",
        lambda *_args, **_kwargs: ValidationReport(),
    )

    profile = tmp_path / "profile.json"
    validation_server.start_validation_server(
        str(oracle),
        None,
        str(tmp_path / "plugin.sock"),
        "aarch64l",
        environment,
        ErrorTypes.INFO,
        is_quiet=True,
        profile_path=str(profile),
    )

    import json

    document = json.loads(profile.read_text())
    assert document["schema"] == "focaccia-qemu-validation-profile-v1"
    assert document["status"] == "passed"
    assert set(document["timings"]) == {
        "executionSeconds",
        "tracingSeconds",
        "validationSeconds",
        "serializationSeconds",
        "totalSeconds",
        "unattributedSeconds",
    }
    assert all(value >= 0 for value in document["timings"].values())


def test_quiet_plugin_validation_still_writes_structured_report(
    tmp_path,
    monkeypatch,
):
    oracle = tmp_path / "oracle.json"
    oracle.write_text("{}")
    environment = make_plugin_trace_environment("aarch64l")
    symbolic = SimpleNamespace(env=environment)
    matched = SimpleNamespace(
        trace=None,
        diagnostics=(),
        pending_transform=None,
        complete=True,
    )
    comparison = ValidationReport()
    iterator = FakePluginIterator()
    writes = []

    monkeypatch.setattr(
        validation_server.parser,
        "parse_transformations",
        lambda _file: symbolic,
    )
    monkeypatch.setattr(
        validation_server,
        "PluginStateIterator",
        lambda *_args, **_kwargs: iterator,
    )
    monkeypatch.setattr(
        validation_server,
        "collect_conc_trace",
        lambda *_args, **_kwargs: matched,
    )
    monkeypatch.setattr(
        validation_server,
        "compare_symbolic",
        lambda *_args, **_kwargs: comparison,
    )
    monkeypatch.setattr(
        validation_server,
        "write_validation_report",
        lambda *args: writes.append(args),
    )
    monkeypatch.setattr(
        validation_server,
        "print_result",
        lambda *_args, **_kwargs: pytest.fail("quiet mode rendered human output"),
    )

    result = validation_server.start_validation_server(
        str(oracle),
        None,
        str(tmp_path / "plugin.sock"),
        "aarch64l",
        environment,
        ErrorTypes.INFO,
        is_quiet=True,
        report_path=str(tmp_path / "validation.json"),
    )

    assert result is matched
    assert writes == [
        (
            str(tmp_path / "validation.json"),
            comparison,
            None,
            matched,
        )
    ]
    assert iterator.finished
    assert not iterator.aborted


def test_plugin_validation_rejects_incomplete_trace_before_finish(
    tmp_path,
    monkeypatch,
):
    oracle = tmp_path / "oracle.json"
    oracle.write_text("{}")
    environment = make_plugin_trace_environment("aarch64l")
    symbolic = SimpleNamespace(env=environment)
    matched = SimpleNamespace(
        trace=None,
        diagnostics=(),
        pending_transform=None,
        complete=False,
    )
    iterator = FakePluginIterator()

    monkeypatch.setattr(
        validation_server.parser,
        "parse_transformations",
        lambda _file: symbolic,
    )
    monkeypatch.setattr(
        validation_server,
        "PluginStateIterator",
        lambda *_args, **_kwargs: iterator,
    )
    monkeypatch.setattr(
        validation_server,
        "collect_conc_trace",
        lambda *_args, **_kwargs: matched,
    )
    monkeypatch.setattr(
        validation_server,
        "compare_symbolic",
        lambda *_args, **_kwargs: ValidationReport(),
    )

    with pytest.raises(RuntimeError, match="complete transition trace"):
        validation_server.start_validation_server(
            str(oracle),
            None,
            str(tmp_path / "plugin.sock"),
            "aarch64l",
            environment,
            ErrorTypes.INFO,
        )

    assert iterator.aborted
    assert not iterator.finished


def test_plugin_validation_aborts_peer_on_collection_failure(
    tmp_path,
    monkeypatch,
):
    oracle = tmp_path / "oracle.json"
    oracle.write_text("{}")
    environment = make_plugin_trace_environment("aarch64l")
    symbolic = SimpleNamespace(env=environment)
    iterator = FakePluginIterator()

    monkeypatch.setattr(
        validation_server.parser,
        "parse_transformations",
        lambda _file: symbolic,
    )
    monkeypatch.setattr(
        validation_server,
        "PluginStateIterator",
        lambda *_args, **_kwargs: iterator,
    )
    monkeypatch.setattr(
        validation_server,
        "collect_conc_trace",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("collection failed")),
    )

    with pytest.raises(RuntimeError, match="collection failed"):
        validation_server.start_validation_server(
            str(oracle),
            None,
            str(tmp_path / "plugin.sock"),
            "aarch64l",
            environment,
            ErrorTypes.INFO,
        )

    assert iterator.aborted
    assert not iterator.finished
