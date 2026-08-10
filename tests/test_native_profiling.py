import json
from types import SimpleNamespace

import pytest

from focaccia.native.profiling import TraceProfiler, write_capture_profile
from focaccia.tools import capture_transforms as capture_module
from focaccia.tools.capture_transforms import make_argparser


def test_profiling_is_disabled_by_default():
    args = make_argparser().parse_args(["/tmp/program"])

    assert args.profile_report is None


def test_profiler_accumulates_components_without_double_counting_nested_spans():
    readings = iter((10.0, 13.0, 20.0, 22.5, 30.0, 30.25))
    profiler = TraceProfiler(lambda: next(readings))

    concrete = profiler.start("concrete")
    nested = profiler.start("concrete")
    profiler.finish("concrete", nested)
    profiler.finish("concrete", concrete)
    symbolic = profiler.start("symbolic")
    profiler.finish("symbolic", symbolic)
    validation = profiler.start("validation")
    profiler.finish("validation", validation)

    profile = profiler.snapshot()
    assert profile.concrete_seconds == 3.0
    assert profile.symbolic_seconds == 2.5
    assert profile.validation_seconds == 0.25
    assert profile.trace_seconds == 0.0
    assert profile.serialization_seconds == 0.0


def test_capture_profile_separates_trace_from_serialization(monkeypatch):
    readings = iter((10.0, 14.0, 20.0, 26.0))
    profiler = TraceProfiler(lambda: next(readings))
    events: list[str] = []
    trace = object()

    class FakeTracer:
        def trace(self, *, time_limit):
            assert time_limit == 7
            events.append("trace")
            return trace

    def serialize(observed_trace, output, out_type):
        assert observed_trace is trace
        assert output == "oracle.trace"
        assert out_type == "msgpack"
        events.append("serialization")

    monkeypatch.setattr(capture_module.parser, "serialize_transformations", serialize)
    args = SimpleNamespace(
        insn_time_limit=7,
        output="oracle.trace",
        out_type="msgpack",
    )

    profile = capture_module._capture_and_serialize(args, FakeTracer(), profiler)

    assert profile is not None
    assert events == ["trace", "serialization"]
    assert profile.trace_seconds == 4.0
    assert profile.serialization_seconds == 6.0


def test_profile_report_is_plain_json_without_schema_version(tmp_path):
    readings = iter((1.0, 2.5))
    profiler = TraceProfiler(lambda: next(readings))
    started = profiler.start("symbolic")
    profiler.finish("symbolic", started)
    destination = tmp_path / "nested" / "profile.json"

    write_capture_profile(destination, profiler.snapshot())

    document = json.loads(destination.read_text())
    assert document == {
        "status": "passed",
        "timings": {
            "concreteSeconds": 0.0,
            "symbolicSeconds": 1.5,
            "validationSeconds": 0.0,
            "traceSeconds": 0.0,
            "serializationSeconds": 0.0,
        },
    }
    assert not (destination.parent / ".profile.json.tmp").exists()


def test_profile_snapshot_rejects_active_measurement():
    profiler = TraceProfiler()
    profiler.start("concrete")

    with pytest.raises(RuntimeError, match="active profile components"):
        profiler.snapshot()
