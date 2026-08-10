import json

import pytest

from focaccia.native.profiling import TraceProfiler, write_capture_profile
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
        },
    }
    assert not (destination.parent / ".profile.json.tmp").exists()


def test_profile_snapshot_rejects_active_measurement():
    profiler = TraceProfiler()
    profiler.start("concrete")

    with pytest.raises(RuntimeError, match="active profile components"):
        profiler.snapshot()
