"""Deterministic accounting regressions; no native process or debugger needed."""

from types import SimpleNamespace
from typing import Any, cast

import pytest

from focaccia.native.profiling import CaptureProfile, TraceProfiler
from focaccia.native.tracer import SymbolicTracer
from focaccia.tools.capture_transforms import _capture_and_serialize


class Clock:
    now = 0.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def test_nested_components_partition_wall_without_assigning_residual():
    clock = Clock()
    profiler = TraceProfiler(clock)
    with profiler.measure("trace"):
        clock.advance(1)
        with profiler.measure("symbolic"):
            clock.advance(1)
            with profiler.measure("concrete"):
                clock.advance(2)
                with profiler.measure("validation"):
                    clock.advance(3)
                    with profiler.measure("symbolic"):
                        clock.advance(4)
            clock.advance(1)
        clock.advance(2)
    with profiler.measure("serialization"):
        clock.advance(7)
    profile = profiler.snapshot()
    assert profile.symbolic_seconds == 6
    assert profile.concrete_seconds == 2
    assert profile.validation_seconds == 3
    assert profile.trace_unassigned_seconds == 3
    assert profile.trace_seconds == 14
    assert profile.serialization_seconds == 7
    assert sum((profile.symbolic_seconds, profile.concrete_seconds,
                profile.validation_seconds, profile.trace_unassigned_seconds)) == profile.trace_seconds
    timings = profile.document()["timings"]
    assert isinstance(timings, dict)
    assert len(timings) == 5


def test_original_four_second_overlap_regression():
    clock = Clock()
    profiler = TraceProfiler(clock)
    with profiler.measure("trace"), profiler.measure("symbolic"):
        clock.advance(1)
        with profiler.measure("concrete"):
            clock.advance(2)
        clock.advance(1)
    profile = profiler.snapshot()
    assert profile.symbolic_seconds == 2
    assert profile.concrete_seconds == 2
    assert profile.trace_seconds == 4


@pytest.mark.parametrize("fails", [False, True])
def test_prediction_is_validation_including_exception_cleanup(fails):
    clock = Clock()
    profiler = TraceProfiler(clock)
    tracer = object.__new__(SymbolicTracer)
    tracer.profiler = profiler
    tracer.target = cast(Any, object())

    class Transform:
        def eval_validation_register_transforms(self, target):
            clock.advance(2)
            if fails:
                raise ValueError("prediction failed")
            return {"RAX": 1}

        def eval_memory_transforms(self, target):
            clock.advance(3)
            return {}

    with profiler.measure("trace"):
        if fails:
            with pytest.raises(ValueError, match="prediction failed"):
                tracer.predict_next_state(cast(Any, "instruction"), cast(Any, Transform()))
        else:
            assert tracer.predict_next_state(cast(Any, "instruction"), cast(Any, Transform())) == ({"RAX": 1}, {})
    profile = profiler.snapshot()
    assert profile.validation_seconds == (2 if fails else 5)
    assert profile.trace_seconds == profile.validation_seconds
    assert profile.trace_unassigned_seconds == 0


def test_trace_failure_unwinds_manual_symbolic_span_without_masking_cause(monkeypatch):
    clock = Clock()
    profiler = TraceProfiler(clock)
    tracer = object.__new__(SymbolicTracer)
    tracer.profiler = profiler

    def failed_trace(time_limit):
        profiler.start("symbolic")
        clock.advance(1)
        with profiler.measure("concrete"):
            clock.advance(2)
            raise ValueError("decode failed")

    monkeypatch.setattr(tracer, "_trace", failed_trace)
    with pytest.raises(ValueError, match="decode failed"):
        _capture_and_serialize(SimpleNamespace(insn_time_limit=None), tracer, profiler)
    profile = profiler.snapshot()
    assert profile.symbolic_seconds == 1
    assert profile.concrete_seconds == 2
    assert profile.trace_seconds == 3


def test_disabled_tracer_does_not_read_clock(monkeypatch):
    tracer = object.__new__(SymbolicTracer)
    tracer.profiler = None
    monkeypatch.setattr(tracer, "_trace", lambda time_limit: time_limit)
    assert tracer.trace(7) == 7
    assert tracer._profile_start("symbolic") is None
    tracer._profile_finish("symbolic", None)


def test_out_of_order_finish_does_not_corrupt_stack():
    clock = Clock()
    profiler = TraceProfiler(clock)
    outer = profiler.start("symbolic")
    inner = profiler.start("concrete")
    with pytest.raises(RuntimeError, match="out of order"):
        profiler.finish("symbolic", outer)
    clock.advance(1)
    profiler.finish("concrete", inner)
    profiler.finish("symbolic", outer)
    assert profiler.snapshot().concrete_seconds == 1
    with pytest.raises(RuntimeError, match="not started"):
        profiler.finish("symbolic", outer)


def test_legacy_profiles_are_not_relabelled_exclusive():
    profile = CaptureProfile(2, 4, 0, 4, 7)
    assert "accounting" not in profile.document()


@pytest.mark.parametrize("bad", [-1, float("nan"), float("inf")])
def test_invalid_clock_reading_rejected(bad):
    clock = Clock()
    profiler = TraceProfiler(clock)
    started = profiler.start("symbolic")
    clock.now = bad
    with pytest.raises(RuntimeError, match="clock"):
        profiler.finish("symbolic", started)
    clock.now = 1
    profiler.finish("symbolic", started)
    assert profiler.snapshot().symbolic_seconds == 1
