from __future__ import annotations

import json
import math
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

ProfileComponent = Literal[
    "concrete",
    "symbolic",
    "validation",
    "trace",
    "serialization",
]
_PROFILE_COMPONENTS: tuple[ProfileComponent, ...] = (
    "concrete",
    "symbolic",
    "validation",
    "trace",
    "serialization",
)
_PHASES = frozenset(("concrete", "symbolic", "validation"))


@dataclass(frozen=True, slots=True)
class CaptureProfile:
    concrete_seconds: float
    symbolic_seconds: float
    validation_seconds: float
    trace_seconds: float
    serialization_seconds: float
    # Absent on manually constructed/legacy measurements: never relabel those.
    trace_unassigned_seconds: float | None = None

    def document(self) -> dict[str, object]:
        document: dict[str, object] = {
            "status": "passed",
            "timings": {
                "concreteSeconds": self.concrete_seconds,
                "symbolicSeconds": self.symbolic_seconds,
                "validationSeconds": self.validation_seconds,
                "traceSeconds": self.trace_seconds,
                "serializationSeconds": self.serialization_seconds,
            },
        }
        if self.trace_unassigned_seconds is not None:
            document["accounting"] = {
                "method": "exclusive-components-v1",
                "traceUnassignedSeconds": self.trace_unassigned_seconds,
                "trace": "inclusive tracer.trace wall time; excludes target/log setup and persistence",
                "serialization": "separate persistence wall time",
                "concrete": "debugger execution; excludes nested symbolic/validation work",
                "symbolic": "trace construction, decode and semantics; excludes nested components",
                "validation": "prediction and comparison; excludes nested concrete execution",
            }
        return document


class TraceProfiler:
    """Opt-in, single-threaded wall timer with exclusive innermost phases.

    Trace and serialization are inclusive wall envelopes, not additive phases.
    Unassigned trace time is measured directly, never donated to a component.
    start/finish must be balanced in LIFO order, including same-component nesting.
    """

    def __init__(self, clock: Callable[[], float] = time.perf_counter):
        self._clock = clock
        self._seconds = {component: 0.0 for component in _PROFILE_COMPONENTS}
        self._stack: list[tuple[ProfileComponent, float]] = []
        self._last: float | None = None
        self._unassigned = 0.0

    def _advance(self) -> float:
        now = self._clock()
        if not math.isfinite(now) or (self._last is not None and now < self._last):
            raise RuntimeError("The profiling clock moved backwards or is non-finite.")
        if self._last is not None:
            elapsed = now - self._last
            active = {component for component, _ in self._stack}
            for wall in ("trace", "serialization"):
                if wall in active:
                    self._seconds[wall] += elapsed
            phase = next((c for c, _ in reversed(self._stack) if c in _PHASES), None)
            if phase is not None:
                self._seconds[phase] += elapsed
            elif "trace" in active:
                self._unassigned += elapsed
        self._last = now
        return now

    def start(self, component: ProfileComponent) -> float:
        if component not in self._seconds:
            raise ValueError(f"Unknown profile component: {component!r}.")
        started = self._advance()
        self._stack.append((component, started))
        return started

    def finish(self, component: ProfileComponent, started: float | None) -> None:
        if not self._stack:
            raise RuntimeError(f"Profile component {component!r} was not started.")
        if self._stack[-1] != (component, started):
            raise RuntimeError(f"Profile component {component!r} finished out of order.")
        self._advance()
        self._stack.pop()

    @contextmanager
    def scope(self) -> Iterator[None]:
        """Unwind manually managed spans on failure without hiding the cause."""
        depth = len(self._stack)
        try:
            yield
        except BaseException:
            try:
                self._advance()
            finally:
                del self._stack[depth:]
            raise
        if len(self._stack) != depth:
            raise RuntimeError("Unbalanced profile scope.")

    @contextmanager
    def measure(self, component: ProfileComponent) -> Iterator[None]:
        started = self.start(component)
        try:
            with self.scope():
                yield
        finally:
            self.finish(component, started)

    def snapshot(self) -> CaptureProfile:
        if self._stack:
            raise RuntimeError(f"Cannot snapshot active profile components: {self._stack}.")
        return CaptureProfile(
            concrete_seconds=self._seconds["concrete"],
            symbolic_seconds=self._seconds["symbolic"],
            validation_seconds=self._seconds["validation"],
            trace_seconds=self._seconds["trace"],
            serialization_seconds=self._seconds["serialization"],
            trace_unassigned_seconds=self._unassigned,
        )


def write_capture_profile(path: str | Path, profile: CaptureProfile) -> None:
    """Atomically write a successful capture profile."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.write_text(
        json.dumps(profile.document(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)
