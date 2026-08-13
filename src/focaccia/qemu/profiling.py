from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


QEMU_PROFILE_SCHEMA = "focaccia-qemu-validation-profile-v1"
ProfileComponent = Literal[
    "execution",
    "tracing",
    "validation",
    "serialization",
]
_PROFILE_COMPONENTS: tuple[ProfileComponent, ...] = (
    "execution",
    "tracing",
    "validation",
    "serialization",
)
_PROFILE_FIELDS = {
    "execution": "executionSeconds",
    "tracing": "tracingSeconds",
    "validation": "validationSeconds",
    "serialization": "serializationSeconds",
}


@dataclass(frozen=True, slots=True)
class QEMUValidationProfile:
    total_seconds: float
    component_seconds: dict[ProfileComponent, float]

    def document(self) -> dict[str, object]:
        timings = {
            _PROFILE_FIELDS[component]: self.component_seconds[component]
            for component in _PROFILE_COMPONENTS
        }
        timings["totalSeconds"] = self.total_seconds
        timings["unattributedSeconds"] = max(
            0.0,
            self.total_seconds - sum(self.component_seconds.values()),
        )
        return {
            "schema": QEMU_PROFILE_SCHEMA,
            "status": "passed",
            "timings": timings,
        }


class QEMUValidationProfiler:
    """Opt-in exclusive wall-clock attribution for QEMU validation."""

    def __init__(self, clock: Callable[[], float] = time.perf_counter):
        self._clock = clock
        self._seconds = {component: 0.0 for component in _PROFILE_COMPONENTS}
        self._stack: list[ProfileComponent] = []
        self._last = self._clock()
        self._total_started: float | None = None
        self._total_seconds: float | None = None

    def start_total(self) -> None:
        if self._total_started is not None or self._total_seconds is not None:
            raise RuntimeError("QEMU validation total timing was already started.")
        self._total_started = self._clock()
        self._last = self._total_started

    def _attribute(self, now: float) -> None:
        elapsed = now - self._last
        if elapsed < 0:
            raise RuntimeError("The QEMU profiling clock moved backwards.")
        if self._stack:
            self._seconds[self._stack[-1]] += elapsed
        self._last = now

    @contextmanager
    def measure(self, component: ProfileComponent) -> Iterator[None]:
        if self._total_started is None or self._total_seconds is not None:
            raise RuntimeError("QEMU validation profiling is not active.")
        now = self._clock()
        self._attribute(now)
        self._stack.append(component)
        try:
            yield
        finally:
            now = self._clock()
            self._attribute(now)
            active = self._stack.pop()
            if active != component:
                raise RuntimeError(
                    f"QEMU profile component {component!r} finished out of order."
                )
            self._last = now

    def finish_total(self) -> None:
        if self._total_started is None or self._total_seconds is not None:
            raise RuntimeError("QEMU validation total timing is not active.")
        if self._stack:
            raise RuntimeError(
                f"Cannot finish QEMU timing with active components: {self._stack}."
            )
        now = self._clock()
        self._attribute(now)
        self._total_seconds = now - self._total_started

    def snapshot(self) -> QEMUValidationProfile:
        if self._total_seconds is None or self._stack:
            raise RuntimeError("QEMU validation profiling is incomplete.")
        return QEMUValidationProfile(
            self._total_seconds,
            dict(self._seconds),
        )


def write_qemu_validation_profile(
    path: str | Path,
    profile: QEMUValidationProfile,
) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.write_text(
        json.dumps(profile.document(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)
