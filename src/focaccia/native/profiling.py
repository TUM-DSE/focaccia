from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

ProfileComponent = Literal["concrete", "symbolic", "validation"]
_PROFILE_COMPONENTS: tuple[ProfileComponent, ...] = (
    "concrete",
    "symbolic",
    "validation",
)


@dataclass(frozen=True, slots=True)
class CaptureProfile:
    concrete_seconds: float
    symbolic_seconds: float
    validation_seconds: float

    def document(self) -> dict[str, object]:
        return {
            "status": "passed",
            "timings": {
                "concreteSeconds": self.concrete_seconds,
                "symbolicSeconds": self.symbolic_seconds,
                "validationSeconds": self.validation_seconds,
            },
        }


class TraceProfiler:
    """Opt-in component timer for evaluation instrumentation."""

    def __init__(self, clock: Callable[[], float] = time.perf_counter):
        self._clock = clock
        self._seconds = {component: 0.0 for component in _PROFILE_COMPONENTS}
        self._depth = {component: 0 for component in _PROFILE_COMPONENTS}

    def start(self, component: ProfileComponent) -> float | None:
        depth = self._depth[component]
        self._depth[component] = depth + 1
        return self._clock() if depth == 0 else None

    def finish(self, component: ProfileComponent, started: float | None) -> None:
        depth = self._depth[component]
        if depth <= 0:
            raise RuntimeError(f"Profile component {component!r} was not started.")
        self._depth[component] = depth - 1
        if started is not None:
            if depth != 1:
                raise RuntimeError(
                    f"Profile component {component!r} finished out of order."
                )
            elapsed = self._clock() - started
            if elapsed < 0:
                raise RuntimeError("The profiling clock moved backwards.")
            self._seconds[component] += elapsed

    def snapshot(self) -> CaptureProfile:
        active = [
            component
            for component, depth in self._depth.items()
            if depth != 0
        ]
        if active:
            raise RuntimeError(f"Cannot snapshot active profile components: {active}.")
        return CaptureProfile(
            concrete_seconds=self._seconds["concrete"],
            symbolic_seconds=self._seconds["symbolic"],
            validation_seconds=self._seconds["validation"],
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
