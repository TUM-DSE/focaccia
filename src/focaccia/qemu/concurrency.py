"""Fail-closed boundary for unsupported concurrent emulator replay."""

from __future__ import annotations


class UnsupportedConcurrencyError(RuntimeError):
    """Concurrent validation was observed outside the supported model."""


def require_single_inferior(thread_count: int) -> None:
    """Reject a GDB inferior that exposes more than one live thread."""
    if thread_count < 0:
        raise ValueError("A thread count cannot be negative.")
    if thread_count > 1:
        raise UnsupportedConcurrencyError(
            f"QEMU exposes {thread_count} live threads; concurrent replay is "
            "unsupported."
        )


def require_event_thread(
    expected_tid: int,
    observed_tid: int,
    *,
    context: str,
) -> None:
    """Reject a deterministic event that changes the synchronized thread."""
    if observed_tid != expected_tid:
        raise UnsupportedConcurrencyError(
            f"{context} changes deterministic thread ID from {hex(expected_tid)} "
            f"to {hex(observed_tid)}; concurrent replay is unsupported."
        )


def reject_thread_creating_effect(effect_name: str) -> None:
    """Reject clone/fork-like effects before executing them in the emulator."""
    raise UnsupportedConcurrencyError(
        f"System call {effect_name} creates another task; concurrent replay is "
        "unsupported."
    )
