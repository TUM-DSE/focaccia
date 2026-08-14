from __future__ import annotations

import os
import sys
import shutil
import ctypes
import signal
from collections.abc import Callable
from os import PathLike
from functools import total_ordering
from hashlib import sha256
from typing import Protocol


@total_ordering
class ErrorSeverity:
    def __init__(self, num: int, name: str):
        """Construct an error severity.

        :param num:  A numerical value that orders the severity with respect
                     to other `ErrorSeverity` objects. Smaller values are less
                     severe.
        :param name: A descriptive name for the error severity, e.g. 'fatal'
                     or 'info'.
        """
        self._numeral = num
        self.name = name

    def __repr__(self) -> str:
        return f"[{self.name}]"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ErrorSeverity):
            return False
        return self._numeral == other._numeral

    def __lt__(self, other: ErrorSeverity) -> bool:
        return self._numeral < other._numeral

    def __hash__(self) -> int:
        return hash(self._numeral)


def float_bits_to_uint(v: float) -> int:
    """Bit-cast a float to a 32-bit integer."""
    return ctypes.c_uint32.from_buffer(ctypes.c_float(v)).value


def uint_bits_to_float(v: int) -> float:
    """Bit-cast a 32-bit integer to a float."""
    return ctypes.c_float.from_buffer(ctypes.c_uint32(v)).value


def double_bits_to_uint(v: float) -> int:
    """Bit-cast a double to a 64-bit integer."""
    return ctypes.c_uint64.from_buffer(ctypes.c_double(v)).value


def uint_bits_to_double(v: int) -> float:
    """Bit-cast a 64-bit integer to a double."""
    return ctypes.c_double.from_buffer(ctypes.c_uint64(v)).value


class HashAlgorithm(Protocol):
    def update(self, data: bytes) -> None: ...
    def hexdigest(self) -> str: ...


def file_hash(
    filename: str | PathLike[str],
    hash_factory: Callable[[], HashAlgorithm] = sha256,
    chunksize: int = 65536,
) -> str:
    """Calculate a file hash with a fresh algorithm instance per call."""
    if chunksize <= 0:
        raise ValueError("Hash chunk size must be positive.")

    algorithm = hash_factory()
    with open(filename, "rb") as file:
        while data := file.read(chunksize):
            algorithm.update(data)
    return algorithm.hexdigest()


def get_envp() -> list[str]:
    """Return current environment array.

    Merge dict-like `os.environ` struct to the traditional list-like
    environment array.
    """
    return [f"{k}={v}" for k, v in os.environ.items()]


def print_separator(separator: str = "-", stream=sys.stdout, count: int = 80):
    maxtermsize = count
    termsize = shutil.get_terminal_size((80, 20)).columns
    print(separator * min(termsize, maxtermsize), file=stream)


def _bounded_text(value: object, limit: int) -> str:
    """Render one value without allowing unbounded diagnostic allocation."""
    try:
        text = str(value)
    except (MemoryError, RecursionError, RuntimeError, ValueError) as error:
        return f"<rendering failed: {type(error).__name__}>"
    if len(text) <= limit:
        return text
    digest = sha256(text.encode(errors="replace")).hexdigest()
    return f"{text[:limit]}... <omitted {len(text) - limit} chars; sha256={digest}>"


def print_result(
    result,
    min_severity: ErrorSeverity,
    *,
    max_diagnostics: int = 200,
    max_entries: int = 200,
    max_rendered_chars: int = 16_384,
):
    """Print bounded comparison diagnostics suitable for embedded debuggers."""
    shown = 0
    suppressed = 0

    trace_diagnostics = tuple(getattr(result, "diagnostics", ()))
    for diagnostic in trace_diagnostics[:max_diagnostics]:
        print(
            f"[TRACE {diagnostic.level.upper()}] "
            f"{diagnostic.code}: {_bounded_text(diagnostic.message, max_rendered_chars)}"
        )
    if len(trace_diagnostics) > max_diagnostics:
        print(
            f"[TRACE SUMMARY] Omitted {len(trace_diagnostics) - max_diagnostics} "
            "additional diagnostics."
        )

    rendered_entries = 0
    omitted_entries = 0
    for res in result:
        # Filter errors by severity
        errs = [e for e in res["errors"] if e.severity >= min_severity]
        suppressed += len(res["errors"]) - len(errs)
        shown += len(errs)

        if errs and rendered_entries >= max_entries:
            omitted_entries += 1
            continue
        if errs:
            rendered_entries += 1
            pc = res["pc"]
            print_separator()
            print(f"For PC={hex(pc)}")
            print_separator()

        # Print all non-suppressed errors
        for n, err in enumerate(errs, start=1):
            print(f" {n:2}. {_bounded_text(err, max_rendered_chars)}")

        if errs:
            print()
            print(f"Expected transformation: {_bounded_text(res['ref'], max_rendered_chars)}")
            print(f"Actual difference:       {_bounded_text(res['txl'], max_rendered_chars)}")

    if omitted_entries:
        print(f"Omitted {omitted_entries} additional result entries.")

    print()
    print("#" * 60)
    print(f"Found {shown} state errors.")
    print(f"Found {len(trace_diagnostics)} trace diagnostics.")
    print(f"Suppressed {suppressed} low-priority errors (showing {min_severity} and higher).")
    print("#" * 60)
    print()


def to_int(value: str) -> int:
    return int(value, 0)


def to_num(value: str) -> int | float:
    try:
        return int(value, 0)
    except:
        return float(value)


class TimeoutError(Exception):
    pass


def timebound(timeout: int | float | None, func, *args, **kwargs):
    if timeout is None:
        return func(*args, **kwargs)

    def _handle_timeout(signum, frame):
        raise TimeoutError(f"Function exceeded {timeout} limit")

    old_handler = signal.signal(signal.SIGALRM, _handle_timeout)
    signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        return func(*args, **kwargs)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)
