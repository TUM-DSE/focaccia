from __future__ import annotations

import os
import sys
import shutil
import ctypes
import signal
from functools import total_ordering
from hashlib import sha256

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
        return f'[{self.name}]'

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

def file_hash(filename: str, hash = sha256(), chunksize: int = 65536) -> str:
    """Calculate a file's hash.

    :param filename:  Name of the file to hash.
    :param hash:      The hash algorithm to use.
    :param chunksize: Optimization option. Size of contiguous chunks to read
                      from the file and feed into the hashing algorithm.
    :return: A hex digest.
    """
    with open(filename, 'rb') as file:
        while True:
            data = file.read(chunksize)
            if not data:
                break
            hash.update(data)
    return hash.hexdigest()

def get_envp() -> list[str]:
    """Return current environment array.

    Merge dict-like `os.environ` struct to the traditional list-like
    environment array.
    """
    return [f'{k}={v}' for k, v in os.environ.items()]

def print_separator(separator: str = '-', stream=sys.stdout, count: int = 80):
    maxtermsize = count
    termsize = shutil.get_terminal_size((80, 20)).columns
    print(separator * min(termsize, maxtermsize), file=stream)

def print_result(result, min_severity: ErrorSeverity):
    """Print a comparison result."""
    shown = 0
    suppressed = 0

    for res in result:
        # Filter errors by severity
        errs = [e for e in res['errors'] if e.severity >= min_severity]
        suppressed += len(res['errors']) - len(errs)
        shown += len(errs)

        if errs:
            pc = res['pc']
            print_separator()
            print(f'For PC={hex(pc)}')
            print_separator()

        # Print all non-suppressed errors
        for n, err in enumerate(errs, start=1):
            print(f' {n:2}. {err}')

        if errs:
            print()
            print(f'Expected transformation: {res["ref"]}')
            print(f'Actual difference:       {res["txl"]}')

    print()
    print('#' * 60)
    print(f'Found {shown} errors.')
    print(f'Suppressed {suppressed} low-priority errors'
          f' (showing {min_severity} and higher).')
    print('#' * 60)
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
        raise TimeoutError(f'Function exceeded {timeout} limit')
    
    old_handler = signal.signal(signal.SIGALRM, _handle_timeout)
    signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        return func(*args, **kwargs)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)

