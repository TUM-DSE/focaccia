"""Handling of non-deterministic behaviour in QEMU."""

from focaccia.tools.qemu.x86 import emulated_system_calls

emulated_system_calls = {
    'x86_64': emulated_system_calls,
    'aarch64': { },
    'aarch64l': { },
    'aarch64b': { }
}
"""A dictionary containing all supported emulated system calls for a given architecture"""

