"""Architecture dispatch for deterministic QEMU replay policy."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from focaccia.qemu.syscall import SyscallPolicy
from focaccia.qemu.x86 import SYSCALL_NUMBER_REGISTER, X86_64_SYSCALL_POLICIES


syscall_number_registers: Mapping[str, str] = MappingProxyType(
    {"x86_64": SYSCALL_NUMBER_REGISTER}
)

syscall_policies: Mapping[str, Mapping[int, SyscallPolicy]] = MappingProxyType(
    {
        "x86_64": X86_64_SYSCALL_POLICIES,
    }
)
