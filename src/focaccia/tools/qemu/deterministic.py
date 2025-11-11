"""Handling of non-deterministic system calls for QEMU."""

import focaccia.arch as arch

emulated_syscalls = {
    arch.x86: [34, 39, 102, 318]
}

