"""Handle system call replay on x86 platforms."""

from focaccia.tools.qemu.syscalls import SyscallInfo

emulated_system_calls = {
    34:   SyscallInfo('pause', []),
    39:   SyscallInfo('getpid', []),
    102:  SyscallInfo('getuid', []),
    318:  SyscallInfo('getrandom', patchup_address_registers=['rdi'])
}

