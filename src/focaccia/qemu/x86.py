from focaccia.qemu.syscall import SyscallInfo

# Incomplete, only the most common ones
emulated_system_calls = {
    34:  SyscallInfo('pause', []),
    39:  SyscallInfo('getpid', []),
    102: SyscallInfo('getuid', []),
    318: SyscallInfo('getrandom', patchup_address_registers=['rdi'])
}

passthrough_system_calls = {
    56:  SyscallInfo('clone', patchup_address_registers=['rdx', 'r10'], creates_thread=True),
}

