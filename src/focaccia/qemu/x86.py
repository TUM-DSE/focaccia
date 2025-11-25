from focaccia.qemu.syscall import SyscallInfo

# Incomplete, only the most common ones
emulated_system_calls = {
    0: SyscallInfo('read', patchup_address_registers=['rsi']),
    1: SyscallInfo('write'),
    19: SyscallInfo('readv', patchup_address_registers=['rsi']),
    20: SyscallInfo('writev'),
    34:  SyscallInfo('pause', []),
    39:  SyscallInfo('getpid', []),
    102: SyscallInfo('getuid', []),
    318: SyscallInfo('getrandom', patchup_address_registers=['rdi'])
}

passthrough_system_calls = {
    56:   SyscallInfo('clone', patchup_address_registers=['rdx', 'r10'], creates_thread=True),
    57:   SyscallInfo('fork', creates_thread=True),
    58:   SyscallInfo('vfork', creates_thread=True),
    435:  SyscallInfo('clone3', patchup_address_registers=['rdi'], creates_thread=True),
}

vdso_system_calls = {
    96: SyscallInfo('gettimeofday', patchup_address_registers=['rdi', 'rsi']),
    201: SyscallInfo('time', patchup_address_registers=['rdi']),
    228: SyscallInfo('clock_gettime', patchup_address_registers=['rdi']),
    309: SyscallInfo('getcpu', patchup_address_registers=['rdi', 'rsi', 'rdx'])
}

