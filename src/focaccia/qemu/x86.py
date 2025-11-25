from focaccia.qemu.syscall import SyscallInfo

# Incomplete, only the most common ones
emulated_system_calls = {
    0: SyscallInfo('read', patchup_address_registers=['rsi']),
    1: SyscallInfo('write'),
    2: SyscallInfo('open'),
    3: SyscallInfo('close'),
    4: SyscallInfo('stat', patchup_address_registers=['rsi']),
    5: SyscallInfo('fstat', patchup_address_registers=['rsi']),
    6: SyscallInfo('lstat', patchup_address_registers=['rsi']),
    8: SyscallInfo('lseek'),
    16: SyscallInfo('ioctl', patchup_address_registers=['rdx']),
    17: SyscallInfo('pread64', patchup_address_registers=['rsi']),
    18: SyscallInfo('pwrite64'),
    19: SyscallInfo('readv', patchup_address_registers=['rsi']),
    20: SyscallInfo('writev'),
    21: SyscallInfo('access'),
    24: SyscallInfo('sched_yield'),
    34:  SyscallInfo('pause'),
    39:  SyscallInfo('getpid'),
    72:  SyscallInfo('fcntl', patchup_address_registers=['rdx']),
    73:  SyscallInfo('flock'),
    74:  SyscallInfo('fsync'),
    75:  SyscallInfo('fdatasync'),
    76:  SyscallInfo('truncate'),
    77:  SyscallInfo('ftruncate'),
    78:  SyscallInfo('getdents', patchup_address_registers=['rsi']),
    79:  SyscallInfo('getcwd', patchup_address_registers=['rdi']),
    80:  SyscallInfo('chdir'),
    81:  SyscallInfo('fchdir'),
    82:  SyscallInfo('rename'),
    83:  SyscallInfo('mkdir'),
    84:  SyscallInfo('rmdir'),
    85:  SyscallInfo('creat'),
    86:  SyscallInfo('link'),
    87:  SyscallInfo('unlink'),
    88:  SyscallInfo('symlink'),
    89:  SyscallInfo('readlink', patchup_address_registers=['rsi']),
    90:  SyscallInfo('chmod'),
    91:  SyscallInfo('fchmod'),
    92:  SyscallInfo('chown'),
    93:  SyscallInfo('fchown'),
    94:  SyscallInfo('lchown'),
    95:  SyscallInfo('umask'),
    102: SyscallInfo('getuid'),
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

