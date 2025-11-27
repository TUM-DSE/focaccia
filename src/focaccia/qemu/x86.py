import struct
from typing import Optional
from dataclasses import dataclass, field

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
    13: SyscallInfo('rt_sigaction', patchup_address_registers=['rdx'], sets_signal_restorer=True),
    14: SyscallInfo('rt_sigprocmask', patchup_address_registers=['rdx']),
    15: SyscallInfo('rt_sigreturn', return_from_signal=True),
    16: SyscallInfo('ioctl', patchup_address_registers=['rdx']),
    17: SyscallInfo('pread64', patchup_address_registers=['rsi']),
    18: SyscallInfo('pwrite64'),
    19: SyscallInfo('readv', patchup_address_registers=['rsi']),
    20: SyscallInfo('writev'),
    21: SyscallInfo('access'),
    22: SyscallInfo('pipe', patchup_address_registers=['rdi']),
    23: SyscallInfo('select', patchup_address_registers=['rsi', 'rdx', 'r10', 'r8']),
    24: SyscallInfo('sched_yield'),
    32: SyscallInfo('dup'),
    33: SyscallInfo('dup2'),
    34:  SyscallInfo('pause'),
    35:  SyscallInfo('nanosleep', patchup_address_registers=['rdi', 'rsi']),
    39:  SyscallInfo('getpid'),
    41:  SyscallInfo('socket'),
    42:  SyscallInfo('connect', patchup_address_registers=['rsi']),
    43:  SyscallInfo('accept', patchup_address_registers=['rsi', 'rdx']),
    44:  SyscallInfo('sendto'),
    45:  SyscallInfo('recvfrom', patchup_address_registers=['rsi']),
    46:  SyscallInfo('sendmsg'),
    47:  SyscallInfo('recvmsg', patchup_address_registers=['rsi']),
    49:  SyscallInfo('bind', patchup_address_registers=['rsi']),
    50:  SyscallInfo('listen'),
    51:  SyscallInfo('getsockname', patchup_address_registers=['rsi', 'rdx']),
    52:  SyscallInfo('getpeername', patchup_address_registers=['rsi', 'rdx']),
    53:  SyscallInfo('sockpair', patchup_address_registers=['r10']),
    54:  SyscallInfo('setsockopt'),
    55:  SyscallInfo('getsockpair', patchup_address_registers=['r10', 'r8']),
    62:  SyscallInfo('kill'),
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
    97:  SyscallInfo('getrlimit', patchup_address_registers=['rsi']),
    98:  SyscallInfo('getrusage', patchup_address_registers=['rsi']),
    102: SyscallInfo('getuid'),
    107: SyscallInfo('geteuid'),
    108: SyscallInfo('getegid'),
    109: SyscallInfo('setpgid'),
    110: SyscallInfo('getpgid'),
    111: SyscallInfo('getpgrp'),
    112: SyscallInfo('getsid'),
    113: SyscallInfo('setreuid'),
    114: SyscallInfo('setregid'),
    115: SyscallInfo('getgroups'),
    116: SyscallInfo('setgroups'),
    117: SyscallInfo('setresuid'),
    118: SyscallInfo('getresuid', patchup_address_registers=['rdi', 'rsi', 'rdx']),
    119: SyscallInfo('setresgid'),
    120: SyscallInfo('getresgid', patchup_address_registers=['rdi', 'rsi', 'rdx']),
    121: SyscallInfo('getpgid'),
    122: SyscallInfo('setfsuid'),
    123: SyscallInfo('setfsgid'),
    124: SyscallInfo('getsid'),
    127: SyscallInfo('rt_sigpending', patchup_address_registers=['rdi']),
    128: SyscallInfo('rt_sigtimedwait', patchup_address_registers=['rsi']),
    129: SyscallInfo('rt_sigqueueinfo', patchup_address_registers=['rdx']),
    130: SyscallInfo('rt_sigsuspend'),
    200: SyscallInfo('tkill'),
    202: SyscallInfo('futex', patchup_address_registers=['rdi', 'r8']), 
    213: SyscallInfo('epoll_create'),
    219: SyscallInfo('restart_syscall'),
    232: SyscallInfo('epoll_wait', patchup_address_registers=['rsi']),
    233: SyscallInfo('epoll_ctl', patchup_address_registers=['r10']),
    257: SyscallInfo('openat'),
    258: SyscallInfo('mkdirat'),
    259: SyscallInfo('mknodat'),
    260: SyscallInfo('fchownat'),
    261: SyscallInfo('futimesat', patchup_address_registers=['rdxi']),
    262: SyscallInfo('newfstatat', patchup_address_registers=['rsi']),
    263: SyscallInfo('unlinkat'),
    264: SyscallInfo('renameat'),
    265: SyscallInfo('linkat'),
    266: SyscallInfo('symlinkat'),
    267: SyscallInfo('readlinkat', patchup_address_registers=['rdx']),
    268: SyscallInfo('fchmodat'),
    269: SyscallInfo('faccessat'),
    270: SyscallInfo('pselect6', patchup_address_registers=['rsi', 'rdx', 'r10', 'r8', 'r9']),
    271: SyscallInfo('ppoll', patchup_address_registers=['rdi']),
    281: SyscallInfo('epoll_pwait', patchup_address_registers=['rsi', 'r8']),
    284: SyscallInfo('eventfd'),
    288: SyscallInfo('accept4', patchup_address_registers=['rsi', 'rdx']),
    290: SyscallInfo('eventfd2'),
    291: SyscallInfo('epoll_create1'),
    292: SyscallInfo('dup3'),
    293: SyscallInfo('pipe2', patchup_address_registers=['rdi']),
    297: SyscallInfo('rt_tgsigqueueinfo', patchup_address_registers=['r10']),
    302: SyscallInfo('prlimit64', patchup_address_registers=['r10']),
    303: SyscallInfo('name_to_handle_at', patchup_address_registers=['rdx', 'r10']),
    304: SyscallInfo('open_by_handle_at', patchup_address_registers=['rsi']),
    316: SyscallInfo('renameat2'),
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

@dataclass
class SigContext:
    """
    Represents struct sigcontext on Linux x86-64.
    You fill these like ctx.r8 = 123, ctx.rip = 0x400abc, etc.
    """

    # GPRs in kernel-defined order
    r8: int = 0
    r9: int = 0
    r10: int = 0
    r11: int = 0
    r12: int = 0
    r13: int = 0
    r14: int = 0
    r15: int = 0
    rdi: int = 0
    rsi: int = 0
    rbp: int = 0
    rbx: int = 0
    rdx: int = 0
    rax: int = 0
    rcx: int = 0
    rsp: int = 0  # OLD rsp before signal
    rip: int = 0  # OLD rip before signal

    eflags: int = 0
    cs: int = 0x33
    ss: int = 0x2b

    err: int = 0
    trapno: int = 0
    oldmask: int = 0
    cr2: int = 0
    fpstate: int = 0   # pointer (kernel uses this)

    # Reserved padding space
    reserved1: int = 0
    reserved2: int = 0
    reserved3: int = 0

    def to_bytes(self) -> bytes:
        """
        Pack exactly like struct sigcontext on x86-64.
        """
        fields = [
            self.r8, self.r9, self.r10, self.r11,
            self.r12, self.r13, self.r14, self.r15,
            self.rdi, self.rsi, self.rbp, self.rbx,
            self.rdx, self.rax, self.rcx, self.rsp,
            self.rip,
            self.eflags,
            self.cs, self.ss,
            self.err, self.trapno, self.oldmask, self.cr2,
            self.fpstate,
            self.reserved1, self.reserved2, self.reserved3,
        ]
        # All fields are 64-bit except CS/SS (16-bit)
        # But kernel packs everything on 8-byte boundaries anyway.
        return struct.pack("<" + "Q"*len(fields), *fields)


# ---------------------------------------------------------------------
# 2. Minimal siginfo_t abstraction (128 bytes on x86-64)
# ---------------------------------------------------------------------

@dataclass
class SigInfo:
    """
    Minimal representation. You can fill as needed.
    Layout here is fixed to 128 bytes.
    Only a few useful fields are exposed.
    """

    si_signo: int = 0
    si_errno: int = 0
    si_code: int = 0
    si_pid: int = 0
    si_uid: int = 0

    def to_bytes(self) -> bytes:
        # Linux siginfo is 128 bytes; real layout is complex.
        # We place the common initial fields and pad the rest.
        buf = bytearray(128)
        struct.pack_into("<iii", buf, 0, self.si_signo, self.si_errno, self.si_code)
        struct.pack_into("<II", buf, 16, self.si_pid, self.si_uid)
        return bytes(buf)


# ---------------------------------------------------------------------
# 3. ucontext_t wrapper (only what matters for signal return)
# ---------------------------------------------------------------------

@dataclass
class UContext:
    """
    Only the parts required for correct signal return.
    """
    sigmask: int = 0    # For simplicity; real sigset_t is 8*16 bytes
    mcontext: SigContext = field(default_factory=SigContext)

    UC_FLAGS: int = 1  # Usually UC_FP_XSTATE

    def to_bytes(self) -> bytes:
        """
        Real ucontext_t is large. Here we pack:
          - uc_flags (8 bytes)
          - uc_link  (8 bytes, NULL)
          - stack_t  (3 * 8 bytes)
          - sigmask  (128 bytes normally; we use 8 bytes for simplicity)
          - padding up to 0x2c0
          - mcontext (struct sigcontext)
        IMPORTANT: total size must be 0x2c0 on x86-64.
        """
        uc_buf = bytearray(0x2c0)

        # uc_flags + uc_link(NULL)
        struct.pack_into("<Q", uc_buf, 0, self.UC_FLAGS)
        struct.pack_into("<Q", uc_buf, 8, 0)

        # stack_t (ss_sp, ss_flags, ss_size)
        struct.pack_into("<QQQ", uc_buf, 16, 0, 0, 0)

        # sigmask (we store a minimal 8 bytes)
        struct.pack_into("<Q", uc_buf, 40, self.sigmask)

        # Now embed sigcontext at the end of ucontext
        mctx_bytes = self.mcontext.to_bytes()
        uc_buf[-len(mctx_bytes):] = mctx_bytes

        return bytes(uc_buf)


# ---------------------------------------------------------------------
# 4. Full rt_sigframe abstraction
# ---------------------------------------------------------------------

@dataclass
class SigFrame:
    sp_new: int                      # RSP after signal delivery
    pretcode: int                    # pointer to restorer trampoline
    uctx: UContext                   # full ucontext (incl. sigcontext)
    siginfo: SigInfo                 # siginfo_t
    tail_size: int = 0               # optional xstate padding

    PRETCODE_SIZE: int = 8
    UCONTEXT_SIZE: int = 0x2c0
    SIGINFO_SIZE: int = 128

    @property
    def uc_addr(self) -> int:
        return self.sp_new + self.PRETCODE_SIZE

    @property
    def siginfo_addr(self) -> int:
        return self.uc_addr + self.UCONTEXT_SIZE

    @property
    def tail_addr(self) -> int:
        return self.siginfo_addr + self.SIGINFO_SIZE

    @property
    def rdx_uc(self) -> int:
        """What to set in guest RDX."""
        return self.uc_addr

    @property
    def rsi_siginfo(self) -> int:
        """What to set in guest RSI."""
        return self.siginfo_addr

    def to_bytes(self) -> bytes:
        buf = bytearray(self.PRETCODE_SIZE + self.UCONTEXT_SIZE +
                        self.SIGINFO_SIZE + self.tail_size)

        # pretcode
        struct.pack_into("<Q", buf, 0, self.pretcode)

        # ucontext
        buf[self.PRETCODE_SIZE : self.PRETCODE_SIZE + self.UCONTEXT_SIZE] = \
            self.uctx.to_bytes()

        # siginfo
        si_off = self.PRETCODE_SIZE + self.UCONTEXT_SIZE
        buf[si_off : si_off + self.SIGINFO_SIZE] = self.siginfo.to_bytes()

        return bytes(buf)

