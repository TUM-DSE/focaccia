"""x86-64 deterministic-replay policy and Linux signal ABI validation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from focaccia.arch.x86 import ArchX86
from focaccia.deterministic import SignalEvent
from focaccia.qemu.syscall import (
    DirectMemoryOutputs,
    DirectOutput,
    ExecutionGuard,
    FdSetExtent,
    FixedExtent,
    IovecResultOutputs,
    MaterializedMemoryWrite,
    NoMemoryOutputs,
    PointedU32Extent,
    ReconcileMode,
    RegisterExtent,
    ReplayEventError,
    ReplayStrategy,
    ResultExtent,
    SyscallPolicy,
    SyscallStateAction,
    validate_policy_table,
)


# x86-64 Linux system-call ABI registers.
SYSCALL_NUMBER_REGISTER = "rax"
SYSCALL_ARGUMENT_REGISTERS = ("rdi", "rsi", "rdx", "r10", "r8", "r9")
SYSCALL_RECORDED_RESULT_REGISTERS = ("rax", "rcx", "r11")


_NO_OUTPUTS = NoMemoryOutputs()
_OFFSET_EXTRAS = frozenset(("none", "writeOffset"))
_OPEN_EXTRAS = frozenset(("none", "openedFds"))
_SOCKET_EXTRAS = frozenset(("none", "socketAddrs"))


def _recorded(
    number: int,
    name: str,
    *,
    state_action: SyscallStateAction = SyscallStateAction.NONE,
    allowed_argument_values: tuple[tuple[str, tuple[int, ...]], ...] = (),
    allowed_extras: frozenset[str] = frozenset(("none",)),
) -> SyscallPolicy:
    return SyscallPolicy(
        number,
        name,
        ReplayStrategy.RECORDED,
        _NO_OUTPUTS,
        state_action=state_action,
        allowed_argument_values=allowed_argument_values,
        allowed_extras=allowed_extras,
    )


def _direct(
    number: int,
    name: str,
    *outputs: DirectOutput,
    require_result_bytes: bool = False,
    result_output_register: str | None = None,
    state_action: SyscallStateAction = SyscallStateAction.NONE,
    recorded_post_registers: tuple[str, ...] = (),
    allowed_argument_values: tuple[tuple[str, tuple[int, ...]], ...] = (),
    allowed_extras: frozenset[str] = frozenset(("none",)),
) -> SyscallPolicy:
    return SyscallPolicy(
        number,
        name,
        ReplayStrategy.RECORDED,
        DirectMemoryOutputs(
            tuple(outputs),
            require_result_bytes=require_result_bytes,
            result_output_register=result_output_register,
        ),
        state_action=state_action,
        recorded_post_registers=recorded_post_registers,
        allowed_argument_values=allowed_argument_values,
        allowed_extras=allowed_extras,
    )


def _execute(
    number: int,
    name: str,
    *,
    outputs: DirectMemoryOutputs | NoMemoryOutputs = _NO_OUTPUTS,
    state_action: SyscallStateAction = SyscallStateAction.NONE,
    reconcile: ReconcileMode = ReconcileMode.EXACT,
    guard: ExecutionGuard = ExecutionGuard.NONE,
    execution_arguments: tuple[str, ...] = (),
    exact_post_registers: tuple[str, ...] = (),
    allowed_extras: frozenset[str] = frozenset(("none",)),
) -> SyscallPolicy:
    return SyscallPolicy(
        number,
        name,
        ReplayStrategy.EXECUTE_RECONCILE,
        outputs,
        state_action=state_action,
        reconcile=reconcile,
        execution_guard=guard,
        execution_arguments=execution_arguments,
        exact_post_registers=exact_post_registers,
        allowed_extras=allowed_extras,
    )


def _reject(number: int, name: str, reason: str) -> SyscallPolicy:
    return SyscallPolicy(
        number,
        name,
        ReplayStrategy.REJECT,
        _NO_OUTPUTS,
        reject_reason=reason,
    )


def _fixed(register: str, size: int) -> DirectOutput:
    return DirectOutput(register, FixedExtent(size))


def _result(register: str, limit_register: str | None = None) -> DirectOutput:
    return DirectOutput(register, ResultExtent(limit_register=limit_register))


def _register(register: str, size_register: str, *, multiplier: int = 1) -> DirectOutput:
    return DirectOutput(register, RegisterExtent(size_register, multiplier=multiplier))


def _sockaddr(register: str, length_pointer_register: str) -> DirectOutput:
    return DirectOutput(register, PointedU32Extent(length_pointer_register, maximum=128))


# Calls classified as recorded actions. They never run against the live host;
# their user-visible register/memory outputs and virtual descriptor/signal state
# are replayed from RR.
_POLICIES: dict[int, SyscallPolicy] = {
    0: _direct(
        0,
        "read",
        _result("rsi", "rdx"),
        require_result_bytes=True,
        allowed_extras=_OFFSET_EXTRAS,
    ),
    1: _recorded(1, "write", allowed_extras=_OFFSET_EXTRAS),
    2: _recorded(
        2,
        "open",
        state_action=SyscallStateAction.OPEN_FD,
        allowed_extras=_OPEN_EXTRAS,
    ),
    3: _recorded(3, "close", state_action=SyscallStateAction.CLOSE_FD),
    4: _direct(4, "stat", _fixed("rsi", 144)),
    5: _direct(5, "fstat", _fixed("rsi", 144)),
    6: _direct(6, "lstat", _fixed("rsi", 144)),
    7: _direct(7, "poll", _register("rdi", "rsi", multiplier=8)),
    8: _recorded(8, "lseek"),
    9: _execute(
        9,
        "mmap",
        state_action=SyscallStateAction.MEMORY_MAPPING,
        guard=ExecutionGuard.ANONYMOUS_MMAP,
        execution_arguments=("rdi", "rsi", "rdx", "r10", "r8", "r9"),
    ),
    10: _execute(
        10,
        "mprotect",
        state_action=SyscallStateAction.MEMORY_MAPPING,
        execution_arguments=("rdi", "rsi", "rdx"),
    ),
    11: _execute(
        11,
        "munmap",
        state_action=SyscallStateAction.MEMORY_MAPPING,
        execution_arguments=("rdi", "rsi"),
    ),
    12: _execute(
        12,
        "brk",
        state_action=SyscallStateAction.MEMORY_MAPPING,
        execution_arguments=("rdi",),
    ),
    13: _direct(
        13,
        "rt_sigaction",
        _fixed("rdx", 32),
        state_action=SyscallStateAction.SIGNAL_ACTION,
    ),
    14: _direct(
        14,
        "rt_sigprocmask",
        _register("rdx", "r10"),
        state_action=SyscallStateAction.SIGNAL_MASK,
    ),
    15: _execute(
        15,
        "rt_sigreturn",
        state_action=SyscallStateAction.RETURN_FROM_SIGNAL,
    ),
    16: _direct(
        16,
        "ioctl:TIOCGWINSZ",
        _fixed("rdx", 8),
        allowed_argument_values=(("rsi", (0x5413,)),),
    ),
    17: _direct(
        17,
        "pread64",
        _result("rsi", "rdx"),
        require_result_bytes=True,
    ),
    18: _recorded(18, "pwrite64"),
    19: SyscallPolicy(
        19,
        "readv",
        ReplayStrategy.RECORDED,
        IovecResultOutputs(),
        allowed_extras=_OFFSET_EXTRAS,
    ),
    20: _recorded(20, "writev", allowed_extras=_OFFSET_EXTRAS),
    21: _recorded(21, "access"),
    22: _direct(
        22,
        "pipe",
        _fixed("rdi", 8),
        state_action=SyscallStateAction.PIPE_FDS,
    ),
    23: _direct(
        23,
        "select",
        DirectOutput("rsi", FdSetExtent()),
        DirectOutput("rdx", FdSetExtent()),
        DirectOutput("r10", FdSetExtent()),
        _fixed("r8", 16),
    ),
    24: SyscallPolicy(24, "sched_yield", ReplayStrategy.SAFE_PASSTHROUGH, _NO_OUTPUTS),
    25: _execute(
        25,
        "mremap",
        state_action=SyscallStateAction.MEMORY_MAPPING,
        execution_arguments=("rdi", "rsi", "rdx", "r10", "r8"),
    ),
    28: _execute(
        28,
        "madvise",
        state_action=SyscallStateAction.MEMORY_MAPPING,
        execution_arguments=("rdi", "rsi", "rdx"),
    ),
    32: _recorded(32, "dup", state_action=SyscallStateAction.DUP_FD),
    33: _recorded(33, "dup2", state_action=SyscallStateAction.DUP_FD),
    34: _recorded(34, "pause"),
    35: _direct(35, "nanosleep", _fixed("rsi", 16)),
    36: _direct(36, "getitimer", _fixed("rsi", 32)),
    37: _recorded(37, "alarm"),
    38: _direct(38, "setitimer", _fixed("rdx", 32)),
    39: _recorded(39, "getpid"),
    40: _direct(40, "sendfile", _fixed("rdx", 8)),
    41: _recorded(41, "socket", state_action=SyscallStateAction.SOCKET_FD),
    42: _recorded(42, "connect", allowed_extras=_SOCKET_EXTRAS),
    43: _direct(
        43,
        "accept",
        _sockaddr("rsi", "rdx"),
        _fixed("rdx", 4),
        state_action=SyscallStateAction.ACCEPT_FD,
        allowed_extras=_SOCKET_EXTRAS,
    ),
    44: _recorded(44, "sendto"),
    45: _direct(
        45,
        "recvfrom",
        _result("rsi", "rdx"),
        _sockaddr("r8", "r9"),
        _fixed("r9", 4),
        result_output_register="rsi",
    ),
    46: _reject(
        46,
        "sendmsg",
        "SCM_RIGHTS and nested msghdr input effects are not yet modeled",
    ),
    47: _reject(
        47,
        "recvmsg",
        "nested msghdr outputs and descriptor passing are not yet modeled",
    ),
    48: _recorded(48, "shutdown"),
    49: _recorded(49, "bind"),
    50: _recorded(50, "listen"),
    51: _direct(
        51,
        "getsockname",
        _sockaddr("rsi", "rdx"),
        _fixed("rdx", 4),
    ),
    52: _direct(
        52,
        "getpeername",
        _sockaddr("rsi", "rdx"),
        _fixed("rdx", 4),
    ),
    53: _direct(
        53,
        "socketpair",
        _fixed("r10", 8),
        state_action=SyscallStateAction.PIPE_FDS,
    ),
    54: _recorded(54, "setsockopt"),
    55: _direct(
        55,
        "getsockopt",
        DirectOutput("r10", PointedU32Extent("r8", maximum=1 << 20)),
        _fixed("r8", 4),
    ),
    56: _reject(56, "clone", "task creation is outside single-thread replay"),
    57: _reject(57, "fork", "task creation is outside single-thread replay"),
    58: _reject(58, "vfork", "task creation is outside single-thread replay"),
    59: _reject(59, "execve", "program-image replacement is not replayed"),
    60: _execute(
        60,
        "exit",
        state_action=SyscallStateAction.TERMINATE,
        execution_arguments=("rdi",),
    ),
    61: _reject(61, "wait4", "waiting requires a concurrent task model"),
    62: _recorded(62, "kill"),
    63: _direct(63, "uname", _fixed("rdi", 390)),
    72: _recorded(
        72,
        "fcntl",
        allowed_argument_values=(("rsi", (1, 2, 3, 6)),),
    ),
    73: _recorded(73, "flock"),
    74: _recorded(74, "fsync"),
    75: _recorded(75, "fdatasync"),
    76: _recorded(76, "truncate"),
    77: _recorded(77, "ftruncate"),
    78: _direct(78, "getdents", _result("rsi", "rdx"), require_result_bytes=True),
    79: _direct(79, "getcwd", _result("rdi", "rsi"), require_result_bytes=True),
    80: _recorded(80, "chdir"),
    81: _recorded(81, "fchdir"),
    82: _recorded(82, "rename"),
    83: _recorded(83, "mkdir"),
    84: _recorded(84, "rmdir"),
    85: _recorded(
        85,
        "creat",
        state_action=SyscallStateAction.OPEN_FD,
        allowed_extras=_OPEN_EXTRAS,
    ),
    86: _recorded(86, "link"),
    87: _recorded(87, "unlink"),
    88: _recorded(88, "symlink"),
    89: _direct(89, "readlink", _result("rsi", "rdx"), require_result_bytes=True),
    90: _recorded(90, "chmod"),
    91: _recorded(91, "fchmod"),
    92: _recorded(92, "chown"),
    93: _recorded(93, "fchown"),
    94: _recorded(94, "lchown"),
    95: _recorded(95, "umask"),
    96: _direct(96, "gettimeofday", _fixed("rdi", 16), _fixed("rsi", 8)),
    97: _direct(97, "getrlimit", _fixed("rsi", 16)),
    98: _direct(98, "getrusage", _fixed("rsi", 144)),
    99: _direct(99, "sysinfo", _fixed("rdi", 112)),
    100: _direct(100, "times", _fixed("rdi", 32)),
    102: _recorded(102, "getuid"),
    104: _recorded(104, "getgid"),
    105: _recorded(105, "setuid"),
    106: _recorded(106, "setgid"),
    107: _recorded(107, "geteuid"),
    108: _recorded(108, "getegid"),
    109: _recorded(109, "setpgid"),
    110: _recorded(110, "getppid"),
    111: _recorded(111, "getpgrp"),
    112: _recorded(112, "setsid"),
    113: _recorded(113, "setreuid"),
    114: _recorded(114, "setregid"),
    117: _recorded(117, "setresuid"),
    118: _direct(
        118,
        "getresuid",
        _fixed("rdi", 4),
        _fixed("rsi", 4),
        _fixed("rdx", 4),
    ),
    119: _recorded(119, "setresgid"),
    120: _direct(
        120,
        "getresgid",
        _fixed("rdi", 4),
        _fixed("rsi", 4),
        _fixed("rdx", 4),
    ),
    121: _recorded(121, "getpgid"),
    124: _recorded(124, "getsid"),
    127: _direct(127, "rt_sigpending", _register("rdi", "rsi")),
    128: _direct(128, "rt_sigtimedwait", _fixed("rsi", 128)),
    129: _recorded(129, "rt_sigqueueinfo"),
    130: _reject(130, "rt_sigsuspend", "interrupted system-call restart is not modeled"),
    131: _direct(
        131,
        "sigaltstack",
        _fixed("rsi", 24),
        state_action=SyscallStateAction.SIGNAL_ALTSTACK,
    ),
    137: _direct(137, "statfs", _fixed("rsi", 120)),
    138: _direct(138, "fstatfs", _fixed("rsi", 120)),
    158: _direct(
        158,
        "arch_prctl",
        _fixed("rsi", 8),
        recorded_post_registers=("fs_base", "gs_base"),
    ),
    186: _recorded(186, "gettid"),
    200: _recorded(200, "tkill"),
    201: _direct(201, "time", _fixed("rdi", 8)),
    202: _reject(202, "futex", "futex state requires a concurrent task model"),
    213: _recorded(213, "epoll_create", state_action=SyscallStateAction.OPEN_FD),
    218: _execute(
        218,
        "set_tid_address",
        reconcile=ReconcileMode.APPLY_RECORDED,
        execution_arguments=("rdi",),
    ),
    219: _reject(219, "restart_syscall", "interrupted system-call restart is not modeled"),
    228: _direct(228, "clock_gettime", _fixed("rsi", 16)),
    231: _execute(
        231,
        "exit_group",
        state_action=SyscallStateAction.TERMINATE,
        execution_arguments=("rdi",),
    ),
    232: _direct(
        232,
        "epoll_wait",
        DirectOutput("rsi", ResultExtent(limit_register="rdx", multiplier=12)),
    ),
    233: _recorded(233, "epoll_ctl"),
    257: _recorded(
        257,
        "openat",
        state_action=SyscallStateAction.OPEN_FD,
        allowed_extras=_OPEN_EXTRAS,
    ),
    258: _recorded(258, "mkdirat"),
    259: _recorded(259, "mknodat"),
    260: _recorded(260, "fchownat"),
    261: _recorded(261, "futimesat"),
    262: _direct(262, "newfstatat", _fixed("rdx", 144)),
    263: _recorded(263, "unlinkat"),
    264: _recorded(264, "renameat"),
    265: _recorded(265, "linkat"),
    266: _recorded(266, "symlinkat"),
    267: _direct(267, "readlinkat", _result("rdx", "r10"), require_result_bytes=True),
    268: _recorded(268, "fchmodat"),
    269: _recorded(269, "faccessat"),
    270: _direct(
        270,
        "pselect6",
        DirectOutput("rsi", FdSetExtent()),
        DirectOutput("rdx", FdSetExtent()),
        DirectOutput("r10", FdSetExtent()),
        _fixed("r8", 16),
    ),
    271: _direct(271, "ppoll", _register("rdi", "rsi", multiplier=8)),
    273: _execute(
        273,
        "set_robust_list",
        execution_arguments=("rdi", "rsi"),
    ),
    281: _direct(
        281,
        "epoll_pwait",
        DirectOutput("rsi", ResultExtent(limit_register="rdx", multiplier=12)),
    ),
    284: _recorded(284, "eventfd", state_action=SyscallStateAction.OPEN_FD),
    288: _direct(
        288,
        "accept4",
        _sockaddr("rsi", "rdx"),
        _fixed("rdx", 4),
        state_action=SyscallStateAction.ACCEPT_FD,
        allowed_extras=_SOCKET_EXTRAS,
    ),
    290: _recorded(290, "eventfd2", state_action=SyscallStateAction.OPEN_FD),
    291: _recorded(291, "epoll_create1", state_action=SyscallStateAction.OPEN_FD),
    292: _recorded(292, "dup3", state_action=SyscallStateAction.DUP_FD),
    293: _direct(
        293,
        "pipe2",
        _fixed("rdi", 8),
        state_action=SyscallStateAction.PIPE_FDS,
    ),
    295: SyscallPolicy(
        295,
        "preadv",
        ReplayStrategy.RECORDED,
        IovecResultOutputs(),
    ),
    296: _recorded(296, "pwritev"),
    297: _recorded(297, "rt_tgsigqueueinfo"),
    302: _direct(302, "prlimit64", _fixed("r10", 16)),
    309: _direct(309, "getcpu", _fixed("rdi", 4), _fixed("rsi", 4), _fixed("rdx", 128)),
    316: _recorded(316, "renameat2"),
    318: _direct(
        318,
        "getrandom",
        _result("rdi", "rsi"),
        require_result_bytes=True,
    ),
    322: _reject(322, "execveat", "program-image replacement is not replayed"),
    334: _reject(334, "rseq", "rseq CPU and abort state is not modeled"),
    435: _reject(435, "clone3", "task creation is outside single-thread replay"),
}


X86_64_SYSCALL_POLICIES: Mapping[int, SyscallPolicy] = validate_policy_table(ArchX86(), _POLICIES)


# Linux x86-64 rt-signal ABI. Offsets are from Linux UAPI sigcontext and
# ucontext layouts. The siginfo location and variable FP/XSTATE tail are taken
# from the recorded handler registers/frame, not guessed from a fixed frame
# size.
X86_64_PRETCODE_OFFSET = 0
X86_64_UCONTEXT_OFFSET = 8
X86_64_UCONTEXT_STACK_OFFSET = 16
X86_64_UCONTEXT_MCONTEXT_OFFSET = 40
X86_64_SIGCONTEXT_SIZE = 256
X86_64_UCONTEXT_SIGMASK_OFFSET = 296
X86_64_KERNEL_SIGSET_SIZE = 8
X86_64_SIGINFO_SIZE = 128
X86_64_FPSTATE_MIN_SIZE = 512
X86_64_FPSTATE_SW_RESERVED_OFFSET = 464
X86_64_FP_XSTATE_MAGIC1 = 0x46505853
X86_64_FP_XSTATE_MAGIC2 = 0x46505845
MAX_X86_SIGNAL_FRAME_SIZE = 1 << 20

X86_64_SIGCONTEXT_REGISTER_OFFSETS: Mapping[str, int] = MappingProxyType(
    {
        "r8": 0,
        "r9": 8,
        "r10": 16,
        "r11": 24,
        "r12": 32,
        "r13": 40,
        "r14": 48,
        "r15": 56,
        "rdi": 64,
        "rsi": 72,
        "rbp": 80,
        "rbx": 88,
        "rdx": 96,
        "rax": 104,
        "rcx": 112,
        "rsp": 120,
        "rip": 128,
        "rflags": 136,
    }
)
X86_64_SIGCONTEXT_CS_OFFSET = 144
X86_64_SIGCONTEXT_GS_OFFSET = 146
X86_64_SIGCONTEXT_FS_OFFSET = 148
X86_64_SIGCONTEXT_SS_OFFSET = 150
X86_64_SIGCONTEXT_FPSTATE_OFFSET = 184


class _RecordedMemoryImage:
    def __init__(self, writes: Sequence[MaterializedMemoryWrite]):
        nonempty = sorted(
            (write for write in writes if write.data),
            key=lambda write: write.recorded_address,
        )
        previous_end: int | None = None
        for write in nonempty:
            if previous_end is not None and write.recorded_address < previous_end:
                raise ReplayEventError("Recorded signal-frame writes overlap.")
            previous_end = write.recorded_address + len(write.data)
        self.writes = tuple(nonempty)

    def read(self, address: int, size: int) -> bytes:
        if size < 0:
            raise ValueError("A signal-frame read cannot have a negative size.")
        result = bytearray()
        cursor = address
        remaining = size
        for write in self.writes:
            start = write.recorded_address
            end = start + len(write.data)
            if end <= cursor:
                continue
            if start > cursor:
                break
            take = min(remaining, end - cursor)
            result.extend(write.data[cursor - start : cursor - start + take])
            cursor += take
            remaining -= take
            if remaining == 0:
                return bytes(result)
        raise ReplayEventError(
            f"Recorded signal frame does not contain [{address:#x}, " f"{address + size:#x})."
        )

    @property
    def start(self) -> int | None:
        return self.writes[0].recorded_address if self.writes else None

    @property
    def end(self) -> int | None:
        if not self.writes:
            return None
        last = self.writes[-1]
        return last.recorded_address + len(last.data)


@dataclass(frozen=True, slots=True)
class X86KernelSigaction:
    """The x86-64 kernel ``struct sigaction`` used by rt_sigaction."""

    handler: int
    flags: int
    restorer: int
    mask: int

    SIZE = 32
    SA_SIGINFO = 0x00000004
    SA_RESTORER = 0x04000000
    SA_ONSTACK = 0x08000000

    @classmethod
    def from_bytes(cls, data: bytes) -> X86KernelSigaction:
        if len(data) != cls.SIZE:
            raise ReplayEventError(
                f"x86-64 kernel sigaction has {len(data)} bytes, expected {cls.SIZE}."
            )
        values = tuple(
            int.from_bytes(data[offset : offset + 8], "little") for offset in range(0, cls.SIZE, 8)
        )
        return cls(*values)

    def to_bytes(self) -> bytes:
        return b"".join(
            value.to_bytes(8, "little")
            for value in (self.handler, self.flags, self.restorer, self.mask)
        )

    def __post_init__(self) -> None:
        for name, value in (
            ("handler", self.handler),
            ("flags", self.flags),
            ("restorer", self.restorer),
            ("mask", self.mask),
        ):
            if value < 0 or value >= 1 << 64:
                raise ValueError(f"Signal-action field {name} is not a uint64.")
        if self.handler not in (0, 1) and not self.flags & self.SA_RESTORER:
            raise ReplayEventError("x86-64 user signal actions require SA_RESTORER.")
        if self.flags & self.SA_RESTORER and self.restorer == 0:
            raise ReplayEventError("SA_RESTORER is set with a null restorer.")


@dataclass(frozen=True, slots=True)
class X86RecordedSignalFrame:
    """Validated recorded x86-64 rt-signal frame and variable FP state."""

    frame_address: int
    ucontext_address: int
    siginfo_address: int
    fpstate_address: int
    fpstate_size: int
    restorer_address: int
    signal_number: int
    signal_mask: int
    altstack: bytes
    saved_registers: Mapping[str, int]
    writes: tuple[MaterializedMemoryWrite, ...]

    @classmethod
    def from_events(
        cls,
        pre_event: SignalEvent,
        post_event: SignalEvent,
        writes: Sequence[MaterializedMemoryWrite],
    ) -> X86RecordedSignalFrame:
        if pre_event.arch.archname != "x86_64" or post_event.arch.archname != "x86_64":
            raise ReplayEventError("x86 signal replay received a non-x86-64 event.")
        if post_event.signal_variant != "signalHandler":
            raise ReplayEventError(
                f"A signal frame requires signalHandler, got {post_event.signal_variant}."
            )
        if post_event.descriptor.disposition != "userHandler":
            raise ReplayEventError("A signalHandler event does not have userHandler disposition.")
        if len(pre_event.descriptor.siginfo) != X86_64_SIGINFO_SIZE:
            raise ReplayEventError(
                f"RR x86-64 siginfo has {len(pre_event.descriptor.siginfo)} bytes, "
                f"expected {X86_64_SIGINFO_SIZE}."
            )

        try:
            frame_address = post_event.registers["rsp"]
            ucontext_address = post_event.registers["rdx"]
            siginfo_address = post_event.registers["rsi"]
        except KeyError as error:
            raise ReplayEventError("Signal-handler event lacks ABI argument registers.") from error
        if ucontext_address != frame_address + X86_64_UCONTEXT_OFFSET:
            raise ReplayEventError(
                f"Signal ucontext is {ucontext_address:#x}; expected frame+8 "
                f"({frame_address + X86_64_UCONTEXT_OFFSET:#x})."
            )
        if frame_address & 0xF != 8:
            raise ReplayEventError(
                f"Signal frame {frame_address:#x} violates x86-64 stack alignment."
            )

        image = _RecordedMemoryImage(writes)
        if image.start != frame_address:
            raise ReplayEventError(
                f"Recorded signal writes start at {image.start!r}, expected " f"{frame_address:#x}."
            )
        image_end = image.end
        if image_end is None or image_end - frame_address > MAX_X86_SIGNAL_FRAME_SIZE:
            raise ReplayEventError("Recorded signal frame is empty or exceeds the size limit.")

        restorer_address = int.from_bytes(image.read(frame_address, 8), "little")
        recorded_siginfo = image.read(siginfo_address, X86_64_SIGINFO_SIZE)
        if recorded_siginfo != pre_event.descriptor.siginfo:
            raise ReplayEventError("Signal-frame siginfo differs from the RR signal action.")
        signal_number = int.from_bytes(recorded_siginfo[:4], "little", signed=True)
        if signal_number != pre_event.descriptor.signal_number:
            raise ReplayEventError("Signal-frame signal number differs from the RR event.")
        try:
            handler_argument = post_event.registers["rdi"]
        except KeyError as error:
            raise ReplayEventError("Signal-handler event lacks RDI.") from error
        if handler_argument != signal_number:
            raise ReplayEventError(
                f"Signal handler receives {handler_argument}, expected {signal_number}."
            )

        mcontext_address = ucontext_address + X86_64_UCONTEXT_MCONTEXT_OFFSET
        saved_registers: dict[str, int] = {}
        for register, offset in X86_64_SIGCONTEXT_REGISTER_OFFSETS.items():
            value = int.from_bytes(image.read(mcontext_address + offset, 8), "little")
            saved_registers[register] = value
            try:
                expected = pre_event.registers[register]
            except KeyError as error:
                raise ReplayEventError(f"Signal event lacks saved register {register}.") from error
            if value != expected:
                raise ReplayEventError(
                    f"Signal context saves {register}={value:#x}, RR event has "
                    f"{expected:#x}. Interrupted/restarted signal contexts are not yet "
                    "supported."
                )

        for register, offset in (
            ("cs", X86_64_SIGCONTEXT_CS_OFFSET),
            ("ss", X86_64_SIGCONTEXT_SS_OFFSET),
        ):
            value = int.from_bytes(image.read(mcontext_address + offset, 2), "little")
            try:
                expected = pre_event.registers[register]
            except KeyError as error:
                raise ReplayEventError(
                    f"Signal event lacks saved segment register {register}."
                ) from error
            if value != expected:
                raise ReplayEventError(
                    f"Signal context saves {register}={value:#x}, expected {expected:#x}."
                )

        fpstate_address = int.from_bytes(
            image.read(mcontext_address + X86_64_SIGCONTEXT_FPSTATE_OFFSET, 8),
            "little",
        )
        if fpstate_address == 0:
            raise ReplayEventError("Recorded x86-64 signal frame omits FP state.")
        if fpstate_address & 0x3F:
            raise ReplayEventError(f"Signal FP state {fpstate_address:#x} is not 64-byte aligned.")
        fpstate = image.read(fpstate_address, X86_64_FPSTATE_MIN_SIZE)
        magic1 = int.from_bytes(
            fpstate[X86_64_FPSTATE_SW_RESERVED_OFFSET : X86_64_FPSTATE_SW_RESERVED_OFFSET + 4],
            "little",
        )
        if magic1 == 0:
            fpstate_size = X86_64_FPSTATE_MIN_SIZE
        elif magic1 == X86_64_FP_XSTATE_MAGIC1:
            extended_size = int.from_bytes(
                fpstate[
                    X86_64_FPSTATE_SW_RESERVED_OFFSET + 4 : X86_64_FPSTATE_SW_RESERVED_OFFSET + 8
                ],
                "little",
            )
            xstate_size = int.from_bytes(
                fpstate[
                    X86_64_FPSTATE_SW_RESERVED_OFFSET + 16 : X86_64_FPSTATE_SW_RESERVED_OFFSET + 20
                ],
                "little",
            )
            if (
                extended_size < X86_64_FPSTATE_MIN_SIZE + 4
                or extended_size > MAX_X86_SIGNAL_FRAME_SIZE
                or xstate_size < X86_64_FPSTATE_MIN_SIZE
                or xstate_size > extended_size - 4
            ):
                raise ReplayEventError("Signal XSTATE size metadata is inconsistent.")
            magic2 = int.from_bytes(image.read(fpstate_address + extended_size - 4, 4), "little")
            if magic2 != X86_64_FP_XSTATE_MAGIC2:
                raise ReplayEventError("Signal XSTATE tail magic is missing.")
            fpstate_size = extended_size
        else:
            raise ReplayEventError(f"Signal FP state has unknown software magic {magic1:#x}.")

        signal_mask = int.from_bytes(
            image.read(
                ucontext_address + X86_64_UCONTEXT_SIGMASK_OFFSET,
                X86_64_KERNEL_SIGSET_SIZE,
            ),
            "little",
        )
        altstack = image.read(ucontext_address + X86_64_UCONTEXT_STACK_OFFSET, 24)
        return cls(
            frame_address,
            ucontext_address,
            siginfo_address,
            fpstate_address,
            fpstate_size,
            restorer_address,
            signal_number,
            signal_mask,
            altstack,
            MappingProxyType(saved_registers),
            tuple(writes),
        )
