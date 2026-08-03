"""AArch64 Linux deterministic-replay policy.

This module deliberately exposes a bounded single-thread baseline. Recorded
file, descriptor, socket, and output effects never execute on the live host;
process-local mappings execute in QEMU and are reconciled. Signal delivery and
other ABI surfaces without fixture-backed semantics remain explicit rejects.
"""

from __future__ import annotations

from collections.abc import Mapping

from focaccia.arch.aarch64 import ArchAArch64
from focaccia.qemu.syscall import (
    DirectMemoryOutputs,
    DirectOutput,
    ExecutionGuard,
    FixedExtent,
    IovecResultOutputs,
    NoMemoryOutputs,
    PointedU32Extent,
    ReconcileMode,
    RegisterExtent,
    ReplayStrategy,
    ResultExtent,
    SyscallPolicy,
    SyscallStateAction,
    validate_policy_table,
)


# Linux AArch64 system-call ABI registers.
SYSCALL_NUMBER_REGISTER = "x8"
SYSCALL_ARGUMENT_REGISTERS = ("x0", "x1", "x2", "x3", "x4", "x5")
SYSCALL_RECORDED_RESULT_REGISTERS = ("x0",)
SYSCALL_EXECUTION_BOUNDARY_REGISTERS: tuple[str, ...] = ()
PC_REGISTER = "pc"
RESULT_REGISTER = "x0"
THREAD_CREATING_SYSCALLS = frozenset((220, 435))
EXIT_GROUP_SYSCALL = 94


_NO_OUTPUTS = NoMemoryOutputs()
_OFFSET_EXTRAS = frozenset(("none", "writeOffset"))
_OPEN_EXTRAS = frozenset(("none", "openedFds"))
_SOCKET_EXTRAS = frozenset(("none", "socketAddrs"))


def _recorded(
    number: int,
    name: str,
    *,
    state_action: SyscallStateAction = SyscallStateAction.NONE,
    allowed_extras: frozenset[str] = frozenset(("none",)),
) -> SyscallPolicy:
    return SyscallPolicy(
        number,
        name,
        ReplayStrategy.RECORDED,
        _NO_OUTPUTS,
        state_action=state_action,
        allowed_extras=allowed_extras,
    )


def _direct(
    number: int,
    name: str,
    *outputs: DirectOutput,
    require_result_bytes: bool = False,
    result_output_register: str | None = None,
    state_action: SyscallStateAction = SyscallStateAction.NONE,
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
        allowed_extras=allowed_extras,
    )


def _execute(
    number: int,
    name: str,
    *,
    state_action: SyscallStateAction = SyscallStateAction.NONE,
    reconcile: ReconcileMode = ReconcileMode.EXACT,
    guard: ExecutionGuard = ExecutionGuard.NONE,
    execution_arguments: tuple[str, ...] = (),
) -> SyscallPolicy:
    return SyscallPolicy(
        number,
        name,
        ReplayStrategy.EXECUTE_RECONCILE,
        _NO_OUTPUTS,
        state_action=state_action,
        reconcile=reconcile,
        execution_guard=guard,
        execution_arguments=execution_arguments,
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


# Numbers and structure sizes follow Linux's AArch64 asm-generic syscall ABI.
# This is intentionally not an assertion of complete Linux syscall support.
_POLICIES: dict[int, SyscallPolicy] = {
    17: _direct(17, "getcwd", _result("x0", "x1"), require_result_bytes=True),
    23: _recorded(23, "dup", state_action=SyscallStateAction.DUP_FD),
    24: _recorded(24, "dup3", state_action=SyscallStateAction.DUP_FD),
    25: _reject(25, "fcntl", "fcntl commands have command-specific pointer and fd effects"),
    29: _reject(
        29,
        "ioctl",
        "ioctl command payloads are variant-specific and have no generic safe replay policy",
    ),
    48: _recorded(48, "faccessat"),
    56: _recorded(
        56,
        "openat",
        state_action=SyscallStateAction.OPEN_FD,
        allowed_extras=_OPEN_EXTRAS,
    ),
    57: _recorded(57, "close", state_action=SyscallStateAction.CLOSE_FD),
    59: _direct(
        59,
        "pipe2",
        _fixed("x0", 8),
        state_action=SyscallStateAction.PIPE_FDS,
    ),
    61: _direct(61, "getdents64", _result("x1", "x2"), require_result_bytes=True),
    62: _recorded(62, "lseek"),
    63: _direct(
        63,
        "read",
        _result("x1", "x2"),
        require_result_bytes=True,
        allowed_extras=_OFFSET_EXTRAS,
    ),
    64: _recorded(64, "write", allowed_extras=_OFFSET_EXTRAS),
    65: SyscallPolicy(
        65,
        "readv",
        ReplayStrategy.RECORDED,
        IovecResultOutputs("x1", "x2"),
        allowed_extras=_OFFSET_EXTRAS,
    ),
    66: _recorded(66, "writev", allowed_extras=_OFFSET_EXTRAS),
    67: _direct(67, "pread64", _result("x1", "x2"), require_result_bytes=True),
    68: _recorded(68, "pwrite64"),
    69: SyscallPolicy(
        69,
        "preadv",
        ReplayStrategy.RECORDED,
        IovecResultOutputs("x1", "x2"),
    ),
    70: _recorded(70, "pwritev"),
    78: _direct(78, "readlinkat", _result("x2", "x3"), require_result_bytes=True),
    79: _direct(79, "newfstatat", _fixed("x2", 128)),
    80: _direct(80, "fstat", _fixed("x1", 128)),
    93: _execute(
        93,
        "exit",
        state_action=SyscallStateAction.TERMINATE,
        execution_arguments=("x0",),
    ),
    94: _execute(
        94,
        "exit_group",
        state_action=SyscallStateAction.TERMINATE,
        execution_arguments=("x0",),
    ),
    96: _execute(
        96,
        "set_tid_address",
        reconcile=ReconcileMode.APPLY_RECORDED,
        execution_arguments=("x0",),
    ),
    98: _reject(98, "futex", "futex state requires a concurrent task model"),
    99: _execute(99, "set_robust_list", execution_arguments=("x0", "x1")),
    101: _direct(101, "nanosleep", _fixed("x1", 16)),
    113: _direct(113, "clock_gettime", _fixed("x1", 16)),
    124: SyscallPolicy(124, "sched_yield", ReplayStrategy.SAFE_PASSTHROUGH, _NO_OUTPUTS),
    132: _reject(132, "sigaltstack", "AArch64 signal-stack replay is not fixture-backed"),
    133: _reject(133, "rt_sigsuspend", "interrupted system-call restart is not modeled"),
    134: _reject(134, "rt_sigaction", "AArch64 signal-action replay is not fixture-backed"),
    135: _reject(135, "rt_sigprocmask", "AArch64 signal-mask replay is not fixture-backed"),
    136: _reject(136, "rt_sigpending", "AArch64 signal replay is not fixture-backed"),
    137: _reject(137, "rt_sigtimedwait", "AArch64 signal replay is not fixture-backed"),
    138: _reject(138, "rt_sigqueueinfo", "AArch64 signal replay is not fixture-backed"),
    139: _reject(139, "rt_sigreturn", "AArch64 signal return is not fixture-backed"),
    160: _direct(160, "uname", _fixed("x0", 390)),
    172: _recorded(172, "getpid"),
    173: _recorded(173, "getppid"),
    174: _recorded(174, "getuid"),
    175: _recorded(175, "geteuid"),
    176: _recorded(176, "getgid"),
    177: _recorded(177, "getegid"),
    178: _recorded(178, "gettid"),
    198: _recorded(198, "socket", state_action=SyscallStateAction.SOCKET_FD),
    199: _direct(
        199,
        "socketpair",
        _fixed("x3", 8),
        state_action=SyscallStateAction.PIPE_FDS,
    ),
    200: _recorded(200, "bind"),
    201: _recorded(201, "listen"),
    202: _direct(
        202,
        "accept",
        _sockaddr("x1", "x2"),
        _fixed("x2", 4),
        state_action=SyscallStateAction.ACCEPT_FD,
        allowed_extras=_SOCKET_EXTRAS,
    ),
    203: _recorded(203, "connect", allowed_extras=_SOCKET_EXTRAS),
    204: _direct(204, "getsockname", _sockaddr("x1", "x2"), _fixed("x2", 4)),
    205: _direct(205, "getpeername", _sockaddr("x1", "x2"), _fixed("x2", 4)),
    206: _recorded(206, "sendto"),
    207: _direct(
        207,
        "recvfrom",
        _result("x1", "x2"),
        _sockaddr("x4", "x5"),
        _fixed("x5", 4),
        result_output_register="x1",
    ),
    208: _recorded(208, "setsockopt"),
    209: _direct(
        209,
        "getsockopt",
        DirectOutput("x3", PointedU32Extent("x4", maximum=1 << 20)),
        _fixed("x4", 4),
    ),
    210: _recorded(210, "shutdown"),
    211: _reject(211, "sendmsg", "nested msghdr effects are not modeled"),
    212: _reject(212, "recvmsg", "nested msghdr outputs and descriptor passing are not modeled"),
    214: _execute(
        214,
        "brk",
        state_action=SyscallStateAction.MEMORY_MAPPING,
        execution_arguments=("x0",),
    ),
    215: _execute(
        215,
        "munmap",
        state_action=SyscallStateAction.MEMORY_MAPPING,
        execution_arguments=("x0", "x1"),
    ),
    216: _execute(
        216,
        "mremap",
        state_action=SyscallStateAction.MEMORY_MAPPING,
        execution_arguments=("x0", "x1", "x2", "x3", "x4"),
    ),
    220: _reject(220, "clone", "task creation is outside single-thread replay"),
    221: _reject(221, "execve", "program-image replacement is not replayed"),
    222: _execute(
        222,
        "mmap",
        state_action=SyscallStateAction.MEMORY_MAPPING,
        guard=ExecutionGuard.ANONYMOUS_MMAP,
        execution_arguments=("x0", "x1", "x2", "x3", "x4", "x5"),
    ),
    226: _execute(
        226,
        "mprotect",
        state_action=SyscallStateAction.MEMORY_MAPPING,
        execution_arguments=("x0", "x1", "x2"),
    ),
    233: _execute(
        233,
        "madvise",
        state_action=SyscallStateAction.MEMORY_MAPPING,
        execution_arguments=("x0", "x1", "x2"),
    ),
    242: _direct(
        242,
        "accept4",
        _sockaddr("x1", "x2"),
        _fixed("x2", 4),
        state_action=SyscallStateAction.ACCEPT_FD,
        allowed_extras=_SOCKET_EXTRAS,
    ),
    260: _reject(260, "wait4", "waiting requires a concurrent task model"),
    261: _direct(261, "prlimit64", _fixed("x3", 16)),
    278: _direct(278, "getrandom", _result("x0", "x1"), require_result_bytes=True),
    293: _reject(293, "rseq", "rseq CPU and abort state is not modeled"),
    435: _reject(435, "clone3", "task creation is outside single-thread replay"),
}


AARCH64_SYSCALL_POLICIES: Mapping[int, SyscallPolicy] = validate_policy_table(
    ArchAArch64("little"),
    _POLICIES,
)
