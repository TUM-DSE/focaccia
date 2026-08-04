"""AArch64 Linux deterministic-replay policy.

This module deliberately exposes a bounded single-thread baseline. Recorded
file, descriptor, socket, and output effects never execute on the live host;
process-local mappings execute in QEMU and are reconciled. Base AArch64
FPSIMD signal frames are validated; SVE/SME extension records remain explicit
unsupported boundaries.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from focaccia.arch.aarch64 import ArchAArch64
from focaccia.deterministic import SignalEvent
from focaccia.qemu.syscall import (
    DirectMemoryOutputs,
    DirectOutput,
    ExecutionGuard,
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


# Linux AArch64 rt-signal ABI offsets. These follow Linux UAPI and the pinned
# QEMU ``linux-user/aarch64/signal.c`` layout.
AARCH64_SIGINFO_SIZE = 128
AARCH64_UCONTEXT_OFFSET = 128
AARCH64_UCONTEXT_STACK_OFFSET = 16
AARCH64_UCONTEXT_SIGMASK_OFFSET = 40
AARCH64_UCONTEXT_MCONTEXT_OFFSET = 176
AARCH64_SIGCONTEXT_FAULT_OFFSET = 0
AARCH64_SIGCONTEXT_REGISTERS_OFFSET = 8
AARCH64_SIGCONTEXT_SP_OFFSET = 256
AARCH64_SIGCONTEXT_PC_OFFSET = 264
AARCH64_SIGCONTEXT_PSTATE_OFFSET = 272
AARCH64_SIGCONTEXT_RESERVED_OFFSET = 288
AARCH64_RESERVED_SIZE = 4096
AARCH64_RT_SIGFRAME_SIZE = 4688
AARCH64_FRAME_RECORD_SIZE = 16
AARCH64_FPSIMD_MAGIC = 0x46508001
AARCH64_FPSIMD_CONTEXT_SIZE = 528
AARCH64_KERNEL_SIGSET_SIZE = 8
MAX_AARCH64_SIGNAL_FRAME_SIZE = 1 << 20


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
            f"Recorded AArch64 signal frame does not contain "
            f"[{address:#x}, {address + size:#x})."
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
class AArch64KernelSigaction:
    """Linux AArch64 kernel ``struct sigaction``."""

    handler: int
    flags: int
    restorer: int
    mask: int

    SIZE = 32
    SA_SIGINFO = 0x00000004
    SA_RESTORER = 0x04000000
    SA_ONSTACK = 0x08000000

    @classmethod
    def from_bytes(cls, data: bytes) -> AArch64KernelSigaction:
        if len(data) != cls.SIZE:
            raise ReplayEventError(
                f"AArch64 kernel sigaction has {len(data)} bytes, expected {cls.SIZE}."
            )
        return cls(
            *(int.from_bytes(data[offset : offset + 8], "little") for offset in range(0, 32, 8))
        )

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
        if self.flags & self.SA_RESTORER and self.restorer == 0:
            raise ReplayEventError("SA_RESTORER is set with a null AArch64 restorer.")


@dataclass(frozen=True, slots=True)
class AArch64RecordedSignalFrame:
    """Validated base AArch64 rt-signal frame with FPSIMD context."""

    frame_address: int
    ucontext_address: int
    siginfo_address: int
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
    ) -> AArch64RecordedSignalFrame:
        if pre_event.arch.archname != "aarch64" or post_event.arch.archname != "aarch64":
            raise ReplayEventError("AArch64 signal replay received another architecture.")
        if post_event.signal_variant != "signalHandler":
            raise ReplayEventError("An AArch64 signal frame requires signalHandler.")
        if post_event.descriptor.disposition != "userHandler":
            raise ReplayEventError("A signalHandler event does not have userHandler disposition.")
        if len(pre_event.descriptor.siginfo) != AARCH64_SIGINFO_SIZE:
            raise ReplayEventError(
                f"RR AArch64 siginfo has {len(pre_event.descriptor.siginfo)} bytes, "
                f"expected {AARCH64_SIGINFO_SIZE}."
            )
        try:
            frame_address = post_event.registers["sp"]
            siginfo_address = post_event.registers["x1"]
            ucontext_address = post_event.registers["x2"]
            restorer_address = post_event.registers["x30"]
        except KeyError as error:
            raise ReplayEventError("AArch64 handler event lacks ABI registers.") from error
        if frame_address & 0xF:
            raise ReplayEventError("AArch64 signal SP is not 16-byte aligned.")
        if siginfo_address != frame_address:
            raise ReplayEventError("AArch64 siginfo pointer does not equal the frame address.")
        if ucontext_address != frame_address + AARCH64_UCONTEXT_OFFSET:
            raise ReplayEventError("AArch64 ucontext pointer has the wrong frame offset.")

        image = _RecordedMemoryImage(writes)
        if image.start != frame_address:
            raise ReplayEventError("Recorded AArch64 signal writes do not start at SP.")
        image_end = image.end
        if image_end is None or image_end - frame_address > MAX_AARCH64_SIGNAL_FRAME_SIZE:
            raise ReplayEventError("Recorded AArch64 signal frame is empty or oversized.")
        recorded_siginfo = image.read(frame_address, AARCH64_SIGINFO_SIZE)
        if recorded_siginfo != pre_event.descriptor.siginfo:
            raise ReplayEventError("AArch64 frame siginfo differs from the RR event.")
        signal_number = int.from_bytes(recorded_siginfo[:4], "little", signed=True)
        if post_event.registers["x0"] != signal_number:
            raise ReplayEventError("AArch64 handler receives the wrong signal number.")

        mcontext = ucontext_address + AARCH64_UCONTEXT_MCONTEXT_OFFSET
        saved: dict[str, int] = {}
        for index in range(31):
            name = f"x{index}"
            value = int.from_bytes(
                image.read(mcontext + AARCH64_SIGCONTEXT_REGISTERS_OFFSET + index * 8, 8),
                "little",
            )
            if value != pre_event.registers[name]:
                raise ReplayEventError(f"AArch64 signal context disagrees for {name}.")
            saved[name] = value
        for name, offset in (
            ("sp", AARCH64_SIGCONTEXT_SP_OFFSET),
            ("pc", AARCH64_SIGCONTEXT_PC_OFFSET),
            ("cpsr", AARCH64_SIGCONTEXT_PSTATE_OFFSET),
        ):
            value = int.from_bytes(image.read(mcontext + offset, 8), "little")
            if value != pre_event.registers[name]:
                raise ReplayEventError(f"AArch64 signal context disagrees for {name}.")
            saved[name] = value

        pre_extra = pre_event.extra_registers
        if pre_extra is None or pre_extra.format != "aarch64-nt-fpr-v1":
            raise ReplayEventError("AArch64 signal entry lacks recorded NT_FPR state.")
        fpsimd = mcontext + AARCH64_SIGCONTEXT_RESERVED_OFFSET
        magic = int.from_bytes(image.read(fpsimd, 4), "little")
        size = int.from_bytes(image.read(fpsimd + 4, 4), "little")
        if magic != AARCH64_FPSIMD_MAGIC or size != AARCH64_FPSIMD_CONTEXT_SIZE:
            raise ReplayEventError("AArch64 signal frame has an invalid FPSIMD record.")
        if int.from_bytes(image.read(fpsimd + 8, 4), "little") != pre_extra.read_register("fpsr"):
            raise ReplayEventError("AArch64 signal frame FPSR differs from RR extra state.")
        if int.from_bytes(image.read(fpsimd + 12, 4), "little") != pre_extra.read_register("fpcr"):
            raise ReplayEventError("AArch64 signal frame FPCR differs from RR extra state.")
        for index in range(32):
            value = int.from_bytes(image.read(fpsimd + 16 + index * 16, 16), "little")
            if value != pre_extra.read_register(f"v{index}"):
                raise ReplayEventError(f"AArch64 signal frame differs for v{index}.")
        next_magic = int.from_bytes(
            image.read(fpsimd + AARCH64_FPSIMD_CONTEXT_SIZE, 4), "little"
        )
        next_size = int.from_bytes(
            image.read(fpsimd + AARCH64_FPSIMD_CONTEXT_SIZE + 4, 4), "little"
        )
        if next_magic != 0 or next_size != 0:
            raise ReplayEventError(
                "AArch64 SVE/SME signal extension records are not supported."
            )

        frame_record = frame_address + AARCH64_RT_SIGFRAME_SIZE
        if int.from_bytes(image.read(frame_record, 8), "little") != pre_event.registers["x29"]:
            raise ReplayEventError("AArch64 unwind frame has the wrong frame pointer.")
        if int.from_bytes(image.read(frame_record + 8, 8), "little") != pre_event.registers["x30"]:
            raise ReplayEventError("AArch64 unwind frame has the wrong link register.")
        if post_event.registers["x29"] != frame_record:
            raise ReplayEventError("AArch64 handler frame pointer has the wrong value.")

        signal_mask = int.from_bytes(
            image.read(ucontext_address + AARCH64_UCONTEXT_SIGMASK_OFFSET, 8), "little"
        )
        altstack = image.read(ucontext_address + AARCH64_UCONTEXT_STACK_OFFSET, 24)
        return cls(
            frame_address,
            ucontext_address,
            siginfo_address,
            restorer_address,
            signal_number,
            signal_mask,
            altstack,
            MappingProxyType(saved),
            tuple(writes),
        )


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
    132: _direct(
        132,
        "sigaltstack",
        _fixed("x1", 24),
        state_action=SyscallStateAction.SIGNAL_ALTSTACK,
    ),
    133: _reject(133, "rt_sigsuspend", "interrupted system-call restart is not modeled"),
    134: _direct(
        134,
        "rt_sigaction",
        _fixed("x2", 32),
        state_action=SyscallStateAction.SIGNAL_ACTION,
    ),
    135: _direct(
        135,
        "rt_sigprocmask",
        _register("x2", "x3"),
        state_action=SyscallStateAction.SIGNAL_MASK,
    ),
    136: _direct(136, "rt_sigpending", _register("x0", "x1")),
    137: _direct(137, "rt_sigtimedwait", _fixed("x1", 128)),
    138: _recorded(138, "rt_sigqueueinfo"),
    139: _execute(
        139,
        "rt_sigreturn",
        state_action=SyscallStateAction.RETURN_FROM_SIGNAL,
    ),
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
