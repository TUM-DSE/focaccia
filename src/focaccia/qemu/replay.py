"""Fail-closed, architecture-dispatched deterministic replay engines.

This module contains no GDB dependency. Tests drive it through in-memory fake
targets; ``qemu.target`` supplies the thin debugger adapter. x86-64 includes
fixture-backed signal handling, while the bounded AArch64 baseline explicitly
rejects signal delivery and return before target mutation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from focaccia.arch import Arch
from focaccia.deterministic import (
    DeterministicLogError,
    Event,
    ExtraRegisterState,
    SignalEvent,
    SyscallEvent,
)
from focaccia.qemu.concurrency import reject_thread_creating_effect
from focaccia.qemu.deterministic import syscall_policies
from focaccia.qemu.syscall import (
    CoverageOutcome,
    DescriptorOffsetReplayEffect,
    DescriptorReplayEffect,
    ExecutionGuard,
    KernelReplayEffect,
    MappingReplayEffect,
    MaterializedMemoryWrite,
    MemoryReplayEffect,
    OpenedDescriptorReplayEffect,
    ReconcileMode,
    RegisterReplayEffect,
    ReplayCoverage,
    ReplayCoverageReport,
    ReplayError,
    ReplayEventError,
    ReplayReconciliationError,
    ReplayStrategy,
    SignalActionReplayEffect,
    SignalAltstackReplayEffect,
    SignalMaskReplayEffect,
    SocketAddressReplayEffect,
    SyscallPolicy,
    SyscallReplayContext,
    SyscallStateAction,
    TerminationReplayEffect,
    UnsupportedReplayEffect,
)
from focaccia.qemu.aarch64 import (
    EXIT_GROUP_SYSCALL as AARCH64_EXIT_GROUP_SYSCALL,
    PC_REGISTER as AARCH64_PC_REGISTER,
    RESULT_REGISTER as AARCH64_RESULT_REGISTER,
    SYSCALL_ARGUMENT_REGISTERS as AARCH64_SYSCALL_ARGUMENT_REGISTERS,
    SYSCALL_EXECUTION_BOUNDARY_REGISTERS as AARCH64_EXECUTION_BOUNDARY_REGISTERS,
    SYSCALL_NUMBER_REGISTER as AARCH64_SYSCALL_NUMBER_REGISTER,
    SYSCALL_RECORDED_RESULT_REGISTERS as AARCH64_RECORDED_RESULT_REGISTERS,
    THREAD_CREATING_SYSCALLS as AARCH64_THREAD_CREATING_SYSCALLS,
    AArch64KernelSigaction,
    AArch64RecordedSignalFrame,
)
from focaccia.qemu.x86 import (
    SYSCALL_ARGUMENT_REGISTERS as X86_64_SYSCALL_ARGUMENT_REGISTERS,
    SYSCALL_NUMBER_REGISTER as X86_64_SYSCALL_NUMBER_REGISTER,
    SYSCALL_RECORDED_RESULT_REGISTERS as X86_64_RECORDED_RESULT_REGISTERS,
    X86KernelSigaction,
    X86RecordedSignalFrame,
)
from focaccia.snapshot import MemoryAccessError, ReadableProgramState, RegisterAccessError


_THREAD_CREATING_SYSCALLS = frozenset((56, 57, 58, 435))
_AARCH64_GPRS = tuple(f"x{index}" for index in range(31)) + ("sp", "pc", "cpsr")
_X86_GPRS = (
    "r15",
    "r14",
    "r13",
    "r12",
    "rbp",
    "rbx",
    "r11",
    "r10",
    "r9",
    "r8",
    "rax",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rip",
    "rsp",
)
_MAP_ANONYMOUS = 0x20
_MAP_FIXED_NOREPLACE = 0x100000
_SA_RESTART = 0x10000000
_SA_NODEFER = 0x40000000
_SA_RESETHAND = 0x80000000
_SIG_BLOCK = 0
_SIG_UNBLOCK = 1
_SIG_SETMASK = 2
_BLOCKABLE_SIGNAL_MASK = ((1 << 64) - 1) & ~((1 << (9 - 1)) | (1 << (19 - 1)))


def validate_x86_partial_signal_extra_transition(
    previous: ExtraRegisterState | None,
    handler: ExtraRegisterState | None,
) -> ExtraRegisterState:
    """Require all non-GDB-writable x86 signal state to remain unchanged.

    QEMU's historical x86 GDB stubs expose MXCSR and XMM0--XMM15, but not the
    complete XSAVE state. A signal transition is replayable through that
    interface only when every other live component is byte-for-byte unchanged.
    The XSAVE SSE-in-use bit and the non-live MXCSR capability mask may change
    as consequences or metadata of restoring MXCSR and the XMM values.
    """
    if previous is None or previous.format != "x86-xsave-v1":
        raise ReplayEventError("x86 signal pre-event lacks recorded XSAVE state.")
    if handler is None or handler.format != "x86-xsave-v1":
        raise ReplayEventError("x86 signal-handler event lacks recorded XSAVE state.")
    if previous.arch != handler.arch or len(previous.raw) != len(handler.raw):
        raise ReplayEventError("x86 signal XSAVE payload layout changes at delivery.")

    before = bytearray(previous.raw)
    after = bytearray(handler.raw)
    # MXCSR and the sixteen architectural XMM registers are writable through
    # every pinned x86-64 QEMU GDB stub used by the evaluator.
    before[24:28] = after[24:28]
    before[160:416] = after[160:416]
    # MXCSR_MASK and the tail of the legacy FXSAVE area are capability or
    # software-reserved metadata, not live execution state.
    before[28:32] = after[28:32]
    before[416:512] = after[416:512]
    if len(before) >= 576:
        previous_bv = int.from_bytes(before[512:520], "little")
        handler_bv = int.from_bytes(after[512:520], "little")
        if (previous_bv ^ handler_bv) & ~(1 << 1):
            raise UnsupportedReplayEffect(
                "x86 signal delivery changes an XSAVE component unavailable through "
                "the QEMU GDB stub."
            )
        before[512:520] = after[512:520]
    if before != after:
        raise UnsupportedReplayEffect(
            "x86 signal delivery changes x87 or extended XSAVE state unavailable "
            "through the QEMU GDB stub."
        )
    return handler


class ReplayTarget(Protocol):
    """Mutation/execution boundary needed by a deterministic replay engine."""

    @property
    def arch(self) -> Arch: ...

    def current_state(self) -> ReadableProgramState: ...

    def skip(self, new_pc: int) -> None: ...

    def write_target_register(self, register: str, value: int) -> None: ...

    def write_target_memory(self, address: int, data: bytes) -> None: ...

    def write_signal_handler_extra_registers(
        self,
        extra_registers: ExtraRegisterState,
    ) -> None: ...

    def execute_replay_instruction(
        self, expected_pc: int | None = None
    ) -> ReadableProgramState | None: ...

    def is_exited(self) -> bool: ...


# Compatibility name retained for existing type annotations and callers.
X86ReplayTarget = ReplayTarget


@dataclass(frozen=True, slots=True)
class VirtualDescriptor:
    fd: int
    kind: str
    source_event: int


SignalAction = X86KernelSigaction | AArch64KernelSigaction
RecordedSignalFrame = X86RecordedSignalFrame | AArch64RecordedSignalFrame


@dataclass(frozen=True, slots=True)
class DeliveredSignal:
    frame: RecordedSignalFrame
    action: SignalAction
    handler_pc: int


@dataclass(frozen=True, slots=True)
class ReplayStateSnapshot:
    descriptors: Mapping[int, VirtualDescriptor]
    descriptor_offsets: Mapping[int, int]
    socket_addresses: Mapping[int, tuple[bytes, bytes]]
    signal_actions: Mapping[int, SignalAction]
    signal_mask: int
    signal_depth: int
    terminated: bool


class X86ReplayState:
    """Kernel-visible state virtualized by recorded-replay handlers."""

    def __init__(self) -> None:
        self.descriptors: dict[int, VirtualDescriptor] = {
            fd: VirtualDescriptor(fd, "inherited", 0) for fd in (0, 1, 2)
        }
        self.descriptor_offsets: dict[int, int] = {}
        self.socket_addresses: dict[int, tuple[bytes, bytes]] = {}
        self.signal_actions: dict[int, SignalAction] = {}
        self.signal_mask = 0
        self.signal_frames: list[DeliveredSignal] = []
        self.altstack: bytes | None = None
        self.terminated = False

    def snapshot(self) -> ReplayStateSnapshot:
        return ReplayStateSnapshot(
            MappingProxyType(dict(self.descriptors)),
            MappingProxyType(dict(self.descriptor_offsets)),
            MappingProxyType(dict(self.socket_addresses)),
            MappingProxyType(dict(self.signal_actions)),
            self.signal_mask,
            len(self.signal_frames),
            self.terminated,
        )


class X86ReplayEngine:
    """Classify and apply deterministic x86-64 actions without live-host fallback."""

    syscall_number_register = X86_64_SYSCALL_NUMBER_REGISTER
    syscall_argument_registers = X86_64_SYSCALL_ARGUMENT_REGISTERS
    recorded_result_registers = X86_64_RECORDED_RESULT_REGISTERS
    execution_boundary_registers: tuple[str, ...] = ()
    execution_control_registers = ("rcx", "r11")
    result_register = "rax"
    pc_register = "rip"
    thread_creating_syscalls = _THREAD_CREATING_SYSCALLS
    exit_group_syscall = 231

    def __init__(self, arch: Arch):
        if arch.archname != "x86_64" or arch.endianness != "little":
            raise UnsupportedReplayEffect(
                f"Deterministic replay is unsupported for {arch.serialized_name}."
            )
        self.arch = arch
        self.policies = syscall_policies[arch.archname]
        self.state = X86ReplayState()
        self.coverage = ReplayCoverage()

    def coverage_report(self) -> ReplayCoverageReport:
        return self.coverage.report()

    def prepare_syscall(self, event: SyscallEvent) -> SyscallPolicy:
        """Validate and classify a pre-event before consuming its post-event."""
        policy = self.policies.get(event.syscall_number)
        try:
            self._validate_pre_event(event)
        except UnsupportedReplayEffect as error:
            self.coverage.record(
                event_count=event.event_count,
                effect=f"syscall:{event.syscall_number}",
                strategy=ReplayStrategy.REJECT,
                outcome=CoverageOutcome.REJECTED,
                detail=str(error),
            )
            raise
        except ReplayError as error:
            self.coverage.record(
                event_count=event.event_count,
                effect=f"syscall:{event.syscall_number}",
                strategy=(policy.strategy if policy is not None else ReplayStrategy.REJECT),
                outcome=CoverageOutcome.FAILED,
                detail=str(error),
            )
            raise
        if policy is None:
            message = (
                f"Unclassified {self.arch.serialized_name} system call "
                f"{event.syscall_number} at RR event {event.event_count}; "
                "deterministic replay refuses live execution."
            )
            self.coverage.record(
                event_count=event.event_count,
                effect=f"syscall:{event.syscall_number}",
                strategy=ReplayStrategy.REJECT,
                outcome=CoverageOutcome.REJECTED,
                detail="unclassified system call",
            )
            raise UnsupportedReplayEffect(
                message,
                event_count=event.event_count,
                syscall_number=event.syscall_number,
            )
        if policy.strategy is ReplayStrategy.REJECT:
            self.coverage.record(
                event_count=event.event_count,
                effect=f"syscall:{policy.name}",
                strategy=policy.strategy,
                outcome=CoverageOutcome.REJECTED,
                detail=policy.reject_reason,
            )
            if policy.number in self.thread_creating_syscalls:
                reject_thread_creating_effect(policy.name)
            raise UnsupportedReplayEffect(
                f"System call {policy.name} ({policy.number}) is rejected: {policy.reject_reason}.",
                event_count=event.event_count,
                syscall_number=policy.number,
                syscall_name=policy.name,
            )
        return policy

    def replay_syscall(
        self,
        target: X86ReplayTarget,
        pre_event: SyscallEvent,
        post_event: SyscallEvent | None,
        *,
        policy: SyscallPolicy | None = None,
    ) -> ReadableProgramState:
        selected = policy or self.prepare_syscall(pre_event)
        try:
            state = self._replay_classified_syscall(
                target,
                pre_event,
                post_event,
                policy=selected,
            )
        except StopIteration:
            # Terminal execution records its handled effect before stopping.
            raise
        except UnsupportedReplayEffect as error:
            self.coverage.record(
                event_count=pre_event.event_count,
                effect=f"syscall:{selected.name}",
                strategy=ReplayStrategy.REJECT,
                outcome=CoverageOutcome.REJECTED,
                detail=str(error),
            )
            raise
        except (
            ReplayError,
            DeterministicLogError,
            RegisterAccessError,
            MemoryAccessError,
        ) as error:
            self.coverage.record(
                event_count=pre_event.event_count,
                effect=f"syscall:{selected.name}",
                strategy=selected.strategy,
                outcome=CoverageOutcome.FAILED,
                detail=str(error),
            )
            raise
        self.coverage.record(
            event_count=pre_event.event_count,
            effect=f"syscall:{selected.name}",
            strategy=selected.strategy,
            outcome=CoverageOutcome.HANDLED,
        )
        return state

    def _replay_classified_syscall(
        self,
        target: X86ReplayTarget,
        pre_event: SyscallEvent,
        post_event: SyscallEvent | None,
        *,
        policy: SyscallPolicy,
    ) -> ReadableProgramState:
        self._validate_target_arch(target)
        target_state = target.current_state()
        self._validate_target_entry(target_state, pre_event)

        if policy.state_action is SyscallStateAction.TERMINATE:
            if post_event is not None:
                raise ReplayEventError(
                    f"Terminal system call {policy.name} unexpectedly has a post-event."
                )
            return self._execute_termination(target, target_state, pre_event, policy)
        if post_event is None:
            raise ReplayEventError(f"System call {policy.name} has no post-event.")

        self._validate_pair(pre_event, post_event, policy)
        if policy.state_action is SyscallStateAction.RETURN_FROM_SIGNAL:
            self._validate_signal_return_entry(target_state)
        writes = self._materialize_writes(post_event)
        result = _signed_u64(self._event_register(post_event, self.result_register))
        context = SyscallReplayContext(pre_event, post_event, target_state, result)
        memory_effects = policy.outputs.plan(context, writes)
        self._check_execution_guard(policy, context)

        if policy.strategy is ReplayStrategy.RECORDED:
            register_effects = self._recorded_register_effects(post_event, policy)
            kernel_effects = self._plan_kernel_effects(
                policy,
                context,
                memory_effects,
            )
            self._apply_recorded_effects(
                target,
                post_event,
                register_effects,
                memory_effects,
            )
            self._apply_kernel_effects(policy, context, kernel_effects, memory_effects)
            return target.current_state()

        if policy.strategy in (
            ReplayStrategy.EXECUTE_RECONCILE,
            ReplayStrategy.SAFE_PASSTHROUGH,
        ):
            execution_inputs, execution_restores = self._plan_execution_registers(
                policy,
                context,
            )
            for effect in execution_inputs:
                target.write_target_register(effect.register, effect.value)
            state = target.execute_replay_instruction(post_event.pc)
            if state is None or target.is_exited():
                raise ReplayReconciliationError(
                    f"System call {policy.name} terminated the target unexpectedly."
                )
            control_effects = self._recorded_execution_control_effects(post_event)
            apply_recorded = policy.reconcile is ReconcileMode.APPLY_RECORDED or (
                policy.reconcile is ReconcileMode.APPLY_RECORDED_ON_ZERO_ARGUMENT
                and context.target_state.read_register(self.syscall_argument_registers[0]) == 0
            )
            if apply_recorded:
                self._reconcile_execution_boundary(state, post_event)
                self._apply_recorded_effects(
                    target,
                    post_event,
                    (
                        RegisterReplayEffect(
                            self.result_register,
                            self._event_register(post_event, self.result_register),
                        ),
                        *control_effects,
                        *execution_restores,
                    ),
                    memory_effects,
                    set_pc=False,
                )
                state = target.current_state()
            else:
                self._reconcile_exact(
                    state,
                    post_event,
                    memory_effects,
                    policy.exact_post_registers,
                )
                self._apply_recorded_effects(
                    target,
                    post_event,
                    (*control_effects, *execution_restores),
                    (),
                    set_pc=False,
                )
                state = target.current_state()
            if policy.state_action is SyscallStateAction.RETURN_FROM_SIGNAL:
                self._finish_signal_return(state, post_event)
            kernel_effects = self._plan_kernel_effects(
                policy,
                context,
                memory_effects,
            )
            self._apply_kernel_effects(policy, context, kernel_effects, memory_effects)
            return state

        raise RuntimeError(f"Unhandled replay strategy {policy.strategy}.")

    def replay_signal(
        self,
        target: X86ReplayTarget,
        pre_event: SignalEvent,
        post_event: SignalEvent,
    ) -> ReadableProgramState | None:
        effect_name = f"signal:{pre_event.descriptor.signal_number}"
        disposition = post_event.descriptor.disposition
        strategy = (
            ReplayStrategy.SAFE_PASSTHROUGH
            if disposition == "ignored"
            else ReplayStrategy.REJECT
            if disposition == "fatal"
            else ReplayStrategy.RECORDED
        )
        try:
            return self._replay_signal(target, pre_event, post_event)
        except UnsupportedReplayEffect as error:
            self.coverage.record(
                event_count=pre_event.event_count,
                effect=effect_name,
                strategy=ReplayStrategy.REJECT,
                outcome=CoverageOutcome.REJECTED,
                detail=str(error),
            )
            raise
        except (
            ReplayError,
            DeterministicLogError,
            RegisterAccessError,
            MemoryAccessError,
        ) as error:
            self.coverage.record(
                event_count=pre_event.event_count,
                effect=effect_name,
                strategy=strategy,
                outcome=CoverageOutcome.FAILED,
                detail=str(error),
            )
            raise

    def _replay_signal(
        self,
        target: X86ReplayTarget,
        pre_event: SignalEvent,
        post_event: SignalEvent,
    ) -> ReadableProgramState | None:
        self._validate_target_arch(target)
        if pre_event.arch != self.arch or post_event.arch != self.arch:
            raise ReplayEventError("Signal events use a different architecture.")
        if pre_event.tid != post_event.tid:
            raise ReplayEventError("Signal events use different thread IDs.")
        if pre_event.signal_variant != "signal":
            raise ReplayEventError("Signal replay requires a signal pre-event.")
        if pre_event.mem_writes:
            raise ReplayEventError("A signal pre-event unexpectedly writes memory.")
        if pre_event.descriptor.arch != self.arch or post_event.descriptor.arch != self.arch:
            raise ReplayEventError("Signal descriptors use a different architecture.")
        if pre_event.descriptor != post_event.descriptor:
            raise ReplayEventError("Paired signal events contain different descriptors.")
        if pre_event.pc is None or post_event.pc is None:
            raise ReplayEventError("Signal replay requires pre/post program counters.")

        target_state = target.current_state()
        if target_state.read_pc() != pre_event.pc:
            raise ReplayEventError(
                f"Signal event expects PC {pre_event.pc:#x}, target has "
                f"{target_state.read_pc():#x}."
            )
        signal_number = pre_event.descriptor.signal_number
        effect_name = f"signal:{signal_number}"

        if post_event.descriptor.disposition == "ignored":
            if post_event.signal_variant != "signalDelivery" or post_event.mem_writes:
                raise ReplayEventError("Ignored signal has handler-frame effects.")
            self._reconcile_event_registers(target_state, post_event, _X86_GPRS)
            self.coverage.record(
                event_count=pre_event.event_count,
                effect=effect_name,
                strategy=ReplayStrategy.SAFE_PASSTHROUGH,
                outcome=CoverageOutcome.HANDLED,
                detail="ignored signal",
            )
            return None
        if post_event.descriptor.disposition == "fatal":
            raise UnsupportedReplayEffect(
                f"Fatal signal {signal_number} delivery is unsupported.",
                event_count=pre_event.event_count,
            )

        action = self.state.signal_actions.get(signal_number)
        if action is None or action.handler in (0, 1):
            raise UnsupportedReplayEffect(
                f"Signal {signal_number} has no replayed user action.",
                event_count=pre_event.event_count,
            )
        writes = self._materialize_writes(post_event)
        frame = X86RecordedSignalFrame.from_events(
            pre_event,
            post_event,
            writes,
            action_uses_siginfo=bool(action.flags & X86KernelSigaction.SA_SIGINFO),
            action_restarts_syscalls=bool(action.flags & _SA_RESTART),
        )
        if target_state.read_register("rsp") != self._event_register(pre_event, "rsp"):
            raise ReplayReconciliationError(
                "Signal-frame replay currently requires the target and RR stack addresses "
                "to match exactly."
            )
        self._reconcile_event_registers(
            target_state,
            pre_event,
            {
                register: self._event_register(pre_event, register)
                for register in frame.saved_registers
            },
        )
        if post_event.pc != action.handler:
            raise ReplayEventError(
                f"Signal handler PC {post_event.pc:#x} differs from rt_sigaction handler "
                f"{action.handler:#x}."
            )
        if frame.restorer_address != action.restorer:
            raise ReplayEventError(
                f"Signal frame restorer {frame.restorer_address:#x} differs from "
                f"rt_sigaction restorer {action.restorer:#x}."
            )
        if frame.signal_mask != self.state.signal_mask:
            raise ReplayEventError(
                f"Signal frame saves mask {frame.signal_mask:#x}, replay state has "
                f"{self.state.signal_mask:#x}."
            )

        # Historical QEMU GDB stubs can write the legacy SSE state but not the
        # complete XSAVE payload. Permit that partial transfer only when every
        # unavailable component is unchanged across signal delivery.
        handler_extra = validate_x86_partial_signal_extra_transition(
            pre_event.extra_registers,
            post_event.extra_registers,
        )
        target.write_signal_handler_extra_registers(handler_extra)

        # All frame bytes, including siginfo, mask, reserved words, and the
        # complete recorded FXSAVE/XSTATE area, are known before the first write.
        for write in writes:
            target.write_target_memory(write.recorded_address, write.data)
        target.skip(post_event.pc)
        for register in ("rax", "rdi", "rsi", "rdx", "rsp", "rflags"):
            target.write_target_register(register, self._event_register(post_event, register))

        self.state.signal_frames.append(DeliveredSignal(frame, action, post_event.pc))
        signal_bit = 1 << (signal_number - 1)
        self.state.signal_mask |= action.mask & _BLOCKABLE_SIGNAL_MASK
        if action.flags & _SA_NODEFER == 0:
            self.state.signal_mask |= signal_bit
        if action.flags & _SA_RESETHAND:
            self.state.signal_actions[signal_number] = X86KernelSigaction(0, 0, 0, 0)
        self.coverage.record(
            event_count=pre_event.event_count,
            effect=effect_name,
            strategy=ReplayStrategy.RECORDED,
            outcome=CoverageOutcome.HANDLED,
            detail=(
                "recorded frame and MXCSR/XMM state; unchanged x87 and extended "
                "XSAVE state preserved"
            ),
        )
        return target.current_state()

    def replay_bookkeeping_event(
        self,
        target: X86ReplayTarget,
        event: Event,
    ) -> None:
        """Handle the sole explicit no-op RR event in single-thread mode."""
        effect_name = f"rr-event:{event.event_type}"
        strategy = (
            ReplayStrategy.SAFE_PASSTHROUGH
            if event.event_type == "sched"
            else ReplayStrategy.REJECT
        )
        try:
            self._replay_bookkeeping_event(target, event)
        except UnsupportedReplayEffect as error:
            self.coverage.record(
                event_count=event.event_count,
                effect=effect_name,
                strategy=ReplayStrategy.REJECT,
                outcome=CoverageOutcome.REJECTED,
                detail=str(error),
            )
            raise
        except (
            ReplayError,
            DeterministicLogError,
            RegisterAccessError,
            MemoryAccessError,
        ) as error:
            self.coverage.record(
                event_count=event.event_count,
                effect=effect_name,
                strategy=strategy,
                outcome=CoverageOutcome.FAILED,
                detail=str(error),
            )
            raise

    def _replay_bookkeeping_event(
        self,
        target: X86ReplayTarget,
        event: Event,
    ) -> None:
        self._validate_target_arch(target)
        if event.event_type != "sched":
            raise UnsupportedReplayEffect(
                f"RR event {event.event_count} ({event.event_type}) has no replay policy.",
                event_count=event.event_count,
            )
        if event.mem_writes:
            raise ReplayEventError("A scheduler event unexpectedly writes user memory.")
        state = target.current_state()
        if event.pc is None or state.read_pc() != event.pc:
            raise ReplayEventError("Scheduler event does not match the target PC.")
        self.coverage.record(
            event_count=event.event_count,
            effect="rr-event:sched",
            strategy=ReplayStrategy.SAFE_PASSTHROUGH,
            outcome=CoverageOutcome.HANDLED,
            detail="single-thread scheduler marker",
        )
        return None

    def _validate_target_arch(self, target: X86ReplayTarget) -> None:
        if target.arch != self.arch:
            raise ReplayEventError("Replay target architecture changed.")

    def _validate_pre_event(self, event: SyscallEvent) -> None:
        if event.arch != self.arch or event.syscall_arch != self.arch:
            raise UnsupportedReplayEffect(
                f"System call {event.syscall_number} uses unsupported architecture "
                f"{event.syscall_arch.serialized_name}.",
                event_count=event.event_count,
                syscall_number=event.syscall_number,
            )
        if event.syscall_state not in ("entering", "enteringPtrace"):
            raise ReplayEventError(f"System-call pre-event has state {event.syscall_state!r}.")
        if event.mem_writes:
            raise ReplayEventError("A system-call entry event unexpectedly writes memory.")
        if event.failed_during_preparation:
            raise UnsupportedReplayEffect(
                f"System call {event.syscall_number} failed during RR preparation.",
                event_count=event.event_count,
                syscall_number=event.syscall_number,
            )
        if event.pc is None:
            raise ReplayEventError("System-call pre-event has no PC.")

    def _validate_target_entry(
        self,
        target_state: ReadableProgramState,
        event: SyscallEvent,
    ) -> None:
        if target_state.read_pc() != event.pc:
            raise ReplayEventError(
                f"System call expects PC {event.pc:#x}, target has {target_state.read_pc():#x}."
            )
        observed_number = target_state.read_register(self.syscall_number_register)
        if observed_number != event.syscall_number:
            raise ReplayEventError(
                f"RR records system call {event.syscall_number}, target requests {observed_number}."
            )

    def _validate_pair(
        self,
        pre_event: SyscallEvent,
        post_event: SyscallEvent,
        policy: SyscallPolicy,
    ) -> None:
        if post_event.arch != self.arch or post_event.syscall_arch != self.arch:
            raise ReplayEventError("System-call post-event uses a different architecture.")
        if post_event.tid != pre_event.tid:
            raise ReplayEventError("System-call pair changes thread ID.")
        if post_event.syscall_number != policy.number:
            raise ReplayEventError("System-call pair changes call number.")
        if post_event.syscall_state != "exiting":
            raise ReplayEventError(
                f"System-call post-event has state {post_event.syscall_state!r}."
            )
        if post_event.failed_during_preparation:
            raise ReplayEventError("System-call post-event reports preparation failure.")
        if pre_event.syscall_extras.kind != "none":
            raise ReplayEventError("A system-call entry event unexpectedly carries extras.")
        extra_kind = post_event.syscall_extras.kind
        if extra_kind not in policy.allowed_extras:
            raise UnsupportedReplayEffect(
                f"System call {policy.name} has unsupported RR extra effect {extra_kind!r}.",
                event_count=post_event.event_count,
                syscall_number=policy.number,
                syscall_name=policy.name,
            )
        if post_event.pc is None:
            raise ReplayEventError("System-call post-event has no PC.")
        if self._event_register(post_event, self.pc_register) != post_event.pc:
            raise ReplayEventError(
                f"System-call post-event {self.pc_register.upper()} differs from its PC."
            )

    @staticmethod
    def _materialize_writes(event: Event) -> tuple[MaterializedMemoryWrite, ...]:
        writes = tuple(MaterializedMemoryWrite.from_recorded(write) for write in event.mem_writes)
        for write in writes:
            if write.tid != event.tid:
                raise ReplayEventError(
                    f"Memory write uses TID {write.tid}, event uses {event.tid}."
                )
        return writes

    @staticmethod
    def _event_register(event: Event, register: str) -> int:
        try:
            return event.registers[register]
        except KeyError as error:
            raise ReplayEventError(
                f"RR event {event.event_count} lacks required register {register}."
            ) from error

    def _recorded_register_effects(
        self,
        post_event: SyscallEvent,
        policy: SyscallPolicy,
    ) -> tuple[RegisterReplayEffect, ...]:
        registers = tuple(
            dict.fromkeys((*self.recorded_result_registers, *policy.recorded_post_registers))
        )
        return tuple(
            RegisterReplayEffect(register, self._event_register(post_event, register))
            for register in registers
        )

    def _plan_execution_registers(
        self,
        policy: SyscallPolicy,
        context: SyscallReplayContext,
    ) -> tuple[tuple[RegisterReplayEffect, ...], tuple[RegisterReplayEffect, ...]]:
        """Plan temporary syscall inputs and their recorded post-event restoration."""
        if policy.number != 9 or context.result < 0:
            return (), ()
        address_register = self.syscall_argument_registers[0]
        flags_register = self.syscall_argument_registers[3]
        if context.target_state.read_register(address_register) != 0:
            return (), ()
        if context.result == 0 or context.result & 0xFFF:
            raise ReplayEventError(
                "Successful anonymous mmap(NULL) has an invalid recorded address."
            )
        flags = context.target_state.read_register(flags_register)
        inputs = (
            RegisterReplayEffect(address_register, context.result),
            RegisterReplayEffect(flags_register, flags | _MAP_FIXED_NOREPLACE),
        )
        restores = tuple(
            RegisterReplayEffect(
                register,
                self._event_register(context.post_event, register),
            )
            for register in (address_register, flags_register)
        )
        return inputs, restores

    def _recorded_execution_control_effects(
        self,
        post_event: SyscallEvent,
    ) -> tuple[RegisterReplayEffect, ...]:
        return tuple(
            RegisterReplayEffect(register, self._event_register(post_event, register))
            for register in self.execution_control_registers
        )

    @staticmethod
    def _apply_recorded_effects(
        target: X86ReplayTarget,
        post_event: SyscallEvent,
        register_effects: Sequence[RegisterReplayEffect],
        memory_effects: Sequence[MemoryReplayEffect],
        *,
        set_pc: bool = True,
    ) -> None:
        if set_pc:
            if post_event.pc is None:
                raise ReplayEventError("Cannot replay an absent post-event PC.")
            target.skip(post_event.pc)
        for effect in register_effects:
            target.write_target_register(effect.register, effect.value)
        for effect in memory_effects:
            target.write_target_memory(effect.target_address, effect.data)

    def _reconcile_execution_boundary(
        self,
        state: ReadableProgramState,
        post_event: SyscallEvent,
    ) -> None:
        if post_event.pc is None or state.read_pc() != post_event.pc:
            raise ReplayReconciliationError(
                f"Executed system call reached {state.read_pc():#x}, expected {post_event.pc!r}."
            )
        self._reconcile_event_registers(
            state,
            post_event,
            self.execution_boundary_registers,
        )

    def _reconcile_exact(
        self,
        state: ReadableProgramState,
        post_event: SyscallEvent,
        memory_effects: Sequence[MemoryReplayEffect],
        extra_registers: Sequence[str],
    ) -> None:
        self._reconcile_execution_boundary(state, post_event)
        self._reconcile_event_registers(
            state,
            post_event,
            (self.result_register, *extra_registers),
        )
        for effect in memory_effects:
            actual = state.read_memory(effect.target_address, len(effect.data))
            if actual != effect.data:
                raise ReplayReconciliationError(
                    f"Executed system call produced different bytes at {effect.target_address:#x}."
                )

    def _reconcile_event_registers(
        self,
        state: ReadableProgramState,
        event: Event,
        registers: Sequence[str] | Mapping[str, int],
    ) -> None:
        if isinstance(registers, Mapping):
            expected_values = registers.items()
        else:
            expected_values = (
                (register, self._event_register(event, register)) for register in registers
            )
        for register, expected in expected_values:
            actual = state.read_register(register)
            if actual != expected:
                raise ReplayReconciliationError(
                    f"RR event {event.event_count} expects {register}={expected:#x}, "
                    f"target has {actual:#x}."
                )

    def _check_execution_guard(
        self,
        policy: SyscallPolicy,
        context: SyscallReplayContext,
    ) -> None:
        for register, allowed in policy.allowed_argument_values:
            recorded = self._event_register(context.pre_event, register)
            target = context.target_state.read_register(register)
            if recorded not in allowed or target not in allowed or target != recorded:
                encoded = ", ".join(f"{value:#x}" for value in allowed)
                raise ReplayEventError(
                    f"System call {policy.name} requires {register} in ({encoded}); "
                    f"RR recorded {recorded:#x}, target has {target:#x}."
                )
        for register in policy.execution_arguments:
            recorded = self._event_register(context.pre_event, register)
            target = context.target_state.read_register(register)
            if target != recorded:
                raise ReplayEventError(
                    f"Executed system call {policy.name} argument {register} differs: "
                    f"RR recorded {recorded:#x}, target has {target:#x}."
                )
        if policy.execution_guard is ExecutionGuard.NONE:
            return
        if policy.execution_guard is ExecutionGuard.ANONYMOUS_MMAP:
            flags_register = self.syscall_argument_registers[3]
            fd_register = self.syscall_argument_registers[4]
            recorded_flags = self._event_register(context.pre_event, flags_register)
            target_flags = context.target_state.read_register(flags_register)
            recorded_fd = _signed_u64(self._event_register(context.pre_event, fd_register))
            target_fd = _signed_u64(context.target_state.read_register(fd_register))
            if target_flags != recorded_flags or target_fd != recorded_fd:
                raise ReplayEventError("mmap flags or descriptor differ from RR.")
            if recorded_flags & _MAP_ANONYMOUS == 0 or recorded_fd != -1:
                raise UnsupportedReplayEffect(
                    "Only anonymous mmap can execute during deterministic replay.",
                    event_count=context.pre_event.event_count,
                    syscall_number=policy.number,
                    syscall_name=policy.name,
                )
            return
        raise RuntimeError(f"Unhandled execution guard {policy.execution_guard}.")

    def _plan_kernel_effects(
        self,
        policy: SyscallPolicy,
        context: SyscallReplayContext,
        memory_effects: Sequence[MemoryReplayEffect],
    ) -> tuple[KernelReplayEffect, ...]:
        action = policy.state_action
        result = context.result
        effects: list[KernelReplayEffect] = []
        if action in (SyscallStateAction.NONE, SyscallStateAction.RETURN_FROM_SIGNAL):
            pass
        elif action in (
            SyscallStateAction.OPEN_FD,
            SyscallStateAction.SOCKET_FD,
            SyscallStateAction.ACCEPT_FD,
        ):
            descriptors = (result,) if result >= 0 else ()
            effects.append(DescriptorReplayEffect(action, descriptors))
        elif action is SyscallStateAction.CLOSE_FD:
            fd = _signed_u64(
                self._event_register(context.pre_event, self.syscall_argument_registers[0])
            )
            descriptors = (fd,) if result == 0 else ()
            effects.append(DescriptorReplayEffect(action, descriptors))
        elif action is SyscallStateAction.DUP_FD:
            descriptors = (result,) if result >= 0 else ()
            effects.append(DescriptorReplayEffect(action, descriptors))
        elif action is SyscallStateAction.PIPE_FDS:
            if result != 0:
                effects.append(DescriptorReplayEffect(action, ()))
            else:
                payload = b"".join(effect.data for effect in memory_effects)
                if len(payload) != 8:
                    raise ReplayEventError(
                        f"Successful {policy.name} must replay exactly two int32 descriptors."
                    )
                descriptors = tuple(
                    int.from_bytes(payload[offset : offset + 4], "little", signed=True)
                    for offset in (0, 4)
                )
                if any(fd < 0 for fd in descriptors):
                    raise ReplayEventError(f"{policy.name} returned a negative descriptor.")
                effects.append(DescriptorReplayEffect(action, descriptors))
        elif action is SyscallStateAction.SIGNAL_ACTION:
            effect = self._plan_signal_action(context, memory_effects)
            if effect is not None:
                effects.append(effect)
        elif action is SyscallStateAction.SIGNAL_MASK:
            effect = self._plan_signal_mask(context, memory_effects)
            if effect is not None:
                effects.append(effect)
        elif action is SyscallStateAction.SIGNAL_ALTSTACK:
            effect = self._plan_signal_altstack(context)
            if effect is not None:
                effects.append(effect)
        elif action is SyscallStateAction.MEMORY_MAPPING:
            effects.append(
                MappingReplayEffect(
                    policy.number,
                    self._event_register(
                        context.pre_event,
                        self.syscall_argument_registers[0],
                    ),
                    self._event_register(
                        context.pre_event,
                        self.syscall_argument_registers[1],
                    ),
                )
            )
        elif action is SyscallStateAction.TERMINATE:
            effects.append(
                TerminationReplayEffect(
                    self._event_register(
                        context.pre_event,
                        self.syscall_argument_registers[0],
                    )
                    & 0xFF,
                    policy.number == self.exit_group_syscall,
                )
            )
        else:
            raise RuntimeError(f"Kernel effect {action} for {policy.name} was not implemented.")
        effects.extend(self._plan_syscall_extras(policy, context))
        return tuple(effects)

    def _apply_kernel_effects(
        self,
        policy: SyscallPolicy,
        context: SyscallReplayContext,
        effects: Sequence[KernelReplayEffect],
        memory_effects: Sequence[MemoryReplayEffect],
    ) -> None:
        del memory_effects
        for effect in effects:
            if isinstance(effect, DescriptorReplayEffect):
                if effect.operation is SyscallStateAction.CLOSE_FD:
                    for fd in effect.descriptors:
                        self.state.descriptors.pop(fd, None)
                        self.state.descriptor_offsets.pop(fd, None)
                        self.state.socket_addresses.pop(fd, None)
                else:
                    for fd in effect.descriptors:
                        self.state.descriptors[fd] = VirtualDescriptor(
                            fd,
                            policy.name,
                            context.pre_event.event_count,
                        )
            elif isinstance(effect, OpenedDescriptorReplayEffect):
                self.state.descriptors[effect.fd] = VirtualDescriptor(
                    effect.fd,
                    f"{policy.name}:{effect.path!r}",
                    context.pre_event.event_count,
                )
            elif isinstance(effect, DescriptorOffsetReplayEffect):
                self.state.descriptor_offsets[effect.fd] = effect.offset
            elif isinstance(effect, SocketAddressReplayEffect):
                self.state.socket_addresses[effect.fd] = (effect.local, effect.remote)
            elif isinstance(effect, SignalActionReplayEffect):
                if effect.action is not None:
                    if not isinstance(
                        effect.action,
                        (X86KernelSigaction, AArch64KernelSigaction),
                    ):
                        raise RuntimeError("Signal action effect has the wrong ABI type.")
                    self.state.signal_actions[effect.signal_number] = effect.action
            elif isinstance(effect, SignalMaskReplayEffect):
                self.state.signal_mask = effect.next_mask
            elif isinstance(effect, SignalAltstackReplayEffect):
                if effect.data is not None:
                    self.state.altstack = effect.data
            elif isinstance(effect, MappingReplayEffect):
                # Execution already reconciled the real QEMU mapping. Keeping
                # this typed effect in planning prevents it from being mistaken
                # for a pure register replay.
                pass
            elif isinstance(effect, TerminationReplayEffect):
                self.state.terminated = True
            else:
                raise RuntimeError(f"Unhandled kernel replay effect {effect!r}.")

    def _plan_syscall_extras(
        self,
        policy: SyscallPolicy,
        context: SyscallReplayContext,
    ) -> tuple[KernelReplayEffect, ...]:
        extra = context.post_event.syscall_extras
        if extra.kind == "none":
            return ()
        if extra.kind == "writeOffset":
            if extra.write_offset is None or extra.write_offset < 0:
                raise ReplayEventError("RR writeOffset extra has no valid offset.")
            fd = _signed_u64(
                self._event_register(context.pre_event, self.syscall_argument_registers[0])
            )
            if fd < 0:
                raise ReplayEventError("RR writeOffset extra uses a negative descriptor.")
            advance = max(context.result, 0) if policy.name in ("write", "writev") else 0
            return (DescriptorOffsetReplayEffect(fd, extra.write_offset + advance),)
        if extra.kind == "openedFds":
            if not extra.opened_fds:
                raise ReplayEventError("RR openedFds extra is empty.")
            effects: list[KernelReplayEffect] = []
            for opened in extra.opened_fds:
                if opened.fd < 0:
                    raise ReplayEventError("RR openedFds contains a negative descriptor.")
                if context.result >= 0 and opened.fd != context.result:
                    raise ReplayEventError(
                        f"RR opened descriptor {opened.fd} differs from result {context.result}."
                    )
                effects.append(
                    OpenedDescriptorReplayEffect(
                        opened.fd,
                        opened.path,
                        opened.device,
                        opened.inode,
                    )
                )
            return tuple(effects)
        if extra.kind == "socketAddrs":
            local = extra.socket_local_address
            remote = extra.socket_remote_address
            if local is None or remote is None:
                raise ReplayEventError("RR socketAddrs extra is incomplete.")
            if policy.state_action is SyscallStateAction.ACCEPT_FD:
                fd = context.result
            else:
                fd = _signed_u64(
                    self._event_register(
                        context.pre_event,
                        self.syscall_argument_registers[0],
                    )
                )
            if fd < 0:
                raise ReplayEventError("RR socketAddrs extra has no successful descriptor.")
            return (SocketAddressReplayEffect(fd, local, remote),)
        raise RuntimeError(
            f"Allowed RR extra {extra.kind!r} for {policy.name} has no state handler."
        )

    def _plan_signal_action(
        self,
        context: SyscallReplayContext,
        memory_effects: Sequence[MemoryReplayEffect],
    ) -> SignalActionReplayEffect | None:
        if context.result != 0:
            return None
        sigset_size = context.target_state.read_register("r10")
        if sigset_size != 8 or self._event_register(context.pre_event, "r10") != 8:
            raise UnsupportedReplayEffect(
                f"rt_sigaction sigset size {sigset_size} is unsupported.",
                event_count=context.pre_event.event_count,
                syscall_number=13,
                syscall_name="rt_sigaction",
            )
        signal_number = context.target_state.read_register("rdi")
        recorded_signal = self._event_register(context.pre_event, "rdi")
        if signal_number != recorded_signal or not 1 <= signal_number <= 64:
            raise ReplayEventError("rt_sigaction signal number differs or is invalid.")

        previous = self.state.signal_actions.get(
            signal_number,
            X86KernelSigaction(0, 0, 0, 0),
        )
        old_pointer = context.target_state.read_register("rdx")
        if old_pointer:
            actual_old = self._memory_effect_bytes(
                memory_effects,
                old_pointer,
                X86KernelSigaction.SIZE,
            )
            if actual_old != previous.to_bytes():
                raise ReplayEventError(
                    "rt_sigaction old-action output disagrees with replayed signal state."
                )

        action_pointer = context.target_state.read_register("rsi")
        action = None
        if action_pointer:
            action = X86KernelSigaction.from_bytes(
                context.target_state.read_memory(action_pointer, X86KernelSigaction.SIZE)
            )
        return SignalActionReplayEffect(signal_number, action)

    def _plan_signal_mask(
        self,
        context: SyscallReplayContext,
        memory_effects: Sequence[MemoryReplayEffect],
    ) -> SignalMaskReplayEffect | None:
        if context.result != 0:
            return None
        size = context.target_state.read_register("r10")
        if size != 8 or self._event_register(context.pre_event, "r10") != 8:
            raise UnsupportedReplayEffect(
                f"rt_sigprocmask sigset size {size} is unsupported.",
                event_count=context.pre_event.event_count,
                syscall_number=14,
                syscall_name="rt_sigprocmask",
            )
        old_pointer = context.target_state.read_register("rdx")
        if old_pointer:
            recorded_old = self._memory_effect_bytes(memory_effects, old_pointer, 8)
            if int.from_bytes(recorded_old, "little") != self.state.signal_mask:
                raise ReplayEventError(
                    "rt_sigprocmask old-mask output disagrees with replayed signal state."
                )
        how = _signed_u64(context.target_state.read_register("rdi"))
        if how != _signed_u64(self._event_register(context.pre_event, "rdi")):
            raise ReplayEventError("rt_sigprocmask operation differs from RR.")
        set_pointer = context.target_state.read_register("rsi")
        if set_pointer == 0:
            next_mask = self.state.signal_mask
        else:
            requested = (
                int.from_bytes(context.target_state.read_memory(set_pointer, 8), "little")
                & _BLOCKABLE_SIGNAL_MASK
            )
            if how == _SIG_BLOCK:
                next_mask = self.state.signal_mask | requested
            elif how == _SIG_UNBLOCK:
                next_mask = self.state.signal_mask & ~requested & ((1 << 64) - 1)
            elif how == _SIG_SETMASK:
                next_mask = requested
            else:
                raise ReplayEventError(f"Unknown rt_sigprocmask operation {how}.")
        return SignalMaskReplayEffect(self.state.signal_mask, next_mask)

    @staticmethod
    def _plan_signal_altstack(
        context: SyscallReplayContext,
    ) -> SignalAltstackReplayEffect | None:
        if context.result != 0:
            return None
        pointer = context.target_state.read_register("rdi")
        data = context.target_state.read_memory(pointer, 24) if pointer else None
        return SignalAltstackReplayEffect(data)

    @staticmethod
    def _memory_effect_bytes(
        effects: Sequence[MemoryReplayEffect],
        address: int,
        size: int,
    ) -> bytes:
        ordered = sorted(effects, key=lambda effect: effect.target_address)
        result = bytearray()
        cursor = address
        remaining = size
        for effect in ordered:
            start = effect.target_address
            end = start + len(effect.data)
            if end <= cursor:
                continue
            if start > cursor:
                break
            take = min(remaining, end - cursor)
            result.extend(effect.data[cursor - start : cursor - start + take])
            cursor += take
            remaining -= take
            if remaining == 0:
                return bytes(result)
        raise ReplayEventError(
            f"Recorded outputs do not contain [{address:#x}, {address + size:#x})."
        )

    def _validate_signal_return_entry(self, state: ReadableProgramState) -> None:
        if not self.state.signal_frames:
            raise ReplayEventError("rt_sigreturn has no delivered signal frame.")
        expected_rsp = self.state.signal_frames[-1].frame.frame_address + 8
        actual_rsp = state.read_register("rsp")
        if actual_rsp != expected_rsp:
            raise ReplayEventError(
                f"rt_sigreturn RSP is {actual_rsp:#x}, expected {expected_rsp:#x}."
            )

    def _finish_signal_return(
        self,
        state: ReadableProgramState,
        post_event: SyscallEvent,
    ) -> None:
        if not self.state.signal_frames:
            raise ReplayEventError("rt_sigreturn has no delivered signal frame.")
        delivered = self.state.signal_frames[-1]
        # The syscall-entry RSP was checked before execution. Checking the
        # complete restored GPR set proves that QEMU consumed this exact frame.
        self._reconcile_event_registers(state, post_event, _X86_GPRS)
        self.state.signal_frames.pop()
        self.state.signal_mask = delivered.frame.signal_mask
        self.state.altstack = delivered.frame.altstack

    def _execute_termination(
        self,
        target: X86ReplayTarget,
        target_state: ReadableProgramState,
        event: SyscallEvent,
        policy: SyscallPolicy,
    ) -> ReadableProgramState:
        context = SyscallReplayContext(event, event, target_state, 0)
        self._check_execution_guard(policy, context)
        effects = self._plan_kernel_effects(policy, context, ())
        state = target.execute_replay_instruction()
        if state is not None or not target.is_exited():
            raise ReplayReconciliationError(
                f"Terminal system call {policy.name} did not terminate the target."
            )
        self._apply_kernel_effects(policy, context, effects, ())
        self.coverage.record(
            event_count=event.event_count,
            effect=f"syscall:{policy.name}",
            strategy=policy.strategy,
            outcome=CoverageOutcome.HANDLED,
            detail="terminal effect",
        )
        raise StopIteration


class AArch64ReplayEngine(X86ReplayEngine):
    """Fixture-backed AArch64 syscall replay with fail-closed signals."""

    syscall_number_register = AARCH64_SYSCALL_NUMBER_REGISTER
    syscall_argument_registers = AARCH64_SYSCALL_ARGUMENT_REGISTERS
    recorded_result_registers = AARCH64_RECORDED_RESULT_REGISTERS
    execution_boundary_registers = AARCH64_EXECUTION_BOUNDARY_REGISTERS
    execution_control_registers: tuple[str, ...] = ()
    result_register = AARCH64_RESULT_REGISTER
    pc_register = AARCH64_PC_REGISTER
    thread_creating_syscalls = AARCH64_THREAD_CREATING_SYSCALLS
    exit_group_syscall = AARCH64_EXIT_GROUP_SYSCALL

    def __init__(self, arch: Arch):
        if arch.archname != "aarch64" or arch.endianness != "little":
            raise UnsupportedReplayEffect(
                f"Deterministic replay is unsupported for {arch.serialized_name}."
            )
        self.arch = arch
        self.policies = syscall_policies[arch.archname]
        self.state = X86ReplayState()
        self.coverage = ReplayCoverage()

    def replay_signal(
        self,
        target: ReplayTarget,
        pre_event: SignalEvent,
        post_event: SignalEvent,
    ) -> ReadableProgramState | None:
        effect_name = f"signal:{pre_event.descriptor.signal_number}"
        disposition = post_event.descriptor.disposition
        strategy = (
            ReplayStrategy.SAFE_PASSTHROUGH
            if disposition == "ignored"
            else ReplayStrategy.REJECT
            if disposition == "fatal"
            else ReplayStrategy.RECORDED
        )
        try:
            return self._replay_aarch64_signal(target, pre_event, post_event)
        except UnsupportedReplayEffect as error:
            self.coverage.record(
                event_count=pre_event.event_count,
                effect=effect_name,
                strategy=ReplayStrategy.REJECT,
                outcome=CoverageOutcome.REJECTED,
                detail=str(error),
            )
            raise
        except (
            ReplayError,
            DeterministicLogError,
            RegisterAccessError,
            MemoryAccessError,
        ) as error:
            self.coverage.record(
                event_count=pre_event.event_count,
                effect=effect_name,
                strategy=strategy,
                outcome=CoverageOutcome.FAILED,
                detail=str(error),
            )
            raise

    def _replay_aarch64_signal(
        self,
        target: ReplayTarget,
        pre_event: SignalEvent,
        post_event: SignalEvent,
    ) -> ReadableProgramState | None:
        self._validate_target_arch(target)
        if pre_event.arch != self.arch or post_event.arch != self.arch:
            raise ReplayEventError("AArch64 signal events use a different architecture.")
        if pre_event.tid != post_event.tid or pre_event.descriptor != post_event.descriptor:
            raise ReplayEventError("AArch64 signal pair changes thread or descriptor.")
        if pre_event.signal_variant != "signal" or pre_event.mem_writes:
            raise ReplayEventError("Malformed AArch64 signal pre-event.")
        if pre_event.pc is None or post_event.pc is None:
            raise ReplayEventError("AArch64 signal replay requires both PCs.")
        target_state = target.current_state()
        if target_state.read_pc() != pre_event.pc:
            raise ReplayEventError("AArch64 signal event does not match the target PC.")

        signal_number = pre_event.descriptor.signal_number
        effect_name = f"signal:{signal_number}"
        if post_event.descriptor.disposition == "ignored":
            if post_event.signal_variant != "signalDelivery" or post_event.mem_writes:
                raise ReplayEventError("Ignored AArch64 signal has frame effects.")
            self._reconcile_event_registers(target_state, post_event, _AARCH64_GPRS)
            self.coverage.record(
                event_count=pre_event.event_count,
                effect=effect_name,
                strategy=ReplayStrategy.SAFE_PASSTHROUGH,
                outcome=CoverageOutcome.HANDLED,
                detail="ignored signal",
            )
            return None
        if post_event.descriptor.disposition == "fatal":
            raise UnsupportedReplayEffect(
                f"Fatal AArch64 signal {signal_number} delivery is unsupported.",
                event_count=pre_event.event_count,
            )

        action = self.state.signal_actions.get(signal_number)
        if not isinstance(action, AArch64KernelSigaction) or action.handler in (0, 1):
            raise UnsupportedReplayEffect(
                f"AArch64 signal {signal_number} has no replayed user action.",
                event_count=pre_event.event_count,
            )
        writes = self._materialize_writes(post_event)
        frame = AArch64RecordedSignalFrame.from_events(pre_event, post_event, writes)
        if target_state.read_register("sp") != self._event_register(pre_event, "sp"):
            raise ReplayReconciliationError(
                "AArch64 signal replay requires matching RR and target stacks."
            )
        self._reconcile_event_registers(target_state, pre_event, frame.saved_registers)
        if post_event.pc != action.handler:
            raise ReplayEventError("AArch64 handler PC differs from rt_sigaction.")
        if action.flags & AArch64KernelSigaction.SA_RESTORER:
            if frame.restorer_address != action.restorer:
                raise ReplayEventError("AArch64 handler LR differs from the signal restorer.")
        if frame.signal_mask != self.state.signal_mask:
            raise ReplayEventError("AArch64 signal frame saves the wrong signal mask.")

        handler_extra = post_event.extra_registers
        if handler_extra is None or handler_extra.format != "aarch64-nt-fpr-v1":
            raise ReplayEventError("AArch64 handler event lacks recorded NT_FPR state.")
        target.write_signal_handler_extra_registers(handler_extra)
        for write in writes:
            target.write_target_memory(write.recorded_address, write.data)
        target.skip(post_event.pc)
        for register in ("x0", "x1", "x2", "x29", "x30", "sp", "cpsr"):
            target.write_target_register(register, self._event_register(post_event, register))

        self.state.signal_frames.append(DeliveredSignal(frame, action, post_event.pc))
        signal_bit = 1 << (signal_number - 1)
        self.state.signal_mask |= action.mask & _BLOCKABLE_SIGNAL_MASK
        if action.flags & _SA_NODEFER == 0:
            self.state.signal_mask |= signal_bit
        if action.flags & _SA_RESETHAND:
            self.state.signal_actions[signal_number] = AArch64KernelSigaction(0, 0, 0, 0)
        self.coverage.record(
            event_count=pre_event.event_count,
            effect=effect_name,
            strategy=ReplayStrategy.RECORDED,
            outcome=CoverageOutcome.HANDLED,
        )
        return target.current_state()

    def _plan_signal_action(
        self,
        context: SyscallReplayContext,
        memory_effects: Sequence[MemoryReplayEffect],
    ) -> SignalActionReplayEffect | None:
        if context.result != 0:
            return None
        size = context.target_state.read_register("x3")
        if size != 8 or self._event_register(context.pre_event, "x3") != 8:
            raise UnsupportedReplayEffect("AArch64 rt_sigaction requires an 8-byte sigset.")
        signal_number = context.target_state.read_register("x0")
        if signal_number != self._event_register(context.pre_event, "x0"):
            raise ReplayEventError("AArch64 rt_sigaction signal number differs from RR.")
        previous = self.state.signal_actions.get(
            signal_number,
            AArch64KernelSigaction(0, 0, 0, 0),
        )
        old_pointer = context.target_state.read_register("x2")
        if old_pointer:
            actual_old = self._memory_effect_bytes(
                memory_effects,
                old_pointer,
                AArch64KernelSigaction.SIZE,
            )
            if actual_old != previous.to_bytes():
                raise ReplayEventError("AArch64 rt_sigaction old action disagrees.")
        action_pointer = context.target_state.read_register("x1")
        action = None
        if action_pointer:
            action = AArch64KernelSigaction.from_bytes(
                context.target_state.read_memory(action_pointer, AArch64KernelSigaction.SIZE)
            )
        return SignalActionReplayEffect(signal_number, action)

    def _plan_signal_mask(
        self,
        context: SyscallReplayContext,
        memory_effects: Sequence[MemoryReplayEffect],
    ) -> SignalMaskReplayEffect | None:
        if context.result != 0:
            return None
        size = context.target_state.read_register("x3")
        if size != 8 or self._event_register(context.pre_event, "x3") != 8:
            raise UnsupportedReplayEffect("AArch64 rt_sigprocmask requires an 8-byte sigset.")
        old_pointer = context.target_state.read_register("x2")
        if old_pointer:
            recorded_old = self._memory_effect_bytes(memory_effects, old_pointer, 8)
            if int.from_bytes(recorded_old, "little") != self.state.signal_mask:
                raise ReplayEventError("AArch64 rt_sigprocmask old mask disagrees.")
        how = _signed_u64(context.target_state.read_register("x0"))
        if how != _signed_u64(self._event_register(context.pre_event, "x0")):
            raise ReplayEventError("AArch64 rt_sigprocmask operation differs from RR.")
        set_pointer = context.target_state.read_register("x1")
        if set_pointer == 0:
            next_mask = self.state.signal_mask
        else:
            requested = (
                int.from_bytes(context.target_state.read_memory(set_pointer, 8), "little")
                & _BLOCKABLE_SIGNAL_MASK
            )
            if how == _SIG_BLOCK:
                next_mask = self.state.signal_mask | requested
            elif how == _SIG_UNBLOCK:
                next_mask = self.state.signal_mask & ~requested & ((1 << 64) - 1)
            elif how == _SIG_SETMASK:
                next_mask = requested
            else:
                raise ReplayEventError(f"Unknown AArch64 rt_sigprocmask operation {how}.")
        return SignalMaskReplayEffect(self.state.signal_mask, next_mask)

    @staticmethod
    def _plan_signal_altstack(
        context: SyscallReplayContext,
    ) -> SignalAltstackReplayEffect | None:
        if context.result != 0:
            return None
        pointer = context.target_state.read_register("x0")
        data = context.target_state.read_memory(pointer, 24) if pointer else None
        return SignalAltstackReplayEffect(data)

    def _validate_signal_return_entry(self, state: ReadableProgramState) -> None:
        if not self.state.signal_frames:
            raise ReplayEventError("AArch64 rt_sigreturn has no delivered frame.")
        expected_sp = self.state.signal_frames[-1].frame.frame_address
        actual_sp = state.read_register("sp")
        if actual_sp != expected_sp:
            raise ReplayEventError(
                f"AArch64 rt_sigreturn SP is {actual_sp:#x}, expected {expected_sp:#x}."
            )

    def _finish_signal_return(
        self,
        state: ReadableProgramState,
        post_event: SyscallEvent,
    ) -> None:
        if not self.state.signal_frames:
            raise ReplayEventError("AArch64 rt_sigreturn has no delivered frame.")
        delivered = self.state.signal_frames[-1]
        self._reconcile_event_registers(state, post_event, _AARCH64_GPRS)
        self.state.signal_frames.pop()
        self.state.signal_mask = delivered.frame.signal_mask
        self.state.altstack = delivered.frame.altstack


def make_replay_engine(arch: Arch) -> X86ReplayEngine | AArch64ReplayEngine:
    """Construct the fail-closed deterministic engine for a supported guest ISA."""
    if arch.archname == "x86_64" and arch.endianness == "little":
        return X86ReplayEngine(arch)
    if arch.archname == "aarch64" and arch.endianness == "little":
        return AArch64ReplayEngine(arch)
    raise UnsupportedReplayEffect(
        f"Deterministic replay is unsupported for {arch.serialized_name}."
    )


def _signed_u64(value: int) -> int:
    value &= (1 << 64) - 1
    return value - (1 << 64) if value & (1 << 63) else value
