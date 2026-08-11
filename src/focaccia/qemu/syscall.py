"""Typed deterministic system-call replay contracts.

The types in this module are independent of GDB.  They turn one RR system-call
pair into explicit register, memory, and kernel-model effects before a replay
target is changed.  Architecture modules own the policy table; unknown calls
are never implicitly executed.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Protocol

from focaccia.arch import Arch
from focaccia.deterministic import MemoryWrite, SyscallEvent
from focaccia.snapshot import ReadableProgramState


MAX_REPLAY_OUTPUT_SIZE = 256 * 1024 * 1024
MAX_IOV_COUNT = 1024
MAX_IOV_BYTES = (1 << 63) - 1


class ReplayError(RuntimeError):
    """Base class for deterministic replay failures."""


class ReplayEventError(ReplayError, ValueError):
    """The deterministic event does not satisfy a handler's contract."""


class ReplayAddressError(ReplayError):
    """A recorded output address cannot be translated to the replay target."""


class ReplayReconciliationError(ReplayError):
    """An executed process-local effect disagrees with the recorded effect."""


class UnsupportedReplayEffect(ReplayError):
    """An effect has no sound policy for the current replay backend."""

    def __init__(
        self,
        message: str,
        *,
        event_count: int | None = None,
        syscall_number: int | None = None,
        syscall_name: str | None = None,
    ):
        super().__init__(message)
        self.event_count = event_count
        self.syscall_number = syscall_number
        self.syscall_name = syscall_name


class ReplayStrategy(str, Enum):
    """How a classified system call is handled."""

    RECORDED = "recorded-replay"
    EXECUTE_RECONCILE = "execute-and-reconcile"
    SAFE_PASSTHROUGH = "safe-passthrough"
    REJECT = "reject"


class ReconcileMode(str, Enum):
    """How user-visible results of an executed system call are reconciled."""

    EXACT = "exact"
    APPLY_RECORDED = "apply-recorded"


class SyscallStateAction(str, Enum):
    """Typed non-memory state tracked by the replay model."""

    NONE = "none"
    OPEN_FD = "open-fd"
    CLOSE_FD = "close-fd"
    DUP_FD = "duplicate-fd"
    PIPE_FDS = "pipe-fds"
    SOCKET_FD = "socket-fd"
    ACCEPT_FD = "accept-fd"
    SIGNAL_ACTION = "signal-action"
    SIGNAL_MASK = "signal-mask"
    SIGNAL_ALTSTACK = "signal-altstack"
    MEMORY_MAPPING = "memory-mapping"
    RETURN_FROM_SIGNAL = "return-from-signal"
    TERMINATE = "terminate"


class ExecutionGuard(str, Enum):
    """Additional precondition before executing a process-local call."""

    NONE = "none"
    ANONYMOUS_MMAP = "anonymous-mmap"


@dataclass(frozen=True, slots=True)
class RegisterReplayEffect:
    """One recorded architectural register update."""

    register: str
    value: int


@dataclass(frozen=True, slots=True)
class MemoryReplayEffect:
    """Known recorded bytes translated to one replay-target address."""

    recorded_address: int
    target_address: int
    data: bytes

    def __post_init__(self) -> None:
        if self.recorded_address < 0 or self.target_address < 0:
            raise ValueError("Replay memory addresses cannot be negative.")
        object.__setattr__(self, "data", bytes(self.data))


@dataclass(frozen=True, slots=True)
class DescriptorReplayEffect:
    """A change to the replay engine's virtual descriptor namespace."""

    operation: SyscallStateAction
    descriptors: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class OpenedDescriptorReplayEffect:
    """Descriptor provenance supplied by RR's openedFds extra payload."""

    fd: int
    path: bytes
    device: int
    inode: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", bytes(self.path))


@dataclass(frozen=True, slots=True)
class SignalMaskReplayEffect:
    """A change to the virtual blocked-signal mask."""

    previous_mask: int | None
    next_mask: int


@dataclass(frozen=True, slots=True)
class SignalActionReplayEffect:
    """A validated x86-64 signal action (kept opaque at the generic layer)."""

    signal_number: int
    action: object | None


@dataclass(frozen=True, slots=True)
class SignalAltstackReplayEffect:
    """A validated replacement signal-stack byte image."""

    data: bytes | None

    def __post_init__(self) -> None:
        if self.data is not None:
            object.__setattr__(self, "data", bytes(self.data))


@dataclass(frozen=True, slots=True)
class DescriptorOffsetReplayEffect:
    """A recorded implicit descriptor offset after one operation."""

    fd: int
    offset: int


@dataclass(frozen=True, slots=True)
class SocketAddressReplayEffect:
    """Recorded local/remote addresses for one virtual socket."""

    fd: int
    local: bytes
    remote: bytes

    def __post_init__(self) -> None:
        object.__setattr__(self, "local", bytes(self.local))
        object.__setattr__(self, "remote", bytes(self.remote))


@dataclass(frozen=True, slots=True)
class MappingReplayEffect:
    """A process-local mapping operation that must execute in QEMU."""

    syscall_number: int
    address: int
    length: int


@dataclass(frozen=True, slots=True)
class TerminationReplayEffect:
    """A recorded process termination request."""

    status: int
    exits_group: bool


KernelReplayEffect = (
    DescriptorReplayEffect
    | OpenedDescriptorReplayEffect
    | SignalMaskReplayEffect
    | SignalActionReplayEffect
    | SignalAltstackReplayEffect
    | DescriptorOffsetReplayEffect
    | SocketAddressReplayEffect
    | MappingReplayEffect
    | TerminationReplayEffect
)


@dataclass(frozen=True, slots=True)
class MaterializedMemoryWrite:
    """A fully known RR memory write."""

    tid: int
    recorded_address: int
    data: bytes

    @classmethod
    def from_recorded(cls, write: MemoryWrite) -> MaterializedMemoryWrite:
        return cls(write.tid, write.address, write.materialize())

    @property
    def end(self) -> int:
        return self.recorded_address + len(self.data)


@dataclass(frozen=True, slots=True)
class SyscallReplayContext:
    """Immutable input available to output-address handlers."""

    pre_event: SyscallEvent
    post_event: SyscallEvent
    target_state: ReadableProgramState
    result: int


class OutputExtent(Protocol):
    """Computes the maximum size of one direct output region."""

    def evaluate(self, context: SyscallReplayContext) -> int: ...

    def register_names(self) -> frozenset[str]: ...


@dataclass(frozen=True, slots=True)
class FixedExtent:
    size: int

    def __post_init__(self) -> None:
        if self.size < 0 or self.size > MAX_REPLAY_OUTPUT_SIZE:
            raise ValueError("A fixed replay-output extent is outside the size limit.")

    def evaluate(self, context: SyscallReplayContext) -> int:
        del context
        return self.size

    def register_names(self) -> frozenset[str]:
        return frozenset()


@dataclass(frozen=True, slots=True)
class RegisterExtent:
    register: str
    multiplier: int = 1
    maximum: int = MAX_REPLAY_OUTPUT_SIZE

    def __post_init__(self) -> None:
        if self.multiplier <= 0:
            raise ValueError("A replay-output multiplier must be positive.")
        if self.maximum < 0 or self.maximum > MAX_REPLAY_OUTPUT_SIZE:
            raise ValueError("A replay-output maximum is outside the size limit.")

    def evaluate(self, context: SyscallReplayContext) -> int:
        try:
            recorded = context.pre_event.registers[self.register]
        except KeyError as error:
            raise ReplayEventError(
                f"System-call event {context.pre_event.event_count} lacks "
                f"size register {self.register}."
            ) from error
        target = context.target_state.read_register(self.register)
        if target != recorded:
            raise ReplayEventError(
                f"System-call size argument {self.register} differs: RR recorded "
                f"{recorded:#x}, target has {target:#x}."
            )
        size = recorded * self.multiplier
        if size < 0 or size > self.maximum:
            raise ReplayEventError(
                f"System-call output extent {size} exceeds the limit {self.maximum}."
            )
        return size

    def register_names(self) -> frozenset[str]:
        return frozenset((self.register,))


@dataclass(frozen=True, slots=True)
class ResultExtent:
    limit_register: str | None = None
    multiplier: int = 1
    maximum: int = MAX_REPLAY_OUTPUT_SIZE

    def __post_init__(self) -> None:
        if self.multiplier <= 0:
            raise ValueError("A replay-output multiplier must be positive.")
        if self.maximum < 0 or self.maximum > MAX_REPLAY_OUTPUT_SIZE:
            raise ValueError("A replay-output maximum is outside the size limit.")

    def evaluate(self, context: SyscallReplayContext) -> int:
        if context.result <= 0:
            return 0
        size = context.result * self.multiplier
        if self.limit_register is not None:
            limit = RegisterExtent(
                self.limit_register,
                multiplier=self.multiplier,
                maximum=self.maximum,
            ).evaluate(context)
            size = min(size, limit)
        if size > self.maximum:
            raise ReplayEventError(
                f"Recorded result implies {size} output bytes, above {self.maximum}."
            )
        return size

    def register_names(self) -> frozenset[str]:
        if self.limit_register is None:
            return frozenset()
        return frozenset((self.limit_register,))


@dataclass(frozen=True, slots=True)
class PointedU32Extent:
    pointer_register: str
    maximum: int = 1 << 20

    def __post_init__(self) -> None:
        if self.maximum <= 0 or self.maximum > MAX_REPLAY_OUTPUT_SIZE:
            raise ValueError("A pointed replay-output maximum is outside the size limit.")

    def evaluate(self, context: SyscallReplayContext) -> int:
        pointer = context.target_state.read_register(self.pointer_register)
        if pointer == 0:
            return 0
        raw = context.target_state.read_memory(pointer, 4)
        size = int.from_bytes(raw, "little")
        if size > self.maximum:
            raise ReplayEventError(f"Pointed output size {size} exceeds the limit {self.maximum}.")
        return size

    def register_names(self) -> frozenset[str]:
        return frozenset((self.pointer_register,))


@dataclass(frozen=True, slots=True)
class FdSetExtent:
    nfds_register: str = "rdi"

    def evaluate(self, context: SyscallReplayContext) -> int:
        nfds = RegisterExtent(
            self.nfds_register,
            maximum=1 << 20,
        ).evaluate(context)
        return ((nfds + 63) // 64) * 8

    def register_names(self) -> frozenset[str]:
        return frozenset((self.nfds_register,))


@dataclass(frozen=True, slots=True)
class DirectOutput:
    """A recorded pointer argument and its maximum output extent."""

    pointer_register: str
    extent: OutputExtent

    def register_names(self) -> frozenset[str]:
        return frozenset((self.pointer_register,)) | self.extent.register_names()


class MemoryOutputHandler(Protocol):
    """Translates all memory writes for one system-call policy."""

    def plan(
        self,
        context: SyscallReplayContext,
        writes: Sequence[MaterializedMemoryWrite],
    ) -> tuple[MemoryReplayEffect, ...]: ...

    def register_names(self) -> frozenset[str]: ...


@dataclass(frozen=True, slots=True)
class NoMemoryOutputs:
    """Require a system-call pair to contain no recorded user-memory output."""

    def plan(
        self,
        context: SyscallReplayContext,
        writes: Sequence[MaterializedMemoryWrite],
    ) -> tuple[MemoryReplayEffect, ...]:
        nonempty = tuple(write for write in writes if write.data)
        if nonempty:
            raise ReplayEventError(
                f"System call {context.pre_event.syscall_number} has "
                f"{len(nonempty)} unexpected recorded memory write(s)."
            )
        return ()

    def register_names(self) -> frozenset[str]:
        return frozenset()


@dataclass(frozen=True, slots=True)
class DirectMemoryOutputs:
    """Translate writes contained in explicitly bounded pointer arguments."""

    outputs: tuple[DirectOutput, ...]
    require_result_bytes: bool = False
    result_output_register: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "outputs", tuple(self.outputs))
        if not self.outputs:
            raise ValueError("A direct-output handler needs at least one output.")
        if self.result_output_register is not None and all(
            output.pointer_register != self.result_output_register for output in self.outputs
        ):
            raise ValueError("The required result-output register is not an output root.")
        if self.require_result_bytes and self.result_output_register is not None:
            raise ValueError("Choose either global or per-root result-byte validation.")

    def register_names(self) -> frozenset[str]:
        names: frozenset[str] = frozenset()
        for output in self.outputs:
            names |= output.register_names()
        return names

    def plan(
        self,
        context: SyscallReplayContext,
        writes: Sequence[MaterializedMemoryWrite],
    ) -> tuple[MemoryReplayEffect, ...]:
        regions: list[tuple[int, int, int, str]] = []
        for output in self.outputs:
            try:
                recorded_base = context.pre_event.registers[output.pointer_register]
            except KeyError as error:
                raise ReplayEventError(
                    f"System-call event {context.pre_event.event_count} lacks pointer "
                    f"register {output.pointer_register}."
                ) from error
            target_base = context.target_state.read_register(output.pointer_register)
            extent = output.extent.evaluate(context)
            if (recorded_base == 0) != (target_base == 0):
                raise ReplayAddressError(
                    f"Pointer {output.pointer_register} is null in only one replay run."
                )
            if recorded_base == 0 or extent == 0:
                continue
            if recorded_base + extent > 1 << 64 or target_base + extent > 1 << 64:
                raise ReplayAddressError(
                    f"Output region for {output.pointer_register} wraps the address space."
                )
            regions.append(
                (recorded_base, recorded_base + extent, target_base, output.pointer_register)
            )

        effects: list[MemoryReplayEffect] = []
        total = 0
        totals_by_register: Counter[str] = Counter()
        for write in writes:
            if not write.data:
                continue
            matches = [
                region
                for region in regions
                if region[0] <= write.recorded_address and write.end <= region[1]
            ]
            if len(matches) != 1:
                roots = ", ".join(item[3] for item in matches) or "none"
                raise ReplayAddressError(
                    f"Recorded write [{write.recorded_address:#x}, {write.end:#x}) "
                    f"matches {len(matches)} direct output regions ({roots})."
                )
            recorded_base, _recorded_end, target_base, output_register = matches[0]
            target_address = target_base + write.recorded_address - recorded_base
            effects.append(
                MemoryReplayEffect(
                    write.recorded_address,
                    target_address,
                    write.data,
                )
            )
            total += len(write.data)
            totals_by_register[output_register] += len(write.data)

        if self.require_result_bytes:
            expected = max(context.result, 0)
            if total != expected:
                raise ReplayEventError(
                    f"Recorded result is {context.result}, but RR contains {total} output " "bytes."
                )
        if self.result_output_register is not None:
            expected = max(context.result, 0)
            actual = totals_by_register[self.result_output_register]
            if actual != expected:
                raise ReplayEventError(
                    f"Recorded result is {context.result}, but output root "
                    f"{self.result_output_register} contains {actual} bytes."
                )
        _validate_target_effects(effects)
        return tuple(effects)


@dataclass(frozen=True, slots=True)
class IovecResultOutputs:
    """Replay a result byte stream through a target 64-bit Linux iovec array."""

    iovec_register: str = "rsi"
    count_register: str = "rdx"

    def register_names(self) -> frozenset[str]:
        return frozenset((self.iovec_register, self.count_register))

    def plan(
        self,
        context: SyscallReplayContext,
        writes: Sequence[MaterializedMemoryWrite],
    ) -> tuple[MemoryReplayEffect, ...]:
        try:
            recorded_count = context.pre_event.registers[self.count_register]
        except KeyError as error:
            raise ReplayEventError(
                f"System-call event lacks iovec count register {self.count_register}."
            ) from error
        target_count = context.target_state.read_register(self.count_register)
        if target_count != recorded_count:
            raise ReplayEventError(
                f"Iovec count differs: RR recorded {recorded_count}, target has " f"{target_count}."
            )
        if recorded_count > MAX_IOV_COUNT:
            raise ReplayEventError(f"Iovec count {recorded_count} exceeds {MAX_IOV_COUNT}.")

        iovec_address = context.target_state.read_register(self.iovec_register)
        if recorded_count and iovec_address == 0:
            raise ReplayAddressError("A nonempty iovec array has a null target pointer.")
        raw_iovecs = context.target_state.read_memory(iovec_address, recorded_count * 16)
        iovecs: list[tuple[int, int]] = []
        capacity = 0
        for index in range(recorded_count):
            offset = index * 16
            base = int.from_bytes(raw_iovecs[offset : offset + 8], "little")
            length = int.from_bytes(raw_iovecs[offset + 8 : offset + 16], "little")
            if length and base == 0:
                raise ReplayAddressError(f"Iovec {index} has a null nonempty base.")
            capacity += length
            if capacity > MAX_IOV_BYTES:
                raise ReplayEventError("Iovec capacity exceeds signed ssize_t range.")
            iovecs.append((base, length))

        expected = max(context.result, 0)
        if expected > capacity:
            raise ReplayEventError(
                f"Recorded result {expected} exceeds target iovec capacity {capacity}."
            )
        payload = b"".join(write.data for write in writes)
        if len(payload) != expected:
            raise ReplayEventError(
                f"Recorded iovec result is {context.result}, but RR contains "
                f"{len(payload)} output bytes."
            )

        effects: list[MemoryReplayEffect] = []
        consumed = 0
        recorded_cursor = writes[0].recorded_address if writes else 0
        for base, length in iovecs:
            if consumed == len(payload):
                break
            chunk = payload[consumed : consumed + min(length, len(payload) - consumed)]
            if chunk:
                effects.append(MemoryReplayEffect(recorded_cursor + consumed, base, chunk))
                consumed += len(chunk)
        if consumed != len(payload):
            raise ReplayAddressError("Unable to place the complete iovec result.")
        _validate_target_effects(effects)
        return tuple(effects)


def _validate_target_effects(effects: Sequence[MemoryReplayEffect]) -> None:
    ranges = sorted(
        (
            effect.target_address,
            effect.target_address + len(effect.data),
        )
        for effect in effects
        if effect.data
    )
    previous_end: int | None = None
    for start, end in ranges:
        if previous_end is not None and start < previous_end:
            raise ReplayAddressError("Translated replay memory writes overlap.")
        previous_end = end


@dataclass(frozen=True, slots=True)
class SyscallPolicy:
    """Complete policy for one architecture-specific system-call number."""

    number: int
    name: str
    strategy: ReplayStrategy
    outputs: MemoryOutputHandler
    state_action: SyscallStateAction = SyscallStateAction.NONE
    reconcile: ReconcileMode = ReconcileMode.EXACT
    execution_guard: ExecutionGuard = ExecutionGuard.NONE
    execution_arguments: tuple[str, ...] = ()
    exact_post_registers: tuple[str, ...] = ()
    recorded_post_registers: tuple[str, ...] = ()
    allowed_argument_values: tuple[tuple[str, tuple[int, ...]], ...] = ()
    allowed_extras: frozenset[str] = frozenset(("none",))
    reject_reason: str | None = None

    def __post_init__(self) -> None:
        if self.number < 0:
            raise ValueError("A system-call number cannot be negative.")
        object.__setattr__(self, "execution_arguments", tuple(self.execution_arguments))
        object.__setattr__(self, "exact_post_registers", tuple(self.exact_post_registers))
        object.__setattr__(
            self, "recorded_post_registers", tuple(self.recorded_post_registers)
        )
        object.__setattr__(
            self,
            "allowed_argument_values",
            tuple(
                (name, tuple(values)) for name, values in self.allowed_argument_values
            ),
        )
        object.__setattr__(self, "allowed_extras", frozenset(self.allowed_extras))
        valid_extras = {
            "none",
            "writeOffset",
            "execFdsToClose",
            "openedFds",
            "socketAddrs",
            "madviseRanges",
        }
        unknown_extras = self.allowed_extras - valid_extras
        if unknown_extras:
            raise ValueError(f"Unknown system-call extra kinds: {sorted(unknown_extras)}.")
        if "none" not in self.allowed_extras:
            raise ValueError("Every system-call policy must permit an empty extra payload.")
        if not self.name:
            raise ValueError("A system-call policy needs a name.")
        if self.strategy is ReplayStrategy.REJECT and not self.reject_reason:
            raise ValueError("A rejected system-call policy needs a reason.")
        if self.strategy is not ReplayStrategy.REJECT and self.reject_reason is not None:
            raise ValueError("Only rejected system-call policies have rejection reasons.")
        if (self.execution_arguments or self.exact_post_registers) and self.strategy not in (
            ReplayStrategy.EXECUTE_RECONCILE,
            ReplayStrategy.SAFE_PASSTHROUGH,
        ):
            raise ValueError("Only executing policies can validate execution arguments.")
        if (
            self.recorded_post_registers
            and self.strategy is not ReplayStrategy.RECORDED
        ):
            raise ValueError(
                "Only recorded policies can apply additional post-event registers."
            )
        if len({name for name, _ in self.allowed_argument_values}) != len(
            self.allowed_argument_values
        ):
            raise ValueError("Constrained system-call argument registers must be unique.")
        if any(
            not values or any(value < 0 for value in values)
            for _, values in self.allowed_argument_values
        ):
            raise ValueError(
                "Allowed system-call argument values must be nonempty and non-negative."
            )
        if (
            self.state_action is SyscallStateAction.TERMINATE
            and self.strategy is not ReplayStrategy.EXECUTE_RECONCILE
        ):
            raise ValueError("Termination must use execute-and-reconcile.")

    @property
    def requires_post_event(self) -> bool:
        return self.state_action is not SyscallStateAction.TERMINATE

    def register_names(self) -> frozenset[str]:
        return (
            self.outputs.register_names()
            | frozenset(self.execution_arguments)
            | frozenset(self.exact_post_registers)
            | frozenset(self.recorded_post_registers)
            | frozenset(name for name, _ in self.allowed_argument_values)
        )


def validate_policy_table(
    arch: Arch,
    policies: Mapping[int, SyscallPolicy],
) -> Mapping[int, SyscallPolicy]:
    """Validate policy keys and every embedded architecture register name."""
    validated: dict[int, SyscallPolicy] = {}
    for number, policy in policies.items():
        if number != policy.number:
            raise ValueError(
                f"System-call policy key {number} disagrees with policy {policy.number}."
            )
        for register in policy.register_names():
            if arch.to_regname(register) is None:
                raise ValueError(
                    f"System call {policy.name} uses invalid {arch.serialized_name} "
                    f"register {register!r}."
                )
        validated[number] = policy
    return MappingProxyType(validated)


class CoverageOutcome(str, Enum):
    HANDLED = "handled"
    REJECTED = "rejected"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ReplayCoverageRecord:
    event_count: int
    effect: str
    strategy: ReplayStrategy
    outcome: CoverageOutcome
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class ReplayCoverageReport:
    records: tuple[ReplayCoverageRecord, ...]
    by_strategy: Mapping[ReplayStrategy, int]
    by_outcome: Mapping[CoverageOutcome, int]


class ReplayCoverage:
    """Append-only replay coverage with immutable snapshots for diagnostics."""

    def __init__(self) -> None:
        self._records: list[ReplayCoverageRecord] = []

    def record(
        self,
        *,
        event_count: int,
        effect: str,
        strategy: ReplayStrategy,
        outcome: CoverageOutcome,
        detail: str | None = None,
    ) -> None:
        self._records.append(ReplayCoverageRecord(event_count, effect, strategy, outcome, detail))

    def report(self) -> ReplayCoverageReport:
        by_strategy = Counter(record.strategy for record in self._records)
        by_outcome = Counter(record.outcome for record in self._records)
        return ReplayCoverageReport(
            tuple(self._records),
            MappingProxyType(dict(by_strategy)),
            MappingProxyType(dict(by_outcome)),
        )
