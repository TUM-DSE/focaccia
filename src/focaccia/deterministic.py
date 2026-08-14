from __future__ import annotations

import importlib
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Generic, Literal, Protocol, TypeVar

from .arch import Arch


class DeterministicLogError(RuntimeError):
    """Base class for deterministic-log failures."""


class DeterministicLogDependencyError(DeterministicLogError):
    """The optional RR parser dependency is unavailable."""


class DeterministicLogFormatError(DeterministicLogError, ValueError):
    """An RR log violates the supported trace format."""


class UnsupportedDeterministicArchitectureError(DeterministicLogFormatError):
    """An RR record uses an architecture that Focaccia cannot decode."""


class UnknownMemoryRangeError(DeterministicLogError):
    """A memory write cannot be materialized without inventing unknown bytes."""


@dataclass(frozen=True, slots=True)
class KnownMemoryRange:
    """Known bytes at a relative offset within one recorded memory write."""

    offset: int
    data: bytes

    def __post_init__(self) -> None:
        if self.offset < 0:
            raise ValueError("A known memory range offset cannot be negative.")
        if not self.data:
            raise ValueError("A known memory range cannot be empty.")
        object.__setattr__(self, "data", bytes(self.data))

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def end(self) -> int:
        return self.offset + self.size


@dataclass(frozen=True, slots=True)
class UnknownMemoryRange:
    """An explicitly unknown hole within one recorded memory write."""

    offset: int
    size: int

    def __post_init__(self) -> None:
        if self.offset < 0:
            raise ValueError("A memory-write hole offset cannot be negative.")
        if self.size <= 0:
            raise ValueError("A memory-write hole must have a positive size.")

    @property
    def end(self) -> int:
        return self.offset + self.size


# Compatibility spelling retained for callers that used the old domain name.
MemoryWriteHole = UnknownMemoryRange


@dataclass(frozen=True, slots=True)
class MemoryWrite:
    """One immutable write partitioned into known bytes and unknown holes."""

    tid: int
    address: int
    size: int
    known_ranges: tuple[KnownMemoryRange, ...]
    unknown_ranges: tuple[UnknownMemoryRange, ...]
    is_conservative: bool = False

    def __post_init__(self) -> None:
        if self.tid <= 0:
            raise ValueError("A memory write must have a positive thread ID.")
        if self.address < 0:
            raise ValueError("A memory-write address cannot be negative.")
        if self.size < 0:
            raise ValueError("A memory-write size cannot be negative.")

        known = tuple(self.known_ranges)
        unknown = tuple(self.unknown_ranges)
        object.__setattr__(self, "known_ranges", known)
        object.__setattr__(self, "unknown_ranges", unknown)

        if tuple(sorted(known, key=lambda item: item.offset)) != known:
            raise ValueError("Known memory ranges must be ordered by offset.")
        if tuple(sorted(unknown, key=lambda item: item.offset)) != unknown:
            raise ValueError("Unknown memory ranges must be ordered by offset.")

        pieces: list[KnownMemoryRange | UnknownMemoryRange] = [*known, *unknown]
        pieces.sort(key=lambda item: item.offset)
        cursor = 0
        for piece in pieces:
            if piece.offset != cursor:
                relation = "overlap" if piece.offset < cursor else "gap"
                raise ValueError(
                    f"Memory-write ranges contain a {relation} at offset {cursor}."
                )
            cursor = piece.end
            if cursor > self.size:
                raise ValueError("A memory-write range extends beyond the write size.")
        if cursor != self.size:
            raise ValueError(
                f"Memory-write ranges cover {cursor} bytes, expected {self.size}."
            )

    @property
    def holes(self) -> tuple[UnknownMemoryRange, ...]:
        return self.unknown_ranges

    @property
    def encoded_data(self) -> bytes:
        """Return the bytes physically present in RR's raw-data stream."""
        return b"".join(item.data for item in self.known_ranges)

    @property
    def is_fully_known(self) -> bool:
        return not self.unknown_ranges

    def materialize(self) -> bytes:
        """Return address-ordered bytes, refusing to fabricate unknown holes."""
        if self.unknown_ranges:
            holes = ", ".join(
                f"[{hole.offset}, {hole.end})" for hole in self.unknown_ranges
            )
            raise UnknownMemoryRangeError(
                f"Memory write at {self.address:#x} contains unknown ranges: {holes}."
            )
        return b"".join(item.data for item in self.known_ranges)


ExtraRegisterFormat = Literal["x86-xsave-v1", "aarch64-nt-fpr-v1"]


@dataclass(frozen=True, slots=True)
class ExtraRegisterState:
    """Versioned raw RR extra-register payload with validated base layouts."""

    arch: Arch
    format: ExtraRegisterFormat
    raw: bytes

    X86_FXSAVE_SIZE = 512
    X86_XSAVE_HEADER_SIZE = 64
    AARCH64_NT_FPR_SIZE = 528
    MAX_SIZE = 1 << 20

    def __post_init__(self) -> None:
        raw = bytes(self.raw)
        object.__setattr__(self, "raw", raw)
        if not raw:
            raise ValueError("An extra-register payload cannot be empty.")
        if len(raw) > self.MAX_SIZE:
            raise ValueError("An extra-register payload exceeds the size limit.")
        if self.format == "x86-xsave-v1":
            if self.arch.archname != "x86_64" or self.arch.endianness != "little":
                raise ValueError("x86 XSAVE state requires little-endian x86-64.")
            if len(raw) < self.X86_FXSAVE_SIZE:
                raise ValueError(
                    f"x86 XSAVE state has {len(raw)} bytes, expected at least "
                    f"{self.X86_FXSAVE_SIZE}."
                )
            if self.X86_FXSAVE_SIZE < len(raw) < (
                self.X86_FXSAVE_SIZE + self.X86_XSAVE_HEADER_SIZE
            ):
                raise ValueError("x86 XSAVE state has a truncated XSAVE header.")
        elif self.format == "aarch64-nt-fpr-v1":
            if self.arch.archname != "aarch64" or self.arch.endianness != "little":
                raise ValueError("AArch64 NT_FPR state requires little-endian AArch64.")
            if len(raw) != self.AARCH64_NT_FPR_SIZE:
                raise ValueError(
                    f"AArch64 NT_FPR state has {len(raw)} bytes, expected "
                    f"{self.AARCH64_NT_FPR_SIZE}."
                )
        else:
            raise ValueError(f"Unknown extra-register format {self.format!r}.")

    @classmethod
    def from_rr(cls, arch: Arch, raw: bytes) -> ExtraRegisterState | None:
        payload = bytes(raw)
        if not payload:
            return None
        if arch.archname == "x86_64" and arch.endianness == "little":
            return cls(arch, "x86-xsave-v1", payload)
        if arch.archname == "aarch64" and arch.endianness == "little":
            return cls(arch, "aarch64-nt-fpr-v1", payload)
        raise UnsupportedDeterministicArchitectureError(
            f"RR extra-register decoding is unsupported for {arch.serialized_name}."
        )

    def read_register(self, name: str) -> int:
        """Decode the base FP/vector registers shared with RR v85."""
        normalized = name.lower()
        if self.format == "aarch64-nt-fpr-v1":
            if normalized.startswith("v") and normalized[1:].isdigit():
                index = int(normalized[1:])
                if 0 <= index < 32:
                    offset = index * 16
                    return int.from_bytes(self.raw[offset : offset + 16], "little")
            if normalized == "fpsr":
                return int.from_bytes(self.raw[512:516], "little")
            if normalized == "fpcr":
                return int.from_bytes(self.raw[516:520], "little")
            raise KeyError(name)

        # The first 512 bytes use the architectural FXSAVE64 layout.
        if normalized.startswith("xmm") and normalized[3:].isdigit():
            index = int(normalized[3:])
            if 0 <= index < 16:
                offset = 160 + index * 16
                return int.from_bytes(self.raw[offset : offset + 16], "little")
        scalar_fields = {
            "fcw": (0, 2),
            "fsw": (2, 2),
            "ftw": (4, 1),
            "fop": (6, 2),
            "fip": (8, 8),
            "fdp": (16, 8),
            "mxcsr": (24, 4),
            "mxcsr_mask": (28, 4),
        }
        if normalized in scalar_fields:
            offset, size = scalar_fields[normalized]
            return int.from_bytes(self.raw[offset : offset + size], "little")
        if normalized == "xstate_bv":
            if len(self.raw) < 576:
                return 0
            return int.from_bytes(self.raw[512:520], "little")
        raise KeyError(name)


class RegisterValues(Mapping[str, int]):
    """Immutable architecture-normalized register values.

    Values are stored under canonical base-register names. Lookup accepts any
    alias known to the architecture and derives that alias from the base value.
    """

    __slots__ = ("arch", "_values")

    def __init__(self, arch: Arch, values: Mapping[str, int] | RegisterValues):
        if isinstance(values, RegisterValues):
            if values.arch != arch:
                raise ValueError("Register values use a different architecture.")
            canonical_values = dict(values._values)
        else:
            canonical_values: dict[str, int] = {}
            for name, value in values.items():
                accessor = arch.get_reg_accessor(name)
                if accessor is None:
                    raise ValueError(f"Unknown {arch.serialized_name} register: {name}.")
                if not isinstance(value, int) or value < 0:
                    raise ValueError(f"Register {name} must contain a non-negative integer.")
                if value >= 1 << accessor.num_bits:
                    raise ValueError(
                        f"Value {value:#x} does not fit in {name} "
                        f"({accessor.num_bits} bits)."
                    )
                base_name = accessor.base_reg
                base_value = value << accessor.start
                if base_name in canonical_values:
                    raise ValueError(f"Duplicate value for base register {base_name}.")
                canonical_values[base_name] = base_value
        self.arch = arch
        self._values = MappingProxyType(canonical_values)

    def __getitem__(self, name: str) -> int:
        accessor = self.arch.get_reg_accessor(name)
        if accessor is None:
            raise KeyError(name)
        try:
            base_value = self._values[accessor.base_reg]
        except KeyError as error:
            raise KeyError(name) from error
        return (base_value & accessor.mask) >> accessor.start

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __repr__(self) -> str:
        return repr(dict(self._values))


@dataclass(frozen=True, slots=True)
class Event:
    pc: int | None
    tid: int
    arch: Arch
    registers: RegisterValues | Mapping[str, int]
    mem_writes: tuple[MemoryWrite, ...] | Sequence[MemoryWrite]
    event_type: str
    event_count: int = 0
    extra_registers: ExtraRegisterState | None = None

    def __post_init__(self) -> None:
        if self.pc is not None and self.pc < 0:
            raise ValueError("An event PC cannot be negative.")
        if self.tid <= 0:
            raise ValueError("An event must have a positive thread ID.")
        if self.event_count < 0:
            raise ValueError("An event count cannot be negative.")
        object.__setattr__(self, "registers", RegisterValues(self.arch, self.registers))
        object.__setattr__(self, "mem_writes", tuple(self.mem_writes))
        if self.extra_registers is not None and self.extra_registers.arch != self.arch:
            raise ValueError("Extra registers use a different architecture.")


@dataclass(frozen=True, slots=True, init=False)
class SyscallBufferFlushEvent(Event):
    mprotect_records: bytes

    def __init__(
        self,
        pc: int | None,
        tid: int,
        arch: Arch,
        registers: RegisterValues | Mapping[str, int],
        memory_writes: Sequence[MemoryWrite],
        mprotect_records: bytes,
        *,
        event_count: int = 0,
        extra_registers: ExtraRegisterState | None = None,
    ):
        Event.__init__(
            self,
            pc,
            tid,
            arch,
            registers,
            memory_writes,
            "syscallBufFlush",
            event_count,
            extra_registers,
        )
        object.__setattr__(self, "mprotect_records", bytes(mprotect_records))


@dataclass(frozen=True, slots=True)
class OpenedFileDescriptor:
    fd: int
    path: bytes
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class MemoryAdviceRange:
    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < self.start:
            raise ValueError("Invalid madvise memory range.")


@dataclass(frozen=True, slots=True)
class SyscallExtra:
    kind: Literal[
        "none",
        "writeOffset",
        "execFdsToClose",
        "openedFds",
        "socketAddrs",
        "madviseRanges",
    ] = "none"
    write_offset: int | None = None
    exec_fds_to_close: tuple[int, ...] = ()
    opened_fds: tuple[OpenedFileDescriptor, ...] = ()
    socket_local_address: bytes | None = None
    socket_remote_address: bytes | None = None
    madvise_ranges: tuple[MemoryAdviceRange, ...] = ()


SyscallState = Literal["enteringPtrace", "entering", "exiting"]


@dataclass(frozen=True, slots=True, init=False)
class SyscallEvent(Event):
    syscall_arch: Arch
    syscall_number: int
    syscall_state: SyscallState
    failed_during_preparation: bool
    syscall_extras: SyscallExtra

    def __init__(
        self,
        pc: int | None,
        tid: int,
        arch: Arch,
        registers: RegisterValues | Mapping[str, int],
        memory_writes: Sequence[MemoryWrite],
        syscall_arch: Arch,
        syscall_number: int,
        syscall_state: SyscallState,
        failed_during_preparation: bool,
        syscall_extras: SyscallExtra | None = None,
        *,
        event_count: int = 0,
        extra_registers: ExtraRegisterState | None = None,
    ):
        if syscall_state not in ("enteringPtrace", "entering", "exiting"):
            raise ValueError(f"Unsupported system-call state: {syscall_state}.")
        Event.__init__(
            self,
            pc,
            tid,
            arch,
            registers,
            memory_writes,
            "syscall",
            event_count,
            extra_registers,
        )
        object.__setattr__(self, "syscall_arch", syscall_arch)
        object.__setattr__(self, "syscall_number", syscall_number)
        object.__setattr__(self, "syscall_state", syscall_state)
        object.__setattr__(
            self, "failed_during_preparation", failed_during_preparation
        )
        object.__setattr__(self, "syscall_extras", syscall_extras or SyscallExtra())


SignalDisposition = Literal["fatal", "userHandler", "ignored"]


@dataclass(frozen=True, slots=True)
class SignalDescriptor:
    arch: Arch
    siginfo: bytes
    deterministic: bool
    disposition: SignalDisposition

    def __post_init__(self) -> None:
        if self.disposition not in ("fatal", "userHandler", "ignored"):
            raise ValueError(f"Unsupported signal disposition: {self.disposition}.")
        siginfo = bytes(self.siginfo)
        if len(siginfo) < 4:
            raise ValueError("Signal info is shorter than si_signo.")
        object.__setattr__(self, "siginfo", siginfo)

    @property
    def signal_number(self) -> int:
        return int.from_bytes(self.siginfo[:4], "little", signed=True)


@dataclass(frozen=True, slots=True, init=False)
class SignalEvent(Event):
    signal_number: SignalDescriptor | None
    signal_delivery: SignalDescriptor | None
    signal_handler: SignalDescriptor | None

    def __init__(
        self,
        pc: int | None,
        tid: int,
        arch: Arch,
        registers: RegisterValues | Mapping[str, int],
        memory_writes: Sequence[MemoryWrite],
        signal_number: SignalDescriptor | None = None,
        signal_delivery: SignalDescriptor | None = None,
        signal_handler: SignalDescriptor | None = None,
        *,
        event_count: int = 0,
        extra_registers: ExtraRegisterState | None = None,
    ):
        variants = (signal_number, signal_delivery, signal_handler)
        if sum(item is not None for item in variants) != 1:
            raise ValueError("A signal event must contain exactly one signal variant.")
        Event.__init__(
            self,
            pc,
            tid,
            arch,
            registers,
            memory_writes,
            "signal",
            event_count,
            extra_registers,
        )
        object.__setattr__(self, "signal_number", signal_number)
        object.__setattr__(self, "signal_delivery", signal_delivery)
        object.__setattr__(self, "signal_handler", signal_handler)

    @property
    def signal_variant(self) -> Literal["signal", "signalDelivery", "signalHandler"]:
        if self.signal_number is not None:
            return "signal"
        if self.signal_delivery is not None:
            return "signalDelivery"
        return "signalHandler"

    @property
    def descriptor(self) -> SignalDescriptor:
        descriptor = self.signal_number or self.signal_delivery or self.signal_handler
        if descriptor is None:  # Defensive; constructor enforces one variant.
            raise RuntimeError("Signal event has no descriptor.")
        return descriptor


MappingSource = Literal["zero", "trace", "file", "debugger"]


@dataclass(frozen=True, slots=True)
class MemoryMapping:
    event_count: int
    start_address: int
    end_address: int
    source: MappingSource | str
    offset: int
    mmap_prot: int
    mmap_flags: int
    name: bytes | str | None = None
    source_file: bytes | None = None

    def __post_init__(self) -> None:
        if self.event_count < 0:
            raise ValueError("A mapping event count cannot be negative.")
        if self.start_address < 0 or self.end_address < self.start_address:
            raise ValueError("Invalid mapping address range.")
        if self.offset < 0:
            raise ValueError("A mapping file offset cannot be negative.")

    @property
    def length(self) -> int:
        return self.end_address - self.start_address


@dataclass(frozen=True, slots=True)
class Task:
    event_count: int
    tid: int

    def __post_init__(self) -> None:
        if self.event_count <= 0:
            raise ValueError("A task event count must be positive.")
        if self.tid <= 0:
            raise ValueError("A task event thread ID must be positive.")


@dataclass(frozen=True, slots=True)
class CloneTask(Task):
    parent_tid: int
    clone_flags: int
    own_namespace_tid: int


@dataclass(frozen=True, slots=True)
class ExecTask(Task):
    filename: bytes
    commandline: tuple[bytes, ...]
    execution_base_address: int
    interpreter_base_address: int
    interpreter_name: bytes
    pac_data: bytes = b""


@dataclass(frozen=True, slots=True)
class ExitTask(Task):
    exit_status: int


@dataclass(frozen=True, slots=True)
class DetachTask(Task):
    pass


@dataclass(frozen=True, slots=True)
class RRTraceMetadata:
    trace_version: int
    schema_version: str
    schema_id: str
    native_architecture: Arch
    trace_uuid: bytes


class EventLog(Protocol):
    base_directory: Path | None
    metadata: RRTraceMetadata | None

    def events(self) -> tuple[Event, ...]: ...

    def tasks(self) -> tuple[Task, ...]: ...

    def mmaps(self) -> tuple[MemoryMapping, ...]: ...


class EmptyEventLog:
    """Explicit event log for deterministic executions with no RR recording."""

    base_directory: Path | None = None
    metadata: RRTraceMetadata | None = None

    def events_file(self) -> None:
        return None

    def tasks_file(self) -> None:
        return None

    def mmaps_file(self) -> None:
        return None

    def data_file(self) -> None:
        return None

    def events(self) -> tuple[Event, ...]:
        return ()

    def tasks(self) -> tuple[Task, ...]:
        return ()

    def mmaps(self) -> tuple[MemoryMapping, ...]:
        return ()


_RR_ADAPTER_MODULE = "focaccia.rr.adapter"


def _load_rr_log(base_directory: Path) -> EventLog:
    try:
        adapter = importlib.import_module(_RR_ADAPTER_MODULE)
    except ModuleNotFoundError as error:
        missing_module = (error.name or "").split(".", 1)[0]
        requirements = {"capnp": "pycapnp", "brotli": "brotli"}
        if missing_module in requirements:
            raise DeterministicLogDependencyError(
                "RR deterministic-log support requires the "
                f"{requirements[missing_module]!r} dependency."
            ) from error
        raise
    return adapter.RRDeterministicLog(base_directory)


class DeterministicLog:
    """Facade selecting an explicit empty log or the versioned RR adapter."""

    def __init__(self, log_dir: str | Path | None):
        self._backend: EventLog
        if log_dir is None:
            self._backend = EmptyEventLog()
        else:
            self._backend = _load_rr_log(Path(log_dir))

    @property
    def base_directory(self) -> Path | None:
        return self._backend.base_directory

    @property
    def metadata(self) -> RRTraceMetadata | None:
        return self._backend.metadata

    def events_file(self) -> Path | None:
        method = getattr(self._backend, "events_file", None)
        return method() if method is not None else None

    def tasks_file(self) -> Path | None:
        method = getattr(self._backend, "tasks_file", None)
        return method() if method is not None else None

    def mmaps_file(self) -> Path | None:
        method = getattr(self._backend, "mmaps_file", None)
        return method() if method is not None else None

    def data_file(self) -> Path | None:
        method = getattr(self._backend, "data_file", None)
        return method() if method is not None else None

    def events(self) -> tuple[Event, ...]:
        return self._backend.events()

    def tasks(self) -> tuple[Task, ...]:
        return self._backend.tasks()

    def mmaps(self) -> tuple[MemoryMapping, ...]:
        return self._backend.mmaps()

    def __bool__(self) -> bool:
        return self.base_directory is not None


class CursorState(str, Enum):
    UNSYNCHRONIZED = "unsynchronized"
    SYNCHRONIZED = "synchronized"
    EXHAUSTED = "exhausted"


class CursorError(DeterministicLogError):
    """Base class for deterministic cursor failures."""


class CursorStateError(CursorError):
    pass


class CursorExhaustedError(CursorError):
    pass


class EventPairError(CursorError):
    pass


class EventSynchronizationError(CursorError):
    pass


class MappingOrderError(CursorError):
    pass


StateT = TypeVar("StateT")


class DeterministicCursor(Generic[StateT]):
    """One bounded cursor over deterministic events and mapping records."""

    def __init__(
        self,
        events: Sequence[Event],
        matcher: Callable[[Event, StateT], bool],
        mappings: Sequence[MemoryMapping] = (),
        *,
        skipped_event_counts: Sequence[int] = (),
    ):
        self.events = tuple(events)
        self.memory_mappings = tuple(mappings)
        self.matcher = matcher
        self.skipped_event_counts = frozenset(skipped_event_counts)
        if any(count <= 0 for count in self.skipped_event_counts):
            raise ValueError("Skipped event counts must be positive.")

        event_counts = [event.event_count for event in self.events if event.event_count]
        if event_counts and len(event_counts) != len(self.events):
            raise ValueError("Event counts must be either all explicit or all implicit.")
        if any(current <= previous for previous, current in zip(event_counts, event_counts[1:])):
            raise ValueError("Event counts must be strictly increasing.")
        mapping_counts = [mapping.event_count for mapping in self.memory_mappings]
        if mapping_counts != sorted(mapping_counts):
            raise MappingOrderError("Memory mappings must be sorted by event count.")

        self._event_position = 0
        self._mapping_position = 0
        self._last_mapping_request: int | None = None
        self._last_consumed: Event | None = None
        self.state = (
            CursorState.EXHAUSTED if not self.events else CursorState.UNSYNCHRONIZED
        )

    @property
    def event_position(self) -> int:
        return self._event_position

    @property
    def mapping_position(self) -> int:
        return self._mapping_position

    @property
    def last_consumed(self) -> Event | None:
        return self._last_consumed

    def _event_count(self, position: int) -> int:
        count = self.events[position].event_count
        return count if count else position + 1

    def _set_position(self, position: int) -> None:
        self._event_position = position
        self.state = (
            CursorState.EXHAUSTED
            if position >= len(self.events)
            else CursorState.SYNCHRONIZED
        )

    def _skip_configured(self) -> None:
        if self.state is not CursorState.SYNCHRONIZED:
            return
        position = self._event_position
        while (
            position < len(self.events)
            and self._event_count(position) in self.skipped_event_counts
        ):
            position += 1
        self._set_position(position)

    def synchronize(self, concrete_state: StateT) -> Event | None:
        """Find the first matching event without consuming it."""
        if self.state is CursorState.EXHAUSTED:
            return None
        if self.state is CursorState.SYNCHRONIZED:
            event = self.peek()
            return event if event is not None and self.matcher(event, concrete_state) else None
        for position, event in enumerate(self.events):
            if self._event_count(position) in self.skipped_event_counts:
                continue
            if self.matcher(event, concrete_state):
                self._set_position(position)
                return event
        return None

    def match(self, concrete_state: StateT) -> Event | None:
        if self.state is CursorState.EXHAUSTED:
            return None
        if self.state is CursorState.UNSYNCHRONIZED:
            if self.synchronize(concrete_state) is None:
                return None

        self._skip_configured()
        if self.state is CursorState.EXHAUSTED:
            return None
        event = self.events[self._event_position]
        if not self.matcher(event, concrete_state):
            return None
        self._last_consumed = event
        self._set_position(self._event_position + 1)
        return event

    def peek(self) -> Event | None:
        if self.state is CursorState.UNSYNCHRONIZED:
            raise CursorStateError("Cannot peek before the event cursor is synchronized.")
        if self.state is CursorState.EXHAUSTED:
            return None
        self._skip_configured()
        if self.state is CursorState.EXHAUSTED:
            return None
        return self.events[self._event_position]

    def skip(self, count: int = 1) -> tuple[Event, ...]:
        if count < 0:
            raise ValueError("Cannot skip a negative number of events.")
        if self.state is CursorState.UNSYNCHRONIZED:
            raise CursorStateError("Cannot skip before the event cursor is synchronized.")
        if count == 0:
            return ()
        if self._event_position + count > len(self.events):
            raise CursorExhaustedError(
                f"Cannot skip {count} events from position {self._event_position}; "
                f"only {len(self.events) - self._event_position} remain."
            )
        start = self._event_position
        end = start + count
        skipped = self.events[start:end]
        self._last_consumed = skipped[-1]
        self._set_position(end)
        return skipped

    def match_pair(self, event: Event | None) -> Event | None:
        if event is None:
            return None
        if event is not self._last_consumed:
            raise EventPairError("The pre-event is not the cursor's last consumed event.")
        if not isinstance(event, (SyscallEvent, SignalEvent)):
            raise EventPairError(f"Event type {event.event_type!r} has no post-event.")
        if self._event_position >= len(self.events):
            raise EventPairError(
                f"Event {event.event_count or self._event_position} has no post-event."
            )

        post_event = self.events[self._event_position]
        self._validate_pair(event, post_event)
        self._last_consumed = post_event
        self._set_position(self._event_position + 1)
        return post_event

    def match_terminal(self, event: Event) -> Event:
        """Consume the terminal exit marker following a system-call pre-event."""
        if event is not self._last_consumed:
            raise EventPairError("The pre-event is not the cursor's last consumed event.")
        if not isinstance(event, SyscallEvent) or event.syscall_state not in (
            "entering",
            "enteringPtrace",
        ):
            raise EventPairError("A terminal transition requires a system-call pre-event.")
        if self._event_position >= len(self.events):
            raise EventPairError(
                f"Event {event.event_count or self._event_position} has no exit marker."
            )

        terminal = self.events[self._event_position]
        if terminal.event_type != "exit":
            raise EventPairError(
                f"A terminal system call must be followed by an exit event, got "
                f"{terminal.event_type!r}."
            )
        if terminal.tid != event.tid:
            raise EventPairError(
                f"Terminal events use different threads: {event.tid} and {terminal.tid}."
            )
        if terminal.arch != event.arch:
            raise EventPairError("Terminal events use different architectures.")
        if terminal.pc is not None:
            raise EventPairError("A terminal exit event must not have a program counter.")

        self._last_consumed = terminal
        self._set_position(self._event_position + 1)
        return terminal

    @staticmethod
    def _validate_pair(pre_event: Event, post_event: Event) -> None:
        if pre_event.tid != post_event.tid:
            raise EventPairError(
                f"Paired events use different threads: {pre_event.tid} and "
                f"{post_event.tid}."
            )
        if pre_event.arch != post_event.arch:
            raise EventPairError("Paired events use different architectures.")

        if isinstance(pre_event, SyscallEvent):
            if not isinstance(post_event, SyscallEvent):
                raise EventPairError("A system-call pre-event must pair with a system call.")
            if pre_event.syscall_state not in ("entering", "enteringPtrace"):
                raise EventPairError(
                    f"System-call pre-event has state {pre_event.syscall_state!r}."
                )
            if post_event.syscall_state != "exiting":
                raise EventPairError(
                    f"System-call post-event has state {post_event.syscall_state!r}."
                )
            if pre_event.syscall_arch != post_event.syscall_arch:
                raise EventPairError("Paired system calls use different architectures.")
            if pre_event.syscall_number != post_event.syscall_number:
                raise EventPairError("Paired system calls use different call numbers.")
            return

        if not isinstance(pre_event, SignalEvent) or not isinstance(post_event, SignalEvent):
            raise EventPairError("A signal pre-event must pair with a signal event.")
        if pre_event.signal_variant != "signal":
            raise EventPairError(
                f"Signal pre-event has variant {pre_event.signal_variant!r}."
            )
        if post_event.signal_variant not in ("signalDelivery", "signalHandler"):
            raise EventPairError(
                f"Signal post-event has variant {post_event.signal_variant!r}."
            )
        if pre_event.descriptor.signal_number != post_event.descriptor.signal_number:
            raise EventPairError("Paired signal events use different signal numbers.")

    def mappings_at(self, event_count: int) -> tuple[MemoryMapping, ...]:
        if event_count < 0:
            raise ValueError("A mapping event count cannot be negative.")
        if (
            self._last_mapping_request is not None
            and event_count < self._last_mapping_request
        ):
            raise MappingOrderError(
                f"Mapping requests must be monotonic: {event_count} follows "
                f"{self._last_mapping_request}."
            )
        self._last_mapping_request = event_count

        position = self._mapping_position
        while (
            position < len(self.memory_mappings)
            and self.memory_mappings[position].event_count < event_count
        ):
            position += 1
        start = position
        while (
            position < len(self.memory_mappings)
            and self.memory_mappings[position].event_count == event_count
        ):
            position += 1
        self._mapping_position = position
        return self.memory_mappings[start:position]

    def __bool__(self) -> bool:
        return bool(self.events)
