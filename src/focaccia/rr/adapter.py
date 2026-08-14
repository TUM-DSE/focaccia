from __future__ import annotations

import io
import struct
import tempfile
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import brotli
import capnp

from focaccia.arch import Arch, supported_architectures
from focaccia.deterministic import (
    CloneTask,
    DetachTask,
    DeterministicLogFormatError,
    Event,
    ExecTask,
    ExtraRegisterState,
    ExitTask,
    KnownMemoryRange,
    MemoryAdviceRange,
    MemoryMapping,
    MemoryWrite,
    OpenedFileDescriptor,
    RRTraceMetadata,
    RegisterValues,
    SignalDescriptor,
    SignalEvent,
    SyscallBufferFlushEvent,
    SyscallEvent,
    SyscallExtra,
    Task,
    UnknownMemoryRange,
    UnsupportedDeterministicArchitectureError,
)


RR_TRACE_VERSION = 85
RR_SCHEMA_VERSION = "rr-trace-v85"
RR_SCHEMA_ID = "0xcaa0b1486c12c629"
RR_SCHEMA_RESOURCE = "rr_trace_v85.capnp"

_BLOCK_HEADER = struct.Struct("<II")
_X86_64_REGISTERS = struct.Struct("<27Q")
_AARCH64_REGISTERS = struct.Struct("<35Qi4x")

MAX_COMPRESSED_BLOCK_SIZE = 64 * 1024 * 1024
MAX_UNCOMPRESSED_BLOCK_SIZE = 64 * 1024 * 1024
MAX_UNCOMPRESSED_STREAM_SIZE = 1024 * 1024 * 1024
MAX_MEMORY_WRITE_SIZE = 256 * 1024 * 1024
CAPNP_TRAVERSAL_LIMIT_WORDS = 64 * 1024 * 1024 // 8


try:
    schema_resource = resources.files("focaccia.rr.schemas").joinpath(
        RR_SCHEMA_RESOURCE
    )
    with resources.as_file(schema_resource) as schema_path:
        RR_SCHEMA = capnp.load(str(schema_path))
except (FileNotFoundError, ModuleNotFoundError) as error:
    raise DeterministicLogFormatError(
        f"Packaged RR schema resource {RR_SCHEMA_RESOURCE!r} is unavailable."
    ) from error

_loaded_schema_id = f"{RR_SCHEMA.schema.node.id:#x}"
if _loaded_schema_id != RR_SCHEMA_ID:
    raise DeterministicLogFormatError(
        f"Packaged RR schema has ID {_loaded_schema_id}, expected {RR_SCHEMA_ID}."
    )


@dataclass(frozen=True, slots=True)
class DecodedRegisterPayload:
    registers: RegisterValues
    original_syscall_number: int | None = None
    original_argument1: int | None = None


def _format_error(message: str, *, source: Path | None = None) -> DeterministicLogFormatError:
    if source is not None:
        return DeterministicLogFormatError(f"{source}: {message}")
    return DeterministicLogFormatError(message)


def _arch_from_rr(value: Any, *, context: str) -> Arch:
    name = str(value)
    if name == "x8664":
        return supported_architectures["x86_64"]
    if name == "aarch64":
        return supported_architectures["aarch64l"]
    if name == "x86":
        raise UnsupportedDeterministicArchitectureError(
            f"{context} uses unsupported 32-bit x86 RR records."
        )
    raise UnsupportedDeterministicArchitectureError(
        f"{context} uses unknown RR architecture {name!r}."
    )


def decode_x86_64_registers(data: bytes) -> DecodedRegisterPayload:
    """Decode RR v85's exact ``X64Arch::user_regs_struct`` layout."""
    if len(data) != _X86_64_REGISTERS.size:
        raise DeterministicLogFormatError(
            "RR v85 x86-64 register payload has length "
            f"{len(data)}, expected {_X86_64_REGISTERS.size}."
        )
    values = _X86_64_REGISTERS.unpack(data)
    names = (
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
        "orig_rax",
        "rip",
        "cs",
        "eflags",
        "rsp",
        "ss",
        "fs_base",
        "gs_base",
        "ds",
        "es",
        "fs",
        "gs",
    )
    decoded = dict(zip(names, values, strict=True))
    original_syscall_number = decoded.pop("orig_rax")
    try:
        registers = RegisterValues(supported_architectures["x86_64"], decoded)
    except ValueError as error:
        raise DeterministicLogFormatError(
            f"Invalid RR v85 x86-64 register value: {error}"
        ) from error
    return DecodedRegisterPayload(registers, original_syscall_number)


def decode_aarch64_registers(data: bytes) -> DecodedRegisterPayload:
    """Decode RR v85's register union, including RR's private tail fields."""
    if len(data) != _AARCH64_REGISTERS.size:
        raise DeterministicLogFormatError(
            "RR v85 AArch64 register payload has length "
            f"{len(data)}, expected {_AARCH64_REGISTERS.size}."
        )
    values = _AARCH64_REGISTERS.unpack(data)
    architectural = {
        **{f"x{index}": values[index] for index in range(31)},
        "sp": values[31],
        "pc": values[32],
        "cpsr": values[33],
    }
    original_argument1 = values[34]
    original_syscall_number = values[35]
    try:
        registers = RegisterValues(supported_architectures["aarch64l"], architectural)
    except ValueError as error:
        raise DeterministicLogFormatError(
            f"Invalid RR v85 AArch64 register value: {error}"
        ) from error
    return DecodedRegisterPayload(
        registers,
        original_syscall_number=original_syscall_number,
        original_argument1=original_argument1,
    )


def decode_registers(arch: Arch, data: bytes) -> DecodedRegisterPayload:
    if arch.archname == "x86_64" and arch.endianness == "little":
        return decode_x86_64_registers(data)
    if arch.archname == "aarch64" and arch.endianness == "little":
        return decode_aarch64_registers(data)
    raise UnsupportedDeterministicArchitectureError(
        f"RR v85 register decoding is unsupported for {arch.serialized_name}."
    )


def _read_exact(stream: io.BufferedReader, size: int, *, context: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise DeterministicLogFormatError(
            f"Truncated {context}: read {len(data)} bytes, expected {size}."
        )
    return data


def read_compressed_stream(path: Path) -> bytes:
    """Decode RR's independently Brotli-compressed block stream."""
    output = bytearray()
    try:
        with path.open("rb") as stream:
            block_index = 0
            while True:
                header = stream.read(_BLOCK_HEADER.size)
                if not header:
                    break
                if len(header) != _BLOCK_HEADER.size:
                    raise _format_error(
                        f"truncated compressed block header {block_index}", source=path
                    )
                compressed_size, uncompressed_size = _BLOCK_HEADER.unpack(header)
                if compressed_size <= 0 or compressed_size > MAX_COMPRESSED_BLOCK_SIZE:
                    raise _format_error(
                        f"invalid compressed size {compressed_size} for block {block_index}",
                        source=path,
                    )
                if (
                    uncompressed_size <= 0
                    or uncompressed_size > MAX_UNCOMPRESSED_BLOCK_SIZE
                ):
                    raise _format_error(
                        f"invalid uncompressed size {uncompressed_size} for block "
                        f"{block_index}",
                        source=path,
                    )
                compressed = _read_exact(
                    stream,
                    compressed_size,
                    context=f"compressed block {block_index} in {path}",
                )
                try:
                    uncompressed = brotli.decompress(compressed)
                except brotli.error as error:
                    raise _format_error(
                        f"invalid Brotli data in block {block_index}: {error}",
                        source=path,
                    ) from error
                if len(uncompressed) != uncompressed_size:
                    raise _format_error(
                        f"block {block_index} expands to {len(uncompressed)} bytes, "
                        f"expected {uncompressed_size}",
                        source=path,
                    )
                if len(output) + len(uncompressed) > MAX_UNCOMPRESSED_STREAM_SIZE:
                    raise _format_error(
                        "uncompressed stream exceeds the configured size limit",
                        source=path,
                    )
                output.extend(uncompressed)
                block_index += 1
    except OSError as error:
        raise _format_error(str(error), source=path) from error
    return bytes(output)


def _read_packed_records(data: bytes, record_type: Any, *, source: Path) -> tuple[Any, ...]:
    if not data:
        return ()
    try:
        # pycapnp's multi-message reader requires a real file descriptor. A
        # temporary file also prevents it from reading beyond this one decoded
        # RR substream.
        with tempfile.TemporaryFile() as stream:
            stream.write(data)
            stream.seek(0)
            records = tuple(
                record_type.read_multiple_packed(
                    stream,
                    traversal_limit_in_words=CAPNP_TRAVERSAL_LIMIT_WORDS,
                )
            )
    except (OSError, capnp.KjException) as error:
        raise _format_error(
            f"invalid packed Cap'n Proto stream: {error}", source=source
        ) from error
    return records


def _union_variant(value: Any, *, context: str) -> str:
    try:
        variant = value.which()
    except capnp.KjException as error:
        raise DeterministicLogFormatError(
            f"Unknown or malformed {context} union variant: {error}"
        ) from error
    if not isinstance(variant, str):
        raise DeterministicLogFormatError(
            f"Invalid {context} union discriminator {variant!r}."
        )
    return variant


class _RawDataCursor:
    def __init__(self, data: bytes, source: Path):
        self._data = data
        self._source = source
        self.position = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self.position

    def read(self, size: int, *, context: str) -> bytes:
        if size < 0:
            raise DeterministicLogFormatError(f"Negative read size for {context}.")
        end = self.position + size
        if end > len(self._data):
            raise _format_error(
                f"truncated raw data for {context}: need {size} bytes at offset "
                f"{self.position}, only {self.remaining} remain",
                source=self._source,
            )
        result = self._data[self.position:end]
        self.position = end
        return result

    def require_exhausted(self) -> None:
        if self.remaining:
            raise _format_error(
                f"raw-data stream has {self.remaining} unreferenced trailing bytes",
                source=self._source,
            )


def _decode_memory_write(raw_write: Any, data: _RawDataCursor) -> MemoryWrite:
    tid = int(raw_write.tid)
    address = int(raw_write.addr)
    size = int(raw_write.size)
    if size > MAX_MEMORY_WRITE_SIZE:
        raise DeterministicLogFormatError(
            f"Memory write at {address:#x} has unsupported size {size}."
        )

    holes: list[UnknownMemoryRange] = []
    logical_offset = 0
    for index, raw_hole in enumerate(raw_write.holes):
        try:
            hole = UnknownMemoryRange(int(raw_hole.offset), int(raw_hole.size))
        except ValueError as error:
            raise DeterministicLogFormatError(
                f"Invalid memory-write hole {index} at {address:#x}: {error}"
            ) from error
        if hole.offset < logical_offset:
            raise DeterministicLogFormatError(
                f"Memory-write hole {index} at {address:#x} is unordered or overlaps."
            )
        if hole.end > size:
            raise DeterministicLogFormatError(
                f"Memory-write hole {index} at {address:#x} extends beyond size {size}."
            )
        holes.append(hole)
        logical_offset = hole.end

    known: list[KnownMemoryRange] = []
    logical_offset = 0
    for index, hole in enumerate(holes):
        known_size = hole.offset - logical_offset
        if known_size:
            known.append(
                KnownMemoryRange(
                    logical_offset,
                    data.read(
                        known_size,
                        context=f"write {address:#x} segment before hole {index}",
                    ),
                )
            )
        logical_offset = hole.end
    tail_size = size - logical_offset
    if tail_size:
        known.append(
            KnownMemoryRange(
                logical_offset,
                data.read(tail_size, context=f"write {address:#x} tail"),
            )
        )

    try:
        return MemoryWrite(
            tid,
            address,
            size,
            tuple(known),
            tuple(holes),
            bool(raw_write.sizeIsConservative),
        )
    except ValueError as error:
        raise DeterministicLogFormatError(
            f"Invalid memory write at {address:#x}: {error}"
        ) from error


def _decode_syscall_extra(raw_extra: Any) -> SyscallExtra:
    variant = _union_variant(raw_extra, context="system-call extra")
    if variant == "none":
        return SyscallExtra()
    if variant == "writeOffset":
        offset = int(raw_extra.writeOffset)
        if offset < 0:
            raise DeterministicLogFormatError("A system-call write offset is negative.")
        return SyscallExtra(variant, write_offset=offset)
    if variant == "execFdsToClose":
        fds = tuple(int(fd) for fd in raw_extra.execFdsToClose)
        if any(fd < 0 for fd in fds):
            raise DeterministicLogFormatError("A system-call close list has a negative fd.")
        return SyscallExtra(variant, exec_fds_to_close=fds)
    if variant == "openedFds":
        opened = tuple(
            OpenedFileDescriptor(
                int(item.fd),
                bytes(item.path),
                int(item.device),
                int(item.inode),
            )
            for item in raw_extra.openedFds
        )
        if any(item.fd < 0 for item in opened):
            raise DeterministicLogFormatError("An opened-file record has a negative fd.")
        return SyscallExtra(variant, opened_fds=opened)
    if variant == "socketAddrs":
        return SyscallExtra(
            variant,
            socket_local_address=bytes(raw_extra.socketAddrs.localAddr),
            socket_remote_address=bytes(raw_extra.socketAddrs.remoteAddr),
        )
    if variant == "madviseRanges":
        try:
            ranges = tuple(
                MemoryAdviceRange(int(item.start), int(item.end))
                for item in raw_extra.madviseRanges
            )
        except ValueError as error:
            raise DeterministicLogFormatError(
                f"Invalid madvise system-call range: {error}"
            ) from error
        return SyscallExtra(variant, madvise_ranges=ranges)
    raise DeterministicLogFormatError(
        f"Unknown system-call extra variant {variant!r}."
    )


def _decode_signal(raw_signal: Any, *, context: str) -> SignalDescriptor:
    arch = _arch_from_rr(raw_signal.siginfoArch, context=f"{context} siginfo")
    disposition = str(raw_signal.disposition)
    if disposition not in ("fatal", "userHandler", "ignored"):
        raise DeterministicLogFormatError(
            f"{context} has unknown signal disposition {disposition!r}."
        )
    try:
        return SignalDescriptor(
            arch,
            bytes(raw_signal.siginfo),
            bool(raw_signal.deterministic),
            disposition,
        )
    except ValueError as error:
        raise DeterministicLogFormatError(
            f"Invalid signal descriptor for {context}: {error}"
        ) from error


def _event_pc(registers: RegisterValues) -> int | None:
    try:
        return registers["PC"]
    except KeyError:
        return None


def _event_from_frame(
    frame: Any,
    event_count: int,
    data: _RawDataCursor,
) -> Event:
    tid = int(frame.tid)
    if tid <= 0:
        raise DeterministicLogFormatError(
            f"RR event {event_count} has invalid thread ID {tid}."
        )
    if int(frame.ticks) < 0:
        raise DeterministicLogFormatError(
            f"RR event {event_count} has negative tick count."
        )
    arch = _arch_from_rr(frame.arch, context=f"event {event_count}")
    event_type = _union_variant(frame.event, context=f"event {event_count}")

    try:
        extra_registers = ExtraRegisterState.from_rr(
            arch,
            bytes(frame.extraRegisters.raw),
        )
    except ValueError as error:
        raise DeterministicLogFormatError(
            f"Invalid extra-register payload at event {event_count}: {error}"
        ) from error

    raw_registers = bytes(frame.registers.raw)
    register_event_types = {
        "instructionTrap",
        "patchSyscall",
        "sched",
        "syscall",
        "signal",
        "signalDelivery",
        "signalHandler",
        "patchAfterSyscall",
        "patchVsyscall",
        "patchTrappingInstruction",
    }
    if not raw_registers and event_type in register_event_types:
        raise DeterministicLogFormatError(
            f"RR {event_type} event {event_count} has no register payload."
        )
    if raw_registers:
        decoded = decode_registers(arch, raw_registers)
        registers = decoded.registers
    else:
        decoded = DecodedRegisterPayload(RegisterValues(arch, {}))
        registers = decoded.registers

    memory_writes = tuple(
        _decode_memory_write(raw_write, data) for raw_write in frame.memWrites
    )

    if event_type == "syscall":
        raw_syscall = frame.event.syscall
        syscall_arch = _arch_from_rr(
            raw_syscall.arch, context=f"system call at event {event_count}"
        )
        syscall_state = str(raw_syscall.state)
        if syscall_state not in ("enteringPtrace", "entering", "exiting"):
            raise DeterministicLogFormatError(
                f"Event {event_count} has unknown system-call state "
                f"{syscall_state!r}."
            )
        if syscall_state in ("enteringPtrace", "entering"):
            mutable_registers = dict(registers.items())
            if arch.archname == "x86_64":
                if decoded.original_syscall_number is None:
                    raise DeterministicLogFormatError(
                        f"Event {event_count} lacks x86-64 orig_rax."
                    )
                mutable_registers["RAX"] = decoded.original_syscall_number
                if mutable_registers["RIP"] < 2:
                    raise DeterministicLogFormatError(
                        f"Event {event_count} has an invalid x86-64 entry PC."
                    )
                mutable_registers["RIP"] -= 2
            elif arch.archname == "aarch64":
                if decoded.original_argument1 is None:
                    raise DeterministicLogFormatError(
                        f"Event {event_count} lacks AArch64 orig_x0."
                    )
                mutable_registers["X0"] = decoded.original_argument1
                if decoded.original_syscall_number is None:
                    raise DeterministicLogFormatError(
                        f"Event {event_count} lacks AArch64 orig_syscall."
                    )
                mutable_registers["X8"] = decoded.original_syscall_number & (
                    (1 << 64) - 1
                )
                if mutable_registers["PC"] < 4:
                    raise DeterministicLogFormatError(
                        f"Event {event_count} has an invalid AArch64 entry PC."
                    )
                mutable_registers["PC"] -= 4
            registers = RegisterValues(arch, mutable_registers)
        return SyscallEvent(
            _event_pc(registers),
            tid,
            arch,
            registers,
            memory_writes,
            syscall_arch,
            int(raw_syscall.number),
            syscall_state,
            bool(raw_syscall.failedDuringPreparation),
            _decode_syscall_extra(raw_syscall.extra),
            event_count=event_count,
            extra_registers=extra_registers,
        )

    if event_type == "syscallbufFlush":
        return SyscallBufferFlushEvent(
            _event_pc(registers),
            tid,
            arch,
            registers,
            memory_writes,
            bytes(frame.event.syscallbufFlush.mprotectRecords),
            event_count=event_count,
            extra_registers=extra_registers,
        )

    if event_type in ("signal", "signalDelivery", "signalHandler"):
        descriptor = _decode_signal(
            getattr(frame.event, event_type), context=f"event {event_count}"
        )
        variants = {
            "signal_number": descriptor if event_type == "signal" else None,
            "signal_delivery": descriptor if event_type == "signalDelivery" else None,
            "signal_handler": descriptor if event_type == "signalHandler" else None,
        }
        return SignalEvent(
            _event_pc(registers),
            tid,
            arch,
            registers,
            memory_writes,
            event_count=event_count,
            extra_registers=extra_registers,
            **variants,
        )

    generic_event_types = {
        "instructionTrap",
        "patchSyscall",
        "syscallbufAbortCommit",
        "syscallbufReset",
        "sched",
        "growMap",
        "exit",
        "patchAfterSyscall",
        "patchVsyscall",
        "patchTrappingInstruction",
    }
    if event_type not in generic_event_types:
        raise DeterministicLogFormatError(
            f"Event {event_count} has unknown variant {event_type!r}."
        )
    return Event(
        _event_pc(registers),
        tid,
        arch,
        registers,
        memory_writes,
        event_type,
        event_count,
        extra_registers,
    )


def _task_from_record(raw_task: Any) -> Task:
    event_count = int(raw_task.frameTime)
    tid = int(raw_task.tid)
    variant = _union_variant(raw_task, context=f"task event {event_count}")
    try:
        if variant == "clone":
            return CloneTask(
                event_count,
                tid,
                int(raw_task.clone.parentTid),
                int(raw_task.clone.flags),
                int(raw_task.clone.ownNsTid),
            )
        if variant == "exec":
            return ExecTask(
                event_count,
                tid,
                bytes(raw_task.exec.fileName),
                tuple(bytes(item) for item in raw_task.exec.cmdLine),
                int(raw_task.exec.exeBase),
                int(raw_task.exec.interpBase),
                bytes(raw_task.exec.interpName),
                bytes(raw_task.exec.pacData.raw),
            )
        if variant == "exit":
            return ExitTask(event_count, tid, int(raw_task.exit.exitStatus))
        if variant == "detach":
            return DetachTask(event_count, tid)
    except ValueError as error:
        raise DeterministicLogFormatError(
            f"Invalid {variant} task event at count {event_count}: {error}"
        ) from error
    raise DeterministicLogFormatError(
        f"Task event {event_count} has unknown variant {variant!r}."
    )


def _mapping_from_record(raw_mapping: Any) -> MemoryMapping:
    event_count = int(raw_mapping.frameTime)
    variant = _union_variant(
        raw_mapping.source, context=f"mapping at event {event_count}"
    )
    if variant not in ("zero", "trace", "file"):
        raise DeterministicLogFormatError(
            f"Mapping at event {event_count} has unknown source {variant!r}."
        )
    source_file = (
        bytes(raw_mapping.source.file.backingFileName)
        if variant == "file"
        else None
    )
    try:
        return MemoryMapping(
            event_count,
            int(raw_mapping.start),
            int(raw_mapping.end),
            variant,
            int(raw_mapping.fileOffsetBytes),
            int(raw_mapping.prot),
            int(raw_mapping.flags),
            bytes(raw_mapping.fsname),
            source_file,
        )
    except ValueError as error:
        raise DeterministicLogFormatError(
            f"Invalid mapping at event {event_count}: {error}"
        ) from error


class RRDeterministicLog:
    """Materialized reader for the packaged RR trace-version-85 schema."""

    def __init__(self, base_directory: Path):
        self.base_directory = base_directory.resolve()
        if not self.base_directory.is_dir():
            raise DeterministicLogFormatError(
                f"RR deterministic log is not a directory: {self.base_directory}."
            )
        self.metadata = self._read_metadata()
        self._events: tuple[Event, ...] | None = None
        self._tasks: tuple[Task, ...] | None = None
        self._mappings: tuple[MemoryMapping, ...] | None = None

    def _file(self, name: str) -> Path:
        path = self.base_directory / name
        if not path.is_file():
            raise DeterministicLogFormatError(
                f"RR deterministic log is missing required file: {path}."
            )
        return path

    def events_file(self) -> Path:
        return self._file("events")

    def tasks_file(self) -> Path:
        return self._file("tasks")

    def mmaps_file(self) -> Path:
        return self._file("mmaps")

    def data_file(self) -> Path:
        return self._file("data")

    def _read_metadata(self) -> RRTraceMetadata:
        version_path = self._file("version")
        try:
            with version_path.open("rb") as stream:
                version_line = stream.readline(64)
                if not version_line.endswith(b"\n"):
                    raise _format_error(
                        "version line is missing its newline", source=version_path
                    )
                try:
                    trace_version = int(version_line[:-1].decode("ascii"))
                except (UnicodeDecodeError, ValueError) as error:
                    raise _format_error(
                        f"invalid RR trace version {version_line!r}", source=version_path
                    ) from error
                if trace_version != RR_TRACE_VERSION:
                    raise _format_error(
                        f"unsupported RR trace version {trace_version}; expected "
                        f"{RR_TRACE_VERSION}",
                        source=version_path,
                    )
                header_data = stream.read()
                try:
                    header = RR_SCHEMA.Header.from_bytes_packed(
                        header_data,
                        traversal_limit_in_words=CAPNP_TRAVERSAL_LIMIT_WORDS,
                    )
                except capnp.KjException as error:
                    raise _format_error(
                        f"invalid RR trace header: {error}", source=version_path
                    ) from error
        except OSError as error:
            raise _format_error(str(error), source=version_path) from error

        if not bool(header.ok):
            raise _format_error("RR recording is marked incomplete", source=version_path)
        trace_uuid = bytes(header.uuid)
        if len(trace_uuid) != 16:
            raise _format_error(
                f"RR trace UUID has length {len(trace_uuid)}, expected 16",
                source=version_path,
            )
        native_arch = _arch_from_rr(header.nativeArch, context="RR trace header")
        return RRTraceMetadata(
            trace_version,
            RR_SCHEMA_VERSION,
            RR_SCHEMA_ID,
            native_arch,
            trace_uuid,
        )

    def events(self) -> tuple[Event, ...]:
        if self._events is None:
            event_path = self.events_file()
            raw_data_path = self.data_file()
            frames = _read_packed_records(
                read_compressed_stream(event_path),
                RR_SCHEMA.Frame,
                source=event_path,
            )
            data = _RawDataCursor(read_compressed_stream(raw_data_path), raw_data_path)
            self._events = tuple(
                _event_from_frame(frame, index, data)
                for index, frame in enumerate(frames, start=1)
            )
            data.require_exhausted()
        return self._events

    def tasks(self) -> tuple[Task, ...]:
        if self._tasks is None:
            path = self.tasks_file()
            records = _read_packed_records(
                read_compressed_stream(path), RR_SCHEMA.TaskEvent, source=path
            )
            tasks = tuple(_task_from_record(record) for record in records)
            counts = [task.event_count for task in tasks]
            if counts != sorted(counts):
                raise DeterministicLogFormatError(
                    "RR task events are not sorted by frame time."
                )
            self._tasks = tasks
        return self._tasks

    def mmaps(self) -> tuple[MemoryMapping, ...]:
        if self._mappings is None:
            path = self.mmaps_file()
            records = _read_packed_records(
                read_compressed_stream(path), RR_SCHEMA.MMap, source=path
            )
            mappings = tuple(_mapping_from_record(record) for record in records)
            counts = [mapping.event_count for mapping in mappings]
            if counts != sorted(counts):
                raise DeterministicLogFormatError(
                    "RR memory mappings are not sorted by frame time."
                )
            self._mappings = mappings
        return self._mappings
