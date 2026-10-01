"""Owned, bounded framing for the Focaccia QEMU plugin protocol."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import stat
import struct
from collections.abc import Buffer
from dataclasses import dataclass
from typing import Protocol

from focaccia.arch import Arch
from focaccia.snapshot import MemoryAccessError, RegisterAccessError

from .state import RegisterObservation


PLUGIN_API_VERSION = 4
PLUGIN_MAGIC = b"FOCPLUG\0"
HANDSHAKE_ACK = b"FOCACPT\0"
FINISH_ACK = b"FOCFIN\0\0" + bytes(8)
ABORT_ACK = b"FOCABR\0\0" + bytes(8)

COMMAND_SIZE = 32
REGISTER_RESPONSE_SIZE = 104
MEMORY_HEADER_SIZE = 24
HANDSHAKE_SIZE = 176
EVENT_SIZE = 96
MAX_REGISTER_BYTES = 64
DEFAULT_MAX_MEMORY_PAYLOAD = 16 * 1024 * 1024
MAX_SNAPSHOT_PLANS = 4096
MAX_PLAN_REGISTERS = 32
PLAN_REGISTER_SIZE = 16
PLAN_ACK_SIZE = 32
SNAPSHOT_HEADER_SIZE = 40
SNAPSHOT_VALUE_SIZE = 64

_COMMAND_READ_REGISTER = 1
_COMMAND_READ_MEMORY = 2
_COMMAND_STEP = 3
_COMMAND_FINISH = 4
_COMMAND_ABORT = 5
_COMMAND_INSTALL_PLAN = 6
_COMMAND_CAPTURE_PLAN = 7
_RESPONSE_OK = 0
_RESPONSE_UNAVAILABLE = 1
_ENDIANNESS_CODES = {"little": 1, "big": 2}
CAP_PC = 1 << 0
CAP_INTEGER = 1 << 1
CAP_STATUS = 1 << 2
CAP_VECTOR = 1 << 3
CAP_TLS = 1 << 4
CAP_AARCH64_SVC = 1 << 5
CAP_BOUNDARY_SNAPSHOTS = 1 << 6

EVENT_CUTPOINT = 1
EVENT_STORE = 2
EVENT_AARCH64_SVC_ENTRY = 3
EVENT_AARCH64_SVC_SUCCESSOR = 4
EVENT_TRANSLATION_BLOCK = 5

_TARGET_NAMES = {
    ("x86_64", "little"): "x86_64",
    ("aarch64", "little"): "aarch64",
    ("aarch64", "big"): "aarch64_be",
}


class SocketLike(Protocol):
    def recv(self, size: int, /) -> bytes: ...
    def sendall(self, data: Buffer, /) -> None: ...
    def shutdown(self, how: int, /) -> None: ...
    def close(self) -> None: ...


class PluginProtocolError(RuntimeError):
    """The plugin peer violated the selected wire protocol."""


class PluginProtocolVersionError(PluginProtocolError):
    pass


class PluginEOFError(PluginProtocolError):
    def __init__(self, expected: int, received: int):
        self.expected = expected
        self.received = received
        super().__init__(
            f"Plugin connection closed after {received} of {expected} expected bytes."
        )


@dataclass(frozen=True, slots=True)
class PluginLaunchIdentity:
    binary_sha256: str
    argv_sha256: str
    env_sha256: str
    cpu_sha256: str

    def digests(self) -> tuple[bytes, ...]:
        values = (self.binary_sha256, self.argv_sha256, self.env_sha256, self.cpu_sha256)
        try:
            decoded = tuple(bytes.fromhex(value) for value in values)
        except ValueError as error:
            raise ValueError("Plugin launch identity must use hexadecimal SHA-256 digests.") from error
        if any(len(value) != 32 for value in decoded):
            raise ValueError("Plugin launch identity fields must be SHA-256 digests.")
        return decoded


def manifest_sha256(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class PluginEvent:
    kind: int
    sequence: int
    epoch: int
    pc: int
    address: int
    size: int
    auxiliary: int
    value: bytes


@dataclass(frozen=True, slots=True)
class BoundarySnapshotUnavailable(RuntimeError):
    """The plugin could not capture a plan; the caller must fall back synchronously."""


@dataclass(frozen=True, slots=True)
class SnapshotPlan:
    pc: int
    generation: int
    registers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BoundarySnapshot:
    pc: int
    generation: int
    occurrence: int
    event_sequence: int
    registers: tuple[RegisterObservation, ...]


@dataclass(frozen=True, slots=True)
class PluginHandshake:
    pid: int
    target: str
    endianness: str
    address_bits: int
    plugin_api_min: int
    plugin_api_current: int
    capabilities: int
    identity: PluginLaunchIdentity


def read_exact(connection: SocketLike, size: int) -> bytes:
    """Read exactly ``size`` bytes or raise a typed EOF error."""
    if size < 0:
        raise ValueError("A framed read size cannot be negative.")
    data = bytearray()
    while len(data) < size:
        try:
            chunk = connection.recv(size - len(data))
        except InterruptedError:
            continue
        except ConnectionResetError as error:
            raise PluginEOFError(size, len(data)) from error
        if not chunk:
            raise PluginEOFError(size, len(data))
        data.extend(chunk)
    return bytes(data)


def _pack_command(
    command: str,
    *,
    register: str = "",
    address: int = 0,
    size: int = 0,
) -> bytes:
    if command == "read-register":
        encoded = register.encode("utf-8")
        if not encoded or len(encoded) >= 16:
            raise ValueError("Plugin register names must contain between 1 and 15 bytes.")
        frame = struct.pack("<B7x16s8x", _COMMAND_READ_REGISTER, encoded)
    elif command == "read-memory":
        if address < 0 or size < 0:
            raise ValueError("Plugin memory addresses and sizes cannot be negative.")
        if address >= 1 << 64 or size >= 1 << 64:
            raise ValueError("Plugin memory addresses and sizes must fit in 64 bits.")
        frame = struct.pack("<B7xQQ8x", _COMMAND_READ_MEMORY, address, size)
    elif command == "step":
        frame = struct.pack("<B31x", _COMMAND_STEP)
    elif command == "finish":
        frame = struct.pack("<B31x", _COMMAND_FINISH)
    elif command == "abort":
        frame = struct.pack("<B31x", _COMMAND_ABORT)
    elif command in {"install-plan", "capture-plan"}:
        if address < 0 or address >= 1 << 64 or size <= 0 or size >= 1 << 64:
            raise ValueError("Snapshot plan identity must use nonzero bounded integers.")
        opcode = _COMMAND_INSTALL_PLAN if command == "install-plan" else _COMMAND_CAPTURE_PLAN
        frame = struct.pack("<B7xQQI4x", opcode, address, size, 0)
    else:
        raise ValueError(f"Unknown plugin command {command!r}.")
    if len(frame) != COMMAND_SIZE:
        raise RuntimeError(f"Internal plugin command size mismatch: {len(frame)}.")
    return frame


def _decode_fixed_string(raw: bytes, context: str) -> str:
    encoded, separator, trailing = raw.partition(b"\0")
    if not separator or any(trailing):
        raise PluginProtocolError(f"Plugin returned malformed {context}.")
    try:
        value = encoded.decode("ascii")
    except UnicodeDecodeError as error:
        raise PluginProtocolError(f"Plugin returned non-ASCII {context}.") from error
    if not value:
        raise PluginProtocolError(f"Plugin returned empty {context}.")
    return value


class PluginTransport:
    """One owned connection using the lockstep internal plugin wire format."""

    def __init__(
        self,
        connection: SocketLike,
        arch: Arch,
        *,
        max_memory_payload: int = DEFAULT_MAX_MEMORY_PAYLOAD,
        expected_identity: PluginLaunchIdentity | None = None,
        required_capabilities: int | None = None,
    ):
        if max_memory_payload <= 0:
            raise ValueError("Plugin payload limit must be positive.")
        self._connection = connection
        self.arch = arch
        self.max_memory_payload = max_memory_payload
        self.expected_identity = expected_identity
        self.required_capabilities = required_capabilities
        self._closed = False
        self._last_sequence = 0
        self._last_epoch = 0
        self._completed = False
        self._plans: dict[int, SnapshotPlan] = {}
        self._snapshot_occurrences: dict[tuple[int, int], int] = {}
        self._boundary_pc: int | None = None

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def completed(self) -> bool:
        return self._completed

    def receive_handshake(self) -> PluginHandshake:
        raw = read_exact(self._connection, HANDSHAKE_SIZE)
        (
            magic, reserved_protocol, pid, raw_target, endianness_code, address_bits,
            api_min, api_current, reserved, capabilities, identity_raw,
        ) = struct.unpack("<8s4sI16sBBBB4sQ128s", raw)
        if magic != PLUGIN_MAGIC:
            raise PluginProtocolError("Plugin supplied invalid handshake magic.")
        if any(reserved_protocol):
            raise PluginProtocolError("Plugin handshake protocol-reserved bytes are nonzero.")
        if pid <= 0:
            raise PluginProtocolError(f"Plugin supplied invalid process ID {pid}.")
        if any(reserved):
            raise PluginProtocolError("Plugin handshake reserved bytes are nonzero.")
        target = _decode_fixed_string(raw_target, "target name")
        expected_target = _TARGET_NAMES.get((self.arch.archname, self.arch.endianness))
        if expected_target is None or target != expected_target:
            raise PluginProtocolError(
                f"Plugin target {target!r} does not match expected {expected_target!r}."
            )
        expected_endianness = _ENDIANNESS_CODES[self.arch.endianness]
        if endianness_code != expected_endianness:
            raise PluginProtocolError(
                "Plugin target endianness does not match the selected guest architecture."
            )
        if address_bits != self.arch.ptr_size:
            raise PluginProtocolError(
                f"Plugin address width {address_bits} does not match "
                f"{self.arch.ptr_size}."
            )
        if not api_min <= PLUGIN_API_VERSION <= api_current:
            raise PluginProtocolVersionError(
                f"Plugin API range {api_min}..{api_current} does not include "
                f"required version {PLUGIN_API_VERSION}."
            )
        identity_values = tuple(
            identity_raw[offset:offset + 32].hex() for offset in range(0, 128, 32)
        )
        identity = PluginLaunchIdentity(*identity_values)
        if self.expected_identity is None:
            raise PluginProtocolError("Plugin launch identity was not configured by the validator.")
        if identity != self.expected_identity:
            raise PluginProtocolError("Plugin launch identity does not match the controlled launch manifest.")
        required = self.required_capabilities
        if required is None:
            required = CAP_PC | CAP_INTEGER | CAP_STATUS
            if self.arch.archname == "aarch64":
                required |= CAP_AARCH64_SVC
        if required == 0 or capabilities & required != required:
            raise PluginProtocolError(
                f"Plugin capabilities {capabilities:#x} do not satisfy required {required:#x}."
            )
        self._connection.sendall(HANDSHAKE_ACK + struct.pack("<Q", required))
        return PluginHandshake(
            pid, target, self.arch.endianness, address_bits,
            api_min, api_current, capabilities, identity,
        )

    def receive_event(self) -> PluginEvent:
        raw = read_exact(self._connection, EVENT_SIZE)
        kind, flags, sequence, epoch, pc, address, size, auxiliary, value, padding = struct.unpack(
            "<BB6xQQQQQQ16s24s", raw
        )
        if flags or any(padding) or kind not in {
            EVENT_CUTPOINT, EVENT_STORE, EVENT_AARCH64_SVC_ENTRY,
            EVENT_AARCH64_SVC_SUCCESSOR, EVENT_TRANSLATION_BLOCK,
        }:
            raise PluginProtocolError("Plugin returned a malformed event frame.")
        if sequence != self._last_sequence + 1 or epoch <= self._last_epoch:
            raise PluginProtocolError("Plugin events are not strictly ordered and monotonic.")
        if kind == EVENT_STORE:
            if size not in (1, 2, 4, 8, 16) or any(value[size:]):
                raise PluginProtocolError("Plugin returned a malformed store event.")
        elif kind == EVENT_TRANSLATION_BLOCK:
            if (
                size == 0
                or size > 1_048_576
                or pc % 4
                or address != pc + (size - 1) * 4
                or auxiliary != 0
                or any(value)
            ):
                raise PluginProtocolError("Plugin returned a malformed translation-block event.")
        elif size != 0 or any(value):
            raise PluginProtocolError("Plugin returned payload bytes for a non-store event.")
        self._last_sequence = sequence
        self._last_epoch = epoch
        self._boundary_pc = pc if kind == EVENT_TRANSLATION_BLOCK else None
        return PluginEvent(kind, sequence, epoch, pc, address, size, auxiliary, value[:size])

    def install_snapshot_plan(self, plan: SnapshotPlan) -> None:
        if self._boundary_pc != plan.pc:
            raise PluginProtocolError("Snapshot plan installation is not at its TB boundary.")
        if not 1 <= len(plan.registers) <= MAX_PLAN_REGISTERS:
            raise ValueError("Snapshot plans must contain between 1 and 32 registers.")
        old = self._plans.get(plan.pc)
        if plan.generation <= 0 or (old is not None and plan.generation <= old.generation):
            raise ValueError("Snapshot plan generation must increase at each PC.")
        encoded = []
        for register in plan.registers:
            try:
                raw = register.encode("ascii")
            except UnicodeEncodeError as error:
                raise ValueError("Snapshot register names must be ASCII.") from error
            if not raw or len(raw) >= PLAN_REGISTER_SIZE:
                raise ValueError("Snapshot register names must contain 1 to 15 bytes.")
            encoded.append(raw + bytes(PLAN_REGISTER_SIZE - len(raw)))
        if len(set(plan.registers)) != len(plan.registers):
            raise ValueError("Snapshot plans cannot contain duplicate registers.")
        self._send_command(struct.pack(
            "<B7xQQI4x", _COMMAND_INSTALL_PLAN, plan.pc, plan.generation,
            len(plan.registers),
        ))
        self._connection.sendall(b"".join(encoded))
        status, pc, generation, count = struct.unpack(
            "<B7xQQI4x", read_exact(self._connection, PLAN_ACK_SIZE)
        )
        if status != _RESPONSE_OK or (pc, generation, count) != (
            plan.pc, plan.generation, len(plan.registers)
        ):
            raise PluginProtocolError("Plugin returned a malformed plan acknowledgement.")
        if len(self._plans) >= MAX_SNAPSHOT_PLANS and old is None:
            raise PluginProtocolError("Snapshot plan table limit exceeded.")
        self._plans[plan.pc] = plan
        self._snapshot_occurrences[(plan.pc, plan.generation)] = 0

    def capture_snapshot(self, pc: int) -> BoundarySnapshot:
        if self._boundary_pc != pc or pc not in self._plans:
            raise PluginProtocolError("Snapshot capture is not at an installed TB boundary.")
        plan = self._plans[pc]
        self._send_command(struct.pack(
            "<B7xQQ8x", _COMMAND_CAPTURE_PLAN, pc, plan.generation
        ))
        status, count, returned_pc, generation, occurrence, sequence = struct.unpack(
            "<B3xIQQQQ", read_exact(self._connection, SNAPSHOT_HEADER_SIZE)
        )
        identity = (returned_pc, generation)
        if identity != (pc, plan.generation):
            raise PluginProtocolError("Plugin snapshot identity does not match its plan.")
        if status == _RESPONSE_UNAVAILABLE:
            if count != 0 or sequence != 0:
                raise PluginProtocolError("Malformed unavailable boundary snapshot.")
            raise BoundarySnapshotUnavailable(
                f"Plugin could not capture plan {generation} at {pc:#x}."
            )
        expected_occurrence = self._snapshot_occurrences[identity] + 1
        if (
            status != _RESPONSE_OK or count != len(plan.registers)
            or occurrence != expected_occurrence or sequence != self._last_sequence
        ):
            raise PluginProtocolError("Boundary snapshot ordering or bounds are invalid.")
        observations = []
        for register in plan.registers:
            size, raw = struct.unpack(
                "<B7x64s", read_exact(self._connection, SNAPSHOT_VALUE_SIZE + 8)
            )
            if size <= 0 or size > MAX_REGISTER_BYTES or any(raw[size:]):
                raise PluginProtocolError("Plugin returned a malformed snapshot register.")
            observations.append(RegisterObservation(
                register, int.from_bytes(raw[:size], self.arch.endianness), size * 8
            ))
        self._snapshot_occurrences[identity] = occurrence
        return BoundarySnapshot(
            pc, generation, occurrence, sequence, tuple(observations)
        )

    def advance(self) -> None:
        self._send_command(_pack_command("step"))
        self._boundary_pc = None

    def _send_command(self, frame: bytes) -> None:
        if self._closed:
            raise PluginProtocolError("Plugin transport is closed.")
        if len(frame) != COMMAND_SIZE:
            raise PluginProtocolError(
                f"Plugin command has length {len(frame)}, expected {COMMAND_SIZE}."
            )
        self._connection.sendall(frame)

    def read_register(self, register: str) -> RegisterObservation:
        self._send_command(_pack_command("read-register", register=register))
        response = read_exact(self._connection, REGISTER_RESPONSE_SIZE)
        status, size, raw_name, raw_value = struct.unpack("<BB6x32s64s", response)
        name = _decode_fixed_string(raw_name, "register name")
        if name != register:
            raise PluginProtocolError(
                f"Plugin returned register {name!r} for request {register!r}."
            )
        if status == _RESPONSE_UNAVAILABLE:
            if size != 0 or any(raw_value):
                raise PluginProtocolError(
                    f"Plugin returned malformed unavailable response for {name}."
                )
            raise RegisterAccessError(
                register,
                f"QEMU plugin cannot access register {register}.",
            )
        if status != _RESPONSE_OK:
            raise PluginProtocolError(
                f"Plugin returned unknown register status {status} for {name}."
            )
        if size == 0 or size > MAX_REGISTER_BYTES:
            raise PluginProtocolError(
                f"Plugin returned invalid size {size} for register {name}."
            )
        if any(raw_value[size:]):
            raise PluginProtocolError(
                f"Plugin returned nonzero padding for register {name}."
            )
        value = int.from_bytes(raw_value[:size], byteorder=self.arch.endianness)
        return RegisterObservation(name, value, size * 8)

    def read_memory(self, address: int, size: int) -> bytes:
        if size < 0:
            raise ValueError("A plugin memory read size cannot be negative.")
        if size == 0:
            return b""
        if size > self.max_memory_payload:
            raise PluginProtocolError(
                f"Requested plugin memory payload {size} exceeds limit "
                f"{self.max_memory_payload}."
            )
        self._send_command(_pack_command("read-memory", address=address, size=size))
        header = read_exact(self._connection, MEMORY_HEADER_SIZE)
        status, returned_address, returned_size = struct.unpack("<B7xQQ", header)
        if returned_address != address:
            raise PluginProtocolError(
                f"Plugin returned address {hex(returned_address)} for a read at "
                f"{hex(address)}."
            )
        if status == _RESPONSE_UNAVAILABLE:
            if returned_size != 0:
                raise PluginProtocolError(
                    "Plugin unavailable-memory response has a nonzero payload size."
                )
            raise MemoryAccessError(
                address,
                size,
                f"QEMU plugin cannot access {size} bytes at {hex(address)}.",
            )
        if status != _RESPONSE_OK:
            raise PluginProtocolError(f"Plugin returned unknown memory status {status}.")
        if returned_size != size:
            raise PluginProtocolError(
                f"Plugin returned {returned_size} bytes for a {size}-byte read at "
                f"{hex(address)}."
            )
        if returned_size > self.max_memory_payload:
            raise PluginProtocolError(
                f"Plugin memory payload {returned_size} exceeds limit "
                f"{self.max_memory_payload}."
            )
        return read_exact(self._connection, returned_size)

    def step(self) -> None:
        self._send_command(_pack_command("step"))

    def finish(self) -> None:
        self._send_command(_pack_command("finish"))
        acknowledgement = read_exact(self._connection, len(FINISH_ACK))
        if acknowledgement != FINISH_ACK:
            raise PluginProtocolError("Plugin returned an invalid finish acknowledgement.")
        self._completed = True
        self.close()

    def abort(self) -> None:
        self._send_command(_pack_command("abort"))
        acknowledgement = read_exact(self._connection, len(ABORT_ACK))
        if acknowledgement != ABORT_ACK:
            raise PluginProtocolError("Plugin returned an invalid abort acknowledgement.")
        self._completed = True
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._connection.close()

    def __enter__(self) -> PluginTransport:
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()


class PluginListener:
    """Context-managed Unix listener that owns its accepted transport."""

    def __init__(
        self,
        path: str,
        arch: Arch,
        *,
        max_memory_payload: int = DEFAULT_MAX_MEMORY_PAYLOAD,
        expected_identity: PluginLaunchIdentity,
        required_capabilities: int | None = None,
    ):
        self.path = path
        self.arch = arch
        self.max_memory_payload = max_memory_payload
        self.expected_identity = expected_identity
        self.required_capabilities = required_capabilities
        self._server: socket.socket | None = None
        self._transport: PluginTransport | None = None
        self._bound = False

    def start(self) -> None:
        if self._server is not None:
            raise RuntimeError("Plugin listener has already been started.")
        try:
            mode = os.lstat(self.path).st_mode
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISSOCK(mode):
                raise PluginProtocolError(
                    f"Refusing to replace non-socket path {self.path}."
                )
            os.unlink(self.path)

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(self.path)
            self._bound = True
            server.listen(1)
        except BaseException:
            server.close()
            if self._bound:
                os.unlink(self.path)
                self._bound = False
            raise
        self._server = server

    def accept(self) -> tuple[PluginTransport, PluginHandshake]:
        if self._server is None:
            raise RuntimeError("Plugin listener has not been started.")
        if self._transport is not None:
            raise RuntimeError("Plugin listener already accepted a connection.")
        connection, _peer = self._server.accept()
        transport = PluginTransport(
            connection,
            self.arch,
            max_memory_payload=self.max_memory_payload,
            expected_identity=self.expected_identity,
            required_capabilities=self.required_capabilities,
        )
        try:
            handshake = transport.receive_handshake()
        except BaseException:
            transport.close()
            raise
        self._transport = transport
        return transport, handshake

    def close(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        if self._server is not None:
            self._server.close()
            self._server = None
        if self._bound:
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass
            self._bound = False

    def __enter__(self) -> PluginListener:
        self.start()
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()
