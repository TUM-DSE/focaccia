"""Owned, bounded framing for the Focaccia QEMU plugin protocol."""

from __future__ import annotations

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


PLUGIN_PROTOCOL_VERSION = 2
PLUGIN_API_VERSION = 4
PLUGIN_MAGIC = b"FOCPLUG\0"
HANDSHAKE_ACK = b"FOCACPT2"
FINISH_ACK = b"FOCFIN02"
ABORT_ACK = b"FOCABR02"

COMMAND_SIZE = 32
REGISTER_RESPONSE_SIZE = 104
MEMORY_HEADER_SIZE = 24
HANDSHAKE_SIZE = 40
MAX_REGISTER_BYTES = 64
DEFAULT_MAX_MEMORY_PAYLOAD = 16 * 1024 * 1024

_COMMAND_READ_REGISTER = 1
_COMMAND_READ_MEMORY = 2
_COMMAND_STEP = 3
_COMMAND_FINISH = 4
_COMMAND_ABORT = 5
_RESPONSE_OK = 0
_RESPONSE_UNAVAILABLE = 1
_ENDIANNESS_CODES = {"little": 1, "big": 2}
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
class PluginHandshake:
    version: int
    pid: int
    target: str
    endianness: str
    address_bits: int
    plugin_api_min: int
    plugin_api_current: int


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
    """One owned connection to a single version-2 plugin instance."""

    def __init__(
        self,
        connection: SocketLike,
        arch: Arch,
        *,
        version: int = PLUGIN_PROTOCOL_VERSION,
        max_memory_payload: int = DEFAULT_MAX_MEMORY_PAYLOAD,
    ):
        if version != PLUGIN_PROTOCOL_VERSION:
            raise PluginProtocolVersionError(
                f"Unsupported plugin protocol version {version}; "
                f"expected {PLUGIN_PROTOCOL_VERSION}."
            )
        if max_memory_payload <= 0:
            raise ValueError("Plugin payload limit must be positive.")
        self._connection = connection
        self.arch = arch
        self.version = version
        self.max_memory_payload = max_memory_payload
        self._closed = False
        self._completed = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def completed(self) -> bool:
        return self._completed

    def receive_handshake(self) -> PluginHandshake:
        raw = read_exact(self._connection, HANDSHAKE_SIZE)
        (
            magic,
            version,
            pid,
            raw_target,
            endianness_code,
            address_bits,
            api_min,
            api_current,
            reserved,
        ) = struct.unpack("<8sII16sBBBB4s", raw)
        if magic != PLUGIN_MAGIC:
            raise PluginProtocolError("Plugin supplied invalid handshake magic.")
        if version != self.version:
            raise PluginProtocolVersionError(
                f"Plugin protocol version {version} does not match {self.version}."
            )
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
        self._connection.sendall(HANDSHAKE_ACK)
        return PluginHandshake(
            version,
            pid,
            target,
            self.arch.endianness,
            address_bits,
            api_min,
            api_current,
        )

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
    ):
        self.path = path
        self.arch = arch
        self.max_memory_payload = max_memory_payload
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
