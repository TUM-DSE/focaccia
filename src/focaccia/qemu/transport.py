"""Owned, bounded framing for the pinned QEMU plugin protocol."""

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


PLUGIN_PROTOCOL_VERSION = 1
"""Version 1 is the fixed-frame layout implemented by the pinned plugin.

The legacy peer sends only a PID during its handshake, so this version is
selected by configuration rather than negotiated on the wire. A future peer
version must add negotiation instead of silently changing these frames.
"""

COMMAND_SIZE = 25
REGISTER_RESPONSE_SIZE = 180
MEMORY_HEADER_SIZE = 16
HANDSHAKE_SIZE = 4
MAX_REGISTER_BYTES = 64
DEFAULT_MAX_MEMORY_PAYLOAD = 16 * 1024 * 1024


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
        frame = struct.pack("=16s9s", encoded, b"READ REG")
    elif command == "read-memory":
        if address < 0 or size < 0:
            raise ValueError("Plugin memory addresses and sizes cannot be negative.")
        if address >= 1 << 64 or size >= 1 << 64:
            raise ValueError("Plugin memory addresses and sizes must fit in 64 bits.")
        frame = struct.pack("=QQ9s", address, size, b"READ MEM")
    elif command == "step":
        frame = struct.pack("=qq9s", 0, 0, b"STEP ONE")
    else:
        raise ValueError(f"Unknown plugin command {command!r}.")
    if len(frame) != COMMAND_SIZE:
        raise RuntimeError(f"Internal plugin command size mismatch: {len(frame)}.")
    return frame


class PluginTransport:
    """One owned connection to a single plugin instance."""

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

    @property
    def closed(self) -> bool:
        return self._closed

    def receive_handshake(self) -> PluginHandshake:
        raw_pid = read_exact(self._connection, HANDSHAKE_SIZE)
        (pid,) = struct.unpack("=i", raw_pid)
        if pid <= 0:
            raise PluginProtocolError(f"Plugin supplied invalid process ID {pid}.")
        return PluginHandshake(self.version, pid)

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
        raw_name, size, raw_value = struct.unpack("=108sQ64s", response)
        try:
            name = raw_name.split(b"\0", 1)[0].decode("utf-8")
        except UnicodeDecodeError as error:
            raise PluginProtocolError("Plugin returned a non-UTF-8 register name.") from error
        if name == "UNKNOWN":
            raise RegisterAccessError(
                register,
                f"QEMU plugin cannot access register {register}.",
            )
        if not name:
            raise PluginProtocolError("Plugin returned an empty register name.")
        if size == 0 or size > MAX_REGISTER_BYTES:
            raise PluginProtocolError(
                f"Plugin returned invalid size {size} for register {name}."
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
        self._send_command(
            _pack_command("read-memory", address=address, size=size)
        )
        header = read_exact(self._connection, MEMORY_HEADER_SIZE)
        returned_address, returned_size = struct.unpack("=QQ", header)
        if returned_size == 0:
            raise MemoryAccessError(
                address,
                size,
                f"QEMU plugin cannot access {size} bytes at {hex(address)}.",
            )
        if returned_address != address:
            raise PluginProtocolError(
                f"Plugin returned address {hex(returned_address)} for a read at "
                f"{hex(address)}."
            )
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
