import socket
import struct
import threading
from collections.abc import Buffer, Callable

import pytest

from focaccia.arch import aarch64, x86
from focaccia.qemu.transport import (
    COMMAND_SIZE,
    PLUGIN_PROTOCOL_VERSION,
    PluginEOFError,
    PluginProtocolError,
    PluginProtocolVersionError,
    PluginTransport,
    read_exact,
)


class LimitedRecvSocket:
    """Real socket wrapper that forces every recv to return a small fragment."""

    def __init__(self, sock: socket.socket, fragment_size: int = 2):
        self.sock = sock
        self.fragment_size = fragment_size

    def recv(self, size: int) -> bytes:
        return self.sock.recv(min(size, self.fragment_size))

    def sendall(self, data: Buffer) -> None:
        self.sock.sendall(data)

    def shutdown(self, how: int) -> None:
        self.sock.shutdown(how)

    def close(self) -> None:
        self.sock.close()


def peer_thread(
    peer: socket.socket,
    action: Callable[[socket.socket], None],
) -> tuple[threading.Thread, list[BaseException]]:
    errors: list[BaseException] = []

    def run() -> None:
        try:
            action(peer)
        except BaseException as error:
            errors.append(error)
        finally:
            peer.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, errors


def finish_peer(thread: threading.Thread, errors: list[BaseException]) -> None:
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert errors == []


def test_socketpair_register_frame_handles_fragmented_response():
    client, peer = socket.socketpair()
    value = 0x1122334455667788

    def respond(sock: socket.socket) -> None:
        command = read_exact(sock, COMMAND_SIZE)
        assert command[16:].rstrip(b"\0") == b"READ REG"
        response = struct.pack(
            "=108sQ64s",
            b"rax",
            8,
            value.to_bytes(8, "little") + bytes(56),
        )
        for byte in response:
            sock.sendall(bytes([byte]))

    thread, errors = peer_thread(peer, respond)
    transport = PluginTransport(
        LimitedRecvSocket(client, fragment_size=3),
        x86.ArchX86(),
    )
    observation = transport.read_register("rax")
    transport.close()
    finish_peer(thread, errors)

    assert observation.name == "rax"
    assert observation.num_bits == 64
    assert observation.value == value


def test_register_value_uses_guest_endianness_not_wire_header_endianness():
    client, peer = socket.socketpair()
    value = 0x0102030405060708
    peer.sendall(
        struct.pack(
            "=108sQ64s",
            b"x0",
            8,
            value.to_bytes(8, "big") + bytes(56),
        )
    )
    transport = PluginTransport(
        client,
        aarch64.ArchAArch64("big"),
    )

    assert transport.read_register("x0").value == value

    assert read_exact(peer, COMMAND_SIZE)[16:].rstrip(b"\0") == b"READ REG"
    transport.close()
    peer.close()


def test_big_endian_memory_frame_uses_native_metadata_and_exact_payload_reads():
    client, peer = socket.socketpair()
    address = 0x4000
    data = b"fragmented-memory"

    def respond(sock: socket.socket) -> None:
        command = read_exact(sock, COMMAND_SIZE)
        sent_address, sent_size, opcode = struct.unpack("=QQ9s", command)
        assert (sent_address, sent_size, opcode.rstrip(b"\0")) == (
            address,
            len(data),
            b"READ MEM",
        )
        response = struct.pack("=QQ", address, len(data)) + data
        for offset in range(0, len(response), 2):
            sock.sendall(response[offset:offset + 2])

    thread, errors = peer_thread(peer, respond)
    transport = PluginTransport(
        LimitedRecvSocket(client, fragment_size=1),
        aarch64.ArchAArch64("big"),
    )
    assert transport.read_memory(address, len(data)) == data
    transport.close()
    finish_peer(thread, errors)


def test_mismatched_memory_response_address_is_a_protocol_error():
    client, peer = socket.socketpair()
    address = 0x4000
    peer.sendall(struct.pack("=QQ", address + 1, 4))
    transport = PluginTransport(client, x86.ArchX86())

    with pytest.raises(PluginProtocolError, match="returned address"):
        transport.read_memory(address, 4)

    assert read_exact(peer, COMMAND_SIZE)[16:].rstrip(b"\0") == b"READ MEM"
    transport.close()
    peer.close()


def test_read_exact_reports_clean_eof_after_partial_frame():
    client, peer = socket.socketpair()
    peer.sendall(b"abc")
    peer.close()

    with pytest.raises(PluginEOFError) as raised:
        read_exact(client, 4)

    client.close()
    assert raised.value.expected == 4
    assert raised.value.received == 3


def test_memory_payload_limit_is_checked_before_sending():
    client, peer = socket.socketpair()
    transport = PluginTransport(
        client,
        x86.ArchX86(),
        max_memory_payload=4,
    )

    with pytest.raises(PluginProtocolError, match="exceeds limit"):
        transport.read_memory(0x1000, 5)

    peer.settimeout(0.05)
    with pytest.raises(TimeoutError):
        peer.recv(1)
    transport.close()
    peer.close()


def test_protocol_version_and_handshake_are_explicit():
    client, peer = socket.socketpair()
    peer.sendall(struct.pack("=i", 1234))
    transport = PluginTransport(client, x86.ArchX86())

    handshake = transport.receive_handshake()

    assert handshake.version == PLUGIN_PROTOCOL_VERSION
    assert handshake.pid == 1234
    transport.close()
    peer.close()

    left, right = socket.socketpair()
    with pytest.raises(PluginProtocolVersionError):
        PluginTransport(left, x86.ArchX86(), version=99)
    left.close()
    right.close()


def test_transport_context_manager_closes_owned_socket():
    client, peer = socket.socketpair()
    with PluginTransport(client, x86.ArchX86()) as transport:
        assert not transport.closed
    assert transport.closed
    assert client.fileno() == -1
    peer.close()
