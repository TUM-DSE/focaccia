import socket
import struct
import threading
from collections.abc import Buffer, Callable

import pytest

from focaccia.arch import aarch64, x86
from focaccia.qemu.transport import (
    ABORT_ACK,
    COMMAND_SIZE,
    FINISH_ACK,
    HANDSHAKE_ACK,
    PLUGIN_API_VERSION,
    PLUGIN_MAGIC,
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


def handshake(
    *,
    target: bytes = b"x86_64",
    endianness: int = 1,
    protocol_version: int = PLUGIN_PROTOCOL_VERSION,
    api_min: int = PLUGIN_API_VERSION,
    api_current: int = PLUGIN_API_VERSION,
) -> bytes:
    return struct.pack(
        "<8sII16sBBBB4s",
        PLUGIN_MAGIC,
        protocol_version,
        1234,
        target,
        endianness,
        64,
        api_min,
        api_current,
        bytes(4),
    )


def test_socketpair_register_frame_handles_fragmented_response():
    client, peer = socket.socketpair()
    value = 0x1122334455667788

    def respond(sock: socket.socket) -> None:
        command = read_exact(sock, COMMAND_SIZE)
        assert command[0] == 1
        assert command[8:24].split(b"\0", 1)[0] == b"rax"
        response = struct.pack(
            "<BB6x32s64s",
            0,
            8,
            b"rax",
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
            "<BB6x32s64s",
            0,
            8,
            b"x0",
            value.to_bytes(8, "big") + bytes(56),
        )
    )
    transport = PluginTransport(
        client,
        aarch64.ArchAArch64("big"),
    )

    assert transport.read_register("x0").value == value

    command = read_exact(peer, COMMAND_SIZE)
    assert command[0] == 1
    assert command[8:24].split(b"\0", 1)[0] == b"x0"
    transport.close()
    peer.close()


def test_big_endian_memory_frame_uses_little_endian_metadata_and_exact_payload_reads():
    client, peer = socket.socketpair()
    address = 0x4000
    data = b"fragmented-memory"

    def respond(sock: socket.socket) -> None:
        command = read_exact(sock, COMMAND_SIZE)
        opcode, sent_address, sent_size = struct.unpack("<B7xQQ8x", command)
        assert (opcode, sent_address, sent_size) == (2, address, len(data))
        response = struct.pack("<B7xQQ", 0, address, len(data)) + data
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


def test_mismatched_register_response_name_is_a_protocol_error():
    client, peer = socket.socketpair()
    peer.sendall(
        struct.pack(
            "<BB6x32s64s",
            0,
            8,
            b"rbx",
            bytes(64),
        )
    )
    transport = PluginTransport(client, x86.ArchX86())

    with pytest.raises(PluginProtocolError, match="for request"):
        transport.read_register("rax")

    assert read_exact(peer, COMMAND_SIZE)[0] == 1
    transport.close()
    peer.close()


def test_mismatched_memory_response_address_is_a_protocol_error():
    client, peer = socket.socketpair()
    address = 0x4000
    peer.sendall(struct.pack("<B7xQQ", 0, address + 1, 4))
    transport = PluginTransport(client, x86.ArchX86())

    with pytest.raises(PluginProtocolError, match="returned address"):
        transport.read_memory(address, 4)

    assert read_exact(peer, COMMAND_SIZE)[0] == 2
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


def test_unavailable_memory_response_must_echo_requested_address():
    client, peer = socket.socketpair()
    peer.sendall(struct.pack("<B7xQQ", 1, 0, 0))
    transport = PluginTransport(client, x86.ArchX86())

    with pytest.raises(PluginProtocolError, match="returned address"):
        transport.read_memory(0x4000, 4)

    assert read_exact(peer, COMMAND_SIZE)[0] == 2
    transport.close()
    peer.close()


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


def test_protocol_handshake_negotiates_and_validates_guest_identity():
    client, peer = socket.socketpair()
    peer.sendall(handshake())
    transport = PluginTransport(client, x86.ArchX86())

    received = transport.receive_handshake()

    assert received.version == PLUGIN_PROTOCOL_VERSION
    assert received.pid == 1234
    assert received.target == "x86_64"
    assert received.endianness == "little"
    assert received.plugin_api_min == PLUGIN_API_VERSION
    assert received.plugin_api_current == PLUGIN_API_VERSION
    assert read_exact(peer, len(HANDSHAKE_ACK)) == HANDSHAKE_ACK
    transport.close()
    peer.close()

    left, right = socket.socketpair()
    with pytest.raises(PluginProtocolVersionError):
        PluginTransport(left, x86.ArchX86(), version=99)
    left.close()
    right.close()


def test_protocol_handshake_rejects_wrong_guest_before_acknowledgement():
    client, peer = socket.socketpair()
    peer.sendall(handshake(target=b"aarch64"))
    transport = PluginTransport(client, x86.ArchX86())

    with pytest.raises(PluginProtocolError, match="does not match"):
        transport.receive_handshake()

    peer.settimeout(0.05)
    with pytest.raises(TimeoutError):
        peer.recv(1)
    transport.close()
    peer.close()


@pytest.mark.parametrize(
    ("method", "opcode", "acknowledgement"),
    [("finish", 4, FINISH_ACK), ("abort", 5, ABORT_ACK)],
)
def test_terminal_commands_require_acknowledgement_and_close_transport(
    method: str,
    opcode: int,
    acknowledgement: bytes,
):
    client, peer = socket.socketpair()

    def respond(sock: socket.socket) -> None:
        command = read_exact(sock, COMMAND_SIZE)
        assert command == bytes([opcode]) + bytes(COMMAND_SIZE - 1)
        for byte in acknowledgement:
            sock.sendall(bytes([byte]))

    thread, errors = peer_thread(peer, respond)
    transport = PluginTransport(LimitedRecvSocket(client, 1), x86.ArchX86())

    getattr(transport, method)()

    assert transport.completed
    assert transport.closed
    finish_peer(thread, errors)


def test_transport_context_manager_closes_owned_socket():
    client, peer = socket.socketpair()
    with PluginTransport(client, x86.ArchX86()) as transport:
        assert not transport.closed
    assert transport.closed
    assert client.fileno() == -1
    peer.close()
