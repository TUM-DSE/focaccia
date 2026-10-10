"""Guest permission framing must not infer write access from debugger reads."""
import socket
import struct

import pytest

from focaccia.arch import x86
from focaccia.qemu.transport import (
    CAP_MEMORY_PERMISSIONS, COMMAND_SIZE, HANDSHAKE_ACK,
    PluginProtocolError, PluginTransport, read_exact,
)
from focaccia.snapshot import MemoryAccessError
from test_qemu_transport import (
    CAPABILITIES, IDENTITY, LimitedRecvSocket, finish_peer, handshake, peer_thread,
)


@pytest.mark.parametrize("flags", [0, 8, 9, 11, 13, 15])
def test_permission_evidence_roundtrip(flags):
    client, peer = socket.socketpair()

    def respond(sock):
        sock.sendall(handshake(capabilities=CAPABILITIES | CAP_MEMORY_PERMISSIONS))
        ack = read_exact(sock, len(HANDSHAKE_ACK) + 8)
        assert ack[:8] == HANDSHAKE_ACK
        command = read_exact(sock, COMMAND_SIZE)
        assert struct.unpack("<B7xQQ8x", command) == (8, 0x4000, 64)
        sock.sendall(struct.pack("<BB6xQQ", 0, flags, 0x4000, 64))

    thread, errors = peer_thread(peer, respond)
    transport = PluginTransport(LimitedRecvSocket(client), x86.ArchX86(),
                                expected_identity=IDENTITY,
                                required_capabilities=CAP_MEMORY_PERMISSIONS)
    transport.receive_handshake()
    assert transport.memory_permissions(0x4000, 64) == flags
    transport.close()
    finish_peer(thread, errors)


@pytest.mark.parametrize("status,flags,address,size,padding", [
    (0, 1, 0x4000, 64, bytes(6)),  # access without mapped
    (0, 16, 0x4000, 64, bytes(6)),  # unknown flag
    (0, 9, 0x4001, 64, bytes(6)),  # wrong identity
    (0, 9, 0x4000, 63, bytes(6)),
    (0, 9, 0x4000, 64, b"\1" + bytes(5)),
    (1, 9, 0x4000, 64, bytes(6)),  # unavailable has no flags
    (2, 0, 0x4000, 64, bytes(6)),
])
def test_malformed_permission_reply(status, flags, address, size, padding):
    client, peer = socket.socketpair()

    def respond(sock):
        read_exact(sock, COMMAND_SIZE)
        sock.sendall(struct.pack("<BB6sQQ", status, flags, padding, address, size))

    thread, errors = peer_thread(peer, respond)
    transport = PluginTransport(client, x86.ArchX86())
    transport._capabilities = CAP_MEMORY_PERMISSIONS
    with pytest.raises(PluginProtocolError):
        transport.memory_permissions(0x4000, 64)
    transport.close()
    finish_peer(thread, errors)


def test_permission_unavailable_is_not_unmapped():
    client, peer = socket.socketpair()

    def respond(sock):
        read_exact(sock, COMMAND_SIZE)
        sock.sendall(struct.pack("<BB6xQQ", 1, 0, 0x4000, 64))

    thread, errors = peer_thread(peer, respond)
    transport = PluginTransport(client, x86.ArchX86())
    transport._capabilities = CAP_MEMORY_PERMISSIONS
    with pytest.raises(MemoryAccessError):
        transport.memory_permissions(0x4000, 64)
    transport.close()
    finish_peer(thread, errors)


def test_permission_queries_require_capability_and_bounded_range():
    client, peer = socket.socketpair()
    try:
        transport = PluginTransport(client, x86.ArchX86())
        with pytest.raises(PluginProtocolError):
            transport.memory_permissions(0, 1)
        transport._capabilities = CAP_MEMORY_PERMISSIONS
        for address, size in [(0, 0), (0, 65537), (-1, 1), (2**64-1, 2), (True, 1)]:
            with pytest.raises(ValueError):
                transport.memory_permissions(address, size)
    finally:
        client.close()
        peer.close()
