"""Bounded passive store evidence is tied to consecutive paused occurrences."""
import socket
import struct

import pytest

from focaccia.arch import x86
from focaccia.qemu.transport import (
    CAP_STORE_FOOTPRINT, COMMAND_SIZE, EVENT_TRANSLATION_BLOCK,
    PluginProtocolError, PluginTransport, StoreSpan, read_exact,
)
from test_qemu_transport import event, peer_thread, finish_peer


def reply(spans=(), *, magic=b"FOCSTOR\0", status=0, count=None,
          start=(0, 0), end=(1, 1)):
    return struct.pack("<8sIIQQQQ", magic, status,
                       len(spans) if count is None else count, *start, *end) + b"".join(
        struct.pack("<QQ", *span) for span in spans)


def transport_pair():
    client, peer = socket.socketpair()
    transport = PluginTransport(client, x86.ArchX86())
    transport._capabilities = CAP_STORE_FOOTPRINT
    return transport, peer


def test_ordered_footprint_preserves_overlaps_and_repeated_tb_occurrences():
    transport, peer = transport_pair()

    def respond(sock):
        for sequence, spans in [(1, ()), (2, ((0x4000, 8), (0x4000, 1))), (3, ())]:
            sock.sendall(event(EVENT_TRANSLATION_BLOCK, sequence, sequence,
                               address=0x1000, size=1))
            assert read_exact(sock, COMMAND_SIZE) == struct.pack("<B7xQQ8x", 9, sequence, sequence)
            sock.sendall(reply(spans, start=(sequence-1, sequence-1), end=(sequence, sequence)))
            assert read_exact(sock, COMMAND_SIZE) == bytes([3]) + bytes(31)

    thread, errors = peer_thread(peer, respond)
    for sequence in range(1, 4):
        transport.receive_event()
        with pytest.raises(PluginProtocolError, match="draining"):
            transport.advance()
        footprint = transport.drain_store_footprint()
        assert (footprint.from_sequence, footprint.to_sequence) == (sequence-1, sequence)
        assert footprint.spans == ((StoreSpan(0x4000, 8), StoreSpan(0x4000, 1)) if sequence == 2 else ())
        with pytest.raises(PluginProtocolError, match="unique"):
            transport.drain_store_footprint()
        transport.advance()
        with pytest.raises(PluginProtocolError, match="unique"):
            transport.drain_store_footprint()
    transport.close()
    finish_peer(thread, errors)


@pytest.mark.parametrize("raw", [
    reply(magic=b"bad"), reply(status=1), reply(count=65537),
    reply(start=(1, 0)), reply(start=(0, 1)), reply(end=(2, 1)), reply(end=(1, 2)),
    reply(((0x4000, 0),)), reply(((0x4000, 3),)), reply(((0x4000, 32),)),
    reply(((2**64-1, 2),)),
])
def test_malformed_footprint_fails_closed(raw):
    transport, peer = transport_pair()

    def respond(sock):
        sock.sendall(event(EVENT_TRANSLATION_BLOCK, 1, 1, address=0x1000, size=1))
        read_exact(sock, COMMAND_SIZE)
        sock.sendall(raw)

    thread, errors = peer_thread(peer, respond)
    transport.receive_event()
    with pytest.raises(PluginProtocolError):
        transport.drain_store_footprint()
    with pytest.raises(PluginProtocolError, match="draining"):
        transport.advance()
    transport.close()
    finish_peer(thread, errors)


def test_footprint_requires_capability_and_paused_event():
    transport, peer = transport_pair()
    try:
        with pytest.raises(PluginProtocolError, match="unique"):
            transport.drain_store_footprint()
        transport._capabilities = 0
        with pytest.raises(PluginProtocolError, match="capability"):
            transport.drain_store_footprint()
    finally:
        transport.close()
        peer.close()
