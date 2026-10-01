import socket
import struct
import threading
from collections.abc import Buffer, Callable

import pytest

from focaccia.arch import aarch64, x86
from focaccia.qemu.transport import (
    ABORT_ACK,
    COMMAND_SIZE,
    EVENT_AARCH64_SVC_ENTRY,
    EVENT_AARCH64_SVC_SUCCESSOR,
    EVENT_STORE,
    EVENT_TRANSLATION_BLOCK,
    FINISH_ACK,
    HANDSHAKE_ACK,
    PLUGIN_API_VERSION,
    PLUGIN_MAGIC,
    PluginEOFError,
    PluginProtocolError,
    PluginLaunchIdentity,
    PluginTransport,
    SnapshotMemoryPlan,
    SnapshotPlan,
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


IDENTITY = PluginLaunchIdentity(*(f"{index:02x}" * 32 for index in range(1, 5)))
CAPABILITIES = 0x3F


def handshake(
    *,
    target: bytes = b"x86_64",
    endianness: int = 1,
    protocol_reserved: bytes = bytes(4),
    api_min: int = PLUGIN_API_VERSION,
    api_current: int = PLUGIN_API_VERSION,
    capabilities: int = CAPABILITIES,
    identity: PluginLaunchIdentity = IDENTITY,
) -> bytes:
    return struct.pack(
        "<8s4sI16sBBBB4sQ128s",
        PLUGIN_MAGIC,
        protocol_reserved,
        1234,
        target,
        endianness,
        64,
        api_min,
        api_current,
        bytes(4),
        capabilities,
        b"".join(identity.digests()),
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
    transport = PluginTransport(client, x86.ArchX86(), expected_identity=IDENTITY)

    received = transport.receive_handshake()

    assert received.pid == 1234
    assert received.target == "x86_64"
    assert received.endianness == "little"
    assert received.plugin_api_min == PLUGIN_API_VERSION
    assert received.plugin_api_current == PLUGIN_API_VERSION
    assert received.capabilities == CAPABILITIES
    assert received.identity == IDENTITY
    acknowledgement = read_exact(peer, len(HANDSHAKE_ACK) + 8)
    assert acknowledgement[:len(HANDSHAKE_ACK)] == HANDSHAKE_ACK
    assert struct.unpack("<Q", acknowledgement[len(HANDSHAKE_ACK):])[0] == 0x7
    transport.close()
    peer.close()


def test_protocol_handshake_rejects_nonzero_reserved_format_bytes():
    client, peer = socket.socketpair()
    peer.sendall(handshake(protocol_reserved=b"\0\0\0\1"))
    transport = PluginTransport(client, x86.ArchX86(), expected_identity=IDENTITY)
    with pytest.raises(PluginProtocolError, match="protocol-reserved"):
        transport.receive_handshake()
    transport.close()
    peer.close()


@pytest.mark.parametrize(
    ("expected_identity", "capabilities", "message"),
    [
        (PluginLaunchIdentity("ff" * 32, *(IDENTITY.__getattribute__(name) for name in ("argv_sha256", "env_sha256", "cpu_sha256"))), CAPABILITIES, "launch identity"),
        (IDENTITY, 1, "capabilities"),
    ],
)
def test_protocol_handshake_fails_closed_on_identity_or_capabilities(expected_identity, capabilities, message):
    client, peer = socket.socketpair()
    peer.sendall(handshake(capabilities=capabilities))
    transport = PluginTransport(client, x86.ArchX86(), expected_identity=expected_identity)
    with pytest.raises(PluginProtocolError, match=message):
        transport.receive_handshake()
    peer.settimeout(0.05)
    with pytest.raises(TimeoutError):
        peer.recv(1)
    transport.close()
    peer.close()


def event(kind, sequence, epoch, *, pc=0x1000, address=0, size=0, auxiliary=0, value=b""):
    return struct.pack(
        "<BB6xQQQQQQ16s24s", kind, 0, sequence, epoch, pc, address, size,
        auxiliary, value + bytes(16 - len(value)), bytes(24),
    )


def test_event_stream_retains_store_value_and_typed_svc_entry_successor():
    client, peer = socket.socketpair()
    peer.sendall(event(EVENT_STORE, 1, 7, address=0x4003, size=4, value=b"ABCD"))
    peer.sendall(event(EVENT_AARCH64_SVC_ENTRY, 2, 8, address=0x4003, auxiliary=96))
    peer.sendall(event(EVENT_AARCH64_SVC_SUCCESSOR, 3, 9, pc=0x1004, address=0x1000, auxiliary=123))
    transport = PluginTransport(client, aarch64.ArchAArch64("little"))
    store = transport.receive_event()
    entry = transport.receive_event()
    successor = transport.receive_event()
    assert (store.address, store.value, store.epoch) == (0x4003, b"ABCD", 7)
    assert (entry.kind, entry.auxiliary, entry.address) == (EVENT_AARCH64_SVC_ENTRY, 96, 0x4003)
    assert (successor.kind, successor.address, successor.auxiliary) == (EVENT_AARCH64_SVC_SUCCESSOR, 0x1000, 123)
    transport.close()
    peer.close()


def test_event_stream_accepts_contiguous_translation_block_descriptor():
    client, peer = socket.socketpair()
    peer.sendall(event(EVENT_TRANSLATION_BLOCK, 1, 2, pc=0x4000,
                       address=0x4008, size=3))
    transport = PluginTransport(client, aarch64.ArchAArch64("little"))
    block = transport.receive_event()
    assert (block.pc, block.address, block.size) == (0x4000, 0x4008, 3)
    transport.close()
    peer.close()


def test_boundary_snapshot_plan_is_installed_once_and_reused_by_occurrence():
    client, peer = socket.socketpair()

    def serve(sock):
        for occurrence, value in ((1, 7), (2, 9)):
            sock.sendall(event(EVENT_TRANSLATION_BLOCK, occurrence, occurrence,
                               pc=0x4000, address=0x4000, size=1))
            if occurrence == 1:
                command = read_exact(sock, COMMAND_SIZE)
                assert command[0] == 6
                assert struct.unpack_from("<QQII", command, 8) == (0x4000, 1, 1, 1)
                assert read_exact(sock, 16).split(b"\0", 1)[0] == b"rax"
                assert read_exact(sock, 8) == struct.pack("<HH4x", 4, 1)
                assert read_exact(sock, 1) == b"\0"
                sock.sendall(struct.pack("<B7xQQII", 0, 0x4000, 1, 1, 1))
            command = read_exact(sock, COMMAND_SIZE)
            assert command[0] == 7
            sock.sendall(struct.pack("<B1xHIQQQQ", 0, 1, 1, 0x4000, 1,
                                     occurrence, occurrence))
            sock.sendall(struct.pack("<B7x64s", 8, value.to_bytes(8, "little")))
            sock.sendall(struct.pack("<QI4x", 0x8000, 4) + b"sync")
            assert read_exact(sock, COMMAND_SIZE)[0] == 3

    thread, errors = peer_thread(peer, serve)
    transport = PluginTransport(client, x86.ArchX86())
    plan = SnapshotPlan(
        0x4000, 1, ("rax",), (SnapshotMemoryPlan(4, b"\0"),)
    )
    values = []
    for occurrence in (1, 2):
        transport.receive_event()
        if occurrence == 1:
            transport.install_snapshot_plan(plan)
        snapshot = transport.capture_snapshot(0x4000)
        assert snapshot.occurrence == occurrence
        values.append(snapshot.registers[0].value)
        assert snapshot.memory == ((0x8000, b"sync"),)
        transport.advance()
    assert values == [7, 9]
    transport.close()
    finish_peer(thread, errors)


def test_event_stream_rejects_noncontiguous_translation_block_descriptor():
    client, peer = socket.socketpair()
    peer.sendall(event(EVENT_TRANSLATION_BLOCK, 1, 2, pc=0x4000,
                       address=0x400c, size=3))
    transport = PluginTransport(client, aarch64.ArchAArch64("little"))
    with pytest.raises(PluginProtocolError, match="translation-block"):
        transport.receive_event()
    transport.close()
    peer.close()


def test_event_stream_rejects_reordered_sequence_or_epoch():
    client, peer = socket.socketpair()
    peer.sendall(event(EVENT_STORE, 1, 2, address=1, size=1, value=b"x"))
    peer.sendall(event(EVENT_STORE, 3, 2, address=2, size=1, value=b"y"))
    transport = PluginTransport(client, x86.ArchX86())
    transport.receive_event()
    with pytest.raises(PluginProtocolError, match="strictly ordered"):
        transport.receive_event()
    transport.close()
    peer.close()


def test_protocol_handshake_rejects_wrong_guest_before_acknowledgement():
    client, peer = socket.socketpair()
    peer.sendall(handshake(target=b"aarch64"))
    transport = PluginTransport(client, x86.ArchX86(), expected_identity=IDENTITY)

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


def test_receive_event_has_bounded_no_progress_timeout():
    client, peer = socket.socketpair()
    transport = PluginTransport(client, x86.ArchX86())
    with pytest.raises(TimeoutError, match="no ordered event"):
        transport.receive_event(0.01)
    transport.close()
    peer.close()


def test_transport_context_manager_closes_owned_socket():
    client, peer = socket.socketpair()
    with PluginTransport(client, x86.ArchX86()) as transport:
        assert not transport.closed
    assert transport.closed
    assert client.fileno() == -1
    peer.close()
