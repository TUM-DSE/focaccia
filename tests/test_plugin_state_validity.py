import struct

import pytest

from focaccia.arch import aarch64
from focaccia.qemu import validation_server
from focaccia.qemu.validation_server import PluginProgramState
from focaccia.snapshot import ProgramState, RegisterAccessError


class FakeConnection:
    def __init__(self, responses: list[bytes]):
        self.responses = responses
        self.sent: list[bytes] = []

    def send(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, size: int) -> bytes:
        response = self.responses.pop(0)
        assert len(response) <= size
        return response


def register_response(value: int, *, size: int = 8) -> bytes:
    data = value.to_bytes(size, "little") + bytes(64 - size)
    return struct.pack("<108sQ64s", b"x0", size, data)


def test_plugin_alias_read_does_not_initialize_unobserved_bits(monkeypatch):
    value = 0x1234567889ABCDEF
    connection = FakeConnection([register_response(value)])
    monkeypatch.setattr(validation_server, "CONN", connection, raising=False)
    state = PluginProgramState(aarch64.ArchAArch64("little"))

    assert state.read_register("W0") == 0x89ABCDEF
    assert ProgramState.read_register(state, "W0") == 0x89ABCDEF
    with pytest.raises(RegisterAccessError):
        ProgramState.read_register(state, "X0")
    assert len(connection.sent) == 1


def test_plugin_fetches_range_when_only_first_byte_is_cached(monkeypatch):
    address = 0x1000
    data = b"ABC"
    connection = FakeConnection(
        [
            struct.pack("<QQ", address, len(data)),
            data,
        ]
    )
    monkeypatch.setattr(validation_server, "CONN", connection, raising=False)
    state = PluginProgramState(aarch64.ArchAArch64("little"))
    state.write_memory(address, data[:1])

    assert state.read_memory(address, len(data)) == data
    assert ProgramState.read_memory(state, address, len(data)) == data
    assert len(connection.sent) == 1
