from typing import Any, cast

import pytest

from focaccia.arch import aarch64, x86
from focaccia.qemu import validation_server
from focaccia.qemu.state import RegisterObservation
from focaccia.qemu.validation_server import PluginProgramState, PluginStateIterator
from focaccia.snapshot import MemoryAccessError, ProgramState, RegisterAccessError


class FakeTransport:
    def __init__(self):
        self.registers: dict[str, RegisterObservation] = {}
        self.memory: dict[int, int] = {}
        self.register_reads: list[str] = []
        self.memory_reads: list[tuple[int, int]] = []
        self.steps = 0
        self.finished = False
        self.aborted = False
        self.closed = False

    def read_register(self, name: str) -> RegisterObservation:
        self.register_reads.append(name)
        try:
            return self.registers[name]
        except KeyError as error:
            raise RegisterAccessError(name, f"Missing fixture register {name}.") from error

    def read_memory(self, address: int, size: int) -> bytes:
        self.memory_reads.append((address, size))
        try:
            return bytes(self.memory[address + offset] for offset in range(size))
        except KeyError as error:
            raise MemoryAccessError(address, size, "Missing fixture memory.") from error

    def step(self) -> None:
        self.steps += 1

    def finish(self) -> None:
        self.finished = True
        self.closed = True

    def abort(self) -> None:
        self.aborted = True
        self.closed = True

    def close(self) -> None:
        self.closed = True


def plugin_state(arch, transport: FakeTransport) -> PluginProgramState:
    return PluginProgramState(arch, cast(Any, transport))


def test_plugin_alias_read_caches_the_canonical_base_register():
    value = 0x1234567889ABCDEF
    transport = FakeTransport()
    transport.registers["x0"] = RegisterObservation("x0", value, 64)
    state = plugin_state(aarch64.ArchAArch64("little"), transport)

    assert state.read_register("W0") == 0x89ABCDEF
    assert state.read_register("X0") == value
    assert ProgramState.read_register(state, "X0") == value
    assert transport.register_reads == ["x0"]


def test_plugin_high_alias_uses_mask_then_shift_and_fetches_base_once():
    transport = FakeTransport()
    transport.registers["rax"] = RegisterObservation("rax", 0x1234, 64)
    state = plugin_state(x86.ArchX86(), transport)

    assert state.read_register("AH") == 0x12
    assert state.read_register("AL") == 0x34
    assert state.read_register("RAX") == 0x1234
    assert transport.register_reads == ["rax"]


@pytest.mark.parametrize(
    "order",
    [
        ("CF", "ZF", "IOPL"),
        ("IOPL", "ZF", "CF"),
    ],
)
def test_plugin_flag_reads_are_order_independent(order: tuple[str, ...]):
    eflags = (1 << 0) | (1 << 6) | (3 << 12)
    transport = FakeTransport()
    transport.registers["eflags"] = RegisterObservation("eflags", eflags, 32)
    state = plugin_state(x86.ArchX86(), transport)

    observed = {name: state.read_register(name) for name in order}

    assert observed == {"CF": 1, "ZF": 1, "IOPL": 3}
    assert state.read_register("RFLAGS") == eflags
    assert transport.register_reads == ["eflags"]


def test_plugin_incomplete_flags_observation_does_not_determine_rflags():
    transport = FakeTransport()
    transport.registers["eflags"] = RegisterObservation("flags", 0x243, 16)
    state = plugin_state(x86.ArchX86(), transport)

    assert state.read_register("FLAGS") == 0x243
    with pytest.raises(RegisterAccessError):
        state.read_register("RFLAGS")
    assert transport.register_reads == ["eflags"]


def test_plugin_aarch64_status_fields_share_one_cpsr_observation():
    cpsr = (1 << 31) | (1 << 30) | (2 << 2)
    transport = FakeTransport()
    transport.registers["cpsr"] = RegisterObservation("cpsr", cpsr, 32)
    state = plugin_state(aarch64.ArchAArch64("little"), transport)

    assert state.read_register("N") == 1
    assert state.read_register("Z") == 1
    assert state.read_register("M") == 8
    assert transport.register_reads == ["cpsr"]


def test_plugin_reads_physical_mmx_value_from_logical_x87_stack():
    value = 0xFFEEDDCCBBAA9988
    transport = FakeTransport()
    # TOP=6 means physical MM1 is exposed as logical ST3.
    transport.registers["fstat"] = RegisterObservation("fstat", 6 << 11, 32)
    transport.registers["st3"] = RegisterObservation(
        "st3",
        value | (0xFFFF << 64),
        80,
    )
    state = plugin_state(x86.ArchX86(), transport)

    assert state.read_register("MM1") == value
    assert transport.register_reads == ["fstat", "st3"]
    with pytest.raises(RegisterAccessError):
        ProgramState.read_register(state, "XMM1")


def test_plugin_fetches_full_range_when_only_first_byte_is_cached():
    address = 0x1000
    data = b"ABC"
    transport = FakeTransport()
    transport.memory.update(
        {address + offset: value for offset, value in enumerate(data)}
    )
    state = plugin_state(aarch64.ArchAArch64("little"), transport)
    state.write_memory(address, data[:1])

    assert state.read_memory(address, len(data)) == data
    assert ProgramState.read_memory(state, address, len(data)) == data
    assert transport.memory_reads == [(address, len(data))]


def test_plugin_cross_page_memory_cache_preserves_byte_validity():
    address = 0x10FF
    data = b"WXYZ"
    transport = FakeTransport()
    transport.memory.update(
        {address + offset: value for offset, value in enumerate(data)}
    )
    state = plugin_state(x86.ArchX86(), transport)

    assert state.read_memory(address, len(data)) == data
    assert state.read_memory(address + 1, 2) == b"XY"
    assert transport.memory_reads == [(address, len(data))]


def test_missing_plugin_values_remain_unknown():
    transport = FakeTransport()
    state = plugin_state(x86.ArchX86(), transport)

    with pytest.raises(RegisterAccessError):
        state.read_register("RAX")
    with pytest.raises(RegisterAccessError):
        ProgramState.read_register(state, "RAX")
    with pytest.raises(MemoryAccessError):
        state.read_memory(0x4000, 4)
    with pytest.raises(MemoryAccessError):
        ProgramState.read_memory(state, 0x4000, 4)


def test_plugin_backend_has_no_module_global_connection_state():
    assert not hasattr(validation_server, "CONN")
    assert not hasattr(validation_server, "SOCK")


def test_plugin_iterator_finish_uses_explicit_terminal_command():
    transport = FakeTransport()

    with PluginStateIterator.from_transport(
        cast(Any, transport),
        x86.ArchX86(),
    ) as iterator:
        iterator.finish()

    assert transport.finished
    assert transport.closed


def test_plugin_iterator_abort_uses_explicit_failure_command():
    transport = FakeTransport()

    with PluginStateIterator.from_transport(
        cast(Any, transport),
        x86.ArchX86(),
    ) as iterator:
        iterator.abort()

    assert transport.aborted
    assert transport.closed


def test_plugin_iterator_context_manager_closes_injected_transport():
    transport = FakeTransport()

    with PluginStateIterator.from_transport(
        cast(Any, transport),
        x86.ArchX86(),
    ) as iterator:
        assert next(iterator).arch == x86.ArchX86()

    assert transport.closed


def test_plugin_states_own_independent_transports():
    first_transport = FakeTransport()
    second_transport = FakeTransport()
    first_transport.registers["rax"] = RegisterObservation("rax", 1, 64)
    second_transport.registers["rax"] = RegisterObservation("rax", 2, 64)

    first = plugin_state(x86.ArchX86(), first_transport)
    second = plugin_state(x86.ArchX86(), second_transport)

    assert first.read_register("RAX") == 1
    assert second.read_register("RAX") == 2
    assert first_transport.register_reads == ["rax"]
    assert second_transport.register_reads == ["rax"]


def test_plugin_step_flushes_all_cached_observations():
    transport = FakeTransport()
    transport.registers["rax"] = RegisterObservation("rax", 1, 64)
    transport.memory[0x5000] = 2
    state = plugin_state(x86.ArchX86(), transport)
    assert state.read_register("RAX") == 1
    assert state.read_memory(0x5000, 1) == b"\x02"

    state.step()
    transport.registers["rax"] = RegisterObservation("rax", 3, 64)
    transport.memory[0x5000] = 4

    assert state.read_register("RAX") == 3
    assert state.read_memory(0x5000, 1) == b"\x04"
    assert transport.steps == 1
