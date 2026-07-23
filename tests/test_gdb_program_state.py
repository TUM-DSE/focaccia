import importlib
import sys
from types import ModuleType, SimpleNamespace
from typing import Any, cast

import pytest

from focaccia.arch import x86
from focaccia.deterministic import (
    CursorState,
    DeterministicCursor,
    DeterministicLog,
    Event,
    EventSynchronizationError,
    KnownMemoryRange,
    MemoryWrite,
    SyscallEvent,
    UnknownMemoryRange,
    UnknownMemoryRangeError,
)
from focaccia.qemu.concurrency import UnsupportedConcurrencyError
from focaccia.qemu.replay import X86ReplayEngine
from focaccia.qemu.syscall import UnsupportedReplayEffect
from focaccia.snapshot import (
    MemoryAccessError,
    ProgramState,
    ReadableProgramState,
    RegisterAccessError,
)


class FakeValue:
    def __init__(self, value: int, size: int):
        self.value = value
        self.type = SimpleNamespace(sizeof=size)

    def cast(self, _type):
        return self

    def __int__(self) -> int:
        return self.value


class FakeFrame:
    def __init__(self, registers: dict[str, FakeValue]):
        self.registers = registers
        self.reads: list[str] = []

    def read_register(self, name: str) -> FakeValue:
        self.reads.append(name)
        try:
            return self.registers[name]
        except KeyError as error:
            raise ValueError(f"missing {name}") from error


class FakeMemory:
    def __init__(self, data: bytes):
        self.data = data

    def tobytes(self) -> bytes:
        return self.data


class FakeInferior:
    def __init__(self, memory: dict[int, int]):
        self.memory = memory
        self.reads: list[tuple[int, int]] = []

    def read_memory(self, address: int, size: int) -> FakeMemory:
        self.reads.append((address, size))
        try:
            return FakeMemory(
                bytes(self.memory[address + offset] for offset in range(size))
            )
        except KeyError as error:
            raise FakeGDBMemoryError("unavailable") from error


class FakeGDBError(RuntimeError):
    pass


class FakeGDBMemoryError(FakeGDBError):
    pass


def load_target_module(monkeypatch):
    fake_gdb = ModuleType("gdb")
    dynamic_gdb = cast(Any, fake_gdb)
    for name in ("Breakpoint", "Frame", "Inferior", "Value"):
        setattr(fake_gdb, name, object)
    dynamic_gdb.error = FakeGDBError
    dynamic_gdb.MemoryError = FakeGDBMemoryError
    dynamic_gdb.lookup_type = lambda name: name
    monkeypatch.setitem(sys.modules, "gdb", fake_gdb)
    sys.modules.pop("focaccia.qemu.target", None)
    return importlib.import_module("focaccia.qemu.target")


def test_gdb_state_caches_base_registers_and_flag_aliases(monkeypatch):
    target = load_target_module(monkeypatch)
    frame = FakeFrame(
        {
            "rax": FakeValue(0x1234, 8),
            "eflags": FakeValue((1 << 0) | (1 << 6) | (3 << 12), 4),
        }
    )
    state = target.GDBProgramState(FakeInferior({}), frame, x86.ArchX86())

    assert state.read_register("AH") == 0x12
    assert state.read_register("AL") == 0x34
    assert state.read_register("CF") == 1
    assert state.read_register("ZF") == 1
    assert state.read_register("IOPL") == 3
    assert frame.reads == ["rax", "eflags"]

    sys.modules.pop("focaccia.qemu.target", None)


def test_gdb_missing_register_remains_unknown(monkeypatch):
    target = load_target_module(monkeypatch)
    state = target.GDBProgramState(FakeInferior({}), FakeFrame({}), x86.ArchX86())

    with pytest.raises(RegisterAccessError):
        state.read_register("RAX")
    with pytest.raises(RegisterAccessError):
        ProgramState.read_register(state, "RAX")

    sys.modules.pop("focaccia.qemu.target", None)


def test_gdb_unsupported_80_bit_scalar_is_not_truncated(monkeypatch):
    target = load_target_module(monkeypatch)
    frame = FakeFrame({"st0": FakeValue((1 << 79) | 7, 10)})
    state = target.GDBProgramState(FakeInferior({}), frame, x86.ArchX86())

    with pytest.raises(RegisterAccessError, match="Unsupported scalar register width"):
        state.read_register("ST0")
    with pytest.raises(RegisterAccessError):
        ProgramState.read_register(state, "ST0")

    sys.modules.pop("focaccia.qemu.target", None)


def test_thread_creating_syscall_is_rejected_before_gdb_step(monkeypatch):
    target = load_target_module(monkeypatch)

    class FakeIterator:
        arch = x86.ArchX86()

        def __init__(self):
            self.current_state_calls = 0
            self.step_calls = 0
            self.replay = X86ReplayEngine(self.arch)

        def _require_replay_engine(self):
            return self.replay

        def current_state(self):
            self.current_state_calls += 1
            return object()

        def _step(self):
            self.step_calls += 1
            raise AssertionError("A thread-creating syscall must not execute.")

    iterator = FakeIterator()
    arch = x86.ArchX86()
    event = SyscallEvent(
        0x1000,
        1,
        arch,
        {"rip": 0x1000, "rax": 56},
        (),
        arch,
        56,
        "entering",
        False,
        event_count=1,
    )
    post_event = SyscallEvent(
        0x1002,
        1,
        arch,
        {"rip": 0x1002, "rax": 0},
        (),
        arch,
        56,
        "exiting",
        False,
        event_count=2,
    )

    with pytest.raises(UnsupportedConcurrencyError, match="clone"):
        target.GDBServerStateIterator._handle_syscall(
            cast(Any, iterator),
            cast(Any, event),
            cast(Any, post_event),
        )

    assert iterator.current_state_calls == 0
    assert iterator.step_calls == 0
    sys.modules.pop("focaccia.qemu.target", None)


def test_gdb_state_uses_sparse_exact_memory_cache(monkeypatch):
    target = load_target_module(monkeypatch)
    address = 0x10FF
    data = b"ABCD"
    inferior = FakeInferior(
        {address + offset: byte for offset, byte in enumerate(data)}
    )
    state = target.GDBProgramState(inferior, FakeFrame({}), x86.ArchX86())

    assert state.read_memory(address, 4) == data
    assert state.read_memory(address + 1, 2) == b"BC"
    assert inferior.reads == [(address, 4)]
    with pytest.raises(MemoryAccessError):
        state.read_memory(0x2000, 1)

    sys.modules.pop("focaccia.qemu.target", None)


def test_qemu_iterator_accepts_explicit_empty_event_log(monkeypatch):
    target = load_target_module(monkeypatch)

    class State:
        def read_pc(self) -> int:
            return 0x1000

    monkeypatch.setattr(target.GDBServerConnector, "__init__", lambda _self, _remote: None)
    monkeypatch.setattr(
        target.GDBServerStateIterator,
        "current_state",
        lambda _self: State(),
    )

    iterator = target.GDBServerStateIterator("unused", DeterministicLog(None))

    assert iterator._replay_tid is None
    assert iterator._events.state is CursorState.EXHAUSTED
    assert iterator._events.events == ()
    sys.modules.pop("focaccia.qemu.target", None)


def test_gdb_signal_replay_rejects_unwritable_complete_fp_state(monkeypatch):
    target = load_target_module(monkeypatch)

    with pytest.raises(UnsupportedReplayEffect, match="x87 tag state"):
        target.GDBServerConnector.reset_signal_handler_fp_state(cast(Any, object()))

    sys.modules.pop("focaccia.qemu.target", None)


def test_qemu_replay_rejects_events_without_synchronization_pc(monkeypatch):
    target = load_target_module(monkeypatch)
    event = Event(None, 1, x86.ArchX86(), {}, (), "syscallbufReset", 1)

    with pytest.raises(EventSynchronizationError, match="has no program counter"):
        target.require_event_pc(event)
    sys.modules.pop("focaccia.qemu.target", None)


def test_qemu_event_loop_fails_on_pending_event_without_pc(monkeypatch):
    target = load_target_module(monkeypatch)
    arch = x86.ArchX86()
    first = Event(0x1000, 1, arch, {"rip": 0x1000}, (), "sched", 1)
    pending = Event(None, 1, arch, {}, (), "syscallbufReset", 2)
    cursor = DeterministicCursor(
        (first, pending),
        lambda event, pc: event.pc == pc,
    )
    assert cursor.match(0x1000) is first

    class FakeIterator:
        _events = cursor

        def current_state(self) -> object:
            raise AssertionError("The target must not advance past an unknown-PC event.")

    with pytest.raises(EventSynchronizationError, match="syscallbufReset"):
        target.GDBServerStateIterator._handle_event(cast(Any, FakeIterator()))
    sys.modules.pop("focaccia.qemu.target", None)


def test_qemu_replay_rejects_unknown_holes_before_changing_target_state(monkeypatch):
    target = load_target_module(monkeypatch)
    arch = x86.ArchX86()
    write = MemoryWrite(
        101,
        0x2000,
        4,
        (KnownMemoryRange(0, b"ab"),),
        (UnknownMemoryRange(2, 2),),
    )
    pre = SyscallEvent(
        0x1000,
        101,
        arch,
        {"rip": 0x1000, "rax": 0},
        (),
        arch,
        0,
        "entering",
        False,
        event_count=1,
    )
    post = SyscallEvent(
        0x1002,
        101,
        arch,
        {"rip": 0x1002, "rax": 4},
        (write,),
        arch,
        0,
        "exiting",
        False,
        event_count=2,
    )

    class FakeIterator:
        changed_target = False
        arch = x86.ArchX86()

        def __init__(self):
            self.replay = X86ReplayEngine(self.arch)
            self.state = ProgramState(self.arch)
            self.state.write_register("rip", 0x1000)
            self.state.write_register("rax", 0)

        def _require_replay_engine(self):
            return self.replay

        def current_state(self) -> ReadableProgramState:
            return self.state

        def skip(self, _new_pc: int) -> None:
            self.changed_target = True

    fake = FakeIterator()
    with pytest.raises(UnknownMemoryRangeError, match="unknown ranges"):
        target.GDBServerStateIterator._handle_syscall(cast(Any, fake), pre, post)
    assert not fake.changed_target
    sys.modules.pop("focaccia.qemu.target", None)
