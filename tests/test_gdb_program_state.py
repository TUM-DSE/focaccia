import importlib
import struct
import sys
from types import ModuleType, SimpleNamespace
from typing import Any, cast

import pytest

from focaccia.arch import aarch64, x86
from focaccia.deterministic import (
    CursorState,
    DeterministicCursor,
    DeterministicLog,
    Event,
    EventSynchronizationError,
    ExtraRegisterState,
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


class FakeVectorComponents:
    def __init__(self, values: list[int]):
        self.values = values

    def __getitem__(self, index: int):
        return FakeValue(self.values[index], 8)


class FakeVectorValue:
    def __init__(self, value: int, size: int):
        self.value = value
        self.type = SimpleNamespace(sizeof=size // 8)

    def __getitem__(self, name: str):
        if name != f"v{self.type.sizeof // 8}_int64":
            raise KeyError(name)
        return FakeVectorComponents(
            [
                self.value >> offset & ((1 << 64) - 1)
                for offset in range(0, self.type.sizeof * 8, 64)
            ]
        )


class FakeRawValue:
    def __init__(self, data: bytes):
        self.bytes = data
        self.type = SimpleNamespace(sizeof=len(data))


class FakeValue:
    def __init__(self, value: int, size: int):
        self.value = value
        self.type = SimpleNamespace(sizeof=size)

    def cast(self, _type):
        return self

    def __int__(self) -> int:
        return self.value


class FakeFrame:
    def __init__(self, registers: dict[str, FakeRawValue | FakeValue | FakeVectorValue]):
        self.registers = registers
        self.reads: list[str] = []

    def read_register(self, name: str) -> FakeRawValue | FakeValue | FakeVectorValue:
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
            return FakeMemory(bytes(self.memory[address + offset] for offset in range(size)))
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
    assert state.read_register("RFLAGS") == (1 << 0) | (1 << 6) | (3 << 12)
    assert frame.reads == ["rax", "eflags"]

    sys.modules.pop("focaccia.qemu.target", None)


def test_gdb_reads_narrow_vector_alias_without_requiring_zmm(monkeypatch):
    target = load_target_module(monkeypatch)
    value = 0x112233445566778899AABBCCDDEEFF00
    frame = FakeFrame({"xmm2": FakeVectorValue(value, 128)})
    state = target.GDBProgramState(FakeInferior({}), frame, x86.ArchX86())

    assert state.read_register("XMM2") == value
    assert frame.reads == ["xmm2"]
    with pytest.raises(RegisterAccessError):
        ProgramState.read_register(state, "YMM2")
    with pytest.raises(RegisterAccessError):
        ProgramState.read_register(state, "ZMM2")

    sys.modules.pop("focaccia.qemu.target", None)


def test_gdb_reads_physical_mmx_value_from_logical_x87_stack(monkeypatch):
    target = load_target_module(monkeypatch)
    value = 0xFFEEDDCCBBAA9988
    # TOP=3 means physical MM5 is exposed as logical ST2.
    frame = FakeFrame(
        {
            "fstat": FakeValue(3 << 11, 4),
            "st2": FakeRawValue(value.to_bytes(8, "little") + b"\xff\xff"),
        }
    )
    state = target.GDBProgramState(FakeInferior({}), frame, x86.ArchX86())

    assert state.read_register("MM5") == value
    assert frame.reads == ["fstat", "st2"]
    with pytest.raises(RegisterAccessError):
        ProgramState.read_register(state, "XMM5")

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
    inferior = FakeInferior({address + offset: byte for offset, byte in enumerate(data)})
    state = target.GDBProgramState(inferior, FakeFrame({}), x86.ArchX86())

    assert state.read_memory(address, 4) == data
    assert state.read_memory(address + 1, 2) == b"BC"
    assert inferior.reads == [(address, 4)]
    with pytest.raises(MemoryAccessError):
        state.read_memory(0x2000, 1)

    sys.modules.pop("focaccia.qemu.target", None)


def test_gdb_step_stops_at_first_guest_signal(monkeypatch):
    target = load_target_module(monkeypatch)
    fake_gdb = cast(Any, sys.modules["gdb"])

    class FakeSignalEvent:
        stop_signal = "SIGSEGV"

    fake_gdb.SignalEvent = FakeSignalEvent
    fake_gdb.selected_frame = lambda: FakeFrame({"pc": FakeValue(0x401014, 8)})
    connector = object.__new__(target.GDBServerConnector)
    connector._terminal_reason = None
    connector.is_exited = lambda: False
    commands: list[str] = []

    def execute(command: str, **_kwargs: object) -> None:
        commands.append(command)
        connector._record_stop_event(FakeSignalEvent())

    fake_gdb.execute = execute

    with pytest.raises(StopIteration):
        connector._step()

    assert commands == ["si"]
    assert connector.terminal_reason() == target.TerminalReason(
        kind="signal",
        signal="SIGSEGV",
        pc=0x401014,
    )
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


def test_initial_exec_discovery_preserves_repeated_event_identity(monkeypatch):
    target = load_target_module(monkeypatch)
    arch = x86.ArchX86()
    prefix = Event(0x9000, 7, arch, {"rip": 0x9000}, (), "sched", 1)
    pre = SyscallEvent(
        0xDEAD,
        7,
        arch,
        {"rip": 0xDEAD, "rax": 59},
        (),
        arch,
        59,
        "entering",
        False,
        event_count=13,
    )
    post = SyscallEvent(
        0x401000,
        7,
        arch,
        {"rip": 0x401000, "rax": 0},
        (),
        arch,
        59,
        "exiting",
        False,
        event_count=14,
    )
    later_same_pc = Event(
        0x401000,
        7,
        arch,
        {"rip": 0x401000},
        (),
        "sched",
        20,
    )

    match = target._matching_initial_x86_exec((prefix, pre, post, later_same_pc), 0x401000)

    assert match == (1, pre, post)
    sys.modules.pop("focaccia.qemu.target", None)


def test_initial_exec_discovery_rejects_ambiguous_matching_pairs(monkeypatch):
    target = load_target_module(monkeypatch)
    arch = x86.ArchX86()

    def pair(count: int) -> tuple[SyscallEvent, SyscallEvent]:
        pre = SyscallEvent(
            0xDEAD,
            7,
            arch,
            {"rip": 0xDEAD, "rax": 59},
            (),
            arch,
            59,
            "entering",
            False,
            event_count=count,
        )
        post = SyscallEvent(
            0x401000,
            7,
            arch,
            {"rip": 0x401000, "rax": 0},
            (),
            arch,
            59,
            "exiting",
            False,
            event_count=count + 1,
        )
        return pre, post

    with pytest.raises(EventSynchronizationError, match="multiple execve"):
        target._matching_initial_x86_exec((*pair(1), *pair(3)), 0x401000)
    sys.modules.pop("focaccia.qemu.target", None)


def test_qemu_iterator_can_start_before_first_rr_event(monkeypatch):
    target = load_target_module(monkeypatch)
    arch = x86.ArchX86()
    event = Event(0x2000, 7, arch, {"rip": 0x2000}, (), "sched", 1)

    class FakeLog:
        def events(self) -> tuple[Event, ...]:
            return (event,)

    class State:
        def read_pc(self) -> int:
            return 0x1000

    def initialize(connector, _remote: str) -> None:
        connector.arch = arch

    monkeypatch.setattr(target.GDBServerConnector, "__init__", initialize)
    monkeypatch.setattr(
        target.GDBServerStateIterator,
        "current_state",
        lambda _self: State(),
    )

    iterator = target.GDBServerStateIterator("unused", cast(Any, FakeLog()))

    assert iterator._events.state is CursorState.UNSYNCHRONIZED
    assert iterator._replay_tid is None
    assert iterator._next_synchronization_event() is event
    sys.modules.pop("focaccia.qemu.target", None)


def test_qemu_iterator_rejects_a_log_without_any_synchronization_pc(monkeypatch):
    target = load_target_module(monkeypatch)
    arch = x86.ArchX86()
    event = Event(None, 7, arch, {}, (), "sched", 1)

    class FakeLog:
        def events(self) -> tuple[Event, ...]:
            return (event,)

    class State:
        def read_pc(self) -> int:
            return 0x1000

    def initialize(connector, _remote: str) -> None:
        connector.arch = arch

    monkeypatch.setattr(target.GDBServerConnector, "__init__", initialize)
    monkeypatch.setattr(
        target.GDBServerStateIterator,
        "current_state",
        lambda _self: State(),
    )

    with pytest.raises(EventSynchronizationError, match="no event with a program counter"):
        target.GDBServerStateIterator("unused", cast(Any, FakeLog()))
    sys.modules.pop("focaccia.qemu.target", None)


def test_qemu_event_loop_synchronizes_when_first_rr_event_is_reached(monkeypatch):
    target = load_target_module(monkeypatch)
    arch = x86.ArchX86()
    event = Event(0x2000, 7, arch, {"rip": 0x2000}, (), "sched", 1)
    state = ProgramState(arch)
    state.write_register("rip", 0x2000)

    guest_arch = arch

    class FakeIterator:
        _events = DeterministicCursor((event,), target.match_event)
        _replay_tid = None
        replay = X86ReplayEngine(guest_arch)
        arch = guest_arch

        def current_state(self) -> ReadableProgramState:
            return state

        def _require_replay_engine(self) -> X86ReplayEngine:
            return self.replay

    iterator = FakeIterator()

    assert target.GDBServerStateIterator._handle_event(cast(Any, iterator)) is None
    assert iterator._replay_tid == 7
    assert iterator._events.state is CursorState.EXHAUSTED
    sys.modules.pop("focaccia.qemu.target", None)


def test_run_until_steps_safely_until_the_first_rr_synchronization(monkeypatch):
    target = load_target_module(monkeypatch)
    arch = x86.ArchX86()
    event = Event(0x3000, 7, arch, {"rip": 0x3000}, (), "sched", 1)
    initial = ProgramState(arch)
    initial.write_register("rip", 0x2000)
    destination = ProgramState(arch)
    destination.write_register("rip", 0x3000)
    iterator = object.__new__(target.GDBServerStateIterator)
    iterator._events = DeterministicCursor((event,), target.match_event)
    iterator._replay_tid = None
    iterator._replay = X86ReplayEngine(arch)
    iterator._first_next = True
    iterator.arch = arch
    iterator.current_state = lambda: initial
    iterator.is_exited = lambda: False
    steps: list[int] = []

    def step() -> ReadableProgramState:
        steps.append(1)
        return destination

    iterator._step = step
    iterator._run_until_any = lambda _addresses: (_ for _ in ()).throw(
        AssertionError("Unsynchronized replay must not continue past event PCs.")
    )

    assert iterator.run_until(0x3000) is destination
    assert iterator._events.state is CursorState.SYNCHRONIZED
    assert iterator._replay_tid == 7
    assert steps == [1]
    sys.modules.pop("focaccia.qemu.target", None)


def test_rr_post_event_is_not_an_initial_synchronization_candidate(monkeypatch):
    target = load_target_module(monkeypatch)
    arch = x86.ArchX86()
    state = ProgramState(arch)
    state.write_register("rip", 0x2000)
    post_event = SyscallEvent(
        0x2000,
        7,
        arch,
        {"rip": 0x2000, "rax": 0},
        (),
        arch,
        0,
        "exiting",
        False,
        event_count=1,
    )

    assert not target.match_event(post_event, state)
    sys.modules.pop("focaccia.qemu.target", None)


def test_run_until_replays_an_event_already_at_the_initial_pc(monkeypatch):
    target = load_target_module(monkeypatch)
    arch = x86.ArchX86()
    event = Event(0x2000, 7, arch, {"rip": 0x2000}, (), "sched", 1)
    start_event = Event(0x3000, 7, arch, {"rip": 0x3000}, (), "sched", 2)
    initial = ProgramState(arch)
    initial.write_register("rip", 0x2000)
    destination = ProgramState(arch)
    destination.write_register("rip", 0x3000)
    iterator = object.__new__(target.GDBServerStateIterator)
    iterator._events = DeterministicCursor((event, start_event), target.match_event)
    iterator._replay_tid = None
    iterator._replay = X86ReplayEngine(arch)
    iterator._first_next = True
    iterator.arch = arch
    stops: list[list[int]] = []
    iterator.current_state = lambda: initial
    iterator.is_exited = lambda: False

    def run_until_any(addresses: list[int]) -> ReadableProgramState:
        stops.append(addresses)
        return destination

    iterator._run_until_any = run_until_any

    assert iterator.run_until(0x3000) is destination
    assert iterator._events.state is CursorState.SYNCHRONIZED
    assert iterator._replay_tid == 7
    assert stops == [[0x3000]]
    sys.modules.pop("focaccia.qemu.target", None)


def x86_elf_image(
    *,
    syscall_offset: int | None,
    virtual_base: int = 0,
) -> bytes:
    size = 0x1000
    image = bytearray(b"\x90" * size)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        image,
        0,
        ident,
        3,
        62,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        1,
        0,
        0,
        0,
    )
    struct.pack_into(
        "<IIQQQQQQ",
        image,
        64,
        1,
        5,
        0,
        virtual_base,
        0,
        size,
        size,
        0x1000,
    )
    if syscall_offset is not None:
        image[syscall_offset : syscall_offset + 2] = b"\x0f\x05"
    return bytes(image)


def test_startup_mmap_uses_existing_syscall_without_writing_rx_text(monkeypatch):
    target = load_target_module(monkeypatch)
    fake_gdb = cast(Any, sys.modules["gdb"])
    entry = 0x401000
    vdso = 0x700000
    syscall_pc = vdso + 0x123
    image = x86_elf_image(
        syscall_offset=syscall_pc - vdso,
        virtual_base=vdso,
    )
    memory = {vdso + offset: byte for offset, byte in enumerate(image)}
    inferior = FakeInferior(memory)
    registers: dict[str, FakeRawValue | FakeValue | FakeVectorValue] = {
        "pc": FakeValue(entry, 8),
        "rax": FakeValue(0, 8),
    }
    frame = FakeFrame(registers)
    connector = object.__new__(target.GDBServerConnector)
    connector.arch = x86.ArchX86()
    connector._process = inferior
    connector._frame = frame
    connector._terminal_reason = None
    connector.is_exited = lambda: False
    writes: list[tuple[int, bytes]] = []
    register_writes: list[tuple[str, int]] = []

    def write_register(register: str, value: int) -> None:
        register_writes.append((register, value))
        if register == "rip":
            registers["pc"] = FakeValue(value, 8)
        elif register == "rax":
            registers["rax"] = FakeValue(value, 8)

    connector.write_target_register = write_register
    connector.write_target_memory = lambda address, data: writes.append((address, data))
    connector.skip = lambda pc: write_register("rip", pc)
    fake_gdb.selected_frame = lambda: frame

    class TemporaryBreakpoint:
        def __init__(self, specification: str, *, temporary: bool):
            assert specification == f"*{syscall_pc + 2:#x}"
            assert temporary
            self.valid = True

        def is_valid(self) -> bool:
            return self.valid

        def delete(self) -> None:
            self.valid = False

    fake_gdb.Breakpoint = TemporaryBreakpoint

    def execute(command: str, **_kwargs: object) -> None:
        assert command == "continue"
        registers["pc"] = FakeValue(syscall_pc + 2, 8)
        registers["rax"] = FakeValue(0x3000, 8)

    fake_gdb.execute = execute

    connector.map_target_memory(0x3000, 0x2000, 3, 0x100122, vdso)

    assert writes == []
    assert register_writes[-1] == ("rip", syscall_pc)
    observed_pc = frame.read_register("pc")
    assert isinstance(observed_pc, FakeValue)
    assert int(observed_pc) == syscall_pc + 2
    assert inferior.memory[syscall_pc] == 0x0F
    assert inferior.memory[syscall_pc + 1] == 0x05
    sys.modules.pop("focaccia.qemu.target", None)


def test_startup_mmap_rejects_image_without_syscall_before_mutation(monkeypatch):
    target = load_target_module(monkeypatch)
    connector = object.__new__(target.GDBServerConnector)
    connector.arch = x86.ArchX86()
    connector._terminal_reason = None
    vdso = 0x700000
    state = ProgramState(connector.arch)
    state.write_register("rip", 0x401000)
    state.write_memory(vdso, x86_elf_image(syscall_offset=None))
    connector.current_state = lambda: state
    mutations: list[object] = []
    connector.write_target_register = lambda *_args: mutations.append(_args)

    with pytest.raises(UnsupportedReplayEffect, match="no x86 SYSCALL"):
        connector.map_target_memory(0x3000, 0x2000, 3, 0x100122, vdso)

    assert mutations == []
    sys.modules.pop("focaccia.qemu.target", None)


def test_gdb_signal_replay_writes_and_verifies_legacy_x86_vector_state(monkeypatch):
    target = load_target_module(monkeypatch)
    fake_gdb = cast(Any, sys.modules["gdb"])
    commands: list[str] = []
    fake_gdb.execute = lambda command, **_kwargs: commands.append(command)

    raw = bytearray(512)
    raw[24:28] = (0x1F80).to_bytes(4, "little")
    state = ProgramState(x86.ArchX86())
    for index in range(16):
        value = index << 64 | index
        raw[160 + index * 16 : 176 + index * 16] = value.to_bytes(16, "little")
        state.write_register(f"xmm{index}", value)
    extra = ExtraRegisterState(x86.ArchX86(), "x86-xsave-v1", bytes(raw))
    fake_gdb.parse_and_eval = lambda expression: (
        extra.read_register("mxcsr")
        if expression == "$mxcsr"
        else pytest.fail(f"unexpected expression {expression}")
    )
    connector = object.__new__(target.GDBServerConnector)
    connector.current_state = lambda: state

    connector.write_signal_handler_extra_registers(extra)

    assert commands == [
        *(
            f"set $xmm{index}.uint128 = {extra.read_register(f'xmm{index}'):#x}"
            for index in range(16)
        ),
        "set $mxcsr = 0x1f80",
    ]
    sys.modules.pop("focaccia.qemu.target", None)


def test_gdb_signal_replay_still_rejects_unwritable_aarch64_fp_state(monkeypatch):
    target = load_target_module(monkeypatch)
    arch = aarch64.ArchAArch64("little")

    with pytest.raises(UnsupportedReplayEffect, match="cannot establish"):
        target.GDBServerConnector.write_signal_handler_extra_registers(
            cast(Any, object()),
            ExtraRegisterState(arch, "aarch64-nt-fpr-v1", bytes(528)),
        )

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
