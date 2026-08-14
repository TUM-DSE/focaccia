from __future__ import annotations

import pytest

import focaccia.deterministic as deterministic
from focaccia.arch import supported_architectures
from focaccia.deterministic import (
    CursorExhaustedError,
    CursorState,
    CursorStateError,
    DeterministicCursor,
    DeterministicLog,
    DeterministicLogDependencyError,
    Event,
    EventPairError,
    KnownMemoryRange,
    MappingOrderError,
    MemoryMapping,
    MemoryWrite,
    SignalDescriptor,
    SignalEvent,
    SyscallEvent,
    UnknownMemoryRange,
    UnknownMemoryRangeError,
)


X86 = supported_architectures["x86_64"]


def event(pc: int, count: int, *, tid: int = 1, kind: str = "fixture") -> Event:
    return Event(pc, tid, X86, {"rip": pc, "rax": count}, (), kind, count)


def syscall(
    pc: int,
    count: int,
    state: str,
    *,
    tid: int = 1,
    number: int = 0,
) -> SyscallEvent:
    return SyscallEvent(
        pc,
        tid,
        X86,
        {"rip": pc, "rax": number},
        (),
        X86,
        number,
        state,  # type: ignore[arg-type]
        False,
        event_count=count,
    )


def mapping(count: int, start: int) -> MemoryMapping:
    return MemoryMapping(count, start, start + 0x1000, "zero", 0, 3, 2)


def test_none_selects_explicit_empty_log_without_importing_rr(monkeypatch):
    def fail_import(_name: str):
        raise AssertionError("The RR adapter must not be imported for no-log mode.")

    monkeypatch.setattr(deterministic.importlib, "import_module", fail_import)

    log = DeterministicLog(None)

    assert log.base_directory is None
    assert log.metadata is None
    assert log.events() == ()
    assert log.tasks() == ()
    assert log.mmaps() == ()
    assert not log


@pytest.mark.parametrize(
    ("module_name", "requirement"),
    (("capnp", "pycapnp"), ("brotli", "brotli")),
)
def test_only_parser_dependencies_become_optional_dependency_errors(
    monkeypatch, tmp_path, module_name, requirement
):
    missing = ModuleNotFoundError(
        f"No module named {module_name!r}",
        name=module_name,
    )

    def fail_import(_name: str):
        raise missing

    monkeypatch.setattr(deterministic.importlib, "import_module", fail_import)

    with pytest.raises(DeterministicLogDependencyError, match=requirement) as raised:
        DeterministicLog(tmp_path)

    assert raised.value.__cause__ is missing


@pytest.mark.parametrize(
    "defect",
    (
        RuntimeError("adapter programming defect"),
        ModuleNotFoundError("No module named 'adapter_bug'", name="adapter_bug"),
    ),
)
def test_unrelated_adapter_import_errors_are_not_converted_to_empty_logs(
    monkeypatch, tmp_path, defect
):
    def fail_import(_name: str):
        raise defect

    monkeypatch.setattr(deterministic.importlib, "import_module", fail_import)

    with pytest.raises(type(defect)) as raised:
        DeterministicLog(tmp_path)

    assert raised.value is defect


def test_memory_write_ranges_are_immutable_ordered_and_fail_closed():
    write = MemoryWrite(
        7,
        0x2000,
        6,
        (KnownMemoryRange(0, b"ab"), KnownMemoryRange(4, b"cd")),
        (UnknownMemoryRange(2, 2),),
    )

    assert write.encoded_data == b"abcd"
    assert write.holes == (UnknownMemoryRange(2, 2),)
    assert not write.is_fully_known
    with pytest.raises(UnknownMemoryRangeError, match="unknown ranges"):
        write.materialize()

    with pytest.raises(ValueError, match="overlap"):
        MemoryWrite(
            7,
            0x2000,
            4,
            (KnownMemoryRange(0, b"abc"),),
            (UnknownMemoryRange(2, 2),),
        )


def test_fully_known_memory_write_materializes_without_mutation():
    write = MemoryWrite(
        7,
        0x2000,
        4,
        (KnownMemoryRange(0, b"ab"), KnownMemoryRange(2, b"cd")),
        (),
    )

    first = write.materialize()
    second = write.materialize()

    assert first == b"abcd"
    assert second == first
    assert isinstance(first, bytes)


def test_cursor_has_explicit_synchronization_pair_and_exhaustion_states():
    events = (
        event(0x10, 1),
        syscall(0x20, 2, "entering"),
        syscall(0x22, 3, "exiting"),
        event(0x30, 4),
    )
    cursor = DeterministicCursor(events, lambda item, pc: item.pc == pc)

    assert cursor.state is CursorState.UNSYNCHRONIZED
    with pytest.raises(CursorStateError):
        cursor.peek()

    pre = cursor.synchronize(0x20)
    assert pre is events[1]
    assert cursor.state is CursorState.SYNCHRONIZED
    assert cursor.event_position == 1
    assert cursor.peek() is pre

    assert cursor.match(0x21) is None
    assert cursor.event_position == 1
    assert cursor.match(0x20) is pre
    assert cursor.event_position == 2
    assert cursor.match_pair(pre) is events[2]
    assert cursor.peek() is events[3]
    assert cursor.match(0x30) is events[3]
    assert cursor.state is CursorState.EXHAUSTED
    assert cursor.peek() is None
    assert cursor.match(0x30) is None


def test_cursor_initial_post_event_establishes_and_advances_synchronization():
    initial_post = syscall(0x1000, 14, "exiting", number=59)
    next_pre = syscall(0x2000, 15, "entering", number=1)
    next_post = syscall(0x2002, 16, "exiting", number=1)
    cursor = DeterministicCursor(
        (initial_post, next_pre, next_post),
        lambda item, pc: item.pc == pc,
    )

    assert cursor.match(0x1000) is initial_post
    assert cursor.state is CursorState.SYNCHRONIZED
    assert cursor.event_position == 1
    assert cursor.peek() is next_pre
    assert cursor.match(0x2000) is next_pre
    assert cursor.match_pair(next_pre) is next_post
    assert cursor.state is CursorState.EXHAUSTED


def test_cursor_unsynchronized_search_is_bounded_and_retryable():
    events = (event(1, 1), event(2, 2))
    calls: list[tuple[int, int]] = []

    def match(item: Event, state: int) -> bool:
        assert item.pc is not None
        calls.append((item.pc, state))
        return item.pc == state

    cursor = DeterministicCursor(events, match)

    assert cursor.match(99) is None
    assert cursor.state is CursorState.UNSYNCHRONIZED
    assert calls == [(1, 99), (2, 99)]
    assert cursor.match(2) is events[1]
    assert cursor.state is CursorState.EXHAUSTED


def test_cursor_configured_skips_and_explicit_skip_are_bounded():
    events = (event(1, 1), event(2, 2), event(3, 3))
    cursor = DeterministicCursor(
        events,
        lambda item, pc: item.pc == pc,
        skipped_event_counts=(2,),
    )

    assert cursor.match(1) is events[0]
    assert cursor.peek() is events[2]
    position = cursor.event_position
    with pytest.raises(CursorExhaustedError):
        cursor.skip(2)
    assert cursor.event_position == position
    assert cursor.skip(1) == (events[2],)
    assert cursor.state is CursorState.EXHAUSTED


def test_cursor_rejects_malformed_pair_type_thread_state_and_number():
    cases = (
        (syscall(10, 1, "entering"), event(12, 2), "must pair"),
        (syscall(10, 1, "entering"), syscall(12, 2, "exiting", tid=2), "threads"),
        (syscall(10, 1, "exiting"), syscall(12, 2, "exiting"), "pre-event"),
        (
            syscall(10, 1, "entering", number=1),
            syscall(12, 2, "exiting", number=2),
            "call numbers",
        ),
    )

    for pre, post, message in cases:
        cursor = DeterministicCursor(
            (pre, post),
            lambda item, pc: item.pc == pc,
        )
        assert cursor.match(pre.pc) is pre
        with pytest.raises(EventPairError, match=message):
            cursor.match_pair(pre)
        assert cursor.event_position == 1


def test_cursor_validates_signal_pair_variant_and_signal_number():
    signal_two = SignalDescriptor(
        X86,
        (2).to_bytes(4, "little", signed=True),
        True,
        "userHandler",
    )
    pre = SignalEvent(
        10,
        1,
        X86,
        {"rip": 10},
        (),
        signal_number=signal_two,
        event_count=1,
    )
    post = SignalEvent(
        20,
        1,
        X86,
        {"rip": 20},
        (),
        signal_handler=signal_two,
        event_count=2,
    )
    cursor = DeterministicCursor((pre, post), lambda item, pc: item.pc == pc)

    assert cursor.match(10) is pre
    assert cursor.match_pair(pre) is post
    assert cursor.state is CursorState.EXHAUSTED

    signal_three = SignalDescriptor(
        X86,
        (3).to_bytes(4, "little", signed=True),
        True,
        "userHandler",
    )
    wrong_post = SignalEvent(
        20,
        1,
        X86,
        {"rip": 20},
        (),
        signal_delivery=signal_three,
        event_count=2,
    )
    cursor = DeterministicCursor((pre, wrong_post), lambda item, pc: item.pc == pc)
    assert cursor.match(10) is pre
    with pytest.raises(EventPairError, match="signal numbers"):
        cursor.match_pair(pre)


def test_cursor_rejects_missing_post_event_without_index_error():
    pre = syscall(10, 1, "entering")
    cursor = DeterministicCursor((pre,), lambda item, pc: item.pc == pc)

    assert cursor.match(10) is pre
    with pytest.raises(EventPairError, match="no post-event"):
        cursor.match_pair(pre)
    assert cursor.state is CursorState.EXHAUSTED


def test_cursor_consumes_terminal_syscall_exit_marker_transactionally():
    pre = syscall(0x1000, 19, "entering", number=231)
    terminal = Event(None, 1, X86, {}, (), "exit", 20)
    cursor = DeterministicCursor(
        (pre, terminal),
        lambda item, pc: item.pc == pc,
    )

    assert cursor.match(0x1000) is pre
    assert cursor.match_terminal(pre) is terminal
    assert cursor.state is CursorState.EXHAUSTED

    malformed = Event(0x1002, 1, X86, {"rip": 0x1002}, (), "exit", 20)
    cursor = DeterministicCursor(
        (pre, malformed),
        lambda item, pc: item.pc == pc,
    )
    assert cursor.match(0x1000) is pre
    with pytest.raises(EventPairError, match="must not have a program counter"):
        cursor.match_terminal(pre)
    assert cursor.event_position == 1


def test_mapping_cursor_skips_missing_event_ids_and_stops_at_future_records():
    mappings = (mapping(1, 0x1000), mapping(1, 0x2000), mapping(4, 0x4000))
    cursor = DeterministicCursor(
        (event(1, 1),),
        lambda item, pc: item.pc == pc,
        mappings,
    )

    assert cursor.mappings_at(1) == mappings[:2]
    assert cursor.mapping_position == 2
    assert cursor.mappings_at(2) == ()
    assert cursor.mapping_position == 2
    assert cursor.mappings_at(3) == ()
    assert cursor.mapping_position == 2
    assert cursor.mappings_at(4) == mappings[2:]
    assert cursor.mapping_position == 3
    with pytest.raises(MappingOrderError, match="monotonic"):
        cursor.mappings_at(3)


def test_mapping_cursor_rejects_unsorted_input():
    with pytest.raises(MappingOrderError, match="sorted"):
        DeterministicCursor(
            (event(1, 1),),
            lambda item, pc: item.pc == pc,
            (mapping(2, 0x2000), mapping(1, 0x1000)),
        )
