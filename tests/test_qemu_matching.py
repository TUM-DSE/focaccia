import importlib
import sys
from types import ModuleType

import pytest
from miasm.expression.expression import ExprId, ExprInt, ExprMem

from focaccia.arch import x86
from focaccia.match import TransitionMatcher
from focaccia.qemu.validation_server import collect_conc_trace
from focaccia.snapshot import ProgramState, RegisterAccessError
from focaccia.symbolic import Instruction, SymbolicTransform, TraceGap
from focaccia.trace import MaterializedTrace, TraceEnvironment


ARCH = x86.ArchX86()
ENV = TraceEnvironment(
    None,
    (),
    (),
    binary_hash=None,
    architecture=ARCH.key,
)


def state(
    pc: int,
    *,
    rax: int | None = None,
    rbx: int | None = None,
    memory: dict[int, bytes] | None = None,
) -> ProgramState:
    result = ProgramState(ARCH)
    result.write_register("PC", pc)
    if rax is not None:
        result.write_register("RAX", rax)
    if rbx is not None:
        result.write_register("RBX", rbx)
    for address, data in (memory or {}).items():
        result.write_memory(address, data)
    return result


def transform(start: int, end: int, *, rax: int | None = None) -> SymbolicTransform:
    changes = {}
    if rax is not None:
        changes[ExprId("RAX", 64)] = ExprInt(rax, 64)
    return SymbolicTransform(1, changes, [], ARCH, start, end)


def trace(*items: SymbolicTransform) -> MaterializedTrace[SymbolicTransform]:
    return MaterializedTrace(items, ENV, [item.addr for item in items])


def codes(result) -> set[str]:
    return {diagnostic.code for diagnostic in result.diagnostics}


def test_plugin_collector_returns_destination_for_single_transition():
    item = transform(0x1000, 0x1001)

    result = collect_conc_trace(
        iter([state(0x1000), state(0x1001)]),
        trace(item),
    )

    assert result.trace is not None
    assert len(result.trace) == 1
    assert [boundary.read_pc() for boundary in result.trace.state_boundaries] == [
        0x1000,
        0x1001,
    ]
    assert result.trace.transforms == (item,)


def test_plugin_collector_preserves_final_transition_of_two():
    transforms = [transform(0x1000, 0x1001), transform(0x1001, 0x1002)]

    result = collect_conc_trace(
        iter([state(0x1000), state(0x1001), state(0x1002)]),
        trace(*transforms),
    )

    assert result.trace is not None
    assert len(result.trace) == 2
    assert len(result.trace.state_boundaries) == 3
    assert result.trace[-1].destination.read_pc() == 0x1002


def test_plugin_collector_composes_symbolic_interior_cutpoints():
    result = collect_conc_trace(
        iter([state(0x1000), state(0x1002)]),
        trace(transform(0x1000, 0x1001), transform(0x1001, 0x1002)),
    )

    assert result.trace is not None
    assert len(result.trace) == 1
    assert result.trace.transforms[0].range == (0x1000, 0x1002)
    assert "symbolic-transforms-composed" in codes(result)


def test_plugin_collector_propagates_opt_in_unmatched_skip():
    result = collect_conc_trace(
        iter([state(0x1000), state(0x1002), state(0x1003)]),
        trace(
            transform(0x1000, 0x1001),
            transform(0x1001, 0x1002),
            transform(0x1002, 0x1003),
        ),
        skip_unmatched=True,
    )

    assert result.trace is not None
    assert isinstance(result.trace.transforms[0], TraceGap)
    assert result.trace.transforms[1].range == (0x1002, 0x1003)
    assert "unmatched-symbolic-transforms-skipped" in codes(result)


def test_skip_mode_does_not_compose_candidate_dependencies(monkeypatch):
    items = tuple(transform(0x1000 + index, 0x1001 + index) for index in range(100))
    for index, item in enumerate(items):
        instruction = "RET" if index == len(items) - 1 else "NOP"
        item.instructions = [Instruction.from_string(instruction, ARCH, item.range[0], 1)]

    def unexpected_plan(_self):
        raise AssertionError("skip mode must not compose successor candidates")

    monkeypatch.setattr(
        "focaccia.match.TransitionMatcher.plan_successor_dependencies",
        unexpected_plan,
    )

    result = collect_conc_trace(
        iter([state(0x1000), state(0x1064)]),
        trace(*items),
        skip_unmatched=True,
    )

    assert result.trace is not None
    assert isinstance(result.trace.transforms[0], TraceGap)


def test_successor_dependency_planning_does_not_materialize_candidate_prefixes(monkeypatch):
    items = tuple(transform(0x1000 + index, 0x1001 + index) for index in range(100))
    for index, item in enumerate(items):
        item.instructions = [
            Instruction.from_string(
                "RET" if index == len(items) - 1 else "NOP",
                ARCH,
                item.range[0],
                1,
            )
        ]
    matcher = TransitionMatcher(trace(*items))
    assert matcher.observe(0x1000) is not None

    def unexpected_finish(_self):
        raise AssertionError("candidate dependency planning must not materialize prefixes")

    monkeypatch.setattr("focaccia.match.SymbolicTransformComposer.finish", unexpected_finish)

    dependencies = matcher.plan_successor_dependencies()

    assert dependencies is not None
    assert dependencies.arch == ARCH


def test_successor_dependencies_rewrite_late_memory_address_to_source_state():
    first = SymbolicTransform(
        1,
        {ExprId("RAX", 64): ExprId("RBX", 64)},
        [],
        ARCH,
        0x1000,
        0x1001,
    )
    second = SymbolicTransform(
        1,
        {ExprId("RCX", 64): ExprMem(ExprId("RAX", 64), 64)},
        [Instruction.from_string("RET", ARCH, 0x1001, 1)],
        ARCH,
        0x1001,
        0x1002,
    )
    matcher = TransitionMatcher(trace(first, second))
    assert matcher.observe(0x1000) is not None

    dependencies = matcher.plan_successor_dependencies()

    assert dependencies is not None
    assert "RBX" in dependencies.registers
    assert len(dependencies.memory) == 1
    assert dependencies.memory[0].ptr == ExprId("RBX", 64)


def test_plugin_collector_captures_union_of_direct_successor_dependencies():
    branch = transform(0x1000, 0x1001)
    branch.instructions = [Instruction.from_string("JNZ 0x1002", ARCH, 0x1000, 2)]
    fallthrough = SymbolicTransform(
        1,
        {ExprId("RAX", 64): ExprId("RBX", 64)},
        [],
        ARCH,
        0x1001,
        0x1002,
    )
    taken = SymbolicTransform(
        1,
        {ExprId("RAX", 64): ExprMem(ExprInt(0x2000, 64), 64)},
        [],
        ARCH,
        0x1002,
        0x1003,
    )

    class TakenStates:
        def __init__(self):
            self._states = iter(
                [
                    state(0x1000, rbx=7, memory={0x2000: b"abcdefgh"}),
                    state(0x1002, rax=7, rbx=7, memory={0x2000: b"abcdefgh"}),
                    state(0x1003, rax=int.from_bytes(b"abcdefgh", "little")),
                ]
            )

        def __iter__(self):
            return self

        def __next__(self):
            return next(self._states)

    result = collect_conc_trace(TakenStates(), trace(branch, fallthrough, taken))

    assert result.trace is not None
    source = result.trace.state_boundaries[0]
    assert source.read_register("RBX") == 7
    assert source.read_memory(0x2000, 8) == b"abcdefgh"
    assert "snapshot-register-unavailable" not in codes(result)
    assert "snapshot-memory-unavailable" not in codes(result)


def test_plugin_collector_captures_late_composed_source_dependencies():
    first = transform(0x1000, 0x1001)
    second = SymbolicTransform(
        1,
        {
            ExprId("RAX", 64): ExprId("RBX", 64),
            ExprId("RBX", 64): ExprMem(ExprInt(0x2000, 64), 64),
        },
        [],
        ARCH,
        0x1001,
        0x1002,
    )

    class PlannedStates:
        def __init__(self):
            self._states = iter(
                [
                    state(0x1000, rbx=7, memory={0x2000: b"abcdefgh"}),
                    state(0x1002, rax=7, rbx=int.from_bytes(b"abcdefgh", "little")),
                ]
            )

        def __iter__(self):
            return self

        def __next__(self):
            return next(self._states)

        def next_cutpoint_pc(self, matcher):
            return 0x1002 if matcher.current_destination_pc is not None else None

    result = collect_conc_trace(PlannedStates(), trace(first, second))

    assert result.trace is not None
    source = result.trace.state_boundaries[0]
    assert source.read_register("RBX") == 7
    assert source.read_memory(0x2000, 8) == b"abcdefgh"
    assert "snapshot-register-unavailable" not in codes(result)
    assert "snapshot-memory-unavailable" not in codes(result)


def test_plugin_collector_classifies_missing_terminal_state():
    item = transform(0x1000, 0x1001)

    result = collect_conc_trace(iter([state(0x1000)]), trace(item))

    assert result.trace is not None
    assert len(result.trace) == 0
    assert result.pending_transform is item
    assert "unmatched-terminal-transition" in codes(result)


def test_gdb_collector_uses_shared_matcher_and_keeps_terminal_state(monkeypatch):
    fake_gdb = ModuleType("gdb")
    for name in ("Breakpoint", "Frame", "Inferior", "Value"):
        setattr(fake_gdb, name, object)
    setattr(fake_gdb, "MemoryError", RuntimeError)
    monkeypatch.setitem(sys.modules, "gdb", fake_gdb)
    sys.modules.pop("focaccia.qemu.target", None)
    sys.modules.pop("focaccia.qemu._qemu_tool", None)

    qemu_tool = importlib.import_module("focaccia.qemu._qemu_tool")

    class FakeGDBStates:
        class Events:
            events = ()

        _events = Events()

        def __init__(self):
            self._states = iter([state(0x1000), state(0x1001), state(0x1002)])

        def __iter__(self):
            return self

        def __next__(self):
            return next(self._states)

        def run_until(self, _address: int):
            return next(self)

        def next_cutpoint_pc(self, matcher):
            return matcher.current_destination_pc

    try:
        result = qemu_tool.collect_conc_trace(
            FakeGDBStates(),
            trace(transform(0x1000, 0x1001), transform(0x1001, 0x1002)),
        )
    finally:
        sys.modules.pop("focaccia.qemu._qemu_tool", None)
        sys.modules.pop("focaccia.qemu.target", None)

    assert result.trace is not None
    assert len(result.trace) == 2
    assert result.trace[-1].destination.read_pc() == 0x1002


def test_plugin_snapshot_does_not_fabricate_unavailable_register_outputs():
    item = transform(0x1000, 0x1001, rax=42)

    result = collect_conc_trace(
        iter([state(0x1000, rax=1), state(0x1001)]),
        trace(item),
    )

    assert result.trace is not None
    assert "snapshot-register-unavailable" in codes(result)
    assert not result.complete
    with pytest.raises(RegisterAccessError):
        result.trace.state_boundaries[-1].read_register("RAX")
