from typing import Any, cast

import pytest
from miasm.core.locationdb import LocationDB
from miasm.core.utils import Disasm_Exception
from miasm.expression.expression import Expr, ExprCond, ExprId, ExprInt
from miasm.jitter.csts import EXCEPT_DIV_BY_ZERO, EXCEPT_SYSCALL

from focaccia import symbolic as symbolic_module
from focaccia.arch import x86
from focaccia.deterministic import (
    CursorState,
    DeterministicCursor,
    Event,
    SignalDescriptor,
    SignalEvent,
    SyscallEvent,
)
from focaccia.native import tracer as tracer_module
from focaccia.native.lldb_target import LLDBConcreteTarget
from focaccia.native.tracer import (
    DisassemblyError,
    DisassemblyMismatchError,
    SpeculativeTracer,
    SymbolicTracer,
)
from focaccia.snapshot import ReadableProgramState
from focaccia.symbolic import (
    DisassemblyContext,
    Instruction,
    SymbolicCompositionError,
    SymbolicTransform,
    TraceGap,
    UnsupportedInstructionError,
    run_instruction,
)
from focaccia.tools.capture_transforms import make_argparser
from focaccia.trace import TraceEnvironment


class FakeRegister:
    size = 8

    def __init__(self, value: int):
        self.value = value

    def IsValid(self) -> bool:
        return True

    def GetValueAsUnsigned(self, *_args) -> int:
        return self.value


def _environment() -> TraceEnvironment:
    return TraceEnvironment(
        "/tmp/oracle",
        ["argument"],
        ["NAME=value"],
        binary_hash="test-hash",
    )


def test_missing_deterministic_log_provides_empty_events():
    assert tracer_module._events_for_environment(_environment()) == ()


@pytest.mark.parametrize("pair_kind", ("syscall", "signal"))
def test_native_tracer_initial_post_event_is_not_paired_or_event_stepped(pair_kind):
    arch = x86.ArchX86()
    initial_post = SyscallEvent(
        0x1000,
        1,
        arch,
        {"rip": 0x1000, "rax": 59},
        (),
        arch,
        59,
        "exiting",
        False,
        event_count=14,
    )
    if pair_kind == "syscall":
        pre_event = SyscallEvent(
            0x2000,
            1,
            arch,
            {"rip": 0x2000, "rax": 1},
            (),
            arch,
            1,
            "entering",
            False,
            event_count=15,
        )
        post_event = SyscallEvent(
            0x2002,
            1,
            arch,
            {"rip": 0x2002, "rax": 1},
            (),
            arch,
            1,
            "exiting",
            False,
            event_count=16,
        )
    else:
        descriptor = SignalDescriptor(
            arch,
            (2).to_bytes(4, "little", signed=True),
            True,
            "ignored",
        )
        pre_event = SignalEvent(
            0x2000,
            1,
            arch,
            {"rip": 0x2000},
            (),
            signal_number=descriptor,
            event_count=15,
        )
        post_event = SignalEvent(
            0x2002,
            1,
            arch,
            {"rip": 0x2002},
            (),
            signal_delivery=descriptor,
            event_count=16,
        )

    class EventState(ReadableProgramState):
        def __init__(self):
            super().__init__(arch)
            self.pc = 0x1000

        def read_pc(self) -> int:
            return self.pc

    state = EventState()
    cursor: DeterministicCursor[ReadableProgramState] = DeterministicCursor(
        (initial_post, pre_event, post_event),
        lambda item, current: item.pc == current.read_pc(),
    )

    event, paired, requires_event_step = tracer_module._match_deterministic_event(
        cursor,
        state,
    )
    assert event is initial_post
    assert paired is None
    assert not requires_event_step
    assert cursor.peek() is pre_event

    state.pc = 0x2000
    event, paired, requires_event_step = tracer_module._match_deterministic_event(
        cursor,
        state,
    )
    assert event is pre_event
    assert paired is post_event
    assert requires_event_step
    assert cursor.state is CursorState.EXHAUSTED


def test_recorded_syscall_control_output_is_not_architectural_state():
    arch = x86.ArchX86()
    pre_event = SyscallEvent(
        0x1000,
        1,
        arch,
        {"rip": 0x1000, "rax": 158},
        (),
        arch,
        158,
        "entering",
        False,
        event_count=15,
    )
    post_event = SyscallEvent(
        0x1002,
        1,
        arch,
        {"rip": 0x1002, "rax": 0},
        (),
        arch,
        158,
        "exiting",
        False,
        event_count=16,
    )

    class SyscallInstruction:
        def __str__(self) -> str:
            return "SYSCALL"

    instruction = cast(Instruction, SyscallInstruction())
    marker = ExprId("exception_flags", 32)
    outputs: dict[Expr, Expr] = {
        marker: ExprInt(EXCEPT_SYSCALL, 32),
        ExprId("RIP", 64): ExprInt(0x1002, 64),
    }

    architectural = tracer_module._architectural_outputs_for_recorded_syscall(
        outputs,
        pre_event,
        post_event,
        instruction,
    )
    assert marker not in architectural
    SymbolicTransform(1, architectural, [instruction], arch, 0x1000, 0x1002)

    unmatched = tracer_module._architectural_outputs_for_recorded_syscall(
        outputs,
        None,
        None,
        instruction,
    )
    assert unmatched is outputs
    with pytest.raises(SymbolicCompositionError, match="exception_flags"):
        SymbolicTransform(1, unmatched, [instruction], arch, 0x1000, 0x1002)

    wrong_marker: dict[Expr, Expr] = {
        marker: ExprInt(EXCEPT_SYSCALL + 1, 32)
    }
    assert (
        tracer_module._architectural_outputs_for_recorded_syscall(
            wrong_marker,
            pre_event,
            post_event,
            instruction,
        )
        is wrong_marker
    )


@pytest.mark.parametrize(
    ("divisor", "marker_removed"),
    ((0x7F0, True), (0, False)),
)
def test_observed_division_removes_only_inactive_exception_control(
    divisor: int,
    marker_removed: bool,
):
    arch = x86.ArchX86()
    marker = ExprId("exception_flags", 32)
    divisor_expr = ExprId("R13", 64)
    outputs: dict[Expr, Expr] = {
        marker: ExprCond(
            divisor_expr,
            marker,
            ExprInt(EXCEPT_DIV_BY_ZERO, 32),
        ),
        ExprId("RAX", 64): ExprCond(
            divisor_expr,
            ExprInt(2, 64),
            ExprId("RAX", 64),
        ),
    }

    class DivisionInstruction:
        def __str__(self) -> str:
            return "DIV R13"

    class DivisionState(ReadableProgramState):
        def __init__(self):
            super().__init__(arch)

        def read_register(self, reg: str) -> int:
            assert reg == "R13"
            return divisor

    architectural = tracer_module._architectural_outputs_for_observed_division(
        outputs,
        cast(Instruction, DivisionInstruction()),
        DivisionState(),
    )
    assert (marker not in architectural) is marker_removed
    assert ExprId("RAX", 64) in architectural


def test_native_terminal_syscall_consumes_exit_marker_and_targets_exit():
    arch = x86.ArchX86()
    pre_event = SyscallEvent(
        0x1000,
        1,
        arch,
        {"rip": 0x1000, "rax": 231},
        (),
        arch,
        231,
        "entering",
        False,
        event_count=19,
    )
    terminal = Event(None, 1, arch, {}, (), "exit", 20)

    class SyscallInstruction:
        def __str__(self) -> str:
            return "SYSCALL"

    class EventState(ReadableProgramState):
        def __init__(self):
            super().__init__(arch)

        def read_pc(self) -> int:
            return 0x1000

    cursor: DeterministicCursor[ReadableProgramState] = DeterministicCursor(
        (pre_event, terminal),
        lambda item, current: item.pc == current.read_pc(),
    )
    event, post_event, requires_event_step = (
        tracer_module._match_deterministic_event(cursor, EventState())
    )
    assert event is pre_event
    assert post_event is terminal
    assert requires_event_step
    assert cursor.state is CursorState.EXHAUSTED

    instruction = cast(Instruction, SyscallInstruction())
    pc_output = ExprId("RIP", 64)
    marker = ExprId("exception_flags", 32)
    outputs: dict[Expr, Expr] = {
        marker: ExprInt(EXCEPT_SYSCALL, 32),
        pc_output: ExprInt(0x1002, 64),
    }
    destination, outputs = tracer_module._terminal_syscall_transition(
        ExprInt(0x1002, 64),
        outputs,
        pre_event,
        terminal,
        instruction,
        pc_output,
        arch,
    )
    assert destination == ExprInt(0, 64)
    assert outputs[pc_output] == ExprInt(0, 64)
    architectural = tracer_module._architectural_outputs_for_recorded_syscall(
        outputs,
        pre_event,
        terminal,
        instruction,
    )
    assert marker not in architectural
    SymbolicTransform(1, architectural, [instruction], arch, 0x1000, 0)


def test_lldb_target_read_pc_normalizes_x86_alias(monkeypatch):
    target = object.__new__(LLDBConcreteTarget)
    target.arch = x86.ArchX86()
    target.archname = x86.archname
    requested = []

    def get_register(regname: str) -> FakeRegister:
        requested.append(regname)
        return FakeRegister(0x1234)

    monkeypatch.setattr(target, "_get_register", get_register)

    assert target.read_pc() == 0x1234
    assert target.read_register("pc") == 0x1234
    assert target.read_register("RIP") == 0x1234
    assert requested == ["rip", "rip", "rip"]


def test_speculative_tracer_uses_target_read_pc():
    class FakeTarget:
        arch = x86.ArchX86()

        def __init__(self):
            self.pc = 0x1000
            self.read_pc_calls = 0
            self.step_calls = 0

        def read_pc(self) -> int:
            self.read_pc_calls += 1
            return self.pc

        def read_register(self, _regname: str) -> int:
            raise AssertionError("SpeculativeTracer must use read_pc at the target boundary")

        def is_exited(self) -> bool:
            return False

        def step(self) -> None:
            self.step_calls += 1
            self.pc += 4

    fake = FakeTarget()
    speculative = SpeculativeTracer(cast(LLDBConcreteTarget, fake))
    speculative.step()

    assert speculative.read_pc() == 0x1004
    assert fake.read_pc_calls == 2
    assert fake.step_calls == 1


def test_speculative_tracer_does_not_read_pc_after_terminal_step():
    class FakeTarget:
        arch = x86.ArchX86()

        def __init__(self):
            self.exited = False
            self.read_pc_calls = 0

        def read_pc(self) -> int:
            self.read_pc_calls += 1
            if self.exited:
                raise AssertionError("terminal targets have no readable PC")
            return 0x1000

        def step(self) -> None:
            self.exited = True

        def is_exited(self) -> bool:
            return self.exited

    fake = FakeTarget()
    speculative = SpeculativeTracer(cast(LLDBConcreteTarget, fake))

    speculative.speculate(None)

    assert speculative.read_pc() == 0
    assert fake.read_pc_calls == 1


def test_symbolic_tracer_selects_local_target_for_none(monkeypatch):
    env = _environment()
    calls = []
    expected = object()

    def local_target(binary: str, argv: list[str], envp: list[str]):
        calls.append((binary, argv, envp))
        return expected

    monkeypatch.setattr(tracer_module, "LLDBLocalTarget", local_target)
    symbolic = object.__new__(SymbolicTracer)
    symbolic.env = env
    symbolic.remote = None

    assert symbolic.create_debug_target() is expected
    assert calls == [(env.binary_name, list(env.argv), list(env.envp))]


def test_symbolic_tracer_selects_remote_target_for_address(monkeypatch):
    env = _environment()
    calls = []

    class FakeRemoteTarget:
        def determine_name(self) -> str:
            assert env.binary_name is not None
            return env.binary_name

    expected = FakeRemoteTarget()

    def remote_target(remote: str, binary: str):
        calls.append((remote, binary))
        return expected

    monkeypatch.setattr(tracer_module, "LLDBRemoteTarget", remote_target)
    symbolic = object.__new__(SymbolicTracer)
    symbolic.env = env
    symbolic.remote = "127.0.0.1:1234"

    assert symbolic.create_debug_target() is expected
    assert calls == [("127.0.0.1:1234", env.binary_name)]


def test_capture_transforms_remote_default_is_none():
    args = make_argparser().parse_args(["/tmp/oracle"])
    assert args.remote is None


def test_disassembly_fallback_uses_instruction_from_string(monkeypatch):
    primary_error = ValueError("primary disassembler failed")
    calls = []
    expected = cast(Instruction, object())

    class FakeContext:
        arch = x86.ArchX86()

        def disassemble(self, _pc: int) -> Instruction:
            raise primary_error

    class FakeTarget:
        def get_disassembly(self, pc: int) -> str:
            assert pc == 0x1000
            return "NOP"

        def get_instruction_size(self, pc: int) -> int:
            assert pc == 0x1000
            return 1

    def from_string(text: str, arch, offset: int, length: int) -> Instruction:
        calls.append((text, arch, offset, length))
        return expected

    monkeypatch.setattr(Instruction, "from_string", staticmethod(from_string))
    context = cast(DisassemblyContext, FakeContext())
    target = cast(LLDBConcreteTarget, FakeTarget())

    assert tracer_module._disassemble_instruction(context, target, 0x1000) is expected
    assert calls == [("NOP", context.arch, 0x1000, 1)]


@pytest.mark.parametrize(
    ("bytecode", "disassembly"),
    [
        (bytes.fromhex("f20fd0ca"), "ADDSUBPS XMM1, XMM2"),
        (bytes.fromhex("660fc2c0d1"), "CMPPD XMM0, XMM0, 0xD1"),
    ],
)
def test_empty_miasm_disassembly_attempts_lldb_fallback(
    bytecode: bytes,
    disassembly: str,
):
    class UnsupportedInstructionTarget:
        arch = x86.ArchX86()

        def __init__(self):
            self.fallback_calls: list[int] = []

        def read_instructions(self, address: int, size: int) -> bytes:
            assert address >= 0x1000
            offset = address - 0x1000
            return bytecode[offset:offset + size]

        def get_disassembly(self, pc: int) -> str:
            self.fallback_calls.append(pc)
            return disassembly

        def get_instruction_size(self, pc: int) -> int:
            assert pc == 0x1000
            return len(bytecode)

    target = UnsupportedInstructionTarget()
    context = DisassemblyContext(cast(ReadableProgramState, target))

    with pytest.raises(DisassemblyError) as raised:
        tracer_module._disassemble_instruction(
            context,
            cast(LLDBConcreteTarget, target),
            0x1000,
        )

    assert target.fallback_calls == [0x1000]
    assert isinstance(raised.value.primary_error, Disasm_Exception)
    assert isinstance(raised.value.primary_error.__cause__, IndexError)
    assert isinstance(raised.value.fallback_error, ValueError)


def test_vex_misdecode_is_rejected_before_using_wrong_semantics():
    bytecode = bytes.fromhex("c5fe6f00")

    class VexTarget:
        arch = x86.ArchX86()

        def __init__(self):
            self.fallback_calls: list[int] = []

        def read_instructions(self, address: int, size: int) -> bytes:
            assert address >= 0x1000
            offset = address - 0x1000
            return bytecode[offset:offset + size]

        def get_instruction_size(self, pc: int) -> int:
            assert pc == 0x1000
            return len(bytecode)

        def get_disassembly(self, pc: int) -> str:
            self.fallback_calls.append(pc)
            return "VMOVDQU YMM0, YMMWORD PTR [RAX]"

    target = VexTarget()
    context = DisassemblyContext(cast(ReadableProgramState, target))

    with pytest.raises(DisassemblyError) as raised:
        tracer_module._disassemble_instruction(
            context,
            cast(LLDBConcreteTarget, target),
            0x1000,
        )

    assert target.fallback_calls == [0x1000]
    assert isinstance(raised.value.primary_error, DisassemblyMismatchError)
    assert "REP OUTSD" in str(raised.value.primary_error)
    assert "3 bytes" in str(raised.value.primary_error)
    assert "4 bytes (c5fe6f00)" in str(raised.value.primary_error)
    assert isinstance(raised.value.fallback_error, ValueError)


def test_disassembly_fallback_does_not_hide_programming_errors():
    programming_error = RuntimeError("fixture programming error")

    class FakeContext:
        arch = x86.ArchX86()

        def disassemble(self, _pc: int) -> Instruction:
            raise programming_error

    class FakeTarget:
        def get_disassembly(self, _pc: int) -> str:
            raise AssertionError("fallback must not run")

    with pytest.raises(RuntimeError) as raised:
        tracer_module._disassemble_instruction(
            cast(DisassemblyContext, FakeContext()),
            cast(LLDBConcreteTarget, FakeTarget()),
            0x1000,
        )

    assert raised.value is programming_error


def test_disassembly_fallback_preserves_both_errors(monkeypatch):
    primary_error = ValueError("primary disassembler failed")
    fallback_error = ValueError("fallback disassembler failed")

    class FakeContext:
        arch = x86.ArchX86()

        def disassemble(self, _pc: int) -> Instruction:
            raise primary_error

    class FakeTarget:
        def get_disassembly(self, _pc: int) -> str:
            return "INVALID"

        def get_instruction_size(self, _pc: int) -> int:
            return 1

    def from_string(*_args, **_kwargs) -> Instruction:
        raise fallback_error

    monkeypatch.setattr(Instruction, "from_string", staticmethod(from_string))
    context = cast(DisassemblyContext, FakeContext())
    target = cast(LLDBConcreteTarget, FakeTarget())

    with pytest.raises(DisassemblyError) as raised:
        tracer_module._disassemble_instruction(context, target, 0x2000)

    assert raised.value.primary_error is primary_error
    assert raised.value.fallback_error is fallback_error
    assert raised.value.__cause__ is fallback_error


def test_force_mode_records_unknown_symbolic_outputs_as_trace_gap(monkeypatch):
    class FakeInstruction:
        instr = object()

        def __str__(self) -> str:
            return "UNMODELED-OUTPUT"

    instruction = cast(Instruction, FakeInstruction())

    class FakeContext:
        arch = x86.ArchX86()
        loc_db = LocationDB()
        lifter = object()

    class FakeCursor:
        events = []
        state = CursorState.EXHAUSTED

        def __init__(self, *_args):
            pass

        def match(self, _target):
            return None

        def match_pair(self, _event):
            return None

    class FakeTarget:
        arch = x86.ArchX86()
        exec_time = 0.0

        def __init__(self):
            self.target = self
            self.pc = 0x1000
            self.executed = False
            self.post_execution_exit_checks = 0

        def is_exited(self) -> bool:
            if not self.executed:
                return False
            self.post_execution_exit_checks += 1
            return self.post_execution_exit_checks >= 2

        def read_pc(self) -> int:
            return self.pc

        def get_current_tid(self) -> int:
            return 9

        def speculate(self, new_pc) -> None:
            assert new_pc is None
            self.pc = 0x1001
            self.executed = True

        def progress_execution(self) -> None:
            pass

    def unsupported_output(*_args, **_kwargs):
        return (
            ExprInt(0x1001, 64),
            {ExprId("UNMODELED", 64): ExprInt(1, 64)},
        )

    monkeypatch.setattr(tracer_module, "DisassemblyContext", lambda _target: FakeContext())
    monkeypatch.setattr(
        tracer_module,
        "_disassemble_instruction",
        lambda _ctx, _target, _pc: instruction,
    )
    monkeypatch.setattr(tracer_module, "DeterministicCursor", FakeCursor)
    monkeypatch.setattr(tracer_module, "timebound", unsupported_output)

    tracer = object.__new__(SymbolicTracer)
    tracer.env = _environment()
    tracer.force = True
    tracer.cross_validate = False
    tracer.validation_time = 0.0
    tracer.target = cast(SpeculativeTracer, FakeTarget())

    trace = tracer.trace()

    assert len(trace) == 1
    gap = trace[0]
    assert isinstance(gap, TraceGap)
    assert gap.range == (0x1000, 0x1001)
    assert gap.reason == "unsupported-semantics"
    assert gap.cause is not None
    assert "UNMODELED" in str(gap.cause)


def test_symbolic_execution_not_implemented_error_is_typed(monkeypatch):
    loc_db = LocationDB()
    loc = loc_db.get_or_create_offset_location(0x1000)
    execution_error = NotImplementedError("fixture execution is unsupported")

    class FakeIrcfg:
        def get_block(self, _loc):
            return object()

    class FakeLifter:
        pc = ExprId("RIP", 64)

        def new_ircfg(self):
            return FakeIrcfg()

        def add_instr_to_ircfg(self, *_args):
            return loc

    class FakeEngine:
        def __init__(self, *_args, **_kwargs):
            pass

        def eval_updt_irblock(self, _block):
            raise execution_error

    monkeypatch.setattr(symbolic_module, "SymbolicExecutionEngine", FakeEngine)

    with pytest.raises(UnsupportedInstructionError) as raised:
        run_instruction(cast(Any, "FIXTURE"), cast(Any, object()), cast(Any, FakeLifter()))

    assert raised.value.__cause__ is execution_error


def test_force_mode_records_symbolic_failure_as_trace_gap(monkeypatch):
    symbolic_error = UnsupportedInstructionError(
        "fixture instruction is unsupported"
    )

    class FakeInstruction:
        instr = object()

        def __str__(self) -> str:
            return "UNSUPPORTED"

    instruction = cast(Instruction, FakeInstruction())

    class FakeContext:
        arch = x86.ArchX86()
        loc_db = LocationDB()
        lifter = object()

    class FakeCursor:
        events = []
        state = CursorState.EXHAUSTED

        def __init__(self, *_args):
            pass

        def match(self, _target):
            return None

        def match_pair(self, _event):
            return None

    class FakeTarget:
        arch = x86.ArchX86()
        exec_time = 0.0

        def __init__(self):
            self.target = self
            self.pc = 0x1000
            self.exited = False

        def is_exited(self) -> bool:
            return self.exited

        def read_pc(self) -> int:
            return self.pc

        def get_current_tid(self) -> int:
            return 9

        def speculate(self, new_pc) -> None:
            assert new_pc is None
            self.pc = 0x1001
            self.exited = True

        def progress_execution(self) -> None:
            pass

    def fail_symbolically(*_args, **_kwargs):
        raise symbolic_error

    monkeypatch.setattr(tracer_module, "DisassemblyContext", lambda _target: FakeContext())
    monkeypatch.setattr(
        tracer_module,
        "_disassemble_instruction",
        lambda _ctx, _target, _pc: instruction,
    )
    monkeypatch.setattr(tracer_module, "DeterministicCursor", FakeCursor)
    monkeypatch.setattr(tracer_module, "timebound", fail_symbolically)

    tracer = object.__new__(SymbolicTracer)
    tracer.env = _environment()
    tracer.force = True
    tracer.cross_validate = False
    tracer.validation_time = 0.0
    tracer.target = cast(SpeculativeTracer, FakeTarget())

    trace = tracer.trace()

    assert len(trace) == 1
    gap = trace[0]
    assert isinstance(gap, TraceGap)
    assert gap.range == (0x1000, 0)
    assert gap.reason == "unsupported-semantics"
    assert gap.cause is symbolic_error
