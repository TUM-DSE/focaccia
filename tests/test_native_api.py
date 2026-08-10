import logging
from typing import Any, cast

import pytest
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import (
    Expr,
    ExprCompose,
    ExprCond,
    ExprId,
    ExprInt,
    ExprOp,
    ExprSlice,
)
from miasm.jitter.csts import EXCEPT_DIV_BY_ZERO, EXCEPT_SYSCALL

from focaccia import symbolic as symbolic_module
from focaccia.arch import x86
from focaccia.deterministic import (
    CursorState,
    DeterministicCursor,
    Event,
    KnownMemoryRange,
    MemoryWrite as EventMemoryWrite,
    SignalDescriptor,
    SignalEvent,
    SyscallEvent,
)
from focaccia.miasm_util import MiasmSymbolResolver
from focaccia.native import tracer as tracer_module
from focaccia.native.lldb_target import LLDBConcreteTarget
from focaccia.native.tracer import (
    DisassemblyError,
    SpeculativeTracer,
    SymbolicTracer,
)
from focaccia.snapshot import ProgramState, ReadableProgramState
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


def test_signal_action_transition_uses_handler_context_without_instruction():
    arch = x86.ArchX86()
    descriptor = SignalDescriptor(
        arch,
        (10).to_bytes(4, "little", signed=True),
        True,
        "userHandler",
    )
    pre_event = SignalEvent(
        0x44142A,
        7,
        arch,
        {"rip": 0x44142A, "rax": 0x1234},
        (),
        signal_number=descriptor,
        event_count=20,
    )
    frame = EventMemoryWrite(
        7,
        0x7FFF0000,
        4,
        (KnownMemoryRange(0, b"frame"[:4]),),
        (),
    )
    post_event = SignalEvent(
        0x402520,
        7,
        arch,
        {"rip": 0x402520, "rax": 0x5678, "rsp": 0x7FFF0000},
        (frame,),
        signal_handler=descriptor,
        event_count=21,
    )

    action = tracer_module._signal_action_transform(pre_event, post_event)

    assert action.range == (0x44142A, 0x402520)
    assert action.instructions == []
    assert action.changed_regs == {
        "RIP": ExprInt(0x402520, 64),
        "RAX": ExprInt(0x5678, 64),
        "RSP": ExprInt(0x7FFF0000, 64),
    }
    assert len(action.memory_writes) == 1
    assert action.memory_writes[0].address == ExprInt(0x7FFF0000, 64)
    assert action.memory_writes[0].value == ExprInt(
        int.from_bytes(b"fram", "little"),
        32,
    )


def test_signal_action_trace_does_not_execute_interrupted_instruction(monkeypatch):
    arch = x86.ArchX86()
    descriptor = SignalDescriptor(
        arch,
        (10).to_bytes(4, "little", signed=True),
        True,
        "userHandler",
    )
    pre_event = SignalEvent(
        0x44142A,
        7,
        arch,
        {"rip": 0x44142A, "rax": 0x1234},
        (),
        signal_number=descriptor,
        event_count=20,
    )
    post_event = SignalEvent(
        0x402520,
        7,
        arch,
        {"rip": 0x402520, "rax": 0x5678},
        (),
        signal_handler=descriptor,
        event_count=21,
    )

    class SignalLog:
        base_directory = "/rr/fixture"

        def events(self):
            return (pre_event, post_event)

    class FakeInstruction:
        addr = 0x44142A
        instr = object()

        def __str__(self) -> str:
            return "MOV RDI, RAX"

    instruction = cast(Instruction, FakeInstruction())

    class FakeContext:
        arch = x86.ArchX86()
        loc_db = LocationDB()
        lifter = object()

    class SignalTarget:
        arch = x86.ArchX86()
        exec_time = 0.0
        strict = True

        def __init__(self):
            self.target = self
            self.pc = 0x44142A
            self.registers = {"RIP": self.pc, "RAX": 0x1234}
            self.progress_calls = 0

        def is_exited(self) -> bool:
            return False

        def read_pc(self) -> int:
            return self.pc

        def get_current_tid(self) -> int:
            return 7

        def read_register(self, regname: str) -> int:
            accessor = self.arch.get_reg_accessor(regname)
            assert accessor is not None
            value = self.registers.get(accessor.base_reg, 0)
            return (value & accessor.mask) >> accessor.start

        def read_memory(self, _address: int, size: int) -> bytes:
            return bytes(size)

        def speculate(self, new_pc: int) -> None:
            assert new_pc == 0x402520

        def progress_execution(self, *, use_breakpoint: bool = False) -> int:
            assert not use_breakpoint
            self.progress_calls += 1
            self.pc = 0x402520
            self.registers = {"RIP": self.pc, "RAX": 0x5678}
            return self.pc

    target = SignalTarget()
    monkeypatch.setattr(tracer_module, "DisassemblyContext", lambda _target: FakeContext())
    monkeypatch.setattr(
        tracer_module,
        "_disassemble_instruction",
        lambda _ctx, _target, _pc: instruction,
    )

    def forbidden_instruction_execution(*_args, **_kwargs):
        raise AssertionError("the interrupted instruction must not execute")

    monkeypatch.setattr(tracer_module, "timebound", forbidden_instruction_execution)
    tracer = object.__new__(SymbolicTracer)
    tracer.env = TraceEnvironment(
        None,
        (),
        (),
        binary_hash=None,
        nondeterminism_log=cast(Any, SignalLog()),
        stop_address=0x402520,
        architecture=arch.key,
    )
    tracer.force = False
    tracer.cross_validate = True
    tracer.target = cast(SpeculativeTracer, target)

    trace = tracer.trace()

    assert target.progress_calls == 1
    assert len(trace) == 1
    assert trace[0].range == (0x44142A, 0x402520)
    assert trace[0].instructions == []


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

    def local_target(binary: str, argv: list[str], envp: list[str], profiler):
        calls.append((binary, argv, envp, profiler))
        return expected

    monkeypatch.setattr(tracer_module, "LLDBLocalTarget", local_target)
    symbolic = object.__new__(SymbolicTracer)
    symbolic.env = env
    symbolic.remote = None
    symbolic.profiler = None

    assert symbolic.create_debug_target() is expected
    assert calls == [(env.binary_name, list(env.argv), list(env.envp), None)]


def test_symbolic_tracer_selects_remote_target_for_address(monkeypatch):
    env = _environment()
    calls = []

    class FakeRemoteTarget:
        def determine_name(self) -> str:
            assert env.binary_name is not None
            return env.binary_name

    expected = FakeRemoteTarget()

    def remote_target(remote: str, binary: str, profiler):
        calls.append((remote, binary, profiler))
        return expected

    monkeypatch.setattr(tracer_module, "LLDBRemoteTarget", remote_target)
    symbolic = object.__new__(SymbolicTracer)
    symbolic.env = env
    symbolic.remote = "127.0.0.1:1234"
    symbolic.profiler = None

    assert symbolic.create_debug_target() is expected
    assert calls == [("127.0.0.1:1234", env.binary_name, None)]


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


def test_empty_miasm_disassembly_attempts_lldb_fallback():
    class EmptyDisassembler:
        def dis_instr(self, _pc: int):
            raise IndexError("empty Miasm block")

    class FallbackTarget:
        arch = x86.ArchX86()

        def get_disassembly(self, pc: int) -> str:
            assert pc == 0x1000
            return "NOP"

        def get_instruction_size(self, pc: int) -> int:
            assert pc == 0x1000
            return 1

    context = object.__new__(DisassemblyContext)
    context.mdis = cast(Any, EmptyDisassembler())
    context.arch = x86.ArchX86()
    target = FallbackTarget()

    instruction = tracer_module._disassemble_instruction(
        context,
        cast(LLDBConcreteTarget, target),
        0x1000,
    )

    assert str(instruction).strip() == "NOP"


@pytest.mark.parametrize(
    ("bytecode", "disassembly", "expected_mnemonic"),
    [
        (bytes.fromhex("f20fd0ca"), "ADDSUBPS XMM1, XMM2", "ADDSUBPS"),
        (bytes.fromhex("660fc2c0d1"), "CMPPD XMM0, XMM0, 0xD1", "CMPLTPD"),
    ],
)
def test_pinned_miasm_decodes_and_lifts_paper_sse_instructions(
    bytecode: bytes,
    disassembly: str,
    expected_mnemonic: str,
):
    class InstructionTarget:
        arch = x86.ArchX86()

        def read_instructions(self, address: int, size: int) -> bytes:
            assert address >= 0x1000
            offset = address - 0x1000
            return bytecode[offset:offset + size]

        def get_disassembly(self, pc: int) -> str:
            assert pc == 0x1000
            return disassembly

        def get_instruction_size(self, pc: int) -> int:
            assert pc == 0x1000
            return len(bytecode)

    target = InstructionTarget()
    context = DisassemblyContext(cast(ReadableProgramState, target))
    instruction = tracer_module._disassemble_instruction(
        context,
        cast(LLDBConcreteTarget, target),
        0x1000,
    )

    assert str(instruction).split(maxsplit=1)[0] == expected_mnemonic
    location_db = LocationDB()
    assignments, extra = instruction.machine.lifter(location_db).get_ir(
        instruction.instr
    )
    assert assignments
    assert extra == []


def test_disassembly_validation_accepts_equivalent_sib_encoding():
    bytecode = bytes.fromhex("488d542420")

    class SibTarget:
        arch = x86.ArchX86()

        def read_instructions(self, address: int, size: int) -> bytes:
            assert address >= 0x1000
            offset = address - 0x1000
            return bytecode[offset:offset + size]

        def get_instruction_size(self, pc: int) -> int:
            assert pc == 0x1000
            return len(bytecode)

        def get_disassembly(self, pc: int) -> str:
            assert pc == 0x1000
            return "LEA RDX, [RSP + 0x20]"

    target = SibTarget()
    context = DisassemblyContext(cast(ReadableProgramState, target))

    instruction = tracer_module._disassemble_instruction(
        context,
        cast(LLDBConcreteTarget, target),
        0x1000,
    )

    assert str(instruction).split() == [
        "LEA",
        "RDX,",
        "QWORD",
        "PTR",
        "[RSP",
        "+",
        "0x20]",
    ]


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
    primary = tracer_module._disassemble_instruction(
        context,
        cast(LLDBConcreteTarget, target),
        0x1000,
    )
    assert str(primary).split(maxsplit=1)[0] == "VMOVDQU"
    assert target.fallback_calls == [0x1000]

    wrong = Instruction.from_string(
        "REP OUTSD",
        target.arch,
        offset=0x1000,
        length=3,
    )

    class WrongContext:
        arch = target.arch

        def disassemble(self, _pc: int) -> Instruction:
            return wrong

    recovered = tracer_module._disassemble_instruction(
        cast(DisassemblyContext, WrongContext()),
        cast(LLDBConcreteTarget, target),
        0x1000,
    )

    assert str(recovered).split(maxsplit=1)[0] == "VMOVDQU"
    assert target.fallback_calls == [0x1000, 0x1000]


def test_rex_mmx_movq_uses_full_mm0_value():
    bytecode = bytes.fromhex("4f0f7ec0")

    class RexMovqTarget:
        arch = x86.ArchX86()

        def read_instructions(self, address: int, size: int) -> bytes:
            assert address >= 0x1000
            offset = address - 0x1000
            return bytecode[offset:offset + size]

        def get_instruction_size(self, pc: int) -> int:
            assert pc == 0x1000
            return len(bytecode)

        def get_disassembly(self, pc: int) -> str:
            assert pc == 0x1000
            return "MOVQ R8, MM0"

    target = RexMovqTarget()
    context = DisassemblyContext(cast(ReadableProgramState, target))
    instruction = tracer_module._disassemble_instruction(
        context,
        cast(LLDBConcreteTarget, target),
        0x1000,
    )

    assert str(instruction).split() == ["MOVQ", "R8,", "MM0"]
    location_db = LocationDB()
    state = ProgramState(target.arch)
    resolver = MiasmSymbolResolver(state, location_db)
    next_pc, outputs = run_instruction(
        instruction.instr,
        resolver,
        instruction.machine.lifter(location_db),
    )
    assert next_pc == ExprInt(0x1004, 64)
    assert outputs[ExprId("R8", 64)] == ExprId("MM0", 64)


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


def _lsl_environment_outputs() -> tuple[Instruction, dict[Expr, Expr]]:
    instruction = Instruction.from_string(
        "LSL AX, BX",
        x86.ArchX86(),
        offset=0x1000,
        length=3,
    )
    selector = ExprId("RBX", 64)[0:16]
    limit = ExprOp("load_segment_limit", selector)
    return instruction, {
        ExprId("RAX", 64): ExprCompose(limit, ExprSlice(ExprId("RAX", 64), 16, 64)),
        ExprId("zf", 1): ExprOp("load_segment_limit_ok", selector),
        ExprId("RIP", 64): ExprInt(0x1003, 64),
    }


def test_lsl_environment_specialization_omits_inaccessible_destination():
    instruction, outputs = _lsl_environment_outputs()
    observed = ProgramState(x86.ArchX86())
    observed.write_register("RAX", 0xA02E698E741F5A6A)
    observed.write_register("ZF", 0)

    specialized = tracer_module._specialize_observed_lsl_outputs(
        instruction,
        outputs,
        observed,
    )

    assert specialized == {
        ExprId("zf", 1): ExprInt(0, 1),
        ExprId("RIP", 64): ExprInt(0x1003, 64),
    }


def test_lsl_environment_specialization_records_successful_limit():
    instruction, outputs = _lsl_environment_outputs()
    observed = ProgramState(x86.ArchX86())
    observed.write_register("RAX", 0xA02E698E741F1234)
    observed.write_register("ZF", 1)

    specialized = tracer_module._specialize_observed_lsl_outputs(
        instruction,
        outputs,
        observed,
    )

    assert specialized == {
        ExprId("zf", 1): ExprInt(1, 1),
        ExprId("RIP", 64): ExprInt(0x1003, 64),
        ExprId("AX", 16): ExprInt(0x1234, 16),
    }


def test_force_mode_records_unknown_symbolic_outputs_as_trace_gap(
    monkeypatch,
    caplog,
):
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
    tracer.target = cast(SpeculativeTracer, FakeTarget())

    with caplog.at_level(logging.INFO, logger=tracer_module.logger.name):
        trace = tracer.trace()

    assert "Execution time:" not in caplog.text
    assert "Symbolic time:" not in caplog.text
    assert "Validation time:" not in caplog.text
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
    tracer.target = cast(SpeculativeTracer, FakeTarget())

    trace = tracer.trace()

    assert len(trace) == 1
    gap = trace[0]
    assert isinstance(gap, TraceGap)
    assert gap.range == (0x1000, 0)
    assert gap.reason == "unsupported-semantics"
    assert gap.cause is symbolic_error
