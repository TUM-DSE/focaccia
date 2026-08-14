from types import SimpleNamespace
from typing import Any, cast

import pytest
from miasm.expression.expression import ExprId, ExprInt

from focaccia.arch import aarch64, x86
from focaccia.deterministic import Event, SyscallEvent
from focaccia.native import lldb_target as lldb_module
from focaccia.native.profiling import TraceProfiler
from focaccia.native.lldb_target import (
    ConcreteExecutionError,
    ConcreteMemoryError,
    ConcreteRegisterError,
    LLDBConcreteTarget,
)
from focaccia.native.tracer import (
    SpeculativeDivergenceError,
    SpeculativeTracer,
    SymbolicTracer,
    match_event,
)
from focaccia.symbolic import SymbolicTransform
from focaccia.tools.capture_transforms import create_symbolic_tracer, make_argparser
from focaccia.trace import TraceEnvironment


class ScriptedTarget:
    arch = x86.ArchX86()
    exec_time = 0.0

    def __init__(
        self,
        *,
        pc: int = 0x1000,
        steps: list[int | None] | None = None,
        run_results: dict[int, int | None] | None = None,
        runs_before_exit: int = 0,
    ):
        self.pc = pc
        self.exited = False
        self.steps = list(steps or [])
        self.run_results = dict(run_results or {})
        self.step_calls = 0
        self.run_calls = 0
        self.runs_before_exit = runs_before_exit
        self.run_until_calls: list[int] = []
        self.register_reads: list[str] = []
        self.memory_reads: list[tuple[int, int]] = []
        self.registers = {name: 0 for name in self.arch.regnames}
        self.registers["RIP"] = pc
        self.memory: dict[int, int] = {}

    def read_pc(self) -> int:
        if self.exited:
            raise AssertionError("an exited target has no readable PC")
        return self.pc

    def _accessor(self, regname: str):
        accessor = self.arch.get_reg_accessor(regname)
        assert accessor is not None
        return accessor

    def read_register(self, regname: str) -> int:
        self.register_reads.append(regname)
        accessor = self._accessor(regname)
        value = self.pc if accessor.base_reg == "RIP" else self.registers[accessor.base_reg]
        return (value & accessor.mask) >> accessor.start

    def write_register(self, regname: str, value: int) -> None:
        accessor = self._accessor(regname)
        base_value = self.registers[accessor.base_reg]
        if self.arch.register_write_zero_extends(regname):
            base_value = 0
        base_value = (base_value & ~accessor.mask) | (value << accessor.start & accessor.mask)
        self.registers[accessor.base_reg] = base_value
        if accessor.base_reg == "RIP":
            self.pc = base_value

    def read_flags(self) -> dict[str, int | bool]:
        return x86.decompose_rflags(self.registers["RFLAGS"])

    def read_memory(self, address: int, size: int) -> bytes:
        self.memory_reads.append((address, size))
        return bytes(self.memory.get(address + offset, 0) for offset in range(size))

    def write_memory(self, address: int, value: bytes) -> None:
        for offset, byte in enumerate(value):
            self.memory[address + offset] = byte

    def step(self) -> None:
        self.step_calls += 1
        if not self.steps:
            raise AssertionError("unexpected concrete step")
        destination = self.steps.pop(0)
        if destination is None:
            self.exited = True
            return
        self.pc = destination
        self.registers["RIP"] = destination

    def run(self) -> None:
        self.run_calls += 1
        if self.runs_before_exit:
            self.runs_before_exit -= 1
        else:
            self.exited = True

    def run_until(self, address: int) -> None:
        self.run_until_calls.append(address)
        destination = self.run_results.get(address, address)
        if destination is None:
            self.exited = True
            return
        self.pc = destination
        self.registers["RIP"] = destination

    def is_exited(self) -> bool:
        return self.exited


def speculative(target: ScriptedTarget) -> SpeculativeTracer:
    return SpeculativeTracer(cast(Any, target))


def test_linear_speculation_materializes_and_verifies_the_observed_pc():
    target = ScriptedTarget(run_results={0x1002: 0x1002})
    target.registers["RAX"] = 7
    tracer = speculative(target)

    tracer.speculate(0x1001)
    tracer.speculate(0x1002)

    assert tracer.read_pc() == 0x1002
    assert target.pc == 0x1000
    assert tracer.read_register("rax") == 7
    assert target.run_until_calls == [0x1002]
    assert tracer.read_pc() == 0x1002
    assert tracer.speculative_count == 0


@pytest.mark.parametrize(
    "predictions",
    (
        (0x1001, 0x1002, 0x1000),
        (0x2000, 0x3000, 0x2000),
    ),
)
def test_repeated_pc_materialization_steps_each_predicted_boundary(
    predictions: tuple[int, ...],
):
    target = ScriptedTarget(steps=list(predictions))
    tracer = speculative(target)

    for predicted_pc in predictions:
        tracer.speculate(predicted_pc)

    assert tracer.progress_execution() == predictions[-1]
    assert target.step_calls == len(predictions)
    assert target.run_until_calls == []
    assert tracer.speculative_count == 0


def test_single_step_branch_mismatch_is_reported_and_resets_speculation():
    target = ScriptedTarget(steps=[0x2000])
    tracer = speculative(target)
    tracer.speculate(0x1001)

    with pytest.raises(SpeculativeDivergenceError) as raised:
        tracer.progress_execution()

    assert raised.value.expected == 0x1001
    assert raised.value.actual == 0x2000
    assert tracer.read_pc() == 0x2000
    assert tracer.speculative_count == 0


def test_multi_instruction_branch_mismatch_is_reported_after_run_until():
    target = ScriptedTarget(run_results={0x1002: 0x3000})
    tracer = speculative(target)
    tracer.speculate(0x1001)
    tracer.speculate(0x1002)

    with pytest.raises(SpeculativeDivergenceError) as raised:
        tracer.progress_execution()

    assert raised.value.expected == 0x1002
    assert raised.value.actual == 0x3000
    assert target.run_until_calls == [0x1002]


def test_recorded_syscall_materialization_uses_post_event_breakpoint():
    target = ScriptedTarget(
        steps=[0x1004],
        run_results={0x1002: 0x1002},
    )
    tracer = speculative(target)
    tracer.speculate(0x1002)

    assert tracer.progress_execution(use_breakpoint=True) == 0x1002
    assert target.run_until_calls == [0x1002]
    assert target.step_calls == 0


def test_recorded_syscall_gap_uses_known_post_event_boundary():
    target = ScriptedTarget(
        steps=[0x1004],
        run_results={0x1002: 0x1002},
    )
    tracer = object.__new__(SymbolicTracer)
    tracer.target = speculative(target)

    assert (
        tracer.progress(
            None,
            step=True,
            recorded_syscall_destination=0x1002,
        )
        == 0x1002
    )
    assert target.run_until_calls == [0x1002]
    assert target.step_calls == 0


def test_predicted_exit_is_materialized_before_reporting_exit():
    target = ScriptedTarget(steps=[None])
    tracer = speculative(target)
    tracer.speculate(0)

    assert tracer.is_exited()
    assert tracer.read_pc() == 0
    assert target.step_calls == 1


def test_terminal_syscall_run_to_exit_uses_bounded_continues():
    target = ScriptedTarget(runs_before_exit=1)
    tracer = speculative(target)

    tracer.run_to_exit()

    assert tracer.is_exited()
    assert tracer.read_pc() == 0
    assert target.run_calls == 2
    assert target.step_calls == 0


def test_unknown_destination_step_records_a_concrete_exit():
    target = ScriptedTarget(steps=[None])
    tracer = speculative(target)

    tracer.speculate(None)

    assert tracer.is_exited()
    assert tracer.read_pc() == 0
    assert target.step_calls == 1


def test_native_cross_validation_compares_only_defined_flag_outputs():
    target = ScriptedTarget()
    target.registers["RFLAGS"] = 0x287
    tracer = object.__new__(SymbolicTracer)
    tracer.target = speculative(target)

    class FlagInstruction:
        addr = 0x1000

        def __str__(self) -> str:
            return "BZHI RAX, RDX, RAX"

    instruction = cast(Any, FlagInstruction())
    transform = SymbolicTransform(
        1,
        {
            ExprId("CF", 1): ExprInt(1, 1),
            ExprId("ZF", 1): ExprInt(0, 1),
            ExprId("SF", 1): ExprInt(1, 1),
            ExprId("OF", 1): ExprInt(0, 1),
        },
        [instruction],
        target.arch,
        0x1000,
        0x1005,
    )

    predicted_registers, predicted_memory = tracer.predict_next_state(
        instruction,
        transform,
    )
    assert predicted_registers == {"CF": 1, "ZF": 0, "SF": 1, "OF": 0}
    assert predicted_memory == {}

    # PF changed from one to zero, but BZHI does not define PF.
    target.registers["RFLAGS"] = 0x283
    tracer.validate(
        instruction,
        transform,
        predicted_registers,
        predicted_memory,
    )


def test_native_cross_validation_retains_implicit_zero_extension():
    target = ScriptedTarget()
    target.registers["RAX"] = 0xFFFFFFFFFFFFFFFF
    transform = SymbolicTransform(
        1,
        {ExprId("EAX", 32): ExprInt(5, 32)},
        [],
        target.arch,
        0x1000,
        0x1002,
    )

    assert transform.eval_validation_register_transforms(speculative(target)) == {
        "RAX": 5
    }


def test_xmm_cross_validation_does_not_require_unchanged_zmm_state():
    class XmmOnlyTarget(ScriptedTarget):
        def read_register(self, regname: str) -> int:
            if regname.upper() == "ZMM0":
                raise AssertionError("backend does not expose ZMM0")
            return super().read_register(regname)

    target = XmmOnlyTarget()
    xmm_value = 0x00112233445566778899AABBCCDDEEFF
    transform = SymbolicTransform(
        1,
        {ExprId("XMM0", 128): ExprInt(xmm_value, 128)},
        [],
        target.arch,
        0x1000,
        0x1004,
    )

    predicted = transform.eval_validation_register_transforms(speculative(target))
    assert predicted == {"XMM0": xmm_value}
    assert target.register_reads == []

    target.write_register("XMM0", xmm_value)
    tracer = object.__new__(SymbolicTracer)
    tracer.target = speculative(target)
    tracer.validate(cast(Any, SimpleNamespace(addr=0x1000)), transform, predicted, {})
    assert target.register_reads == ["XMM0"]


def test_memory_write_invalidates_every_overlapping_cached_range():
    target = ScriptedTarget()
    target.write_memory(0x2000, b"abcdef")
    target.write_memory(0x3000, b"keep")
    tracer = speculative(target)

    assert tracer.read_memory(0x2000, 4) == b"abcd"
    assert tracer.read_memory(0x2002, 2) == b"cd"
    assert tracer.read_memory(0x3000, 4) == b"keep"
    assert tracer.read_memory(0x3000, 4) == b"keep"

    tracer.write_memory(0x2001, b"XY")

    assert tracer.read_memory(0x2000, 4) == b"aXYd"
    assert tracer.read_memory(0x2002, 2) == b"Yd"
    assert tracer.read_memory(0x3000, 4) == b"keep"
    assert target.memory_reads.count((0x3000, 4)) == 1
    assert target.memory_reads.count((0x2000, 4)) == 2
    assert target.memory_reads.count((0x2002, 2)) == 2


def test_register_write_invalidates_overlapping_aliases_and_zero_extension():
    target = ScriptedTarget()
    target.registers["RAX"] = 0x1122334455667788
    tracer = speculative(target)

    assert tracer.read_register("RAX") == 0x1122334455667788
    assert tracer.read_register("AL") == 0x88
    tracer.write_register("AL", 0xAA)
    assert tracer.read_register("RAX") == 0x11223344556677AA
    assert tracer.read_register("AL") == 0xAA

    tracer.write_register("EAX", 1)
    assert tracer.read_register("RAX") == 1
    assert target.register_reads.count("RAX") == 3

    tracer.write_register("RIP", 0x4000)
    assert tracer.read_pc() == 0x4000


def event(registers: dict[str, int]) -> Event:
    return Event(0x1000, 1, x86.ArchX86(), registers, [], "fixture")


def test_event_matching_skips_pc_by_name_not_by_numeric_value():
    target = ScriptedTarget()
    target.registers["RAX"] = 0x1000
    target.registers["RBX"] = 7

    assert not match_event(
        event({"rip": 0x1000, "rax": 0x1000, "rbx": 8}),
        speculative(target),
    )
    assert match_event(
        event(
            {
                "rip": 0xDEADBEEF,
                "rax": 0x1000,
                "rbx": 7,
                "xmm0": 0xBAD,
            }
        ),
        speculative(target),
    )


def test_x86_syscall_entry_matching_ignores_hardware_clobbered_rcx_and_r11():
    target = ScriptedTarget(pc=0x401793)
    target.registers.update(
        {
            "RAX": 231,
            "RBX": 7,
            "RCX": 0,
            "R11": 0,
        }
    )
    entering = SyscallEvent(
        0x401793,
        1,
        target.arch,
        {
            "rip": 0x401793,
            "rax": 231,
            "rbx": 7,
            "rcx": 0xFFFFFFFFFFFFFFFF,
            "r11": 0x246,
        },
        (),
        target.arch,
        231,
        "entering",
        False,
    )

    assert match_event(entering, speculative(target))

    mismatched_registers = dict(entering.registers.items())
    mismatched_registers["RBX"] = 8
    mismatched_unaffected = SyscallEvent(
        0x401793,
        1,
        target.arch,
        mismatched_registers,
        (),
        target.arch,
        231,
        "entering",
        False,
    )
    assert not match_event(mismatched_unaffected, speculative(target))

    exiting = SyscallEvent(
        0x401793,
        1,
        target.arch,
        dict(entering.registers.items()),
        (),
        target.arch,
        231,
        "exiting",
        False,
    )
    assert not match_event(exiting, speculative(target))


def test_capture_options_keep_debug_and_cross_validation_independent():
    env = TraceEnvironment("/tmp/oracle", (), (), binary_hash="fixture")
    calls = []
    sentinel = object()

    def factory(actual_env, **kwargs):
        calls.append((actual_env, kwargs))
        return sentinel

    debug_args = make_argparser().parse_args(["--debug", "/tmp/oracle"])
    cross_args = make_argparser().parse_args(["--cross-validate", "/tmp/oracle"])
    profiler = TraceProfiler()

    assert create_symbolic_tracer(debug_args, env, factory) is sentinel
    assert calls[-1][1]["cross_validate"] is False
    assert calls[-1][1]["profiler"] is None
    assert create_symbolic_tracer(cross_args, env, factory, profiler) is sentinel
    assert calls[-1][1]["cross_validate"] is True
    assert calls[-1][1]["profiler"] is profiler


class FakeError:
    def __init__(self, success: bool, message: str = "fixture error"):
        self._success = success
        self._message = message

    def Success(self) -> bool:
        return self._success

    def GetCString(self) -> str:
        return self._message


class FakeBreakpoint:
    def __init__(self, identifier: int = 4, locations: int = 1):
        self.identifier = identifier
        self.locations = locations

    def IsValid(self) -> bool:
        return True

    def GetID(self) -> int:
        return self.identifier

    def GetNumLocations(self) -> int:
        return self.locations


class FakeLLDBTarget:
    def __init__(self, breakpoint: FakeBreakpoint | None = None):
        self.breakpoint = breakpoint or FakeBreakpoint()
        self.deleted: list[int] = []

    def BreakpointCreateByAddress(self, _address: int) -> FakeBreakpoint:
        return self.breakpoint

    def BreakpointDelete(self, identifier: int) -> bool:
        self.deleted.append(identifier)
        return True


class FakeLLDBProcess:
    def __init__(self, state: int, continue_error: FakeError):
        self.state = state
        self.continue_error = continue_error

    def GetState(self) -> int:
        return self.state

    def Continue(self) -> FakeError:
        return self.continue_error


def bare_lldb_target(process: FakeLLDBProcess, target: FakeLLDBTarget) -> LLDBConcreteTarget:
    result = object.__new__(LLDBConcreteTarget)
    result.process = cast(Any, process)
    result.target = cast(Any, target)
    return result


def test_lldb_target_rejects_invalid_debugger_and_process_objects():
    class Valid:
        def IsValid(self) -> bool:
            return True

    class Invalid:
        def IsValid(self) -> bool:
            return False

    base_target_type = LLDBConcreteTarget
    with pytest.raises(ConcreteExecutionError, match="debugger is invalid"):
        base_target_type(cast(Any, Invalid()), cast(Any, Valid()), cast(Any, Valid()))
    with pytest.raises(ConcreteExecutionError, match="process is invalid"):
        base_target_type(cast(Any, Valid()), cast(Any, Valid()), cast(Any, Invalid()))


def test_lldb_remote_initialization_consumes_delayed_stopped_event():
    class Valid:
        def IsValid(self) -> bool:
            return True

    class FakeProcess(Valid):
        state = lldb_module.lldb.eStateUnloaded

        def GetState(self) -> int:
            return self.state

    process = FakeProcess()

    class FakeListener(Valid):
        waits: list[int] = []

        def WaitForEvent(self, timeout: int, _event) -> bool:
            self.waits.append(timeout)
            process.state = lldb_module.lldb.eStateStopped
            return True

    listener = FakeListener()

    class FakeDebugger(Valid):
        def GetCommandInterpreter(self):
            return Valid()

        def GetListener(self):
            return listener

    class FakePlatform(Valid):
        def GetTriple(self) -> str:
            return "x86_64-unknown-linux"

    class FakeTarget(Valid):
        executable = Valid()

        def GetExecutable(self):
            return self.executable

        def FindModule(self, executable):
            assert executable is self.executable
            return Valid()

        def GetPlatform(self):
            return FakePlatform()

    base_target_type = LLDBConcreteTarget
    concrete = base_target_type(
        cast(Any, FakeDebugger()),
        cast(Any, FakeTarget()),
        cast(Any, process),
    )

    assert concrete.process.GetState() == lldb_module.lldb.eStateStopped
    assert listener.waits == [1]


def test_lldb_execution_is_profiled_only_with_explicit_collector(monkeypatch):
    stopped = 77
    monkeypatch.setattr(lldb_module.lldb, "eStateStopped", stopped)
    monkeypatch.setattr(lldb_module.lldb, "eStateExited", 88)
    process = FakeLLDBProcess(stopped, FakeError(True))
    concrete = bare_lldb_target(process, FakeLLDBTarget())
    readings = iter((4.0, 5.25))
    concrete.profiler = TraceProfiler(lambda: next(readings))

    concrete.run()

    assert concrete.profiler.snapshot().concrete_seconds == 1.25


def test_run_until_removes_temporary_breakpoint_on_success(monkeypatch):
    stopped = 77
    monkeypatch.setattr(lldb_module.lldb, "eStateStopped", stopped)
    monkeypatch.setattr(lldb_module.lldb, "eStateExited", 88)
    process = FakeLLDBProcess(stopped, FakeError(True))
    target = FakeLLDBTarget()
    concrete = bare_lldb_target(process, target)
    observed_pcs = iter((0x3000, 0x4000))
    concrete.read_pc = lambda: next(observed_pcs)

    concrete.run_until(0x4000)

    assert target.deleted == [4]


def test_run_until_rejects_unexpected_process_state_and_cleans_up(monkeypatch):
    monkeypatch.setattr(lldb_module.lldb, "eStateStopped", 77)
    monkeypatch.setattr(lldb_module.lldb, "eStateExited", 88)
    process = FakeLLDBProcess(99, FakeError(True))
    target = FakeLLDBTarget()
    concrete = bare_lldb_target(process, target)
    concrete.read_pc = lambda: 0x3000

    with pytest.raises(ConcreteExecutionError, match="unexpected state"):
        concrete.run_until(0x4000)

    assert target.deleted == [4]


def test_unresolved_breakpoint_is_deleted_before_error():
    target = FakeLLDBTarget(FakeBreakpoint(locations=0))
    process = FakeLLDBProcess(77, FakeError(True))
    concrete = bare_lldb_target(process, target)

    with pytest.raises(ConcreteExecutionError, match="no resolved location"):
        concrete._create_address_breakpoint(0x4000)

    assert target.deleted == [4]


def test_run_until_removes_temporary_breakpoint_when_continue_fails(monkeypatch):
    stopped = 77
    monkeypatch.setattr(lldb_module.lldb, "eStateStopped", stopped)
    monkeypatch.setattr(lldb_module.lldb, "eStateExited", 88)
    process = FakeLLDBProcess(stopped, FakeError(False, "continue failed"))
    target = FakeLLDBTarget()
    concrete = bare_lldb_target(process, target)
    concrete.read_pc = lambda: 0x3000

    with pytest.raises(ConcreteExecutionError, match="continue failed"):
        concrete.run_until(0x4000)

    assert target.deleted == [4]


@pytest.mark.parametrize("byteorder", ["little", "big"])
def test_lldb_vector_reads_follow_the_target_byte_order(byteorder):
    value = 0x00112233445566778899AABBCCDDEEFF
    raw = value.to_bytes(16, byteorder=byteorder)

    class VectorData:
        def ReadRawData(self, _error, offset: int, size: int) -> bytes:
            return raw[offset:offset + size]

    class VectorRegister:
        size = 16
        data = VectorData()

        def IsValid(self) -> bool:
            return True

    concrete = object.__new__(LLDBConcreteTarget)
    concrete.arch = aarch64.ArchAArch64(byteorder)
    concrete.archname = "aarch64"
    cast(Any, concrete)._get_register = lambda _name: VectorRegister()

    assert concrete.read_register("V0") == value


def test_lldb_80_bit_register_reads_preserve_all_bytes():
    value = 0x1234567890ABCDEFFEDC
    raw = value.to_bytes(10, byteorder="little")

    class WideData:
        def ReadRawData(self, _error, offset: int, size: int) -> bytes:
            return raw[offset:offset + size]

    class WideRegister:
        size = 10
        data = WideData()

        def IsValid(self) -> bool:
            return True

    concrete = object.__new__(LLDBConcreteTarget)
    concrete.arch = x86.ArchX86()
    concrete.archname = "x86_64"
    cast(Any, concrete)._get_register = lambda _name: WideRegister()

    assert concrete.read_register("ST0") == value


def test_lldb_remote_x86_flags_width_uses_the_eflags_alias():
    class EflagsRegister:
        size = 4

        def IsValid(self) -> bool:
            return True

        def GetValueAsUnsigned(self, _error, _fallback: int) -> int:
            return (1 << 10) | (1 << 21)

    requested: list[str] = []
    concrete = object.__new__(LLDBConcreteTarget)
    concrete.arch = x86.ArchX86()
    concrete.archname = "x86_64"

    def get_register(name: str) -> EflagsRegister:
        requested.append(name)
        return EflagsRegister()

    cast(Any, concrete)._get_register = get_register

    assert concrete.read_register("DF") == 1
    assert concrete.read_flags()["ID"] == 1
    assert requested == ["df", "rflags", "rflags"]


def test_lldb_canonical_rflags_read_zero_extends_eflags_observation():
    value = (1 << 0) | (1 << 6) | (1 << 31)

    class EflagsRegister:
        size = 4

        def IsValid(self) -> bool:
            return True

        def GetValueAsUnsigned(self, _error, _fallback: int) -> int:
            return value

    concrete = object.__new__(LLDBConcreteTarget)
    concrete.arch = x86.ArchX86()
    concrete.archname = "x86_64"
    cast(Any, concrete)._get_register = lambda _name: EflagsRegister()

    assert concrete.read_register("RFLAGS") == value


def test_lldb_canonical_rflags_read_rejects_incomplete_flags_observation():
    class FlagsRegister:
        size = 2

        def IsValid(self) -> bool:
            return True

        def GetValueAsUnsigned(self, _error, _fallback: int) -> int:
            return 0

    concrete = object.__new__(LLDBConcreteTarget)
    concrete.arch = x86.ArchX86()
    concrete.archname = "x86_64"
    cast(Any, concrete)._get_register = lambda _name: FlagsRegister()

    with pytest.raises(ConcreteRegisterError, match="RFLAGS has size 2, expected 8"):
        concrete.read_register("RFLAGS")


def test_lldb_remote_x86_flags_width_rejects_incomplete_flags_alias():
    class FlagsRegister:
        size = 2

        def IsValid(self) -> bool:
            return True

        def GetValueAsUnsigned(self, _error, _fallback: int) -> int:
            return 0

    concrete = object.__new__(LLDBConcreteTarget)
    concrete.arch = x86.ArchX86()
    concrete.archname = "x86_64"
    cast(Any, concrete)._get_register = lambda _name: FlagsRegister()

    with pytest.raises(ConcreteRegisterError, match="RFLAGS has size 2, expected 8"):
        concrete.read_flags()


def test_lldb_scalar_register_errors_do_not_fabricate_zero():
    class FailedRegister:
        size = 8

        def IsValid(self) -> bool:
            return True

        def GetValueAsUnsigned(self, error, _fallback: int) -> int:
            error.SetErrorString("register unavailable")
            return 0

    concrete = object.__new__(LLDBConcreteTarget)
    concrete.arch = x86.ArchX86()
    concrete.archname = "x86_64"
    cast(Any, concrete)._get_register = lambda _name: FailedRegister()

    with pytest.raises(ConcreteRegisterError, match="register unavailable"):
        concrete.read_register("RAX")


def test_lldb_memory_reads_reject_short_successful_results(monkeypatch):
    class ShortProcess:
        def ReadMemory(self, _address: int, _size: int, _error) -> bytes:
            return b"x"

    monkeypatch.setattr(
        lldb_module.lldb,
        "SBError",
        lambda: SimpleNamespace(success=True),
    )
    concrete = object.__new__(LLDBConcreteTarget)
    concrete.process = cast(Any, ShortProcess())

    with pytest.raises(ConcreteMemoryError, match="Short LLDB memory read"):
        concrete.read_memory(0x5000, 2)
