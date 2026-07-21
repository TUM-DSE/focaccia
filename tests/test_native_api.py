from typing import cast

import pytest

from focaccia.arch import x86
from focaccia.native import tracer as tracer_module
from focaccia.native.lldb_target import LLDBConcreteTarget
from focaccia.native.tracer import DisassemblyError, SpeculativeTracer, SymbolicTracer
from focaccia.symbolic import DisassemblyContext, Instruction
from focaccia.tools.capture_transforms import make_argparser
from focaccia.trace import TraceEnvironment


class FakeRegister:
    size = 8

    def __init__(self, value: int):
        self.value = value

    def IsValid(self) -> bool:
        return True

    def GetValueAsUnsigned(self) -> int:
        return self.value


def _environment() -> TraceEnvironment:
    return TraceEnvironment(
        "/tmp/oracle",
        ["argument"],
        ["NAME=value"],
        binary_hash="test-hash",
    )


def test_missing_deterministic_log_provides_empty_events():
    assert tracer_module._events_for_environment(_environment()) == []


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
