from types import SimpleNamespace
from typing import cast

from focaccia import cli
from focaccia.arch import x86
from focaccia.reproducer import Reproducer
from focaccia.snapshot import ProgramState
from focaccia.symbolic import SymbolicTransform
from focaccia.trace import Trace, TraceEnvironment


def _environment() -> TraceEnvironment:
    return TraceEnvironment(
        "/tmp/oracle",
        ["argument"],
        ["NAME=value"],
        binary_hash="test-hash",
    )


def test_collect_concrete_trace_uses_local_target_factory():
    env = _environment()
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("PC", 0x1000)
    calls = []

    class FakeTarget:
        def __init__(self):
            self.exited = False
            self.breakpoints = []

        def set_breakpoint(self, address: int) -> None:
            self.breakpoints.append(address)

        def is_exited(self) -> bool:
            return self.exited

        def record_snapshot(self) -> ProgramState:
            return snapshot

        def run(self) -> None:
            self.exited = True

    target = FakeTarget()

    def target_factory(binary: str, argv: list[str], envp: list[str]) -> FakeTarget:
        calls.append((binary, argv, envp))
        return target

    result = cli.collect_concrete_trace(env, [0x1000, 0x2000], target_factory)

    assert calls == [(env.binary_name, env.argv, env.envp)]
    assert target.breakpoints == [0x1000, 0x2000]
    assert result == [snapshot]


def test_oracle_program_uses_symbolic_tracer_factory(monkeypatch):
    env = _environment()
    trace = Trace([], [], env)
    calls = []

    class FakeTracer:
        def trace(self) -> Trace[SymbolicTransform]:
            return trace

    def tracer_factory(actual_env: TraceEnvironment) -> FakeTracer:
        calls.append(actual_env)
        return FakeTracer()

    monkeypatch.setattr(cli, "get_truth_env", lambda _args: env)
    args = SimpleNamespace(oracle_program=env.binary_name, oracle_trace=None)

    assert cli.get_symbolic_trace(args, tracer_factory) is trace
    assert calls == [env]


def test_reproducer_uses_local_target_factory():
    snapshot = ProgramState(x86.ArchX86())
    snapshot.write_register("PC", 0x1234)
    calls = []

    class FakeTarget:
        def get_basic_block_inst(self, addr: int) -> list[str]:
            assert addr == 0x1234
            return ["NOP", "RET"]

        def get_symbol_limit(self) -> int:
            return 0x8000

    def target_factory(oracle: str, argv: list[str]) -> FakeTarget:
        calls.append((oracle, argv))
        return FakeTarget()

    symbolic = cast(SymbolicTransform, object())
    reproducer = Reproducer("/tmp/oracle", ["argument"], snapshot, symbolic, target_factory)

    assert calls == [("/tmp/oracle", ["argument"])]
    assert reproducer.bb == ["NOP", "RET"]
    assert reproducer.sl == 0x8000
