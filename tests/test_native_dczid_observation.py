"""Native MRS observation is hardware-oracle input, never QEMU output inference."""
from types import SimpleNamespace

import pytest
from miasm.expression.expression import ExprId

from focaccia.arch.aarch64 import ArchAArch64
from focaccia.execution import ExecutionOutcome, ExecutionState
from focaccia.native import tracer as module
from focaccia.native.lldb_target import ConcreteRegisterError
from focaccia.no_replay import UnsupportedNoReplayAction
from focaccia.snapshot import ProgramState
from focaccia.symbolic import Instruction, SymbolicTransform
from focaccia.trace import TraceEnvironment
from test_aarch64_no_replay import static_elf


class NativeMrsTarget:
    arch = ArchAArch64('little')

    def __init__(self, value=4, failure=None):
        self.state = ProgramState(self.arch)
        self.process = SimpleNamespace(GetNumThreads=lambda: 1)
        self.exited = False
        self.value = value
        self.failure = failure
        self.steps = []
        self.runs = 0
        self.tid = 71
        for i in range(31):
            self.state.write_register(f'X{i}', i + 100)
        for name, value in {'PC': 0x1000, 'SP': 0x70001000, 'CPSR': 0x60000000}.items():
            self.state.write_register(name, value)
        self.state.write_memory(0x1000, bytes.fromhex('e5003bd5c80b80d2000080d2010000d4'))

    def __getattr__(self, name):
        return getattr(self.state, name)

    def read_register(self, name):
        if name == 'DCZID_EL0':
            raise ConcreteRegisterError('register dczid_el0 not found')
        assert not self.exited, 'post-exit register read'
        return self.state.read_register(name)

    def is_exited(self):
        return self.exited

    def get_current_tid(self):
        return self.tid

    def step(self):
        pc = self.state.read_pc()
        self.steps.append(pc)
        if pc == 0x1000:
            self.state.write_register('X5', self.value)
            if self.failure == 'preserved':
                self.state.write_register('X0', 999)
            elif self.failure == 'exit':
                self.exited = True
            elif self.failure == 'tid':
                self.tid += 1
        elif pc == 0x1004:
            self.state.write_register('X8', 94)
        elif pc == 0x1008:
            self.state.write_register('X0', 0)
        else:
            pytest.fail('unobserved/double native step')
        self.state.write_register('PC', pc + (8 if self.failure == 'pc' else 4))

    def run_until(self, pc):
        while self.state.read_pc() != pc:
            self.step()

    def run(self):
        assert self.state.read_pc() == 0x100c
        self.runs += 1
        self.exited = True

    def execution_outcome(self):
        return ExecutionOutcome(ExecutionState.EXITED, exit_status=0)


def capture(monkeypatch, tmp_path, target, cross_validate=True):
    monkeypatch.setattr(module.SymbolicTracer, 'create_debug_target', lambda self: target)
    words = {0x1000: 0xd53b00e5, 0x1004: 0xd2800bc8, 0x1008: 0xd2800000, 0x100c: 0xd4000001}

    def decode(ctx, target, pc, cache):
        instruction = Instruction.from_bytecode(words[pc].to_bytes(4, 'little'), target.arch)
        instruction.addr = pc
        setattr(instruction.instr, 'offset', pc)
        return instruction

    monkeypatch.setattr(module, '_disassemble_instruction', decode)
    return module.SymbolicTracer(TraceEnvironment(str(static_elf(tmp_path)), (), ()),
                                  whole_program=True, cross_validate=cross_validate)


@pytest.mark.parametrize('cross_validate', [False, True])
@pytest.mark.parametrize('value', [0, 4, 5, 20])
def test_native_mrs_steps_once_keeps_symbolic_environment_and_all_transitions(monkeypatch, tmp_path, cross_validate, value):
    target = NativeMrsTarget(value)
    tracer = capture(monkeypatch, tmp_path, target, cross_validate)
    trace = tracer.trace()
    assert target.steps == [0x1000, 0x1004, 0x1008]
    assert target.runs == 1
    assert len(trace) == 3
    first = trace[0]
    assert isinstance(first, SymbolicTransform)
    assert first.changed_regs['X5'] == ExprId('DCZID_EL0', 64)
    assert trace[0].range == (0x1000, 0x1004)
    assert trace.completion is not None
    assert trace.completion.state_count == 4
    assert tracer.target._native_dczid_observation == (71, value, 0x1000)


@pytest.mark.parametrize('failure', ['preserved', 'pc', 'exit', 'tid', 'reserved'])
def test_native_observation_rejects_bad_boundary_and_effects(monkeypatch, tmp_path, failure):
    target = NativeMrsTarget(32 if failure == 'reserved' else 4, failure)
    tracer = capture(monkeypatch, tmp_path, target)
    with pytest.raises((module.ValidationError, UnsupportedNoReplayAction)):
        tracer.trace()
    assert target.steps == [0x1000]
    assert target.runs == 0
    assert tracer.target._native_dczid_observation is None


@pytest.mark.parametrize('scope', ['remote', 'bounded', 'rr', 'other-register', 'discard'])
def test_native_observation_is_narrow_and_never_steps_unrelated_context(monkeypatch, tmp_path, scope):
    target = NativeMrsTarget()
    tracer = capture(monkeypatch, tmp_path, target)
    if scope == 'remote':
        tracer.remote = 'emulator:1234'
    elif scope == 'bounded':
        tracer.whole_program = False
    elif scope == 'rr':
        setattr(tracer, 'env', SimpleNamespace(detlog=object()))
    word = 0xd53bd045 if scope == 'other-register' else 0xd53b00ff if scope == 'discard' else 0xd53b00e5
    target.state.write_memory(0x1000, word.to_bytes(4, 'little'))
    instruction = Instruction.from_bytecode(word.to_bytes(4, 'little'), target.arch)
    instruction.addr = 0x1000
    setattr(instruction.instr, 'offset', 0x1000)
    if scope == 'discard':
        with pytest.raises(UnsupportedNoReplayAction, match='XZR'):
            tracer._observe_native_dczid_mrs(instruction, 71)
    else:
        assert tracer._observe_native_dczid_mrs(instruction, 71) is None
    assert target.steps == []


def test_changed_native_instruction_rejects_before_execution(monkeypatch, tmp_path):
    target = NativeMrsTarget()
    tracer = capture(monkeypatch, tmp_path, target)
    instruction = Instruction.from_bytecode(bytes.fromhex('e5003bd5'), target.arch)
    instruction.addr = 0x1000
    setattr(instruction.instr, 'offset', 0x1000)
    target.state.write_memory(0x1000, bytes.fromhex('45003bd5'))
    with pytest.raises(module.ValidationError, match='identity changed'):
        tracer._observe_native_dczid_mrs(instruction, 71)
    assert target.steps == []


@pytest.mark.parametrize('prior', [4, 5])
def test_repeated_native_observations_cannot_silently_change_context(monkeypatch, tmp_path, prior):
    target = NativeMrsTarget(4)
    tracer = capture(monkeypatch, tmp_path, target)
    tracer.target._native_dczid_observation = (71, prior, 0xff0)
    instruction = Instruction.from_bytecode(bytes.fromhex('e5003bd5'), target.arch)
    instruction.addr = 0x1000
    setattr(instruction.instr, 'offset', 0x1000)
    if prior != 4:
        with pytest.raises(UnsupportedNoReplayAction, match='context changed'):
            tracer._observe_native_dczid_mrs(instruction, 71)
    else:
        assert tracer._observe_native_dczid_mrs(instruction, 71) is not None
        tracer.target._clear_cache()
        assert tracer.target.read_register('DCZID_EL0') == 4
    assert target.steps == [0x1000]


def test_native_observation_cannot_be_reused_by_other_task(monkeypatch, tmp_path):
    target = NativeMrsTarget()
    tracer = capture(monkeypatch, tmp_path, target)
    tracer.target._native_dczid_observation = (70, 4, 0x1000)
    with pytest.raises(ConcreteRegisterError, match='different task'):
        tracer.target.read_register('DCZID_EL0')
