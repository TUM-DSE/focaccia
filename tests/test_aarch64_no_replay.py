"""Little-endian static AArch64 no-replay startup contracts, fake backends only.

Live acceptance additionally needs native AArch64 hardware, authorized LLDB
ptrace, and QEMU Linux-user GDB sockets exposing independent task IDs/TLS.
No native or emulated process is launched by this regression check.
"""
import struct
from types import SimpleNamespace

import pytest

from focaccia.arch.aarch64 import ArchAArch64
from focaccia.arch.arch import ArchitectureKey
from focaccia.completion import TraceCompletion
from focaccia.execution import ExecutionOutcome, ExecutionState
from focaccia.no_replay import (
    ExitAction, ExitScope, NoReplayActionMismatch, NoReplaySetTidBoundary,
    UnsupportedNoReplayAction, describe_no_replay_action,
    no_replay_syscall_opcode, require_exit_only_entry, require_private_tid_storage,
    snapshot_set_tid_inputs, validate_set_tid_transition,
)
from focaccia.snapshot import ProgramState
from focaccia.utils import file_hash


ARCH = ArchAArch64('little')


def static_elf(tmp_path):
    data = bytearray(120)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HH', data, 16, 2, 183)
    struct.pack_into('<QQ', data, 24, 0x1000, 64)
    struct.pack_into('<HH', data, 54, 56, 1)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 6, 0, 0x420000, 0, 0x100, 0x1000, 0x1000)
    path = tmp_path / 'aarch64-static.elf'
    path.write_bytes(data)
    return path


@pytest.mark.parametrize('failure', [None, 'machine', 'endian', 'dynamic', 'entry', 'hash', 'readonly', 'range'])
def test_aarch64_static_entry_and_private_registration(tmp_path, failure):
    path = static_elf(tmp_path)
    data = bytearray(path.read_bytes())
    if failure == 'machine':
        struct.pack_into('<H', data, 18, 62)
    elif failure == 'endian':
        data[5] = 2
    elif failure == 'dynamic':
        struct.pack_into('<I', data, 64, 3)
    elif failure == 'readonly':
        struct.pack_into('<I', data, 68, 4)
    path.write_bytes(data)

    def check():
        require_exit_only_entry(str(path), 'bad' if failure == 'hash' else file_hash(str(path)),
                                0x1004 if failure == 'entry' else 0x1000, ARCH.key)
        require_private_tid_storage(str(path), 0x420ffe if failure == 'range' else 0x420258, ARCH.key)
    if failure:
        with pytest.raises(UnsupportedNoReplayAction):
            check()
    else:
        check()


def tid_states(tid=11399):
    before, after = ProgramState(ARCH), ProgramState(ARCH)
    for state in (before, after):
        for index in range(31):
            state.write_register(f'X{index}', index + 100)
        for name, value in {'PC': 0x1000, 'SP': 0x70001000, 'CPSR': 0x60000000,
                            'TPIDR': 0x420100, 'X0': 0x420258, 'X8': 96}.items():
            state.write_register(name, value)
        state.write_memory(0x420258, b'\x78\x56\x34\x12')
        state.write_memory(0x1000, b'\x01\x00\x00\xd4')
    after.write_register('PC', 0x1004)
    after.write_register('X0', tid)
    return before, after


@pytest.mark.parametrize('corrupt', [None, 'PC', 'X0', 'X1', 'X8', 'X18', 'X30', 'SP', 'CPSR', 'TPIDR', 'memory'])
def test_aarch64_tid_checks_local_context_and_preserved_abi(corrupt):
    before, after = tid_states()
    frozen = snapshot_set_tid_inputs(before)
    if corrupt == 'memory':
        after.write_memory(0x420258, bytes(4))
    elif corrupt:
        after.write_register(corrupt, after.read_register(corrupt) ^ 1)
    if corrupt:
        with pytest.raises(NoReplayActionMismatch):
            validate_set_tid_transition(frozen, after, 11399)
    else:
        assert validate_set_tid_transition(frozen, after, 11399).expected_tid == 11399
        boundary = NoReplaySetTidBoundary(0, describe_no_replay_action(before), 0x420258, 11399)
        assert boundary.descriptor.architecture == ARCH.key


@pytest.mark.parametrize('native_single_step', [False, True])
def test_aarch64_native_captures_svc_tid_and_exit(monkeypatch, tmp_path, native_single_step):
    from focaccia.native import tracer as module
    from focaccia.symbolic import EXECUTION_TID, Instruction, SymbolicTransform
    from focaccia.trace import TraceEnvironment
    before, after = tid_states(1)
    if native_single_step:
        before.write_register('CPSR', before.read_register('CPSR') | (1 << 21))

    class Target:
        arch = ARCH
        process = SimpleNamespace(GetNumThreads=lambda: 1)
        state = before
        exited = False

        def __getattr__(self, name):
            return getattr(self.state, name)

        def is_exited(self):
            return self.exited

        def get_current_tid(self):
            return 1

        def step(self):
            if self.state.read_pc() == 0x1000:
                self.state = after
            elif self.state.read_pc() == 0x1004:
                self.state.write_register('X8', 94)
                self.state.write_register('PC', 0x1008)
            elif self.state.read_pc() == 0x1008:
                self.state.write_register('X0', 0)
                self.state.write_register('PC', 0x100c)
            else:
                pytest.fail('unexpected instruction')

        def run_until(self, pc):
            while self.state.read_pc() != pc:
                self.step()

        def run(self):
            assert self.state.read_pc() == 0x100c
            self.exited = True

        def execution_outcome(self):
            return ExecutionOutcome(ExecutionState.EXITED, exit_status=0)

    after.write_memory(0x100c, b'\x01\x00\x00\xd4')
    target = Target()
    monkeypatch.setattr(module.SymbolicTracer, 'create_debug_target', lambda self: target)
    instructions = {0x1000: 'SVC 0x0', 0x1004: 'MOVZ X8, 0x5E', 0x1008: 'MOVZ X0, 0x0', 0x100c: 'SVC 0x0'}
    monkeypatch.setattr(module, '_disassemble_instruction', lambda ctx, target, pc, cache:
                        Instruction.from_string(instructions[pc], ARCH, pc, 4))
    trace = module.SymbolicTracer(TraceEnvironment(str(static_elf(tmp_path)), (), ()),
                                  whole_program=True, cross_validate=True).trace()
    assert len(trace) == 3
    first = trace[0]
    assert isinstance(first, SymbolicTransform)
    assert first.changed_regs['X0'] == EXECUTION_TID
    assert trace[0].range == (0x1000, 0x1004)
    assert trace.completion is not None
    assert trace.completion.no_replay_exit == ExitAction(0, ExitScope.GROUP)
    assert len(trace.completion.no_replay_set_tid) == 1
    assert trace.completion.no_replay_set_fs == ()


@pytest.mark.parametrize('word', [0xd4000001, 0xd4000021, 0xd4000002, 0xd4200000, 0xd4400000, 0xd503201f])
def test_qemu_guard_rejects_all_aarch64_exception_instructions(monkeypatch, word):
    from test_gdb_program_state import load_target_module
    from focaccia.qemu.syscall import UnsupportedReplayEffect
    module = load_target_module(monkeypatch)
    target = module.GDBServerStateIterator.__new__(module.GDBServerStateIterator)
    state, _ = tid_states()
    state.write_memory(0x1000, word.to_bytes(4, 'little'))
    target.arch = ARCH
    target._no_replay_exit_only = object()
    target.current_state = lambda: state
    if word != 0xd503201f:
        with pytest.raises(UnsupportedReplayEffect):
            target._guard_no_replay_step()
    else:
        target._guard_no_replay_step()


def test_qemu_aarch64_tid_uses_independent_identity(monkeypatch, tmp_path):
    from test_gdb_program_state import load_target_module
    from focaccia.deterministic import DeterministicCursor
    module = load_target_module(monkeypatch)
    before, after = tid_states(999)
    terminal = ProgramState(ARCH)
    terminal.write_register('PC', 0x1010)
    terminal.write_register('X8', 94)
    terminal.write_register('X0', 0)
    boundary = NoReplaySetTidBoundary(0, describe_no_replay_action(before), 0x420258, 11399)
    expected = TraceCompletion(0x1010, 3, 4, ExecutionOutcome(ExecutionState.EXITED, exit_status=0),
                               describe_no_replay_action(terminal), ExitAction(0, ExitScope.GROUP), (), (boundary,))
    target = module.GDBServerStateIterator.__new__(module.GDBServerStateIterator)
    target.arch = ARCH
    target.binary = str(static_elf(tmp_path))
    target._replay = None
    target._events = DeterministicCursor((), module.match_event)
    target._process = SimpleNamespace(threads=lambda: [SimpleNamespace(ptid=(1, 999, 0))])
    target._terminal_reason = None
    target._require_stopped = lambda: None
    target.is_exited = lambda: False
    target.current_state = lambda: before
    breakpoints = []

    class SuccessorBreakpoint:
        def __init__(self, address, *, internal):
            assert address == '*0x1004' and internal is True
            breakpoints.append(self)

        def delete(self):
            breakpoints.remove(self)

    monkeypatch.setattr(module.gdb, 'Breakpoint', SuccessorBreakpoint)

    def resume(command):
        assert command == 'continue' and len(breakpoints) == 1
        target.current_state = lambda: after

    target._resume = resume
    target.enable_no_replay_exit_only(expected)
    target.authorize_no_replay_source(0x1000, 0, 0)
    assert target._execute_no_replay_set_tid() is after
    assert breakpoints == []
    assert target._observed_no_replay_set_tid[0].expected_tid == 999
    assert after.read_register('X0') == 999  # never inject native11399
    terminal.write_memory(0x1010, b'\x01\x00\x00\xd4')
    target.current_state = lambda: terminal
    calls = []
    target.execute_replay_instruction = lambda: calls.append('exit')
    target.execution_outcome = lambda: ExecutionOutcome(ExecutionState.EXITED, exit_status=0)
    observed, action = target.execute_terminal_action(expected, retained_transform_count=3)
    assert calls == ['exit']
    assert action.expected == action.observed == ExitAction(0, ExitScope.GROUP)
    assert observed.no_replay_set_tid[0].expected_tid == 999


def test_qemu_aarch64_tls_uses_explicit_system_register_wire_name(monkeypatch):
    from test_gdb_program_state import load_target_module, FakeInferior, FakeFrame, FakeValue
    from focaccia.snapshot import RegisterAccessError
    module = load_target_module(monkeypatch)
    frame = FakeFrame({'TPIDR_EL0': FakeValue(0x420100, 8)})
    state = module.GDBProgramState(FakeInferior({}), frame, ARCH)
    assert state.read_register('TPIDR') == 0x420100
    assert state.read_register('TPIDR_EL0') == 0x420100
    assert frame.reads == ['TPIDR_EL0']
    missing = module.GDBProgramState(FakeInferior({}), FakeFrame({}), ARCH)
    with pytest.raises(RegisterAccessError):
        missing.read_register('TPIDR')


@pytest.mark.parametrize('base', [0, 0x420100, 0x123456789abcdef0])
def test_aarch64_tls_is_an_ordinary_msr_mrs_state_transition(base):
    from miasm.core.locationdb import LocationDB
    from focaccia.miasm_util import MiasmSymbolResolver
    from focaccia.symbolic import Instruction, SymbolicTransform, run_instruction
    state = ProgramState(ARCH)
    state.write_register('X0', base)
    # MSR TPIDR_EL0,X0 / MRS X1,TPIDR_EL0 (not x86 ARCH_SET_FS).
    for pc, word, register in [(0x1000, 0xd51bd040, 'TPIDR'), (0x1004, 0xd53bd041, 'X1')]:
        instruction = Instruction.from_bytecode(word.to_bytes(4, 'little'), ARCH)
        setattr(instruction.instr, 'offset', pc)
        locations = LocationDB()
        _, outputs = run_instruction(instruction.instr, MiasmSymbolResolver(state, locations),
                                     instruction.machine.lifter(locations))
        transform = SymbolicTransform(1, outputs, [instruction], ARCH, pc, pc + 4)
        predicted = transform.eval_register_transforms(state)
        assert predicted[register] == base
        assert transform.memory_writes == []
        for name, value in predicted.items():
            state.write_register(name, value)
    assert state.read_register('TPIDR_EL0') == base


def test_no_replay_aarch64_big_endian_is_not_implicitly_supported():
    with pytest.raises(UnsupportedNoReplayAction):
        no_replay_syscall_opcode(ArchitectureKey('aarch64', 'big'))
