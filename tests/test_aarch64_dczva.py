"""Target-specific DCZID and bounded 64-byte DC ZVA, without native execution."""
import pytest
from miasm.core.locationdb import LocationDB
from focaccia.arch.aarch64 import ArchAArch64
from focaccia.miasm_util import MiasmSymbolResolver
from focaccia.snapshot import ProgramState
from focaccia.symbolic import (
    Instruction, SymbolicTransform, SymbolEvaluationError, UnsupportedInstructionError,
    DisassemblyContext, _decode_aarch64_dczva, run_instruction,
)


ARCH = ArchAArch64('little')


def transform(word, state):
    instruction = Instruction.from_bytecode(word.to_bytes(4, 'little'), ARCH)
    locations = LocationDB()
    _, outputs = run_instruction(instruction.instr, MiasmSymbolResolver(state, locations),
                                 instruction.machine.lifter(locations))
    return instruction, SymbolicTransform(1, outputs, [instruction], ARCH, 0, 4)


@pytest.mark.parametrize('value', [0, 4, 5, 16, 20])
def test_mrs_dczid_uses_own_state_not_native_or_analyzer_host(value):
    state = ProgramState(ARCH)
    state.write_register('DCZID_EL0', value)
    _, effect = transform(0xd53b00e5, state)
    assert effect.eval_register_transforms(state)['X5'] == value


@pytest.mark.parametrize('offset', [0, 1, 31, 63])
def test_dczva_aligned_zero_memory_preserves_surrounding_bytes(offset):
    state = ProgramState(ARCH)
    state.write_register('X3', 0x2000 + offset)
    state.write_register('DCZID_EL0', 4)
    state.write_memory(0x1fff, b'\x77' * 66)
    instruction, effect = transform(0xd50b7423, state)
    assert str(instruction) == 'DC ZVA, X3'
    assert instruction.to_bytecode() == bytes.fromhex('23740bd5')
    assert Instruction.from_string(str(instruction), ARCH, length=4).to_bytecode() == instruction.to_bytecode()
    assert effect.eval_memory_transforms(state) == {0x2000: bytes(64)}
    assert effect.eval_register_transforms(state) == {'PC': 4, 'DCZID_EL0': 4}
    assert state.read_memory(0x1fff, 66) == b'\x77' * 66


@pytest.mark.parametrize('value', [0, 3, 5, 16, 20, 36])
def test_dczva_other_size_or_prohibited_context_cannot_become_zero(value):
    native = ProgramState(ARCH)
    native.write_register('X3', 0x2000)
    native.write_register('DCZID_EL0', 4)
    _, effect = transform(0xd50b7423, native)
    emulator = ProgramState(ARCH)
    emulator.write_register('X3', 0x2000)
    emulator.write_register('DCZID_EL0', value)
    with pytest.raises(SymbolEvaluationError):
        effect.eval_memory_transforms(emulator)


@pytest.mark.parametrize('text', ['DC ZVA, X31', 'DC ZVA, X32', 'DC ZVA, SP', 'DC ZVA, W3', 'DC CVAU, X3', 'DC ZVA, X3 trailing'])
def test_dczva_unknown_forms_reject(text):
    with pytest.raises(UnsupportedInstructionError):
        Instruction.from_string(text, ARCH, length=4)


def test_dczva_capability_guard_survives_dead_store_composition():
    from miasm.expression.expression import ExprInt, ExprMem
    from focaccia.symbolic import SymbolicTransformComposer
    state = ProgramState(ARCH)
    state.write_register('X3', 0x2000)
    state.write_register('DCZID_EL0', 4)
    _, effect = transform(0xd50b7423, state)
    later = SymbolicTransform(1, {ExprMem(ExprInt(0x2000, 64), 512): ExprInt(0, 512)}, [], ARCH, 4, 8)
    composer = SymbolicTransformComposer(effect)
    composer.append(later)
    composed = composer.finish()
    state.write_register('DCZID_EL0', 5)
    with pytest.raises(SymbolEvaluationError):
        composed.eval_register_transforms(state)


def test_dczva_mode_length_and_missing_capability_reject():
    from focaccia.snapshot import RegisterAccessError
    for architecture, length in [(ArchAArch64('big'), 4), (ARCH, 8)]:
        with pytest.raises(UnsupportedInstructionError):
            Instruction.from_string('DC ZVA, X3', architecture, length=length)
    assert _decode_aarch64_dczva(bytes.fromhex('23740bd5'), ArchAArch64('big')) is None
    assert _decode_aarch64_dczva(bytes.fromhex('23740b'), ARCH) is None
    assert _decode_aarch64_dczva(bytes.fromhex('237b0bd5'), ARCH) is None
    state = ProgramState(ARCH)
    state.write_register('X3', 0x2000)
    _, effect = transform(0xd50b7423, state)
    with pytest.raises(RegisterAccessError):
        effect.eval_memory_transforms(state)


def test_actual_dczva_disassembly_keeps_instruction_and_location():
    state = ProgramState(ARCH)
    state.write_memory(0x4006e4, bytes.fromhex('23740bd5'))
    setattr(state, 'read_instructions', state.read_memory)
    instruction = DisassemblyContext(state).disassemble(0x4006e4)
    assert str(instruction) == 'DC ZVA, X3'
    assert instruction.addr == 0x4006e4
    assert instruction.length == 4


@pytest.mark.parametrize('value', [4, 5, 20])
def test_native_reads_actual_debugger_register_not_host_constant(monkeypatch, value):
    from test_native_api import LLDBConcreteTarget, FakeRegister
    target = object.__new__(LLDBConcreteTarget)
    target.arch = ARCH
    target.archname = ARCH.archname
    requested = []

    def observed(name):
        requested.append(name)
        return FakeRegister(value)

    monkeypatch.setattr(target, '_get_register', observed)
    assert target.read_register('DCZID_EL0') == value
    assert requested == ['dczid_el0']


def test_qemu_reads_own_explicit_dczid_system_register(monkeypatch):
    from test_gdb_program_state import load_target_module, FakeInferior, FakeFrame, FakeValue
    module = load_target_module(monkeypatch)
    frame = FakeFrame({'DCZID_EL0': FakeValue(5, 8)})
    state = module.GDBProgramState(FakeInferior({}), frame, ARCH)
    assert state.read_register('DCZID_EL0') == 5
    assert frame.reads == ['DCZID_EL0']
