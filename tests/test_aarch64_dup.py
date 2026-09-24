"""Arm DUP(general) regression for musl memset startup; no live execution.

Arm DUP(general) decode/operation: lowest set imm5[3:0] selects element
size; imm5 higher bits ignored, Q selects64/128 bits; V{64} clears high64.
https://www.scs.stanford.edu/~zyedidia/arm64/dup_advsimd_gen.html
"""
import pytest
from miasm.core.locationdb import LocationDB

from focaccia.arch.aarch64 import ArchAArch64
from focaccia.arch.x86 import ArchX86
from focaccia.miasm_util import MiasmSymbolResolver
from focaccia.snapshot import ProgramState
from focaccia.symbolic import (
    Instruction, SymbolicTransform, DisassemblyContext, UnsupportedInstructionError,
    _decode_aarch64_dup, run_instruction,
)


@pytest.mark.parametrize('width,q', [(8, 0), (8, 1), (16, 0), (16, 1), (32, 0), (32, 1), (64, 1)])
@pytest.mark.parametrize('value', [0, 0x123456789abcdef0, 0xffffffffffffffff])
@pytest.mark.parametrize('source', [1, 31])
def test_dup_general_exact_symbolic_replication_and_upper_clear(width, q, value, source):
    arch = ArchAArch64('little')
    word = 0x0e000c00 | q << 30 | (width // 8) << 16 | source << 5 | 7
    instruction = Instruction.from_bytecode(word.to_bytes(4, 'little'), arch)
    assert instruction.to_bytecode() == word.to_bytes(4, 'little')
    assert Instruction.from_string(str(instruction), arch, length=4).to_bytecode() == instruction.to_bytecode()
    state = ProgramState(arch)
    state.write_register('V7', (1 << 128) - 1)
    if source != 31:
        state.write_register('X1', value)
    locations = LocationDB()
    pc, outputs = run_instruction(instruction.instr, MiasmSymbolResolver(state, locations),
                                   instruction.machine.lifter(locations))
    transform = SymbolicTransform(1, outputs, [instruction], arch, 0, 4)
    element = (value if source != 31 else 0) & ((1 << width) - 1)
    expected = sum(element << shift for shift in range(0, 64 << q, width))
    assert transform.eval_register_transforms(state) == {'V7': expected, 'PC': 4}
    assert pc is not None
    assert int(pc) == 4
    assert transform.memory_writes == []
    assert state.read_register('V7') == (1 << 128) - 1


@pytest.mark.parametrize('imm5', range(32))
@pytest.mark.parametrize('q', [0, 1])
def test_dup_ignored_encoding_bits_and_reserved_sizes(imm5, q):
    word = 0x0e000c20 | q << 30 | imm5 << 16
    if imm5 & 15 == 0 or (imm5 & 15 == 8 and q == 0):
        with pytest.raises(UnsupportedInstructionError):
            Instruction.from_bytecode(word.to_bytes(4, 'little'), ArchAArch64('little'))
    else:
        instruction = Instruction.from_bytecode(word.to_bytes(4, 'little'), ArchAArch64('little'))
        assert instruction.to_bytecode() == word.to_bytes(4, 'little')


@pytest.mark.parametrize('text', ['DUP V0.1D, X1', 'DUP V0.16B, X1', 'DUP V0.2D, W1',
                                 'DUP V32.16B, W1', 'DUP V0.16B, W32', 'DUP V0.16B, W31',
                                 'DUP V0.16B, SP', 'DUP V0.16B, V1.B[0]', 'DUP B0, V1.B[0]',
                                 'DUP Z0.B, W1', 'DUP V0.16B, W1 trailing'])
def test_unimplemented_or_invalid_dup_text_fails_closed(text):
    with pytest.raises(UnsupportedInstructionError):
        Instruction.from_string(text, ArchAArch64('little'), length=4)


@pytest.mark.parametrize('word', [0x4e010420, 0x5e010420, 0x4e083c01, 0xd503201f])
def test_other_vector_and_instruction_classes_are_not_intercepted(word):
    assert _decode_aarch64_dup(word.to_bytes(4, 'little'), ArchAArch64('little')) is None


def test_dup_mode_and_length_are_explicit():
    data = bytes.fromhex('200c014e')
    assert _decode_aarch64_dup(data, ArchX86()) is None
    assert _decode_aarch64_dup(data, ArchAArch64('big')) is None
    assert _decode_aarch64_dup(data[:3], ArchAArch64('little')) is None
    with pytest.raises(UnsupportedInstructionError):
        Instruction.from_string('DUP V0.16B, W1', ArchAArch64('big'), length=4)
    with pytest.raises(UnsupportedInstructionError):
        Instruction.from_string('DUP V0.16B, W1', ArchAArch64('little'), length=8)


@pytest.mark.parametrize('failure', ['instruction-mode', 'length', 'lifter-mode'])
def test_dup_execution_rejects_mismatched_mode_or_length(failure):
    arch = ArchAArch64('little')
    instruction = Instruction.from_string('DUP V0.16B, W1', arch)
    locations = LocationDB()
    lifter = instruction.machine.lifter(locations)
    if failure == 'instruction-mode':
        instruction.instr.mode = 'b'
    elif failure == 'length':
        setattr(instruction.instr, 'l', 8)
    else:
        lifter.attrib = 'b'
    with pytest.raises(UnsupportedInstructionError):
        run_instruction(instruction.instr, MiasmSymbolResolver(ProgramState(arch), locations), lifter)


def test_actual_memset_startup_decodes_without_lldb_or_miasm_fallback():
    state = ProgramState(ArchAArch64('little'))
    state.write_memory(0x400620, bytes.fromhex('200c014e'))
    setattr(state, 'read_instructions', state.read_memory)
    instruction = DisassemblyContext(state).disassemble(0x400620)
    assert str(instruction) == 'DUP V0.16B, W1'
    assert instruction.addr == 0x400620
    assert instruction.length == 4
    assert instruction.to_bytecode() == bytes.fromhex('200c014e')
