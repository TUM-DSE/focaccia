"""CC/LO and CS/HS are equivalent encodings, not relaxed branch validation."""
from types import SimpleNamespace
from typing import Any

import pytest
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import ExprId

from focaccia.arch.aarch64 import ArchAArch64
from focaccia.miasm_util import MiasmSymbolResolver
from focaccia.native import tracer
from focaccia.snapshot import ProgramState
from focaccia.symbolic import DisassemblyContext, Instruction, UnsupportedInstructionError, run_instruction


ARCH = ArchAArch64('little')
PC = 0x400530
DEST = 0x400524
RAW = bytes.fromhex('a3ffff54')


@pytest.mark.parametrize('mnemonic,condition', [('B.CC', 3), ('B.LO', 3), ('B.CS', 2), ('B.HS', 2), ('b.lo', 3), ('b.hs', 2)])
@pytest.mark.parametrize('offset', [-1048576, -12, 0, 4, 1048572])
@pytest.mark.parametrize('endianness', ['little', 'big'])
def test_carry_aliases_encode_same_signed_displacement_without_mutating_target(mnemonic, condition, offset, endianness):
    arch = ArchAArch64(endianness)
    instruction = Instruction.from_string(f'{mnemonic} {PC + offset:#x}', arch, PC, 4)
    before_args = tuple(instruction.instr.args)
    expected = 0x54000000 | ((offset // 4 & 0x7ffff) << 5) | condition
    assert instruction.to_bytecode() == expected.to_bytes(4, endianness)
    assert tuple(instruction.instr.args) == before_args
    assert int(instruction.instr.args[0]) == PC + offset


@pytest.mark.parametrize('mnemonic', ['B.CC', 'B.LO', 'B.CS', 'B.HS'])
@pytest.mark.parametrize('carry', [0, 1])
def test_carry_alias_semantics_preserve_condition(mnemonic, carry):
    instruction = Instruction.from_string(f'{mnemonic} {DEST:#x}', ARCH, PC, 4)
    state = ProgramState(ARCH)
    state.write_register('C', carry)
    locations = LocationDB()
    next_pc, _ = run_instruction(instruction.instr, MiasmSymbolResolver(state, locations),
                                  instruction.machine.lifter(locations))
    taken = carry == (0 if mnemonic in ('B.CC', 'B.LO') else 1)
    assert next_pc is not None
    assert int(next_pc) == (DEST if taken else PC + 4)


@pytest.mark.parametrize('offset', [-1048580, 1048576, -2, 2])
def test_bad_carry_branch_displacement_rejects(offset):
    instruction = Instruction.from_string(f'B.LO {PC + offset:#x}', ARCH, PC, 4)
    with pytest.raises(UnsupportedInstructionError):
        instruction.to_bytecode()


@pytest.mark.parametrize('failure', ['mode', 'length', 'operand'])
def test_invalid_carry_branch_mode_or_operand_rejects(failure):
    instruction = Instruction.from_string(f'B.LO {DEST:#x}', ARCH, PC, 4)
    if failure == 'mode':
        instruction.instr.mode = 'b'
    elif failure == 'length':
        instruction.length = 8
    else:
        instruction.instr.args = [ExprId('X0', 64)]
    with pytest.raises(UnsupportedInstructionError):
        instruction.to_bytecode()


def target(raw=RAW, text=f'B.LO {DEST:#x}') -> Any:
    return SimpleNamespace(arch=ARCH, read_instructions=lambda pc, size: raw,
                           get_instruction_size=lambda pc: 4,
                           get_disassembly=lambda pc: text)


def test_actual_backward_branch_decodes_verifies_and_retains_absolute_target():
    state = ProgramState(ARCH)
    state.write_memory(PC, RAW)
    setattr(state, 'read_instructions', state.read_memory)
    ctx = DisassemblyContext(state)
    instruction = tracer._disassemble_instruction(ctx, target(), PC)
    assert instruction.instr.name == 'B.CC'
    assert int(instruction.instr.args[0]) == DEST
    assert instruction.to_bytecode() == RAW


@pytest.mark.parametrize('text,raw', [(f'B.LO {DEST:#x}', RAW),
                                      (f'B.HS {DEST:#x}', bytes.fromhex('a2ffff54')),
                                      (f'B.LO {DEST + 4:#x}', RAW),
                                      (f'B.HS {DEST:#x}', RAW)])
def test_lldb_alias_fallback_requires_exact_target_and_condition(text, raw):
    def no_decode(pc):
        raise ValueError('decoder unavailable')
    ctx: Any = SimpleNamespace(arch=ARCH, disassemble=no_decode)
    if (text, raw) in [(f'B.LO {DEST:#x}', RAW), (f'B.HS {DEST:#x}', bytes.fromhex('a2ffff54'))]:
        assert tracer._disassemble_instruction(ctx, target(raw, text), PC).to_bytecode() == raw
    else:
        with pytest.raises(tracer.DisassemblyError):
            tracer._disassemble_instruction(ctx, target(raw, text), PC)


def test_primary_branch_cannot_pass_on_mnemonic_only():
    instruction = Instruction.from_string(f'B.CC {DEST + 4:#x}', ARCH, PC, 4)
    with pytest.raises(tracer.DisassemblyMismatchError):
        tracer._validate_primary_disassembly(instruction, target(), PC)
    assert tracer._disassembly_mnemonics_compatible('B.CC 0', 'B.LO 0')
    assert tracer._disassembly_mnemonics_compatible('B.CS 0', 'B.HS 0')
    assert not tracer._disassembly_mnemonics_compatible('B.CC 0', 'B.HS 0')
