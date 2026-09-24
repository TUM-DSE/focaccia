"""Exact retained whole-program ELF forms; fixtures are ISA expectations, not live oracles."""
import pytest
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import ExprId, ExprInt, ExprMem

from focaccia.arch.x86 import ArchX86
from focaccia.miasm_util import MiasmSymbolResolver, eval_expr
from focaccia.snapshot import ProgramState
from focaccia.symbolic import (
    Instruction, DisassemblyContext, UnsupportedInstructionError,
    _decode_x86_vmovdqa, run_instruction,
)


@pytest.mark.parametrize('address,hexcode,location,load', [
    (0x401052, 'c5fd6f05a60f0000', 0x402000, True),
    (0x40105a, 'c5fd7f4424c0', 0x7fc0, False),
    (0x401064, 'c5fd7f4424e0', 0x7fe0, False),
    (0x401075, 'c5fd6f4424c0', 0x7fc0, True),
])
def test_actual_elf_aligned_moves(address, hexcode, location, load):
    arch = ArchX86()
    raw = bytes.fromhex(hexcode)
    state = ProgramState(arch)
    state.write_memory(address, raw)
    state.write_register('RIP', address)
    state.write_register('RSP', 0x8000)
    value = int.from_bytes(bytes(range(32)), 'little')
    state.write_register('ZMM0', value | (((1 << 256) - 1) << 256))
    state.write_memory(location, value.to_bytes(32, 'little'))
    setattr(state, 'read_instructions', state.read_memory)
    instruction = DisassemblyContext(state).disassemble(address)
    assert instruction.to_bytecode() == raw
    assert instruction.length == len(raw)
    loc_db = LocationDB()
    resolver = MiasmSymbolResolver(state, loc_db)
    pc, outputs = run_instruction(instruction.instr, resolver, instruction.machine.lifter(loc_db))
    assert pc == ExprInt(address + len(raw), 64)
    if load:
        effect = outputs[ExprId('ZMM0', 512)]
        assert eval_expr(effect, resolver) == ExprInt(value, 512)
    else:
        memory, = [key for key in outputs if isinstance(key, ExprMem)]
        assert memory.size == 256
        assert eval_expr(memory.ptr, resolver) == ExprInt(location, 64)
        effect = outputs[memory]
        assert eval_expr(effect, resolver) == ExprInt(value, 256)
        assert not any(str(key).startswith(('XMM', 'YMM', 'ZMM')) for key in outputs)
    state.write_register('RIP' if len(raw) == 8 else 'RSP',
                         (address if len(raw) == 8 else 0x8000) + 1)
    state.write_memory(location + 1, value.to_bytes(32, 'little'))
    assert not eval_expr(effect, resolver).is_int()


@pytest.mark.parametrize('hexcode', ['c5fd6f05', 'c5fd7f4424', 'c5fd6fc0', 'c5fd7f05a60f0000'])
def test_unsupported_aligned_forms_fail_closed(hexcode):
    with pytest.raises(UnsupportedInstructionError):
        _decode_x86_vmovdqa(bytes.fromhex(hexcode), ArchX86())


@pytest.mark.parametrize('hexcode', ['c5f96f05a60f0000', 'c5fe6f00', 'c4e17d6f00', '62f17d486f00'])
def test_other_widths_prefixes_and_unaligned_move_not_intercepted(hexcode):
    assert _decode_x86_vmovdqa(bytes.fromhex(hexcode), ArchX86()) is None


def test_aligned_move_bytecode_roundtrip():
    raw = bytes.fromhex('c5fd6f05a60f0000')
    assert Instruction.from_bytecode(raw, ArchX86()).to_bytecode() == raw


@pytest.mark.parametrize('failure', ['width', 'length', 'mode', 'operand'])
def test_aligned_move_mutated_instruction_rejected(failure):
    instruction = Instruction.from_bytecode(bytes.fromhex('c5fd6f05a60f0000'), ArchX86())
    if failure == 'width':
        instruction.instr.args[0] = ExprId('XMM0', 128)
    elif failure == 'length':
        setattr(instruction.instr, 'l', 4)
    elif failure == 'mode':
        instruction.instr.mode = 32
    else:
        instruction.instr.args[0] = ExprId('YMM1', 256)
    with pytest.raises(UnsupportedInstructionError):
        instruction.to_bytecode()
    db = LocationDB()
    with pytest.raises(UnsupportedInstructionError):
        run_instruction(instruction.instr, MiasmSymbolResolver(ProgramState(ArchX86()), db),
                        instruction.machine.lifter(db))
