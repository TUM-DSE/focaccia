"""Byte-bound ISA fixtures for the remaining retained whole-program AVX path."""
import pytest
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import ExprId, ExprInt, ExprMem

from focaccia.arch.x86 import ArchX86
from focaccia.miasm_util import MiasmSymbolResolver, eval_expr
from focaccia.snapshot import ProgramState, RegisterAccessError
from focaccia.symbolic import (
    Instruction, DisassemblyContext, UnsupportedInstructionError,
    _decode_x86_avx_logic, run_instruction,
)


def test_complete_retained_vector_body_decodes_and_lifts_to_setne():
    # Static LLDB disassembly of the retained ELF, 0x401052..0x40108e.
    code = bytes.fromhex(
        'c5fd6f05a60f0000 c5fd7f4424c0 c5f9efc0 c5fd7f4424e0 '
        'c5fe6f00 c5fe7f02 c5f877 c5fd6f4424c0 c5fc574424e0 '
        '31c0 c4e27d17c0 c5f877 0f95c0')
    state = ProgramState(ArchX86())
    state.write_memory(0x401052, code)
    state.write_memory(0x402000, bytes(range(32)))
    for name, value in [('RIP', 0x401052), ('RSP', 0x8000), ('RAX', 0x7fc0),
                        ('RDX', 0x7fe0), ('RFLAGS', 0x202)]:
        state.write_register(name, value)
    for n in range(32):
        state.write_register(f'ZMM{n}', (1 << 512) - 1)
    setattr(state, 'read_instructions', state.read_memory)
    context = DisassemblyContext(state)
    pc = 0x401052
    while pc < 0x40108e:
        instruction = context.disassemble(pc)
        resolver = MiasmSymbolResolver(state, context.loc_db)
        next_pc, outputs = run_instruction(instruction.instr, resolver, context.lifter)
        assert next_pc == ExprInt(pc + instruction.length, 64)
        # Evaluate all RHS against the same pre-state before simultaneous writes.
        values = [(key, eval_expr(value, resolver)) for key, value in outputs.items()]
        addresses = {key: eval_expr(key.ptr, resolver) for key in outputs if isinstance(key, ExprMem)}
        for key, value in values:
            assert isinstance(value, ExprInt), (instruction, key, value)
            if isinstance(key, ExprMem):
                address = addresses[key]
                assert isinstance(address, ExprInt)
                state.write_memory(int(address), int(value).to_bytes(key.size // 8, 'little'))
            elif str(key) != 'IRDst':
                state.write_register(str(key), int(value))
        pc += instruction.length
    assert pc == 0x40108e
    assert state.read_register('RAX') == 0
    assert state.read_memory(0x7fe0, 32) == bytes(range(32))
    assert state.read_register('ZMM0') == 0



def execute(raw, state):
    instruction = Instruction.from_bytecode(bytes.fromhex(raw), state.arch)
    db = LocationDB()
    pc, outputs = run_instruction(instruction.instr, MiasmSymbolResolver(state, db),
                                  instruction.machine.lifter(db))
    assert pc == ExprInt(len(bytes.fromhex(raw)), 64)
    resolver = MiasmSymbolResolver(state, db)
    return {str(key): eval_expr(value, resolver) for key, value in outputs.items()}


def test_vpxor_self_clears_all_upper_bits_without_reading_unknown_source():
    state = ProgramState(ArchX86())
    outputs = execute('c5f9efc0', state)
    assert outputs['ZMM0'] == ExprInt(0, 512)
    assert set(outputs) == {'ZMM0', 'RIP', 'IRDst'}


def test_unknown_vector_inputs_are_not_fabricated():
    state = ProgramState(ArchX86())
    state.write_register('RSP', 0x8000)
    with pytest.raises(RegisterAccessError):
        execute('c5f877', state)
    with pytest.raises(RegisterAccessError):
        execute('c4e27d17c0', state)


def test_vzeroupper_preserves_low128_of_all_sixteen_registers_only():
    state = ProgramState(ArchX86())
    for n in range(32):
        state.write_register(f'ZMM{n}', ((1 << 512) - 1) ^ n)
    outputs = execute('c5f877', state)
    assert set(outputs) == {'RIP', 'IRDst'} | {f'ZMM{n}' for n in range(16)}
    for n in range(16):
        assert outputs[f'ZMM{n}'] == ExprInt(((1 << 128) - 1) ^ n, 512)


@pytest.mark.parametrize('stack', [0x8000, 0x8001])
def test_vxorps_exact256_bitwise_unaligned_memory_and_upper_clear(stack):
    state = ProgramState(ArchX86())
    source = int.from_bytes(bytes(range(32)), 'little')
    memory = int.from_bytes(bytes(reversed(range(32))), 'little')
    state.write_register('ZMM0', source | (((1 << 256) - 1) << 256))
    state.write_register('RSP', stack)
    state.write_memory(stack - 32, memory.to_bytes(32, 'little'))
    outputs = execute('c5fc574424e0', state)
    assert outputs['ZMM0'] == ExprInt(source ^ memory, 512)
    assert set(outputs) == {'ZMM0', 'RIP', 'IRDst'}


@pytest.mark.parametrize('value', [0, 1, 1 << 31, 1 << 127, 1 << 128, 1 << 255, (1 << 256) - 1])
def test_vptest_tests_every_bit_and_sets_exact_six_flags(value):
    state = ProgramState(ArchX86())
    state.write_register('YMM0', value)
    outputs = execute('c4e27d17c0', state)
    assert set(outputs) == {'RIP', 'IRDst', 'zf', 'cf', 'of', 'sf', 'af', 'pf'}
    assert outputs['zf'] == ExprInt(int(value == 0), 1)
    assert outputs['cf'] == ExprInt(1, 1)  # (~YMM0 & YMM0) == 0
    for flag in ('of', 'sf', 'af', 'pf'):
        assert outputs[flag] == ExprInt(0, 1)


@pytest.mark.parametrize('raw', [
    'c5fd6f05a60f0000', 'c5fd6f4424c0', 'c5fd7f4424c0', 'c5fd7f4424e0',
    'c5f9efc0', 'c5f877', 'c5fc574424e0', 'c4e27d17c0',
])
def test_project_avx_text_roundtrip(raw):
    decoded = Instruction.from_bytecode(bytes.fromhex(raw), ArchX86())
    reparsed = Instruction.from_string(
        str(decoded.instr), ArchX86(), offset=0, length=decoded.length,
    )
    assert reparsed.to_bytecode() == bytes.fromhex(raw)


@pytest.mark.parametrize('text,length', [
    ('VMOVDQA YMM1, @256[RIP + 0xFAE]', 8),
    ('VMOVDQA YMM0, @128[RIP + 0xFAE]', 8),
    ('VMOVDQA YMM0, @256[RIP + 0x100000008]', 8),
    ('VPXOR XMM1, XMM0, XMM0', 4),
    ('VZEROUPPER', 4),
    ('VXORPS YMM0, YMM0, @256[RSP + 0xFFFFFFFFFFFFFFC0]', 6),
    ('VPTEST YMM0, YMM1', 5),
])
def test_project_avx_text_rejects_wrong_width_operands_or_length(text, length):
    with pytest.raises((ValueError, UnsupportedInstructionError)):
        Instruction.from_string(text, ArchX86(), offset=0, length=length)


@pytest.mark.parametrize('raw', ['c5f9efc0', 'c5f877', 'c5fc574424e0', 'c4e27d17c0'])
def test_actual_avx_bytes_native_context_and_roundtrip(raw):
    state = ProgramState(ArchX86())
    bytecode = bytes.fromhex(raw)
    state.write_memory(0x401060, bytecode)
    setattr(state, 'read_instructions', state.read_memory)
    instruction = DisassemblyContext(state).disassemble(0x401060)
    assert instruction.addr == 0x401060
    assert instruction.length == len(bytecode)
    assert instruction.to_bytecode() == bytecode


@pytest.mark.parametrize('raw', ['c5f9efc1', 'c5fdefc0', 'c5f87700', 'c5fc574424e1', 'c5f8574424e0', 'c4e27917c0', 'c4e27d17c1'])
def test_other_avx_forms_not_intercepted(raw):
    bytecode = bytes.fromhex(raw)
    if raw == 'c5f87700':
        # The following byte is a different instruction, not part of VZEROUPPER.
        instruction = _decode_x86_avx_logic(bytecode, ArchX86())
        assert instruction is not None and instruction.l == 3
    else:
        assert _decode_x86_avx_logic(bytecode, ArchX86()) is None


@pytest.mark.parametrize('raw', ['c5f9efc0', 'c5f877', 'c5fc574424e0', 'c4e27d17c0'])
def test_truncated_avx_forms_and_mutated_operands_reject(raw):
    bytecode = bytes.fromhex(raw)
    assert _decode_x86_avx_logic(bytecode[:-1], ArchX86()) is None
    instruction = Instruction.from_bytecode(bytecode, ArchX86())
    instruction.instr.args = [ExprId('XMM1', 128)]
    with pytest.raises(UnsupportedInstructionError):
        instruction.to_bytecode()
    db = LocationDB()
    with pytest.raises(UnsupportedInstructionError):
        run_instruction(instruction.instr, MiasmSymbolResolver(ProgramState(ArchX86()), db),
                        instruction.machine.lifter(db))
