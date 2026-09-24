"""Pinned-Miasm LDAPUR data semantics, not native or acquire-ordering validation.

Table 2's memory case uses LDAPUR X0, [X1, #-8]. Miasm models this
single-thread load as LDR; its memory-barrier TODO is outside this check.
Big-endian instruction bytes below follow Miasm's aarch64b codec contract,
not a claim that AArch64 BE8 hardware fetches big-endian instructions.
"""

import pytest
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import ExprId, ExprInt

from focaccia.arch.aarch64 import ArchAArch64
from focaccia.miasm_util import MiasmSymbolResolver
from focaccia.snapshot import ProgramState
from focaccia.symbolic import Instruction, SymbolicTransform, run_instruction


@pytest.mark.parametrize("endianness", ["little", "big"])
@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("offset", [-256, -8, -1, 0, 1, 255])
@pytest.mark.parametrize("construction", ["binary", "string"])
def test_ldapur_signed_unscaled_load(endianness, width, offset, construction):
    arch = ArchAArch64(endianness)
    # LDAPUR's signed imm9 occupies bits 20:12; Rn=X1, Rt=W0/X0.
    word = 0x99400020 | ((width == 64) << 30) | ((offset & 0x1FF) << 12)
    bytecode = word.to_bytes(4, endianness)
    register = "X0" if width == 64 else "W0"
    if construction == "binary":
        instruction = Instruction.from_bytecode(bytecode, arch)
    else:
        instruction = Instruction.from_string(
            f"LDAPUR {register}, [X1, {offset}]", arch, offset=0, length=4
        )

    assert instruction.instr.name == "LDAPUR"
    assert instruction.instr.mode == endianness[0]
    assert instruction.addr == 0
    assert instruction.length == 4
    assert instruction.to_bytecode() == bytecode

    state = ProgramState(arch)
    base = 0x2000
    state.write_register("X1", base)
    state.write_register("X0", (1 << 64) - 1)
    # Distinct bytes expose endianness and truncation; the top bit is set
    # for both widths, so W0 must zero-extend rather than sign-extend.
    data = bytes.fromhex("91a2b3c4d5e6f788")[: width // 8]
    state.write_memory(base + offset, data)
    locations = LocationDB()
    next_pc, outputs = run_instruction(
        instruction.instr,
        MiasmSymbolResolver(state, locations),
        instruction.machine.lifter(locations),
    )
    assert next_pc == ExprInt(4, 64)
    assert set(outputs) == {ExprId("X0", 64), ExprId("PC", 64), ExprId("IRDst", 64)}
    transform = SymbolicTransform(1, outputs, [instruction], arch, 0, 4)
    assert transform.eval_register_transforms(state) == {
        "X0": int.from_bytes(data, endianness),
        "PC": 4,
    }
    assert transform.memory_writes == []
    assert state.read_register("X1") == base


@pytest.mark.parametrize("endianness", ["little", "big"])
def test_ldapur_string_preserves_trace_location(endianness):
    instruction = Instruction.from_string(
        "LDAPUR X0, [X1, -8]", ArchAArch64(endianness), offset=0x401000, length=4
    )
    assert instruction.addr == instruction.instr.offset == 0x401000
    assert instruction.length == instruction.instr.l == 4
