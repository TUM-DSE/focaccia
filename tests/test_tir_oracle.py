"""Real ASL -> TIR -> Focaccia fixtures, run by the tir-oracle-validation check."""

import json
import os

import pytest

from focaccia.arch.aarch64 import ArchAArch64
from focaccia.compare import compare_symbolic
from focaccia.snapshot import ProgramState
from focaccia.symbolic import (
    DisassemblyContext,
    SymbolicTransform,
    SymbolicTransformComposer,
    UnsupportedInstructionError,
)
from focaccia.tir_backend import TirBackend
from focaccia.trace import TraceEnvironment, TransitionTrace

pytestmark = pytest.mark.integration
ARCH = ArchAArch64("little")
PC = 0x400000
ENV = TraceEnvironment(None, (), (), binary_hash=None, architecture=ARCH.key)
MASK = (1 << 64) - 1


@pytest.fixture(scope="module")
def backend():
    # A missing package is a failure, not a skip or a Miasm fallback.
    return TirBackend(os.environ["FOCACCIA_TIR_ORACLE"])


def state(pc=PC, **registers):
    result = ProgramState(ARCH)
    result.write_register("PC", pc)
    result.write_register("CPSR", 0)
    for name, value in registers.items():
        result.write_register(name, value)
    return result


def transform(backend, code, pc=PC):
    source = state(pc)
    source.write_memory(pc, bytes.fromhex(code))
    context = DisassemblyContext(source)
    instruction = context.disassemble(pc)
    next_pc, outputs = backend.generate(instruction, source, context)
    assert next_pc is not None
    return SymbolicTransform(1, outputs, [instruction], ARCH, pc, int(next_pc))


def test_add_is_parameterized_and_wraps_without_using_miasm_semantics(backend, monkeypatch):
    monkeypatch.setattr(
        "focaccia.semantics.run_instruction", lambda *a: pytest.fail("Miasm semantics used")
    )
    tx = transform(backend, "00040091")  # ADD X0, X0, #1
    assert set(tx.changed_regs) == {"PC", "X0"}
    for value in (0, 1, (1 << 63) - 1, 1 << 63, MASK):
        expected = tx.eval_register_transforms(state(X0=value))
        assert expected == {"PC": PC + 4, "X0": (value + 1) & MASK}
    assert tx.get_used_registers() == ["X0"]
    assert tx.get_used_memory_addresses() == []


def test_subs_flags_roundtrip_and_mismatch_detection(backend):
    tx = transform(backend, "420400f1")  # SUBS X2, X2, #1
    tx = SymbolicTransform.from_json(json.loads(json.dumps(tx.to_json())))
    for value in (0, 1, 2, (1 << 63) - 1, 1 << 63, MASK):
        before = state(X2=value)
        result = (value - 1) & MASK
        expected = {
            "X2": result,
            "N": result >> 63,
            "Z": int(result == 0),
            "C": int(value >= 1),
            "V": int(value == 1 << 63),
            "PC": PC + 4,
        }
        flags = sum(
            expected[name] << bit for name, bit in [("N", 31), ("Z", 30), ("C", 29), ("V", 28)]
        )
        assert tx.eval_register_transforms(before) == {"X2": result, "PC": PC + 4, "CPSR": flags}
        after = state(**expected)
        report = compare_symbolic(TransitionTrace([before, after], [tx], ENV))
        assert len(report) == 1 and report[0]["errors"] == []
        after.write_register("C", expected["C"] ^ 1)
        bad = compare_symbolic(TransitionTrace([before, after], [tx], ENV))
        assert bad[0]["errors"], "wrong carry flag must be detected"


def test_32bit_destination_zero_extends(backend):
    tx = transform(backend, "20040011")  # ADD W0, W1, #1
    before = state(X0=MASK, X1=0x12345678FFFFFFFF)
    assert tx.eval_register_transforms(before)["X0"] == 0


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("subtract", [False, True])
@pytest.mark.parametrize("set_flags", [False, True])
def test_immediate_arithmetic_variants(backend, bits, subtract, set_flags):
    # Architectural encoding fields select the test inputs; expected arithmetic
    # is independent of both TIR and Miasm's instruction-semantic implementations.
    immediate, shift = 4095, 12
    opcode = (
        0x11000000
        | ((bits == 64) << 31)
        | (subtract << 30)
        | (set_flags << 29)
        | (1 << 22)
        | (immediate << 10)
        | (1 << 5)
    )
    tx = transform(backend, opcode.to_bytes(4, "little").hex())
    mask = (1 << bits) - 1
    sign = 1 << (bits - 1)
    operand = immediate << shift
    for input_value in (0, 1, operand - 1, operand, sign - 1, sign, mask):
        full_input = input_value | (0x12345678 << 32) if bits == 32 else input_value
        actual = tx.eval_register_transforms(state(X1=full_input))
        result = (input_value - operand if subtract else input_value + operand) & mask
        assert actual["X0"] == result  # Includes zero-extension for W writes.
        if set_flags:
            overflow = (
                ((input_value ^ operand) if subtract else ~(input_value ^ operand))
                & (input_value ^ result)
                & sign
            )
            carry = input_value >= operand if subtract else input_value + operand > mask
            assert {
                name: (actual["CPSR"] >> bit) & 1
                for name, bit in [("N", 31), ("Z", 30), ("C", 29), ("V", 28)]
            } == {
                "N": int(bool(result & sign)),
                "Z": int(result == 0),
                "C": int(carry),
                "V": int(bool(overflow)),
            }
        else:
            assert set(actual) == {"PC", "X0"}


def test_flag_setting_discard_destination(backend):
    tx = transform(backend, "5f0400f1")  # SUBS XZR, X2, #1 (CMP alias)
    actual = tx.eval_register_transforms(state(X2=1))
    assert actual == {"PC": PC + 4, "CPSR": (1 << 30) | (1 << 29)}


def test_stack_pointer_mapping(backend):
    tx = transform(backend, "ff430091")  # ADD SP, SP, #16
    assert tx.eval_register_transforms(state(SP=0x8000))["SP"] == 0x8010


def test_issue_2248_exact_seven_instruction_chain_is_tir_derived(backend, monkeypatch):
    monkeypatch.setattr(
        "focaccia.semantics.run_instruction", lambda *a: pytest.fail("Miasm semantics used")
    )
    codes = [
        "5f0003eb",  # cmp x2, x3
        "eca79f9a",  # cset x12, lt
        "8b1d0012",  # and w11, w12, #0xff
        "7f010071",  # cmp w11, #0
        "ee039fda",  # csetm x14, ne
        "cd25c49a",  # lsr x13, x14, x4
        "a01d4093",  # sxtb x0, w13
    ]
    transforms = [transform(backend, code, PC + 4 * index) for index, code in enumerate(codes)]
    composer = SymbolicTransformComposer(transforms[0], track_dependencies=True)
    for item in transforms[1:]:
        composer.append(item)
    combined = composer.finish()
    actual = combined.eval_register_transforms(state(X2=0, X3=1, X4=2))
    assert actual == {
        "CPSR": 1 << 29,
        "PC": PC + 28,
        "X0": MASK,
        "X11": 1,
        "X12": 1,
        "X13": 0x3FFFFFFFFFFFFFFF,
        "X14": MASK,
    }
    assert set(combined.get_used_registers()) == {"CPSR", "X2", "X3", "X4"}
    assert combined.get_used_memory_addresses() == []


def test_composition_preserves_dependencies_and_flags(backend):
    first = transform(backend, "420400f1")
    second = transform(backend, "43080091", PC + 4)  # ADD X3, X2, #2
    composer = SymbolicTransformComposer(first, track_dependencies=True)
    composer.append(second)
    combined = composer.finish()
    for value in (0, 1, 1 << 63, MASK):
        result = combined.eval_register_transforms(state(X2=value))
        assert result["X2"] == (value - 1) & MASK
        assert result["X3"] == (value + 1) & MASK
        assert result["PC"] == PC + 8
        assert (result["CPSR"] >> 29) & 1 == int(value >= 1)
    assert "X2" in combined.get_used_registers()
    assert "X3" not in combined.get_used_registers()


@pytest.mark.parametrize("code", ["1f2003d5", "010000d4", "000040f9"])
def test_other_instruction_classes_remain_explicitly_unsupported(backend, code):
    with pytest.raises(UnsupportedInstructionError):
        transform(backend, code)


def test_configuration_memory_cannot_replace_instruction_bytes(backend):
    with pytest.raises(UnsupportedInstructionError, match="configuration memory"):
        transform(backend, "420400f1", 0x1000)
