"""Real ASL -> TIR -> Focaccia fixtures, run by the tir-oracle-validation check."""

import json
import os
from pathlib import Path
import subprocess

from miasm.expression.expression import ExprId
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


@pytest.mark.parametrize(
    ("code", "operation"),
    [
        ("4200c05a", lambda value: int(f"{value:032b}"[::-1], 2)),  # RBIT W2, W2
        ("4210c05a", lambda value: 32 - value.bit_length()),  # CLZ W2, W2
    ],
)
def test_bit_operations_use_exact_asl_residual_and_zero_extend(backend, code, operation):
    tx = transform(backend, code)
    for value in (0, 1, 0x80000000, 0x01234567, 0xFFFFFFFF):
        actual = tx.eval_register_transforms(state(X2=value | (0xA5A5A5A5 << 32)))
        assert actual == {"PC": PC + 4, "X2": operation(value)}


def test_lua_udiv_fixture_uses_exact_asl_transition(backend):
    tx = transform(backend, "4308d79a")  # UDIV X3, X2, X23
    mask = (1 << 64) - 1
    for dividend, divisor in ((0, 0), (7, 3), (mask, 1), (mask, 17)):
        actual = tx.eval_register_transforms(state(X2=dividend, X23=divisor))
        expected = 0 if divisor == 0 else dividend // divisor
        assert actual == {"PC": PC + 4, "X3": expected}


def test_lua_ccmp_register_fixture_uses_exact_asl_transition(backend):
    tx = transform(backend, "621046fa")  # CCMP X3, X6, #2, NE
    assert tx.eval_register_transforms(state(X3=7, X6=3, CPSR=0x40000000)) == {
        "PC": PC + 4, "CPSR": 0x20000000,
    }
    assert tx.eval_register_transforms(state(X3=5, X6=5, CPSR=0)) == {
        "PC": PC + 4, "CPSR": 0x60000000,
    }
    assert tx.eval_register_transforms(state(X3=0, X6=1, CPSR=0)) == {
        "PC": PC + 4, "CPSR": 0x80000000,
    }
    assert tx.eval_register_transforms(state(X3=1 << 63, X6=1, CPSR=0)) == {
        "PC": PC + 4, "CPSR": 0x30000000,
    }


@pytest.mark.parametrize(("code", "left_reg", "right_reg", "output"), [
    ("e07eb39b", "X23", "X19", "X0"),  # UMULL X0, W23, W19
    ("857fba9b", "X28", "X26", "X5"),  # UMULL X5, W28, W26
    ("807fa09b", "X28", "X0", "X0"),   # UMULL X0, W28, W0
])
def test_lua_umull_fixture_uses_exact_asl_transition(
    backend, code, left_reg, right_reg, output
):
    tx = transform(backend, code)
    for left, right in ((0, 0), (1, 2), (0xFFFFFFFF, 0xFFFFFFFF)):
        actual = tx.eval_register_transforms(state(**{left_reg: left, right_reg: right}))
        assert actual == {"PC": PC + 4, output: left * right}


def test_lua_madd_fixture_uses_exact_asl_transition(backend):
    tx = transform(backend, "6010199b")  # MADD X0, X3, X25, X4
    mask = (1 << 64) - 1
    for left, right, addend in ((0, 0, 0), (2, 3, 4), (mask, 2, 7)):
        actual = tx.eval_register_transforms(
            state(X3=left, X25=right, X4=addend)
        )
        assert actual == {"PC": PC + 4, "X0": (left * right + addend) & mask}


def test_lua_mul_fixture_uses_exact_asl_transition(backend):
    tx = transform(backend, "c07e009b")  # MUL X0, X22, X0
    for left, right in ((0, 0), (1, 2), (0xFFFFFFFFFFFFFFFF, 2), (1 << 63, 3)):
        actual = tx.eval_register_transforms(state(X0=right, X22=left))
        assert actual == {"PC": PC + 4, "X0": left * right & ((1 << 64) - 1)}


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


def audited_classes():
    path = Path(__file__).parents[1] / "reproducers/issue-2248-tir/instruction-classes.json"
    document = json.loads(path.read_text())
    assert document["schema"] == 1
    return document["classes"]


def test_every_dynamic_static_musl_instruction_class_is_audited_and_exported(backend):
    fixtures = audited_classes()
    payload = "".join(f"{item['pc']} {item['bytes']}\n" for item in fixtures)
    completed = subprocess.run(
        [backend.executable, "--audit-classes"], input=payload, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=120,
    )
    observed = [line.split(maxsplit=2)[2] for line in completed.stdout.splitlines()]
    assert observed == [item["class"] for item in fixtures]
    assert len(observed) == len(set(observed)) == 32
    for item in fixtures:
        if item["class"] == "decode_aarch64_system_exceptions_runtime_svc":
            with pytest.raises(UnsupportedInstructionError, match="residual helper"):
                transform(backend, item["bytes"], item["pc"])
        else:
            source = state(item["pc"])
            for index in range(31):
                source.write_register(f"X{index}", item["pc"] + 4 if index == 30 else 0)
            source.write_register("SP", 0)
            source.write_memory(item["pc"], bytes.fromhex(item["bytes"]))
            instruction = DisassemblyContext(source).disassemble(item["pc"])
            next_pc, outputs = backend.generate(instruction, source, DisassemblyContext(source))
            assert next_pc is not None and ExprId("PC", 64) in outputs


def test_branch_memory_address_system_vector_and_mul_semantics(backend):
    branch = transform(backend, "01000014", 0x4001D4)  # B 0x4001d8
    assert branch.eval_register_transforms(state(0x4001D4))["PC"] == 0x4001D8

    address = transform(backend, "01000090", 0x4001C8)  # ADRP X1, 0x400000
    assert address.eval_register_transforms(state(0x4001C8))["X1"] == 0x400000

    load = transform(backend, "418440f8", 0x4001E8)  # LDR X1, [X2], #8
    before = state(0x4001E8, X2=0x8000)
    before.write_memory(0x8000, bytes.fromhex("8877665544332211"))
    loaded = load.eval_register_transforms(before)
    assert loaded["X1"] == 0x1122334455667788 and loaded["X2"] == 0x8008

    system = transform(backend, "e5003bd5", 0x402E48)  # MRS X5, DCZID_EL0
    assert system.eval_register_transforms(state(0x402E48))["X5"] == 7

    vector = transform(backend, "200c014e", 0x402DB0)  # DUP V0.16B, W1
    assert vector.eval_register_transforms(state(0x402DB0, X1=0xAB))["V0"] == int.from_bytes(
        bytes([0xAB]) * 16, "little"
    )

    multiply = transform(backend, "417cce9b", 0x40262C)  # UMULH X1, X2, X14
    operands = state(0x40262C, X2=0xFEDCBA9876543210, X14=0x123456789ABCDEF0)
    expected = (operands.read_register("X2") * operands.read_register("X14")) >> 64
    assert multiply.eval_register_transforms(operands)["X1"] == expected


def test_issue_364_ldsmaxb_is_one_atomic_state_transition(backend, monkeypatch):
    monkeypatch.setattr(
        "focaccia.semantics.run_instruction", lambda *a: pytest.fail("Miasm semantics used")
    )
    tx = transform(backend, "20402238")  # ldsmaxb w2, w0, [x1]
    before = state(X1=0x8000, X2=3)
    before.write_memory(0x8000, b"\xff")
    assert tx.eval_register_transforms(before) == {"PC": PC + 4, "X0": 0xFF}
    assert tx.eval_ordered_memory_transforms(before) == ((0x8000, b"\x03"),)
    assert tx.eval_memory_transforms(before) == {0x8000: b"\x03"}
    # The register return and conditional write both consume the same incoming
    # memory state; this is not synthesized as unrelated load/store events.
    reads = tx.get_used_memory_addresses()
    assert reads and {tx.eval_memory_address(read.ptr, before) for read in reads} == {0x8000}


def test_other_atomic_and_ldapr_stlr_opcodes_remain_fail_closed(backend):
    with pytest.raises(UnsupportedInstructionError, match="audited LDSMAXB"):
        transform(backend, "40402138")  # ldsmaxb w1, w0, [x2]
    with pytest.raises(UnsupportedInstructionError, match="audited LDAPUR"):
        transform(backend, "20905fd9")  # ldapur x0, [x1, #-7]


def test_issue_2419_ldapur_uses_signed_address_and_little_endian_data(backend, monkeypatch):
    monkeypatch.setattr(
        "focaccia.semantics.run_instruction", lambda *a: pytest.fail("Miasm semantics used")
    )
    tx = transform(backend, "20805fd9")  # ldapur x0, [x1, #-8]
    before = state(X1=0x8008)
    before.write_memory(0x8000, bytes.fromhex("efbeadde11111111"))
    before.write_memory(0x8200, bytes.fromhex("bebafeca22222222"))
    assert tx.eval_register_transforms(before) == {
        "PC": PC + 4,
        "X0": 0x11111111DEADBEEF,
    }
    reads = tx.get_used_memory_addresses()
    assert len(reads) == 1
    assert tx.eval_memory_address(reads[0].ptr, before) == 0x8000
    assert tx.memory_writes == []


def test_svc_is_deliberately_external_action_not_synthetic_tir_state(backend):
    with pytest.raises(UnsupportedInstructionError, match="residual helper"):
        transform(backend, "010000d4", 0x402F44)
    harness = (Path(__file__).parent / "probes/tir_no_replay_smoke.py").read_text()
    for number in (96, 94):
        assert str(number) in harness
    assert '"synthetic_state_mutation": False' in harness


def test_configuration_memory_cannot_replace_instruction_bytes(backend):
    with pytest.raises(UnsupportedInstructionError, match="configuration memory"):
        transform(backend, "420400f1", 0x1000)
