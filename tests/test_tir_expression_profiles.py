"""Source profiles share a decoder without widening its register trust boundary."""

import pytest
from miasm.expression.expression import ExprId

from focaccia.tir_backend import _ExpressionDecoder


def register(name, bits):
    return {"kind": "register", "bits": bits, "name": name}


def definition(identifier, node):
    return {"id": identifier, **node}


def test_explicit_register_contract_supports_intel_and_source_masks():
    decoder = _ExpressionDecoder(
        registers={"RAX": 64, "RFLAGS": 64, "__known_RFLAGS": 64},
        allow_vector_zero_extension=False,
    )
    assert decoder.decode(register("RAX", 64)) == ExprId("RAX", 64)
    assert decoder.decode(register("__known_RFLAGS", 64)) == ExprId("__known_RFLAGS", 64)
    with pytest.raises(ValueError, match="input register"):
        decoder.decode(register("X0", 64))
    with pytest.raises(ValueError, match="width"):
        decoder.decode(register("RFLAGS", 32))


def test_expression_dag_definitions_decode_topologically_and_check_reference_width():
    definitions = [
        definition(0, register("RAX", 64)),
        definition(1, {"kind": "binary", "bits": 64, "op": "add",
            "left": {"kind": "reference", "bits": 64, "id": 0},
            "right": {"kind": "constant", "bits": 64, "value": "0x1"}}),
    ]
    decoder = _ExpressionDecoder(registers={"RAX": 64}, definitions=definitions)
    root = {"kind": "reference", "bits": 64, "id": 1}
    assert decoder.decode(root).size == 64
    with pytest.raises(ValueError, match="reference width"):
        decoder.decode({"kind": "reference", "bits": 32, "id": 0})
    with pytest.raises(ValueError, match="reference id"):
        decoder.decode({"kind": "reference", "bits": 64, "id": 2})


def test_expression_dag_definition_ids_must_match_array_positions():
    with pytest.raises(ValueError, match="ids must match topological order"):
        _ExpressionDecoder(registers={"RAX": 64}, definitions=[
            definition(1, {"kind": "constant", "bits": 64, "value": "0x1"}),
        ])


def test_expression_dag_rejects_forward_and_cyclic_references():
    forward = [
        definition(0, {"kind": "binary", "bits": 64, "op": "add",
            "left": {"kind": "reference", "bits": 64, "id": 1},
            "right": {"kind": "constant", "bits": 64, "value": "0x1"}}),
        definition(1, {"kind": "constant", "bits": 64, "value": "0x1"}),
    ]
    with pytest.raises(ValueError, match="Forward or cyclic"):
        _ExpressionDecoder(registers={"RAX": 64}, definitions=forward)
    with pytest.raises(ValueError, match="Forward or cyclic"):
        _ExpressionDecoder(registers={"RAX": 64}, definitions=[
            definition(0, {"kind": "binary", "bits": 64, "op": "add",
                "left": {"kind": "reference", "bits": 64, "id": 0},
                "right": {"kind": "constant", "bits": 64, "value": "0x1"}}),
        ])


def test_expression_dag_depth_is_larger_than_tree_limit_but_bounded():
    definitions = [definition(0, register("RAX", 64))]
    for index in range(1, 300):
        definitions.append(definition(index, {
            "kind": "binary", "bits": 64, "op": "add",
            "left": {"kind": "reference", "bits": 64, "id": index - 1},
            "right": {"kind": "constant", "bits": 64, "value": "0x1"},
        }))
    expression = _ExpressionDecoder(registers={"RAX": 64}, definitions=definitions).decode(
        {"kind": "reference", "bits": 64, "id": 299})
    from focaccia.arch.x86 import ArchX86
    from focaccia.boundary_oracle import predict
    from focaccia.intel_symbolic import (
        IntelInstructionResidual, IntelPreBoundaryState,
        knownness_inputs_for_observation,
    )
    from miasm.expression.expression import ExprInt

    arch = ArchX86()
    outputs = {"RAX": expression, "RIP": ExprInt(0x1001, 64)}
    masks = {name: ExprInt((1 << expr.size) - 1, expr.size)
             for name, expr in outputs.items()}
    residual = IntelInstructionResidual(0x1000, 1, outputs, masks)
    observed = {name: 0 for name in (
        "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
        "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
        "RIP", "RFLAGS", "FS_BASE", "GS_BASE",
    )}
    observed.update(RIP=0x1000, RAX=7, RFLAGS=0x202)
    observed.update({f"XMM{i}": 0 for i in range(16)})
    state = IntelPreBoundaryState(observed, lambda *_: b"", lambda *_: 0)
    prediction = predict(residual.to_transform(2), state,
        knownness_inputs=knownness_inputs_for_observation(observed), register_names=("RAX",))
    assert prediction.registers["RAX"].value == 306

    too_deep = [definition(0, register("RAX", 64))]
    for index in range(1, 2050):
        too_deep.append(definition(index, {
            "kind": "binary", "bits": 64, "op": "add",
            "left": {"kind": "reference", "bits": 64, "id": index - 1},
            "right": {"kind": "constant", "bits": 64, "value": "0x1"},
        }))
    with pytest.raises(ValueError, match="DAG depth"):
        _ExpressionDecoder(registers={"RAX": 64}, definitions=too_deep)


def test_cached_dag_reference_revalidates_register_and_memory_context():
    known = "__known_RFLAGS"
    with pytest.raises(ValueError, match="through expression reference"):
        _ExpressionDecoder(
            registers={"RAX": 64},
            definitions=[definition(0, register(known, 64))],
            definition_registers={"RAX": 64, known: 64},
        ).decode({"kind": "reference", "bits": 64, "id": 0})
    memory_node = {"kind": "memory_after", "bits": 8, "prefix": 1,
                   "address": {"kind": "constant", "bits": 64, "value": "0x1000"}}
    decoder = _ExpressionDecoder(registers={"RAX": 64}, memory_prefix_limit=1,
                                 definitions=[definition(0, memory_node)],
                                 definition_memory_prefix_limit=1)
    decoder.memory_prefix_limit = 0
    with pytest.raises(ValueError, match="prefix through expression reference"):
        decoder.decode({"kind": "reference", "bits": 8, "id": 0})


def test_default_arm_contract_does_not_accept_intel_inputs():
    decoder = _ExpressionDecoder()
    assert decoder.decode(register("X0", 64)) == ExprId("X0", 64)
    with pytest.raises(ValueError, match="input register"):
        decoder.decode(register("RAX", 64))


def test_register_contract_is_copied_not_response_extensible():
    contract = {"RAX": 64}
    decoder = _ExpressionDecoder(registers=contract)
    contract["surprise"] = 64
    with pytest.raises(ValueError, match="input register"):
        decoder.decode(register("surprise", 64))


def test_source_profile_can_forbid_vector_zero_extension():
    decoder = _ExpressionDecoder(registers={"V0": 128}, allow_vector_zero_extension=False)
    with pytest.raises(ValueError, match="width"):
        decoder.decode(register("V0", 512))


@pytest.mark.parametrize("op,left,right,expected", [
    ("slt", 0xff, 1, 1), ("ult", 0xff, 1, 0),
    ("sle", 0xff, 0xff, 1), ("sgt", 1, 0xff, 1),
    ("sge", 0xff, 1, 0), ("sdiv", 0xf9, 2, 0xfd),
])
def test_signed_scalar_operations_preserve_sign(op, left, right, expected):
    from miasm.expression.simplifications import expr_simp
    from miasm.expression.expression import ExprInt

    node = {"kind": "binary", "op": op, "bits": 8 if op == "sdiv" else 1,
            "left": {"kind": "constant", "bits": 8, "value": hex(left)},
            "right": {"kind": "constant", "bits": 8, "value": hex(right)}}
    result = expr_simp(_ExpressionDecoder().decode(node))
    assert result == ExprInt(expected, node["bits"])


def test_ordered_memory_node_requires_explicit_write_bound():
    node = {"kind": "memory_after", "bits": 16, "prefix": 1,
            "address": {"kind": "constant", "bits": 64, "value": "0x1000"}}
    with pytest.raises(ValueError, match="prefix"):
        _ExpressionDecoder().decode(node)
    with pytest.raises(ValueError, match="prefix"):
        _ExpressionDecoder(memory_prefix_limit=0).decode(node)
    with pytest.raises(ValueError, match="prefix"):
        _ExpressionDecoder(memory_prefix_limit=True)
    from focaccia.arch.x86 import ArchX86
    from focaccia.snapshot import ProgramState
    from focaccia.symbolic import SymbolicTransform
    from miasm.expression.expression import ExprInt, ExprMem

    arch = ArchX86()
    state = ProgramState(arch)
    state.write_memory(0x1000, bytes((0xaa, 0xbb)))
    expression = _ExpressionDecoder(memory_prefix_limit=1).decode(node)
    transform = SymbolicTransform(1, {
        ExprMem(ExprInt(0x1000, 64), 16): ExprInt(0x1122, 16),
        ExprId("RAX", 64): expression.zeroExtend(64),
    }, [], arch, 0, 1)
    assert transform.eval_register_transforms(state)["RAX"] == 0x1122
    node["prefix"] = 0
    original = _ExpressionDecoder(memory_prefix_limit=1).decode(node)
    before = SymbolicTransform(1, {ExprId("RAX", 64): original.zeroExtend(64)}, [], arch, 0, 1)
    assert before.eval_register_transforms(state)["RAX"] == 0xbbaa


@pytest.mark.parametrize("contract", [{"RAX": True}, {"RAX": 0}, {"RAX": 4096}, {"": 64}])
def test_invalid_register_contract_fails_closed(contract):
    with pytest.raises(ValueError, match="register contract"):
        _ExpressionDecoder(registers=contract)
