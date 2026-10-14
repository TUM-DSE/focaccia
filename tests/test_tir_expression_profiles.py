"""Source profiles share a decoder without widening its register trust boundary."""

import pytest
from miasm.expression.expression import ExprId

from focaccia.tir_backend import _ExpressionDecoder


def register(name, bits):
    return {"kind": "register", "bits": bits, "name": name}


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


@pytest.mark.parametrize("contract", [{"RAX": True}, {"RAX": 0}, {"RAX": 4096}, {"": 64}])
def test_invalid_register_contract_fails_closed(contract):
    with pytest.raises(ValueError, match="register contract"):
        _ExpressionDecoder(registers=contract)
