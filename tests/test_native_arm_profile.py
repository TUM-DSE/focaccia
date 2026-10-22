"""Native ARM TIR profile specialization and fail-closed profile identity."""
import json
import os
import subprocess

import pytest
from miasm.expression.expression import ExprId, ExprInt

from focaccia.tir_backend import decode_response
from focaccia.symbolic import SymbolEvaluationError, UnsupportedInstructionError

PC = 4_194_736


def _oracle():
    executable = os.environ.get("FOCACCIA_TIR_ORACLE")
    if not executable:
        pytest.skip("packaged TIR oracle is not configured")
    return executable


def _response(executable, args, instruction):
    result = subprocess.run(
        [executable, *args], input=f"{PC} {instruction}\n", text=True,
        capture_output=True, check=True, timeout=120,
    )
    return json.loads(result.stdout)


def test_native_dczid_config_specializes_mrs_and_dc_zva():
    oracle = _oracle()
    mrs = _response(oracle, ["--export-transitions", "--dczid-el0", "4"], "e5003bd5")
    assert mrs["profile"] == "aarch64-native-dczid-el0"
    assert mrs["configuration"] == {
        "dczid_el0": "4", "dczva_el0_permitted": True,
    }
    _, outputs = decode_response(json.dumps(mrs), PC, bytes.fromhex("e5003bd5"),
                                 expected_native_config={"dczid_el0": 4})
    assert outputs[ExprId("X5", 64)] == ExprInt(4, 64)

    zva = _response(oracle, ["--export-transitions", "--dczid-el0", "4"], "20740bd5")
    assert zva["profile"] == "aarch64-native-dczid-el0"
    assert zva["configuration"] == {
        "dczid_el0": "4", "dczva_el0_permitted": True,
    }
    _, effects = decode_response(json.dumps(zva), PC, bytes.fromhex("20740bd5"),
                                 expected_native_config={"dczid_el0": 4})
    writes = [(key, value) for key, value in effects.items()
              if key.__class__.__name__ == "ExprMem"]
    assert sum(key.size // 8 for key, _value in writes) == 64
    assert all(value == ExprInt(0, value.size) for _key, value in writes)



def test_scalar_flag_zeros_preserve_existing_qemu_instruction_support():
    instruction = "5f8001f1"
    response = _response(_oracle(), ["--export-transitions"], instruction)
    decode_response(json.dumps(response), PC, bytes.fromhex(instruction))


def test_audited_nop_exports_in_default_and_native_profiles():
    oracle = _oracle()
    instruction = "1f2003d5"
    default = _response(oracle, ["--export-transitions"], instruction)
    _, default_outputs = decode_response(json.dumps(default), PC, bytes.fromhex(instruction))
    assert default_outputs[ExprId("PC", 64)] == ExprInt(PC + 4, 64)

    native = _response(oracle, ["--export-transitions", "--dczid-el0", "4"], instruction)
    _, native_outputs = decode_response(
        json.dumps(native), PC, bytes.fromhex(instruction), expected_native_config={"dczid_el0": 4}
    )
    assert native_outputs[ExprId("PC", 64)] == ExprInt(PC + 4, 64)

    unrelated_hint = _response(oracle, ["--export-transitions"], "7f2003d5")
    assert unrelated_hint["status"] == "unsupported"
    assert "audited NOP fixture" in unrelated_hint["reason"]


@pytest.mark.parametrize("bs", [0, 1, 2, 4, 7, 9])
def test_dczva_dynamic_alignment_exports_configured_blocksize(bs):
    oracle = _oracle()
    dczid = bs  # DZP=0; the profile derives EL0 DZE=1.
    instruction = "20740bd5"
    response = _response(oracle, ["--export-transitions", "--dczid-el0", str(dczid)], instruction)
    _, effects = decode_response(
        json.dumps(response), PC, bytes.fromhex(instruction),
        expected_native_config={"dczid_el0": dczid},
    )
    address = response["memory_writes"][0]["address"]
    assert address["kind"] == "slice" and address["start"] == 0
    aligned = address["value"]
    assert aligned["kind"] == "binary" and aligned["op"] == "and"
    assert aligned["left"] == {"kind": "register", "bits": 64, "name": "X0"}
    assert aligned["right"]["value"] == hex(((1 << 64) - 1) & ~((4 << bs) - 1))
    addresses = [write["address"] for write in response["memory_writes"]]
    chunk_bytes = 256
    expected_offsets = list(range(0, 4 << bs, chunk_bytes))
    assert len(addresses) == len(expected_offsets)
    for offset, chunk_address in zip(expected_offsets, addresses):
        if offset == 0:
            assert chunk_address == address
        else:
            assert chunk_address["kind"] == "binary" and chunk_address["op"] == "add"
            assert chunk_address["left"] == address
            assert chunk_address["right"]["value"] == hex(offset)
    writes = [(key, value) for key, value in effects.items()
              if key.__class__.__name__ == "ExprMem"]
    assert sum(key.size // 8 for key, _value in writes) == 4 << bs
    assert all(value == ExprInt(0, value.size) for _key, value in writes)


def test_maximum_dczid_block_size_nine_is_valid():
    oracle = _oracle()
    mrs = _response(oracle, ["--export-transitions", "--dczid-el0", "9"], "e5003bd5")
    _, outputs = decode_response(
        json.dumps(mrs), PC, bytes.fromhex("e5003bd5"), expected_native_config={"dczid_el0": 9}
    )
    assert outputs[ExprId("X5", 64)] == ExprInt(9, 64)


def test_dczid_dzp_prohibits_dc_zva_fail_closed():
    oracle = _oracle()
    prohibited = _response(oracle, ["--export-transitions", "--dczid-el0", "20"], "20740bd5")
    assert prohibited["configuration"] == {
        "dczid_el0": "20", "dczva_el0_permitted": False,
    }
    with pytest.raises(UnsupportedInstructionError):
        decode_response(json.dumps(prohibited), PC, bytes.fromhex("20740bd5"),
                        expected_native_config={"dczid_el0": 20})


def test_default_profile_remains_qemu_and_native_mismatch_fails_closed():
    oracle = _oracle()
    default = _response(oracle, ["--export-transitions"], "e5003bd5")
    assert default["profile"] == "aarch64-fullspec-el0"
    assert "configuration" not in default
    _, outputs = decode_response(json.dumps(default), PC, bytes.fromhex("e5003bd5"))
    assert outputs[ExprId("X5", 64)] == ExprInt(7, 64)

    native = _response(oracle, ["--export-transitions", "--dczid-el0", "4"], "e5003bd5")
    with pytest.raises(SymbolEvaluationError):
        decode_response(json.dumps(native), PC, bytes.fromhex("e5003bd5"))
    with pytest.raises(SymbolEvaluationError):
        decode_response(json.dumps(native), PC, bytes.fromhex("e5003bd5"),
                        expected_native_config={"dczid_el0": 7})
    with pytest.raises(SymbolEvaluationError, match="expected native configuration"):
        decode_response(json.dumps(native), PC, bytes.fromhex("e5003bd5"),
                        expected_native_config={"dczid_el0": 10})


@pytest.mark.parametrize("value", ["10", "15", "31", "32", "18446744073709551616", "-1", "nope"])
def test_native_dczid_configuration_rejects_invalid_value(value):
    result = subprocess.run(
        [_oracle(), "--export-transitions", "--dczid-el0", value],
        input=f"{PC} e5003bd5\n", text=True, capture_output=True, timeout=120,
    )
    assert result.returncode != 0
