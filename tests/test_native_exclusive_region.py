import json
import os
import subprocess

import pytest
from miasm.expression.expression import ExprId, ExprInt

from focaccia.arch.aarch64 import ArchAArch64
from focaccia.symbolic import SymbolEvaluationError
from focaccia.tir_backend import TirBackend, decode_region_response


def _request():
    return {
        "schema": 1,
        "entry_pc": str(0x43C540),
        "instructions": [
            {"pc": str(0x43C540), "instruction": "04fc5fc8"},  # LDAXR X4,[X0]
            {"pc": str(0x43C544), "instruction": "9f0005eb"},  # CMP X4,X5
            {"pc": str(0x43C548), "instruction": "a1000054"},  # B.NE comparison-skip
            {"pc": str(0x43C54C), "instruction": "60600b91"},  # ADD X0,X3,#0x2d8
            {"pc": str(0x43C550), "instruction": "02fc04c8"},  # STLXR W4,X2,[X0]
        ],
        "exit_pcs": [str(0x43C554), str(0x43C55C)],
        "max_steps": 5,
    }


def _clrex_request():
    return {
        "schema": 1,
        "entry_pc": str(0x43C540),
        "instructions": [
            {"pc": str(0x43C540), "instruction": "04fc5fc8"},
            {"pc": str(0x43C544), "instruction": "5f3f03d5"},  # CLREX
            {"pc": str(0x43C548), "instruction": "02fc04c8"},  # STLXR after CLREX
        ],
        "exit_pcs": [str(0x43C54C)],
        "max_steps": 3,
    }


def _expr(name, bits):
    return {"bits": bits, "kind": "register", "name": name}


def _response(*, event="none", activation=None):
    request = _request()
    return {
        "schema": 1,
        "architecture": "aarch64",
        "endianness": "little",
        "tir_revision": "a" * 40,
        "profile": "aarch64-fullspec-el0",
        "status": "ok",
        "request": request,
        "entry_pc": request["entry_pc"],
        "first_instruction": request["instructions"][0]["instruction"],
        "outcomes": [{
            "exit_pc": request["exit_pcs"][0],
            "activation": activation or {"bits": 1, "kind": "constant", "value": "0x1"},
            "guards": [{"bits": 1, "kind": "constant", "value": "0x1"}],
            "outputs": {"PC": _expr("PC", 64), "X0": _expr("X0", 64)},
            "memory_reads": [{"address": {"bits": 64, "kind": "constant", "value": "0x2000"}, "bits": 64}],
            "memory_writes": [],
            "monitor_event": event,
        }],
    }


def test_region_decoder_preserves_activation_guards_and_clear_alternative():
    decoded = decode_region_response(json.dumps(_response(event="clear-before-store")), _request())
    assert len(decoded) == 1
    activation, guards, outputs, event, reads, exit_pc = decoded[0]
    assert activation.size == 1 and len(guards) == 1
    assert outputs[ExprId("PC", 64)].size == 64
    assert event == "clear-before-store"
    assert len(reads) == 1 and reads[0][1] == 64
    assert exit_pc == 0x43C554


def test_region_decoder_keeps_false_activation_separate_from_guards():
    response = json.dumps(_response(activation={"bits": 1, "kind": "constant", "value": "0x0"}))
    activation, guards, _, _, _, _ = decode_region_response(response, _request())[0]
    assert activation.size == 1 and len(guards) == 1
    assert str(activation) != str(guards[0])


def test_region_decoder_rejects_identity_mismatch_and_unknown_event():
    response = _response()
    response["request"]["entry_pc"] = "1004"
    with pytest.raises(SymbolEvaluationError):
        decode_region_response(json.dumps(response), _request())
    with pytest.raises(SymbolEvaluationError):
        decode_region_response(json.dumps(_response(event="hardware-post-status")), _request())


@pytest.mark.skipif(not os.environ.get("FOCACCIA_TIR_REGION_ORACLE"), reason="packaged source oracle required")
@pytest.mark.parametrize("instruction", ["04fc5fc8", "02fc04c8", "5f3f03d5"])
def test_standalone_monitor_instructions_require_region(instruction):
    oracle = os.environ["FOCACCIA_TIR_REGION_ORACLE"]
    result = subprocess.run([oracle, "--export-transitions"],
        input=f"{0x43C540} {instruction}\n", capture_output=True, text=True,
        timeout=120, check=True)
    response = json.loads(result.stdout)
    assert response["status"] == "unsupported"
    assert "requires a bounded source region" in response["reason"]


@pytest.mark.skipif(not os.environ.get("FOCACCIA_TIR_REGION_ORACLE"), reason="packaged source oracle required")
def test_real_lua_compare_branch_exclusive_region_has_both_exits_and_paired_effects():
    backend = TirBackend(executable=os.environ["FOCACCIA_TIR_REGION_ORACLE"])
    outcomes = backend.export_region(_request())
    candidates = backend.export_region_transforms(_request(), arch=ArchAArch64("little"))
    assert candidates and all(candidate.transform.source_owned for candidate in candidates)
    assert all(candidate.activation.size == 1 for candidate in candidates)
    assert any(candidate.memory_reads for candidate in candidates)
    assert any(not isinstance(candidate[0], ExprInt) for candidate in outcomes)
    exits = {str(candidate[-1]) for candidate in outcomes}
    assert exits == set(_request()["exit_pcs"])
    skip = [o for o in outcomes if o[-1] == 0x43C55C]
    store = [o for o in outcomes if o[-1] == 0x43C554]
    assert skip and all(not [k for k in o[2] if k.__class__.__name__ == "ExprMem"] for o in skip)
    assert any(o[4] for o in outcomes)  # LDAXR faulting read retained
    assert any([k for k in o[2] if k.__class__.__name__ == "ExprMem"] for o in store)
    assert any(o[3] == "clear-before-store" and not [k for k in o[2] if k.__class__.__name__ == "ExprMem"] for o in store)


@pytest.mark.skipif(not os.environ.get("FOCACCIA_TIR_REGION_ORACLE"), reason="packaged source oracle required")
def test_clrex_region_source_outcome_is_failure_only():
    backend = TirBackend(executable=os.environ["FOCACCIA_TIR_REGION_ORACLE"])
    outcomes = backend.export_region(_clrex_request())
    assert outcomes
    assert all(o[3] == "none" for o in outcomes)
    assert all(not [k for k in o[2] if k.__class__.__name__ == "ExprMem"] for o in outcomes)
