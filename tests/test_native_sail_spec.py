"""Sail adapter tests exercise the existing native source-owned comparator."""
from dataclasses import replace
import hashlib
import json
import os

import pytest

from focaccia.arch.x86 import ArchX86
from focaccia.intel_symbolic import REQUIRED_OUTPUTS, knownness_inputs_for_observation
from focaccia.native.sail_spec import SailNativeOracle
from focaccia.native.spec_validate import (
    NativeSnapshot, SpecValidationError, UnsupportedNativeEvent, _predict_transition, _validate_transition,
)
from focaccia.sail_symbolic import SailOracle
from focaccia.symbolic import SymbolEvaluationError

PC = 0x400000
MODEL = os.environ.get("FOCACCIA_SAIL_MODEL", "")
ORACLE = os.environ.get("FOCACCIA_SAIL_ORACLE", "")


def snapshot(code, **registers):
    values = {name: 0 for name in REQUIRED_OUTPUTS}
    values.update(RIP=PC, RSP=0x2010, RFLAGS=0x202)
    values.update(registers)
    return NativeSnapshot(ArchX86(), values, {PC: code + b"\x90" * 15, 0x2000: bytes(32)},
        ({"start": PC, "end": PC + len(code) + 15, "perms": "r-x", "private": True},
         {"start": 0x2000, "end": 0x2020, "perms": "rw-", "private": True}),
        "full-boundary-memory-diff")


@pytest.mark.parametrize("selection,oracle,model", [("sail", None, None), ("intel", "oracle", None), ("intel", None, "model")])
def test_sail_selection_cannot_silently_select_arm(selection, oracle, model):
    from types import SimpleNamespace
    from focaccia.native.spec_validate import _validate_source_selection, UnsupportedNativeEvent
    args = SimpleNamespace(x86_spec=selection, sail_oracle=oracle, sail_model=model)
    with pytest.raises(UnsupportedNativeEvent, match="x86-64 target"):
        _validate_source_selection(args, "aarch64")


def test_unqualified_or_hash_mismatched_models_rejected_before_process_start(tmp_path, monkeypatch):
    path = tmp_path / "x86.tir"
    path.write_text("untrusted source")
    def no_process(*args, **kwargs):
        raise AssertionError("Unqualified source must be rejected before launch")
    monkeypatch.setattr("subprocess.Popen", no_process)
    with pytest.raises(SymbolEvaluationError, match="provenance"):
        SailOracle("unused", path)
    provenance = {"schema": 1, "architecture": "x86_64", "source": "sail-x86",
                  "undefined_values_preserved": False,
                  "undefined_representation": "sail_undefined_v1",
                  "source_model_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    (tmp_path / "provenance.json").write_text(json.dumps(provenance))
    with pytest.raises(SymbolEvaluationError, match="undefined"):
        SailOracle("unused", path)
    provenance.update(undefined_values_preserved=True, source_model_sha256="0" * 64)
    (tmp_path / "provenance.json").write_text(json.dumps(provenance))
    with pytest.raises(SymbolEvaluationError, match="hash"):
        SailOracle("unused", path)
    provenance.update(source_model_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                      undefined_representation="zero-defaults")
    (tmp_path / "provenance.json").write_text(json.dumps(provenance))
    with pytest.raises(SymbolEvaluationError):
        SailOracle("unused", path)


@pytest.mark.skipif(not (MODEL and ORACLE), reason="requires Nix-built Sail source model and exporter")
@pytest.mark.parametrize("code,inputs,expected", [
    ("31c0", {"RAX": 123}, {"RAX": 0}),
    ("4801d8", {"RAX": 7, "RBX": 8}, {"RAX": 15, "RFLAGS": 0x206}),
    ("4801d8", {"RAX": (1 << 64) - 1, "RBX": 1}, {"RAX": 0, "RFLAGS": 0x257}),
    ("4801d8", {"RAX": (1 << 63) - 1, "RBX": 1}, {"RAX": 1 << 63, "RFLAGS": 0xA96}),
    ("488b03", {"RBX": 0x2000}, {"RAX": 0}),
    ("488903", {"RAX": 7, "RBX": 0x2000}, {}),
    ("eb02", {}, {"RIP": PC + 4}),
    ("7202", {"RFLAGS": 0x203}, {"RIP": PC + 4}),
    ("7202", {"RFLAGS": 0x202}, {"RIP": PC + 2}),
])
def test_real_sail_source_uses_native_shared_prediction_and_rejects_corruption(code, inputs, expected):
    before = snapshot(bytes.fromhex(code), **inputs)
    oracle = SailNativeOracle(MODEL, ORACLE)
    try:
        transform = oracle(before)
        assert transform.source_owned
        prediction = _predict_transition(transform, before, oracle.knownness_inputs)
        for name, value in expected.items():
            assert prediction.registers[name].value == value
        if code == "31c0":
            assert prediction.registers["RFLAGS"].mask == ((1 << 64) - 1) ^ 0x10
        post_regs = dict(before.registers)
        for name, item in prediction.registers.items():
            post_regs[name] = (post_regs.get(name, 0) & ~item.mask) | (item.value & item.mask)
        memory = {base: bytearray(data) for base, data in before.memory.items()}
        for address, data in prediction.memory.items():
            for offset, value in enumerate(data):
                for base, region in memory.items():
                    if base <= address + offset < base + len(region):
                        region[address + offset - base] = value
                        break
        after = replace(before, registers=post_regs,
                        memory={base: bytes(data) for base, data in memory.items()})
        _validate_transition(transform, before, after, prediction)
        for register in ("RIP", "R12"):
            corrupted = replace(after, registers={**after.registers, register: after.registers[register] ^ 1})
            with pytest.raises(SpecValidationError, match="mismatch"):
                _validate_transition(transform, before, corrupted, prediction)
        changed = {**after.memory, 0x2000: after.memory[0x2000][:-1] + b"\xff"}
        with pytest.raises(SpecValidationError):
            _validate_transition(transform, before, replace(after, memory=changed), prediction)
    finally:
        oracle.close()


@pytest.mark.skipif(not (MODEL and ORACLE), reason="requires Nix-built Sail source model and exporter")
def test_real_sail_residuals_compose_store_then_load_in_shared_composer():
    from types import SimpleNamespace
    from focaccia.sail_symbolic import SailSymbolicBackend
    from focaccia.intel_symbolic import compose_intel_residuals
    before = snapshot(bytes.fromhex("488903488b0b"), RAX=7, RBX=0x2000)
    oracle = SailOracle(ORACLE, MODEL)
    try:
        backend = SailSymbolicBackend(oracle)
        residuals = [backend.specialize(SimpleNamespace(pc=PC, code=bytes.fromhex("488903"))),
                     backend.specialize(SimpleNamespace(pc=PC + 3, code=bytes.fromhex("488b0b")))]
        composed = compose_intel_residuals(residuals, 1)
        prediction = _predict_transition(composed, before, knownness_inputs_for_observation(before.registers))
        assert prediction.registers["RCX"].value == 7
        assert prediction.registers["RIP"].value == PC + 6
        assert prediction.memory[0x2000] == (7).to_bytes(8, "little")
    finally:
        oracle.close()


@pytest.mark.skipif(not (MODEL and ORACLE), reason="requires Nix-built Sail source model and exporter")
def test_real_sail_backend_uses_existing_live_tb_predictor_without_another_execution_path():
    from types import SimpleNamespace
    from focaccia.sail_symbolic import SailSymbolicBackend
    from focaccia.intel_symbolic import SymbolicIntelLiveModel
    from focaccia.native.intel_spec import _SnapshotTransport
    before = snapshot(bytes.fromhex("488903488b0b"), RAX=7, RBX=0x2000)

    class ExactBoundaries:
        def decode(self, pc, code):
            # Independent fixture boundaries only; semantics still come from
            # the real Sail fetch/step and must certify these exact lengths.
            expected = {PC: bytes.fromhex("488903"), PC + 3: bytes.fromhex("488b0b")}[pc]
            assert code.startswith(expected)
            return SimpleNamespace(pc=pc, code=expected, iform="SAIL_TEST_BOUNDARY")

    oracle = SailOracle(ORACLE, MODEL)
    try:
        live = SymbolicIntelLiveModel(SailSymbolicBackend(oracle), ExactBoundaries(),
                                      _SnapshotTransport(before), 1)
        live.boundary(before.registers)
        prediction = live.predict(SimpleNamespace(size=2, pc=PC, address=PC + 3))
        assert prediction.registers["RCX"].value == 7
        assert prediction.registers["RIP"].value == PC + 6
        assert prediction.memory[0x2000] == (7).to_bytes(8, "little")
        assert live.instructions == 2
        assert not live.environment_cutpoint
    finally:
        oracle.close()


@pytest.mark.skipif(not (MODEL and ORACLE), reason="requires Nix-built Sail source model and exporter")
def test_real_sail_undefined_flag_stays_unknown_when_consumed_by_next_instruction():
    from types import SimpleNamespace
    from focaccia.sail_symbolic import SailSymbolicBackend
    from focaccia.intel_symbolic import compose_intel_residuals
    before = snapshot(bytes.fromhex("31c09f"), RAX=123)
    oracle = SailOracle(ORACLE, MODEL)
    try:
        backend = SailSymbolicBackend(oracle)
        residuals = [backend.specialize(SimpleNamespace(pc=PC, code=bytes.fromhex("31c0"))),
                     backend.specialize(SimpleNamespace(pc=PC + 2, code=bytes.fromhex("9f")))]
        prediction = _predict_transition(compose_intel_residuals(residuals, 1), before,
                                         knownness_inputs_for_observation(before.registers))
        # XOR leaves AF undefined; LAHF transfers it to AH bit 4 (RAX bit 12).
        assert prediction.registers["RAX"].mask == ((1 << 64) - 1) ^ 0x1000
        assert prediction.registers["RAX"].value & ~0x1000 == 0x4600
    finally:
        oracle.close()


@pytest.mark.skipif(not (MODEL and ORACLE), reason="requires Nix-built Sail source model and exporter")
def test_real_sail_read_permissions_and_undefined_control_fail_before_execution():
    oracle = SailNativeOracle(MODEL, ORACLE)
    try:
        for unsupported in ("d9e8", "0f05", "0f34", "cd80"):
            # x87 and kernel/ABI handoffs must not masquerade as ordinary
            # complete source steps that could execute outside the OS policy.
            with pytest.raises(UnsupportedNativeEvent, match="Sail source rejected"):
                oracle(snapshot(bytes.fromhex(unsupported)))
        with pytest.raises((SpecValidationError, SymbolEvaluationError)):
            oracle(snapshot(bytes.fromhex("488b03"), RBX=0x3000))
        incompatible = snapshot(bytes.fromhex("4801d8"), RFLAGS=2)
        candidate = oracle(incompatible)
        with pytest.raises(SymbolEvaluationError, match="guard"):
            _predict_transition(candidate, incompatible, oracle.knownness_inputs)
        before = snapshot(bytes.fromhex("7202"))
        oracle.set_knownness_inputs(knownness_inputs_for_observation(before.registers))
        assert oracle.knownness_inputs is not None
        oracle.knownness_inputs["RFLAGS"] = 0
        with pytest.raises((SpecValidationError, SymbolEvaluationError)):
            oracle(before)
    finally:
        oracle.close()
