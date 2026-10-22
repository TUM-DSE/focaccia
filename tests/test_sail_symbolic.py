"""Sail shares the existing source masks, prediction and comparison machinery."""
import json

import pytest

from focaccia.arch.x86 import ArchX86
from focaccia.boundary_oracle import predict, compare
from focaccia.sail_symbolic import PROFILE, decode_sail_residual
from focaccia.snapshot import ReadableProgramState
from focaccia.symbolic import SymbolEvaluationError, UnsupportedInstructionError

MODEL = "a" * 64
PC = 0x400000
CODE = bytes.fromhex("31c0")


def const(bits, value):
    return {"kind": "constant", "bits": bits, "value": hex(value)}


def response():
    return {"schema": 1, "architecture": "x86_64", "profile": PROFILE,
            "source_model_sha256": MODEL, "tir_revision": "b" * 40, "pc": str(PC), "code": CODE.hex(),
            "status": "ok", "length": 2,
            "outputs": {"RIP": const(64, PC + 2), "RAX": const(64, 0)},
            "defined_masks": {"RIP": const(64, (1 << 64) - 1), "RAX": const(64, (1 << 64) - 1)},
            "guards": [], "memory_reads": [], "memory_writes": [],
            "control": {"repeat": const(1, 0), "environment_cutpoint": const(1, 0)},
            "control_masks": {"repeat": const(1, 1), "environment_cutpoint": const(1, 1)}}


def decode(value):
    return decode_sail_residual(json.dumps(value), pc=PC, code=CODE, source_model_sha256=MODEL)


class State(ReadableProgramState):
    def __init__(self):
        super().__init__(ArchX86())

    def read_register(self, reg):
        return {"RIP": PC, "RAX": 17, "RFLAGS": 2}[reg]

    def read_memory(self, addr, size):
        raise AssertionError("Unexpected concrete memory input")


def test_sail_import_uses_shared_source_owned_prediction_and_corruption_comparison():
    residual = decode(response())
    transform = residual.to_transform(1)
    assert transform.source_owned
    prediction = predict(transform, State(), register_names=("RIP", "RAX"),
                         knownness_inputs={"RIP": (1 << 64) - 1, "RAX": (1 << 64) - 1})
    assert compare(prediction, {"RIP": PC + 2, "RAX": 0}, {}).ok
    assert not compare(prediction, {"RIP": PC + 2, "RAX": 1}, {}).ok
    assert not compare(prediction, {"RIP": PC + 3, "RAX": 0}, {}).ok


@pytest.mark.parametrize("field,value", [
    ("source_model_sha256", "b" * 64), ("profile", "intel-usermode-qemu64-v1"),
    ("architecture", "aarch64"), ("pc", str(PC + 1)), ("code", "90"),
    ("schema", True), ("length", True), ("length", 3), ("tir_revision", "unknown"),
])
def test_source_identity_and_length_drift_rejected(field, value):
    source = response()
    source[field] = value
    with pytest.raises(SymbolEvaluationError):
        decode(source)


def test_missing_masks_unknown_registers_and_extra_fields_fail_closed():
    source = response()
    source["defined_masks"].pop("RAX")
    with pytest.raises(SymbolEvaluationError):
        decode(source)
    source = response()
    source["hardware_poststate"] = {"RAX": 0}
    with pytest.raises(SymbolEvaluationError):
        decode(source)
    source = response()
    source["outputs"]["BOGUS"] = const(64, 0)
    source["defined_masks"]["BOGUS"] = const(64, 0)
    with pytest.raises(SymbolEvaluationError):
        decode(source)


def test_source_undefined_masks_survive_without_observation_redefinition():
    source = response()
    source["defined_masks"]["RAX"] = const(64, 0)
    transform = decode(source).to_transform(1)
    prediction = predict(transform, State(), register_names=("RIP", "RAX"),
                         knownness_inputs={"RIP": (1 << 64) - 1, "RAX": (1 << 64) - 1})
    assert prediction.registers["RAX"].mask == 0
    assert compare(prediction, {"RIP": PC + 2, "RAX": 999}, {}).ok


def test_false_source_guard_rejected_before_native_execution():
    source = response()
    source["guards"] = [const(1, 0)]
    with pytest.raises(SymbolEvaluationError):
        predict(decode(source).to_transform(1), State(), register_names=("RIP", "RAX"))


def test_ordered_same_address_writes_and_unused_reads_are_retained():
    source = response()
    for value in (1, 2):
        source["memory_writes"].append({
            "address": const(64, 0x2000), "address_mask": const(64, (1 << 64) - 1),
            "value": const(8, value), "value_mask": const(8, 255), "condition": const(1, 1),
        })
    source["memory_reads"] = [{"address": const(64, 0x2000),
        "address_mask": const(64, (1 << 64) - 1), "bits": 8,
        "condition": const(1, 1), "write_prefix": 1}]
    residual = decode(source)
    assert len(residual.to_transform(1).memory_writes) == 2
    assert residual.read_effects[0].write_prefix == 1
    source["memory_reads"][0]["write_prefix"] = 3
    with pytest.raises(SymbolEvaluationError):
        decode(source)


def test_unsupported_source_reason_cannot_be_interpreted_as_empty_transition():
    source = {name: value for name, value in response().items() if name in {
        "schema", "architecture", "profile", "source_model_sha256", "tir_revision", "pc", "code"}}
    source.update(status="unsupported", reason="x87 is outside qualified semantics")
    with pytest.raises(UnsupportedInstructionError):
        decode(source)


def test_undefined_source_store_is_rejected_before_hardware_memory_can_seed_later_load():
    source = response()
    source["memory_writes"] = [{
        "address": const(64, 0x2000), "address_mask": const(64, (1 << 64) - 1),
        "value": const(8, 0), "value_mask": const(8, 0), "condition": const(1, 1),
    }]
    with pytest.raises(SymbolEvaluationError, match="undefined value"):
        predict(decode(source).to_transform(1), State(), register_names=("RIP", "RAX"))


@pytest.mark.parametrize("control", ["repeat", "environment_cutpoint"])
def test_unqualified_microstep_or_environment_handoff_cannot_enter_complete_step_pipeline(control):
    source = response()
    source["control"][control] = const(1, 1)
    with pytest.raises(SymbolEvaluationError, match="complete source instructions"):
        decode(source)


def test_store_and_read_cannot_see_future_or_self_store_bytes():
    source = response()
    write = {"address": const(64, 0x2000), "address_mask": const(64, (1 << 64) - 1),
             "value": const(8, 1), "value_mask": const(8, 255), "condition": const(1, 1)}
    source["memory_writes"] = [dict(write), dict(write)]
    source["memory_writes"][0]["value"] = {
        "kind": "memory_after", "bits": 8, "address": const(64, 0x2000), "prefix": 1}
    with pytest.raises(SymbolEvaluationError):
        decode(source)
    source["memory_writes"][0] = dict(write)
    source["memory_reads"] = [{
        "address": {"kind": "memory_after", "bits": 64, "address": const(64, 0x2000), "prefix": 1},
        "address_mask": const(64, (1 << 64) - 1), "bits": 8,
        "condition": const(1, 1), "write_prefix": 0,
    }]
    with pytest.raises(SymbolEvaluationError):
        decode(source)


def test_knownness_metadata_cannot_be_used_as_an_architectural_value():
    source = response()
    source["outputs"]["RAX"] = {"kind": "register", "bits": 64, "name": "__focaccia_known_RAX"}
    with pytest.raises(SymbolEvaluationError):
        decode(source)
