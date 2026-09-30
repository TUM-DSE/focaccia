"""Protocol and failure-boundary tests; no Rust process or native tracing."""

import json
from types import SimpleNamespace

import pytest
from miasm.expression.expression import ExprId, ExprInt

from focaccia.arch.aarch64 import ArchAArch64
from focaccia.arch.x86 import ArchX86
from focaccia.snapshot import ProgramState
from focaccia.symbolic import (
    DisassemblyContext,
    Instruction,
    SymbolEvaluationError,
    UnsupportedInstructionError,
)
from focaccia.tir_backend import TirBackend, decode_response

PC = 0x400000
CODE = bytes.fromhex("00040091")  # add x0, x0, #1
ARCH = ArchAArch64("little")


def constant(bits, value):
    return {"kind": "constant", "bits": bits, "value": hex(value)}


def response():
    return {
        "schema": 1,
        "architecture": "aarch64",
        "endianness": "little",
        "pc": str(PC),
        "instruction": CODE.hex(),
        "tir_revision": "a" * 40,
        "profile": "aarch64-fullspec-el0",
        "status": "ok",
        "outputs": {
            "PC": constant(64, PC + 4),
            "X0": {
                "kind": "binary",
                "bits": 64,
                "op": "add",
                "left": {"kind": "register", "bits": 64, "name": "X0"},
                "right": constant(64, 1),
            },
        },
        "memory_writes": [],
    }


def state_and_instruction(arch=ARCH, code=CODE):
    state = ProgramState(arch)
    state.write_memory(PC, code)
    instruction = Instruction.from_string("ADD X0, X0, 0x1", arch, PC, 4)
    return state, instruction, DisassemblyContext(state)


def test_valid_response_constructs_parameterized_transform():
    next_pc, outputs = decode_response(json.dumps(response()), PC, CODE)
    assert next_pc == ExprInt(PC + 4, 64)
    assert outputs[ExprId("X0", 64)] == ExprId("X0", 64) + ExprInt(1, 64)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", 2),
        ("schema", True),
        ("architecture", "x86_64"),
        ("endianness", "big"),
        ("pc", str(PC + 4)),
        ("instruction", "ffffffff"),
        ("profile", "usermode"),
        ("tir_revision", "unknown"),
        ("status", "success"),
    ],
)
def test_mismatching_protocol_metadata_is_rejected(field, value):
    document = response()
    document[field] = value
    with pytest.raises(SymbolEvaluationError):
        decode_response(json.dumps(document), PC, CODE)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda doc: doc["outputs"].pop("PC"),
        lambda doc: doc["outputs"].update(PC=constant(32, PC + 8)),
        lambda doc: doc["outputs"].update(X0=constant(32, 1)),
        lambda doc: doc["outputs"].update(UNKNOWN=constant(64, 0)),
        lambda doc: doc["outputs"]["X0"].update(op="call"),
        lambda doc: doc["outputs"]["X0"]["left"].update(name="XZR"),
        lambda doc: doc["outputs"]["X0"]["right"].update(value="0x10000000000000000"),
        lambda doc: doc["outputs"]["X0"]["right"].update(bits=True),
        lambda doc: doc["outputs"]["X0"].update(extra="unmodeled effect"),
        lambda doc: doc.update(memory_writes={}),
    ],
)
def test_malformed_or_unmodeled_output_is_rejected(mutate):
    document = response()
    mutate(document)
    with pytest.raises(SymbolEvaluationError):
        decode_response(json.dumps(document), PC, CODE)


@pytest.mark.parametrize("text", ["not json", "[]", '{"schema":1,"schema":1}', "x" * 1_048_577])
def test_invalid_envelope_is_rejected(text):
    with pytest.raises(SymbolEvaluationError):
        decode_response(text, PC, CODE)


def test_unsupported_is_not_a_successful_empty_transform():
    document = response()
    document.pop("outputs")
    document.pop("memory_writes")
    document.update(status="unsupported", reason="memory residual")
    with pytest.raises(UnsupportedInstructionError, match="memory residual"):
        decode_response(json.dumps(document), PC, CODE)


def test_unknown_expression_is_rejected():
    document = response()
    document["outputs"]["X0"] = {"kind": "load", "bits": 64}
    with pytest.raises(SymbolEvaluationError):
        decode_response(json.dumps(document), PC, CODE)


def test_backend_uses_exact_bytes_sanitizes_environment_and_caches(monkeypatch):
    state, instruction, context = state_and_instruction()
    calls = []
    monkeypatch.setenv("TIRAMISU_MODE", "usermode")
    monkeypatch.setenv("TIR_NO_INT_LOWER", "1")
    monkeypatch.setenv("TIR_ASL_AST", "/wrong/ast.json")

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=json.dumps(response()), stderr="")

    monkeypatch.setattr("focaccia.tir_backend.subprocess.run", run)
    backend = TirBackend("fixture-oracle")
    pc, outputs = backend.generate(instruction, state, context)
    assert pc is not None and int(pc) == PC + 4
    outputs.clear()  # Callers cannot mutate the cached transform.
    assert backend.generate(instruction, state, context)[1]
    assert len(calls) == 1
    assert calls[0][0] == ["fixture-oracle", str(PC), CODE.hex()]
    assert not any(k.startswith(("TIR_", "TIRAMISU_")) for k in calls[0][1]["env"])
    state.write_memory(PC, bytes.fromhex("00080091"))
    with pytest.raises(SymbolEvaluationError, match="does not match"):
        backend.generate(instruction, state, context)
    assert len(calls) == 2  # Changed code at the same PC cannot reuse a cache entry.


def test_backend_failure_never_falls_back_to_miasm(monkeypatch):
    state, instruction, context = state_and_instruction()
    monkeypatch.setattr(
        "focaccia.tir_backend.subprocess.run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="oracle failed"),
    )
    monkeypatch.setattr(
        "focaccia.symbolic.run_instruction", lambda *a: pytest.fail("Miasm fallback")
    )
    with pytest.raises(SymbolEvaluationError, match="oracle failed"):
        TirBackend("fixture-oracle").generate(instruction, state, context)


def test_unsupported_architecture_is_rejected_before_launch(monkeypatch):
    state = ProgramState(ArchX86())
    instruction = Instruction.from_string("NOP", state.arch, PC, 1)
    monkeypatch.setattr(
        "focaccia.tir_backend.subprocess.run", lambda *a, **k: pytest.fail("oracle launch")
    )
    with pytest.raises(UnsupportedInstructionError):
        TirBackend().generate(instruction, state, DisassemblyContext(state))


def test_response_depth_is_bounded():
    document = response()
    expression = constant(64, 0)
    for _ in range(66):
        expression = {"kind": "unary", "bits": 64, "op": "not", "value": expression}
    document["outputs"]["X0"] = expression
    with pytest.raises(SymbolEvaluationError, match="depth"):
        decode_response(json.dumps(document), PC, CODE)
