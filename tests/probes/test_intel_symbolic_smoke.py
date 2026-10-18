"""Opt-in source-residual simulation for an exact XED ADD form.

Set INTEL_SYMBOLIC_ORACLE once the schema-2 TIR profile wrapper is available.
This test never invokes the concrete source evaluator as an expected-value path.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import sys

import pytest

from focaccia.intel_client import IntelOracle
from focaccia.intel_symbolic import (
    GPR_OUTPUTS, IntelPreBoundaryState, IntelSymbolicBackend,
    knownness_inputs_for_observation,
)
from focaccia.boundary_oracle import predict


pytestmark = pytest.mark.skipif(
    not os.environ.get("INTEL_SYMBOLIC_ORACLE"),
    reason="private Intel symbolic exporter opt-in required",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _decoder_module():
    path = Path(os.environ.get("INTEL_SYMBOLIC_DECODER_MODULE", "../tir/scripts/intel_decode.py"))
    spec = importlib.util.spec_from_file_location("intel_symbolic_smoke_decoder", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load Intel decoder module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _observations(rax: int, rbx: int) -> dict[str, int]:
    values = {name: 0 for name in GPR_OUTPUTS}
    values.update(RAX=rax, RBX=rbx, RIP=0x1000, RFLAGS=0x202,
                  FS_BASE=0, GS_BASE=0)
    values.update({f"XMM{i}": 0 for i in range(16)})
    return values


@pytest.mark.parametrize(
    "left,right,expected_result,expected_flag_bits",
    [
        (4, 3, 7, 0x000),
        ((1 << 64) - 1, 1, 0, 0x055),  # CF|PF|AF|ZF
    ],
)
def test_symbolic_add_residual_on_independent_assignments(
    left, right, expected_result, expected_flag_bits,
):
    oracle_path = os.environ["INTEL_SYMBOLIC_ORACLE"]
    model_path = Path(os.environ.get(
        "INTEL_SYMBOLIC_MODEL", "/tmp/carbonara-usermode-full/typed.json",
    ))
    decoder_bin = Path(os.environ.get(
        "INTEL_SYMBOLIC_DECODER", "/tmp/carbonara-xed/bin/intel-xed-decode",
    ))
    decoder_module = _decoder_module()
    with IntelOracle(oracle_path, model_path, timeout=180) as oracle, \
            decoder_module.Decoder(decoder_bin, timeout=180) as decoder:
        instruction = decoder.decode(0x1000, bytes.fromhex("4801d8"))  # ADD RAX, RBX
        assert instruction.iform.startswith("ADD")
        backend = IntelSymbolicBackend(oracle, _sha256(model_path))
        residual = backend.specialize(instruction)
        transform = residual.to_transform(1)
        observed = _observations(left, right)
        state = IntelPreBoundaryState(
            observed,
            lambda address, size: (_ for _ in ()).throw(
                AssertionError(f"register ADD unexpectedly read memory {address:#x}+{size}")
            ),
            lambda *_: 0,
        )
        prediction = predict(
            transform, state,
            knownness_inputs=knownness_inputs_for_observation(observed),
            register_names=("RAX", "RFLAGS"),
        )
    assert prediction.registers["RAX"].value == expected_result
    required_flags = 0x8D5  # CF, PF, AF, ZF, SF, OF
    flags = prediction.registers["RFLAGS"]
    assert flags.mask & required_flags == required_flags
    assert flags.value & required_flags == expected_flag_bits
