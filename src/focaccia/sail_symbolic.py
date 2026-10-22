"""Sail x86 residual ingestion into the shared source-owned symbolic pipeline.

This module implements no instruction semantics. Source predictions are built
only from immutable instruction bytes, model identity, and symbolic inputs.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re

from miasm.expression.expression import ExprInt

from .intel_client import IntelOracle, IntelOracleError
from .intel_symbolic import (
    IntelInstructionResidual, IntelOrderedEffect, IntelReadEffect,
    _REGISTER_CONTRACT, _KNOWNNESS_REGISTER_CONTRACT,
)
from .symbolic import SymbolEvaluationError, UnsupportedInstructionError
from .tir_backend import _ExpressionDecoder

PROFILE = "sail-x86-usermode-v1"
MAX_RESPONSE = 16 * 1024 * 1024


def _pairs(items):
    result = {}
    for name, value in items:
        if name in result:
            raise ValueError(f"Duplicate Sail response key {name!r}")
        result[name] = value
    return result


def _fields(value, names):
    if not isinstance(value, dict) or set(value) != set(names):
        raise ValueError("Unexpected Sail residual fields")


def decode_sail_residual(text: str, *, pc: int, code: bytes,
                         source_model_sha256: str, tir_revision: str | None = None) -> IntelInstructionResidual:
    """Import x86 source values into the same residual type as the Intel source.

    The existing name of that type does not select Intel instruction semantics:
    it is the x86 architecture/mask/ordered-effect contract shared by sources.
    """
    try:
        if (len(text) > MAX_RESPONSE or type(pc) is not int or not 0 <= pc < 1 << 64
                or not isinstance(code, bytes) or not 1 <= len(code) <= 15
                or re.fullmatch(r"[0-9a-f]{64}", source_model_sha256) is None):
            raise ValueError("Invalid bounded Sail request identity")
        response = json.loads(text, object_pairs_hook=_pairs)
        common = {"schema", "architecture", "profile", "source_model_sha256", "tir_revision", "pc", "code", "status"}
        if not isinstance(response, dict):
            raise ValueError("Sail response is not an object")
        if (type(response.get("schema")) is not int or response["schema"] != 1
                or response.get("architecture") != "x86_64"
                or response.get("profile") != PROFILE
                or response.get("source_model_sha256") != source_model_sha256
                or not isinstance(response.get("tir_revision"), str)
                or re.fullmatch(r"[0-9a-f]{40}", response["tir_revision"]) is None
                or (tir_revision is not None and response["tir_revision"] != tir_revision)
                or response.get("pc") != str(pc) or response.get("code") != code.hex()):
            raise ValueError("Sail residual source/architecture/PC/code identity mismatch")
        if response.get("status") == "unsupported":
            _fields(response, common | {"reason"})
            reason = response["reason"]
            if not isinstance(reason, str) or not 1 <= len(reason) <= 4096:
                raise ValueError("Malformed Sail unsupported diagnostic")
            raise UnsupportedInstructionError(f"Sail source: {reason}")
        _fields(response, common | {"length", "outputs", "defined_masks", "guards", "memory_reads", "memory_writes", "control", "control_masks"})
        if response["status"] != "ok":
            raise ValueError("Invalid Sail response status")
        length = response["length"]
        if type(length) is not int or not 1 <= length <= len(code):
            raise ValueError("Invalid Sail instruction length")
        writes = response["memory_writes"]
        reads = response["memory_reads"]
        guards = response["guards"]
        if (not isinstance(writes, list) or len(writes) > 4096
                or not isinstance(reads, list) or len(reads) > 4096
                or not isinstance(guards, list) or len(guards) > 4096):
            raise ValueError("Sail effect/guard budget exceeded")
        decoder = _ExpressionDecoder(
            registers={**_REGISTER_CONTRACT, **_KNOWNNESS_REGISTER_CONTRACT},
            allow_vector_zero_extension=False, memory_prefix_limit=len(writes),
        )
        values, masks = response["outputs"], response["defined_masks"]
        if (not isinstance(values, dict) or not values or not isinstance(masks, dict)
                or set(values) != set(masks) or not set(values) <= set(_REGISTER_CONTRACT)
                or "RIP" not in values):
            raise ValueError("Sail outputs require exact register/mask coverage and RIP")
        def expression(node, prefix, *, mask=False):
            decoder.registers = ({**_REGISTER_CONTRACT, **_KNOWNNESS_REGISTER_CONTRACT}
                                 if mask else _REGISTER_CONTRACT)
            decoder.memory_prefix_limit = prefix
            return decoder.decode(node)

        outputs = {name: expression(value, len(writes)) for name, value in values.items()}
        defined = {name: expression(value, len(writes), mask=True) for name, value in masks.items()}
        effects = []
        for ordinal, item in enumerate(writes):
            _fields(item, {"address", "value", "address_mask", "value_mask", "condition"})
            effects.append(IntelOrderedEffect(
                expression(item["address"], ordinal), expression(item["value"], ordinal),
                expression(item["address_mask"], ordinal, mask=True),
                expression(item["value_mask"], ordinal, mask=True),
                expression(item["condition"], ordinal, mask=True),
            ))
        read_effects = []
        for item in reads:
            _fields(item, {"address", "bits", "condition", "address_mask", "write_prefix"})
            bits = item["bits"]
            prefix = item["write_prefix"]
            if (type(bits) is not int or bits <= 0 or bits % 8
                    or type(prefix) is not int or not 0 <= prefix <= len(writes)):
                raise ValueError("Invalid Sail source read width/prefix")
            read_effects.append(IntelReadEffect(
                expression(item["address"], prefix), expression(item["address_mask"], prefix, mask=True),
                bits // 8, expression(item["condition"], prefix, mask=True), prefix,
            ))
        _fields(response["control"], {"repeat", "environment_cutpoint"})
        _fields(response["control_masks"], {"repeat", "environment_cutpoint"})
        controls = {name: expression(value, len(writes)) for name, value in response["control"].items()}
        control_masks = {name: expression(value, len(writes), mask=True)
                         for name, value in response["control_masks"].items()}
        if (any(value != ExprInt(0, 1) for value in controls.values())
                or any(value != ExprInt(1, 1) for value in control_masks.values())):
            raise ValueError("Sail profile admits complete source instructions only")
        return IntelInstructionResidual(pc, length, outputs, defined,
            tuple(expression(guard, len(writes), mask=True) for guard in guards), tuple(effects),
            controls=controls, control_masks=control_masks, read_effects=tuple(read_effects))
    except UnsupportedInstructionError:
        raise
    except (ValueError, KeyError, TypeError, RecursionError) as error:
        raise SymbolEvaluationError(f"Invalid Sail source residual: {error}") from error


class SailSymbolicBackend:
    """Source selector compatible with the existing x86 residual composer.

    ``instruction`` supplies an independently bounded exact encoding, not
    instruction behavior. The Sail fetch/decode must agree with that boundary.
    Unlike the legacy ``generate`` interface this retains source guards, masks,
    and ordered effects rather than reducing a residual to an output dict.
    """
    name = "sail"

    def __init__(self, oracle):
        self.oracle = oracle

    def specialize(self, instruction) -> IntelInstructionResidual:
        residual = self.oracle.specialize(instruction.pc, instruction.code)
        if residual.length != len(instruction.code):
            raise SymbolEvaluationError("Sail source decode disagrees with exact instruction boundary")
        return residual


class SailOracle(IntelOracle):
    """Same bounded JSON-lines transport, with a source-specific wire contract."""
    def __init__(self, executable: str, model: str | Path, *, timeout: float = 120):
        self.model_path = Path(model)
        self.model_hash = hashlib.sha256(self.model_path.read_bytes()).hexdigest()
        try:
            provenance = json.loads(self.model_path.with_name("provenance.json").read_text(),
                                    object_pairs_hook=_pairs)
            if (not isinstance(provenance, dict) or type(provenance.get("schema")) is not int
                    or provenance["schema"] != 1 or provenance.get("architecture") != "x86_64"
                    or provenance.get("source") != "sail-x86"
                    or provenance.get("undefined_values_preserved") is not True
                    or provenance.get("undefined_representation") != "sail_undefined_v1"
                    or provenance.get("source_model_sha256") != self.model_hash):
                raise ValueError("Sail model does not preserve source undefined values or hash identity")
        except (OSError, ValueError, TypeError) as error:
            raise SymbolEvaluationError(f"Invalid Sail model provenance: {error}") from error
        self.provenance = provenance
        self.tir_revision = None
        environment = {name: value for name, value in os.environ.items()
                       if not name.startswith(("TIR_", "TIRAMISU_", "FOCACCIA_TIR_MODULE"))}
        super().__init__(executable, self.model_path, timeout=timeout, env=environment,
            command=(executable, "--export-sail-transitions", "--module", str(self.model_path)))

    def validate_response(self, response):
        if (not isinstance(response, dict) or not isinstance(response.get("status"), str)
                or response["status"] not in {"ok", "unsupported"}):
            raise IntelOracleError("Malformed Sail source response")

    def checked(self, request: dict) -> dict:
        response = self.request(request)
        if response["status"] != "ok":
            raise IntelOracleError(f"Sail source rejected request: {response.get('reason')}")
        return response

    def specialize(self, pc: int, code: bytes) -> IntelInstructionResidual:
        # Validate inputs before transmitting; the exporter independently checks
        # them too. Never pass concrete post-registers or post-memory.
        if type(pc) is not int or not 0 <= pc < 1 << 64 or not isinstance(code, bytes) or not 1 <= len(code) <= 15:
            raise SymbolEvaluationError("Invalid Sail specialization input")
        response = self.request({"pc": str(pc), "code": code.hex()})
        try:
            residual = decode_sail_residual(json.dumps(response), pc=pc, code=code,
                                           source_model_sha256=self.model_hash,
                                           tir_revision=self.tir_revision)
        except UnsupportedInstructionError:
            # The decoder validates provenance before interpreting this status.
            if self.tir_revision is None:
                self.tir_revision = response["tir_revision"]
            raise
        if self.tir_revision is None:
            self.tir_revision = response["tir_revision"]
        return residual
