"""Sail source adapter for the existing native observation/validation runner."""
from __future__ import annotations

from ..intel_symbolic import (
    IntelProjectedReadEffect, capture_projected_intel_read_effects,
    knownness_inputs_for_observation, predict_residual_register,
)
from ..sail_symbolic import SailOracle
from ..symbolic import UnsupportedInstructionError
from .spec_validate import (
    SpecValidationError, UnsupportedNativeEvent, _byte, _mapping, _permission, _snapshot_state,
)


class SailNativeOracle:
    """Export before execution; use the same source-owned transforms/comparator.

    This does not use host execution to resolve undefined values or branches.
    AArch64 hosts can exercise the adapter using immutable synthetic x86
    prestates; native x86 acceptance still requires actual x86 hardware.
    """
    def __init__(self, model, executable, *, timeout=120):
        self.oracle = SailOracle(executable, model, timeout=timeout)
        self.model_hash = self.oracle.model_hash
        self.source_provenance = dict(self.oracle.provenance)
        self.knownness_inputs = None
        self.last_repeat_pc = None

    def __call__(self, snapshot):
        if snapshot.arch.archname != "x86_64":
            raise SpecValidationError("Sail x86 oracle received a non-x86 snapshot")
        pc = snapshot.registers.get("RIP")
        if type(pc) is not int:
            raise SpecValidationError("Sail prestate omitted RIP")
        code = bytearray()
        for address in range(pc, min(pc + 15, 1 << 64)):
            mapping = _mapping(snapshot.mappings, address)
            value = _byte(snapshot.memory, address)
            if mapping is None or value is None or not {"r", "x"} <= set(_permission(mapping, address)):
                break
            code.append(value)
        if not code:
            raise SpecValidationError("Sail instruction fetch lacks readable executable evidence")
        try:
            residual = self.oracle.specialize(pc, bytes(code))
        except UnsupportedInstructionError as error:
            raise UnsupportedNativeEvent(f"Sail source rejected boundary {pc:#x}: {error}") from error
        if self.knownness_inputs is None:
            self.knownness_inputs = knownness_inputs_for_observation(snapshot.registers)
        transform = residual.to_transform(1, snapshot.arch)
        # Reads that produce no surviving output still carry permission and
        # definedness obligations. Preserve these alongside the ordered stores.
        reads = tuple(IntelProjectedReadEffect(
            effect.condition, effect.address, effect.address_mask,
            effect.byte_count, effect.write_prefix,
        ) for effect in residual.read_effects)
        state = _snapshot_state(snapshot)
        capture_projected_intel_read_effects(transform, reads, state, self.knownness_inputs)
        # Undefined control flow is not an acceptable set of post-PC values.
        # Resolve this source output using prestate only, before native stepping.
        predict_residual_register(residual, "RIP", state, self.knownness_inputs, 1)
        return transform

    @property
    def tir_revision(self):
        return self.oracle.tir_revision

    def set_knownness_inputs(self, knownness):
        self.knownness_inputs = dict(knownness)

    def close(self):
        self.oracle.close()
