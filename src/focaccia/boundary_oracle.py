"""Architecture-neutral prediction and comparison for symbolic boundaries.

Adapters own decoding and concrete state acquisition; this module only evaluates
SymbolicTransform equations and compares explicitly observed facts.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


def _final_memory(writes) -> dict[int, bytes]:
    """Coalesce already evaluated stores without re-running their expressions."""
    final_bytes = {}
    for address, data in writes:
        final_bytes.update({address + offset: byte for offset, byte in enumerate(data)})
    final_memory = {}
    if final_bytes:
        addresses = sorted(final_bytes)
        start = previous = addresses[0]
        chunk = bytearray([final_bytes[start]])
        for address in addresses[1:]:
            if address != previous + 1:
                final_memory[start] = bytes(chunk)
                start, chunk = address, bytearray()
            chunk.append(final_bytes[address])
            previous = address
        final_memory[start] = bytes(chunk)
    return final_memory


@dataclass(frozen=True)
class RegisterPrediction:
    value: int
    mask: int
    width: int


@dataclass(frozen=True)
class BoundaryPrediction:
    registers: Mapping[str, RegisterPrediction]
    ordered_writes: tuple[tuple[int, bytes], ...]
    memory: Mapping[int, bytes]

    def __post_init__(self):
        registers = dict(self.registers)
        for name, item in registers.items():
            if not isinstance(name, str) or not isinstance(item, RegisterPrediction):
                raise ValueError("Register predictions require names and RegisterPrediction values.")
            if (type(item.width) is not int or item.width <= 0
                    or type(item.value) is not int or type(item.mask) is not int
                    or not 0 <= item.value < 1 << item.width
                    or not 0 <= item.mask < 1 << item.width):
                raise ValueError(f"Invalid value, mask, or width for register {name}.")
        writes = tuple(self.ordered_writes)
        if any(type(address) is not int or address < 0 or not isinstance(data, bytes)
               for address, data in writes):
            raise ValueError("Ordered writes require nonnegative addresses and bytes values.")
        memory = dict(self.memory)
        if any(type(address) is not int or address < 0 or not isinstance(data, bytes)
               for address, data in memory.items()):
            raise ValueError("Memory predictions require nonnegative addresses and bytes values.")
        if memory != _final_memory(writes):
            raise ValueError("Final memory must equal coalesced ordered-write results.")
        object.__setattr__(self, "registers", MappingProxyType(registers))
        object.__setattr__(self, "ordered_writes", writes)
        object.__setattr__(self, "memory", MappingProxyType(memory))


@dataclass(frozen=True)
class ComparisonResult:
    ok: bool
    diagnostics: tuple[Mapping[str, object], ...]


def predict(transform, state, *, knownness_inputs=None, register_names=None) -> BoundaryPrediction:
    """Evaluate a transform, optionally checking a complete source observation view.

    Source callers can request unchanged registers as well as modified outputs;
    comparing only modified outputs would miss unexpected implementation clobbers.
    """
    if transform.source_owned:
        pairs, stores = transform.eval_source_transition(
            state, knownness_inputs or {}, register_names=register_names,
        )
        memory = _final_memory(stores)
    else:
        if register_names is not None:
            raise ValueError("An explicit observation view requires source-owned definedness.")
        pairs = {name: (value, (1 << transform.arch.get_reg_accessor(name).num_bits) - 1)
                 for name, value in transform.eval_validation_register_transforms(state).items()}
        stores = transform.eval_ordered_memory_transforms(state)
        memory = _final_memory(stores)
    registers = {}
    for name, (value, mask) in pairs.items():
        accessor = transform.arch.get_reg_accessor(name)
        registers[name] = RegisterPrediction(value, mask, accessor.num_bits)
    return BoundaryPrediction(registers, tuple(stores), memory)


def compare(prediction: BoundaryPrediction, observed_registers: Mapping[str, int],
            observed_memory: Mapping[int, bytes], *, required_masks: Mapping[str, int] | None = None,
            observation_masks: Mapping[str, int] | None = None,
            actual_store_addresses=None, require_store_coverage: bool = False) -> ComparisonResult:
    """Compare observations; required masks enforce knownness, observation masks select comparisons."""
    if type(require_store_coverage) is not bool:
        raise ValueError("require_store_coverage must be bool.")
    errors = []
    required_masks = {} if required_masks is None else dict(required_masks)
    observation_masks = {} if observation_masks is None else dict(observation_masks)
    for options, label in ((required_masks, "required"), (observation_masks, "observation")):
        for name, mask in options.items():
            prediction_item = prediction.registers.get(name)
            if prediction_item is None:
                errors.append({"kind": "required_register_missing", "register": name, "policy": label})
            elif type(mask) is not int or not 0 <= mask < 1 << prediction_item.width:
                raise ValueError(f"Invalid {label} mask for register {name}.")
        for name in prediction.registers:
            if required_masks.get(name, 0) & ~observation_masks.get(name, prediction.registers[name].mask):
                raise ValueError(f"Required bits for {name} are excluded from observation.")
    for name, expected in prediction.registers.items():
        required = required_masks.get(name, expected.mask)
        observed = observation_masks.get(name, expected.mask)
        actual = observed_registers.get(name)
        if actual is None:
            errors.append({"kind": "missing_register", "register": name})
            continue
        if type(actual) is not int or not 0 <= actual < 1 << expected.width:
            raise ValueError(f"Invalid observed value for register {name}.")
        if expected.mask & required != required:
            errors.append({"kind": "unknown_required_bits", "register": name,
                           "required_mask": required, "known_mask": expected.mask})
        compare_mask = expected.mask & observed
        if ((actual ^ expected.value) & compare_mask) != 0:
            errors.append({"kind": "register_mismatch", "register": name,
                           "expected": expected.value, "actual": actual, "mask": compare_mask})
    for address, expected in prediction.memory.items():
        actual = observed_memory.get(address)
        if actual != expected:
            errors.append({"kind": "memory_mismatch", "address": address,
                           "expected": expected, "actual": actual})
    if require_store_coverage:
        if actual_store_addresses is None:
            errors.append({"kind": "missing_store_evidence"})
        else:
            wanted = {address + offset for address, data in prediction.ordered_writes
                      for offset in range(len(data))}
            actual = set(actual_store_addresses)
            if any(type(address) is not int or address < 0 for address in actual):
                raise ValueError("Observed store addresses must be nonnegative integers.")
            for address in sorted(wanted - actual):
                errors.append({"kind": "missing_store", "address": address})
            for address in sorted(actual - wanted):
                errors.append({"kind": "extra_store", "address": address})
    return ComparisonResult(not errors, tuple(errors))
