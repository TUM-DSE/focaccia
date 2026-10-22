"""Prepare source alternatives before an exclusive region, then compare outcomes.

A hardware result may match an already predicted outcome. It never supplies an
input to the source oracle or chooses which outcomes are predicted.
"""
from dataclasses import dataclass

from .spec_validate import (
    NativeSnapshot, SpecValidationError, _predict_transition, _snapshot_state,
    _validate_memory_coverage, _validate_transition,
)
from ..symbolic import _TransformEvaluator


@dataclass(frozen=True)
class PreparedCandidate:
    source: object
    prediction: object


def request_for_region(region):
    return {
        "schema": 1,
        "entry_pc": str(region.entry_pc),
        "instructions": [
            {"pc": str(pc), "instruction": code.hex()}
            for pc, code in region.instructions
        ],
        "exit_pcs": [str(pc) for pc in region.exit_pcs],
        "max_steps": region.max_steps,
    }


def prepare_candidates(pre, candidates):
    if pre.arch.archname != "aarch64":
        raise SpecValidationError("Exclusive regions require AArch64 observations.")
    state = _snapshot_state(pre)
    knownness = {}
    for name in pre.registers:
        accessor = pre.arch.get_reg_accessor(name)
        if accessor is not None and accessor.base_reg == name:
            knownness[name] = (1 << accessor.num_bits) - 1
    prepared = []
    for candidate in candidates:
        transform = candidate.transform
        if not transform.source_owned:
            raise SpecValidationError("Region candidate omitted source-owned guards/masks.")
        evaluator = _TransformEvaluator(state, [], knownness)
        defined = transform._eval_source_definedness(
            candidate.activation, state, knownness, evaluator, write_prefix=0,
        )
        if candidate.activation.size != 1 or defined != 1:
            raise SpecValidationError("Region path activation is not fully defined.")
        active = evaluator.evaluate(candidate.activation)
        if active == 0:
            continue
        if active != 1:
            raise SpecValidationError("Region path activation is not Boolean.")
        for address, bits in candidate.memory_reads:
            mask = transform._eval_source_definedness(
                address, state, knownness, evaluator, write_prefix=0,
            )
            if mask != (1 << address.size) - 1 or type(bits) is not int or bits <= 0 or bits % 8:
                raise SpecValidationError("Region read obligation is not fully defined.")
            state.read_memory(evaluator.evaluate(address), bits // 8)
        # Mandatory source assertions are not path-selection conditions. An
        # active assertion/permission failure aborts before hardware runs.
        prediction = _predict_transition(transform, pre, knownness)
        prepared.append(PreparedCandidate(candidate, prediction))
    if not prepared:
        raise SpecValidationError("No source region outcome is active for the prestate.")
    return tuple(prepared)


def snapshot_from_evidence(arch, evidence):
    snapshot = NativeSnapshot(
        arch, dict(evidence.registers),
        {mapping.start: data for mapping, data in evidence.memory.regions},
        tuple(evidence.mappings), evidence.memory.capability,
        evidence.stdout, evidence.stderr,
    )
    _validate_memory_coverage(snapshot)
    return snapshot


def compare_candidates(pre, post, prepared):
    matched, failures = [], []
    for candidate in prepared:
        try:
            _validate_transition(
                candidate.source.transform, pre, post, candidate.prediction,
            )
        except SpecValidationError as error:
            failures.append(str(error))
        else:
            matched.append(candidate.source.monitor_event)
    if not matched:
        raise SpecValidationError(
            "No precomputed source region outcome matches native observation: "
            + "; ".join(failures[:4])
        )
    return tuple(matched)
