from dataclasses import replace
import pytest
from miasm.expression.expression import Expr, ExprId, ExprInt, ExprMem

from focaccia.arch.aarch64 import ArchAArch64
from focaccia.native.region_validate import prepare_candidates, compare_candidates
from focaccia.native.spec_target import SpecMemoryMapping
from focaccia.native.spec_validate import NativeSnapshot, SpecValidationError
from focaccia.symbolic import SymbolicTransform, SymbolEvaluationError
from focaccia.tir_backend import RegionCandidate


def prestate():
    arch = ArchAArch64("little")
    return NativeSnapshot(
        arch, {"PC": 0x1000, "CPSR": 0, "X0": 7, "X1": 0},
        {0x1000: b"code", 0x2000: b"a"},
        (SpecMemoryMapping(0x1000, 0x1004, True, False, True, True, "code"),
         SpecMemoryMapping(0x2000, 0x2001, True, True, False, True, "data")),
        "full-boundary-memory-diff",
    )


def candidate(pre, status, *, active=1, guards=(), reads=()):
    outputs: dict[Expr, Expr] = {ExprId("PC", 64): ExprInt(0x1004, 64),
                                 ExprId("X1", 64): ExprInt(status, 64)}
    memory_masks = {}
    if status == 0:
        destination = ExprMem(ExprInt(0x2000, 64), 8)
        outputs[destination] = ExprInt(ord("b"), 8)
        memory_masks[destination] = (ExprInt((1 << 64) - 1, 64), ExprInt(255, 8))
    transform = SymbolicTransform(
        1, outputs, [], pre.arch, 0x1000, 0x1004, source_owned=True,
        defined_masks={name: ExprInt((1 << 64) - 1, 64) for name in ("PC", "X1")},
        memory_defined_masks=memory_masks, guards=guards,
    )
    return RegionCandidate(ExprInt(active, 1), transform,
                           "none" if status == 0 else "clear-before-store", reads)


def poststate(pre, status, data):
    return replace(pre, registers={**pre.registers, "PC": 0x1004, "X1": status},
                   memory={**pre.memory, 0x2000: data})


def test_monitor_outcomes_are_precomputed_and_status_is_paired_with_store(monkeypatch):
    pre = prestate()
    prepared = prepare_candidates(pre, (candidate(pre, 0), candidate(pre, 1)))

    def no_post_prediction(*args, **kwargs):
        raise AssertionError("comparison must not recompute expected results")

    monkeypatch.setattr("focaccia.native.region_validate._predict_transition", no_post_prediction)
    assert compare_candidates(pre, poststate(pre, 0, b"b"), prepared) == ("none",)
    assert compare_candidates(pre, poststate(pre, 1, b"a"), prepared) == ("clear-before-store",)
    with pytest.raises(SpecValidationError, match="No precomputed"):
        compare_candidates(pre, poststate(pre, 1, b"b"), prepared)


def test_inactive_path_is_lazy_but_active_assertion_is_not_silently_discarded():
    pre = prestate()
    denied = ((ExprInt(0xDEAD, 64), 8),)
    inactive = candidate(pre, 0, active=0, guards=(ExprInt(0, 1),), reads=denied)
    assert len(prepare_candidates(pre, (inactive, candidate(pre, 1)))) == 1
    with pytest.raises(SymbolEvaluationError, match="guard.*false"):
        prepare_candidates(pre, (candidate(pre, 0, guards=(ExprInt(0, 1),)),))
    with pytest.raises(SpecValidationError, match="read denied"):
        prepare_candidates(pre, (candidate(pre, 0, reads=denied),))


def test_no_active_source_outcome_fails_closed():
    pre = prestate()
    with pytest.raises(SpecValidationError, match="No source region outcome"):
        prepare_candidates(pre, (candidate(pre, 0, active=0),))
