import pytest
from miasm.expression.expression import ExprId, ExprInt, ExprMem

from focaccia.arch.aarch64 import ArchAArch64
from focaccia.arch.x86 import ArchX86
from focaccia.boundary_oracle import BoundaryPrediction, RegisterPrediction, compare, predict
from focaccia.snapshot import ReadableProgramState
from focaccia.symbolic import SymbolicTransform


class State(ReadableProgramState):
    def __init__(self, arch, registers=None, memory=None):
        super().__init__(arch)
        self.registers = registers or {}
        self.memory = memory or {}

    def read_register(self, name):
        canonical = self.arch.to_regname(name)
        if canonical not in self.registers:
            raise KeyError(name)
        return self.registers[canonical]

    def read_memory(self, address, size):
        return bytes(self.memory[address + i] for i in range(size))


def make_transform(arch, name, source_owned=False):
    accessor = arch.get_reg_accessor(name)
    expr_id = ExprId(name, accessor.num_bits)
    result = SymbolicTransform(
        1, {expr_id: ExprInt(7, accessor.num_bits)}, [], arch, 0, 1,
        defined_masks={name: ExprInt((1 << accessor.num_bits) - 1, accessor.num_bits)} if source_owned else None,
        source_owned=source_owned,
    )
    return result


@pytest.mark.parametrize("arch,name", [(ArchAArch64("little"), "X0"), (ArchX86(), "RAX")])
@pytest.mark.parametrize("source_owned", [False, True])
def test_predicts_synthetic_register_transform_across_architectures(arch, name, source_owned):
    transform = make_transform(arch, name, source_owned)
    state = State(arch, {name: 3})
    prediction = predict(transform, state, knownness_inputs={})
    assert prediction.registers[name].value == 7
    assert prediction.registers[name].mask == (1 << arch.get_reg_accessor(name).num_bits) - 1


def test_required_bits_differ_from_comparison_mask_and_zero_required_still_compares():
    pred = BoundaryPrediction({"FLAGS": RegisterPrediction(0b10, 0b11, 2)}, (), {})
    result = compare(pred, {"FLAGS": 0}, {}, required_masks={"FLAGS": 0})
    assert {d["kind"] for d in result.diagnostics} == {"register_mismatch"}
    with pytest.raises(ValueError, match="excluded"):
        compare(pred, {"FLAGS": 0}, {}, required_masks={"FLAGS": 1}, observation_masks={"FLAGS": 0})


def test_missing_required_register_and_invalid_masks_rejected():
    pred = BoundaryPrediction({}, (), {})
    assert not compare(pred, {}, {}, required_masks={"R": 1}).ok
    with pytest.raises(ValueError):
        compare(BoundaryPrediction({"R": RegisterPrediction(0, 0, 1)}, (), {}), {}, {}, required_masks={"R": -1})


def test_store_coverage_expands_multibyte_overlaps_to_byte_addresses():
    pred = BoundaryPrediction({}, ((0x10, b"abc"), (0x12, b"XY")), {0x10: b"abXY"})
    assert compare(pred, {}, {0x10: b"abXY"}, actual_store_addresses={0x10, 0x11, 0x12, 0x13},
                   require_store_coverage=True).ok
    result = compare(pred, {}, {0x10: b"abXY"}, actual_store_addresses={0x10, 0x11, 0x12},
                     require_store_coverage=True)
    assert any(d["kind"] == "missing_store" and d["address"] == 0x13 for d in result.diagnostics)


def test_source_owned_false_guard_is_rejected():
    from focaccia.symbolic import SymbolEvaluationError
    arch = ArchAArch64("little")
    name = "X0"
    width = arch.get_reg_accessor(name).num_bits
    transform = SymbolicTransform(1, {ExprId(name, width): ExprInt(1, width)}, [], arch, 0, 1,
        defined_masks={name: ExprInt((1 << width) - 1, width)},
        guards=(ExprInt(0, 1),), source_owned=True)
    with pytest.raises(SymbolEvaluationError, match="false"):
        predict(transform, State(arch, {name: 0}))


def test_comparison_rejects_missing_store_evidence_and_extra_address():
    prediction = BoundaryPrediction({}, ((1, b"z"),), {1: b"z"})
    assert not compare(prediction, {}, {}, require_store_coverage=True).ok
    result = compare(prediction, {}, {}, actual_store_addresses={1, 2}, require_store_coverage=True)
    assert any(d["kind"] == "extra_store" and d["address"] == 2 for d in result.diagnostics)


def test_arm_probe_boundary_comparison_uses_shared_comparator():
    import runpy
    from pathlib import Path

    probe = runpy.run_path(str(Path(__file__).parent / "probes/tir_no_replay_smoke.py"))
    validator_cls = probe["OnlineTirValidator"]
    block_cls = probe["PendingBlock"]
    arch = ArchAArch64("little")
    validator = validator_cls.__new__(validator_cls)
    validator.active = block_cls(0x100, 0x100, 1, 0, "hash", None,
                                 {"X0": 9}, (), {}, None)
    validator.state = None
    validator.arch = arch
    validator.errors = []
    validator.store_evidence = []
    validator.blocks = []

    class Observed:
        def write_register(self, name, value): pass
        def read_register(self, name): return 8

    validator._compare_active(0x100, 1, observed_state=Observed())
    assert validator.errors[0]["subject"] == "X0"
    assert validator.errors[0]["expected"] == "0x9"
    assert validator.errors[0]["actual"] == "0x8"
