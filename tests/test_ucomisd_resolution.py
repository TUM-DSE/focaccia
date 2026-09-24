"""Concrete binary64 flag semantics, including the retained Lua regression."""

import pytest
from miasm.expression.expression import ExprId, ExprInt, ExprMem, ExprOp

from focaccia.arch.x86 import ArchX86
from focaccia.compare import ErrorTypes, compare_symbolic
from focaccia.miasm_util import expr_simp
from focaccia.snapshot import ProgramState
from focaccia.symbolic import SymbolicTransform
from focaccia.trace import TraceEnvironment, TransitionTrace


@pytest.mark.parametrize("operation,index", [("cf", 0), ("zf", 1), ("pf", 2)])
@pytest.mark.parametrize(
    "left,right,flags",
    [
        (0x407F900000000000, 0x407F900000000000, (0, 1, 0)),
        (0, 0x8000000000000000, (0, 1, 0)),
        (0x8000000000000000, 0, (0, 1, 0)),
        (0x3FF0000000000000, 0x4000000000000000, (1, 0, 0)),
        (0x4000000000000000, 0x3FF0000000000000, (0, 0, 0)),
        (0xBFF0000000000000, 0xC000000000000000, (0, 0, 0)),
        (0xC000000000000000, 0xBFF0000000000000, (1, 0, 0)),
        (0xBFF0000000000000, 0x3FF0000000000000, (1, 0, 0)),
        (0x3FF0000000000000, 0xBFF0000000000000, (0, 0, 0)),
        (1, 0, (0, 0, 0)),
        (0x8000000000000001, 0, (1, 0, 0)),
        (0x7FF0000000000000, 0x7FEFFFFFFFFFFFFF, (0, 0, 0)),
        (0xFFF0000000000000, 0xFFEFFFFFFFFFFFFF, (1, 0, 0)),
        (0x7FF0000000000000, 0x7FF0000000000000, (0, 1, 0)),
        (0xFFF0000000000000, 0xFFF0000000000000, (0, 1, 0)),
        (0x7FF8000000000001, 0, (1, 1, 1)),
        (0, 0x7FF0000000000001, (1, 1, 1)),
        (0xFFF8000000000001, 0xFFF8000000000001, (1, 1, 1)),
        (0xFFF0000000000001, 0x7FF0000000000000, (1, 1, 1)),
    ],
)
def test_binary64_comparison_flags(left, right, flags, operation, index):
    expression = ExprOp(f"ucomisd_{operation}", ExprInt(left, 64), ExprInt(right, 64))
    assert expr_simp(expression) == ExprInt(flags[index], 1)


@pytest.mark.parametrize("operation", ["cf", "zf", "pf"])
def test_unknown_equal_operands_do_not_imply_ordered_equality(operation):
    operand = ExprId("unknown", 64)
    expression = ExprOp(f"ucomisd_{operation}", operand, operand)
    assert expr_simp(expression) == expression


def test_wrong_operand_width_is_rejected():
    with pytest.raises(ValueError, match="binary64"):
        expr_simp(ExprOp("ucomisd_cf", ExprInt(0, 32), ExprInt(0, 32)))


@pytest.mark.parametrize(
    "observed,missing,severity",
    [
        (0, None, None),
        (1, None, ErrorTypes.CONFIRMED),
        (0, "register", ErrorTypes.INCOMPLETE),
        (0, "memory", ErrorTypes.POSSIBLE),
    ],
)
def test_lua_flag_transition_accepts_only_known_correct_result(observed, missing, severity):
    arch = ArchX86()
    source, destination = ProgramState(arch), ProgramState(arch)
    source.write_register("RIP", 0x41FE90)
    destination.write_register("RIP", 0x41FE96)
    source.write_register("RSP", 0x8000)
    if missing != "register":
        source.write_register("XMM0", 0x407F900000000000)
    if missing != "memory":
        source.write_memory(0x8008, (0x407F900000000000).to_bytes(8, "little"))
    destination.write_register("CF", observed)
    transform = SymbolicTransform(
        1,
        {
            ExprId("cf", 1): ExprOp(
                "ucomisd_cf",
                ExprId("XMM0", 128)[:64],
                ExprMem(ExprId("RSP", 64) + ExprInt(8, 64), 64),
            )
        },
        [],
        arch,
        0x41FE90,
        0x41FE96,
    )
    trace = TransitionTrace(
        [source, destination],
        [transform],
        TraceEnvironment(None, (), (), binary_hash=None, architecture=arch.key),
    )
    errors = compare_symbolic(trace)[0]["errors"]
    if severity is None:
        assert errors == []
    else:
        assert len(errors) == 1
        assert errors[0].severity == severity
