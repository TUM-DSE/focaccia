import pytest
from miasm.expression.expression import ExprInt, ExprOp

from focaccia.miasm_util import expr_simp


@pytest.mark.parametrize(
    ("binary32", "binary64"),
    [
        (0x00000000, 0x0000000000000000),
        (0x80000000, 0x8000000000000000),
        (0x3F800000, 0x3FF0000000000000),
        (0x3FC00000, 0x3FF8000000000000),
        (0x00000001, 0x36A0000000000000),
        (0x007FFFFF, 0x380FFFFFC0000000),
        (0x7F800000, 0x7FF0000000000000),
        (0xFF800000, 0xFFF0000000000000),
        (0x7FC12345, 0x7FF82468A0000000),
        (0x7F812345, 0x7FF82468A0000000),
        (0xFF812345, 0xFFF82468A0000000),
    ],
)
def test_fp32_to_fp64_widening_is_bit_precise(binary32: int, binary64: int):
    result = expr_simp(ExprOp("fpconvert_fp64", ExprInt(binary32, 32)))

    assert isinstance(result, ExprInt)
    assert result.size == 64
    assert int(result) == binary64


def test_fp32_to_fp64_rejects_non_fp32_operands():
    with pytest.raises(NotImplementedError, match="32-bit"):
        expr_simp(ExprOp("fpconvert_fp64", ExprInt(0, 64)))
