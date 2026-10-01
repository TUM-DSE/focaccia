import pytest
from miasm.expression.expression import ExprId, ExprInt, ExprMem, ExprSlice

from focaccia.qemu.snapshot_recipe import (
    RECIPE_ADD,
    RECIPE_CONST,
    RECIPE_END,
    RECIPE_LOAD,
    RECIPE_REG,
    UnsupportedSnapshotRecipe,
    compile_address_recipe,
)


def test_unsupported_expression_diagnostic_does_not_render_expression_tree():
    expression = ExprSlice(ExprId("X1", 128), 0, 64)
    with pytest.raises(
        UnsupportedSnapshotRecipe,
        match="kind=ExprSlice, operation=None, size=64",
    ):
        compile_address_recipe(expression, {})


def test_register_offset_recipe_matches_wire_language():
    expression = ExprId("X1", 64) + ExprInt(-8, 64)
    assert compile_address_recipe(expression, {"X1": (0, 64)}) == bytes([
        RECIPE_REG, 64, 0,
        RECIPE_CONST, 64, 0xF8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        RECIPE_ADD,
        RECIPE_END,
    ])


def test_pointer_chase_recipe_is_ordered_before_offset():
    expression = ExprMem(ExprId("X1", 64), 64) + ExprInt(8, 64)
    recipe = compile_address_recipe(expression, {"X1": (3, 64)})
    assert recipe[:5] == bytes([RECIPE_REG, 64, 3, RECIPE_LOAD, 64])
    assert recipe[-2:] == bytes([RECIPE_ADD, RECIPE_END])


def test_recipe_rejects_width_alias_without_silent_narrowing():
    with pytest.raises(UnsupportedSnapshotRecipe, match="register"):
        compile_address_recipe(ExprId("W1", 32), {"W1": (0, 64)})


def test_recipe_rejects_more_than_eight_pointer_reads():
    expression = ExprId("X1", 64)
    for _ in range(9):
        expression = ExprMem(expression, 64)
    with pytest.raises(UnsupportedSnapshotRecipe, match="read bound"):
        compile_address_recipe(expression, {"X1": (0, 64)})
