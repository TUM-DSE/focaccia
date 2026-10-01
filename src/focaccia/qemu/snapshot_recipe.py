"""Bounded compiler for target-neutral snapshot address recipes."""

from __future__ import annotations

import struct

from miasm.expression.expression import ExprId, ExprInt, ExprMem, ExprOp


RECIPE_END = 0
RECIPE_CONST = 1
RECIPE_REG = 2
RECIPE_ADD = 3
RECIPE_SUB = 4
RECIPE_AND = 5
RECIPE_OR = 6
RECIPE_XOR = 7
RECIPE_SHL = 8
RECIPE_LSHR = 9
RECIPE_OPS = {
    "+": RECIPE_ADD, "-": RECIPE_SUB, "&": RECIPE_AND,
    "|": RECIPE_OR, "^": RECIPE_XOR, "<<": RECIPE_SHL,
    ">>": RECIPE_LSHR,
}
RECIPE_LOAD = 12
MAX_RECIPE_OPS = 64
MAX_RECIPE_BYTES = 640
MAX_RECIPE_READS = 8


class UnsupportedSnapshotRecipe(ValueError):
    pass


def compile_address_recipe(expression, register_indices: dict[str, tuple[int, int]]) -> bytes:
    """Compile one source-state expression, rejecting anything not exactly representable.

    ``register_indices`` maps canonical symbolic names to ``(wire index, wire width)``.
    The wire width must exactly match the expression width; narrowing is never inferred.
    """
    code = bytearray()
    operations = 0
    reads = 0

    def emit(item) -> None:
        nonlocal operations, reads
        operations += 1
        if operations > MAX_RECIPE_OPS:
            raise UnsupportedSnapshotRecipe("Snapshot recipe operation bound exceeded.")
        if isinstance(item, ExprInt):
            if not 0 < item.size <= 64:
                raise UnsupportedSnapshotRecipe("Snapshot constants must fit in 64 bits.")
            code.extend((RECIPE_CONST, item.size))
            code.extend(struct.pack("<Q", int(item) & ((1 << item.size) - 1)))
        elif isinstance(item, ExprId):
            identity = register_indices.get(str(item))
            if identity is None or identity[1] != item.size or identity[0] > 255:
                raise UnsupportedSnapshotRecipe(f"Unsupported snapshot register {item}.")
            code.extend((RECIPE_REG, item.size, identity[0]))
        elif isinstance(item, ExprMem):
            if not 0 < item.size <= 64 or item.size % 8:
                raise UnsupportedSnapshotRecipe("Pointer-chase loads must be 1 to 8 bytes.")
            reads += 1
            if reads > MAX_RECIPE_READS:
                raise UnsupportedSnapshotRecipe("Snapshot recipe read bound exceeded.")
            emit(item.ptr)
            code.extend((RECIPE_LOAD, item.size))
        elif isinstance(item, ExprOp) and item.op in RECIPE_OPS and len(item.args) == 2:
            emit(item.args[0])
            emit(item.args[1])
            code.append(RECIPE_OPS[item.op])
        else:
            kind = type(item).__name__
            operation = getattr(item, "op", None)
            size = getattr(item, "size", None)
            raise UnsupportedSnapshotRecipe(
                f"Unsupported snapshot expression kind={kind}, "
                f"operation={operation!r}, size={size!r}."
            )
        if len(code) >= MAX_RECIPE_BYTES:
            raise UnsupportedSnapshotRecipe("Snapshot recipe byte bound exceeded.")

    emit(expression)
    if expression.size != 64:
        raise UnsupportedSnapshotRecipe("Snapshot addresses must be exactly 64 bits.")
    code.append(RECIPE_END)
    if len(code) > MAX_RECIPE_BYTES:
        raise UnsupportedSnapshotRecipe("Snapshot recipe byte bound exceeded.")
    return bytes(code)
