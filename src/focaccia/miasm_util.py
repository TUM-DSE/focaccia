from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB, LocKey
from miasm.expression.expression import (
    Expr,
    ExprOp,
    ExprId,
    ExprLoc,
    ExprInt,
    ExprMem,
    ExprCompose,
    ExprSlice,
    ExprCond,
)
from miasm.expression.simplifications import expr_simp_explicit

from . import arch
from .arch import Arch
from .snapshot import ReadableProgramState, MemoryAccessError


def make_machine(_arch: Arch) -> Machine:
    """Create a Miasm `Machine` object corresponding to an `Arch`."""
    machines = {
        arch.x86.archname: lambda _: Machine("x86_64"),
        # Miasm only has ARM machine names with the l/b suffix:
        arch.aarch64.archname: lambda a: Machine(f"aarch64{a.endianness[0]}"),
    }
    return machines[_arch.archname](_arch)


def simp_segm(expr_simp, expr: ExprOp):
    """Simplify a segmentation expression to an addition of the segment
    register's base value and the address argument.
    """
    import miasm.arch.x86.regs as regs

    base_regs = {
        regs.FS: ExprId("fs_base", 64),
        regs.GS: ExprId("gs_base", 64),
    }

    if expr.op == "segm":
        segm, addr = expr.args
        assert segm == regs.FS or segm == regs.GS
        return expr_simp(base_regs[segm] + addr)
    return expr


def simp_fadd(expr_simp, expr: ExprOp):
    from .utils import (
        float_bits_to_uint,
        uint_bits_to_float,
        double_bits_to_uint,
        uint_bits_to_double,
    )

    if expr.op != "fadd":
        return expr

    assert len(expr.args) == 2
    lhs, rhs = expr.args
    if lhs.is_int() and rhs.is_int():
        assert lhs.size == rhs.size
        if lhs.size == 32:
            uint_to_float = uint_bits_to_float
            float_to_uint = float_bits_to_uint
        elif lhs.size == 64:
            uint_to_float = uint_bits_to_double
            float_to_uint = double_bits_to_uint
        else:
            raise NotImplementedError("fadd on values of size not in {32, 64}")

        res = float_to_uint(uint_to_float(lhs.arg) + uint_to_float(rhs.arg))
        return expr_simp(ExprInt(res, expr.size))
    return expr


def simp_fsub(expr_simp, expr: ExprOp):
    from .utils import (
        float_bits_to_uint,
        uint_bits_to_float,
        double_bits_to_uint,
        uint_bits_to_double,
    )

    if expr.op != "fsub":
        return expr

    assert len(expr.args) == 2
    lhs, rhs = expr.args
    if lhs.is_int() and rhs.is_int():
        assert lhs.size == rhs.size
        if lhs.size == 32:
            uint_to_float = uint_bits_to_float
            float_to_uint = float_bits_to_uint
        elif lhs.size == 64:
            uint_to_float = uint_bits_to_double
            float_to_uint = double_bits_to_uint
        else:
            raise NotImplementedError("fsub on values of size not in {32, 64}")

        res = float_to_uint(uint_to_float(lhs.arg) - uint_to_float(rhs.arg))
        return expr_simp(ExprInt(res, expr.size))
    return expr


def _fp32_bits_to_fp64_bits(value: int) -> int:
    """Widen one IEEE-754 binary32 bit pattern to binary64 exactly.

    Finite values are represented exactly in binary64. NaN sign and payload
    are retained while signaling NaNs are quieted, matching a numeric IEEE-754
    conversion.
    """
    value &= (1 << 32) - 1
    sign = value >> 31
    exponent = value >> 23 & 0xFF
    fraction = value & ((1 << 23) - 1)

    if exponent == 0:
        if fraction == 0:
            return sign << 63
        leading_bit = fraction.bit_length() - 1
        widened_exponent = leading_bit - 149 + 1023
        widened_fraction = (fraction - (1 << leading_bit)) << (52 - leading_bit)
    elif exponent == 0xFF:
        widened_exponent = 0x7FF
        widened_fraction = fraction << (52 - 23)
        if fraction:
            widened_fraction |= 1 << 51
    else:
        widened_exponent = exponent - 127 + 1023
        widened_fraction = fraction << (52 - 23)

    return sign << 63 | widened_exponent << 52 | widened_fraction


def simp_fpconvert_fp64(expr_simp, expr: ExprOp):
    if expr.op != "fpconvert_fp64":
        return expr

    if len(expr.args) != 1:
        raise NotImplementedError(f"fpconvert_fp64 expects one argument, received: {expr.args}")

    operand = expr.args[0]
    if operand.is_int():
        if operand.size != 32:
            raise NotImplementedError(
                f"fpconvert_fp64 expects a 32-bit value, received {operand.size} bits"
            )
        return expr_simp(ExprInt(_fp32_bits_to_fp64_bits(int(operand)), 64))
    return expr


# The expression simplifier used in this module
expr_simp = expr_simp_explicit
expr_simp.enable_passes(
    {
        ExprOp: [simp_segm, simp_fadd, simp_fsub, simp_fpconvert_fp64],
    }
)


class MiasmSymbolResolver:
    """Resolves atomic symbols to some state."""

    def __init__(self, state: ReadableProgramState, loc_db: LocationDB):
        self._state = state
        self._loc_db = loc_db
        self._arch = state.arch
        self.endianness: Arch.Endianness = self._arch.endianness

    def _miasm_to_regname(self, regname: str) -> str:
        """Convert a register name as used by Miasm to one that follows
        Focaccia's naming conventions."""
        canonical = self._arch.to_regname(regname)
        return canonical if canonical is not None else regname.upper()

    def resolve_register(self, regname: str) -> int | None:
        return self._state.read_register(self._miasm_to_regname(regname))

    def resolve_memory(self, addr: int, size: int) -> bytes | None:
        try:
            return self._state.read_memory(addr, size)
        except MemoryAccessError:
            return None

    def resolve_location(self, loc: LocKey) -> int | None:
        return self._loc_db.get_location_offset(loc)

    def resolve_environment_operation(self, operation: str, args: tuple[Expr, ...]) -> Expr | None:
        """Resolve a target-dependent operation from explicit target metadata.

        The default deliberately leaves such operations symbolic.  In
        particular, it must never query the analyzer host.
        """
        return None


_RECURSIVE_SIMPLIFICATION_DEPTH_LIMIT = 32


def expression_children(expression: Expr) -> tuple[Expr, ...]:
    """Return direct children without invoking Miasm's recursive visitors."""
    if isinstance(expression, (ExprInt, ExprId, ExprLoc)):
        return ()
    if isinstance(expression, ExprMem):
        return (expression.ptr,)
    if isinstance(expression, ExprSlice):
        return (expression.arg,)
    if isinstance(expression, ExprCond):
        return (expression.cond, expression.src1, expression.src2)
    if isinstance(expression, (ExprOp, ExprCompose)):
        return expression.args
    raise TypeError(f"Unknown expression type {type(expression).__name__}")


def expression_depth(expression: Expr) -> int:
    """Measure expression DAG depth iteratively, without structural hashing."""
    depths: dict[int, int] = {}
    pending: list[tuple[Expr, bool]] = [(expression, False)]
    while pending:
        current, expanded = pending.pop()
        key = id(current)
        if key in depths:
            continue
        children = expression_children(current)
        if not expanded:
            pending.append((current, True))
            pending.extend(
                (child, False) for child in reversed(children) if id(child) not in depths
            )
            continue
        depths[key] = 1 + max((depths[id(child)] for child in children), default=-1)
    return depths[id(expression)]


def simplify_if_shallow(expression: Expr, depth: int | None = None) -> Expr:
    """Preserve deep expressions exactly instead of recursing in Miasm."""
    actual_depth = expression_depth(expression) if depth is None else depth
    if actual_depth >= _RECURSIVE_SIMPLIFICATION_DEPTH_LIMIT:
        return expression
    return expr_simp(expression)


def iter_expression_dag(expression: Expr):
    """Yield every identity-distinct DAG node once without recursion."""
    pending = [expression]
    visited: set[int] = set()
    while pending:
        current = pending.pop()
        key = id(current)
        if key in visited:
            continue
        visited.add(key)
        yield current
        pending.extend(reversed(expression_children(current)))


def eval_expr(expr: Expr, conc_state: MiasmSymbolResolver) -> Expr:
    """Evaluate and simplify an expression DAG using an iterative work list."""
    results: dict[int, Expr] = {}
    depths: dict[int, int] = {}
    pending: list[tuple[Expr, bool]] = [(expr, False)]

    while pending:
        current, expanded = pending.pop()
        key = id(current)
        if key in results:
            continue
        children = expression_children(current)
        if not expanded:
            pending.append((current, True))
            pending.extend(
                (child, False) for child in reversed(children) if id(child) not in results
            )
            continue

        if isinstance(current, ExprInt):
            rebuilt = current
        elif isinstance(current, ExprId):
            value = conc_state.resolve_register(current.name)
            if value is None:
                rebuilt = current
            elif isinstance(value, int):
                rebuilt = ExprInt(value, current.size)
            else:
                rebuilt = value
        elif isinstance(current, ExprLoc):
            offset = conc_state.resolve_location(current.loc_key)
            rebuilt = current if offset is None else ExprInt(offset, current.size)
        elif isinstance(current, ExprMem):
            assert current.size % 8 == 0
            address = results[id(current.ptr)]
            if not isinstance(address, ExprInt):
                rebuilt = ExprMem(address, current.size)
            else:
                memory = conc_state.resolve_memory(int(address), current.size // 8)
                if memory is None:
                    rebuilt = ExprMem(address, current.size)
                else:
                    if len(memory) * 8 != current.size:
                        raise ValueError("Resolved memory has an unexpected size.")
                    rebuilt = ExprInt(
                        int.from_bytes(memory, byteorder=conc_state.endianness),
                        current.size,
                    )
        elif isinstance(current, ExprSlice):
            rebuilt = ExprSlice(results[id(current.arg)], current.start, current.stop)
        elif isinstance(current, ExprCond):
            condition = results[id(current.cond)]
            if isinstance(condition, ExprInt):
                selected = current.src1 if int(condition) != 0 else current.src2
                rebuilt = results[id(selected)]
            else:
                rebuilt = ExprCond(
                    condition,
                    results[id(current.src1)],
                    results[id(current.src2)],
                )
        elif isinstance(current, ExprOp):
            arguments = tuple(results[id(argument)] for argument in current.args)
            resolved = conc_state.resolve_environment_operation(current.op, arguments)
            rebuilt = resolved if resolved is not None else ExprOp(current.op, *arguments)
        elif isinstance(current, ExprCompose):
            rebuilt = ExprCompose(*(results[id(argument)] for argument in current.args))
        else:
            raise TypeError(f"Unknown expression type {type(current).__name__}")

        rebuilt_depth = 1 + max((depths[id(child)] for child in children), default=-1)
        result = simplify_if_shallow(rebuilt, rebuilt_depth)
        results[key] = result
        depths[key] = rebuilt_depth if result is rebuilt else expression_depth(result)

    return results[id(expr)]
