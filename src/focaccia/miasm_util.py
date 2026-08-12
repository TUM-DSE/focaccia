from typing import Callable

from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB, LocKey
from miasm.expression.expression import Expr, ExprOp, ExprId, ExprLoc, \
                                        ExprInt, ExprMem, ExprCompose, \
                                        ExprSlice, ExprCond
from miasm.expression.simplifications import expr_simp_explicit

from . import arch
from .arch import Arch
from .snapshot import ReadableProgramState, MemoryAccessError

def make_machine(_arch: Arch) -> Machine:
    """Create a Miasm `Machine` object corresponding to an `Arch`."""
    machines = {
        arch.x86.archname: lambda _: Machine('x86_64'),
        # Miasm only has ARM machine names with the l/b suffix:
        arch.aarch64.archname: lambda a: Machine(f'aarch64{a.endianness[0]}'),
    }
    return machines[_arch.archname](_arch)

def simp_segm(expr_simp, expr: ExprOp):
    """Simplify a segmentation expression to an addition of the segment
    register's base value and the address argument.
    """
    import miasm.arch.x86.regs as regs

    base_regs = {
        regs.FS: ExprId('fs_base', 64),
        regs.GS: ExprId('gs_base', 64),
    }

    if expr.op == 'segm':
        segm, addr = expr.args
        assert(segm == regs.FS or segm == regs.GS)
        return expr_simp(base_regs[segm] + addr)
    return expr

def simp_fadd(expr_simp, expr: ExprOp):
    from .utils import float_bits_to_uint, uint_bits_to_float, \
                       double_bits_to_uint, uint_bits_to_double

    if expr.op != 'fadd':
        return expr

    assert(len(expr.args) == 2)
    lhs, rhs = expr.args
    if lhs.is_int() and rhs.is_int():
        assert(lhs.size == rhs.size)
        if lhs.size == 32:
            uint_to_float = uint_bits_to_float
            float_to_uint = float_bits_to_uint
        elif lhs.size == 64:
            uint_to_float = uint_bits_to_double
            float_to_uint = double_bits_to_uint
        else:
            raise NotImplementedError('fadd on values of size not in {32, 64}')

        res = float_to_uint(uint_to_float(lhs.arg) + uint_to_float(rhs.arg))
        return expr_simp(ExprInt(res, expr.size))
    return expr

def simp_fsub(expr_simp, expr: ExprOp):
    from .utils import float_bits_to_uint, uint_bits_to_float, \
                       double_bits_to_uint, uint_bits_to_double

    if expr.op != 'fsub':
        return expr

    assert(len(expr.args) == 2)
    lhs, rhs = expr.args
    if lhs.is_int() and rhs.is_int():
        assert(lhs.size == rhs.size)
        if lhs.size == 32:
            uint_to_float = uint_bits_to_float
            float_to_uint = float_bits_to_uint
        elif lhs.size == 64:
            uint_to_float = uint_bits_to_double
            float_to_uint = double_bits_to_uint
        else:
            raise NotImplementedError('fsub on values of size not in {32, 64}')

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
    if expr.op != 'fpconvert_fp64':
        return expr

    if len(expr.args) != 1:
        raise NotImplementedError(
            f'fpconvert_fp64 expects one argument, received: {expr.args}'
        )

    operand = expr.args[0]
    if operand.is_int():
        if operand.size != 32:
            raise NotImplementedError(
                f'fpconvert_fp64 expects a 32-bit value, received {operand.size} bits'
            )
        return expr_simp(ExprInt(_fp32_bits_to_fp64_bits(int(operand)), 64))
    return expr

# The expression simplifier used in this module
expr_simp = expr_simp_explicit
expr_simp.enable_passes({
    ExprOp: [simp_segm, simp_fadd, simp_fsub, simp_fpconvert_fp64],
})

class MiasmSymbolResolver:
    """Resolves atomic symbols to some state."""

    def __init__(self,
                 state: ReadableProgramState,
                 loc_db: LocationDB):
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

def eval_expr(expr: Expr, conc_state: MiasmSymbolResolver) -> Expr:
    """Evaluate a symbolic expression with regard to a concrete reference
    state.

    :param expr:       An expression to evaluate.
    :param conc_state: The concrete reference state from which symbolic
                       register and memory state is resolved.

    :return: The most simplified and concrete representation of `expr` that
             is producible with the values from `conc_state`. Is guaranteed to
             be either an `ExprInt` or an `ExprLoc` *if* `conc_state` only
             returns concrete register- and memory values.
    """
    # Most of these implementation are just copy-pasted members of
    # `SymbolicExecutionEngine`.
    expr_to_visitor: dict[type[Expr], Callable] = {
        ExprInt:     _eval_exprint,
        ExprId:      _eval_exprid,
        ExprLoc:     _eval_exprloc,
        ExprMem:     _eval_exprmem,
        ExprSlice:   _eval_exprslice,
        ExprCond:    _eval_exprcond,
        ExprOp:      _eval_exprop,
        ExprCompose: _eval_exprcompose,
    }

    visitor = expr_to_visitor.get(expr.__class__, None)
    if visitor is None:
        raise TypeError("Unknown expr type")

    ret = visitor(expr, conc_state)
    ret = expr_simp(ret)
    assert(ret is not None)

    return ret

def _eval_exprint(expr: ExprInt, _):
    """Evaluate an ExprInt using the current state"""
    return expr

def _eval_exprid(expr: ExprId, state: MiasmSymbolResolver):
    """Evaluate an ExprId using the current state"""
    val = state.resolve_register(expr.name)
    if val is None:
        return expr
    if isinstance(val, int):
        return ExprInt(val, expr.size)
    return val

def _eval_exprloc(expr: ExprLoc, state: MiasmSymbolResolver):
    """Evaluate an ExprLoc using the current state"""
    offset = state.resolve_location(expr.loc_key)
    if offset is None:
        return expr
    return ExprInt(offset, expr.size)

def _eval_exprmem(expr: ExprMem, state: MiasmSymbolResolver):
    """Evaluate an ExprMem using the current state.
    This function first evaluates the memory pointer value.
    """
    assert(expr.size % 8 == 0)

    addr = eval_expr(expr.ptr, state)
    if not addr.is_int():
        return expr

    assert(isinstance(addr, ExprInt))
    mem = state.resolve_memory(int(addr), expr.size // 8)
    if mem is None:
        return expr

    assert(len(mem) * 8 == expr.size)
    return ExprInt(int.from_bytes(mem, byteorder=state.endianness), expr.size)

def _eval_exprcond(expr, state: MiasmSymbolResolver):
    """Evaluate only the selected branch when the condition is concrete."""
    cond = eval_expr(expr.cond, state)
    if isinstance(cond, ExprInt):
        selected = expr.src1 if int(cond) != 0 else expr.src2
        return eval_expr(selected, state)
    src1 = eval_expr(expr.src1, state)
    src2 = eval_expr(expr.src2, state)
    return ExprCond(cond, src1, src2)

def _eval_exprslice(expr, state: MiasmSymbolResolver):
    """Evaluate an ExprSlice using the current state"""
    arg = eval_expr(expr.arg, state)
    return ExprSlice(arg, expr.start, expr.stop)

def _eval_exprop(expr, state: MiasmSymbolResolver):
    """Evaluate an ExprOp using the current state"""
    args = [eval_expr(arg, state) for arg in expr.args]

    if expr.op in ('x86_cpuid', 'focaccia_memory_byte'):
        resolved = state.resolve_environment_operation(expr.op, tuple(args))
        if resolved is not None:
            return resolved

    return ExprOp(expr.op, *args)

def _eval_exprcompose(expr, state: MiasmSymbolResolver):
    """Evaluate an ExprCompose using the current state"""
    args = []
    for arg in expr.args:
        args.append(eval_expr(arg, state))
    return ExprCompose(*args)
