from typing import Callable

from miasm.core.locationdb import LocationDB, LocKey
from miasm.expression.expression import Expr, ExprOp, ExprId, ExprLoc, \
                                        ExprInt, ExprMem, ExprCompose, \
                                        ExprSlice, ExprCond
from miasm.expression.simplifications import expr_simp_explicit

from .snapshot import ProgramState

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

# The expression simplifier used in this module
expr_simp = expr_simp_explicit
expr_simp.enable_passes({ExprOp: [simp_segm]})

class MiasmConcreteState:
    """Resolves atomic symbols to some state."""

    miasm_flag_aliases = {
        'NF':     'SF',
        'I_F':    'IF',
        'IOPL_F': 'IOPL',
        'I_D':    'ID',
    }

    def __init__(self, state: ProgramState, loc_db: LocationDB):
        self._state = state
        self._loc_db = loc_db

    def resolve_register(self, regname: str) -> int | None:
        regname = regname.upper()
        if regname in self.miasm_flag_aliases:
            regname = self.miasm_flag_aliases[regname]
        return self._state.read_register(regname)

    def resolve_memory(self, addr: int, size: int) -> bytes | None:
        return self._state.read_memory(addr, size)

    def resolve_location(self, loc: LocKey) -> int | None:
        return self._loc_db.get_location_offset(loc)

def eval_expr(expr: Expr, conc_state: MiasmConcreteState) -> Expr:
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

def _eval_exprid(expr: ExprId, state: MiasmConcreteState):
    """Evaluate an ExprId using the current state"""
    val = state.resolve_register(expr.name)
    if val is None:
        return expr
    if isinstance(val, int):
        return ExprInt(val, expr.size)
    return val

def _eval_exprloc(expr: ExprLoc, state: MiasmConcreteState):
    """Evaluate an ExprLoc using the current state"""
    offset = state.resolve_location(expr.loc_key)
    if offset is None:
        return expr
    return ExprInt(offset, expr.size)

def _eval_exprmem(expr: ExprMem, state: MiasmConcreteState):
    """Evaluate an ExprMem using the current state.
    This function first evaluates the memory pointer value.
    """
    # TODO: Implement cases with more than 64 bytes.
    #
    # The symbolic memory class used in SymbolicExecutionEngine may return
    # ExprCompose objects here. Maybe I should use that.
    assert(expr.size <= 64)
    assert(expr.size % 8 == 0)

    addr = eval_expr(expr.ptr, state)
    if not addr.is_int():
        return expr

    mem = state.resolve_memory(int(addr), int(expr.size / 8))
    if mem is None:
        return expr

    assert(len(mem) * 8 == expr.size)
    return ExprInt(int.from_bytes(mem), expr.size)

def _eval_exprcond(expr, state: MiasmConcreteState):
    """Evaluate an ExprCond using the current state"""
    cond = eval_expr(expr.cond, state)
    src1 = eval_expr(expr.src1, state)
    src2 = eval_expr(expr.src2, state)
    return ExprCond(cond, src1, src2)

def _eval_exprslice(expr, state: MiasmConcreteState):
    """Evaluate an ExprSlice using the current state"""
    arg = eval_expr(expr.arg, state)
    return ExprSlice(arg, expr.start, expr.stop)

def _eval_cpuid(rax: ExprInt, out_reg: ExprInt):
    """Evaluate the `x86_cpuid` operator by performing a real invocation of
    the CPUID instruction.

    :param rax:     The current value of RAX. Must be concrete.
    :param out_reg: An index in `[0, 4)` signaling which register's value
                    shall be returned. Must be concrete.
    """
    from cpuid import cpuid

    regs = cpuid.CPUID()(int(rax))

    if int(out_reg) >= len(regs):
        raise ValueError(f'Output register may not be {out_reg}.')
    return ExprInt(regs[int(out_reg)], out_reg.size)

def _eval_exprop(expr, state: MiasmConcreteState):
    """Evaluate an ExprOp using the current state"""
    args = []
    for oarg in expr.args:
        arg = eval_expr(oarg, state)
        args.append(arg)

    if expr.op == 'x86_cpuid':
        # Can't do this in an expression simplifier plugin because the
        # arguments must be concrete.
        assert(len(expr.args) == 2)
        return _eval_cpuid(args[0], args[1])
    return ExprOp(expr.op, *args)

def _eval_exprcompose(expr, state: MiasmConcreteState):
    """Evaluate an ExprCompose using the current state"""
    args = []
    for arg in expr.args:
        args.append(eval_expr(arg, state))
    return ExprCompose(*args)
