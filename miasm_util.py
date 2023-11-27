from miasm.core.locationdb import LocationDB, LocKey
from miasm.expression.expression import Expr, ExprOp, ExprId, ExprLoc, \
                                        ExprInt, ExprMem, ExprCompose, \
                                        ExprSlice, ExprCond
from miasm.expression.simplifications import expr_simp_explicit

from snapshot import ProgramState

class MiasmConcreteState:
    miasm_flag_aliases = {
        'NF':     'SF',
        'I_F':    'IF',
        'IOPL_F': 'IOPL',
        'I_D':    'ID',
    }

    def __init__(self, state: ProgramState, loc_db: LocationDB):
        self.state = state
        self.loc_db = loc_db

    def resolve_register(self, regname: str) -> int:
        regname = regname.upper()
        if regname in self.miasm_flag_aliases:
            regname = self.miasm_flag_aliases[regname]
        return self.state.read(regname)

    def resolve_memory(self, addr: int, size: int) -> bytes:
        return self.state.read_memory(addr, size)

    def resolve_location(self, loc: LocKey) -> int | None:
        return self.loc_db.get_location_offset(loc)

def eval_expr(expr: Expr, conc_state: MiasmConcreteState) -> int:
    # Most of these implementation are just copy-pasted members of
    # `SymbolicExecutionEngine`.
    expr_to_visitor = {
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
    ret = expr_simp_explicit(ret)
    assert(ret is not None)

    return ret

def _eval_exprint(expr: ExprInt, _):
    """Evaluate an ExprInt using the current state"""
    return expr

def _eval_exprid(expr: ExprId, state: MiasmConcreteState):
    """Evaluate an ExprId using the current state"""
    val = state.resolve_register(expr.name)
    return ExprInt(val, expr.size)

def _eval_exprloc(expr: ExprLoc, state: MiasmConcreteState):
    """Evaluate an ExprLoc using the current state"""
    offset = state.resolve_location(expr.loc_key)
    if offset is not None:
        return ExprInt(offset, expr.size)
    return expr

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
    ret = state.resolve_memory(int(addr), int(expr.size / 8))
    assert(len(ret) * 8 == expr.size)
    return ExprInt(int.from_bytes(ret, byteorder='little'), expr.size)

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

def _eval_exprop(expr, state: MiasmConcreteState):
    """Evaluate an ExprOp using the current state"""
    args = []
    for oarg in expr.args:
        arg = eval_expr(oarg, state)
        args.append(arg)
    return ExprOp(expr.op, *args)

def _eval_exprcompose(expr, state: MiasmConcreteState):
    """Evaluate an ExprCompose using the current state"""
    args = []
    for arg in expr.args:
        args.append(eval_expr(arg, state))
    return ExprCompose(*args)
