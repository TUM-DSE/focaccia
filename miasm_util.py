from angr_targets.memory_map import MemoryMap
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import Expr, ExprOp, ExprId, ExprLoc, \
                                        ExprInt, ExprMem, ExprCompose, \
                                        ExprSlice, ExprCond
from miasm.expression.simplifications import expr_simp_explicit

class MiasmProgramState:
    def __init__(self,
                 regs: dict[ExprId, ExprInt],
                 mem: list[tuple[MemoryMap, bytes]]
                 ):
        self.regs = regs
        self.memory = mem

    def _find_mem_map(self, addr: int) \
            -> tuple[MemoryMap, bytes] | tuple[None, None]:
        for m, data in self.memory:
            if addr >= m.start_address and addr < m.end_address:
                return m, data
        return None, None

    def read_memory(self, addr: int, size: int) -> bytes:
        res = bytes()
        while size > 0:
            m, data = self._find_mem_map(addr)
            if m is None:
                raise AttributeError(f'No memory mapping contains the address {addr}.')

            assert(m is not None and data is not None)
            read_off = addr - m.start_address
            read_size = min(size, m.end_address - addr)
            assert(read_off + read_size <= len(data))
            res += data[read_off:read_off+read_size]

            size -= read_size
            addr += read_size
        return res

def eval_expr(expr: Expr, conc_state: MiasmProgramState, loc_db) -> int:
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

    ret = visitor(expr, conc_state, loc_db)
    ret = expr_simp_explicit(ret)
    assert(ret is not None)

    return ret

def _eval_exprint(expr: ExprInt, _, __: LocationDB):
    """Evaluate an ExprInt using the current state"""
    return expr

def _eval_exprid(expr: ExprId, state: MiasmProgramState, _):
    """Evaluate an ExprId using the current state"""
    return state.regs[expr]

def _eval_exprloc(expr: ExprLoc, _, loc_db: LocationDB):
    """Evaluate an ExprLoc using the current state"""
    offset = loc_db.get_location_offset(expr.loc_key)
    if offset is not None:
        return ExprInt(offset, expr.size)
    return expr

def _eval_exprmem(expr: ExprMem, state: MiasmProgramState, loc_db: LocationDB):
    """Evaluate an ExprMem using the current state.
    This function first evaluates the memory pointer value.
    """
    # TODO: Implement cases with more than 64 bytes.
    #
    # The symbolic memory class used in SymbolicExecutionEngine may return
    # ExprCompose objects here. Maybe I should use that.
    assert(expr.size <= 64)
    assert(expr.size % 8 == 0)

    addr = eval_expr(expr.ptr, state, loc_db)
    ret = state.read_memory(int(addr), int(expr.size / 8))
    assert(len(ret) * 8 == expr.size)
    return ExprInt(int.from_bytes(ret, byteorder='little'), expr.size)

def _eval_exprcond(expr, state: MiasmProgramState, loc_db: LocationDB):
    """Evaluate an ExprCond using the current state"""
    cond = eval_expr(expr.cond, state, loc_db)
    src1 = eval_expr(expr.src1, state, loc_db)
    src2 = eval_expr(expr.src2, state, loc_db)
    return ExprCond(cond, src1, src2)

def _eval_exprslice(expr, state: MiasmProgramState, loc_db: LocationDB):
    """Evaluate an ExprSlice using the current state"""
    arg = eval_expr(expr.arg, state, loc_db)
    return ExprSlice(arg, expr.start, expr.stop)

def _eval_exprop(expr, state: MiasmProgramState, loc_db: LocationDB):
    """Evaluate an ExprOp using the current state"""
    args = []
    for oarg in expr.args:
        arg = eval_expr(oarg, state, loc_db)
        args.append(arg)
    return ExprOp(expr.op, *args)

def _eval_exprcompose(expr, state: MiasmProgramState, loc_db: LocationDB):
    """Evaluate an ExprCompose using the current state"""
    args = []
    for arg in expr.args:
        args.append(eval_expr(arg, state, loc_db))
    return ExprCompose(*args)
