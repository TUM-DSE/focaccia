"""Interpreter for claripy ASTs"""

from inspect import signature
from logging import debug

import claripy as cp

class SymbolResolver:
    def __init__(self):
        pass

    def resolve(self, symbol_name: str) -> cp.ast.Base:
        raise NotImplementedError()

class SymbolResolveError(Exception):
    def __init__(self, symbol, reason: str = ""):
        super().__init__(f'Unable to resolve symbol name \"{symbol}\" to a'
                         ' concrete value'
                         + f': {reason}' if len(reason) > 0 else '.')

def eval(resolver: SymbolResolver, expr) -> int:
    """Evaluate a claripy expression to a concrete value.

    :param resolver: A `SymbolResolver` implementation that can resolve symbol
                     names to concrete values.
    :param expr:     The claripy AST to evaluate. Should be a subclass of
                     `claripy.ast.Base`.

    :return: A concrete value if the expression was resolved successfully.
             If `expr` is not a claripy AST, `expr` is returned immediately.
    :raise NotImplementedError:
    :raise SymbolResolveError: If `resolver` is not able to resolve a symbol.
    """
    if not issubclass(type(expr), cp.ast.Base):
        return expr

    if expr.depth == 1:
        if expr.symbolic:
            name = expr._encoded_name.decode()
            val = resolver.resolve(name)
            if val is None:
                raise SymbolResolveError(name)
            return eval(resolver, val)
        else: # if expr.concrete
            assert(expr.concrete)
            return expr.v

    # Expression is a non-trivial AST, i.e. a function
    return _eval_op(resolver, expr.op, *expr.args)

def _eval_op(resolver: SymbolResolver, op, *args) -> int:
    """Evaluate a claripy operator expression.

    :param *args: Arguments to the function `op`. These are NOT evaluated yet!
    """
    assert(type(op) is str)

    def concat(*vals):
        res = 0
        for val in vals:
            assert(type(val) is cp.ast.BV)
            res = res << val.length
            res = res | eval(resolver, val)
        return res

    # Handle claripy's operators
    if op == 'Concat':
        res = concat(*args)
        debug(f'Concatenating {args} to {hex(res)}')
        return res
    if op == 'Extract':
        assert(len(args) == 3)
        start, end, val = (eval(resolver, arg) for arg in args)
        size = start - end + 1
        res = (val >> end) & ((1 << size) - 1)
        debug(f'Extracing range [{start}, {end}] from {hex(val)}: {hex(res)}')
        return res
    if op == 'If':
        assert(len(args) == 3)
        cond, iftrue, iffalse = (eval(resolver, arg) for arg in args)
        debug(f'Evaluated branch condition {args[0]} to {cond}')
        return iftrue if bool(cond) else iffalse
    if op == 'Reverse':
        assert(len(args) == 1)
        return concat(*reversed(args[0].chop(8)))

    # `op` is not one of claripy's special operators, so treat it as the name
    # of a python operator function (because that is how claripy names its OR,
    # EQ, etc.)

    # Convert some of the non-python names to magic names
    # NOTE: We use python's signed comparison operators for unsigned
    #       comparisons. I'm not sure that this is legal.
    if op in ['SGE', 'SGT', 'SLE', 'SLT', 'UGE', 'UGT', 'ULE', 'ULT']:
        op = '__' + op[1:].lower() + '__'

    if op in ['And', 'Or']:
        op =  '__' + op.lower() + '__'

    resolved_args = [eval(resolver, arg) for arg in args]
    try:
        func = getattr(int, op)
    except AttributeError:
        raise NotImplementedError(op)

    # Sometimes claripy doesn't build its AST in an arity-respecting way if
    # adjacent operations are associative. For example, it might pass five
    # arguments to an XOR function instead of nesting the AST deeper.
    #
    # That's why we have to check with the python function's signature for its
    # number of arguments and manually apply parentheses.
    sig = signature(func)
    assert(len(args) >= len(sig.parameters))

    debug(f'Trying to evaluate function {func} with arguments {resolved_args}')
    if len(sig.parameters) == len(args):
        return func(*resolved_args)
    else:
        # Fold parameters from left by successively applying `op` to a
        # subset of them
        return _eval_op(resolver,
                       op,
                       func(*resolved_args[0:len(sig.parameters)]),
                       *resolved_args[len(sig.parameters):]
                       )
