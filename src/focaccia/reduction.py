"""Resumable concrete evaluation of cached specification-derived residuals.

A session belongs to one immutable entry boundary. It never reads live memory:
missing source bytes are yielded to the caller, which must capture them before
releasing that boundary. Ordered predicted writes are an oracle-only overlay.
"""
from dataclasses import dataclass

from miasm.expression.expression import (
    ExprCompose, ExprCond, ExprId, ExprInt, ExprMem, ExprOp, ExprSlice,
)
from miasm.expression.simplifications import expr_simp

from focaccia.miasm_util import eval_expr
from focaccia.snapshot import RegisterAccessError
from focaccia.symbolic import (
    SymbolEvaluationError, _DEFERRED_MEMORY_BYTE_OP, _TransformEvaluator,
    expression_children,
)


@dataclass(frozen=True)
class MemoryRequest:
    address: int
    size: int


class ReductionSession:
    """Single-occurrence continuation; reuse residual expressions, not sessions.

    ``run`` yields exact source-memory requests and accepts immutable bytes via
    ``send``. Its return value is the tuple of concrete expression results.
    Completed DAG nodes survive suspension. Only the selected conditional arm
    is evaluated. Limits fail closed rather than dropping dependencies.
    """

    def __init__(self, expressions, state, writes=(), *, max_nodes=100000,
                 max_requests=4096, max_bytes=1048576, max_write_depth=128):
        self.expressions = tuple(expressions)
        self.writes = tuple(writes)
        self.max_nodes = max_nodes
        self.max_requests = max_requests
        self.max_bytes = max_bytes
        self.max_write_depth = max_write_depth
        self.endianness = state.arch.endianness
        self.source = {}
        self.results = {}
        self.registers = {}
        self.register_errors = {}
        self.versions = {}
        self.indexed = 0
        self.building = []
        self.requests = 0
        self.bytes_captured = 0
        self.bytes_forwarded = 0
        self.nodes_evaluated = 0
        self.started = False
        self.closed = False
        # Freeze register inputs before any suspension; never consult exit state.
        resolver = _TransformEvaluator(state, [])
        seen = set()
        pending = list(self.expressions)
        for write in self.writes:
            pending.extend((write.address, write.value))
        while pending:
            node = pending.pop()
            if id(node) in seen:
                continue
            seen.add(id(node))
            if len(seen) > max_nodes:
                raise SymbolEvaluationError("Residual node budget exceeded")
            register_leaf = isinstance(node, ExprId) or (
                isinstance(node, ExprSlice) and isinstance(node.arg, ExprId)
            )
            if register_leaf:
                # A snapshot can contain only Wn or selected status bits. Do
                # not require the unknown remainder of its canonical register.
                try:
                    value = expr_simp(eval_expr(node, resolver))
                    if not isinstance(value, ExprInt):
                        raise SymbolEvaluationError("Missing residual register input")
                    self.registers[id(node)] = value
                except (RegisterAccessError, ValueError, KeyError) as error:
                    self.register_errors[id(node)] = error
                continue
            pending.extend(expression_children(node))

    def close(self):
        """Seal this occurrence; no further evidence may be requested."""
        self.closed = True

    def _memory(self, address, size):
        if self.closed:
            raise SymbolEvaluationError("Reduction session is sealed")
        if size <= 0 or size > self.max_bytes:
            raise SymbolEvaluationError("Invalid or over-budget memory request")
        offset = 0
        while offset < size:
            if address + offset in self.source:
                offset += 1
                continue
            start = offset
            while offset < size and address + offset not in self.source:
                offset += 1
            count = offset - start
            if (self.requests >= self.max_requests
                    or self.bytes_captured + count > self.max_bytes):
                raise SymbolEvaluationError("Source-memory budget exceeded")
            self.requests += 1
            data = yield MemoryRequest(address + start, count)
            if self.closed:
                raise SymbolEvaluationError("Evidence supplied after sealing")
            if not isinstance(data, bytes) or len(data) != count:
                raise SymbolEvaluationError("Missing or malformed source-memory evidence")
            self.source.update((address + start + i, byte) for i, byte in enumerate(data))
            self.bytes_captured += count
        return bytes(self.source[address + i] for i in range(size))

    def _deferred(self, address, prefix):
        if prefix > len(self.writes):
            raise SymbolEvaluationError("Invalid ordered-write prefix")
        if self.building and prefix > self.building[-1]:
            raise SymbolEvaluationError("Cyclic ordered-write dependency")
        while self.indexed < prefix:
            index = self.indexed
            if len(self.building) >= self.max_write_depth:
                raise SymbolEvaluationError("Ordered-write depth budget exceeded")
            self.building.append(index)
            try:
                write = self.writes[index]
                pointer = int((yield from self._evaluate(write.address)))
                value = int((yield from self._evaluate(write.value)))
            finally:
                self.building.pop()
            if self.bytes_forwarded + write.size_bytes > self.max_bytes:
                raise SymbolEvaluationError("Ordered-write byte budget exceeded")
            data = value.to_bytes(write.size_bytes, self.endianness)
            self.bytes_forwarded += len(data)
            for i, byte in enumerate(data):
                self.versions.setdefault(pointer + i, []).append((index + 1, byte))
            self.indexed += 1
        for version, byte in reversed(self.versions.get(address, ())):
            if version <= prefix:
                return byte
        return (yield from self._memory(address, 1))[0]

    def _evaluate(self, expression):
        pending = [(expression, False)]
        while pending:
            if self.closed:
                raise SymbolEvaluationError("Reduction session is sealed")
            node, expanded = pending.pop()
            key = id(node)
            if key in self.results:
                continue
            if key in self.register_errors:
                raise SymbolEvaluationError("Missing residual register input") from self.register_errors[key]
            if key in self.registers:
                result = self.registers[key]
            elif isinstance(node, ExprCond):
                if id(node.cond) not in self.results:
                    pending.extend(((node, False), (node.cond, False)))
                    continue
                branch = node.src1 if int(self.results[id(node.cond)]) else node.src2
                if id(branch) not in self.results:
                    pending.extend(((node, True), (branch, False)))
                    continue
                result = self.results[id(branch)]
            else:
                children = expression_children(node)
                if not expanded:
                    pending.append((node, True))
                    pending.extend((child, False) for child in reversed(children)
                                   if id(child) not in self.results)
                    continue
                args = tuple(self.results[id(child)] for child in children)
                if isinstance(node, ExprInt):
                    result = node
                elif isinstance(node, ExprId):
                    result = self.registers[key]
                elif isinstance(node, ExprMem):
                    if node.size % 8:
                        raise SymbolEvaluationError("Non-byte memory access")
                    data = yield from self._memory(int(args[0]), node.size // 8)
                    result = ExprInt(int.from_bytes(data, self.endianness), node.size)
                elif isinstance(node, ExprSlice):
                    result = expr_simp(ExprSlice(args[0], node.start, node.stop))
                elif isinstance(node, ExprCompose):
                    result = expr_simp(ExprCompose(*args))
                elif isinstance(node, ExprOp):
                    if node.op == _DEFERRED_MEMORY_BYTE_OP:
                        if len(args) != 2:
                            raise SymbolEvaluationError("Malformed deferred byte")
                        result = ExprInt((yield from self._deferred(
                            int(args[0]), int(args[1]))), node.size)
                    else:
                        result = expr_simp(ExprOp(node.op, *args))
                else:
                    raise SymbolEvaluationError("Unsupported residual expression")
            if not isinstance(result, ExprInt):
                raise SymbolEvaluationError("Unsupported concrete residual operation")
            self.results[key] = result
            self.nodes_evaluated += 1
        return self.results[id(expression)]

    def run(self):
        if self.started or self.closed:
            raise SymbolEvaluationError("Reduction session cannot be reused")
        self.started = True
        try:
            values = []
            for expression in self.expressions:
                values.append(int((yield from self._evaluate(expression))))
            return tuple(values)
        finally:
            self.close()
