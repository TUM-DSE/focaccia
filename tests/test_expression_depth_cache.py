from miasm.core.locationdb import LocationDB
from miasm.expression.expression import ExprId, ExprInt

from focaccia import miasm_util
from focaccia.arch.x86 import ArchX86
from focaccia.snapshot import ProgramState


def test_depth_memo_reuses_shared_subtrees_without_structural_rescans(monkeypatch):
    root = ExprId("RAX", 64)
    for _ in range(80):
        root = root + ExprInt(1, 64)
    calls = 0
    original = miasm_util.expression_children

    def children(expression):
        nonlocal calls
        calls += 1
        return original(expression)

    monkeypatch.setattr(miasm_util, "expression_children", children)
    memo = {}
    assert miasm_util.expression_depth(root, _cache=memo) == 80
    measured = calls
    assert miasm_util.expression_depth(root ^ ExprInt(7, 64), _cache=memo) == 81
    assert calls - measured <= 4
    assert all(id(expression) == key for key, (expression, _) in memo.items())


def test_explicit_resolved_memo_reuses_nodes_in_one_immutable_context():
    state = ProgramState(ArchX86())
    state.write_register("RAX", 12)

    class CountingResolver(miasm_util.MiasmSymbolResolver):
        reads = 0

        def resolve_register(self, name):
            self.reads += 1
            return super().resolve_register(name)

    resolver = CountingResolver(state, LocationDB())
    shared = ExprId("RAX", 64) + ExprInt(7, 64)
    memo = {}
    assert int(miasm_util.eval_expr(shared, resolver, _resolved=memo)) == 19
    reads = resolver.reads
    assert int(miasm_util.eval_expr(shared ^ ExprInt(3, 64), resolver, _resolved=memo)) == 16
    assert resolver.reads == reads
    assert all(id(expression) == key for key, (expression, _) in memo.items())


def test_eval_depth_memo_does_not_cache_mutable_state_values():
    state = ProgramState(ArchX86())
    resolver = miasm_util.MiasmSymbolResolver(state, LocationDB())
    expression = (ExprId("RAX", 64) + ExprInt(7, 64)) ^ ExprInt(3, 64)
    for value in (1, 100, 0xffffffffffffffff):
        state.write_register("RAX", value)
        actual = miasm_util.eval_expr(expression, resolver)
        assert int(actual) == (((value + 7) & (2**64 - 1)) ^ 3)
