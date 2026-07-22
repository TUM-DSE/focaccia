import sys
import types

import pytest
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import ExprId, ExprInt, ExprOp

from focaccia.arch import aarch64, x86
from focaccia.compare import ErrorTypes, compare_symbolic
from focaccia.miasm_util import MiasmSymbolResolver, eval_expr
from focaccia.snapshot import ProgramState
from focaccia.symbolic import SymbolEvaluationError, SymbolicTransform, eval_symbol
from focaccia.trace import TraceEnvironment, TransitionTrace


def test_cpuid_remains_an_explicit_environment_operation(monkeypatch):
    fake_cpuid = types.ModuleType("cpuid")

    class ForbiddenCpuid:
        def __init__(self):
            raise AssertionError("analyzer-host CPUID must not be queried")

    setattr(fake_cpuid, "CPUID", ForbiddenCpuid)
    monkeypatch.setitem(sys.modules, "cpuid", fake_cpuid)

    state = ProgramState(x86.ArchX86())
    expression = ExprOp("x86_cpuid", ExprInt(0, 64), ExprInt(0, 64))
    result = eval_expr(expression, MiasmSymbolResolver(state, LocationDB()))

    assert isinstance(result, ExprOp)
    assert result.op == "x86_cpuid"
    with pytest.raises(SymbolEvaluationError, match="remains unresolved"):
        eval_symbol(expression, state)


def test_unresolved_cpuid_makes_validation_incomplete_instead_of_crashing():
    arch = x86.ArchX86()
    source = ProgramState(arch)
    source.write_register("RIP", 0x1000)
    source.write_register("RAX", 0)
    destination = ProgramState(arch)
    destination.write_register("RIP", 0x1001)
    destination.write_register("RAX", 0)
    operation = ExprOp("x86_cpuid", ExprInt(0, 64), ExprInt(0, 64))
    transform = SymbolicTransform(
        1,
        {ExprId("RAX", 64): operation},
        [],
        arch,
        0x1000,
        0x1001,
    )
    trace = TransitionTrace(
        [source, destination],
        [transform],
        TraceEnvironment(None, (), (), binary_hash=None, architecture=arch.key),
    )

    report = compare_symbolic(trace)

    assert report[0]["errors"]
    assert report[0]["errors"][0].severity == ErrorTypes.INCOMPLETE
    assert "unresolved environment symbol" in report[0]["errors"][0].error_msg


def test_aarch64_dczid_has_no_analyzer_host_reader():
    arch = aarch64.ArchAArch64("little")

    assert arch.get_reg_reader("DCZID") is None
    assert arch.to_regname("DCZID_EL0") is None
