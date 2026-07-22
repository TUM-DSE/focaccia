from miasm.expression.expression import ExprId, ExprInt

from focaccia.arch import x86
from focaccia.compare import ErrorTypes, compare_symbolic
from focaccia.match import match_transitions
from focaccia.snapshot import ProgramState
from focaccia.symbolic import SymbolicTransform, TraceGap
from focaccia.trace import MaterializedTrace, TraceEnvironment


ARCH = x86.ArchX86()
ENVIRONMENT = TraceEnvironment(
    None,
    (),
    (),
    binary_hash=None,
    architecture=ARCH.key,
)


def state(pc: int, *, rax: int = 0) -> ProgramState:
    result = ProgramState(ARCH)
    result.write_register("RIP", pc)
    result.write_register("RAX", rax)
    return result


def transform(start: int, end: int, value: int) -> SymbolicTransform:
    return SymbolicTransform(
        1,
        {ExprId("RAX", 64): ExprInt(value, 64)},
        [],
        ARCH,
        start,
        end,
    )


def gap(start: int, end: int) -> TraceGap:
    error = NotImplementedError("unsupported fixture instruction")
    return TraceGap(
        1,
        ARCH,
        start,
        end,
        "unsupported-semantics",
        str(error),
        cause=error,
    )


def diagnostic_codes(result) -> set[str]:
    return {diagnostic.code for diagnostic in result.diagnostics}


def test_gap_is_retained_and_later_validation_resumes_at_exact_cutpoint():
    unknown = gap(0x1000, 0x1001)
    known = transform(0x1001, 0x1002, 7)
    symbolic = MaterializedTrace(
        [unknown, known],
        ENVIRONMENT,
        [0x1000, 0x1001],
    )

    matched = match_transitions(
        [state(0x1000), state(0x1001), state(0x1002, rax=7)],
        symbolic,
    )

    assert matched.trace is not None
    assert list(matched.trace.transforms) == [unknown, known]
    assert "symbolic-gap-retained" in diagnostic_codes(matched)

    report = compare_symbolic(matched.trace, diagnostics=matched.diagnostics)
    assert "symbolic-trace-gap" in diagnostic_codes(report)
    assert report[0]["errors"][0].severity == ErrorTypes.INCOMPLETE
    assert report[1]["errors"] == []


def test_gap_cannot_be_composed_away_without_its_concrete_cutpoint():
    symbolic = MaterializedTrace(
        [gap(0x1000, 0x1001), transform(0x1001, 0x1002, 7)],
        ENVIRONMENT,
        [0x1000, 0x1001],
    )

    matched = match_transitions(
        [state(0x1000), state(0x1002, rax=7)],
        symbolic,
    )

    assert matched.trace is not None
    assert len(matched.trace.transforms) == 0
    assert "symbolic-gap-without-cutpoint" in diagnostic_codes(matched)
    assert matched.pending_transform is symbolic[0]


def test_gap_preserves_the_original_exception_and_addresses():
    cause = RuntimeError("lift failed")
    unknown = TraceGap(
        4,
        ARCH,
        0x2000,
        0x2004,
        "unsupported-semantics",
        str(cause),
        cause=cause,
    )

    assert unknown.addr == 0x2000
    assert unknown.range == (0x2000, 0x2004)
    assert unknown.cause is cause
    assert unknown.cause_type == "builtins.RuntimeError"
