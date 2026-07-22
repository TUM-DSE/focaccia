from miasm.expression.expression import ExprId, ExprInt

from focaccia.arch import x86
from focaccia.compare import (
    ErrorTypes,
    ValidationReport,
    compare_simple,
    compare_symbolic,
)
from focaccia.snapshot import ProgramState
from focaccia.symbolic import SymbolicTransform
from focaccia.trace import TraceEnvironment, TransitionTrace
from focaccia.utils import print_result


ARCH = x86.ArchX86()
ENV = TraceEnvironment(
    None,
    (),
    (),
    binary_hash=None,
    architecture=ARCH.key,
)


def state(pc: int, rax: int = 0) -> ProgramState:
    result = ProgramState(ARCH)
    result.write_register("PC", pc)
    result.write_register("RAX", rax)
    return result


def assign_rax(start: int, end: int, value: int) -> SymbolicTransform:
    return SymbolicTransform(
        1,
        {ExprId("RAX", 64): ExprInt(value, 64)},
        [],
        ARCH,
        start,
        end,
    )


def diagnostic_codes(report: ValidationReport) -> set[str]:
    return {diagnostic.code for diagnostic in report.diagnostics}


def test_compare_symbolic_validates_the_final_transition():
    states = [state(0x1000, 1), state(0x1001, 2), state(0x1002, 3)]
    transforms = [assign_rax(0x1000, 0x1001, 2), assign_rax(0x1001, 0x1002, 3)]
    trace = TransitionTrace(states, transforms, ENV)

    report = compare_symbolic(trace)

    assert len(report) == 2
    assert [entry["pc"] for entry in report] == [0x1000, 0x1001]
    assert all(entry["errors"] == [] for entry in report)
    assert report.diagnostics == ()


def test_single_transition_produces_one_comparison_result():
    trace = TransitionTrace(
        [state(0x1000, 1), state(0x1001, 2)],
        [assign_rax(0x1000, 0x1001, 2)],
        ENV,
    )

    report = compare_symbolic(trace)

    assert len(report) == 1
    assert report[0]["pc"] == 0x1000
    assert report[0]["errors"] == []


def test_mismatch_in_final_transition_is_not_dropped():
    trace = TransitionTrace(
        [state(0x1000, 1), state(0x1001, 2), state(0x1002, 99)],
        [assign_rax(0x1000, 0x1001, 2), assign_rax(0x1001, 0x1002, 3)],
        ENV,
    )

    report = compare_symbolic(trace)

    assert len(report) == 2
    final_errors = report[-1]["errors"]
    assert len(final_errors) == 1
    assert final_errors[0].severity == ErrorTypes.CONFIRMED


def test_compare_symbolic_reports_empty_and_unequal_shapes():
    empty = compare_symbolic([], [])
    missing_destination = compare_symbolic(
        [state(0x1000)],
        [assign_rax(0x1000, 0x1001, 2)],
    )
    extra_destination = compare_symbolic(
        [state(0x1000), state(0x1001), state(0x1002)],
        [assign_rax(0x1000, 0x1001, 2)],
    )

    assert len(empty) == 0
    assert "empty-state-trace" in diagnostic_codes(empty)
    assert "transition-trace-cardinality" in diagnostic_codes(missing_destination)
    assert "transition-trace-cardinality" in diagnostic_codes(extra_destination)


def test_zero_transition_trace_is_valid_and_empty():
    report = compare_symbolic(TransitionTrace([state(0x1000)], [], ENV))

    assert len(report) == 0
    assert report.diagnostics == ()


def test_range_mismatch_is_a_structured_error_not_a_printed_skip(capsys):
    trace = TransitionTrace(
        [state(0x1000), state(0x1002)],
        [assign_rax(0x1000, 0x1001, 0)],
        ENV,
    )

    report = compare_symbolic(trace)

    assert len(report) == 1
    assert "transition-range-mismatch" in diagnostic_codes(report)
    assert report[0]["errors"][0].severity == ErrorTypes.INCOMPLETE
    assert capsys.readouterr().out == ""


def test_compare_simple_rejects_unequal_lengths_without_zip_truncation(capsys):
    report = compare_simple(
        [state(0x1000), state(0x1001)],
        [state(0x1000)],
    )

    assert len(report) == 0
    assert "concrete-trace-cardinality" in diagnostic_codes(report)
    assert capsys.readouterr().out == ""


def test_compare_simple_rejects_unmatched_initial_boundaries():
    report = compare_simple(
        [state(0x1000), state(0x1001)],
        [state(0x2000), state(0x1001)],
    )

    assert len(report) == 0
    assert "concrete-pc-mismatch" in diagnostic_codes(report)


def test_compare_simple_handles_two_empty_traces():
    report = compare_simple([], [])

    assert len(report) == 0
    assert "empty-concrete-traces" in diagnostic_codes(report)


def test_result_renderer_does_not_report_shape_failure_as_clean(capsys):
    report = compare_symbolic([], [])

    print_result(report, ErrorTypes.INFO)
    output = capsys.readouterr().out

    assert "empty-state-trace" in output
    assert "Found 1 trace diagnostics." in output
