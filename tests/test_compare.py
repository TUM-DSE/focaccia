from typing import cast

from miasm.expression.expression import ExprId, ExprInt, ExprMem, ExprOp

from focaccia.arch import aarch64, x86
from focaccia.compare import (
    ErrorTypes,
    ValidationReport,
    compare_simple,
    compare_symbolic,
)
from focaccia.snapshot import ProgramState
from focaccia.symbolic import Instruction, SymbolicTransform
from focaccia.trace import TraceDiagnostic, TraceEnvironment, TransitionTrace
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


def errors_with_severity(report: ValidationReport, severity) -> list:
    return [
        error
        for entry in report
        for error in entry["errors"]
        if error.severity == severity
    ]


class InstructionStub:
    def to_string(self) -> str:
        return "XGETBV"


def memory_write(start: int, end: int, address, value) -> SymbolicTransform:
    return SymbolicTransform(
        1,
        {ExprMem(address, value.size): value},
        [],
        ARCH,
        start,
        end,
    )


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
    source = state(0x1000, 1)
    transform = assign_rax(0x1000, 0x1001, 2)
    trace = TransitionTrace(
        [source, state(0x1001, 2)],
        [transform],
        ENV,
    )

    report = compare_symbolic(trace)

    assert len(report) == 1
    assert set(report[0]) == {"pc", "txl", "ref", "errors", "snap"}
    assert report[0]["pc"] == 0x1000
    assert report[0]["ref"] is transform
    assert report[0]["snap"] is source
    assert report[0]["errors"] == []
    assert report[0]["txl"].read_register("RAX") == 1


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


def test_compare_simple_classifies_each_asymmetric_empty_trace_as_cardinality_error():
    for tested, reference in (([], [state(0x1000)]), ([state(0x1000)], [])):
        report = compare_simple(tested, reference)

        assert len(report) == 0
        assert len(report.diagnostics) == 1
        assert report.diagnostics[0].level == "error"
        assert report.diagnostics[0].code == "concrete-trace-cardinality"
        assert "tested=" in report.diagnostics[0].message
        assert "reference=" in report.diagnostics[0].message


def test_validation_report_with_entry_is_immutable_and_preserves_diagnostics():
    first = {"pc": 0x1000}
    second = {"pc": 0x1001}
    diagnostic = TraceDiagnostic("info", "example", "example diagnostic")
    report = ValidationReport([first], [diagnostic])

    extended = report.with_entry(second)

    assert tuple(report) == (first,)
    assert tuple(extended) == (first, second)
    assert extended.diagnostics == (diagnostic,)


def test_result_renderer_does_not_report_shape_failure_as_clean(capsys):
    report = compare_symbolic([], [])

    print_result(report, ErrorTypes.INFO)
    output = capsys.readouterr().out

    assert "empty-state-trace" in output
    assert "Found 1 trace diagnostics." in output


def test_compare_simple_reports_initial_and_later_unavailable_pcs():
    missing_initial = ProgramState(ARCH)
    initial_report = compare_simple([missing_initial], [state(0x1000)])

    assert len(initial_report) == 0
    assert diagnostic_codes(initial_report) == {"concrete-pc-unavailable"}
    assert initial_report.diagnostics[0].concrete_index == 0

    missing_later = ProgramState(ARCH)
    missing_later.write_register("RAX", 2)
    later_report = compare_simple(
        [state(0x1000, 1), missing_later],
        [state(0x1000, 1), state(0x1001, 2)],
    )

    assert len(later_report) == 1
    assert diagnostic_codes(later_report) == {"concrete-pc-unavailable"}
    assert later_report.diagnostics[0].concrete_index == 1


def test_compare_simple_rejects_initial_and_mid_trace_architecture_changes():
    arm_initial = ProgramState(aarch64.ArchAArch64("little"))
    arm_initial.write_register("PC", 0x1000)
    initial_report = compare_simple([state(0x1000)], [arm_initial])

    assert len(initial_report) == 0
    assert diagnostic_codes(initial_report) == {"concrete-architecture-mismatch"}

    arm_later = ProgramState(aarch64.ArchAArch64("little"))
    arm_later.write_register("PC", 0x1001)
    later_report = compare_simple(
        [state(0x1000), arm_later],
        [state(0x1000), state(0x1001)],
    )

    assert len(later_report) == 1
    assert diagnostic_codes(later_report) == {"concrete-architecture-mismatch"}
    assert later_report.diagnostics[0].concrete_index == 1


def test_compare_simple_stops_at_a_later_pc_mismatch():
    report = compare_simple(
        [state(0x1000), state(0x1001)],
        [state(0x1000), state(0x2001)],
    )

    assert len(report) == 1
    assert diagnostic_codes(report) == {"concrete-pc-mismatch"}
    assert report.diagnostics[0].concrete_index == 1


def test_compare_simple_classifies_register_delta_mismatches():
    report = compare_simple(
        [state(0x1000, 1), state(0x1001, 7)],
        [state(0x1000, 1), state(0x1001, 8)],
    )

    confirmed = errors_with_severity(report, ErrorTypes.CONFIRMED)
    assert len(report) == 2
    assert len(confirmed) == 1
    assert "register RAX" in confirmed[0].error_msg
    assert "Expected difference: 0x7" in confirmed[0].error_msg
    assert "actual difference in the translation: 0x6" in confirmed[0].error_msg


def test_symbolic_register_validation_distinguishes_missing_inputs_and_outputs():
    missing_memory = SymbolicTransform(
        1,
        {ExprId("RAX", 64): ExprMem(ExprInt(0x2000, 64), 64)},
        [],
        ARCH,
        0x1000,
        0x1001,
    )
    memory_report = compare_symbolic(
        TransitionTrace(
            [state(0x1000), state(0x1001)],
            [missing_memory],
            ENV,
        )
    )
    assert len(errors_with_severity(memory_report, ErrorTypes.POSSIBLE)) == 1
    assert "not entirely present in the tested source state" in memory_report[0]["errors"][0].error_msg

    missing_register = SymbolicTransform(
        1,
        {ExprId("RAX", 64): ExprId("RBX", 64)},
        [],
        ARCH,
        0x1000,
        0x1001,
    )
    register_report = compare_symbolic(
        TransitionTrace(
            [state(0x1000), state(0x1001)],
            [missing_register],
            ENV,
        )
    )
    assert len(errors_with_severity(register_report, ErrorTypes.INCOMPLETE)) == 1
    assert "unavailable register RBX" in register_report[0]["errors"][0].error_msg

    destination = ProgramState(ARCH)
    destination.write_register("PC", 0x1001)
    output_report = compare_symbolic(
        TransitionTrace(
            [state(0x1000), destination],
            [assign_rax(0x1000, 0x1001, 42)],
            ENV,
        )
    )
    assert len(errors_with_severity(output_report, ErrorTypes.INCOMPLETE)) == 1
    assert "RAX changed but is unavailable" in output_report[0]["errors"][0].error_msg


def test_microarchitecture_dependent_register_mismatch_is_not_confirmed():
    arch = x86.ArchX86()
    source = ProgramState(arch)
    source.write_register("PC", 0x1000)
    source.write_register("RAX", 0)
    destination = ProgramState(arch)
    destination.write_register("PC", 0x1001)
    destination.write_register("RAX", 2)
    instruction = cast(Instruction, InstructionStub())
    transform = SymbolicTransform(
        1,
        {ExprId("RAX", 64): ExprInt(1, 64)},
        [instruction],
        arch,
        0x1000,
        0x1001,
    )
    environment = TraceEnvironment(None, (), (), binary_hash=None, architecture=arch.key)

    report = compare_symbolic(TransitionTrace([source, destination], [transform], environment))

    assert len(errors_with_severity(report, ErrorTypes.POSSIBLE)) == 1
    assert errors_with_severity(report, ErrorTypes.CONFIRMED) == []
    assert "microarchitecture-specific register RAX" in report[0]["errors"][0].error_msg


def test_microarchitecture_dependent_missing_register_is_explicitly_incomplete():
    arch = x86.ArchX86()
    source = ProgramState(arch)
    source.write_register("PC", 0x1000)
    destination = ProgramState(arch)
    destination.write_register("PC", 0x1001)
    destination.write_register("RAX", 0)
    instruction = cast(Instruction, InstructionStub())
    transform = SymbolicTransform(
        1,
        {ExprId("RAX", 64): ExprId("RBX", 64)},
        [instruction],
        arch,
        0x1000,
        0x1001,
    )
    environment = TraceEnvironment(None, (), (), binary_hash=None, architecture=arch.key)

    report = compare_symbolic(TransitionTrace([source, destination], [transform], environment))

    assert len(errors_with_severity(report, ErrorTypes.INCOMPLETE)) == 1
    assert "microarchitecturally-dependent register RBX" in report[0]["errors"][0].error_msg


def test_symbolic_memory_validation_classifies_missing_and_incorrect_destinations():
    transform = memory_write(
        0x1000,
        0x1001,
        ExprInt(0x2000, 64),
        ExprInt(0xBEEF, 16),
    )

    unavailable = compare_symbolic(
        TransitionTrace([state(0x1000), state(0x1001)], [transform], ENV)
    )
    assert len(errors_with_severity(unavailable, ErrorTypes.POSSIBLE)) == 1
    assert "Memory range [0x2000, 0x2002) is unavailable" in unavailable[0]["errors"][0].error_msg

    wrong_destination = state(0x1001)
    wrong_destination.write_memory(0x2000, b"\x00\x00")
    mismatch = compare_symbolic(
        TransitionTrace([state(0x1000), wrong_destination], [transform], ENV)
    )
    assert len(errors_with_severity(mismatch, ErrorTypes.CONFIRMED)) == 1
    assert "Expected efbe, actual 0000" in mismatch[0]["errors"][0].error_msg

    correct_destination = state(0x1001)
    correct_destination.write_memory(0x2000, b"\xef\xbe")
    accepted = compare_symbolic(
        TransitionTrace([state(0x1000), correct_destination], [transform], ENV)
    )
    assert accepted[0]["errors"] == []


def test_symbolic_memory_validation_fails_closed_on_unavailable_dependencies():
    missing_memory = memory_write(
        0x1000,
        0x1001,
        ExprInt(0x2000, 64),
        ExprMem(ExprInt(0x3000, 64), 16),
    )
    memory_report = compare_symbolic(
        TransitionTrace([state(0x1000), state(0x1001)], [missing_memory], ENV)
    )
    assert len(errors_with_severity(memory_report, ErrorTypes.INCOMPLETE)) == 1
    assert "not entirely present in the tested source state" in memory_report[0]["errors"][0].error_msg

    missing_register = memory_write(
        0x1000,
        0x1001,
        ExprId("RBX", 64),
        ExprInt(0x42, 8),
    )
    register_report = compare_symbolic(
        TransitionTrace([state(0x1000), state(0x1001)], [missing_register], ENV)
    )
    assert len(errors_with_severity(register_report, ErrorTypes.INCOMPLETE)) == 1
    assert "unavailable register RBX" in register_report[0]["errors"][0].error_msg

    environment_address = ExprOp("x86_cpuid", ExprInt(0, 64), ExprInt(0, 64))
    unresolved_environment = memory_write(
        0x1000,
        0x1001,
        environment_address,
        ExprInt(0x42, 8),
    )
    environment_report = compare_symbolic(
        TransitionTrace(
            [state(0x1000), state(0x1001)],
            [unresolved_environment],
            ENV,
        )
    )
    assert len(errors_with_severity(environment_report, ErrorTypes.INCOMPLETE)) == 1
    assert "unresolved environment symbol" in environment_report[0]["errors"][0].error_msg


def test_symbolic_comparison_reports_boundary_and_architecture_failures():
    source_without_pc = ProgramState(ARCH)
    source_without_pc.write_register("RAX", 0)
    missing_pc = compare_symbolic(
        TransitionTrace(
            [source_without_pc, state(0x1001)],
            [assign_rax(0x1000, 0x1001, 0)],
            ENV,
        )
    )

    assert diagnostic_codes(missing_pc) == {"transition-pc-unavailable"}
    assert missing_pc[0]["txl"] is None
    assert missing_pc[0]["errors"][0].severity == ErrorTypes.INCOMPLETE

    arm_destination = ProgramState(aarch64.ArchAArch64("little"))
    arm_destination.write_register("PC", 0x1001)
    mixed = compare_symbolic(
        TransitionTrace(
            [state(0x1000), arm_destination],
            [assign_rax(0x1000, 0x1001, 0)],
            ENV,
        )
    )

    assert diagnostic_codes(mixed) == {"transition-architecture-mismatch"}
    assert mixed[0]["txl"] is None
    assert mixed[0]["errors"][0].severity == ErrorTypes.INCOMPLETE


def test_symbolic_comparison_accepts_valid_legacy_iterables_and_rejects_transform_only_input():
    transform = assign_rax(0x1000, 0x1001, 2)
    accepted = compare_symbolic(
        [state(0x1000, 1), state(0x1001, 2)],
        [transform],
    )

    assert len(accepted) == 1
    assert accepted[0]["errors"] == []
    assert accepted.diagnostics == ()

    transform_only = compare_symbolic([], [transform])

    assert len(transform_only) == 0
    assert diagnostic_codes(transform_only) == {
        "empty-state-trace",
        "transition-trace-cardinality",
    }


def test_symbolic_comparison_rejects_duplicate_transform_input_and_retains_diagnostics():
    trace = TransitionTrace(
        [state(0x1000), state(0x1001)],
        [assign_rax(0x1000, 0x1001, 0)],
        ENV,
    )
    duplicate = compare_symbolic(trace, trace.transforms)

    assert len(duplicate) == 0
    assert diagnostic_codes(duplicate) == {"duplicate-transform-input"}

    prior = TraceDiagnostic("info", "fixture-context", "fixture diagnostic")
    retained = compare_symbolic([], [], diagnostics=[prior])

    assert retained.diagnostics[0] is prior
    assert diagnostic_codes(retained) == {"fixture-context", "empty-state-trace"}
