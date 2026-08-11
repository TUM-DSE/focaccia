from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from typing import Any, overload

from .snapshot import MemoryAccessError, ProgramState, RegisterAccessError
from .symbolic import (
    SymbolEvaluationError,
    SymbolicTraceItem,
    SymbolicTransform,
    TraceGap,
)
from .trace import (
    DiagnosticLevel,
    TraceDiagnostic,
    TraceEnvironment,
    TransitionTrace,
)
from .utils import ErrorSeverity


class ErrorTypes:
    INFO = ErrorSeverity(0, "INFO")
    INCOMPLETE = ErrorSeverity(2, "INCOMPLETE DATA")
    POSSIBLE = ErrorSeverity(4, "UNCONFIRMED ERROR")
    CONFIRMED = ErrorSeverity(5, "ERROR")


class Error:
    """A state comparison error."""

    def __init__(self, severity: ErrorSeverity, msg: str):
        self.severity = severity
        self.error_msg = msg

    def __repr__(self) -> str:
        return f"{self.severity} {self.error_msg}"


ComparisonEntry = dict[str, Any]


class ValidationReport(Sequence[ComparisonEntry]):
    """Comparison entries plus structured non-entry diagnostics."""

    def __init__(
        self,
        entries: Iterable[ComparisonEntry] = (),
        diagnostics: Iterable[TraceDiagnostic] = (),
    ):
        self.entries = tuple(entries)
        self.diagnostics = tuple(diagnostics)

    def __len__(self) -> int:
        return len(self.entries)

    @overload
    def __getitem__(self, index: int) -> ComparisonEntry: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[ComparisonEntry, ...]: ...

    def __getitem__(
        self, index: int | slice
    ) -> ComparisonEntry | tuple[ComparisonEntry, ...]:
        return self.entries[index]

    def __iter__(self) -> Iterator[ComparisonEntry]:
        return iter(self.entries)

    def with_entry(self, entry: ComparisonEntry) -> ValidationReport:
        return ValidationReport((*self.entries, entry), self.diagnostics)


def _diagnostic(
    level: DiagnosticLevel,
    code: str,
    message: str,
    *,
    concrete_index: int | None = None,
    transform_index: int | None = None,
) -> TraceDiagnostic:
    return TraceDiagnostic(
        level,
        code,
        message,
        concrete_index,
        transform_index,
    )


def _calc_transformation(previous: ProgramState, current: ProgramState) -> ProgramState:
    """Calculate known register differences between two context blocks."""
    if previous.arch != current.arch:
        raise ValueError(
            f"Cannot compare state architectures {previous.arch} and {current.arch}."
        )

    transformation = ProgramState(previous.arch)
    for reg in previous.arch.regnames:
        try:
            prev_val = previous.read_register(reg)
            cur_val = current.read_register(reg)
            transformation.write_register(reg, cur_val - prev_val)
        except RegisterAccessError:
            pass
    return transformation


def _find_errors(
    transform_txl: ProgramState,
    transform_truth: ProgramState,
) -> list[Error]:
    """Find differing known register transformations."""
    if transform_truth.arch != transform_txl.arch:
        return [
            Error(
                ErrorTypes.INCOMPLETE,
                "Unable to compare register differences from different architectures.",
            )
        ]

    errors = []
    for reg in transform_truth.arch.regnames:
        try:
            diff_txl = transform_txl.read_register(reg)
            diff_truth = transform_truth.read_register(reg)
        except RegisterAccessError:
            errors.append(
                Error(
                    ErrorTypes.INFO,
                    "Unable to calculate difference: value for register "
                    f"{reg} is not set in either the tested or reference state.",
                )
            )
            continue

        if diff_txl != diff_truth:
            errors.append(
                Error(
                    ErrorTypes.CONFIRMED,
                    f"Transformation of register {reg} is false. Expected "
                    f"difference: {hex(diff_truth)}, actual difference in the "
                    f"translation: {hex(diff_txl)}.",
                )
            )
    return errors


def compare_simple(
    test_states: Iterable[ProgramState],
    truth_states: Iterable[ProgramState],
) -> ValidationReport:
    """Compare equal-length concrete state traces without silent truncation."""
    tested = tuple(test_states)
    truth = tuple(truth_states)
    diagnostics: list[TraceDiagnostic] = []

    if not tested and not truth:
        diagnostics.append(
            _diagnostic(
                "incomplete",
                "empty-concrete-traces",
                "Both concrete traces are empty; no transition can be compared.",
            )
        )
        return ValidationReport(diagnostics=diagnostics)
    if len(tested) != len(truth):
        diagnostics.append(
            _diagnostic(
                "error",
                "concrete-trace-cardinality",
                "Concrete trace lengths differ: "
                f"tested={len(tested)}, reference={len(truth)}.",
            )
        )
        return ValidationReport(diagnostics=diagnostics)
    entries: list[ComparisonEntry] = []
    try:
        initial_pc = tested[0].read_pc()
        initial_truth_pc = truth[0].read_pc()
    except RegisterAccessError as error:
        diagnostics.append(
            _diagnostic(
                "error",
                "concrete-pc-unavailable",
                f"Unable to read an initial concrete PC: {error}.",
                concrete_index=0,
            )
        )
        return ValidationReport(diagnostics=diagnostics)
    if tested[0].arch != truth[0].arch:
        diagnostics.append(
            _diagnostic(
                "error",
                "concrete-architecture-mismatch",
                f"Initial concrete states have architectures {tested[0].arch} "
                f"and {truth[0].arch}.",
                concrete_index=0,
            )
        )
        return ValidationReport(diagnostics=diagnostics)
    if initial_pc != initial_truth_pc:
        diagnostics.append(
            _diagnostic(
                "incomplete",
                "concrete-pc-mismatch",
                f"Initial tested PC {hex(initial_pc)} does not match reference "
                f"PC {hex(initial_truth_pc)}.",
                concrete_index=0,
            )
        )
        return ValidationReport(diagnostics=diagnostics)

    entries.append(
        {
            "pc": initial_pc,
            "txl": tested[0],
            "ref": truth[0],
            "errors": [],
            "snap": tested[0],
        }
    )

    for index in range(1, len(tested)):
        previous_test = tested[index - 1]
        previous_truth = truth[index - 1]
        current_test = tested[index]
        current_truth = truth[index]
        try:
            pc_test = current_test.read_pc()
            pc_truth = current_truth.read_pc()
        except RegisterAccessError as error:
            diagnostics.append(
                _diagnostic(
                    "error",
                    "concrete-pc-unavailable",
                    f"Unable to read concrete PC at state {index}: {error}.",
                    concrete_index=index,
                )
            )
            break

        if pc_test != pc_truth:
            diagnostics.append(
                _diagnostic(
                    "incomplete",
                    "concrete-pc-mismatch",
                    f"Tested PC {hex(pc_test)} does not match reference PC "
                    f"{hex(pc_truth)} at state {index}.",
                    concrete_index=index,
                )
            )
            break
        if previous_test.arch != current_test.arch or previous_truth.arch != current_truth.arch:
            diagnostics.append(
                _diagnostic(
                    "error",
                    "concrete-architecture-mismatch",
                    f"Architecture changes across concrete transition {index - 1}.",
                    concrete_index=index,
                )
            )
            break

        transform_truth = _calc_transformation(previous_truth, current_truth)
        transform_test = _calc_transformation(previous_test, current_test)
        entries.append(
            {
                "pc": pc_test,
                "txl": transform_test,
                "ref": transform_truth,
                "errors": _find_errors(transform_test, transform_truth),
                "snap": previous_test,
            }
        )

    return ValidationReport(entries, diagnostics)


def _find_register_errors(
    txl_from: ProgramState,
    txl_to: ProgramState,
    transform_truth: SymbolicTransform,
    is_uarch_dep: bool,
) -> list[Error]:
    """Compare symbolic register outputs against a concrete destination."""
    try:
        truth = transform_truth.eval_validation_register_transforms(txl_from)
    except MemoryAccessError as error:
        start, end = transform_truth.range
        return [
            Error(
                ErrorTypes.POSSIBLE,
                f"Register transformations {hex(start)} -> {hex(end)} depend on "
                f"{error.mem_size} bytes at memory address {hex(error.mem_addr)} "
                "that are not entirely present in the tested source state.",
            )
        ]
    except SymbolEvaluationError as error:
        start, end = transform_truth.range
        return [
            Error(
                ErrorTypes.INCOMPLETE,
                f"Register transformations {hex(start)} -> {hex(end)} depend "
                f"on an unresolved environment symbol: {error}",
            )
        ]
    except RegisterAccessError as error:
        start, end = transform_truth.range
        if is_uarch_dep:
            return [
                Error(
                    ErrorTypes.INCOMPLETE,
                    f"Register transformations {hex(start)} -> {hex(end)} depend "
                    "on the unavailable microarchitecturally-dependent register "
                    f"{error.regname}.",
                )
            ]
        return [
            Error(
                ErrorTypes.INCOMPLETE,
                f"Register transformations {hex(start)} -> {hex(end)} depend on "
                f"the unavailable register {error.regname}.",
            )
        ]

    errors = []
    for regname, truth_val in truth.items():
        try:
            txl_val = txl_to.read_register(regname)
        except RegisterAccessError:
            errors.append(
                Error(
                    ErrorTypes.INCOMPLETE,
                    f"Value of register {regname} changed but is unavailable in "
                    "the tested destination state.",
                )
            )
            continue

        if txl_val == truth_val:
            continue
        if is_uarch_dep:
            errors.append(
                Error(
                    ErrorTypes.POSSIBLE,
                    f"Content of microarchitecture-specific register {regname} "
                    f"differs. Expected {hex(truth_val)}, actual {hex(txl_val)}.",
                )
            )
        else:
            errors.append(
                Error(
                    ErrorTypes.CONFIRMED,
                    f"Content of register {regname} is false. Expected "
                    f"{hex(truth_val)}, actual {hex(txl_val)}.",
                )
            )
    return errors


def _find_memory_errors(
    txl_from: ProgramState,
    txl_to: ProgramState,
    transform_truth: SymbolicTransform,
) -> list[Error]:
    """Compare symbolic memory outputs against a concrete destination."""
    try:
        truth = transform_truth.eval_memory_transforms(txl_from)
    except MemoryAccessError as error:
        start, end = transform_truth.range
        return [
            Error(
                ErrorTypes.INCOMPLETE,
                f"Memory transformations {hex(start)} -> {hex(end)} depend on "
                f"{error.mem_size} bytes at memory address {hex(error.mem_addr)} "
                "that are not entirely present in the tested source state.",
            )
        ]
    except SymbolEvaluationError as error:
        start, end = transform_truth.range
        return [
            Error(
                ErrorTypes.INCOMPLETE,
                f"Memory transformations {hex(start)} -> {hex(end)} depend "
                f"on an unresolved environment symbol: {error}",
            )
        ]
    except RegisterAccessError as error:
        start, end = transform_truth.range
        return [
            Error(
                ErrorTypes.INCOMPLETE,
                f"Memory transformations {hex(start)} -> {hex(end)} depend on "
                f"the unavailable register {error.regname}.",
            )
        ]

    errors = []
    for address, truth_bytes in truth.items():
        size = len(truth_bytes)
        try:
            txl_bytes = txl_to.read_memory(address, size)
        except MemoryAccessError:
            errors.append(
                Error(
                    ErrorTypes.POSSIBLE,
                    f"Memory range [{hex(address)}, {hex(address + size)}) is "
                    "unavailable in the tested destination state.",
                )
            )
            continue

        if txl_bytes != truth_bytes:
            errors.append(
                Error(
                    ErrorTypes.CONFIRMED,
                    f"Content of memory at {hex(address)} is false. Expected "
                    f"{truth_bytes.hex()}, actual {txl_bytes.hex()}.",
                )
            )
    return errors


def _find_errors_symbolic(
    txl_from: ProgramState,
    txl_to: ProgramState,
    transform_truth: SymbolicTransform,
) -> list[Error]:
    """Apply one symbolic transform to its concrete source/destination pair."""
    is_uarch_dep = any(
        txl_from.arch.is_instr_uarch_dep(instruction.to_string())
        for instruction in transform_truth.instructions
    )
    errors = []
    errors.extend(
        _find_register_errors(txl_from, txl_to, transform_truth, is_uarch_dep)
    )
    errors.extend(_find_memory_errors(txl_from, txl_to, transform_truth))
    return errors


def _coerce_transition_trace(
    test_states: TransitionTrace[ProgramState, SymbolicTraceItem]
    | Iterable[ProgramState]
    | None,
    transforms: Iterable[SymbolicTraceItem] | None,
) -> tuple[
    TransitionTrace[ProgramState, SymbolicTraceItem] | None,
    list[TraceDiagnostic],
]:
    diagnostics: list[TraceDiagnostic] = []
    if isinstance(test_states, TransitionTrace):
        if transforms is not None:
            diagnostics.append(
                _diagnostic(
                    "error",
                    "duplicate-transform-input",
                    "compare_symbolic received a TransitionTrace and a second "
                    "transform iterable.",
                )
            )
            return None, diagnostics
        return test_states, diagnostics

    states = tuple(test_states or ())
    symbolic = tuple(transforms or ())
    if not states:
        diagnostics.append(
            _diagnostic(
                "incomplete",
                "empty-state-trace",
                "Symbolic comparison requires at least one concrete state boundary.",
            )
        )
        if symbolic:
            diagnostics.append(
                _diagnostic(
                    "error",
                    "transition-trace-cardinality",
                    f"Received 0 states for {len(symbolic)} transforms.",
                )
            )
        return None, diagnostics
    if len(states) != len(symbolic) + 1:
        diagnostics.append(
            _diagnostic(
                "error",
                "transition-trace-cardinality",
                "Symbolic comparison requires exactly one more state than "
                f"transforms: {len(states)} != {len(symbolic)} + 1.",
            )
        )
        return None, diagnostics

    environment = TraceEnvironment(
        None,
        (),
        (),
        binary_hash=None,
        architecture=states[0].arch.key,
    )
    return TransitionTrace(states, symbolic, environment), diagnostics


def compare_symbolic(
    test_states: TransitionTrace[ProgramState, SymbolicTraceItem]
    | Iterable[ProgramState]
    | None,
    transforms: Iterable[SymbolicTraceItem] | None = None,
    *,
    diagnostics: Iterable[TraceDiagnostic] = (),
) -> ValidationReport:
    """Validate every transform against exactly two concrete state boundaries."""
    transition_trace, shape_diagnostics = _coerce_transition_trace(
        test_states, transforms
    )
    all_diagnostics = [*diagnostics, *shape_diagnostics]
    if transition_trace is None:
        return ValidationReport(diagnostics=all_diagnostics)

    entries: list[ComparisonEntry] = []
    for index, transition in enumerate(transition_trace):
        source = transition.source
        destination = transition.destination
        transform = transition.transform

        try:
            source_pc = source.read_pc()
            destination_pc = destination.read_pc()
        except RegisterAccessError as error:
            all_diagnostics.append(
                _diagnostic(
                    "error",
                    "transition-pc-unavailable",
                    f"Unable to read transition {index} boundary PC: {error}.",
                    concrete_index=index,
                    transform_index=index,
                )
            )
            entries.append(
                {
                    "pc": transform.addr,
                    "txl": None,
                    "ref": transform,
                    "errors": [
                        Error(
                            ErrorTypes.INCOMPLETE,
                            f"Transition boundary PC is unavailable: {error}.",
                        )
                    ],
                    "snap": source,
                }
            )
            continue

        entry_errors: list[Error] = []
        if source.arch != destination.arch or source.arch != transform.arch:
            message = (
                f"Transition {index} mixes architectures: source={source.arch}, "
                f"destination={destination.arch}, transform={transform.arch}."
            )
            all_diagnostics.append(
                _diagnostic(
                    "error",
                    "transition-architecture-mismatch",
                    message,
                    concrete_index=index,
                    transform_index=index,
                )
            )
            entry_errors.append(Error(ErrorTypes.INCOMPLETE, message))
        elif (source_pc, destination_pc) != transform.range:
            message = (
                f"Concrete transition [{hex(source_pc)} -> {hex(destination_pc)}] "
                f"does not match symbolic range [{hex(transform.range[0])} -> "
                f"{hex(transform.range[1])}]."
            )
            all_diagnostics.append(
                _diagnostic(
                    "error",
                    "transition-range-mismatch",
                    message,
                    concrete_index=index,
                    transform_index=index,
                )
            )
            entry_errors.append(Error(ErrorTypes.INCOMPLETE, message))
        elif isinstance(transform, TraceGap):
            message = (
                f"Symbolic semantics are unavailable for transition {index} "
                f"({transform.reason}): {transform.message}"
            )
            all_diagnostics.append(
                _diagnostic(
                    "incomplete",
                    "symbolic-trace-gap",
                    message,
                    concrete_index=index,
                    transform_index=index,
                )
            )
            entry_errors.append(Error(ErrorTypes.INCOMPLETE, message))
        else:
            entry_errors.extend(_find_errors_symbolic(source, destination, transform))

        try:
            concrete_transform = _calc_transformation(source, destination)
        except ValueError:
            concrete_transform = None
        entries.append(
            {
                "pc": source_pc,
                "txl": concrete_transform,
                "ref": transform,
                "errors": entry_errors,
                "snap": source,
            }
        )

    return ValidationReport(entries, all_diagnostics)
