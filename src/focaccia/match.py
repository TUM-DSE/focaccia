"""Order-preserving matching of concrete state boundaries to symbolic transforms."""

from __future__ import annotations

from bisect import bisect_left
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .snapshot import ProgramState, RegisterAccessError
from .symbolic import (
    SymbolicTraceItem,
    SymbolicTransformComposer,
    TraceGap,
)
from .trace import (
    DiagnosticLevel,
    MaterializedTrace,
    TraceDiagnostic,
    TraceEnvironment,
    TransformStream,
    TransitionTrace,
)


@dataclass(frozen=True, slots=True)
class MatchedBoundary:
    """A retained concrete boundary and the transforms on either side of it."""

    concrete_index: int
    pc: int
    incoming: SymbolicTraceItem | None
    outgoing: SymbolicTraceItem | None


@dataclass(frozen=True, slots=True)
class MatchResult:
    """A cardinality-valid matched trace plus non-fatal/fatal diagnostics."""

    trace: TransitionTrace[ProgramState, SymbolicTraceItem] | None
    diagnostics: tuple[TraceDiagnostic, ...]
    pending_transform: SymbolicTraceItem | None = None

    @property
    def complete(self) -> bool:
        return self.trace is not None and all(
            diagnostic.level == "info" for diagnostic in self.diagnostics
        )


def _as_symbolic_trace(
    transforms: MaterializedTrace[SymbolicTraceItem]
    | TransformStream[SymbolicTraceItem]
    | Iterable[SymbolicTraceItem],
) -> MaterializedTrace[SymbolicTraceItem] | TransformStream[SymbolicTraceItem]:
    if isinstance(transforms, (MaterializedTrace, TransformStream)):
        return transforms

    items = tuple(transforms)
    architecture = items[0].arch.key if items else None
    environment = TraceEnvironment(
        None,
        (),
        (),
        binary_hash=None,
        architecture=architecture,
    )
    return MaterializedTrace(items, environment, [item.addr for item in items])


class TransitionMatcher:
    """Incrementally select concrete/symbolic cutpoints in execution order.

    The matcher consumes each symbolic transform at most once.  When a concrete
    state lands on a later symbolic boundary, every intervening transform is
    composed into one incoming transform rather than discarded.
    """

    def __init__(
        self,
        transforms: MaterializedTrace[SymbolicTraceItem]
        | TransformStream[SymbolicTraceItem]
        | Iterable[SymbolicTraceItem],
        *,
        stop_address: int | None = None,
        skip_unmatched: bool = False,
    ):
        self.trace = _as_symbolic_trace(transforms)
        self.environment = self.trace.env
        self.addresses = self.trace.require_addresses()
        source_positions: dict[int, list[int]] = {}
        for index, address in enumerate(self.addresses):
            source_positions.setdefault(address, []).append(index)
        self._source_positions = {
            address: tuple(positions) for address, positions in source_positions.items()
        }
        self._iterator = (
            self.trace.cursor() if isinstance(self.trace, MaterializedTrace) else self.trace
        )
        self._stop_address = self.environment.stop_address if stop_address is None else stop_address
        self._skip_unmatched = skip_unmatched

        self._diagnostics: list[TraceDiagnostic] = []
        self._next_transform_index = 0
        self._loaded_transforms: dict[int, SymbolicTraceItem] = {}
        self._current_index: int | None = None
        self._current: SymbolicTraceItem | None = None
        self._source_pc: int | None = None
        self._has_source = False
        self._has_boundary = False
        self._done = False
        self._finished = False
        self._concrete_count = 0
        self._extra_concrete_count = 0
        self._first_extra_concrete_index: int | None = None
        self._pending_transform: SymbolicTraceItem | None = None
        self._planned_destinations: dict[tuple[int, int], SymbolicTraceItem] = {}
        self._architecture = None
        self._thread_id: int | None = None

    @property
    def done(self) -> bool:
        return self._done

    @property
    def diagnostics(self) -> tuple[TraceDiagnostic, ...]:
        return tuple(self._diagnostics)

    @property
    def pending_transform(self) -> SymbolicTraceItem | None:
        return self._pending_transform

    @property
    def current_destination_pc(self) -> int | None:
        """Return the next symbolic destination from the retained source."""
        return self._current.range[1] if self._has_source and self._current is not None else None

    def plan_successors(self) -> tuple[SymbolicTraceItem, ...]:
        """Compose candidate observable ranges through one bounded basic block.

        QEMU may expose only a later boundary within the native execution's
        current basic block. Every intervening oracle destination is therefore
        a candidate until the executed control-flow instruction terminates the
        block. The persisted trace fixes the executed path; divergent emulator
        destinations remain unmatched and fail closed.
        """
        if self._done or not self._has_source:
            return ()
        assert self._current is not None
        assert self._current_index is not None
        planned: list[SymbolicTraceItem] = []
        previous: SymbolicTraceItem | None = None
        for end_index in range(self._current_index, len(self.addresses)):
            transform = self._read_transform(end_index)
            if transform is None:
                return tuple(planned)
            if previous is not None and previous.range[1] != transform.range[0]:
                self._fatal(
                    "symbolic-trace-discontinuous",
                    f"Candidate transform {end_index - 1} ends at "
                    f"{hex(previous.range[1])}, but transform {end_index} starts "
                    f"at {hex(transform.range[0])}.",
                    transform_index=end_index,
                )
                return tuple(planned)
            candidate = self.plan_destination(transform.range[1])
            if candidate is not None:
                planned.append(candidate)
            previous = transform
            if isinstance(transform, TraceGap):
                break
            if end_index > self._current_index and transform.instructions:
                underlying = getattr(transform.instructions[-1], "instr", None)
                if underlying is None or underlying.breakflow():
                    break
        return tuple(planned)

    def _diagnose(
        self,
        level: DiagnosticLevel,
        code: str,
        message: str,
        *,
        concrete_index: int | None = None,
        transform_index: int | None = None,
    ) -> None:
        self._diagnostics.append(
            TraceDiagnostic(
                level,
                code,
                message,
                concrete_index,
                transform_index,
            )
        )

    def _fatal(
        self,
        code: str,
        message: str,
        *,
        concrete_index: int | None = None,
        transform_index: int | None = None,
    ) -> None:
        self._diagnose(
            "error",
            code,
            message,
            concrete_index=concrete_index,
            transform_index=transform_index,
        )
        self._done = True
        self._has_source = False
        self._current = None
        self._current_index = None

    def _stop_incomplete(
        self,
        code: str,
        message: str,
        *,
        concrete_index: int | None = None,
        transform_index: int | None = None,
        pending: SymbolicTraceItem | None = None,
    ) -> None:
        self._diagnose(
            "incomplete",
            code,
            message,
            concrete_index=concrete_index,
            transform_index=transform_index,
        )
        self._pending_transform = pending
        self._done = True
        self._has_source = False
        self._current = None
        self._current_index = None

    def fail_concrete_state(self, index: int, error: Exception) -> None:
        self._concrete_count = max(self._concrete_count, index + 1)
        self._fatal(
            "concrete-pc-unavailable",
            f"Unable to read concrete state {index} program counter: {error}.",
            concrete_index=index,
            transform_index=self._current_index,
        )

    def _read_transform(self, index: int) -> SymbolicTraceItem | None:
        if index in self._loaded_transforms:
            return self._loaded_transforms[index]
        if index != self._next_transform_index:
            raise RuntimeError(
                f"Internal transform cursor mismatch: {index} != {self._next_transform_index}."
            )
        try:
            transform = next(self._iterator)
        except StopIteration:
            self._fatal(
                "symbolic-trace-truncated",
                f"Symbolic trace ended before transform {index}; "
                f"the address index declares {len(self.addresses)} transforms.",
                transform_index=index,
            )
            return None
        except Exception as error:
            self._fatal(
                "symbolic-trace-read-error",
                f"Unable to read symbolic transform {index}: {error}.",
                transform_index=index,
            )
            return None

        self._next_transform_index += 1
        expected_address = self.addresses[index]
        if transform.addr != expected_address:
            self._fatal(
                "symbolic-address-mismatch",
                f"Transform {index} starts at {hex(transform.addr)}, but its "
                f"address index contains {hex(expected_address)}.",
                transform_index=index,
            )
            return None

        if self._thread_id is None:
            self._thread_id = transform.tid
        elif transform.tid != self._thread_id:
            self._fatal(
                "unsupported-thread-transition",
                f"Transform {index} changes thread ID from {self._thread_id} to "
                f"{transform.tid}; concurrent traces are unsupported.",
                transform_index=index,
            )
            return None

        if self._architecture is None:
            self._architecture = transform.arch
            if (
                self.environment.architecture is not None
                and self.environment.architecture != transform.arch.key
            ):
                self._fatal(
                    "symbolic-architecture-mismatch",
                    f"Transform architecture {transform.arch} conflicts with "
                    f"trace environment {self.environment.architecture}.",
                    transform_index=index,
                )
                return None
        elif transform.arch != self._architecture:
            self._fatal(
                "symbolic-architecture-mismatch",
                f"Transform {index} has architecture {transform.arch}, expected "
                f"{self._architecture}.",
                transform_index=index,
            )
            return None
        self._loaded_transforms[index] = transform
        return transform

    def _verify_exhausted(self) -> None:
        try:
            next(self._iterator)
        except StopIteration:
            return
        except Exception as error:
            self._fatal(
                "symbolic-trace-read-error",
                f"Unable to verify symbolic trace exhaustion: {error}.",
                transform_index=self._next_transform_index,
            )
            return
        self._fatal(
            "symbolic-address-count-mismatch",
            "Symbolic trace contains transforms beyond its address index.",
            transform_index=self._next_transform_index,
        )

    def _find_address(self, start: int, pc: int) -> int | None:
        positions = self._source_positions.get(pc)
        if positions is None:
            return None
        offset = bisect_left(positions, start)
        return positions[offset] if offset < len(positions) else None

    def _load_initial_transform(self, target_index: int) -> SymbolicTraceItem | None:
        for index in range(self._next_transform_index, target_index + 1):
            transform = self._read_transform(index)
            if transform is None:
                return None
            if index == target_index:
                self._current_index = index
                self._current = transform
        for index in tuple(self._loaded_transforms):
            if index < target_index:
                del self._loaded_transforms[index]
        return self._current

    def _stop_at_boundary(self, transform_index: int, pc: int) -> None:
        skipped = len(self.addresses) - transform_index
        if skipped:
            self._diagnose(
                "info",
                "symbolic-suffix-outside-stop",
                f"Stopped at {hex(pc)} with {skipped} symbolic transforms "
                "outside the selected region.",
                transform_index=transform_index,
            )
        else:
            self._verify_exhausted()
        self._current = None
        self._current_index = None
        self._has_source = False
        self._done = True

    def _find_destination(
        self,
        start_index: int,
        pc: int,
        concrete_index: int,
    ) -> int | None:
        assert self._current is not None
        if self._current.range[1] == pc:
            return start_index

        # Every non-terminal destination is the following transform's source.
        # Consult the address index before decoding any additional transforms;
        # repeated PCs select the first occurrence after the current source.
        next_source = self._find_address(start_index + 1, pc)
        if next_source is not None:
            return next_source - 1

        # A persisted trace records its final destination separately because
        # the source-address index has one entry per transform. Composition
        # below still decodes and verifies every selected transform and checks
        # that the composed range really ends at this PC.
        terminal_index = len(self.addresses) - 1
        if self._stop_address == pc and terminal_index > start_index:
            return terminal_index

        if self._stop_address is not None:
            return None

        # Legacy/unbounded streams have no indexed terminal destination. Keep
        # their historical fallback, while bounded persisted traces avoid an
        # expensive full-suffix decode for every unmatched concrete state.
        previous: SymbolicTraceItem = self._current
        for index in range(start_index + 1, len(self.addresses)):
            transform = self._read_transform(index)
            if transform is None:
                return None
            if previous.range[1] != transform.range[0]:
                self._fatal(
                    "symbolic-trace-discontinuous",
                    f"Transform {index - 1} ends at {hex(previous.range[1])}, "
                    f"but transform {index} starts at {hex(transform.range[0])}.",
                    concrete_index=concrete_index,
                    transform_index=index,
                )
                return None
            if transform.range[1] == pc:
                return index
            previous = transform
        return None

    def _skip_through(
        self,
        end_index: int,
        concrete_index: int,
    ) -> TraceGap | None:
        assert self._current is not None
        assert self._current_index is not None
        start_index = self._current_index
        previous = self._current
        first_instruction = previous.instructions[0] if previous.instructions else None

        for index in range(start_index + 1, end_index + 1):
            transform = self._read_transform(index)
            if transform is None:
                return None
            if previous.range[1] != transform.range[0]:
                self._fatal(
                    "symbolic-trace-discontinuous",
                    f"Cannot skip transform {index - 1} ending at "
                    f"{hex(previous.range[1])} before transform {index} starting "
                    f"at {hex(transform.range[0])}.",
                    concrete_index=concrete_index,
                    transform_index=index,
                )
                return None
            if previous.tid != transform.tid:
                self._fatal(
                    "unsupported-thread-transition",
                    "Cannot skip transforms from different threads; concurrent "
                    "traces are unsupported.",
                    concrete_index=concrete_index,
                    transform_index=index,
                )
                return None
            previous = transform

        count = end_index - start_index + 1
        message = (
            f"Skipped {count} unmatched symbolic transforms from "
            f"{hex(self._current.range[0])} to {hex(previous.range[1])}; "
            "their semantics were not composed."
        )
        self._diagnose(
            "incomplete",
            "unmatched-symbolic-transforms-skipped",
            message,
            concrete_index=concrete_index,
            transform_index=start_index,
        )
        return TraceGap(
            self._current.tid,
            self._current.arch,
            self._current.range[0],
            previous.range[1],
            "unmatched-transform-skip",
            message,
            instruction=first_instruction,
        )

    def _compose_through(
        self,
        end_index: int,
        concrete_index: int,
    ) -> SymbolicTraceItem | None:
        assert self._current is not None
        assert self._current_index is not None
        if isinstance(self._current, TraceGap):
            if end_index != self._current_index:
                self._stop_incomplete(
                    "symbolic-gap-without-cutpoint",
                    f"Cannot compose across trace gap {self._current_index} without "
                    f"a concrete boundary at {hex(self._current.range[1])}.",
                    concrete_index=concrete_index,
                    transform_index=self._current_index,
                    pending=self._current,
                )
                return None
            self._diagnose(
                "incomplete",
                "symbolic-gap-retained",
                f"Retained explicit trace gap {self._current_index} "
                f"({self._current.reason}): {self._current.message}",
                concrete_index=concrete_index,
                transform_index=self._current_index,
            )
            return self._current

        if end_index == self._current_index:
            return self._current

        composer = SymbolicTransformComposer(self._current)
        previous: SymbolicTraceItem = self._current

        for index in range(self._current_index + 1, end_index + 1):
            transform = self._read_transform(index)
            if transform is None:
                return None
            if previous.range[1] != transform.range[0]:
                self._fatal(
                    "symbolic-trace-discontinuous",
                    f"Cannot compose transform {index - 1} ending at "
                    f"{hex(previous.range[1])} with transform {index} starting "
                    f"at {hex(transform.range[0])}.",
                    concrete_index=concrete_index,
                    transform_index=index,
                )
                return None
            if previous.tid != transform.tid:
                self._fatal(
                    "unsupported-thread-transition",
                    "Cannot compose transforms from different threads; "
                    "concurrent traces are unsupported.",
                    concrete_index=concrete_index,
                    transform_index=index,
                )
                return None
            if isinstance(transform, TraceGap):
                self._stop_incomplete(
                    "symbolic-gap-without-cutpoint",
                    f"Cannot compose across trace gap {index} without a concrete "
                    f"boundary at {hex(transform.range[0])}.",
                    concrete_index=concrete_index,
                    transform_index=index,
                    pending=transform,
                )
                return None
            try:
                composer.append(transform)
            except Exception as error:
                self._fatal(
                    "symbolic-composition-failed",
                    f"Unable to compose transform {index}: {error}.",
                    concrete_index=concrete_index,
                    transform_index=index,
                )
                return None
            previous = transform
        return composer.finish()

    def plan_destination(self, pc: int) -> SymbolicTraceItem | None:
        """Compose the current source through a backend-declared next cutpoint.

        Live emulator states cannot be read after execution advances. Backends
        therefore declare their next observable PC while still stopped, and
        the collector snapshots dependencies from this complete composition.
        The later observation must reach the same range or fail closed.
        """
        if self._done or not self._has_source:
            return None
        assert self._current is not None
        assert self._current_index is not None
        start_index = self._current_index
        end_index = self._find_destination(start_index, pc, self._concrete_count)
        if end_index is None:
            return None
        key = (start_index, end_index)
        cached = self._planned_destinations.get(key)
        if cached is not None:
            return cached
        planned = self._compose_through(end_index, self._concrete_count)
        if planned is not None:
            self._planned_destinations[key] = planned
        return planned

    def observe(self, pc: int) -> MatchedBoundary | None:
        concrete_index = self._concrete_count
        self._concrete_count += 1

        if self._done:
            if self._first_extra_concrete_index is None:
                self._first_extra_concrete_index = concrete_index
            self._extra_concrete_count += 1
            return None

        if not self.addresses:
            self._has_boundary = True
            self._diagnose(
                "incomplete",
                "symbolic-trace-empty",
                "The symbolic trace is empty; no concrete transition can be validated.",
                concrete_index=concrete_index,
            )
            self._verify_exhausted()
            self._done = True
            return MatchedBoundary(concrete_index, pc, None, None)

        if not self._has_source:
            target_index = self._find_address(self._next_transform_index, pc)
            if target_index is None:
                self._diagnose(
                    "info",
                    "concrete-state-skipped",
                    f"Concrete state {concrete_index} at {hex(pc)} is not a "
                    "remaining symbolic source boundary.",
                    concrete_index=concrete_index,
                    transform_index=self._next_transform_index,
                )
                if self._stop_address == pc:
                    self._diagnose(
                        "incomplete",
                        "stop-address-unmatched",
                        f"Concrete execution reached stop address {hex(pc)} without "
                        "a matching symbolic boundary.",
                        concrete_index=concrete_index,
                        transform_index=self._next_transform_index,
                    )
                    self._done = True
                return None

            skipped = target_index - self._next_transform_index
            if skipped:
                self._diagnose(
                    "info",
                    "symbolic-prefix-skipped",
                    f"Skipped {skipped} symbolic transforms before the first "
                    f"matching concrete boundary at {hex(pc)}.",
                    concrete_index=concrete_index,
                    transform_index=target_index,
                )
            current = self._load_initial_transform(target_index)
            if current is None:
                return None
            self._has_boundary = True
            self._source_pc = pc

            if self._stop_address == pc:
                self._stop_at_boundary(target_index, pc)
                return MatchedBoundary(concrete_index, pc, None, None)

            self._has_source = True
            return MatchedBoundary(concrete_index, pc, None, current)

        assert self._current is not None
        assert self._current_index is not None
        assert self._source_pc is not None
        start_index = self._current_index

        end_index = self._find_destination(start_index, pc, concrete_index)
        if end_index is None:
            if self._done:
                return None
            self._diagnose(
                "info",
                "concrete-state-skipped",
                f"Concrete state {concrete_index} at {hex(pc)} is not a "
                "reachable symbolic destination boundary.",
                concrete_index=concrete_index,
                transform_index=start_index,
            )
            if self._stop_address == pc:
                self._diagnose(
                    "incomplete",
                    "stop-address-unmatched",
                    f"Concrete execution reached stop address {hex(pc)} without "
                    "a matching symbolic destination.",
                    concrete_index=concrete_index,
                    transform_index=start_index,
                )
                self._pending_transform = self._current
                self._done = True
            return None

        planned = self._planned_destinations.get((start_index, end_index))
        if end_index > start_index and self._skip_unmatched:
            incoming = self._skip_through(end_index, concrete_index)
        elif planned is not None:
            incoming = planned
        else:
            incoming = self._compose_through(end_index, concrete_index)
        if incoming is None:
            return None
        if incoming.range != (self._source_pc, pc):
            self._fatal(
                "symbolic-trace-discontinuous",
                f"Composed transform range {incoming.range!r} does not connect "
                f"retained concrete boundaries {hex(self._source_pc)} and {hex(pc)}.",
                concrete_index=concrete_index,
                transform_index=start_index,
            )
            return None

        composed_count = end_index - start_index + 1
        if composed_count > 1:
            self._diagnose(
                "info",
                "symbolic-transforms-composed",
                f"Composed {composed_count} symbolic transforms between concrete "
                f"cutpoints {hex(self._source_pc)} and {hex(pc)}.",
                concrete_index=concrete_index,
                transform_index=start_index,
            )

        next_index = end_index + 1
        for index in range(start_index, end_index + 1):
            self._loaded_transforms.pop(index, None)
        outgoing: SymbolicTraceItem | None = None
        self._current = None
        self._current_index = None
        self._planned_destinations.clear()

        if self._stop_address == pc:
            self._stop_at_boundary(next_index, pc)
        elif next_index < len(self.addresses):
            outgoing = self._read_transform(next_index)
            if outgoing is not None:
                if incoming.range[1] != outgoing.range[0]:
                    self._fatal(
                        "symbolic-trace-discontinuous",
                        f"Transform {end_index} ends at {hex(incoming.range[1])}, "
                        f"but transform {next_index} starts at "
                        f"{hex(outgoing.range[0])}.",
                        concrete_index=concrete_index,
                        transform_index=next_index,
                    )
                    outgoing = None
                else:
                    self._current = outgoing
                    self._current_index = next_index
                    self._source_pc = pc
                    self._has_source = True
        else:
            self._verify_exhausted()
            if not self._done:
                self._done = True
            self._has_source = False

        return MatchedBoundary(concrete_index, pc, incoming, outgoing)

    def finish(self) -> None:
        if self._finished:
            return
        self._finished = True

        if self._concrete_count == 0:
            self._diagnose(
                "incomplete",
                "concrete-trace-empty",
                "The concrete trace has no state boundary.",
                transform_index=self._current_index or 0,
            )
        elif self._has_source and not self._done:
            assert self._current is not None
            self._pending_transform = self._current
            self._diagnose(
                "incomplete",
                "unmatched-terminal-transition",
                f"Concrete execution ended at source boundary {hex(self._source_pc or 0)} "
                f"before transform {self._current_index} reached destination "
                f"{hex(self._current.range[1])}.",
                concrete_index=self._concrete_count - 1,
                transform_index=self._current_index,
            )
            self._done = True
        elif not self._has_boundary and not self._done:
            self._diagnose(
                "incomplete",
                "no-matching-boundary",
                "No concrete state matched a symbolic source boundary.",
                transform_index=self._next_transform_index,
            )
            self._done = True

        if self._extra_concrete_count:
            self._diagnose(
                "info",
                "concrete-suffix-skipped",
                f"Ignored {self._extra_concrete_count} concrete states after "
                "symbolic matching completed.",
                concrete_index=self._first_extra_concrete_index,
            )

    def make_result(
        self,
        states: Sequence[ProgramState],
        transforms: Sequence[SymbolicTraceItem],
    ) -> MatchResult:
        self.finish()
        trace = None
        if states:
            try:
                trace = TransitionTrace(states, transforms, self.environment)
            except ValueError as error:
                self._diagnose(
                    "error",
                    "matched-trace-cardinality",
                    str(error),
                )
        return MatchResult(trace, self.diagnostics, self._pending_transform)


def match_transitions(
    concrete_states: Iterable[ProgramState],
    symbolic_transforms: MaterializedTrace[SymbolicTraceItem]
    | TransformStream[SymbolicTraceItem]
    | Iterable[SymbolicTraceItem],
    *,
    skip_unmatched: bool = False,
) -> MatchResult:
    """Match materialized concrete states to symbolic transitions."""
    matcher = TransitionMatcher(symbolic_transforms, skip_unmatched=skip_unmatched)
    retained_states: list[ProgramState] = []
    retained_transforms: list[SymbolicTraceItem] = []

    for concrete_index, state in enumerate(concrete_states):
        try:
            pc = state.read_pc()
        except RegisterAccessError as error:
            matcher.fail_concrete_state(concrete_index, error)
            break

        boundary = matcher.observe(pc)
        if boundary is None:
            continue
        if boundary.incoming is None:
            if retained_states:
                matcher._fatal(
                    "unexpected-initial-boundary",
                    "Matcher produced a second initial boundary.",
                    concrete_index=concrete_index,
                )
                break
            retained_states.append(state)
            continue

        if not retained_states:
            matcher._fatal(
                "missing-source-boundary",
                "Matcher produced a destination without a retained source state.",
                concrete_index=concrete_index,
            )
            break
        retained_transforms.append(boundary.incoming)
        retained_states.append(state)

    return matcher.make_result(retained_states, retained_transforms)


def match_traces(
    ctrace: Sequence[ProgramState],
    strace: Sequence[SymbolicTraceItem],
) -> tuple[list[ProgramState], list[SymbolicTraceItem]]:
    """Compatibility wrapper around the shared non-mutating matcher."""
    result = match_transitions(ctrace, strace)
    if result.trace is None:
        return [], []
    return list(result.trace.state_boundaries), list(result.trace.transforms)


def fold_traces(
    ctrace: Sequence[ProgramState],
    strace: Sequence[SymbolicTraceItem],
) -> tuple[list[ProgramState], list[SymbolicTraceItem]]:
    """Compatibility alias for adaptive matching; inputs are never mutated."""
    return match_traces(ctrace, strace)
