from typing import cast

from miasm.expression.expression import ExprId, ExprInt

from focaccia.arch import aarch64, x86
from focaccia.match import TransitionMatcher, fold_traces, match_traces, match_transitions
from focaccia.snapshot import ProgramState
from focaccia.symbolic import Instruction, SymbolicTransform, SymbolicTransformComposer
from focaccia.trace import MaterializedTrace, TraceEnvironment, TransformStream


ARCH = x86.ArchX86()


def environment(**kwargs) -> TraceEnvironment:
    return TraceEnvironment(
        None,
        (),
        (),
        binary_hash=None,
        architecture=ARCH.key,
        **kwargs,
    )


def state(pc: int) -> ProgramState:
    result = ProgramState(ARCH)
    result.write_register("PC", pc)
    return result


def transform(start: int, end: int, tid: int = 1) -> SymbolicTransform:
    return SymbolicTransform(tid, {}, [], ARCH, start, end)


def changing_transform(
    start: int,
    end: int,
    register: str,
    value: int,
) -> SymbolicTransform:
    return SymbolicTransform(
        1,
        {ExprId(register, 64): ExprInt(value, 64)},
        [],
        ARCH,
        start,
        end,
    )


def symbolic_trace(*transforms: SymbolicTransform, **env_kwargs) -> MaterializedTrace:
    return MaterializedTrace(
        transforms,
        environment(**env_kwargs),
        [item.addr for item in transforms],
    )


def diagnostic_codes(result) -> set[str]:
    return {diagnostic.code for diagnostic in result.diagnostics}


def test_linear_match_preserves_terminal_state_and_every_transform():
    states = [state(0x1000), state(0x1001), state(0x1002)]
    transforms = [transform(0x1000, 0x1001), transform(0x1001, 0x1002)]

    result = match_transitions(states, symbolic_trace(*transforms))

    assert result.complete
    assert result.trace is not None
    assert result.trace.state_boundaries == tuple(states)
    assert result.trace.transforms == tuple(transforms)
    assert [transition.destination for transition in result.trace] == states[1:]


def test_single_transform_keeps_both_state_boundaries():
    states = [state(0x1000), state(0x1001)]
    item = transform(0x1000, 0x1001)

    result = match_transitions(states, symbolic_trace(item))

    assert result.trace is not None
    assert len(result.trace) == 1
    assert result.trace[0].source is states[0]
    assert result.trace[0].destination is states[1]
    assert result.trace[0].transform is item


def test_repeated_pc_matching_is_ordered_and_composes_hidden_loop_body():
    transforms = [
        transform(0x1000, 0x1001),
        transform(0x1001, 0x1000),
        transform(0x1000, 0x1002),
    ]
    states = [state(0x1000), state(0x1000), state(0x1002)]

    result = match_transitions(states, symbolic_trace(*transforms))

    assert result.trace is not None
    assert [item.range for item in result.trace.transforms] == [
        (0x1000, 0x1000),
        (0x1000, 0x1002),
    ]
    assert "symbolic-transforms-composed" in diagnostic_codes(result)


def test_skipped_symbolic_interior_is_composed_without_mutating_inputs():
    first = transform(0x1000, 0x1001)
    second = transform(0x1001, 0x1002)
    before = [first.to_json(), second.to_json()]

    result = match_transitions(
        [state(0x1000), state(0x1002)],
        symbolic_trace(first, second),
    )

    assert result.trace is not None
    assert len(result.trace) == 1
    assert result.trace.transforms[0].range == (0x1000, 0x1002)
    assert result.trace.transforms[0] is not first
    assert [first.to_json(), second.to_json()] == before


def test_composed_cutpoint_retains_outputs_from_every_skipped_transform():
    result = match_transitions(
        [state(0x1000), state(0x1002)],
        symbolic_trace(
            changing_transform(0x1000, 0x1001, "RAX", 1),
            changing_transform(0x1001, 0x1002, "RBX", 2),
        ),
    )

    assert result.trace is not None
    composed = result.trace.transforms[0]
    assert isinstance(composed, SymbolicTransform)
    assert set(composed.changed_regs) == {"RAX", "RBX"}


def test_adaptive_matching_consumes_a_one_shot_transform_stream_once():
    materialized = symbolic_trace(
        transform(0x1000, 0x1001),
        transform(0x1001, 0x1002),
    )
    stream = materialized.cursor()

    result = match_transitions(
        [state(0x1000), state(0x1002)],
        stream,
    )

    assert result.trace is not None
    assert [item.range for item in result.trace.transforms] == [(0x1000, 0x1002)]
    assert stream.exhausted
    assert stream.position == 2


def test_bounded_unmatched_destination_does_not_decode_symbolic_suffix():
    transforms = tuple(transform(0x1000 + index, 0x1001 + index) for index in range(10_000))
    stream = TransformStream(
        iter(transforms),
        environment(stop_address=0x1000 + len(transforms)),
        [item.addr for item in transforms],
    )
    matcher = TransitionMatcher(stream)

    assert matcher.observe(0x1000) is not None
    assert stream.position == 1

    assert matcher.observe(0xDEAD) is None
    assert stream.position == 1
    assert not matcher.done

    boundary = matcher.observe(0x1001)
    assert boundary is not None
    assert boundary.incoming is transforms[0]
    assert stream.position == 2


def test_indexed_terminal_destination_composes_and_verifies_full_suffix():
    transforms = (
        transform(0x1000, 0x1001),
        transform(0x1001, 0x1002),
        transform(0x1002, 0x1003),
    )
    stream = TransformStream(
        iter(transforms),
        environment(stop_address=0x1003),
        [item.addr for item in transforms],
    )

    result = match_transitions([state(0x1000), state(0x1003)], stream)

    assert result.trace is not None
    assert [item.range for item in result.trace.transforms] == [(0x1000, 0x1003)]
    assert stream.position == len(transforms)
    assert stream.exhausted
    assert result.complete


def test_large_terminal_cutpoint_uses_one_incremental_composer(monkeypatch):
    transforms = tuple(
        changing_transform(
            0x1000 + index,
            0x1001 + index,
            "RAX",
            index,
        )
        for index in range(2_000)
    )
    instruction_markers = [cast(Instruction, object()) for _ in transforms]
    for item, marker in zip(transforms, instruction_markers, strict=True):
        item.instructions = [marker]
    append_calls = 0
    original_append = SymbolicTransformComposer.append

    def counted_append(self, item):
        nonlocal append_calls
        append_calls += 1
        return original_append(self, item)

    monkeypatch.setattr(SymbolicTransformComposer, "append", counted_append)
    stream = TransformStream(
        iter(transforms),
        environment(stop_address=0x1000 + len(transforms)),
        [item.addr for item in transforms],
    )

    result = match_transitions(
        [state(0x1000), state(0x1000 + len(transforms))],
        stream,
    )

    assert result.trace is not None
    assert result.complete
    assert result.trace.transforms[0].range == (0x1000, 0x1000 + len(transforms))
    assert append_calls == len(transforms)
    assert result.trace.transforms[0].instructions == instruction_markers
    assert stream.exhausted


def test_legacy_trace_without_stop_address_still_matches_terminal_destination():
    transforms = (
        transform(0x1000, 0x1001),
        transform(0x1001, 0x1002),
        transform(0x1002, 0x1003),
    )

    result = match_transitions(
        [state(0x1000), state(0x1003)],
        symbolic_trace(*transforms),
    )

    assert result.trace is not None
    assert [item.range for item in result.trace.transforms] == [(0x1000, 0x1003)]
    assert result.complete


def test_concrete_only_states_are_skipped_with_a_structured_diagnostic():
    result = match_transitions(
        [state(0x1000), state(0xDEAD), state(0x1001)],
        symbolic_trace(transform(0x1000, 0x1001)),
    )

    assert result.trace is not None
    assert [item.read_pc() for item in result.trace.state_boundaries] == [
        0x1000,
        0x1001,
    ]
    assert "concrete-state-skipped" in diagnostic_codes(result)
    assert result.complete


def test_unmatched_terminal_transition_remains_explicitly_pending():
    item = transform(0x1000, 0x1001)

    result = match_transitions([state(0x1000)], symbolic_trace(item))

    assert result.trace is not None
    assert len(result.trace.state_boundaries) == 1
    assert len(result.trace.transforms) == 0
    assert result.pending_transform is item
    assert "unmatched-terminal-transition" in diagnostic_codes(result)
    assert not result.complete


def test_empty_and_untyped_inputs_return_diagnostics_instead_of_overrunning():
    empty = match_transitions([], [])
    no_transforms = match_transitions([state(0x1000)], [])

    assert empty.trace is None
    assert "concrete-trace-empty" in diagnostic_codes(empty)
    assert no_transforms.trace is not None
    assert len(no_transforms.trace) == 0
    assert "symbolic-trace-empty" in diagnostic_codes(no_transforms)


def test_discontinuous_symbolic_ranges_fail_closed():
    result = match_transitions(
        [state(0x1000), state(0x2000)],
        symbolic_trace(
            transform(0x1000, 0x1001),
            transform(0x2000, 0x2001),
        ),
    )

    assert result.trace is not None
    assert len(result.trace) == 0
    assert "symbolic-trace-discontinuous" in diagnostic_codes(result)
    assert not result.complete


def test_thread_switches_are_rejected_as_unsupported():
    result = match_transitions(
        [state(0x1000), state(0x1001), state(0x1002)],
        symbolic_trace(
            transform(0x1000, 0x1001, tid=1),
            transform(0x1001, 0x1002, tid=2),
        ),
    )

    assert result.trace is not None
    assert len(result.trace) == 1
    assert "unsupported-thread-transition" in diagnostic_codes(result)
    assert not result.complete


def test_stop_address_is_retained_as_the_final_destination_boundary():
    transforms = [transform(0x1000, 0x1001), transform(0x1001, 0x1002)]
    result = match_transitions(
        [state(0x1000), state(0x1001), state(0x1002)],
        symbolic_trace(*transforms, stop_address=0x1001),
    )

    assert result.trace is not None
    assert [item.read_pc() for item in result.trace.state_boundaries] == [
        0x1000,
        0x1001,
    ]
    assert [item.range for item in result.trace.transforms] == [(0x1000, 0x1001)]
    assert "symbolic-suffix-outside-stop" in diagnostic_codes(result)


def test_symbolic_prefix_before_the_first_concrete_boundary_is_explicitly_skipped():
    first = transform(0x1000, 0x1001)
    second = transform(0x1001, 0x1002)

    result = match_transitions(
        [state(0x1001), state(0x1002)],
        symbolic_trace(first, second),
    )

    assert result.trace is not None
    assert result.trace.transforms == (second,)
    assert "symbolic-prefix-skipped" in diagnostic_codes(result)
    assert result.complete


def test_no_matching_boundary_and_unavailable_pc_fail_closed():
    unmatched = match_transitions(
        [state(0xDEAD), state(0xBEEF)],
        symbolic_trace(transform(0x1000, 0x1001)),
    )

    assert unmatched.trace is None
    assert "concrete-state-skipped" in diagnostic_codes(unmatched)
    assert "no-matching-boundary" in diagnostic_codes(unmatched)
    assert not unmatched.complete

    missing_pc = ProgramState(ARCH)
    unavailable = match_transitions(
        [missing_pc],
        symbolic_trace(transform(0x1000, 0x1001)),
    )

    assert unavailable.trace is None
    assert diagnostic_codes(unavailable) == {"concrete-pc-unavailable"}
    assert not unavailable.complete


def test_unmatched_stop_addresses_preserve_incomplete_state():
    source_stop = match_transitions(
        [state(0xDEAD)],
        symbolic_trace(transform(0x1000, 0x1001), stop_address=0xDEAD),
    )

    assert source_stop.trace is None
    assert "stop-address-unmatched" in diagnostic_codes(source_stop)
    assert not source_stop.complete

    item = transform(0x1000, 0x1001)
    destination_stop = match_transitions(
        [state(0x1000), state(0xDEAD)],
        symbolic_trace(item, stop_address=0xDEAD),
    )

    assert destination_stop.trace is not None
    assert len(destination_stop.trace) == 0
    assert destination_stop.pending_transform is item
    assert "stop-address-unmatched" in diagnostic_codes(destination_stop)
    assert not destination_stop.complete


def test_concrete_suffix_after_symbolic_completion_is_reported():
    item = transform(0x1000, 0x1001)
    result = match_transitions(
        [state(0x1000), state(0x1001), state(0x1002), state(0x1003)],
        symbolic_trace(item),
    )

    assert result.trace is not None
    assert result.trace.transforms == (item,)
    assert "concrete-suffix-skipped" in diagnostic_codes(result)
    diagnostic = next(item for item in result.diagnostics if item.code == "concrete-suffix-skipped")
    assert diagnostic.concrete_index == 2


def test_symbolic_address_index_must_match_the_stream_contents():
    item = transform(0x1000, 0x1001)
    wrong_address = MaterializedTrace(
        [item],
        environment(),
        [0x2000],
    )

    result = match_transitions([state(0x2000)], wrong_address)

    assert result.trace is None
    assert diagnostic_codes(result) == {"symbolic-address-mismatch"}


def test_symbolic_stream_length_must_match_its_address_index():
    truncated = TransformStream(
        iter(()),
        environment(),
        [0x1000],
    )
    truncated_result = match_transitions([state(0x1000)], truncated)

    assert truncated_result.trace is None
    assert diagnostic_codes(truncated_result) == {"symbolic-trace-truncated"}

    first = transform(0x1000, 0x1001)
    extra = transform(0x1001, 0x1002)
    oversized = TransformStream(
        iter((first, extra)),
        environment(),
        [0x1000],
    )
    oversized_result = match_transitions(
        [state(0x1000), state(0x1001)],
        oversized,
    )

    assert oversized_result.trace is not None
    assert oversized_result.trace.transforms == (first,)
    assert "symbolic-address-count-mismatch" in diagnostic_codes(oversized_result)
    assert not oversized_result.complete


def test_symbolic_stream_read_errors_are_structured():
    def broken_stream():
        raise RuntimeError("fixture stream failed")
        yield transform(0x1000, 0x1001)

    stream = TransformStream(
        broken_stream(),
        environment(),
        [0x1000],
    )

    result = match_transitions([state(0x1000)], stream)

    assert result.trace is None
    assert diagnostic_codes(result) == {"symbolic-trace-read-error"}
    assert "fixture stream failed" in result.diagnostics[0].message


def test_symbolic_architecture_must_match_environment_and_other_transforms():
    item = transform(0x1000, 0x1001)
    conflicting_environment = TraceEnvironment(
        None,
        (),
        (),
        binary_hash=None,
        architecture=aarch64.ArchAArch64("little").key,
    )
    environment_mismatch = MaterializedTrace(
        [item],
        conflicting_environment,
        [item.addr],
    )

    first_result = match_transitions([state(0x1000)], environment_mismatch)

    assert first_result.trace is None
    assert diagnostic_codes(first_result) == {"symbolic-architecture-mismatch"}

    arm = aarch64.ArchAArch64("little")
    second = SymbolicTransform(1, {}, [], arm, 0x1001, 0x1002)
    mixed = MaterializedTrace(
        [item, second],
        environment(),
        [item.addr, second.addr],
    )
    mixed_result = match_transitions(
        [state(0x1000), state(0x1001), state(0x1002)],
        mixed,
    )

    assert mixed_result.trace is not None
    assert mixed_result.trace.transforms == (item,)
    assert "symbolic-architecture-mismatch" in diagnostic_codes(mixed_result)
    assert not mixed_result.complete


def test_legacy_matcher_wrappers_are_non_mutating_and_share_the_engine():
    states = [state(0x1000), state(0x1002)]
    transforms = [transform(0x1000, 0x1001), transform(0x1001, 0x1002)]
    original_states = list(states)
    original_transforms = [item.to_json() for item in transforms]

    matched_states, matched_transforms = match_traces(states, transforms)
    folded_states, folded_transforms = fold_traces(states, transforms)

    assert states == original_states
    assert [item.to_json() for item in transforms] == original_transforms
    assert [item.read_pc() for item in matched_states] == [0x1000, 0x1002]
    assert [item.range for item in matched_transforms] == [(0x1000, 0x1002)]
    assert [item.read_pc() for item in folded_states] == [0x1000, 0x1002]
    assert [item.range for item in folded_transforms] == [(0x1000, 0x1002)]
