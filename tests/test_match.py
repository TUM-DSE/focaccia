from miasm.expression.expression import ExprId, ExprInt

from focaccia.arch import x86
from focaccia.match import fold_traces, match_traces, match_transitions
from focaccia.snapshot import ProgramState
from focaccia.symbolic import SymbolicTransform
from focaccia.trace import MaterializedTrace, TraceEnvironment


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
