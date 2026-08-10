from __future__ import annotations

from collections.abc import Sequence

import pytest
from hypothesis import given, settings, strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule

from focaccia.trace import (
    MaterializedTrace,
    StreamExhaustedError,
    TraceEnvironment,
    TransformStream,
    Transition,
    TransitionTrace,
)


PROPERTY_SETTINGS = settings(
    max_examples=100,
    derandomize=True,
    database=None,
    deadline=None,
)
ENVIRONMENT = TraceEnvironment(
    "/tmp/property-program",
    ["argument"],
    ["NAME=value"],
    binary_hash="property-hash",
)


def consume(stream: TransformStream[int], count: int) -> list[int]:
    consumed = []
    for _ in range(count):
        try:
            consumed.append(next(stream))
        except StopIteration:
            break
    return consumed


@settings(
    max_examples=50,
    stateful_step_count=50,
    derandomize=True,
    database=None,
    deadline=None,
)
class TraceCursorStateMachine(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.items: tuple[int, ...] = ()
        self.stream = TransformStream(iter(self.items), ENVIRONMENT)
        self.model_position = 0
        self.model_exhausted = False

    @initialize(items=st.lists(st.integers(), max_size=30))
    def initialize_stream(self, items: list[int]) -> None:
        self.items = tuple(items)
        self.stream = TransformStream(iter(self.items), ENVIRONMENT)
        self.model_position = 0
        self.model_exhausted = False

    @rule()
    def read_next(self) -> None:
        if self.model_position < len(self.items):
            assert next(self.stream) == self.items[self.model_position]
            self.model_position += 1
        else:
            with pytest.raises(StopIteration):
                next(self.stream)
            self.model_exhausted = True

    @rule(count=st.integers(min_value=0, max_value=40))
    def skip_forward(self, count: int) -> None:
        available = len(self.items) - self.model_position
        if count <= available:
            self.stream.skip(count)
            self.model_position += count
            return

        with pytest.raises(StreamExhaustedError) as raised:
            self.stream.skip(count)
        assert raised.value.requested == count
        assert raised.value.skipped == available
        assert raised.value.position == len(self.items)
        self.model_position = len(self.items)
        self.model_exhausted = True

    @rule(count=st.integers(max_value=-1))
    def reject_backward_skip(self, count: int) -> None:
        with pytest.raises(ValueError, match="negative"):
            self.stream.skip(count)

    @invariant()
    def cursor_matches_model(self) -> None:
        assert self.stream.position == self.model_position
        assert self.stream.exhausted is self.model_exhausted
        assert self.stream.env is ENVIRONMENT


TestTraceCursorStateMachine = TraceCursorStateMachine.TestCase


@st.composite
def materialized_cases(
    draw: st.DrawFn,
) -> tuple[list[int], list[int] | None, int, int]:
    items = draw(st.lists(st.integers(), max_size=40))
    addresses = draw(
        st.one_of(
            st.none(),
            st.lists(
                st.integers(min_value=0, max_value=(1 << 64) - 1),
                min_size=len(items),
                max_size=len(items),
            ),
        )
    )
    first_count = draw(st.integers(min_value=0, max_value=len(items) + 2))
    second_count = draw(st.integers(min_value=0, max_value=len(items) + 2))
    return items, addresses, first_count, second_count


@PROPERTY_SETTINGS
@given(case=materialized_cases())
def test_materialized_trace_cursors_are_independent_sequence_views(
    case: tuple[list[int], list[int] | None, int, int],
) -> None:
    items, addresses, first_count, second_count = case
    trace = MaterializedTrace(items, ENVIRONMENT, addresses)
    first = trace.cursor()
    second = trace.cursor()

    assert len(trace) == len(items)
    assert tuple(trace) == tuple(items)
    assert trace[:] == tuple(items)
    assert consume(first, first_count) == items[:first_count]
    assert consume(second, second_count) == items[:second_count]
    assert first.position == min(first_count, len(items))
    assert second.position == min(second_count, len(items))
    assert first.addresses == second.addresses == (
        tuple(addresses) if addresses is not None else None
    )
    assert tuple(trace) == tuple(items)


@st.composite
def transition_cases(
    draw: st.DrawFn,
) -> tuple[list[str], list[int], slice]:
    transform_count = draw(st.integers(min_value=0, max_value=30))
    states = [f"state-{index}" for index in range(transform_count + 1)]
    transforms = list(range(transform_count))
    bound = transform_count + 3
    start = draw(st.one_of(st.none(), st.integers(min_value=-bound, max_value=bound)))
    stop = draw(st.one_of(st.none(), st.integers(min_value=-bound, max_value=bound)))
    step = draw(
        st.one_of(
            st.none(),
            st.integers(min_value=-5, max_value=5).filter(lambda value: value != 0),
        )
    )
    return states, transforms, slice(start, stop, step)


def expected_transitions(
    states: Sequence[str],
    transforms: Sequence[int],
) -> tuple[Transition[str, int], ...]:
    return tuple(
        Transition(states[index], transform, states[index + 1])
        for index, transform in enumerate(transforms)
    )


@PROPERTY_SETTINGS
@given(case=transition_cases())
def test_transition_trace_preserves_every_boundary_under_iteration_and_slicing(
    case: tuple[list[str], list[int], slice],
) -> None:
    states, transforms, selected = case
    trace = TransitionTrace(states, transforms, ENVIRONMENT)
    expected = expected_transitions(states, transforms)

    assert len(trace) == len(transforms)
    assert trace.state_boundaries == tuple(states)
    assert trace.transforms == tuple(transforms)
    assert tuple(trace) == expected
    assert trace[selected] == expected[selected]
    assert tuple(reversed(trace)) == tuple(reversed(expected))
