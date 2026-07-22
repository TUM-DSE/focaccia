import io
import json

import msgpack
import pytest

from focaccia import trace as trace_module
from focaccia.arch import aarch64, x86
from focaccia.parser import parse_qemu, serialize_snapshots, stream_transformation
from focaccia.snapshot import ProgramState
from focaccia.symbolic import SymbolicTransform
from focaccia.trace import (
    MaterializedTrace,
    StreamExhaustedError,
    TraceEnvironment,
    TransformStream,
    Transition,
    TransitionTrace,
)


def environment(**kwargs) -> TraceEnvironment:
    return TraceEnvironment(
        "/tmp/program",
        ["argument"],
        ["NAME=value"],
        binary_hash="test-hash",
        **kwargs,
    )


def make_state(pc: int) -> ProgramState:
    state = ProgramState(x86.ArchX86())
    state.write_register("PC", pc)
    return state


def make_transform(start: int, end: int) -> SymbolicTransform:
    return SymbolicTransform(1, {}, [], x86.ArchX86(), start, end)


def test_trace_kinds_are_explicit():
    assert not hasattr(trace_module, "Trace")
    assert not hasattr(trace_module, "TraceContainer")


def test_materialized_program_state_trace_is_repeatable_and_indexable():
    states = [make_state(0x1000), make_state(0x1001)]
    trace = MaterializedTrace(states, environment(), [0x1000, 0x1001])
    states.append(make_state(0x1002))

    assert len(trace) == 2
    assert list(trace) == list(trace) == states[:2]
    assert trace[0] is states[0]
    assert trace[:] == tuple(states[:2])
    assert trace.require_addresses() == (0x1000, 0x1001)
    assert not hasattr(trace, "states")


def test_materialized_symbolic_trace_creates_independent_cursors():
    transforms = [make_transform(0x1000, 0x1001), make_transform(0x1001, 0x1002)]
    trace = MaterializedTrace(transforms, environment(), [0x1000, 0x1001])

    first = trace.cursor()
    second = trace.cursor()
    assert next(first) is transforms[0]
    assert next(first) is transforms[1]
    assert next(second) is transforms[0]
    assert list(trace) == transforms


def test_materialized_trace_requires_explicit_matching_addresses():
    state = make_state(0x1000)
    trace = MaterializedTrace([state], environment())

    assert trace.addresses is None
    with pytest.raises(ValueError, match="no address index"):
        trace.require_addresses()
    with pytest.raises(ValueError, match="address count"):
        MaterializedTrace([state], environment(), [])


def test_empty_materialized_trace_has_sequence_semantics():
    trace = MaterializedTrace([], environment(), [])

    assert not trace
    assert len(trace) == 0
    assert list(trace) == []
    assert list(trace) == []
    assert trace.require_addresses() == ()
    with pytest.raises(IndexError):
        _ = trace[0]


def test_transform_stream_is_one_shot_and_tracks_position():
    stream = TransformStream(iter([10, 20, 30]), environment(), [1, 2, 3])

    assert iter(stream) is stream
    assert next(stream) == 10
    stream.skip()
    assert stream.position == 2
    assert next(stream) == 30
    assert stream.position == 3
    with pytest.raises(StopIteration):
        next(stream)
    assert stream.exhausted
    assert list(stream) == []
    assert stream.require_addresses() == (1, 2, 3)


def test_msgpack_transform_stream_has_explicit_one_shot_contract():
    transforms = [make_transform(0x1000, 0x1001), make_transform(0x1001, 0x1002)]
    env = environment(architecture=x86.ArchX86().key)
    packer = msgpack.Packer()
    encoded = b"".join(
        [
            packer.pack({"env": env.to_json(), "addresses": [0x1000, 0x1001]}),
            *(packer.pack({"state": transform.to_json()}) for transform in transforms),
        ]
    )

    stream = stream_transformation(io.BytesIO(encoded))
    assert next(stream).range == (0x1000, 0x1001)
    stream.skip()
    assert stream.position == 2
    assert stream.require_addresses() == (0x1000, 0x1001)
    with pytest.raises(StopIteration):
        next(stream)


def test_transform_stream_skip_exhaustion_is_explicit():
    stream = TransformStream(iter([1, 2]), environment())

    with pytest.raises(StreamExhaustedError) as raised:
        stream.skip(3)
    assert raised.value.requested == 3
    assert raised.value.skipped == 2
    assert raised.value.position == 2
    assert stream.exhausted

    with pytest.raises(ValueError, match="negative"):
        TransformStream(iter([]), environment()).skip(-1)


def test_transition_trace_enforces_state_transform_cardinality():
    env = environment()
    valid = TransitionTrace(["s0", "s1"], ["t0"], env)

    assert len(valid) == 1
    assert valid.state_boundaries == ("s0", "s1")
    assert valid.transforms == ("t0",)
    assert valid[0] == Transition("s0", "t0", "s1")
    assert valid[-1] == valid[0]
    assert list(valid) == [Transition("s0", "t0", "s1")]
    assert len(TransitionTrace(["initial"], [], env)) == 0

    with pytest.raises(ValueError, match="one more state"):
        TransitionTrace([], [], env)
    with pytest.raises(ValueError, match="one more state"):
        TransitionTrace(["s0"], ["t0"], env)


def test_trace_environment_is_immutable_and_defensively_copies_inputs():
    argv = ["argument"]
    envp = ["NAME=value"]
    env = TraceEnvironment(
        "/tmp/program",
        argv,
        envp,
        binary_hash="test-hash",
    )
    argv.append("later")
    envp.clear()

    assert env.argv == ("argument",)
    assert env.envp == ("NAME=value",)
    with pytest.raises(AttributeError):
        setattr(env, "start_address", 0x1000)


def test_trace_environment_equality_includes_bounds_provenance_and_endianness():
    little = environment(
        start_address=0x1000,
        stop_address=0x2000,
        replay_provenance="rr:recording-a",
        architecture=aarch64.ArchAArch64("little").key,
    )
    same = environment(
        start_address=0x1000,
        stop_address=0x2000,
        replay_provenance="rr:recording-a",
        architecture=aarch64.ArchAArch64("little").key,
    )

    assert little == same
    assert hash(little) == hash(same)
    assert little != environment(
        start_address=0x1001,
        stop_address=0x2000,
        replay_provenance="rr:recording-a",
        architecture=aarch64.ArchAArch64("little").key,
    )
    assert little != environment(
        start_address=0x1000,
        stop_address=0x2001,
        replay_provenance="rr:recording-a",
        architecture=aarch64.ArchAArch64("little").key,
    )
    assert little != environment(
        start_address=0x1000,
        stop_address=0x2000,
        replay_provenance="rr:recording-b",
        architecture=aarch64.ArchAArch64("little").key,
    )
    assert little != environment(
        start_address=0x1000,
        stop_address=0x2000,
        replay_provenance="rr:recording-a",
        architecture=aarch64.ArchAArch64("big").key,
    )


def test_trace_environment_metadata_round_trip():
    env = environment(
        start_address=0x1000,
        stop_address=0x2000,
        replay_provenance="rr:recording-a",
        architecture=aarch64.ArchAArch64("big").key,
    )

    assert TraceEnvironment.from_json(env.to_json()) == env
    with pytest.raises(ValueError, match="conflicts"):
        env.with_architecture(aarch64.ArchAArch64("little").key)


def test_trace_environment_reads_legacy_metadata_without_bounds():
    env = TraceEnvironment.from_json(
        {
            "binary_name": None,
            "binary_hash": None,
            "argv": [],
            "envp": [],
        }
    )

    assert env.start_address is None
    assert env.stop_address is None
    assert env.replay_provenance is None
    assert env.architecture is None


def test_legacy_log_parser_uses_typed_unknown_environment():
    trace = parse_qemu(io.StringIO(""), x86.ArchX86())

    assert trace.env.binary_name is None
    assert trace.env.binary_hash is None
    assert trace.env.argv == ()
    assert trace.env.envp == ()
    assert trace.env.detlog is None
    assert trace.env.replay_provenance is None
    assert trace.env.architecture == x86.ArchX86().key


def test_empty_materialized_snapshot_serialization_returns_after_writing():
    output = io.StringIO()
    env = environment(architecture=x86.ArchX86().key)
    serialize_snapshots(MaterializedTrace([], env), output)

    document = json.loads(output.getvalue())
    assert document["schema_version"] == 2
    assert document["trace_kind"] == "states"
    assert document["architecture"] == "x86_64"
    assert document["item_count"] == 0
    assert document["items"] == []
