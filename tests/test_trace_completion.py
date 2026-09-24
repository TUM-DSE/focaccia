"""Pure fixtures: persistence does not establish live whole-program support."""

import io
import json
from dataclasses import replace
from typing import Any, cast

import msgpack
import pytest

from focaccia.arch.x86 import ArchX86
from focaccia.completion import TraceCompletion, TraceScope
from focaccia.execution import ExecutionOutcome, ExecutionState
from focaccia.no_replay import (
    ExitAction, ExitScope, NoReplayActionDescriptor, NoReplayActionKind,
    NoReplayMmapBoundary, NoReplayMprotectBoundary, NoReplaySetFsBoundary,
    NoReplaySetTidBoundary,
)
from focaccia.persistence import (
    MSGPACK_MAGIC,
    ParseError,
    parse_snapshots,
    parse_transformations,
    serialize_snapshots,
    serialize_transformations,
    stream_transformation,
)
from focaccia.snapshot import ProgramState
from focaccia.symbolic import SymbolicTransform
from focaccia.trace import MaterializedTrace, TraceEnvironment, TransformStream, TransitionTrace


def fixture(outcome=None):
    arch = ArchX86()
    env = TraceEnvironment(None, [], [], start_address=0x1000, architecture=arch.key)
    item = SymbolicTransform(1, {}, [], arch, 0x1000, 0x1001)
    completion = TraceCompletion(
        0x1001, 1, 2, outcome or ExecutionOutcome(ExecutionState.EXITED, exit_status=0)
    )
    return MaterializedTrace(
        [item], env, [0x1000], scope=TraceScope.WHOLE_PROGRAM, completion=completion
    )


@pytest.mark.parametrize(
    "outcome",
    [
        ExecutionOutcome(ExecutionState.EXITED, exit_status=0),
        ExecutionOutcome(ExecutionState.EXITED, exit_status=7),
        ExecutionOutcome(ExecutionState.EXITED, termination_signal=15),
        ExecutionOutcome(ExecutionState.EXITED, backend_status=15),
        ExecutionOutcome(ExecutionState.UNKNOWN, description="transport lost"),
    ],
)
@pytest.mark.parametrize("encoding", ["json", "msgpack"])
def test_completion_roundtrip(tmp_path, outcome, encoding):
    original = fixture(outcome)
    path = tmp_path / "trace"
    serialize_transformations(original, path, encoding)
    if encoding == "json":
        with path.open() as source:
            result = parse_transformations(source)
    else:
        with path.open("rb") as source:
            result = stream_transformation(source)
            assert result.completion is None
            next(result)
            assert result.completion is None
            assert list(result) == []
    assert result.scope is TraceScope.WHOLE_PROGRAM
    assert result.completion == original.completion
    assert result.completion is not None
    assert result.completion.outcome.terminal_known == outcome.terminal_known


def test_state_completion_and_environment_separation():
    oracle = fixture()
    states = []
    for pc in (0x1000, 0x1001):
        state = ProgramState(ArchX86())
        state.write_register("RIP", pc)
        states.append(state)
    witness = MaterializedTrace(states, oracle.env)
    assert witness.completion is None
    assert witness.scope is TraceScope.UNSPECIFIED
    observed = MaterializedTrace(
        states, oracle.env, scope=TraceScope.WHOLE_PROGRAM, completion=oracle.completion
    )
    output = io.StringIO()
    serialize_snapshots(observed, output)
    result = parse_snapshots(io.StringIO(output.getvalue()))
    assert result.completion == observed.completion
    assert len(result) == 2
    assert result[-1].read_pc() == 0x1001
    cursor = observed.cursor()
    assert list(cursor) == states
    assert cursor.completion == observed.completion
    paired = TransitionTrace(
        states, list(oracle), oracle.env, scope=oracle.scope, completion=oracle.completion
    )
    assert len(paired) == 1
    with pytest.raises(ValueError):
        TransitionTrace(
            states[:1], [], oracle.env, scope=oracle.scope, completion=oracle.completion
        )


@pytest.mark.parametrize("version", [2, 3, 4])
def test_old_traces_remain_witnesses_when_rewritten(tmp_path, version):
    trace = fixture()
    path = tmp_path / "trace"
    serialize_transformations(trace, path)
    document = json.loads(path.read_text())
    document["schema_version"] = version
    document.pop("scope")
    document.pop("completion")
    if version == 2:
        document["items"][0]["mem"] = {}
    old = parse_transformations(io.StringIO(json.dumps(document)))
    assert old.scope is TraceScope.UNSPECIFIED
    assert old.completion is None
    serialize_transformations(old, path)
    rewritten = json.loads(path.read_text())
    assert rewritten["scope"] == "unspecified"
    assert rewritten["completion"] is None


@pytest.mark.parametrize(
    "change",
    [
        {"final_pc": 0},
        {"transform_count": 2, "state_count": 3},
        {"state_count": 1},
        {"final_pc": True},
        {"outcome": {"debugger_status": 0}},
    ],
)
def test_malformed_completion_rejected(tmp_path, change):
    path = tmp_path / "trace"
    serialize_transformations(fixture(), path)
    document = json.loads(path.read_text())
    document["completion"].update(change)
    with pytest.raises(ParseError):
        parse_transformations(io.StringIO(json.dumps(document)))


def test_truncation_never_exposes_completion(tmp_path):
    path = tmp_path / "trace"
    serialize_transformations(fixture(), path, "msgpack")
    data = path.read_bytes()
    for damaged in (data[:-1], data + b"x"):
        stream = stream_transformation(io.BytesIO(damaged))
        assert stream.declared_completion == fixture().completion
        with pytest.raises(ParseError):
            list(stream)
        assert stream.completion is None
        assert not stream.exhausted
        with pytest.raises(ParseError):
            list(stream)
        assert stream.completion is None


def test_msgpack_declared_completion_matches_json_but_requires_verified_eof(tmp_path):
    expected = fixture()
    json_path, msgpack_path = tmp_path / "trace.json", tmp_path / "trace.msgpack"
    serialize_transformations(expected, json_path, "json")
    serialize_transformations(expected, msgpack_path, "msgpack")
    with json_path.open() as source:
        materialized = parse_transformations(source)
    with msgpack_path.open("rb") as source:
        streamed = stream_transformation(source)
        assert streamed.declared_completion == materialized.completion
        assert streamed.completion is None
        list(streamed)
        assert streamed.completion == materialized.completion


def test_binding_and_scope_requirements():
    trace = fixture()
    assert trace.completion is not None
    with pytest.raises(ValueError):
        MaterializedTrace(list(trace), trace.env, completion=trace.completion)
    with pytest.raises(ValueError):
        MaterializedTrace(
            list(trace),
            trace.env,
            scope=trace.scope,
            completion=replace(trace.completion, final_pc=0),
        )
    with pytest.raises(ValueError):
        replace(trace.completion, outcome=ExecutionOutcome(ExecutionState.STOPPED))
    stream = TransformStream(
        iter([]), trace.env, [], scope=trace.scope, completion=trace.completion
    )
    with pytest.raises(ValueError):
        list(stream)
    assert stream.completion is None


def test_witness_scope_is_not_promoted(tmp_path):
    source = fixture()
    witness = MaterializedTrace(
        list(source),
        source.env,
        source.addresses,
        scope=TraceScope.WITNESS,
        completion=source.completion,
    )
    path = tmp_path / "trace"
    serialize_transformations(witness.cursor(), path, "msgpack")
    with path.open("rb") as source_file:
        result = stream_transformation(source_file)
        list(result)
    assert result.scope is TraceScope.WITNESS
    assert result.completion == witness.completion


def test_zero_ordinary_transforms_needs_an_explicit_live_boundary(tmp_path):
    env = TraceEnvironment(None, [], [], architecture=ArchX86().key, start_address=0x1234)
    completion = TraceCompletion(
        0x1234, 0, 1, ExecutionOutcome(ExecutionState.EXITED, exit_status=0)
    )
    with pytest.raises(ValueError, match="final live PC"):
        MaterializedTrace([], env, [], scope=TraceScope.WHOLE_PROGRAM, completion=completion)
    # A requested start address cannot certify a missing observed boundary.
    path = tmp_path / "trace"
    serialize_transformations(fixture(), path)
    document = json.loads(path.read_text())
    document["items"] = []
    document["addresses"] = []
    document["item_count"] = 0
    document["completion"]["transform_count"] = 0
    document["completion"]["state_count"] = 1
    with pytest.raises(ParseError, match="final live PC"):
        parse_transformations(io.StringIO(json.dumps(document)))


@pytest.mark.parametrize("encoding", ["json", "msgpack"])
@pytest.mark.parametrize("kind", [NoReplayActionKind.EXIT, NoReplayActionKind.EXIT_GROUP])
def test_terminal_action_descriptor_roundtrip(tmp_path, encoding, kind):
    source = fixture()
    assert source.completion is not None
    action = NoReplayActionDescriptor(ArchX86().key, 0x1001, kind)
    completion = replace(source.completion, terminal_action=action)
    trace = MaterializedTrace(
        list(source), source.env, source.addresses, scope=source.scope, completion=completion
    )
    path = tmp_path / "trace"
    serialize_transformations(trace, path, encoding)
    if encoding == "json":
        result = parse_transformations(io.StringIO(path.read_text()))
        encoded = json.loads(path.read_text())["completion"]["terminal_action"]
        assert set(encoded) == {"architecture", "pc", "kind"}
    else:
        result = stream_transformation(io.BytesIO(path.read_bytes()))
        list(result)
    assert result.completion == completion


@pytest.mark.parametrize(
    "change",
    [
        {"kind": "set_tid_address"},
        {"pc": 0},
        {"kind": "unknown"},
        {"architecture": "aarch64l"},
        {"native_return": 0},
    ],
)
def test_terminal_action_descriptor_rejects_invalid_metadata(tmp_path, change):
    source = fixture()
    assert source.completion is not None
    action = NoReplayActionDescriptor(ArchX86().key, 0x1001, NoReplayActionKind.EXIT)
    source.completion = replace(source.completion, terminal_action=action)
    path = tmp_path / "trace"
    serialize_transformations(source, path)
    document = json.loads(path.read_text())
    document["completion"]["terminal_action"].update(change)
    with pytest.raises(ParseError):
        parse_transformations(io.StringIO(json.dumps(document)))


@pytest.mark.parametrize("changes", [
    {"final_pc": -1}, {"final_pc": True}, {"final_pc": 1 << 64},
    {"transform_count": -1}, {"state_count": 1}, {"outcome": None},
    {"terminal_action": {}},
])
def test_completion_rejects_invalid_direct_construction(changes):
    source = fixture()
    assert source.completion is not None
    with pytest.raises(ValueError):
        replace(source.completion, **changes)


def test_completion_validates_ordered_interior_action_evidence():
    arch = ArchX86().key
    terminal = NoReplayActionDescriptor(arch, 0x1001, NoReplayActionKind.EXIT)
    exit_action = ExitAction(0, ExitScope.THREAD)
    tid = NoReplaySetTidBoundary(
        1,
        NoReplayActionDescriptor(arch, 0x1000, NoReplayActionKind.SET_TID_ADDRESS),
        0x4000,
        123,
    )
    mmap = NoReplayMmapBoundary(
        2,
        NoReplayActionDescriptor(arch, 0x1000, NoReplayActionKind.MMAP_ANONYMOUS_PRIVATE),
        8192,
        0,
    )
    mprotect = NoReplayMprotectBoundary(
        3,
        NoReplayActionDescriptor(arch, 0x1000, NoReplayActionKind.MPROTECT_NONE_PAGE),
        0,
        4096,
        4096,
    )
    completion = TraceCompletion(
        0x1001,
        4,
        5,
        ExecutionOutcome(ExecutionState.EXITED, exit_status=0),
        terminal,
        exit_action,
        no_replay_set_tid=(tid,),
        no_replay_mmap=(mmap,),
        no_replay_mprotect=(mprotect,),
    )
    assert completion.no_replay_mprotect == (mprotect,)

    invalid_changes = [
        {"no_replay_set_tid": []},
        {"no_replay_set_tid": ({},)},
        {"no_replay_set_tid": (replace(tid, transform_index=4),)},
        {"no_replay_set_tid": (tid, replace(tid, transform_index=2, expected_tid=124))},
        {"no_replay_set_fs": (set_fs_boundary(1),), "no_replay_set_tid": (tid,)},
        {"no_replay_mmap": []},
        {"no_replay_mmap": ({},)},
        {"no_replay_mmap": (replace(mmap, occurrence=1),)},
        {"no_replay_mmap": (replace(mmap, transform_index=4),)},
        {"no_replay_mmap": (replace(mmap, transform_index=1),), "no_replay_set_tid": (tid,)},
        {"no_replay_mprotect": []},
        {"no_replay_mprotect": ({},)},
        {"no_replay_mprotect": (replace(mprotect, occurrence=1),)},
        {"no_replay_mprotect": (replace(mprotect, transform_index=2),)},
        {"no_replay_mprotect": (replace(mprotect, transform_index=4),)},
        {"no_replay_mprotect": (replace(mprotect, transform_index=1),), "no_replay_set_tid": (tid,)},
    ]
    for changes in invalid_changes:
        with pytest.raises(ValueError):
            replace(completion, **changes)


def test_trace_metadata_requires_typed_scope_and_completion():
    env = TraceEnvironment(None, [], [])
    with pytest.raises(ValueError, match="TraceScope"):
        MaterializedTrace([], env, scope=cast(Any, "whole-program"))
    with pytest.raises(ValueError, match="TraceCompletion"):
        MaterializedTrace([], env, scope=TraceScope.WITNESS, completion=cast(Any, {}))


def test_state_completion_requires_known_final_pc():
    state = ProgramState(ArchX86())
    state.write_register("RIP", 0x1234)
    completion = TraceCompletion(0x1234, 0, 1, ExecutionOutcome(ExecutionState.UNKNOWN))
    trace = MaterializedTrace(
        [state],
        TraceEnvironment(None, [], []),
        scope=TraceScope.WHOLE_PROGRAM,
        completion=completion,
    )
    output = io.StringIO()
    serialize_snapshots(trace, output)
    document = json.loads(output.getvalue())
    document["items"][0]["registers"] = {}
    document["items"][0]["register_validity"] = {}
    with pytest.raises(ParseError, match="known final live PC"):
        parse_snapshots(io.StringIO(json.dumps(document)))


def exit_fixture(argument=0x100, scope=ExitScope.THREAD):
    source = fixture()
    assert source.completion is not None
    kind = NoReplayActionKind.EXIT if scope is ExitScope.THREAD else NoReplayActionKind.EXIT_GROUP
    source.completion = replace(
        source.completion,
        terminal_action=NoReplayActionDescriptor(ArchX86().key, 0x1001, kind),
        no_replay_exit=ExitAction(argument, scope),
    )
    return source


@pytest.mark.parametrize("encoding", ["json", "msgpack"])
@pytest.mark.parametrize("scope", list(ExitScope))
@pytest.mark.parametrize("argument", [0, 0x100, (1 << 64) - 1])
def test_no_replay_exit_roundtrip(tmp_path, encoding, scope, argument):
    source = exit_fixture(argument, scope)
    path = tmp_path / "trace"
    serialize_transformations(source, path, encoding)
    if encoding == "json":
        result = parse_transformations(io.StringIO(path.read_text()))
        encoded = json.loads(path.read_text())["completion"]["no_replay_exit"]
        assert encoded == {"argument": argument, "scope": scope.value}
    else:
        result = stream_transformation(io.BytesIO(path.read_bytes()))
        assert result.completion is None
        list(result)
    assert result.completion == source.completion
    assert result.completion is not None
    assert result.completion.no_replay_exit is not None
    assert result.completion.no_replay_exit.argument == argument


def test_no_replay_exit_state_roundtrip():
    source = exit_fixture()
    states = []
    for pc in (0x1000, 0x1001):
        state = ProgramState(ArchX86())
        state.write_register("RIP", pc)
        states.append(state)
    trace = MaterializedTrace(states, source.env, scope=source.scope, completion=source.completion)
    output = io.StringIO()
    serialize_snapshots(trace, output)
    result = parse_snapshots(io.StringIO(output.getvalue()))
    assert result.completion == source.completion


@pytest.mark.parametrize("changes", [
    {"no_replay_exit": {}},
    {"terminal_action": None},
    {"no_replay_exit": ExitAction(0, ExitScope.GROUP)},
    {"terminal_action": NoReplayActionDescriptor(ArchX86().key, 0x1000, NoReplayActionKind.EXIT)},
])
def test_no_replay_exit_rejects_unbound_direct_evidence(changes):
    completion = exit_fixture().completion
    assert completion is not None
    with pytest.raises(ValueError):
        replace(completion, **changes)


@pytest.mark.parametrize("evidence", [
    {}, [], True,
    {"argument": 0},
    {"argument": 0, "scope": "thread", "status": 0},
    {"argument": True, "scope": "thread"},
    {"argument": -1, "scope": "thread"},
    {"argument": 1 << 64, "scope": "thread"},
    {"argument": "0", "scope": "thread"},
    {"argument": 0.0, "scope": "thread"},
    {"argument": 0, "scope": "group"},
    {"argument": 0, "scope": "unknown"},
])
def test_no_replay_exit_rejects_malformed_persistence(tmp_path, evidence):
    path = tmp_path / "trace"
    serialize_transformations(exit_fixture(), path)
    document = json.loads(path.read_text())
    document["completion"]["no_replay_exit"] = evidence
    with pytest.raises(ParseError):
        parse_transformations(io.StringIO(json.dumps(document)))


@pytest.mark.parametrize("explicit_null", [False, True])
def test_no_replay_exit_optional_in_current_schema(tmp_path, explicit_null):
    path = tmp_path / "trace"
    serialize_transformations(fixture(), path)
    document = json.loads(path.read_text())
    assert "no_replay_exit" not in document["completion"]
    if explicit_null:
        document["completion"]["no_replay_exit"] = None
    result = parse_transformations(io.StringIO(json.dumps(document)))
    assert result.completion is not None
    assert result.completion.no_replay_exit is None


def test_no_replay_exit_preserves_full_effect_label_and_unknown_outcome():
    first, second = exit_fixture(0), exit_fixture(0x100)
    assert first.completion is not None and second.completion is not None
    assert first.completion.no_replay_exit is not None
    assert second.completion.no_replay_exit is not None
    assert first.completion.terminal_action == second.completion.terminal_action
    assert first.completion.outcome == second.completion.outcome
    assert first.completion.no_replay_exit.status == second.completion.no_replay_exit.status
    assert first.completion.no_replay_exit != second.completion.no_replay_exit
    unknown = replace(first.completion, outcome=ExecutionOutcome(ExecutionState.UNKNOWN))
    assert unknown.no_replay_exit == first.completion.no_replay_exit
    assert not unknown.outcome.terminal_known


@pytest.mark.parametrize("mode", ["absent", "null", "malformed", "unbound", "truncated"])
def test_no_replay_exit_stream_header_validation(tmp_path, mode):
    path = tmp_path / "trace"
    serialize_transformations(exit_fixture(), path, "msgpack")
    data = path.read_bytes()
    start = len(MSGPACK_MAGIC)
    length = int.from_bytes(data[start:start + 8], "big")
    end = start + 8 + length
    header = msgpack.unpackb(data[start + 8:end], raw=False)
    if mode == "absent":
        header["completion"].pop("no_replay_exit")
    elif mode == "null":
        header["completion"]["no_replay_exit"] = None
    elif mode == "malformed":
        header["completion"]["no_replay_exit"]["argument"] = True
    elif mode == "unbound":
        header["completion"]["terminal_action"] = None
    payload = msgpack.packb(header, use_bin_type=True)
    assert isinstance(payload, bytes)
    modified = MSGPACK_MAGIC + len(payload).to_bytes(8, "big") + payload + data[end:]
    if mode in ("malformed", "unbound"):
        with pytest.raises(ParseError):
            stream_transformation(io.BytesIO(modified))
    elif mode == "truncated":
        stream = stream_transformation(io.BytesIO(modified[:-1]))
        with pytest.raises(ParseError):
            list(stream)
        assert stream.completion is None
    else:
        stream = stream_transformation(io.BytesIO(modified))
        list(stream)
        assert stream.completion is not None
        assert stream.completion.no_replay_exit is None


def set_fs_boundary(index=0, base=0x7000):
    return NoReplaySetFsBoundary(
        index, NoReplayActionDescriptor(ArchX86().key, 0x1000, NoReplayActionKind.SET_FS), base
    )


def set_fs_fixture():
    source = exit_fixture()
    assert source.completion is not None
    source.completion = replace(source.completion, no_replay_set_fs=(set_fs_boundary(),))
    return source


@pytest.mark.parametrize("encoding", ["json", "msgpack"])
def test_no_replay_set_fs_roundtrip(tmp_path, encoding):
    source = set_fs_fixture()
    path = tmp_path / "trace"
    serialize_transformations(source, path, encoding)
    if encoding == "json":
        document = json.loads(path.read_text())
        assert document["completion"]["no_replay_set_fs"] == [{
            "transform_index": 0,
            "descriptor": {"architecture": "x86_64", "pc": 0x1000, "kind": "arch_prctl_set_fs"},
            "base": 0x7000,
        }]
        result = parse_transformations(io.StringIO(path.read_text()))
    else:
        result = stream_transformation(io.BytesIO(path.read_bytes()))
        assert result.completion is None
        list(result)
    assert result.completion == source.completion


@pytest.mark.parametrize("encoding", ["json", "msgpack"])
def test_no_replay_set_fs_repeated_pc_order_roundtrip(tmp_path, encoding):
    source = set_fs_fixture()
    assert source.completion is not None
    boundaries = (set_fs_boundary(0, 0), set_fs_boundary(1, (1 << 47) - 4097))
    completion = replace(source.completion, transform_count=2, state_count=3, no_replay_set_fs=boundaries)
    trace = MaterializedTrace(
        [source[0], source[0]], source.env, [0x1000, 0x1000], scope=source.scope, completion=completion
    )
    path = tmp_path / "trace"
    serialize_transformations(trace, path, encoding)
    if encoding == "json":
        result = parse_transformations(io.StringIO(path.read_text()))
    else:
        result = stream_transformation(io.BytesIO(path.read_bytes()))
        list(result)
    assert result.completion == completion


def test_no_replay_set_fs_state_roundtrip():
    source = set_fs_fixture()
    states = []
    for pc in (0x1000, 0x1001):
        state = ProgramState(ArchX86())
        state.write_register("RIP", pc)
        states.append(state)
    output = io.StringIO()
    serialize_snapshots(MaterializedTrace(states, source.env, scope=source.scope, completion=source.completion), output)
    assert parse_snapshots(io.StringIO(output.getvalue())).completion == source.completion


@pytest.mark.parametrize("changes", [
    {"no_replay_set_fs": None},
    {"no_replay_set_fs": []},
    {"no_replay_set_fs": ({},)},
    {"no_replay_set_fs": (set_fs_boundary(1),)},
    {"no_replay_set_fs": (set_fs_boundary(), set_fs_boundary())},
    {"no_replay_exit": None},
])
def test_no_replay_set_fs_rejects_invalid_completion(changes):
    completion = set_fs_fixture().completion
    assert completion is not None
    with pytest.raises(ValueError):
        replace(completion, **changes)


def test_no_replay_set_fs_order_and_full_base_evidence():
    completion = set_fs_fixture().completion
    assert completion is not None
    first, second = set_fs_boundary(0), set_fs_boundary(2, 0x8000)
    ordered = replace(completion, transform_count=3, state_count=4, no_replay_set_fs=(first, second))
    assert ordered.no_replay_set_fs[0].descriptor == ordered.no_replay_set_fs[1].descriptor
    assert first.base != second.base
    with pytest.raises(ValueError):
        replace(ordered, no_replay_set_fs=(second, first))


@pytest.mark.parametrize("evidence", [None, {}, True, "", [None], [{}], [
    {"transform_index": 0, "descriptor": {}, "base": 0x7000}
]])
def test_no_replay_set_fs_rejects_invalid_list(tmp_path, evidence):
    path = tmp_path / "trace"
    serialize_transformations(set_fs_fixture(), path)
    document = json.loads(path.read_text())
    document["completion"]["no_replay_set_fs"] = evidence
    with pytest.raises(ParseError):
        parse_transformations(io.StringIO(json.dumps(document)))


@pytest.mark.parametrize("field,value", [
    ("transform_index", True), ("transform_index", -1), ("transform_index", 1),
    ("transform_index", "0"), ("transform_index", 0.0),
    ("base", True), ("base", -1), ("base", 1 << 64), ("base", "0"), ("base", 0.0),
    ("extra", 0),
    ("descriptor", None),
    ("descriptor", {"architecture": "x86_64", "pc": 0x1000, "kind": "exit"}),
    ("descriptor", {"architecture": "aarch64l", "pc": 0x1000, "kind": "arch_prctl_set_fs"}),
    ("descriptor", {"architecture": "x86_64", "pc": True, "kind": "arch_prctl_set_fs"}),
    ("descriptor", {"architecture": "x86_64", "pc": 0x1000, "kind": "unknown"}),
    ("descriptor", {"architecture": "x86_64", "pc": 0x1000, "kind": "arch_prctl_set_fs", "extra": 0}),
])
def test_no_replay_set_fs_rejects_malformed_boundary(tmp_path, field, value):
    path = tmp_path / "trace"
    serialize_transformations(set_fs_fixture(), path)
    document = json.loads(path.read_text())
    document["completion"]["no_replay_set_fs"][0][field] = value
    with pytest.raises(ParseError):
        parse_transformations(io.StringIO(json.dumps(document)))


@pytest.mark.parametrize("present", [False, True])
def test_no_replay_set_fs_optional_in_current_schema(tmp_path, present):
    path = tmp_path / "trace"
    serialize_transformations(fixture(), path)
    document = json.loads(path.read_text())
    assert "no_replay_set_fs" not in document["completion"]
    if present:
        document["completion"]["no_replay_set_fs"] = []
    result = parse_transformations(io.StringIO(json.dumps(document)))
    assert result.completion is not None
    assert result.completion.no_replay_set_fs == ()


@pytest.mark.parametrize("mode", ["malformed", "unbound", "truncated"])
def test_no_replay_set_fs_stream_validation(tmp_path, mode):
    path = tmp_path / "trace"
    serialize_transformations(set_fs_fixture(), path, "msgpack")
    data = path.read_bytes()
    start = len(MSGPACK_MAGIC)
    length = int.from_bytes(data[start:start + 8], "big")
    end = start + 8 + length
    header = msgpack.unpackb(data[start + 8:end], raw=False)
    if mode == "malformed":
        header["completion"]["no_replay_set_fs"][0]["base"] = True
    elif mode == "unbound":
        header["completion"].pop("no_replay_exit")
    payload = msgpack.packb(header, use_bin_type=True)
    assert isinstance(payload, bytes)
    modified = MSGPACK_MAGIC + len(payload).to_bytes(8, "big") + payload + data[end:]
    if mode == "truncated":
        stream = stream_transformation(io.BytesIO(modified[:-1]))
        with pytest.raises(ParseError):
            list(stream)
        assert stream.completion is None
    else:
        with pytest.raises(ParseError):
            stream_transformation(io.BytesIO(modified))
