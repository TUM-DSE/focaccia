import copy
import io
import json
from pathlib import Path

import msgpack
import pytest
from miasm.expression.expression import ExprId, ExprInt, ExprMem

from focaccia.arch import aarch64, x86
from focaccia.parser import (
    SCHEMA_VERSION,
    AmbiguousArchitectureError,
    ArchitectureParseError,
    ExpressionWidthError,
    InstructionParseError,
    MissingFieldError,
    ParseError,
    StateParseError,
    TraceCardinalityError,
    TraceKindError,
    TraceLimitError,
    TransformParseError,
    TruncatedTraceError,
    UnsupportedSchemaVersionError,
    parse_snapshots,
    parse_transformations,
    serialize_snapshots,
    serialize_transformations,
    stream_transformation,
)
from focaccia.persistence import MAX_TRACE_ITEMS, MSGPACK_MAGIC
from focaccia.snapshot import ProgramState
from focaccia.symbolic import SymbolicTransform
from focaccia.trace import MaterializedTrace, TraceEnvironment

FIXTURES = Path(__file__).parent / "fixtures" / "traces"


def environment(arch) -> TraceEnvironment:
    return TraceEnvironment(
        "/tmp/program",
        ["argument"],
        ["NAME=value"],
        binary_hash="test-hash",
        start_address=0x1000,
        stop_address=0x2000,
        replay_provenance="rr:fixture",
        architecture=arch.key,
    )


def transform(arch=None) -> SymbolicTransform:
    if arch is None:
        arch = x86.ArchX86()
    return SymbolicTransform(
        7,
        {
            ExprId("RAX", 64): ExprInt(42, 64),
            ExprMem(ExprInt(0x2000, 64), 16): ExprInt(0xABCD, 16),
        },
        [],
        arch,
        0x1000,
        0x1001,
    )


def transform_trace() -> MaterializedTrace[SymbolicTransform]:
    item = transform()
    return MaterializedTrace([item], environment(item.arch), [item.addr])


def write_transform_json(tmp_path: Path) -> tuple[Path, dict]:
    path = tmp_path / "trace.json"
    serialize_transformations(transform_trace(), path, "json")
    return path, json.loads(path.read_text())


def encode_msgpack_frames(frames: list[dict]) -> bytes:
    encoded = bytearray(MSGPACK_MAGIC)
    for frame in frames:
        payload = msgpack.packb(frame, use_bin_type=True)
        assert isinstance(payload, bytes)
        encoded.extend(len(payload).to_bytes(8, "big"))
        encoded.extend(payload)
    return bytes(encoded)


def decode_msgpack_frames(data: bytes) -> list[dict]:
    assert data.startswith(MSGPACK_MAGIC)
    frames = []
    offset = len(MSGPACK_MAGIC)
    while offset < len(data):
        end_of_length = offset + 8
        assert end_of_length <= len(data)
        length = int.from_bytes(data[offset:end_of_length], "big")
        end_of_payload = end_of_length + length
        assert end_of_payload <= len(data)
        frames.append(
            msgpack.unpackb(
                data[end_of_length:end_of_payload],
                raw=False,
                strict_map_key=False,
            )
        )
        offset = end_of_payload
    return frames


def write_transform_msgpack(tmp_path: Path) -> tuple[Path, list[dict]]:
    path = tmp_path / "trace.msgpack"
    serialize_transformations(transform_trace(), path, "msgpack")
    return path, decode_msgpack_frames(path.read_bytes())


def test_schema_v2_json_transform_round_trip(tmp_path):
    path, document = write_transform_json(tmp_path)

    assert document["schema_version"] == SCHEMA_VERSION
    assert document["trace_kind"] == "transforms"
    assert document["architecture"] == "x86_64"
    assert document["addresses"] == [0x1000]
    assert document["item_count"] == 1
    assert len(document["items"]) == 1

    with path.open() as stream:
        parsed = parse_transformations(stream)
    assert parsed.env == transform_trace().env
    assert parsed.require_addresses() == (0x1000,)
    assert [item.to_json() for item in parsed] == [transform().to_json()]
    assert list(parsed) == list(parsed)


def test_schema_v2_msgpack_transform_round_trip(tmp_path):
    path, frames = write_transform_msgpack(tmp_path)
    header = frames[0]

    assert header["schema_version"] == SCHEMA_VERSION
    assert header["trace_kind"] == "transforms"
    assert header["architecture"] == "x86_64"
    assert header["addresses"] == [0x1000]
    assert header["item_count"] == 1
    assert set(frames[1]) == {"item"}

    with path.open("rb") as source:
        parsed = stream_transformation(source)
        assert parsed.env == transform_trace().env
        assert parsed.require_addresses() == (0x1000,)
        assert [item.to_json() for item in parsed] == [transform().to_json()]
        assert parsed.exhausted


def test_json_and_msgpack_share_logical_header_fields(tmp_path):
    _, json_document = write_transform_json(tmp_path)
    _, msgpack_frames = write_transform_msgpack(tmp_path)
    msgpack_header = msgpack_frames[0]

    common_fields = {
        "schema_version",
        "trace_kind",
        "architecture",
        "environment",
        "addresses",
        "item_count",
    }
    assert common_fields <= json_document.keys()
    assert set(msgpack_header) == common_fields
    for field in common_fields:
        assert msgpack_header[field] == json_document[field]


def test_empty_state_trace_is_a_typed_v2_document():
    arch = x86.ArchX86()
    trace = MaterializedTrace([], environment(arch))
    output = io.StringIO()
    serialize_snapshots(trace, output)
    document = json.loads(output.getvalue())

    assert document["schema_version"] == SCHEMA_VERSION
    assert document["trace_kind"] == "states"
    assert document["architecture"] == "x86_64"
    assert document["item_count"] == 0
    assert document["items"] == []
    parsed = parse_snapshots(io.StringIO(output.getvalue()))
    assert len(parsed) == 0
    assert parsed.env == trace.env


def test_empty_transform_trace_round_trips_in_both_formats(tmp_path):
    arch = x86.ArchX86()
    trace = MaterializedTrace([], environment(arch), [])

    json_path = tmp_path / "empty.json"
    serialize_transformations(trace, json_path, "json")
    with json_path.open() as source:
        assert len(parse_transformations(source)) == 0

    msgpack_path = tmp_path / "empty.msgpack"
    serialize_transformations(trace, msgpack_path, "msgpack")
    with msgpack_path.open("rb") as source:
        parsed = stream_transformation(source)
        assert list(parsed) == []
        assert parsed.exhausted


def test_aarch64_big_endian_state_round_trip():
    arch = aarch64.ArchAArch64("big")
    state = ProgramState(arch)
    state.write_register("PC", 0x1000)
    state.write_register("W0", 0x12345678)
    state.write_memory(0x2000, b"\x01\x02")
    trace = MaterializedTrace([state], environment(arch), [0x1000])
    output = io.StringIO()

    serialize_snapshots(trace, output)
    parsed = parse_snapshots(io.StringIO(output.getvalue()))

    assert parsed.env.architecture == arch.key
    assert parsed.require_addresses() == (0x1000,)
    assert parsed[0].arch == arch
    assert parsed[0].read_register("W0") == 0x12345678
    assert parsed[0].read_memory(0x2000, 2) == b"\x01\x02"


def test_known_legacy_json_fixtures_are_readable():
    with (FIXTURES / "legacy-transform-v1.json").open() as source:
        transforms = parse_transformations(source)
    with (FIXTURES / "legacy-state-v1.json").open() as source:
        states = parse_snapshots(source)

    assert transforms.require_addresses() == (0x1000,)
    assert transforms[0].range == (0x1000, 0x1001)
    assert states[0].read_register("PC") == 0x1000
    assert states[0].read_memory(0x2000, 2) == b"\x01\x02"

    typed_empty = {
        "env": transform_trace().env.to_json(),
        "addrs": [],
        "states": [],
    }
    assert len(parse_transformations(io.StringIO(json.dumps(typed_empty)))) == 0


def test_ambiguous_legacy_aarch64_identity_is_rejected():
    transform_document = json.loads(
        (FIXTURES / "legacy-transform-v1.json").read_text()
    )
    transform_document["states"][0]["arch"] = "aarch64"
    state_document = json.loads((FIXTURES / "legacy-state-v1.json").read_text())
    state_document["architecture"] = "aarch64"

    with pytest.raises(AmbiguousArchitectureError):
        parse_transformations(io.StringIO(json.dumps(transform_document)))
    with pytest.raises(AmbiguousArchitectureError):
        parse_snapshots(io.StringIO(json.dumps(state_document)))
    with pytest.raises(AmbiguousArchitectureError):
        parse_snapshots(io.StringIO("{}"))

    explicit_identity = {"isa": "aarch64", "endianness": "big"}
    transform_document["env"]["architecture"] = explicit_identity
    state_document["env"]["architecture"] = explicit_identity
    state_document["snapshots"][0]["registers"] = {"PC": 0x1000}
    transforms = parse_transformations(
        io.StringIO(json.dumps(transform_document))
    )
    states = parse_snapshots(io.StringIO(json.dumps(state_document)))
    assert transforms[0].arch == aarch64.ArchAArch64("big")
    assert states[0].arch == aarch64.ArchAArch64("big")


def test_explicit_null_binary_hash_does_not_rehash_during_parsing(tmp_path):
    _, document = write_transform_json(tmp_path)
    document["environment"]["binary_name"] = "/definitely/not/present"
    document["environment"]["binary_hash"] = None

    parsed = parse_transformations(io.StringIO(json.dumps(document)))

    assert parsed.env.binary_name == "/definitely/not/present"
    assert parsed.env.binary_hash is None


def test_unknown_schema_versions_and_wrong_trace_kinds_are_rejected(tmp_path):
    _, document = write_transform_json(tmp_path)
    unknown = copy.deepcopy(document)
    unknown["schema_version"] = SCHEMA_VERSION + 1
    wrong_kind = copy.deepcopy(document)
    wrong_kind["trace_kind"] = "states"
    wrong_item_shape = copy.deepcopy(document)
    wrong_item_shape["items"] = [
        {"registers": {}, "register_validity": {}, "memory": []}
    ]

    with pytest.raises(UnsupportedSchemaVersionError):
        parse_transformations(io.StringIO(json.dumps(unknown)))
    with pytest.raises(TraceKindError):
        parse_transformations(io.StringIO(json.dumps(wrong_kind)))
    with pytest.raises(MissingFieldError):
        parse_transformations(io.StringIO(json.dumps(wrong_item_shape)))

    _, msgpack_frames = write_transform_msgpack(tmp_path)
    msgpack_frames[0]["schema_version"] = SCHEMA_VERSION + 1
    with pytest.raises(UnsupportedSchemaVersionError):
        stream_transformation(io.BytesIO(encode_msgpack_frames(msgpack_frames)))


def test_v2_cardinality_and_address_mismatches_are_rejected(tmp_path):
    _, document = write_transform_json(tmp_path)
    wrong_count = copy.deepcopy(document)
    wrong_count["item_count"] = 2
    wrong_address = copy.deepcopy(document)
    wrong_address["addresses"] = [0x1001]

    with pytest.raises(TraceCardinalityError):
        parse_transformations(io.StringIO(json.dumps(wrong_count)))
    with pytest.raises(TransformParseError, match="address index"):
        parse_transformations(io.StringIO(json.dumps(wrong_address)))


def test_state_memory_ranges_and_register_values_are_validated():
    arch = x86.ArchX86()
    state = ProgramState(arch)
    state.write_register("PC", 0x1000)
    trace = MaterializedTrace([state], environment(arch), [0x1000])
    output = io.StringIO()
    serialize_snapshots(trace, output)
    document = json.loads(output.getvalue())

    bad_register = copy.deepcopy(document)
    bad_register["items"][0]["registers"]["RIP"] = 1 << 64
    bad_memory = copy.deepcopy(document)
    bad_memory["items"][0]["memory"] = [
        {"range": [0x2000, 0x2002], "data": "AA=="}
    ]
    bad_validity = copy.deepcopy(document)
    bad_validity["items"][0]["register_validity"]["RIP"] = 0xFF
    bad_range = copy.deepcopy(document)
    bad_range["items"][0]["memory"] = [
        {"range": [0x2002, 0x2001], "data": ""}
    ]
    overlapping_ranges = copy.deepcopy(document)
    overlapping_ranges["items"][0]["memory"] = [
        {"range": [0x2000, 0x2002], "data": "AAE="},
        {"range": [0x2001, 0x2003], "data": "AQI="},
    ]
    bad_state_address = copy.deepcopy(document)
    bad_state_address["addresses"] = [0x1001]

    with pytest.raises(ParseError):
        parse_snapshots(io.StringIO(json.dumps(bad_register)))
    with pytest.raises(StateParseError, match="declares 2 bytes"):
        parse_snapshots(io.StringIO(json.dumps(bad_memory)))
    with pytest.raises(StateParseError, match="outside its validity mask"):
        parse_snapshots(io.StringIO(json.dumps(bad_validity)))
    with pytest.raises(StateParseError, match="non-empty and increasing"):
        parse_snapshots(io.StringIO(json.dumps(bad_range)))
    with pytest.raises(StateParseError, match="overlaps"):
        parse_snapshots(io.StringIO(json.dumps(overlapping_ranges)))
    with pytest.raises(StateParseError, match="does not match address index"):
        parse_snapshots(io.StringIO(json.dumps(bad_state_address)))


def test_symbolic_expression_widths_and_instruction_lengths_are_validated(tmp_path):
    _, document = write_transform_json(tmp_path)
    bad_width = copy.deepcopy(document)
    bad_width["items"][0]["regs"]["RAX"] = "ExprId('EAX', 32)"
    bad_instruction = copy.deepcopy(document)
    bad_instruction["items"][0]["instructions"] = [[0, "NOP"]]
    overlapping_registers = copy.deepcopy(document)
    overlapping_registers["items"][0]["regs"]["EAX"] = "ExprInt(0x1, 32)"

    with pytest.raises(ExpressionWidthError):
        parse_transformations(io.StringIO(json.dumps(bad_width)))
    with pytest.raises(InstructionParseError):
        parse_transformations(io.StringIO(json.dumps(bad_instruction)))
    with pytest.raises(TransformParseError, match="Overlapping register"):
        parse_transformations(io.StringIO(json.dumps(overlapping_registers)))


def test_missing_v2_metadata_and_oversized_counts_are_rejected(tmp_path):
    _, document = write_transform_json(tmp_path)
    missing = copy.deepcopy(document)
    del missing["environment"]
    oversized = copy.deepcopy(document)
    oversized["item_count"] = MAX_TRACE_ITEMS + 1
    reversed_bounds = copy.deepcopy(document)
    reversed_bounds["environment"]["start_address"] = 0x2000
    reversed_bounds["environment"]["stop_address"] = 0x1000
    oversized_address = copy.deepcopy(document)
    oversized_address["addresses"] = [1 << 64]

    with pytest.raises(MissingFieldError):
        parse_transformations(io.StringIO(json.dumps(missing)))
    with pytest.raises(TraceLimitError):
        parse_transformations(io.StringIO(json.dumps(oversized)))
    with pytest.raises(TraceCardinalityError, match="start_address"):
        parse_transformations(io.StringIO(json.dumps(reversed_bounds)))
    with pytest.raises(ParseError):
        parse_transformations(io.StringIO(json.dumps(oversized_address)))


def test_truncated_and_trailing_msgpack_streams_are_rejected(tmp_path):
    _, frames = write_transform_msgpack(tmp_path)

    with pytest.raises(TruncatedTraceError, match="magic header"):
        stream_transformation(io.BytesIO(MSGPACK_MAGIC[:-1]))

    truncated = io.BytesIO(encode_msgpack_frames([frames[0]]))
    truncated_stream = stream_transformation(truncated)
    with pytest.raises(TruncatedTraceError):
        next(truncated_stream)

    trailing = io.BytesIO(
        encode_msgpack_frames([frames[0], frames[1], frames[1]])
    )
    trailing_stream = stream_transformation(trailing)
    with pytest.raises(TraceCardinalityError):
        list(trailing_stream)

    incomplete_trailing = io.BytesIO(
        encode_msgpack_frames([frames[0], frames[1]]) + b"\x00"
    )
    incomplete_trailing_stream = stream_transformation(incomplete_trailing)
    with pytest.raises(TruncatedTraceError, match="frame 1 length"):
        list(incomplete_trailing_stream)


def test_top_level_and_item_architectures_must_agree(tmp_path):
    _, document = write_transform_json(tmp_path)
    document["items"][0]["arch"] = "aarch64b"

    with pytest.raises(ArchitectureParseError):
        parse_transformations(io.StringIO(json.dumps(document)))
