import base64
import io
import json

from focaccia.arch import aarch64, x86
from focaccia.parser import SCHEMA_VERSION, parse_snapshots, serialize_snapshots
from focaccia.snapshot import ProgramState
from focaccia.trace import MaterializedTrace, TraceEnvironment


def test_wide_x86_registers_serialize_without_integer_limits():
    arch = x86.ArchX86()
    state = ProgramState(arch)
    state.write_register("PC", 0x1000)
    st0 = (1 << 79) | 0x1122334455667788
    xmm0 = 0xFFEEDDCCBBAA99887766554433221100
    zmm2 = (1 << 511) | xmm0
    state.write_register("ST0", st0)
    state.write_register("XMM0", xmm0)
    state.write_register_bits("ZMM1", 0xA5A5, (1 << 16) - 1)
    state.write_register("ZMM2", zmm2)
    trace = MaterializedTrace(
        [state],
        TraceEnvironment(None, (), (), binary_hash=None, architecture=arch.key),
        [0x1000],
    )
    output = io.StringIO()

    serialize_snapshots(trace, output)
    document = json.loads(output.getvalue())
    parsed = parse_snapshots(io.StringIO(output.getvalue()))

    assert document["items"][0]["registers"]["ST0"] == f"0x{st0:020x}"
    assert document["items"][0]["registers"]["ZMM0"] == f"0x{xmm0:0128x}"
    assert document["items"][0]["register_validity"]["ZMM0"] == f"0x{(1 << 128) - 1:0128x}"
    assert document["items"][0]["registers"]["ZMM2"] == f"0x{zmm2:0128x}"
    assert parsed[0].read_register("ST0") == st0
    assert parsed[0].read_register("XMM0") == xmm0
    assert parsed[0].read_register("ZMM2") == zmm2
    assert not parsed[0].test_register("ZMM0")
    assert parsed[0].known_register_bits()["ZMM1"] == (0xA5A5, 0xFFFF)


def test_snapshot_serialization_preserves_identity_and_partial_validity():
    arch = aarch64.ArchAArch64("big")
    state = ProgramState(arch)
    state.write_register("PC", 0x1000)
    state.write_register("W0", 0x12345678)
    state.write_memory(0x2001, b"AB")

    env = TraceEnvironment("", [], [], binary_hash="test-hash")
    trace = MaterializedTrace([state], env)
    output = io.StringIO()
    serialize_snapshots(trace, output)
    serialized = output.getvalue()
    document = json.loads(serialized)
    parsed = parse_snapshots(io.StringIO(serialized))

    assert document["schema_version"] == SCHEMA_VERSION
    assert document["trace_kind"] == "states"
    assert document["architecture"] == "aarch64b"
    assert document["item_count"] == 1
    assert document["items"][0]["registers"] == {
        "PC": "0x0000000000001000",
        "X0": "0x0000000012345678",
    }
    assert document["items"][0]["register_validity"] == {
        "PC": "0xffffffffffffffff",
        "X0": "0x00000000ffffffff",
    }
    assert document["items"][0]["memory"] == [
        {
            "range": [0x2001, 0x2003],
            "data": base64.b64encode(b"AB").decode("ascii"),
        }
    ]
    assert parsed.addresses is None
    assert len(parsed) == 1
    assert list(parsed) == list(parsed)
    assert parsed[0].read_register("PC") == 0x1000
    assert parsed[0].read_register("W0") == 0x12345678
    assert not parsed[0].test_register("X0")
    assert parsed[0].known_register_bits()["X0"] == (
        0x12345678,
        (1 << 32) - 1,
    )
    assert parsed[0].read_memory(0x2001, 2) == b"AB"
    assert parsed.env.architecture == arch.key
