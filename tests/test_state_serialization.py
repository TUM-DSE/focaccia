import base64
import io
import json

from focaccia.arch import aarch64
from focaccia.parser import parse_snapshots, serialize_snapshots
from focaccia.snapshot import ProgramState
from focaccia.trace import MaterializedTrace, TraceEnvironment


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

    assert document["architecture"] == "aarch64b"
    assert document["snapshots"][0]["registers"] == {
        "PC": 0x1000,
        "W0": 0x12345678,
    }
    assert document["snapshots"][0]["memory"] == [
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
    assert parsed[0].read_memory(0x2001, 2) == b"AB"
    assert parsed.env.architecture == arch.key
