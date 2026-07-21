import base64
import io
import json
from typing import cast

from focaccia.arch import aarch64
from focaccia.parser import serialize_snapshots
from focaccia.snapshot import ProgramState
from focaccia.trace import Trace, TraceEnvironment


class SnapshotTrace(list[ProgramState]):
    def __init__(self, states: list[ProgramState], env: TraceEnvironment):
        super().__init__(states)
        self.env = env


def test_snapshot_serialization_preserves_identity_and_partial_validity():
    arch = aarch64.ArchAArch64("big")
    state = ProgramState(arch)
    state.write_register("PC", 0x1000)
    state.write_register("W0", 0x12345678)
    state.write_memory(0x2001, b"AB")

    env = TraceEnvironment("", [], [], binary_hash="test-hash")
    trace = SnapshotTrace([state], env)
    output = io.StringIO()
    serialize_snapshots(cast(Trace[ProgramState], trace), output)
    document = json.loads(output.getvalue())

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
