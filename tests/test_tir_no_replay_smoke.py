"""Fixture/provenance and report checks for the live smoke, without launching QEMU."""

from pathlib import Path
import runpy
import struct
import socket
import os
from types import SimpleNamespace

import pytest
from miasm.expression.expression import ExprId, ExprInt

from focaccia.completion import TraceScope
from focaccia.parser import parse_transformations, serialize_transformations

PROBE = runpy.run_path(str(Path(__file__).parent / "probes/tir_no_replay_smoke.py"))
probe = SimpleNamespace(**PROBE)
PC = 0x400000


def elf():
    data = bytearray(0x104)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", data, 16, 2, 183, 1)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HHH", data, 52, 64, 56, 1)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0x100, PC, PC, 4, 4, 4)
    data[0x100:] = bytes.fromhex("00040091")
    return data


def test_private_debugger_socket_readiness_and_cleanup():
    with probe.PrivateGdbSocket() as channel:
        directory = Path(channel.directory.name)
        assert directory.stat().st_mode & 0o777 == 0o700
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(channel.path))
            listener.listen(1)
            channel.wait_ready(timeout=1)
        descriptor = channel.fd
    assert not directory.exists()
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_socket_startup_timeout_is_explicit(monkeypatch):
    with probe.PrivateGdbSocket() as channel:
        monkeypatch.setattr(probe.select, "select", lambda *args: ([], [], []))
        with pytest.raises(TimeoutError):
            channel.wait_ready(timeout=1)


def test_region_is_read_from_the_executable_mapping():
    assert probe.read_region(bytes(elf()), PC, PC + 4) == bytes.fromhex("00040091")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda data: data.__setitem__(5, 2),
        lambda data: struct.pack_into("<H", data, 16, 3),
        lambda data: struct.pack_into("<H", data, 18, 62),
        lambda data: struct.pack_into("<H", data, 54, 8),
        lambda data: struct.pack_into("<H", data, 56, 0),
        lambda data: struct.pack_into("<I", data, 64, 3),
        lambda data: struct.pack_into("<I", data, 68, 4),
        lambda data: struct.pack_into("<I", data, 68, 7),
        lambda data: struct.pack_into("<Q", data, 72, 0x1000),
        lambda data: struct.pack_into("<Q", data, 104, 3),
    ],
)
def test_invalid_or_unmapped_elf_is_rejected(mutate):
    data = elf()
    mutate(data)
    with pytest.raises(ValueError):
        probe.read_region(bytes(data), PC, PC + 4)


@pytest.mark.parametrize(
    "start,stop",
    [(PC, PC), (PC + 1, PC + 4), (PC, PC + 8), (-4, 0), (PC, PC + 8192), (True, PC + 4)],
)
def test_invalid_region_bounds_are_rejected(start, stop):
    with pytest.raises(ValueError):
        probe.read_region(bytes(elf()), start, stop)


def test_reference_is_parameterized_and_serializes_as_a_witness(tmp_path, monkeypatch):
    binary = tmp_path / "fixture"
    binary.write_bytes(elf())

    class Backend:
        def __init__(self, executable):
            assert executable == "fixture-oracle"

        def generate(self, instruction, state, context):
            assert not state.test_register("X0")  # No emulator/native input values.
            pc = ExprInt(instruction.addr + 4, 64)
            return pc, {ExprId("PC", 64): pc, ExprId("X0", 64): ExprId("X0", 64) + ExprInt(1, 64)}

    monkeypatch.setitem(probe.generate_reference.__globals__, "TirBackend", Backend)
    reference = probe.generate_reference(binary, PC, PC + 4, "fixture-oracle")
    assert reference.require_addresses() == (PC,)
    assert reference.scope is TraceScope.WITNESS
    assert reference.env.detlog is None
    path = tmp_path / "oracle.json"
    serialize_transformations(reference, path)
    with path.open() as stream:
        loaded = parse_transformations(stream)
    assert len(loaded) == 1 and loaded[0].range == (PC, PC + 4)
    assert loaded.scope is TraceScope.WITNESS
    assert loaded.env.binary_hash == reference.env.binary_hash


def report(injected=False) -> dict:
    return {
        "schema": "focaccia-qemu-validation-v1",
        "status": "mismatch" if injected else "accepted",
        "trace": {
            "complete": True,
            "terminal_reached": True,
            "terminal_pc": PC + 4,
            "transform_count": 1,
            "state_count": 2,
        },
        "replay": {"active": False, "record_count": 0},
        "completion": {"scope": "witness"},
        "validation": {
            "entry_count": 1,
            "diagnostics": [],
            "entries": [
                {"errors": [{"severity": "confirmed", "subject": "CPSR"}] if injected else []}
            ],
        },
    }


@pytest.mark.parametrize("injected", [False, True])
def test_report_requires_complete_bounded_evidence(injected):
    probe.validate_report(report(injected), stop=PC + 4, count=1, injected=injected)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda doc: doc.update(status="incomplete"),
        lambda doc: doc["trace"].update(complete=False),
        lambda doc: doc["trace"].update(terminal_reached=False),
        lambda doc: doc["trace"].update(state_count=1),
        lambda doc: doc["trace"].update(terminal_pc=PC),
        lambda doc: doc["validation"].update(entry_count=0),
        lambda doc: doc["validation"].update(diagnostics=[{"code": "gap"}]),
        lambda doc: doc["replay"].update(active=True),
        lambda doc: doc["completion"].update(scope="whole-program"),
    ],
)
def test_report_never_accepts_missing_observations_or_replay(mutate):
    document = report()
    mutate(document)
    with pytest.raises(ValueError):
        probe.validate_report(document, stop=PC + 4, count=1, injected=False)


def test_coarse_case_requires_only_the_expected_composition_diagnostic():
    document = report()
    document["validation"]["diagnostics"] = [
        {
            "level": "info",
            "code": "symbolic-transforms-composed",
            "concrete_index": 1,
            "transform_index": 0,
        }
    ]
    probe.validate_report(document, stop=PC + 4, count=1, injected=False, coarse=True)
    with pytest.raises(ValueError):
        probe.validate_report(document, stop=PC + 4, count=1, injected=False)
    document["validation"]["diagnostics"][0]["level"] = "incomplete"
    with pytest.raises(ValueError):
        probe.validate_report(document, stop=PC + 4, count=1, injected=False, coarse=True)


def test_injection_requires_a_confirmed_flag_mismatch():
    document = report(True)
    document["validation"]["entries"][0]["errors"][0]["severity"] = "incomplete"
    with pytest.raises(ValueError):
        probe.validate_report(document, stop=PC + 4, count=1, injected=True)
