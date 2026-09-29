"""Static contracts for the live #2248 smoke; no QEMU is launched here."""

import os
from pathlib import Path
import runpy
import socket
import struct
from types import SimpleNamespace

from miasm.expression.expression import ExprId, ExprInt
import pytest

from focaccia.completion import TraceScope
from focaccia.parser import parse_transformations, serialize_transformations

PROBE = runpy.run_path(str(Path(__file__).parent / "probes/tir_no_replay_smoke.py"))
probe = SimpleNamespace(**PROBE)
PC = 0x400000


def elf(code=probe.EXPECTED_CODE):
    data = bytearray(0x100 + len(code))
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", data, 16, 2, 183, 1)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HHH", data, 52, 64, 56, 1)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0x100, PC, PC, len(code), len(code), 4)
    data[0x100:] = code
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


def test_exact_region_is_read_from_executable_mapping():
    assert probe.read_region(bytes(elf()), PC, PC + 28) == probe.EXPECTED_CODE


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
        probe.read_region(bytes(data), PC, PC + 28)


@pytest.mark.parametrize(
    "start,stop",
    [(PC, PC), (PC + 1, PC + 4), (PC, PC + 32), (-4, 0), (PC, PC + 8192), (True, PC + 4)],
)
def test_invalid_region_bounds_are_rejected(start, stop):
    with pytest.raises(ValueError):
        probe.read_region(bytes(elf()), start, stop)


def test_reference_uses_tir_for_all_exact_instructions(tmp_path, monkeypatch):
    binary = tmp_path / "fixture"
    binary.write_bytes(elf())
    calls = []

    class Backend:
        def __init__(self, executable):
            assert executable == "fixture-oracle"

        def generate(self, instruction, state, context):
            assert not state.test_register("X0")
            calls.append(state.read_instructions(instruction.addr, 4))
            pc = ExprInt(instruction.addr + 4, 64)
            return pc, {ExprId("PC", 64): pc, ExprId("X0", 64): ExprId("X0", 64)}

    monkeypatch.setitem(probe.generate_reference.__globals__, "TirBackend", Backend)
    reference = probe.generate_reference(binary, PC, PC + 28, "fixture-oracle")
    assert calls == [probe.EXPECTED_CODE[index : index + 4] for index in range(0, 28, 4)]
    assert reference.require_addresses() == tuple(range(PC, PC + 28, 4))
    assert reference.scope is TraceScope.WITNESS
    assert reference.env.detlog is None
    path = tmp_path / "oracle.json"
    serialize_transformations(reference, path)
    with path.open() as stream:
        loaded = parse_transformations(stream)
    assert len(loaded) == 7
    assert loaded.scope is TraceScope.WITNESS
    assert loaded.env.binary_hash == reference.env.binary_hash


def test_reference_rejects_any_noncanonical_instruction(tmp_path):
    binary = tmp_path / "fixture"
    changed = bytearray(probe.EXPECTED_CODE)
    changed[0] ^= 1
    binary.write_bytes(elf(bytes(changed)))
    with pytest.raises(ValueError, match="exact seven-instruction"):
        probe.generate_reference(binary, PC, PC + 28, "must-not-run")


def report(*, coarse=False, mismatch=False):
    count = 1 if coarse else 7
    diagnostics = []
    if coarse:
        diagnostics = [{
            "level": "info",
            "code": "symbolic-transforms-composed",
            "concrete_index": 1,
            "transform_index": 0,
        }]
    entries = [{"errors": []} for _ in range(count)]
    if mismatch:
        entries[-1]["errors"] = [{"severity": "confirmed", "subject": "X0"}]
    return {
        "schema": "focaccia-qemu-validation-v1",
        "status": "mismatch" if mismatch else "accepted",
        "trace": {
            "complete": True,
            "terminal_reached": True,
            "terminal_pc": PC + 28,
            "transform_count": count,
            "state_count": count + 1,
        },
        "replay": {"active": False, "record_count": 0},
        "completion": {"scope": "witness"},
        "validation": {"entry_count": count, "diagnostics": diagnostics, "entries": entries},
    }


@pytest.mark.parametrize("coarse,mismatch", [(False, False), (True, False), (True, True)])
def test_report_accepts_only_required_matrix_evidence(coarse, mismatch):
    probe.validate_report(report(coarse=coarse, mismatch=mismatch), stop=PC + 28, mismatch=mismatch, coarse=coarse)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda doc: doc.update(status="incomplete"),
        lambda doc: doc["trace"].update(complete=False),
        lambda doc: doc["trace"].update(terminal_reached=False),
        lambda doc: doc["trace"].update(state_count=1),
        lambda doc: doc["trace"].update(terminal_pc=PC),
        lambda doc: doc["validation"].update(entry_count=0),
        lambda doc: doc["replay"].update(active=True),
        lambda doc: doc["completion"].update(scope="whole-program"),
    ],
)
def test_report_rejects_missing_bounded_evidence(mutate):
    document = report()
    mutate(document)
    with pytest.raises(ValueError):
        probe.validate_report(document, stop=PC + 28, mismatch=False, coarse=False)


def test_coarse_case_requires_exact_composition_diagnostic():
    document = report(coarse=True)
    document["validation"]["diagnostics"][0]["level"] = "incomplete"
    with pytest.raises(ValueError):
        probe.validate_report(document, stop=PC + 28, mismatch=False, coarse=True)


@pytest.mark.parametrize("severity,subject", [("possible", "X0"), ("confirmed", "X1")])
def test_injected_coarse_requires_confirmed_x0_only(severity, subject):
    document = report(coarse=True, mismatch=True)
    document["validation"]["entries"][-1]["errors"][0].update(
        severity=severity, subject=subject
    )
    with pytest.raises(ValueError):
        probe.validate_report(document, stop=PC + 28, mismatch=True, coarse=True)
