"""Static contracts for the whole-program #2248 harness; no QEMU is launched."""

import json
from pathlib import Path
import runpy
import struct
from types import SimpleNamespace

import pytest

PROBE = runpy.run_path(str(Path(__file__).parent / "probes/tir_no_replay_smoke.py"))
probe = SimpleNamespace(**PROBE)
PC = 0x400000


def elf(code=probe.EXPECTED_CALLME, *, dynamic=False):
    data = bytearray(0x100 + len(code))
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", data, 16, 2, 183, 1)
    struct.pack_into("<QQ", data, 24, PC, 64)
    struct.pack_into("<HH", data, 54, 56, 2 if dynamic else 1)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0x100, PC, PC, len(code), len(code), 4)
    if dynamic:
        struct.pack_into("<I", data, 120, 3)
    data[0x100:] = code
    return data


def test_static_aarch64_elf_entry_and_file_backed_load_are_required(tmp_path):
    binary = tmp_path / "fixture"
    binary.write_bytes(elf())
    entry, loads = probe.elf_loads(binary)
    assert entry == PC
    assert probe.read_image(loads, PC, len(probe.EXPECTED_CALLME)) == probe.EXPECTED_CALLME


@pytest.mark.parametrize("mutation", [
    lambda data: data.__setitem__(5, 2),
    lambda data: struct.pack_into("<H", data, 16, 3),
    lambda data: struct.pack_into("<H", data, 18, 62),
    lambda data: struct.pack_into("<H", data, 54, 8),
])
def test_malformed_fixture_is_rejected(tmp_path, mutation):
    data = elf()
    mutation(data)
    binary = tmp_path / "fixture"
    binary.write_bytes(data)
    with pytest.raises(ValueError):
        probe.elf_loads(binary)


def test_dynamic_interpreter_is_rejected(tmp_path):
    binary = tmp_path / "fixture"
    binary.write_bytes(elf(dynamic=True))
    with pytest.raises(ValueError, match="interpreter"):
        probe.elf_loads(binary)


def test_plugin_manifest_binds_empty_argv_environment_and_explicit_cpu(tmp_path):
    binary = tmp_path / "fixture"
    binary.write_bytes(b"fixture")
    identity = probe.launch_identity(binary)
    option = probe.plugin_option("plugin.so", tmp_path / "socket", identity, PC, PC + 8,
                                 coarse=True, cutpoints=(PC + 4,))
    assert "coarse=on" in option and f"cutpoint={PC + 4}" in option
    assert identity.argv_sha256 == probe.manifest_sha256([])
    assert identity.env_sha256 == probe.manifest_sha256([])
    assert identity.cpu_sha256 == probe.manifest_sha256(probe.CPU_PROFILE)


def report(*, mismatch=False):
    entries = [{"errors": []}, {"errors": []}]
    if mismatch:
        entries[0]["errors"] = [{"severity": "confirmed", "subject": "X0"}]
    return {
        "status": "mismatch" if mismatch else "accepted",
        "trace": {"terminal_pc": PC + 8},
        "completion": {"scope": "whole-program", "complete": True,
                       "execution_complete": True},
        "validation": {"entries": entries},
    }


@pytest.mark.parametrize("mismatch", [False, True])
def test_report_requires_complete_terminal_evidence_and_localized_x0(mismatch):
    probe.validate_report(report(mismatch=mismatch), mismatch=mismatch, terminal_pc=PC + 8)


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(status="incomplete"),
    lambda value: value["completion"].update(complete=False),
    lambda value: value["completion"].update(execution_complete=False),
    lambda value: value["completion"].update(scope="witness"),
    lambda value: value["trace"].update(terminal_pc=PC),
])
def test_report_rejects_weakened_whole_program_evidence(mutation):
    document = report()
    mutation(document)
    with pytest.raises(ValueError):
        probe.validate_report(document, mismatch=False, terminal_pc=PC + 8)


def test_harness_declares_no_rr_miasm_or_state_mutation():
    source = Path(PROBE["__file__"]).read_text()
    assert '"record_replay": False' in source
    assert '"miasm_semantics": False' in source
    assert '"synthetic_state_mutation": False' in source
    assert "-g" not in json.dumps(PROBE.get("CPU_PROFILE"))
