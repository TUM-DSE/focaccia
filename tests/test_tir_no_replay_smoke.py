"""Static contracts for the whole-program AArch64 TIR harness; no QEMU is launched."""

import json
from pathlib import Path
import runpy
import struct
from types import SimpleNamespace

import pytest

PROBE = runpy.run_path(str(Path(__file__).parent / "probes/tir_no_replay_smoke.py"))
probe = SimpleNamespace(**PROBE)
PC = 0x400000


def test_fixtures_have_canonical_focaccia_eval_semantics():
    root = Path(__file__).parents[1] / "reproducers"
    source2248 = (root / "issue-2248-tir/main.c").read_text()
    source364 = (root / "issue-364-tir/main.c").read_text()
    source2419 = (root / "issue-2419-tir/main.c").read_text()
    assert "return callme(0, 0, 0, 1, 2) == -1 ? 0 : 1;" in source2248
    assert "int8_t values[3] = { 0, -1, 3 };" in source364
    assert "0x11111111deadbeef" in source2419
    assert "0x22222222cafebabe" in source2419
    assert all("printf" not in source for source in (source2248, source364, source2419))

    probe = (Path(__file__).parent / "probes/tir_no_replay_smoke.py").read_text()
    assert 'writes[0]["value"] != "03"' in probe
    assert "self.state.read_memory(address, len(expected))" in probe
    assert '"final_memory_verified": True' in probe


def test_remaining_trigger_opcodes_and_claims_are_exact():
    root = Path(__file__).parents[1] / "reproducers"
    atomic = json.loads((root / "issue-364-tir/instruction-classes.json").read_text())
    ldapur = json.loads((root / "issue-2419-tir/instruction-classes.json").read_text())
    assert atomic["instructions"] == [{
        "bytes": "20402238",
        "class": "decode_aarch64_memory_atomicops_ld",
        "assembly": "ldsmaxb w2, w0, [x1]",
        "evidence": "one TIR atomic state transition reads the old byte, returns it in W0, and conditionally writes the signed maximum",
    }]
    assert ldapur["instructions"][0]["bytes"] == "20805fd9"
    assert ldapur["instructions"][0]["class"].endswith("signed_offset_lda_stl")


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
    option = probe.plugin_option("plugin.so", tmp_path / "socket", identity, PC, PC + 8)
    assert "online-blocks=on" in option
    assert "cutpoint=" not in option and "coarse=" not in option
    assert identity.argv_sha256 == probe.manifest_sha256([])
    assert identity.env_sha256 == probe.manifest_sha256([])
    assert identity.cpu_sha256 == probe.manifest_sha256(probe.CPU_PROFILE)


def report(*, mismatch=False):
    errors = [{"severity": "confirmed", "subject": "X0"}] if mismatch else []
    return {
        "status": "mismatch" if mismatch else "accepted",
        "terminal": {"pc": PC + 8},
        "completion": {"scope": "whole-program", "complete": True,
                       "execution_complete": True},
        "errors": errors,
    }


@pytest.mark.parametrize("mismatch", [False, True])
def test_report_requires_complete_terminal_evidence_and_localized_x0(mismatch):
    probe.validate_report(
        report(mismatch=mismatch), issue=2248, mismatch=mismatch, terminal_pc=PC + 8
    )


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(status="incomplete"),
    lambda value: value["completion"].update(complete=False),
    lambda value: value["completion"].update(execution_complete=False),
    lambda value: value["completion"].update(scope="witness"),
    lambda value: value["terminal"].update(pc=PC),
])
def test_report_rejects_weakened_whole_program_evidence(mutation):
    document = report()
    mutation(document)
    with pytest.raises(ValueError):
        probe.validate_report(document, issue=2248, mismatch=False, terminal_pc=PC + 8)


def test_harness_is_single_execution_online_without_path_oracle():
    source = Path(PROBE["__file__"]).read_text()
    assert '"qemu_executions_per_case": 1' in source
    assert '"dynamic_path_oracle": False' in source
    assert '"record_replay": False' in source
    assert '"miasm_semantics": False' in source
    assert '"synthetic_state_mutation": False' in source
    assert "discover_execution" not in source
    assert "discover_logged_execution" not in source
    assert "-d\", \"in_asm" not in source
    assert "-g" not in json.dumps(PROBE.get("CPU_PROFILE"))
