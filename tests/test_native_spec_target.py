from __future__ import annotations

import os
import struct
import threading
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

import pytest

from focaccia.arch import supported_architectures
from focaccia.execution import ExecutionState
from focaccia.native import spec_target
from focaccia.native.lldb_target import ConcreteExecutionError, ConcreteMemoryError, LLDBLocalTarget

@pytest.fixture
def elf_fixture(tmp_path):
    path = tmp_path / "header.elf"
    data = bytearray(120)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQ", data, 16, 2, 183, 1, 0x4001B0, 64)
    struct.pack_into("<HHH", data, 52, 64, 56, 1)
    struct.pack_into("<I", data, 64, 1)
    path.write_bytes(data)
    path.chmod(0o755)
    return path


def test_elf_architecture_and_interpreter_detection(elf_fixture):
    assert spec_target.NativeSpecTarget._elf_arch(str(elf_fixture)) == "aarch64"
    assert spec_target.NativeSpecTarget._elf_entry(str(elf_fixture)) == 0x4001B0
    assert not spec_target.NativeSpecTarget._has_interpreter(str(elf_fixture))


def test_foreign_isa_rejected_before_launch(tmp_path, monkeypatch, elf_fixture):
    foreign = tmp_path / "foreign.elf"
    data = bytearray(elf_fixture.read_bytes())
    machine = 183 if os.uname().machine in {"x86_64", "amd64"} else 62
    data[18:20] = machine.to_bytes(2, "little")
    foreign.write_bytes(data)
    foreign.chmod(0o755)
    launches = []
    monkeypatch.setattr(spec_target, "LLDBLocalTarget", lambda *a, **kw: launches.append(a))
    with pytest.raises(ConcreteExecutionError, match="Foreign ISA"):
        spec_target.NativeSpecTarget(foreign)
    assert not launches


@pytest.mark.parametrize("arch_name", ["aarch64", "x86_64"])
def test_register_collection_uses_arch_specific_canonical_layout(arch_name, monkeypatch):
    arch = supported_architectures[arch_name]
    register = type("Register", (), {
        "IsValid": lambda self: True,
        "GetByteSize": lambda self: 4,
        "GetValueAsUnsigned": lambda self, error, default: 7,
    })()
    frame = type("Frame", (), {"FindRegister": lambda self, name: register})()
    thread = type("Thread", (), {"GetFrameAtIndex": lambda self, index: frame})()
    def read_register(self, name):
        if arch_name == "x86_64" and name.startswith(("ZMM", "ST", "MM")):
            raise AssertionError(f"Unqualified unsupported Intel register requested: {name}")
        return 7

    fake = type("Concrete", (), {
        "arch": arch,
        "archname": arch_name,
        "process": type("Process", (), {
            "GetNumThreads": lambda self: 1,
            "GetSelectedThread": lambda self: thread,
        })(),
        "read_register": read_register,
        "read_flags": lambda self: {"N": 1, "DIT": 1} if arch_name == "aarch64" else {"CF": 1},
    })()
    target = object.__new__(spec_target.NativeSpecTarget)
    target._closed = False
    # Partial debugger fixture implements only register observation.
    target._target = cast(LLDBLocalTarget, fake)
    regs = target.read_registers()
    if arch_name == "aarch64":
        assert set(arch.regnames) - {"DCZID_EL0"} <= regs.keys()
    assert regs["N" if arch_name == "aarch64" else "CF"] == 1
    if arch_name == "aarch64":
        assert "DIT" not in regs  # Legacy alias must not expose hardware SS as DIT.
    if arch_name == "x86_64":
        assert {"RIP", "RFLAGS", "RAX", "R15", "XMM0", "XMM15", "FS_BASE", "GS_BASE"} <= regs.keys()
        assert not any(name.startswith(("ZMM", "ST", "MM")) for name in regs)


def test_snapshot_contract_does_not_claim_store_addresses():
    mapping = spec_target.SpecMemoryMapping(0x1000, 0x1004, True, True, False, True, "[heap]")
    snap = spec_target.MemorySnapshot(
        spec_target.MEMORY_EVIDENCE_CAPABILITY, ((mapping, b"abcd"),)
    )
    assert snap.capability == "full-boundary-memory-diff"
    assert "store" not in snap.capability


@pytest.mark.integration
def test_native_aarch64_launch_entry_registers_snapshot_and_step():
    path = os.environ.get("FOCACCIA_NATIVE_SPEC_FIXTURE")
    if not path or not Path(path).is_file() or os.uname().machine not in {"aarch64", "arm64"}:
        pytest.skip("Requires an AArch64 host and FOCACCIA_NATIVE_SPEC_FIXTURE")
    with spec_target.NativeSpecTarget(path) as target:
        assert target.arch is supported_architectures["aarch64"]
        assert target.pid > 0
        registers = target.read_registers()
        assert {"PC", "SP", "X0", "CPSR", "FPCR", "FPSR", "TPIDR"}.issubset(registers)
        assert all(f"V{i}" in registers for i in range(32))
        before = target.memory_snapshot()
        assert before.capability == spec_target.MEMORY_EVIDENCE_CAPABILITY
        assert before.regions
        assert all(m.private and m.read for m, _ in before.regions)
        outcome = None
        for _ in range(10000):
            outcome = target.step()
            if outcome.state == ExecutionState.EXITED:
                break
            assert outcome.state == ExecutionState.STOPPED
            target.read_registers()
        assert outcome is not None and outcome.state == ExecutionState.EXITED
        assert target.exit_status == 0
        assert target.stdout == b""
        assert target.stderr == b""


def test_close_is_idempotent_and_observation_fails_after_close(monkeypatch):
    # Exercise ownership cleanup without launching a child.
    target = object.__new__(spec_target.NativeSpecTarget)
    target._closed = False
    target._target = None
    target._timeout_lock = threading.Lock()
    target._timeout_timer = None
    target._timeout_pidfd = None
    target._stdout = target._stderr = b""
    target._output_dir = cast(
        TemporaryDirectory[str], type("Temp", (), {"cleanup": lambda self: None})()
    )
    target._stdout_path = target._stderr_path = "/missing/native-target-output"
    target.close()
    target.close()
    with pytest.raises(ConcreteExecutionError, match="closed"):
        target.read_registers()


def test_mapping_snapshot_fails_closed_for_shared_writable(monkeypatch):
    target = object.__new__(spec_target.NativeSpecTarget)
    target._closed = False
    # Partial debugger fixture implements only mapping metadata.
    target._target = cast(LLDBLocalTarget, type("Target", (), {
        "process": type("Process", (), {"GetProcessID": lambda self: os.getpid()})(),
        "get_mappings": lambda self: [],
    })())
    real_read = Path.read_text
    monkeypatch.setattr(Path, "read_text", lambda self, *a, **kw: "1000-2000 rw-s 00000000 00:00 0 /shared")
    with pytest.raises(ConcreteMemoryError, match="Shared writable"):
        target.mappings()
    monkeypatch.setattr(Path, "read_text", lambda self, *a, **kw: "1000-2000 -w-p 00000000 00:00 0 [anon]")
    with pytest.raises(ConcreteMemoryError, match="unreadable"):
        target.mappings()
    monkeypatch.setattr(Path, "read_text", real_read)
