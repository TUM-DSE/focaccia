"""Static validation and boundary-only contract for exclusive-region observation."""

from enum import Enum
import os
import shutil
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType, SimpleNamespace
from typing import cast

import pytest

try:
    import lldb
except ImportError:
    lldb = None
    sys.modules["lldb"] = cast(ModuleType, SimpleNamespace(eStopReasonBreakpoint=3))

from focaccia.native.exclusive_target import (
    BoundaryEvidence,
    ExclusiveRegion,
    RegionInstruction,
    execute_region,
    observe_exclusive_attempt,
    plan_region,
    verify_region,
)
from focaccia.native.lldb_target import ConcreteExecutionError, LLDBLocalTarget

BASE = 0x1000
WORDS = (
    (BASE, 0xC85FFC04),  # LDAXR X4, [X0]
    (BASE + 4, 0xEB05009F),  # CMP X4, X5
    (BASE + 8, 0x540000A1),  # B.NE BASE+0x1c
    (BASE + 12, 0x910B6060),  # ADD X0, X3, #0x2d8
    (BASE + 16, 0xC804FC02),  # STLXR W4, X2, [X0]
)
REGION = ExclusiveRegion(
    BASE,
    tuple((pc, word.to_bytes(4, "little")) for pc, word in WORDS),
    (BASE + 20, BASE + 0x1C),
    len(WORDS),
)


class Memory:
    capability = "full-boundary-memory-diff"


class OutcomeState(Enum):
    STOPPED = 1


class FakeThread:
    def __init__(self, bp_id):
        self.bp_id = bp_id

    def GetStopReason(self):
        return 3

    def GetStopReasonDataCount(self):
        return 1

    def GetStopReasonDataAtIndex(self, index):
        return self.bp_id


class FakeProcess:
    def __init__(self, target):
        self.target = target

    def GetProcessID(self):
        return 100

    def GetSelectedThread(self):
        return FakeThread(self.target.hit_id)


class FakeTarget:
    archname = "aarch64"
    arch: SimpleNamespace

    def __init__(self, exit_pc):
        self.pc = BASE
        self.exit_pc = exit_pc
        self.bytes = {pc: word.to_bytes(4, "little") for pc, word in WORDS}
        self.bytes[BASE + 20] = (0x35000000).to_bytes(4, "little")
        self.bytes[BASE + 0x1C] = (0xD5033BBF).to_bytes(4, "little")
        self.bps = {}
        self.hit_id = None
        self.process = FakeProcess(self)
        self.exited = False
        self.capture_saw_restored_code = []

    def read_memory(self, pc, size):
        return self.bytes[pc][:size]

    def read_pc(self):
        return self.pc

    def read_registers(self):
        return {"PC": self.pc, "X0": 0, "CPSR": 0}

    def memory_snapshot(self):
        return Memory()

    def mappings(self):
        return ("private-readable",)

    @property
    def stdout(self):
        return b""

    @property
    def stderr(self):
        return b""

    def get_mappings(self):
        return [SimpleNamespace(start_address=BASE, end_address=BASE + 0x100, perms="rwx")]

    def set_breakpoint(self, pc):
        ident = len(self.bps) + 10
        self.bps[ident] = (pc, self.bytes[pc])
        self.bytes[pc] = b"\xcc\xcc\xcc\xcc"
        return ident

    def remove_breakpoint(self, ident):
        pc, code = self.bps.pop(ident)
        self.bytes[pc] = code

    def run(self):
        matching = [(ident, pc) for ident, (pc, _code) in self.bps.items() if pc == self.exit_pc]
        assert matching
        self.hit_id, self.pc = matching[0]

    def is_exited(self):
        return self.exited

    def execution_outcome(self):
        return SimpleNamespace(state=OutcomeState.STOPPED, stop_signal=None)


def capture(target):
    assert not target.bps, "post-RAM evidence must be captured after breakpoint restoration"
    target.capture_saw_restored_code.append(True)
    return BoundaryEvidence(
        memory=Memory(),
        registers={"PC": target.pc, "X0": 0, "CPSR": 0},
        mappings=("private-readable",),
        stdout=b"",
        stderr=b"",
    )


def test_region_discovery_and_verification_cover_all_exits():
    target = FakeTarget(BASE + 20)
    region = plan_region(target, BASE)
    assert region == REGION
    assert verify_region(region) == BASE + 16


@pytest.mark.parametrize("exit_pc", [BASE + 20, BASE + 0x1C])
def test_observer_runs_one_attempt_to_any_verified_exit_and_restores_before_capture(
    exit_pc,
    monkeypatch,
):
    monkeypatch.setattr("os.pidfd_open", lambda pid: os.open(os.devnull, os.O_RDONLY))
    monkeypatch.setattr("signal.pidfd_send_signal", lambda fd, sig: None)
    target = FakeTarget(exit_pc)
    result = observe_exclusive_attempt(target, REGION, lambda: capture(target))
    assert result.exit_pc == exit_pc
    assert result.store_pc == BASE + 16
    assert result.region_boundary_only
    assert target.capture_saw_restored_code == [True, True]
    assert not target.bps


def test_execute_region_returns_raw_boundary_evidence_without_classification(monkeypatch):
    monkeypatch.setattr("os.pidfd_open", lambda pid: os.open(os.devnull, os.O_RDONLY))
    monkeypatch.setattr("signal.pidfd_send_signal", lambda fd, sig: None)
    target = FakeTarget(BASE + 20)
    target.arch = SimpleNamespace(archname="aarch64")
    outcome, metadata = execute_region(target, REGION)
    assert outcome.state.name == "STOPPED"
    assert metadata["exit_pc"] == BASE + 20
    assert metadata["region_boundary_only"]
    assert metadata["internal_pc_trace_available"] is False
    assert metadata["post"].registers["PC"] == BASE + 20


def test_cfg_rejects_retry_backedge_before_execution():
    backwards = RegionInstruction(
        BASE + 8, (0x54FFFFA1).to_bytes(4, "little"), (BASE + 12, BASE - 4)
    )
    malformed = ExclusiveRegion(
        BASE,
        REGION.instructions[:2] + ((backwards.pc, backwards.code),) + REGION.instructions[3:],
        (BASE + 20, BASE + 0x1C),
        len(REGION.instructions),
    )
    with pytest.raises(ConcreteExecutionError, match="Backward edge"):
        verify_region(malformed)


def test_straightline_exclusive_attempt_and_backward_external_skip_exit():
    straight = ExclusiveRegion(
        BASE,
        tuple((BASE + 4 * i, word.to_bytes(4, "little")) for i, word in enumerate(
            (0x885FFC02, 0x2A020022, 0x8803FC02))),
        (BASE + 12,), 3,
    )
    assert verify_region(straight) == BASE + 8
    backward = ExclusiveRegion(
        BASE,
        tuple((BASE + 4 * i, word.to_bytes(4, "little")) for i, word in enumerate(
            (0x885FFC82, 0x6B0200BF, 0x54FFFF61, 0x8802FC83))),
        (BASE + 16, BASE - 12), 4,
    )
    assert verify_region(backward) == BASE + 12


def test_cfg_rejects_syscall_or_call_before_execution():
    svc = (BASE + 12, (0xD4000001).to_bytes(4, "little"))
    bad = ExclusiveRegion(
        BASE,
        REGION.instructions[:3] + (svc, REGION.instructions[4]),
        REGION.exit_pcs,
        REGION.max_steps,
    )
    with pytest.raises(ConcreteExecutionError, match="trap|Syscall"):
        verify_region(bad)


@pytest.mark.parametrize(
    "word",
    [
        0x00000000,  # UDF
        0xD4200000,  # BRK
        0xF9000000,  # STR X0, [X0]
        0xF9400020,  # LDR X0, [X1]
        0xD53BD040,  # MRS X0, TPIDR_EL0
        0xD51B4200,  # MSR DAIFSET, #2
    ],
)
def test_cfg_rejects_unsupported_memory_sysreg_and_trap_instructions(word):
    invalid = (BASE + 12, word.to_bytes(4, "little"))
    bad = ExclusiveRegion(
        BASE,
        REGION.instructions[:3] + (invalid, REGION.instructions[4]),
        REGION.exit_pcs,
        REGION.max_steps,
    )
    with pytest.raises(ConcreteExecutionError, match="Unsupported|trap|privileged"):
        verify_region(bad)


def test_cfg_rejects_unlisted_exit_before_execution():
    wrong_branch = (BASE + 8, 0x54000081.to_bytes(4, "little"))
    bad = ExclusiveRegion(
        BASE,
        REGION.instructions[:2] + (wrong_branch,) + REGION.instructions[3:],
        REGION.exit_pcs,
        REGION.max_steps,
    )
    with pytest.raises(ConcreteExecutionError, match="undeclared PC"):
        verify_region(bad)


def test_missing_full_private_ram_evidence_is_rejected():
    with pytest.raises(ConcreteExecutionError, match="full private-memory"):
        BoundaryEvidence(object(), {"PC": BASE}, (), b"", b"")


@pytest.mark.skipif(
    os.uname().machine not in {"aarch64", "arm64"}
    or lldb is None
    or not shutil.which("clang")
    or not shutil.which("ld.lld")
    or not shutil.which("nm"),
    reason="requires native AArch64, LLDB Python, clang/LLD and nm",
)
@pytest.mark.parametrize("entry_method", ["run_until", "hardware_step"])
@pytest.mark.parametrize(
    ("expected", "exit_name", "final_value"),
    [
        (7, "after_store", 8),  # compare matches; STLXR may succeed or lose reservation
        (8, "comparison_skip", 7),  # comparison-skip exit, no store-exclusive
    ],
)
def test_real_aarch64_complete_region_observation(
    expected, exit_name, final_value, entry_method, record_property
):

    assembly = f"""
.global _start
.global region
.global after_store
.global comparison_skip
.text
_start:
  adr x0, value
  mov w1, #{expected}
region:
  ldaxr x4, [x0]
  cmp x4, x1
  b.ne comparison_skip
  add x2, x4, #1
  stlxr w6, x2, [x0]
after_store:
  cbnz w6, region
  b finish
comparison_skip:
  dmb ish
finish:
  nop
  mov x8, #93
  svc #0
.data
.align 3
value: .quad 7
"""
    with TemporaryDirectory(prefix="exclusive-test-") as directory:
        root = Path(directory)
        asm = root / "fixture.s"
        binary = root / "fixture.elf"
        asm.write_text(assembly)
        linker_dir = Path(cast(str, shutil.which("ld.lld"))).parent
        subprocess.run(
            [
                cast(str, shutil.which("clang")),
                "-target",
                "aarch64-linux-gnu",
                f"-B{linker_dir}",
                "-nostdlib",
                "-static",
                "-Wl,-e,_start",
                "-Wl,--build-id=none",
                "-o",
                str(binary),
                str(asm),
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        symbols = subprocess.run(
            ["nm", "-n", str(binary)], check=True, text=True, capture_output=True, timeout=10
        ).stdout
        addresses = {
            fields[-1]: int(fields[0], 16)
            for line in symbols.splitlines()
            if len(fields := line.split()) >= 3
        }
        stdout_path, stderr_path = root / "stdout", root / "stderr"
        native = LLDBLocalTarget(
            str(binary),
            [],
            None,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
        )
        try:
            if entry_method == "run_until":
                native.run_until(addresses["region"])
                assert native.read_pc() == addresses["region"]
            else:
                while native.read_pc() != addresses["region"]:
                    native.step()
                assert native.read_register("CPSR") & (1 << 21)  # debugger SS bit after step
            region = plan_region(native, addresses["region"])
            original_code = {
                pc: native.read_memory(pc, 4)
                for pc in (*[address for address, _ in region.instructions], *region.exit_pcs)
            }
            assert region.exit_pcs == (
                addresses["after_store"],
                addresses["comparison_skip"],
            )

            class PrivateMemory:
                capability = "full-boundary-memory-diff"
                regions: tuple

            def evidence():
                mappings = []
                regions = []
                total = 0
                for line in (
                    Path(f"/proc/{native.process.GetProcessID()}/maps").read_text().splitlines()
                ):
                    fields = line.split(maxsplit=5)
                    lo, hi = (int(value, 16) for value in fields[0].split("-", 1))
                    perms = fields[1]
                    name = fields[5] if len(fields) > 5 else ""
                    mapping = SimpleNamespace(start=lo, end=hi, perms=perms, name=name)
                    mappings.append(mapping)
                    if "r" in perms and "p" in perms and name not in {"[vvar]", "[vvar_vclock]"}:
                        total += hi - lo
                        if total > 256 * 1024 * 1024:
                            raise ConcreteExecutionError("Test memory map exceeds snapshot policy.")
                        regions.append((mapping, native.read_memory(lo, hi - lo)))
                memory = PrivateMemory()
                memory.regions = tuple(regions)
                registers = {
                    **{f"X{i}": native.read_register(f"X{i}") for i in range(31)},
                    **{name: native.read_register(name) for name in ("SP", "PC", "CPSR")},
                    **{f"V{i}": native.read_register(f"V{i}") for i in range(32)},
                }
                for name in ("FPCR", "FPSR"):
                    reg = native.process.GetSelectedThread().GetFrameAtIndex(0).FindRegister(name)
                    assert lldb is not None
                    error = lldb.SBError()
                    registers[name] = int(reg.GetValueAsUnsigned(error, 0))
                    assert error.Success()
                stdout = stdout_path.read_bytes() if stdout_path.exists() else b""
                stderr = stderr_path.read_bytes() if stderr_path.exists() else b""
                return BoundaryEvidence(memory, registers, tuple(mappings), stdout, stderr)

            statuses = {0: 0, 1: 0}
            attempts = 100 if exit_name == "after_store" else 1
            for attempt in range(attempts):
                observed = observe_exclusive_attempt(native, region, evidence)
                assert observed.exit_pc == addresses[exit_name]
                assert all(native.read_memory(pc, 4) == code for pc, code in original_code.items())
                pre_memory = cast(PrivateMemory, observed.pre.memory)
                post_memory = cast(PrivateMemory, observed.post.memory)
                assert pre_memory.regions and post_memory.regions
                assert observed.post.registers["PC"] == observed.exit_pc
                data_region = next(
                    (mapping, data)
                    for mapping, data in post_memory.regions
                    if mapping.start <= addresses["value"] < mapping.end
                )
                assert "w" in data_region[0].perms and "p" in data_region[0].perms
                assert data_region[0].name.endswith("fixture.elf")
                offset = addresses["value"] - data_region[0].start
                observed_value = int.from_bytes(data_region[1][offset : offset + 8], "little")
                if exit_name == "after_store":
                    status = observed.post.registers["X6"]
                    assert status in (0, 1)
                    statuses[status] += 1
                    assert observed_value == (8 if status == 0 else 7)
                    if status == 0:
                        break
                    # Continue the real program's CBNZ retry transition. The observer
                    # has already restored exit code; this debugger step is outside LL/SC.
                    native.step()
                    assert native.read_pc() == region.entry_pc
                else:
                    assert observed_value == final_value
            if exit_name == "after_store":
                assert statuses[0] > 0, f"no successful STLXR among 100 attempts: {statuses}"
                record_property(f"{entry_method}_stlxr_status_counts", repr(statuses))
                record_property(
                    f"{entry_method}_memory_values",
                    "status 1 => 7 (unchanged); status 0 => 8 (stored)",
                )
        finally:
            native.process.Kill()
            assert lldb is not None
            lldb.SBDebugger.Destroy(native.debugger)
