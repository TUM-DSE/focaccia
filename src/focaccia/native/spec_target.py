"""Fail-closed native target for observing whole-program specifications.

Memory evidence is a boundary snapshot/diff only: a store that writes the
value already present is inherently invisible to before/after snapshots.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import signal
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Iterable

from focaccia.arch import Arch, supported_architectures
from focaccia.execution import ExecutionOutcome, ExecutionState
from focaccia.native.lldb_target import (
    ConcreteExecutionError,
    ConcreteMemoryError,
    ConcreteRegisterError,
    LLDBLocalTarget,
)

MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
MAX_MAPPINGS = 65536
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
# The vDSO ELF/code image is stable and readable; only its separate kernel-
# updated data pages are volatile. User code may inspect the vDSO symbol table.
VOLATILE_MAPPING_NAMES = {"[vvar]", "[vvar_vclock]"}
MEMORY_EVIDENCE_CAPABILITY = "full-boundary-memory-diff"


@dataclass(frozen=True, slots=True)
class SpecMemoryMapping:
    start: int
    end: int
    read: bool
    write: bool
    execute: bool
    private: bool
    name: str

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass(frozen=True, slots=True)
class MemorySnapshot:
    """Complete stable private-readable memory snapshot; never store addresses."""
    capability: str
    regions: tuple[tuple[SpecMemoryMapping, bytes], ...]

    def __post_init__(self) -> None:
        if self.capability != MEMORY_EVIDENCE_CAPABILITY:
            raise ValueError("Unsupported memory evidence capability.")


class NativeSpecTarget:
    """Run and observe one local ELF process using LLDB's native stepping.

    ``argv`` excludes argv[0], as in LLDBLocalTarget. ``env`` is an iterable
    of KEY=VALUE strings (or a mapping). All observations are concrete hardware
    observations, not model predictions.
    """

    def __init__(self, binary: str | os.PathLike[str], argv: Iterable[str] = (), env=()):
        self.binary = str(Path(binary).resolve())
        self._target: LLDBLocalTarget | None = None
        self._closed = False
        self._timeout_lock = threading.Lock()
        self._timeout_timer = None
        self._timeout_pidfd = None
        self._timed_out = False
        self.hardware_profile = None
        self._stdout = b""
        self._stderr = b""
        self._output_dir = None
        self._stdout_path = ""
        self._stderr_path = ""
        self._exit_status: int | None = None
        self._backend_status: int | None = None
        self._validate_elf(self.binary)
        elf_arch = self._elf_arch(self.binary)
        host_arch = {"aarch64": "aarch64", "arm64": "aarch64", "x86_64": "x86_64", "amd64": "x86_64"}.get(os.uname().machine)
        if host_arch is None or elf_arch != host_arch:
            raise ConcreteExecutionError(
                f"Foreign ISA: host is {host_arch or os.uname().machine}, ELF is {elf_arch}."
            )
        self._output_dir = tempfile.TemporaryDirectory(prefix="focaccia-native-")
        self._stdout_path = os.path.join(self._output_dir.name, "stdout")
        self._stderr_path = os.path.join(self._output_dir.name, "stderr")
        envp = [f"{k}={v}" for k, v in env.items()] if hasattr(env, "items") else list(env)
        try:
            self._target = LLDBLocalTarget(
                self.binary, list(argv), envp,
                stdout_path=self._stdout_path, stderr_path=self._stderr_path,
            )
            if self._target.archname not in supported_architectures:
                raise ConcreteExecutionError(f"Unsupported native ISA {self._target.archname}.")
            self.arch: Arch = self._target.arch
            expected = {"aarch64": {"aarch64", "arm64"}, "x86_64": {"x86_64", "amd64"}}
            if elf_arch not in expected.get(self.arch.archname, set()):
                raise ConcreteExecutionError(
                    f"Foreign ISA: ELF is {elf_arch}, LLDB launched {self._target.archname}."
                )
            self.pid = int(self._target.process.GetProcessID())
            if not self.pid:
                raise ConcreteExecutionError("LLDB launched a process without a valid PID.")
            self._check_single_thread()
            self._mappings = self.mappings()
            if not self._mappings:
                raise ConcreteMemoryError("No process mappings are available.")
            # A dynamic image's first stop may be in its loader rather than the
            # target ELF. The static-only policy fails closed at ELF metadata.
            if self._has_interpreter(self.binary):
                raise ConcreteExecutionError("Dynamic ELF interpreter unsupported: entry coverage is not assured.")
            pc_name = "PC" if self._target.archname == "aarch64" else "RIP"
            pc = self.read_registers().get(pc_name)
            if pc != self._elf_entry(self.binary):
                raise ConcreteExecutionError(
                    f"LLDB initial PC {pc!r} is not ELF entry {self._elf_entry(self.binary):#x}."
                )
            if not any(m.execute and m.start <= pc < m.end for m in self._mappings):
                raise ConcreteExecutionError("ELF entry is not in an executable mapping.")
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _elf_header(path: str) -> tuple[bytes, int]:
        with open(path, "rb") as f:
            header = f.read(64)
        if len(header) < 64 or header[:4] != b"\x7fELF" or header[4] != 2:
            raise ConcreteExecutionError("Only ELF64 binaries are supported.")
        if header[5] not in (1, 2):
            raise ConcreteExecutionError("Invalid ELF byte order.")
        return header, header[5]

    @classmethod
    def _elf_entry(cls, path: str) -> int:
        header, endian = cls._elf_header(path)
        order = "little" if endian == 1 else "big"
        elf_type = int.from_bytes(header[16:18], order)
        if elf_type != 2:  # ET_EXEC; ET_DYN needs a proven load-bias calculation.
            raise ConcreteExecutionError("Only fixed-address ET_EXEC ELF entry is supported.")
        return int.from_bytes(header[24:32], order)

    @classmethod
    def _elf_arch(cls, path: str) -> str:
        header, endian = cls._elf_header(path)
        machine = int.from_bytes(header[18:20], "little" if endian == 1 else "big")
        return {183: "aarch64", 62: "x86_64"}.get(machine, f"e_machine={machine}")

    @classmethod
    def _validate_elf(cls, path: str) -> None:
        cls._elf_header(path)
        if not os.access(path, os.X_OK):
            raise ConcreteExecutionError(f"ELF is not executable: {path}")

    @classmethod
    def _has_interpreter(cls, path: str) -> bool:
        h, endian = cls._elf_header(path)
        order = "little" if endian == 1 else "big"
        phoff = int.from_bytes(h[32:40], order)
        phentsize = int.from_bytes(h[54:56], order)
        phnum = int.from_bytes(h[56:58], order)
        if phentsize < 56 or phnum > MAX_MAPPINGS:
            raise ConcreteExecutionError("Malformed ELF program-header table.")
        with open(path, "rb") as f:
            for i in range(phnum):
                f.seek(phoff + i * phentsize)
                ph = f.read(phentsize)
                if len(ph) != phentsize:
                    raise ConcreteExecutionError("Truncated ELF program-header table.")
                if int.from_bytes(ph[:4], order) == 3:  # PT_INTERP
                    return True
        return False

    def _check_live(self) -> LLDBLocalTarget:
        if self._closed or self._target is None:
            raise ConcreteExecutionError("Native target is closed.")
        return self._target

    def _check_single_thread(self) -> None:
        t = self._check_live()
        if t.process.GetNumThreads() != 1:
            raise ConcreteExecutionError("Multiple-thread execution is unsupported.")

    def configure_arm_profile(self, helper: str) -> dict:
        """Observe hardware configuration independently before guest execution.

        Pin the owned tracee and helper to one CPU. The helper is a separate
        native process; no destination register from the instruction under test
        supplies an expected value or alters the specification's instruction body.
        """
        self._check_live()
        if self.arch.archname != "aarch64" or self.hardware_profile is not None:
            raise ConcreteExecutionError("Invalid or repeated ARM hardware-profile setup.")
        cpus = os.sched_getaffinity(self.pid)
        if not cpus:
            raise ConcreteExecutionError("No CPU is available for native configuration capture.")
        cpu = min(cpus)
        os.sched_setaffinity(self.pid, {cpu})
        path = Path(helper).resolve(strict=True)
        completed = subprocess.run(
            [str(path), "--cpu", str(cpu)], capture_output=True, timeout=10, check=False,
        )
        if completed.returncode:
            raise ConcreteExecutionError(f"Hardware-profile capture failed: {completed.stderr!r}")
        try:
            profile = json.loads(completed.stdout)
            if (set(profile) != {"schema", "architecture", "cpu", "dczid_el0"}
                    or type(profile["schema"]) is not int or profile["schema"] != 1
                    or profile["architecture"] != "aarch64"
                    or type(profile["cpu"]) is not int or profile["cpu"] != cpu
                    or type(profile["dczid_el0"]) is not int
                    or not 0 <= profile["dczid_el0"] <= 31
                    or (profile["dczid_el0"] & 15) > 9
                    or os.sched_getaffinity(self.pid) != {cpu}):
                raise ValueError("Mismatched or unsupported hardware profile")
        except (ValueError, TypeError, KeyError) as error:
            raise ConcreteExecutionError(f"Invalid hardware-profile evidence: {error}") from error
        profile["helper_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.hardware_profile = MappingProxyType(dict(profile))
        return dict(profile)

    def read_registers(self) -> dict[str, int]:
        t = self._check_live()
        self._check_single_thread()
        result = {}
        # DCZID_EL0 is a capability/system register, not mutable architectural
        # execution state; LLDB kernels do not consistently expose it to inferiors.
        if t.archname == "aarch64":
            names = {
                *(f"X{i}" for i in range(31)), "SP", "PC", "CPSR", "TPIDR",
                *(f"V{i}" for i in range(32)), "FPCR", "FPSR",
            }
        elif t.archname == "x86_64":
            names = {
                "RIP", "RFLAGS", "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
                *(f"R{i}" for i in range(8, 16)), *(f"XMM{i}" for i in range(16)),
                "FS_BASE", "GS_BASE",
            }
        else:
            raise ConcreteRegisterError(f"Unsupported register profile for {t.archname}.")
        for name in sorted(names):
            try:
                if name in {"FPCR", "FPSR"}:
                    import lldb
                    reg = t.process.GetSelectedThread().GetFrameAtIndex(0).FindRegister(name)
                    if reg is None or not reg.IsValid() or reg.GetByteSize() != 4:
                        raise ConcreteRegisterError(f"Required observable register {name} unavailable.")
                    error = lldb.SBError()
                    result[name] = int(reg.GetValueAsUnsigned(error, 0))
                    if not error.Success():
                        raise ConcreteRegisterError(f"Unable to read {name}: {error.GetCString()}")
                else:
                    result[name] = t.read_register(name)
            except ConcreteRegisterError as e:
                raise ConcreteRegisterError(f"Required observable register {name} unavailable: {e}") from e
        for name, value in t.read_flags().items():
            # The shared legacy CPSR table also contains AArch32 aliases; bit
            # 21, for example, is native AArch64 debugger single-step state,
            # not DIT. This backend's modeled ARM status view is NZCV only.
            if t.arch.archname == "aarch64" and name.upper() not in {"N", "Z", "C", "V"}:
                continue
            result[name.upper()] = int(value)
        return result

    def read_memory(self, addr: int, size: int) -> bytes:
        return self._check_live().read_memory(addr, size)

    def mappings(self) -> tuple[SpecMemoryMapping, ...]:
        t = self._check_live()
        proc_maps = Path(f"/proc/{t.process.GetProcessID()}/maps")
        if not proc_maps.is_file():
            raise ConcreteMemoryError("Cannot inspect process-private mapping metadata.")
        rows = []
        try:
            for line in proc_maps.read_text().splitlines():
                fields = line.split(maxsplit=5)
                lo, hi = (int(x, 16) for x in fields[0].split("-", 1))
                perms = fields[1]
                name = fields[5] if len(fields) > 5 else ""
                rows.append(SpecMemoryMapping(lo, hi, "r" in perms, "w" in perms,
                                              "x" in perms, "p" in perms, name))
        except (OSError, ValueError, IndexError) as e:
            raise ConcreteMemoryError(f"Invalid process mapping metadata: {e}") from e
        if len(rows) > MAX_MAPPINGS:
            raise ConcreteMemoryError("Mapping count exceeds native resource policy.")
        # Verify each /proc mapping is represented by the debugger and fail on
        # shared-writable pages, which are outside the private-state boundary.
        lldb_maps = t.get_mappings()
        for m in rows:
            if m.write and not m.private:
                raise ConcreteMemoryError(f"Shared writable mapping unsupported: {m.name}")
            if m.write and not m.read:
                raise ConcreteMemoryError(f"Writable private mapping is unreadable: {m.name}")
            if m.name in VOLATILE_MAPPING_NAMES or not m.read:
                # Linux /proc retains PROT_NONE guard mappings which LLDB may
                # omit from its readable-region list. Their permissions remain
                # explicit evidence, but their bytes are outside this backend's
                # stable private-readable snapshot capability.
                continue
            covering = [x for x in lldb_maps if x.start_address <= m.start and x.end_address >= m.end]
            if len(covering) != 1:
                raise ConcreteMemoryError(f"LLDB mapping metadata missing for {m.start:#x}-{m.end:#x}.")
            if m.read and "r" not in covering[0].perms:
                raise ConcreteMemoryError(f"LLDB cannot read private mapping {m.start:#x}-{m.end:#x}.")
        return tuple(rows)

    def memory_snapshot(self) -> MemorySnapshot:
        regions = []
        total = 0
        for m in self.mappings():
            if m.name in VOLATILE_MAPPING_NAMES or not m.read or not m.private:
                continue
            total += m.size
            if total > MAX_SNAPSHOT_BYTES:
                raise ConcreteMemoryError(f"Snapshot exceeds {MAX_SNAPSHOT_BYTES} byte policy.")
            data = self.read_memory(m.start, m.size)
            if len(data) != m.size:
                raise ConcreteMemoryError(f"Incomplete snapshot for {m.start:#x}-{m.end:#x}.")
            regions.append((m, data))
        return MemorySnapshot(MEMORY_EVIDENCE_CAPABILITY, tuple(regions))

    def _capture_output(self, *, required: bool = False) -> None:
        for path, attr in ((self._stdout_path, "_stdout"), (self._stderr_path, "_stderr")):
            try:
                with open(path, "rb") as stream:
                    data = stream.read(MAX_OUTPUT_BYTES + 1)
                if len(data) > MAX_OUTPUT_BYTES:
                    if required:
                        raise ConcreteExecutionError("Native output exceeds the capture limit.")
                    data = data[:MAX_OUTPUT_BYTES]
                setattr(self, attr, data)
            except OSError as error:
                if required:
                    raise ConcreteExecutionError(f"Missing native output evidence: {path}") from error

    def set_timeout(self, seconds: float) -> None:
        """Bound even a synchronous debugger step blocked inside a syscall.

        The pidfd identifies this owned child, never a subsequently reused PID.
        The timer and close path serialize fd access to avoid descriptor reuse.
        """
        if not math.isfinite(seconds) or seconds <= 0:
            raise ValueError("Native timeout must be finite and positive.")
        self._check_live()
        with self._timeout_lock:
            if self._timeout_timer is not None:
                raise ConcreteExecutionError("Native execution timeout is already armed.")
            self._timeout_pidfd = os.pidfd_open(self.pid)

            def expire():
                with self._timeout_lock:
                    if self._closed or self._timeout_pidfd is None:
                        return
                    try:
                        signal.pidfd_send_signal(self._timeout_pidfd, signal.SIGKILL)
                    except ProcessLookupError:
                        return  # The owned process has already terminated.
                    self._timed_out = True

            self._timeout_timer = threading.Timer(seconds, expire)
            self._timeout_timer.daemon = True
            self._timeout_timer.start()

    def step(self) -> ExecutionOutcome:
        t = self._check_live()
        if self._timed_out:
            raise ConcreteExecutionError("Native execution timed out.")
        if t.is_exited():
            status = int(t.process.GetExitStatus())
            self._exit_status = 0 if status == 0 else None
            self._backend_status = status
            self._capture_output(required=True)
            # LLDB Linux reports signal death and exit(n) with ambiguous raw
            # status in some versions. Only zero is unambiguously successful.
            return ExecutionOutcome(ExecutionState.EXITED, exit_status=0 if status == 0 else None,
                                    backend_status=status)
        self._check_single_thread()
        if self.hardware_profile is not None and os.sched_getaffinity(self.pid) != {self.hardware_profile["cpu"]}:
            raise ConcreteExecutionError("Native hardware-profile CPU affinity changed.")
        t.step()
        if self._timed_out:
            raise ConcreteExecutionError("Native execution timed out.")
        result = t.execution_outcome()
        if result.state == ExecutionState.STOPPED:
            self._check_single_thread()
        elif result.state == ExecutionState.EXITED:
            status = int(t.process.GetExitStatus())
            self._exit_status = 0 if status == 0 else None
            self._backend_status = status
            self._capture_output(required=True)
            result = ExecutionOutcome(ExecutionState.EXITED, exit_status=0 if status == 0 else None,
                                      backend_status=status, description=result.description)
        return result

    def step_complete_instruction(
        self, *, repeat_pc: int | None = None, max_micro_steps: int = 1_000_000,
    ) -> ExecutionOutcome:
        """Observe a complete architectural instruction, including x86 REP.

        Debuggers may expose a REP iteration or the complete instruction per
        step. Coalesce same-PC iteration stops when the adapter has independently
        decoded REP. No predicted successor or post-state value selects the
        expected result: the specification predicts the full instruction first.
        """
        if repeat_pc is None:
            return self.step()
        if (self.arch.archname != "x86_64" or type(repeat_pc) is not int
                or repeat_pc < 0 or type(max_micro_steps) is not int or max_micro_steps <= 0):
            raise ConcreteExecutionError("Invalid native REP boundary policy.")
        target = self._check_live()
        if target.read_pc() != repeat_pc:
            raise ConcreteExecutionError("Native REP entry PC differs from its decoded boundary.")
        for _ in range(max_micro_steps):
            outcome = self.step()
            if outcome.state != ExecutionState.STOPPED or outcome.stop_signal is not None:
                return outcome
            if target.read_pc() != repeat_pc:
                return outcome
        raise ConcreteExecutionError("Native REP micro-step budget exceeded.")

    def refresh_output(self) -> None:
        """Capture output at a stopped syscall boundary before ABI comparison."""
        self._check_live()
        self._capture_output(required=True)

    @property
    def stdout(self) -> bytes:
        return self._stdout

    @property
    def stderr(self) -> bytes:
        return self._stderr

    @property
    def exit_status(self) -> int | None:
        """Known normal exit code (LLDB-ambiguous nonzero statuses are None)."""
        return self._exit_status

    @property
    def backend_status(self) -> int | None:
        """Raw LLDB status, not a claim that the process exited normally."""
        return self._backend_status

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with self._timeout_lock:
            if self._timeout_timer is not None:
                self._timeout_timer.cancel()
            if self._timeout_pidfd is not None:
                os.close(self._timeout_pidfd)
                self._timeout_pidfd = None
        t, self._target = self._target, None
        if t is not None:
            try:
                if not t.is_exited():
                    t.process.Kill()
            finally:
                import lldb
                lldb.SBDebugger.Destroy(t.debugger)
        self._capture_output()
        if self._output_dir is not None:
            self._output_dir.cleanup()

    def __enter__(self) -> "NativeSpecTarget":
        self._check_live()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
