"""Whole-program native execution checked against independent source specifications.

Hardware is only the observation backend. AArch64 transitions come from the
streaming TIR exporter; x86 transitions come from explicitly selected Intel/XED
or Sail source residuals through the shared symbolic predictor/comparator.
RAM evidence is the full private-memory boundary diff, not a passive store trace.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Mapping, Protocol, Sequence
import os
import subprocess
import select

from miasm.expression.expression import ExprId
from ..boundary_oracle import BoundaryPrediction, RegisterPrediction, compare, predict
from ..snapshot import ReadableProgramState
from ..symbolic import SymbolicTransform, UnsupportedInstructionError


class SpecValidationError(RuntimeError):
    pass


class UnsupportedNativeEvent(SpecValidationError):
    pass


@dataclass(frozen=True)
class NativeSnapshot:
    arch: object
    registers: Mapping[str, int]
    memory: Mapping[int, bytes]
    mappings: Sequence[object]
    memory_capability: str
    stdout: bytes = b""
    stderr: bytes = b""


@dataclass(frozen=True)
class NativeTerminal:
    exit_status: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class NativeStep:
    kind: str
    exit_status: int | None = None
    signal: int | None = None


class NativeSpecTarget(Protocol):
    arch: object

    def read_registers(self) -> Mapping[str, int]: ...
    def memory_snapshot(self) -> object: ...
    def mappings(self) -> Sequence[object]: ...
    def step(self) -> object: ...
    def close(self) -> None: ...


Oracle = Callable[[NativeSnapshot], SymbolicTransform | None]
SyscallContract = Callable[[NativeSnapshot, NativeSnapshot | None, NativeStep], None]


def _permission(mapping, address):
    if isinstance(mapping, Mapping):
        start, end, perms = mapping.get("start"), mapping.get("end"), mapping.get("perms")
    else:
        start = getattr(mapping, "start", getattr(mapping, "start_address", None))
        end = getattr(mapping, "end", getattr(mapping, "end_address", None))
        perms = getattr(mapping, "perms", None)
    if not (type(start) is int and type(end) is int and start <= address < end):
        return ""
    if isinstance(perms, str):
        return perms
    if isinstance(perms, int):
        return (
            ("r" if perms & 1 else "-") + ("w" if perms & 2 else "-") + ("x" if perms & 4 else "-")
        )
    return (
        ("r" if getattr(mapping, "read", False) else "-")
        + ("w" if getattr(mapping, "write", False) else "-")
        + ("x" if getattr(mapping, "execute", False) else "-")
    )


def _mapping(maps, address):
    return next((m for m in maps if _permission(m, address)), None)


def _byte(memory, address):
    for base, data in memory.items():
        if base <= address < base + len(data):
            return data[address - base]
    return None


def _diff(before, after):
    # Most instruction boundaries retain identical map/region layout. Compare
    # those regions in C-backed bytes equality first and enumerate only changed
    # regions; this preserves exact byte-diff semantics without expanding every
    # private-RAM address into a Python integer set at every instruction.
    same_layout = before.keys() == after.keys() and all(
        len(data) == len(after[base]) for base, data in before.items()
    )
    if same_layout:
        changed = {}
        for base, data in before.items():
            updated = after[base]
            if data == updated:
                continue
            changed.update(
                (base + offset, new)
                for offset, (old, new) in enumerate(zip(data, updated, strict=True))
                if old != new
            )
        return changed

    # Mapping creation/removal or region splitting uses the reference semantics
    # until an interval-sweep diff can be used without losing missing-byte facts.
    addresses = {
        base + i
        for view in (before, after)
        for base, data in view.items()
        for i in range(len(data))
    }
    return {a: _byte(after, a) for a in addresses if _byte(before, a) != _byte(after, a)}


def _pc_name(registers, arch):
    names = {str(n).upper() for n in registers}
    for name in ("PC", "RIP") if getattr(arch, "archname", "") == "aarch64" else ("RIP", "PC"):
        if name in names:
            return name
    raise SpecValidationError("Native snapshot omitted PC.")


def _reg_value(arch, regs, name):
    canonical = arch.to_regname(name)
    if canonical in regs:
        return regs[canonical]
    accessor = arch.get_reg_accessor(canonical) if canonical else None
    if accessor and accessor.base_reg in regs:
        return (regs[accessor.base_reg] & accessor.mask) >> accessor.start
    raise SpecValidationError(f"Oracle read unobserved register {name}.")


def _validate_memory_coverage(snapshot):
    if snapshot.memory_capability != "full-boundary-memory-diff":
        raise SpecValidationError("Native snapshot lacks the full-boundary-memory-diff capability.")

    def bounds(mapping):
        if isinstance(mapping, Mapping):
            return mapping.get("start"), mapping.get("end")
        return (
            getattr(mapping, "start", getattr(mapping, "start_address", None)),
            getattr(mapping, "end", getattr(mapping, "end_address", None)),
        )

    def private_readable(mapping):
        if isinstance(mapping, Mapping):
            perms = mapping.get("perms", "")
            readable = "r" in perms if isinstance(perms, str) else bool(perms & 1)
            private = (
                mapping.get("private") is True or "p" in perms
                if isinstance(perms, str)
                else mapping.get("private") is True
            )
            name = mapping.get("name", "")
        else:
            readable = bool(getattr(mapping, "read", False))
            private = bool(getattr(mapping, "private", False))
            name = getattr(mapping, "name", "")
        return readable and private and name not in {"[vvar]", "[vvar_vclock]"}

    mappings = []
    for mapping in snapshot.mappings:
        if not private_readable(mapping):
            continue
        start, end = bounds(mapping)
        if type(start) is not int or type(end) is not int or not 0 <= start < end <= 1 << 64:
            raise SpecValidationError("Invalid private readable mapping range.")
        mappings.append((start, end))
    mappings.sort()
    if not mappings:
        raise SpecValidationError("Snapshot has no private readable mapping coverage evidence.")
    for (_, previous_end), (next_start, _) in zip(mappings, mappings[1:]):
        if next_start < previous_end:
            raise SpecValidationError("Private readable mappings overlap.")

    regions = []
    for base, data in snapshot.memory.items():
        if type(base) is not int or not isinstance(data, bytes) or not data:
            raise SpecValidationError("Memory evidence must contain nonempty byte regions.")
        end = base + len(data)
        if base < 0 or end > 1 << 64:
            raise SpecValidationError("Memory evidence region is outside address space.")
        containers = [(lo, hi) for lo, hi in mappings if lo <= base and end <= hi]
        if len(containers) != 1:
            raise SpecValidationError(
                "Memory region is outside or ambiguously covered by mappings."
            )
        regions.append((base, end))
    regions.sort()
    for (_, previous_end), (next_start, _) in zip(regions, regions[1:]):
        if next_start < previous_end:
            raise SpecValidationError("Private memory evidence regions overlap.")

    for start, end in mappings:
        cursor = start
        for lo, hi in regions:
            if hi <= cursor or lo >= end:
                continue
            if lo != cursor:
                raise SpecValidationError(f"Private memory evidence gap at {cursor:#x}.")
            cursor = hi
            if cursor == end:
                break
        if cursor != end:
            raise SpecValidationError(f"Private mapping bytes are incomplete at {cursor:#x}.")


def _capture(target):
    if callable(getattr(target, "snapshot", None)):
        snap = target.snapshot()
        if isinstance(snap, NativeSnapshot):
            _validate_memory_coverage(snap)
            return snap
    registers = dict(target.read_registers())
    captured = target.memory_snapshot()
    regions = getattr(captured, "regions", None)
    if regions is None:
        raise SpecValidationError("Memory snapshot lacks stable private regions.")
    snapshot = NativeSnapshot(
        target.arch,
        registers,
        {m.start: data for m, data in regions},
        tuple(target.mappings()),
        getattr(captured, "capability", None),
        bytes(getattr(target, "stdout", b"")),
        bytes(getattr(target, "stderr", b"")),
    )
    _validate_memory_coverage(snapshot)
    return snapshot


def _step(target, repeat_pc=None):
    if repeat_pc is not None:
        method = getattr(target, "step_complete_instruction", None)
        if not callable(method):
            raise SpecValidationError("Native target lacks REP-completion API.")
        result = method(repeat_pc=repeat_pc)
    else:
        method = getattr(target, "step_one_hardware_instruction", None) or getattr(
            target, "step", None
        )
        if not callable(method):
            raise SpecValidationError("Native target lacks one-instruction step API.")
        result = method()
    if isinstance(result, NativeStep):
        return result
    state = getattr(getattr(result, "state", None), "value", getattr(result, "state", None))
    if state == "exited":
        return NativeStep("exit", getattr(result, "exit_status", None))
    if state == "stopped":
        sig = getattr(result, "stop_signal", None)
        return NativeStep("signal", signal=sig) if sig is not None else NativeStep("instruction")
    if state in {"signal", "signaled"}:
        return NativeStep("signal", signal=getattr(result, "termination_signal", None))
    raise SpecValidationError(f"Unexpected native execution result {result!r}.")


def _snapshot_state(pre):
    """Read-only, permission-checked inputs frozen before native execution."""
    class State(ReadableProgramState):
        def __init__(self):
            super().__init__(pre.arch)

        def read_register(self, name):
            return _reg_value(self.arch, pre.registers, name)

        def read_memory(self, address, size):
            out = bytearray()
            for a in range(address, address + size):
                m = _mapping(pre.mappings, a)
                val = _byte(pre.memory, a)
                if val is None or m is None or "r" not in _permission(m, a):
                    raise SpecValidationError(f"Oracle read denied at {a:#x}.")
                out.append(val)
            return bytes(out)

    return State()


def _predict_transition(transform, pre, knownness=None):
    pc = _pc_name(pre.registers, pre.arch)
    if transform.range[0] != pre.registers[pc] or transform.arch != pre.arch:
        raise SpecValidationError("Oracle transition PC/architecture mismatch.")
    state = _snapshot_state(pre)
    if pre.arch.archname == "x86_64" and not transform.source_owned:
        raise SpecValidationError("Intel transitions must be imported source residuals.")
    if transform.source_owned:
        if pre.arch.archname == "x86_64":
            from ..intel_symbolic import REQUIRED_OUTPUTS, knownness_inputs_for_observation

            register_names = REQUIRED_OUTPUTS
            if knownness is None:
                knownness = knownness_inputs_for_observation(
                    {str(k).upper(): v for k, v in pre.registers.items()}
                )
        else:
            register_names = []
            observed_masks = {}
            for name in pre.registers:
                accessor = pre.arch.get_reg_accessor(name)
                if accessor is not None and accessor.base_reg == name:
                    register_names.append(name)
                    observed_masks[name] = (1 << accessor.num_bits) - 1
            if knownness is None:
                knownness = observed_masks
        # Source-owned ARM regions must retain guards and masks too; rebuilding
        # them as a legacy projection would silently discard those obligations.
        prediction = predict(
            transform, state, knownness_inputs=knownness, register_names=register_names
        )
    else:
        canonical = transform.canonical_register_outputs()
        projected = SymbolicTransform(
            transform.tid,
            {ExprId(n, e.size): e for n, e in canonical.items()},
            transform.instructions,
            transform.arch,
            transform.range[0],
            transform.range[1],
        )
        projected.memory_writes = list(transform.memory_writes)
        prediction = predict(projected, state)
    for address, data in prediction.memory.items():
        for a in range(address, address + len(data)):
            m = _mapping(pre.mappings, a)
            if m is None or "w" not in _permission(m, a):
                raise SpecValidationError(f"Predicted store lacks pre-write permission at {a:#x}.")
            if "x" in _permission(m, a):
                raise UnsupportedNativeEvent(f"Source store targets executable memory at {a:#x}.")
    return prediction


def _validate_transition(transform, pre, post, prediction=None):
    from .spec_syscalls import _validate_mapping_changes

    prediction = _predict_transition(transform, pre) if prediction is None else prediction
    # An instruction/atomic region is not an OS-service boundary. Hidden
    # changes to mapping permissions or captured output are not authorized.
    _validate_mapping_changes(pre, post, ())
    if post.stdout != pre.stdout or post.stderr != pre.stderr:
        raise SpecValidationError("Unexpected output outside an OS-service boundary.")
    regs = dict(prediction.registers)
    cpsr = regs.get("CPSR") if pre.arch.archname == "aarch64" else None
    if pre.arch.archname == "aarch64":
        cpsr = cpsr or RegisterPrediction(pre.registers["CPSR"], 0xF0000000, 32)
        # Compare declared NZCV only; LLDB also exposes debugger/PSTATE bits that
        # are outside the TIR architectural flag view.
        regs["CPSR"] = RegisterPrediction(cpsr.value, 0xF0000000, 32)
        names = {str(n).upper() for n in (*pre.registers.keys(), *post.registers.keys())}
        for name in names:
            acc = pre.arch.get_reg_accessor(name)
            if acc and acc.base_reg == "CPSR" and name != "CPSR":
                mask = (1 << acc.num_bits) - 1
                regs[name] = RegisterPrediction(
                    (cpsr.value >> acc.start) & mask,
                    (0xF0000000 >> acc.start) & mask,
                    acc.num_bits,
                )
    for raw, value in pre.registers.items():
        name = str(raw).upper()
        if name == "CPSR" and pre.arch.archname == "aarch64":
            continue
        acc = pre.arch.get_reg_accessor(name)
        canonical = acc.base_reg if acc else name
        if canonical != name or canonical in regs:
            continue
        width = acc.num_bits if acc else {"FPCR": 32, "FPSR": 32}.get(canonical)
        if width is None:
            raise SpecValidationError(f"No width contract for observed register {canonical}.")
        regs[canonical] = RegisterPrediction(value, (1 << width) - 1, width)
    full = BoundaryPrediction(regs, prediction.ordered_writes, prediction.memory)
    actual = {}
    for addr, data in prediction.memory.items():
        values = [_byte(post.memory, addr + i) for i in range(len(data))]
        if any(v is None for v in values):
            raise SpecValidationError(f"Post-store bytes unavailable at {addr:#x}.")
        actual[addr] = bytes(values)
    result = compare(full, {str(k).upper(): v for k, v in post.registers.items()}, actual)
    if not result.ok:
        raise SpecValidationError(
            f"Boundary mismatch at {_pc_name(pre.registers, pre.arch)}={pre.registers[_pc_name(pre.registers, pre.arch)]:#x} instruction={transform.instructions[0] if transform.instructions else None}: {result.diagnostics!r}"
        )
    changed = _diff(pre.memory, post.memory)
    expected = {a + i: b for a, data in prediction.memory.items() for i, b in enumerate(data)}
    unexpected = {a: v for a, v in changed.items() if expected.get(a) != v}
    if unexpected:
        raise SpecValidationError(f"Unexpected private-RAM diff: {unexpected!r}")
    for a, v in expected.items():
        if _byte(post.memory, a) != v:
            raise SpecValidationError(f"Predicted memory byte missing at {a:#x}.")
    for a in changed:
        m0, m1 = _mapping(pre.mappings, a), _mapping(post.mappings, a)
        if m0 is None or m1 is None or "x" in _permission(m0, a) or "x" in _permission(m1, a):
            raise SpecValidationError(f"Mapping/self-modifying change at {a:#x}.")


class NativeSpecValidator:
    def __init__(self, target, oracle, *, syscall_policy=None, max_steps=10_000_000):
        if type(max_steps) is not int or max_steps <= 0:
            raise ValueError("max_steps must be positive")
        self.target, self.oracle, self.syscall_policy, self.max_steps = (
            target,
            oracle,
            syscall_policy,
            max_steps,
        )
        self.knownness_inputs = None
        self.validated_instruction_boundaries = 0
        self.validated_syscalls = {}
        self.entry_pc = None
        self.current_pc = None
        self.validated_exclusive_regions = 0
        self.validated_vdso_services = 0
        self.vdso_observer = None

    def _exclusive_region(self, pre):
        if pre.arch.archname != "aarch64" or not callable(getattr(self.oracle, "region_candidates", None)):
            return False
        from .exclusive_target import is_exclusive_entry, plan_region, execute_region
        from .region_validate import prepare_candidates, snapshot_from_evidence, compare_candidates

        code = self.target.read_memory(self.current_pc, 4)
        if not is_exclusive_entry(code):
            return False
        import os

        profile = getattr(self.target, "hardware_profile", None)
        if profile is not None and os.sched_getaffinity(self.target.pid) != {profile["cpu"]}:
            raise SpecValidationError("Native hardware-profile CPU affinity changed.")
        region = plan_region(self.target, self.current_pc)
        prepared = prepare_candidates(pre, self.oracle.region_candidates(region, pre.arch))
        _, evidence = execute_region(self.target, region)
        observed_pre = snapshot_from_evidence(pre.arch, evidence["pre"])
        if observed_pre != pre:
            raise SpecValidationError("Exclusive prestate changed after source prediction.")
        post = snapshot_from_evidence(pre.arch, evidence["post"])
        compare_candidates(pre, post, prepared)
        self.validated_exclusive_regions += 1
        return True

    def run(self):
        for index in range(self.max_steps):
            pre = _capture(self.target)
            self.current_pc = pre.registers[_pc_name(pre.registers, pre.arch)]
            if self.entry_pc is None:
                self.entry_pc = pre.registers[_pc_name(pre.registers, pre.arch)]
            if self.knownness_inputs is not None and callable(
                getattr(self.oracle, "set_knownness_inputs", None)
            ):
                self.oracle.set_knownness_inputs(self.knownness_inputs)
            if self._exclusive_region(pre):
                continue
            if self.vdso_observer is not None:
                identity = self.vdso_observer.identity
                if self.current_pc == identity.start + identity.symbol.offset:
                    token = self.vdso_observer.preflight(pre)
                    self.vdso_observer.execute(token)
                    self.validated_vdso_services += 1
                    continue
                if identity.start <= self.current_pc < identity.end:
                    raise UnsupportedNativeEvent("vDSO entry outside the recognized service boundary")
            transform = self.oracle(pre)
            if self.knownness_inputs is None and hasattr(self.oracle, "knownness_inputs"):
                self.knownness_inputs = self.oracle.knownness_inputs
            syscall_token = None
            syscall = None
            if transform is None:
                if self.syscall_policy is None:
                    raise UnsupportedNativeEvent(
                        "Syscall instruction rejected before execution: no stateful Linux policy configured."
                    )
                syscall_token = self.syscall_policy.preflight(pre)
                syscall = syscall_token.op
            if syscall is not None and callable(
                getattr(self.oracle, "validate_syscall_prestate", None)
            ):
                self.oracle.validate_syscall_prestate(pre)
            if (
                transform is not None
                and pre.arch.archname == "x86_64"
                and self.knownness_inputs is None
            ):
                from ..intel_symbolic import knownness_inputs_for_observation

                self.knownness_inputs = knownness_inputs_for_observation(
                    {str(k).upper(): v for k, v in pre.registers.items()}
                )
            prediction = (
                _predict_transition(transform, pre, self.knownness_inputs)
                if transform is not None
                else None
            )
            repeat_pc = getattr(self.oracle, "last_repeat_pc", None)
            event = _step(self.target, repeat_pc)
            if event.kind == "signal":
                raise UnsupportedNativeEvent(f"Unexpected signal {event.signal} at step {index}")
            if event.kind == "exit":
                if transform is not None or syscall_token is None or syscall != "exit":
                    raise SpecValidationError("Exit without pre-recognized exit syscall")
                self.syscall_policy.validate(pre, None, event, syscall_token)
                self.validated_instruction_boundaries += 1
                self.validated_syscalls[syscall] = self.validated_syscalls.get(syscall, 0) + 1
                if event.exit_status != 0:
                    raise SpecValidationError(f"nonzero/ambiguous exit status {event.exit_status}")
                return NativeTerminal(
                    event.exit_status,
                    bytes(getattr(self.target, "stdout", b"")),
                    bytes(getattr(self.target, "stderr", b"")),
                )
            if transform is None:
                if syscall_token is None or syscall == "exit":
                    raise SpecValidationError("Missing or unexpectedly returning syscall token")
                refresh_output = getattr(self.target, "refresh_output", None)
                if not callable(refresh_output):
                    raise SpecValidationError(
                        "Native target cannot refresh syscall-boundary output evidence"
                    )
                refresh_output()
            else:
                refresh_output = getattr(self.target, "refresh_output", None)
                if callable(refresh_output):
                    refresh_output()
            post = _capture(self.target)
            if transform is None:
                self.syscall_policy.validate(pre, post, event, syscall_token)
                if callable(getattr(self.oracle, "validate_syscall_successor", None)):
                    self.oracle.validate_syscall_successor(post)
                self.validated_instruction_boundaries += 1
                self.validated_syscalls[syscall] = self.validated_syscalls.get(syscall, 0) + 1
            else:
                _validate_transition(transform, pre, post, prediction)
                self.validated_instruction_boundaries += 1
                if self.knownness_inputs is not None:
                    for name, item in prediction.registers.items():
                        self.knownness_inputs[
                            f"ZMM{name[3:]}" if name.startswith("XMM") else name
                        ] = item.mask
        raise SpecValidationError(f"Step budget exceeded ({self.max_steps})")


def validate_native_program(target, oracle, **kwargs):
    try:
        return NativeSpecValidator(target, oracle, **kwargs).run()
    finally:
        try:
            oracle.close()
        finally:
            target.close()


def _decode_tir_response(line, pc, code, native_config):
    from ..tir_backend import decode_response

    try:
        return decode_response(line, pc, code, expected_native_config=native_config)
    except UnsupportedInstructionError as error:
        raise UnsupportedNativeEvent(
            f"TIR does not support instruction at PC {pc:#x}, bytes={code.hex()}: {error}"
        ) from error
    except Exception as error:
        raise SpecValidationError(
            f"TIR response invalid at PC {pc:#x}, bytes={code.hex()}: {error}"
        ) from error


class NativeTIROracle:
    """Persistent TIR batch exporter; AArch64 decoding is fixed-width, not Miasm."""

    def __init__(self, executable, timeout=120.0, hardware_profile=None):
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("TIR_", "TIRAMISU_", "FOCACCIA_TIR_MODULE"))
        }
        self.timeout = timeout
        self.executable = executable
        self.hardware_profile = hardware_profile
        self.native_config = None
        if hardware_profile is not None:
            if (
                hardware_profile.get("architecture") != "aarch64"
                or type(hardware_profile.get("dczid_el0")) is not int
                or not 0 <= hardware_profile["dczid_el0"] <= 31
                or (hardware_profile["dczid_el0"] & 0xF) > 9
            ):
                raise SpecValidationError("Invalid independent native ARM profile.")
            # Preserve BS/DZP. The configured source profile derives only
            # user DC ZVA permission from DZP under EL0/no-EL2, not SCTLR input.
            self.native_config = {"dczid_el0": hardware_profile["dczid_el0"]}
        command = [executable, "--export-transitions"]
        if self.native_config is not None:
            command.extend(["--dczid-el0", str(self.native_config["dczid_el0"])])
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            bufsize=1,
            env=env,
        )
        self.cache = {}
        self.tir_revision = None

    def region_candidates(self, region, arch):
        from ..tir_backend import TirBackend
        from .region_validate import request_for_region

        return TirBackend(self.executable, timeout=self.timeout).export_region_transforms(
            request_for_region(region), arch=arch, expected_native_config=self.native_config,
        )

    def __call__(self, snap):
        if snap.arch.archname != "aarch64" or snap.arch.endianness != "little":
            raise SpecValidationError("TIR requires little-endian AArch64")
        pc = snap.registers[_pc_name(snap.registers, snap.arch)]
        if pc % 4:
            raise SpecValidationError(f"unaligned ARM PC {pc:#x}")
        code = bytearray()
        for a in range(pc, pc + 4):
            m = _mapping(snap.mappings, a)
            byte = _byte(snap.memory, a)
            if m is None or "x" not in _permission(m, a) or byte is None:
                raise SpecValidationError(f"instruction fetch denied at {a:#x}")
            code.append(byte)
        code = bytes(code)
        word = int.from_bytes(code, "little")
        if word & 0xFFE0001F == 0xD4000001:
            return None
        key = (pc, code)
        if key not in self.cache:
            if self.process.poll() is not None:
                raise SpecValidationError("TIR oracle process exited")
            self.process.stdin.write(f"{pc} {code.hex()}\n")
            self.process.stdin.flush()
            ready, _, _ = select.select([self.process.stdout], [], [], self.timeout)
            if not ready:
                raise SpecValidationError(f"TIR timeout at {pc:#x}")
            line = self.process.stdout.readline().rstrip("\n")
            if not line:
                raise SpecValidationError(f"TIR stream ended at {pc:#x}")
            try:
                import json

                response = json.loads(line)
                revision = response.get("tir_revision") if isinstance(response, dict) else None
                if self.tir_revision is None:
                    self.tir_revision = revision
                elif revision != self.tir_revision:
                    raise SpecValidationError("TIR revision changed during native execution.")
                _, self.cache[key] = _decode_tir_response(line, pc, code, self.native_config)
            except (UnsupportedNativeEvent, SpecValidationError):
                raise
            except Exception as error:
                raise SpecValidationError(
                    f"TIR response invalid at PC {pc:#x}, bytes={code.hex()}: {error}"
                ) from error
        return SymbolicTransform(1, self.cache[key], [], snap.arch, pc, pc + 4)

    def close(self):
        if self.process.stdin is not None:
            try:
                self.process.stdin.close()
            except OSError:
                pass
        if self.process.poll() is None:
            try:
                self.process.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait()
        if self.process.stdout is not None:
            self.process.stdout.close()
        if self.process.stderr is not None:
            self.process.stderr.close()


def _write_report(report, output_path=None):
    import json

    rendered = json.dumps(report, sort_keys=True)
    if output_path:
        from pathlib import Path

        Path(output_path).write_text(rendered + "\n")
    print(rendered)


def _failure_context(args, target, validator, oracle_profile, hardware_profile):
    import hashlib
    from pathlib import Path

    details = {}
    binary = getattr(args, "binary", None)
    if binary and Path(binary).is_file():
        details["binary_sha256"] = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
    if oracle_profile is not None:
        details["oracle_profile"] = oracle_profile
    if hardware_profile:
        configuration = dict(hardware_profile)
        configuration["dczva_el0_permitted"] = not bool(hardware_profile["dczid_el0"] & 0x10)
        configuration["dczva_permission_basis"] = (
            "DCZID_EL0.DZP under fixed EL0/no-EL2 source profile; SCTLR_EL1 not read"
        )
        details["oracle_configuration"] = configuration
    if validator is not None:
        details.update(
            {
                "entry_pc": validator.entry_pc,
                "failed_boundary_pc": validator.current_pc,
                "failed_boundary_pc_hex": (
                    f"{validator.current_pc:#x}" if validator.current_pc is not None else None
                ),
                "validated_instruction_boundaries": validator.validated_instruction_boundaries,
                "validated_exclusive_regions": validator.validated_exclusive_regions,
                "validated_vdso_services": validator.validated_vdso_services,
                "validated_syscall_counts": dict(validator.validated_syscalls),
            }
        )
    return details


def _validate_source_selection(args, architecture):
    if architecture != "x86_64" and (
        args.x86_spec == "sail" or args.sail_oracle or args.sail_model
    ):
        raise UnsupportedNativeEvent("Explicit Sail x86 selection/assets require an x86-64 target")


def main(argv=None):
    import argparse, hashlib, shutil
    from pathlib import Path
    from .spec_target import NativeSpecTarget

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", required=True)
    p.add_argument("--arm-oracle", default="focaccia-tir-oracle")
    p.add_argument(
        "--hardware-profile-helper", help="independent native ARM system-register profile helper"
    )
    p.add_argument("--intel-oracle")
    p.add_argument("--intel-model")
    p.add_argument("--intel-xed")
    p.add_argument("--x86-spec", choices=("intel", "sail"), default="intel")
    p.add_argument("--sail-oracle")
    p.add_argument("--sail-model")
    p.add_argument("--timeout", type=float, default=120.0)
    p.add_argument("--max-steps", type=int, default=10_000_000)
    p.add_argument("--stdin-file", help="bytes supplied to policy-controlled stdin reads")
    p.add_argument(
        "--allow-read-path",
        action="append",
        default=[],
        help="explicit path permitted for readonly open/stat syscalls; repeatable",
    )
    p.add_argument("--expected-stdout")
    p.add_argument("--expected-stdout-file")
    p.add_argument("--expected-exit-status", type=int, default=0)
    p.add_argument("--output", help="also write the final JSON report to this path")
    p.add_argument("program_args", nargs=argparse.REMAINDER)
    args = p.parse_args(argv)
    program_args = args.program_args[1:] if args.program_args[:1] == ["--"] else args.program_args
    target = oracle = validator = None
    hardware_profile = None
    spec = None
    oracle_profile = None
    expected = None
    launch_uid, launch_gid = os.getuid(), os.getgid()
    stdin_bytes = Path(args.stdin_file).read_bytes() if args.stdin_file else b""
    try:
        target = NativeSpecTarget(args.binary, program_args)
        _validate_source_selection(args, target.arch.archname)
        if callable(getattr(target, "set_timeout", None)):
            target.set_timeout(args.timeout)
        if target.arch.archname == "aarch64":
            if not args.hardware_profile_helper:
                raise UnsupportedNativeEvent(
                    "ARM requires an independent hardware-profile helper before stepping."
                )
            hardware_profile = target.configure_arm_profile(args.hardware_profile_helper)
            oracle = NativeTIROracle(args.arm_oracle, args.timeout, hardware_profile)
            spec = "streaming TIR ARM fullspec EL0"
            oracle_profile = "aarch64-native-dczid-el0"
        elif target.arch.archname == "x86_64" and args.x86_spec == "sail":
            if not (args.sail_oracle and args.sail_model):
                raise UnsupportedNativeEvent("Sail requires --sail-oracle and --sail-model")
            if args.intel_oracle or args.intel_model or args.intel_xed:
                raise UnsupportedNativeEvent("Sail selection cannot silently mix Intel source assets")
            from .sail_spec import SailNativeOracle
            from ..sail_symbolic import PROFILE as sail_profile

            oracle = SailNativeOracle(args.sail_model, args.sail_oracle, timeout=args.timeout)
            spec = "Sail x86 source residuals (TIR specialization)"
            oracle_profile = sail_profile
        elif target.arch.archname == "x86_64":
            if args.sail_oracle or args.sail_model:
                raise UnsupportedNativeEvent("Sail assets require explicit --x86-spec=sail")
            if not (args.intel_oracle and args.intel_model):
                _write_report(
                    {
                        "status": "hardware-pending",
                        "architecture": "x86_64",
                        "execution_backend": "native",
                        "implementation": "Intel source oracle/model configuration required",
                    },
                    args.output,
                )
                return 2
            from .intel_spec import IntelNativeOracle
            from ..intel_symbolic import PROFILE as intel_profile

            xed = args.intel_xed or shutil.which("intel-xed-decode")
            if not xed:
                _write_report(
                    {
                        "status": "hardware-pending",
                        "architecture": "x86_64",
                        "execution_backend": "native",
                        "implementation": "Intel exact-XED decoder not configured or available on PATH",
                    },
                    args.output,
                )
                return 2
            oracle = IntelNativeOracle(
                args.intel_model,
                args.intel_oracle,
                xed,
                timeout=args.timeout,
            )
            spec = "Intel source residuals (XED + imported model)"
            oracle_profile = intel_profile
        else:
            raise SpecValidationError(f"Unsupported ISA {target.arch.archname}")
        if args.expected_stdout is not None and args.expected_stdout_file is not None:
            p.error("choose one stdout expectation")
        expected = (
            args.expected_stdout.encode()
            if args.expected_stdout is not None
            else Path(args.expected_stdout_file).read_bytes()
            if args.expected_stdout_file
            else None
        )
        from .spec_syscalls import NativeLinuxPolicy

        syscall_policy = NativeLinuxPolicy(
            stdin=stdin_bytes,
            allowed_read_paths=args.allow_read_path,
            uid=launch_uid,
            gid=launch_gid,
            page_size=os.sysconf("SC_PAGE_SIZE"),
        )
        validator = NativeSpecValidator(
            target, oracle, syscall_policy=syscall_policy, max_steps=args.max_steps
        )
        if target.arch.archname == "aarch64":
            from .vdso import NativeVDSOClockGettime

            validator.vdso_observer = NativeVDSOClockGettime(target, syscall_policy=syscall_policy)
        final = validator.run()
        if target.exit_status != args.expected_exit_status:
            raise SpecValidationError(
                f"expected exit {args.expected_exit_status}, observed {target.exit_status}"
            )
        if expected is None:
            raise UnsupportedNativeEvent(
                "Expected stdout must be provided for whole-program acceptance"
            )
        if final.stdout != expected:
            raise SpecValidationError(
                f"stdout mismatch expected {expected!r}, observed {final.stdout!r}"
            )
        binary_hash = hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()
        oracle_configuration = (
            dict(hardware_profile)
            if hardware_profile
            else {"model_sha256": getattr(oracle, "model_hash", None)}
        )
        if hardware_profile:
            oracle_configuration["dczva_el0_permitted"] = not bool(
                hardware_profile["dczid_el0"] & 0x10
            )
            oracle_configuration["dczva_permission_basis"] = (
                "DCZID_EL0.DZP under fixed EL0/no-EL2 source profile; SCTLR_EL1 not read"
            )
        report = {
            "status": "accepted",
            "architecture": target.arch.archname,
            "binary_sha256": binary_hash,
            "execution_backend": "native",
            "specification_backend": spec,
            "oracle_profile": oracle_profile,
            "oracle_revision": getattr(oracle, "tir_revision", None),
            "source_provenance": getattr(oracle, "source_provenance", None),
            "oracle_configuration": oracle_configuration,
            "entry_pc": validator.entry_pc,
            "validated_instruction_boundaries": validator.validated_instruction_boundaries,
            "validated_exclusive_regions": validator.validated_exclusive_regions,
            "validated_vdso_services": validator.validated_vdso_services,
            "vdso_internals_instruction_spec_checked": False,
            "exclusive_internal_pc_trace_available": False,
            "validated_syscall_counts": dict(validator.validated_syscalls),
            "arm_status_register_view": "NZCV-only" if target.arch.archname == "aarch64" else None,
            "non_nzcv_cpsr_bits_compared": False if target.arch.archname == "aarch64" else None,
            "terminal_status": target.exit_status,
            "expected_exit_status": args.expected_exit_status,
            "expected_exit_status_match": True,
            "expected_stdout_match": True,
            "syscall_policy": {
                "uid": launch_uid,
                "gid": launch_gid,
                "page_size": os.sysconf("SC_PAGE_SIZE"),
                "allowed_read_paths": list(args.allow_read_path),
                "stdin_sha256": hashlib.sha256(stdin_bytes).hexdigest(),
            },
            "stdout_hex": final.stdout.hex(),
            "stderr_hex": final.stderr.hex(),
            "memory_evidence_capability": "full-private-memory-boundary-diff",
            "memory_evidence_scope": "complete stable private-readable mappings; volatile kernel mappings excluded",
            "actual_store_trace_available": False,
            "same_value_store_observable": False,
            "wall_timeout_seconds": args.timeout,
            "timeout_scope": "owned-tracee wall-clock watchdog and per-oracle request; use external timeout to bound validator startup and cleanup too",
        }
        _write_report(report, args.output)
        return 0
    except UnsupportedNativeEvent as e:
        details = _failure_context(args, target, validator, oracle_profile, hardware_profile)
        _write_report(
            {
                "status": "unsupported",
                "oracle_revision": getattr(oracle, "tir_revision", None),
                "source_provenance": getattr(oracle, "source_provenance", None),
                "architecture": getattr(getattr(target, "arch", None), "archname", None),
                "execution_backend": "native" if target is not None else None,
                **details,
                "error": str(e),
            },
            args.output,
        )
        return 2
    except Exception as e:
        details = _failure_context(args, target, validator, oracle_profile, hardware_profile)
        _write_report(
            {
                "status": "mismatch",
                "oracle_revision": getattr(oracle, "tir_revision", None),
                "source_provenance": getattr(oracle, "source_provenance", None),
                "architecture": getattr(getattr(target, "arch", None), "archname", None),
                "execution_backend": "native" if target is not None else None,
                **details,
                "error": f"{type(e).__name__}: {e}",
            },
            args.output,
        )
        return 1
    finally:
        if oracle is not None:
            try:
                oracle.close()
            except Exception:
                pass
        if target is not None:
            target.close()


if __name__ == "__main__":
    # Keep `python -m ...` on the same logical module identity as entry-point
    # imports used by syscall/Intel adapters. The duplicate __main__ definitions
    # are never used for execution or exception matching.
    from focaccia.native.spec_validate import main as _canonical_main

    raise SystemExit(_canonical_main())
