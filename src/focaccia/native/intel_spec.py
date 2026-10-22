"""Native x86-64 source-specification adapter (exact XED + Intel source model).

The native target supplies observations only. Instruction bytes are decoded by
Intel XED and semantics are imported from the checked Intel/TIR model; there is
intentionally no concrete opcode or Miasm fallback.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import shutil
from types import SimpleNamespace
from typing import Mapping

from ..arch.x86 import ArchX86
from ..intel_client import IntelOracle
from ..intel_symbolic import (
    IntelSymbolicBackend, SymbolicIntelLiveModel, _rep_control_output_names,
    _rep_control_scratch, _rep_prefix_projection, _rep_control_transform,
    _evaluate_composed_register, predict_residual_control,
    knownness_inputs_for_observation, predict_syscall_prestate,
)
from ..symbolic import SymbolicTransform, SymbolicTransformComposer
from .spec_validate import NativeSnapshot, SpecValidationError


class XEDDecoder:
    """Strict one-instruction decoder using the pinned intel-xed-decode tool."""

    def __init__(self, executable: str, *, timeout: float = 5.0):
        self.executable, self.timeout = str(executable), timeout

    def decode(self, pc: int, code: bytes):
        if not isinstance(code, bytes) or not code or len(code) > 15:
            raise SpecValidationError("XED requires 1..15 exact instruction bytes.")
        try:
            result = subprocess.run([self.executable], input=code.hex().encode() + b"\n",
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=self.timeout, check=False)
            if result.returncode:
                raise ValueError("XED decoder failed")
            rows = result.stdout.splitlines()
            if len(rows) != 1:
                raise ValueError("XED returned a non-singleton response")
            value = json.loads(rows[0])
            expected = {"status", "iform", "iclass", "length", "operand_size",
                        "address_size", "fields"}
            if not isinstance(value, dict) or set(value) != expected or value["status"] != "decoded":
                raise ValueError("malformed XED response")
            length = value["length"]
            if type(length) is not int or not 1 <= length <= min(15, len(code)):
                raise ValueError("XED length differs from supplied pre-state bytes")
            return SimpleNamespace(pc=pc, code=code[:length], iform=value["iform"],
                                   operand_size=value["operand_size"],
                                   address_size=value["address_size"], fields=value["fields"])
        except (OSError, subprocess.TimeoutExpired, ValueError, TypeError, json.JSONDecodeError) as e:
            raise SpecValidationError(f"Exact Intel XED decode failed: {e}") from e


class _SnapshotTransport:
    """Permission-checked view of one immutable NativeSnapshot."""
    def __init__(self, snapshot: NativeSnapshot):
        self.snapshot = snapshot

    def memory_permissions(self, address: int, size: int) -> int:
        flags = 15
        for a in range(address, address + size):
            mapping = next((m for m in self.snapshot.mappings
                            if _mapping_bounds(m)[0] <= a < _mapping_bounds(m)[1]), None)
            if mapping is None:
                return 0
            flags &= _mapping_perms(mapping)
        return flags

    def read_memory(self, address: int, size: int) -> bytes:
        result = bytearray()
        for a in range(address, address + size):
            mapping = next((m for m in self.snapshot.mappings
                            if _mapping_bounds(m)[0] <= a < _mapping_bounds(m)[1]), None)
            p = _mapping_perms(mapping) if mapping is not None else 0
            if not p & 1:
                raise SpecValidationError(f"Intel pre-state read denied at {a:#x}.")
            value = next((data[a-base] for base, data in self.snapshot.memory.items()
                          if base <= a < base + len(data)), None)
            if value is None:
                raise SpecValidationError(f"Intel pre-state bytes unavailable at {a:#x}.")
            result.append(value)
        return bytes(result)


def _mapping_bounds(mapping):
    if isinstance(mapping, Mapping):
        return mapping.get("start", -1), mapping.get("end", -1)
    return getattr(mapping, "start", getattr(mapping, "start_address", -1)), getattr(mapping, "end", getattr(mapping, "end_address", -1))


def _mapping_perms(mapping):
    if mapping is None:
        return 0
    if isinstance(mapping, Mapping):
        perms = mapping.get("perms", "")
        if isinstance(perms, int):
            return (1 if perms & 1 else 0) | (2 if perms & 2 else 0) | (4 if perms & 4 else 0) | 8
        return (1 if "r" in perms else 0) | (2 if "w" in perms else 0) | (4 if "x" in perms else 0) | 8
    return (1 if getattr(mapping, "read", False) else 0) | (2 if getattr(mapping, "write", False) else 0) | (4 if getattr(mapping, "execute", False) else 0) | 8


class IntelNativeOracle:
    """Callable NativeSnapshot oracle consumed by ``NativeSpecValidator``.

    ``model`` is the immutable typed source model; ``oracle`` is the source
    evaluator executable (intel-eval --json-lines protocol); ``xed`` is the
    exact XED JSON-lines decoder. Source knownness is retained across native
    boundaries by the validator; concrete observation alone never redefines
    undefined source bits.
    """
    def __init__(self, model: str | Path, oracle: str, xed: str | None = None, *, timeout: float = 60,
                 max_steps: int = 100000):
        self.model_path = Path(model)
        self.model_hash = hashlib.sha256(self.model_path.read_bytes()).hexdigest()
        self.oracle = IntelOracle(str(oracle), self.model_path, timeout=timeout)
        self.backend = IntelSymbolicBackend(self.oracle, self.model_hash)
        selected_xed = xed or shutil.which("intel-xed-decode")
        if not selected_xed:
            raise ValueError("Provide --intel-xed or put intel-xed-decode on PATH.")
        self.decoder = XEDDecoder(selected_xed)
        self.max_steps = max_steps
        self.instructions = 0
        self.knownness_inputs = None
        self.pending_syscall_prestate = None
        self.pending_syscall_next_ip = None
        self.instruction_hint = None
        self.last_repeat_pc = None

    def __call__(self, snapshot: NativeSnapshot):
        if getattr(snapshot.arch, "archname", None) != "x86_64":
            raise SpecValidationError("Intel source oracle received a non-Intel snapshot.")
        regs = {str(k).upper(): int(v) for k, v in snapshot.registers.items()}
        pc = regs.get("RIP", regs.get("PC"))
        if pc is None:
            raise SpecValidationError("Intel pre-state omitted RIP.")
        transport = _SnapshotTransport(snapshot)
        # Fetch only mapped pre-state bytes, stopping at an unreadable boundary;
        # XED will reject a truncated encoding rather than guessing.
        code = bytearray()
        for offset in range(15):
            try:
                code.extend(transport.read_memory(pc + offset, 1))
            except SpecValidationError:
                if not code:
                    raise
                break
        instruction = self.decoder.decode(pc, bytes(code))
        self.instruction_hint = {"pc": pc, "iform": instruction.iform}
        self.last_repeat_pc = pc if instruction.iform.startswith("REP") else None
        if transport.memory_permissions(pc, len(instruction.code)) & 12 != 12:
            raise SpecValidationError("Intel instruction lacks pre-state mapped execute permission.")
        event = SimpleNamespace(size=1, pc=pc, address=pc)
        live = SymbolicIntelLiveModel(self.backend, self.decoder, transport, 1,
                                       step_limit=self.max_steps)
        live.boundary(regs)
        # The validator owns source knownness across native boundaries. Callers
        # can bind its map; only the first standalone invocation infers the
        # observable input contract.
        if self.knownness_inputs is None:
            self.knownness_inputs = knownness_inputs_for_observation(regs)
        live.knownness_inputs = dict(self.knownness_inputs)
        residual = self.backend.specialize(instruction)
        if instruction.iform == "SYSCALL":
            live.predict(event)  # validate guards, source cutpoint and read/write obligations
            self.pending_syscall_prestate = predict_syscall_prestate(
                residual, live.state, live.knownness_inputs, 1,
            )
            repeat = predict_residual_control(
                residual, "repeat", live.state, live.knownness_inputs, 1,
            )
            cutpoint = predict_residual_control(
                residual, "environment_cutpoint", live.state, live.knownness_inputs, 1,
            )
            if repeat != 0 or cutpoint != 1:
                raise SpecValidationError("SYSCALL source controls must be repeat=0 and cutpoint=1.")
            self.pending_syscall_next_ip = predict_residual_control(
                residual, "next_ip", live.state, live.knownness_inputs, 1,
            )
            self._require_known_syscall_inputs(regs, live.knownness_inputs)
            return None
        if not instruction.iform.startswith("REP"):
            live.predict(event)  # source guards and lazy input checks
            self.instructions += live.instructions
            return residual.to_transform(1)
        live.predict(event)  # shared engine also validates read obligations and effects
        transform = self._predict_full_rep(residual, live)
        self.instructions += live.instructions
        return transform

    def _predict_full_rep(self, residual, live):
        """Compose the full source-predicted REP to completion, before stepping."""
        arch = ArchX86()
        pc = residual.pc
        seed = SymbolicTransform(1, {}, [], arch, pc, pc, defined_masks={}, source_owned=True)
        block = SymbolicTransformComposer(seed)
        controls = _rep_control_output_names(residual)
        scratch = _rep_control_scratch(residual)
        prefix = _rep_prefix_projection(block.finish(), controls, 1)
        state = SymbolicTransformComposer(prefix)
        steps = []
        virtual_pc = pc
        for _ in range(self.max_steps):
            step = residual.to_transform(1)
            step.range = (virtual_pc, virtual_pc + residual.length)
            step.addr = virtual_pc
            control_step = _rep_control_transform(residual, 1, scratch, virtual_pc, controls)
            projected = state.fork()
            projected.append(control_step)
            repeat = _evaluate_composed_register(
                projected.finish(), scratch, live.state, live.knownness_inputs,
            )
            if repeat not in (0, 1):
                raise SpecValidationError("Intel source REP repeat control is not boolean.")
            cutpoint = predict_residual_control(
                residual, "environment_cutpoint", live.state, live.knownness_inputs,
                1, prefix_composer=state, pc=virtual_pc,
            )
            if cutpoint != 0:
                raise SpecValidationError("REP source unexpectedly reached an environment cutpoint.")
            # Architectural RIP from the actual source output; repeat control
            # is independently predicted and never inferred from post-state.
            from ..intel_symbolic import predict_residual_register
            architectural_rip = predict_residual_register(
                residual, "RIP", live.state, live.knownness_inputs, 1,
                prefix_composer=state, pc=virtual_pc,
            )
            if repeat and architectural_rip != pc:
                raise SpecValidationError("Repeating Intel source step did not retain REP entry RIP.")
            steps.append(step)
            state.append(control_step)
            if not repeat:
                break
            virtual_pc += residual.length
        else:
            raise SpecValidationError("Intel source REP exceeded iteration safety limit.")
        composed = SymbolicTransformComposer(steps[0])
        for step in steps[1:]:
            composed.append(step)
        result = composed.finish()
        result.range = (pc, pc + residual.length)
        result.addr = pc
        return result

    def set_knownness_inputs(self, values):
        """Receive persistent masks from NativeSpecValidator before prediction."""
        self.knownness_inputs = dict(values)

    def _require_known_syscall_inputs(self, registers, knownness):
        """Require defined syscall identity and exactly the ABI-used arguments."""
        number = registers.get("RAX")
        argument_counts = {0: 3, 1: 3, 60: 1, 231: 1, 12: 1, 218: 1,
                           273: 3, 302: 4, 318: 3, 228: 2}
        count = argument_counts.get(number)
        if count is None:
            raise SpecValidationError(f"Unsupported Intel Linux syscall {number}.")
        for name in ("RAX", "RDI", "RSI", "RDX", "R10", "R8", "R9")[:1 + count]:
            width = 64
            mask = knownness.get(name)
            if type(mask) is not int or mask != (1 << width) - 1:
                raise SpecValidationError(f"SYSCALL uses undefined {name} input.")

    def validate_syscall_prestate(self, snapshot):
        """Check source controls and saved CPU inputs before native SYSCALL."""
        prediction = self.pending_syscall_prestate
        if prediction is None or self.pending_syscall_next_ip is None:
            raise SpecValidationError("SYSCALL lacks source-predicted saved prestate/continuation.")
        for name, item in prediction.registers.items():
            observed = snapshot.registers.get(name)
            if observed is None or ((observed ^ item.value) & item.mask):
                raise SpecValidationError(f"SYSCALL source prestate mismatch for {name}.")

    def validate_syscall_successor(self, snapshot):
        """Check resumed native RIP against the source Next_IP, not ABI length."""
        expected = self.pending_syscall_next_ip
        if expected is None:
            raise SpecValidationError("SYSCALL successor lacks a source-predicted continuation.")
        actual = snapshot.registers.get("RIP", snapshot.registers.get("PC"))
        if actual != expected:
            raise SpecValidationError(
                f"SYSCALL source Next_IP mismatch: expected {expected:#x}, observed {actual!r}."
            )
        self.pending_syscall_prestate = None
        self.pending_syscall_next_ip = None

    def close(self):
        self.oracle.close()


def make_native_spec_oracle(args):
    """CLI factory; requires model/evaluator and explicit XED or PATH lookup."""
    xed = getattr(args, "intel_xed", None) or shutil.which("intel-xed-decode")
    if not xed:
        raise ValueError("Pass --intel-xed or add intel-xed-decode to PATH.")
    return IntelNativeOracle(args.intel_model, args.intel_oracle, xed,
                             max_steps=getattr(args, "max_steps", 100000))
