"""Corrupt observations from a real native ARM run, never oracle inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from focaccia.native.spec_target import MemorySnapshot, NativeSpecTarget
from focaccia.native.spec_validate import (
    NativeSpecValidator,
    NativeTIROracle,
    SpecValidationError,
    UnsupportedNativeEvent,
)
from focaccia.native.spec_syscalls import NativeLinuxPolicy


class CorruptObservation:
    def __init__(self, target, control):
        self.target, self.control = target, control
        self.steps = 0
        self.returned_syscall = False
        self.injected = False

    def __getattr__(self, name):
        return getattr(self.target, name)

    def step(self):
        registers = self.target.read_registers()
        word = int.from_bytes(self.target.read_memory(registers["PC"], 4), "little")
        syscall = word & 0xFFE0001F == 0xD4000001
        outcome = self.target.step()
        self.steps += 1
        self.returned_syscall = syscall and outcome.state.value == "stopped"
        return outcome

    def read_registers(self):
        registers = self.target.read_registers()
        if self.injected or not self.steps:
            return registers
        if self.control in {"syscall-preservation", "syscall-resume"}:
            if not self.returned_syscall:
                return registers
            name, mask = ("X8", 1) if self.control == "syscall-preservation" else ("PC", 4)
        else:
            entry = {
                "pc": ("PC", 4),
                "unchanged-gpr": ("X20", 1),
                "simd": ("V15", 1),
                "fpsr": ("FPSR", 1 << 27),
            }.get(self.control)
            if entry is None:
                return registers
            name, mask = entry
        registers = dict(registers)
        registers[name] ^= mask
        self.injected = True
        return registers

    def memory_snapshot(self):
        snapshot = self.target.memory_snapshot()
        if self.control != "memory" or self.injected or not self.steps:
            return snapshot
        regions = list(snapshot.regions)
        for index, (mapping, data) in enumerate(regions):
            if mapping.private and mapping.read and mapping.write and not mapping.execute and data:
                regions[index] = (mapping, data[:-1] + bytes([data[-1] ^ 1]))
                self.injected = True
                return MemorySnapshot(snapshot.capability, tuple(regions))
        raise RuntimeError("No observed private RAM is available for the memory control")


def run_control(binary, executable, helper, control, timeout):
    target = NativeSpecTarget(binary)
    oracle = None
    proxy = CorruptObservation(target, control)
    try:
        target.set_timeout(timeout)
        profile = target.configure_arm_profile(helper)
        oracle = NativeTIROracle(executable, timeout, profile)
        validator = NativeSpecValidator(
            proxy,
            oracle,
            syscall_policy=NativeLinuxPolicy(
                uid=os.getuid(), gid=os.getgid(), page_size=os.sysconf("SC_PAGE_SIZE")
            ),
        )
        try:
            validator.run()
        except UnsupportedNativeEvent as error:
            return {
                "control": control,
                "status": "blocked",
                "error": str(error),
                "injected": proxy.injected,
            }
        except SpecValidationError as error:
            return {
                "control": control,
                "status": "rejected" if proxy.injected else "failed",
                "error": str(error),
                "injected": proxy.injected,
                "hardware_steps": proxy.steps,
                "validated_boundaries": validator.validated_instruction_boundaries,
            }
        return {"control": control, "status": "incorrectly-accepted", "injected": proxy.injected}
    finally:
        try:
            if oracle is not None:
                oracle.close()
        finally:
            target.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--oracle", required=True)
    parser.add_argument("--hardware-profile-helper", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args(argv)
    controls = [
        run_control(args.binary, args.oracle, args.hardware_profile_helper, name, args.timeout)
        for name in (
            "pc",
            "unchanged-gpr",
            "simd",
            "fpsr",
            "memory",
            "syscall-preservation",
            "syscall-resume",
        )
    ]
    result = {
        "execution_backend": "native",
        "architecture": "aarch64",
        "binary_sha256": hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
        "status": "passed" if all(x["status"] == "rejected" for x in controls) else "failed",
        "controls": controls,
    }
    Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
