"""Observation-only x86-64 whole-program QEMU TB trace smoke probe.

Captured transport data is evidence only; this does not validate TIR semantics.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from focaccia.arch import supported_architectures
from focaccia.qemu.transport import (
    CAP_BOUNDARY_SNAPSHOTS, CAP_INTEGER, CAP_PC, CAP_STATUS, CAP_VECTOR,
    EVENT_AARCH64_SVC_ENTRY, EVENT_AARCH64_SVC_SUCCESSOR, EVENT_TRANSLATION_BLOCK,
    PluginEOFError, PluginLaunchIdentity, PluginListener,
    SnapshotPlan,
    manifest_sha256,
)

SCHEMA = "focaccia-intel-snapshot-smoke-v1"
CPU_PROFILE = {"architecture": {"isa": "x86_64", "endianness": "little"}, "profile": "qemu-x86_64-default"}
INPUT = Path("/tmp/carbonara-sha256-input")
GPRS = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
SNAPSHOT_REGISTERS = (*GPRS, "eflags", *(f"xmm{index}" for index in range(15)))
EXTRA_REGISTERS = ("xmm15", "fs_base")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def elf_entry(path: Path) -> int:
    header = path.read_bytes()[:64]
    if len(header) != 64 or header[:6] != b"\x7fELF\x02\x01":
        raise ValueError(f"not an ELF64 little-endian binary: {path}")
    return struct.unpack_from("<Q", header, 24)[0]


def observe(qemu: str, plugin: str, binary: Path, output: Path, timeout: float) -> dict:
    """Record all ordered events for the requested BusyBox invocation.

    Events are serialized with raw transport fields so later consumers can
    replay immutable snapshots; no guest state is inferred here.
    """
    if not INPUT.is_file():
        raise FileNotFoundError(INPUT)
    argv, env = ["sha256sum", str(INPUT)], {}
    identity = PluginLaunchIdentity(
        sha256(binary), manifest_sha256(argv), manifest_sha256(env),
        manifest_sha256(CPU_PROFILE),
    )
    socket_path = Path(tempfile.mkdtemp(prefix="focaccia-intel-smoke-")) / "plugin.sock"
    listener = PluginListener(
        str(socket_path), supported_architectures["x86_64"], expected_identity=identity,
        required_capabilities=CAP_PC | CAP_INTEGER | CAP_STATUS | CAP_VECTOR | CAP_BOUNDARY_SNAPSHOTS,
    )
    listener.start()
    option = ",".join((
        plugin, f"socket={listener.path}", "start=0", "stop=18446744073709551615",
        f"binary-sha256={identity.binary_sha256}", f"argv-sha256={identity.argv_sha256}",
        f"env-sha256={identity.env_sha256}", f"cpu-sha256={identity.cpu_sha256}",
        "online-blocks=on", "automatic-snapshots=off",
    ))
    command = [qemu, "-plugin", option, str(binary), *argv]
    process = None
    first_event = None
    previous_tb = None
    event_count = 0
    syscall_event_count = 0
    installed_plans = set()
    trace_path = output.with_suffix(output.suffix + ".events.jsonl")
    trace_stream = trace_path.open("w")
    stdout_stream = stderr_stream = None
    try:
        stdout_path = output.with_suffix(output.suffix + ".stdout")
        stderr_path = output.with_suffix(output.suffix + ".stderr")
        stdout_stream = stdout_path.open("w")
        stderr_stream = stderr_path.open("w")
        process = subprocess.Popen(command, env=env, stdout=stdout_stream, stderr=stderr_stream, text=True)
        assert listener._server is not None
        listener._server.settimeout(0.25)
        while True:
            try:
                transport, handshake = listener.accept()
                break
            except TimeoutError:
                if process.poll() is not None:
                    process.wait(timeout=timeout)
                    stdout_stream.flush(); stderr_stream.flush()
                    stderr = stderr_path.read_text()
                    raise RuntimeError(
                        f"QEMU exited before plugin handshake ({process.returncode}): {stderr[-4096:]}"
                    )
        while True:
            try:
                event = transport.receive_event(timeout=timeout)
            except PluginEOFError:
                process.wait(timeout=timeout)
                break
            if event.kind in (EVENT_AARCH64_SVC_ENTRY, EVENT_AARCH64_SVC_SUCCESSOR):
                action = {"kind": "syscall-entry" if event.kind == EVENT_AARCH64_SVC_ENTRY else "syscall-return",
                          "sequence": event.sequence, "epoch": event.epoch, "pc": event.pc,
                          "argument0_or_address": event.address, "size": event.size,
                          "syscall_or_result": event.auxiliary}
                trace_stream.write(json.dumps(action, separators=(",", ":")) + "\n")
                syscall_event_count += 1
                transport.advance()
                continue
            if event.kind != EVENT_TRANSLATION_BLOCK:
                raise RuntimeError(f"unexpected x86 event kind {event.kind}")
            if event.pc not in installed_plans:
                transport.install_snapshot_plan(SnapshotPlan(
                    event.pc, 1,
                    SNAPSHOT_REGISTERS,
                ))
                installed_plans.add(event.pc)
            snapshot = transport.capture_snapshot(event.pc)
            regs = {item.name: {"bits": item.num_bits, "hex": hex(item.value)}
                    for item in snapshot.registers}
            for register in EXTRA_REGISTERS:
                item = transport.read_register(register)
                regs[item.name] = {"bits": item.num_bits, "hex": hex(item.value)}
            memory_address = int(regs["rsp"]["hex"], 16)
            try:
                stack_bytes = transport.read_memory(memory_address, 16)
                memory_read_error = None
            except Exception as error:
                from focaccia.qemu.transport import MemoryAccessError
                if not isinstance(error, MemoryAccessError):
                    raise
                stack_bytes = b""
                memory_read_error = str(error)
            observation = {
                "kind": event.kind, "sequence": event.sequence, "epoch": event.epoch,
                "pc": event.pc, "tb_last_pc": event.address, "instruction_count": event.size,
                "snapshot_occurrence": snapshot.occurrence,
                "snapshot_generation": snapshot.generation,
                "registers": regs,
                "memory_reads": [{"address": memory_address, "size": len(stack_bytes),
                                  "hex": stack_bytes.hex(), "unavailable": memory_read_error}],
                "observed_poststate_for": previous_tb,
            }
            if first_event is None:
                first_event = observation
            event_count += 1
            previous_tb = {"sequence": event.sequence, "pc": event.pc}
            trace_stream.write(json.dumps(observation, separators=(",", ":")) + "\n")
            if event_count % 1000 == 0:
                trace_stream.flush()
                print(f"captured {event_count} TB-boundary snapshots", file=sys.stderr, flush=True)
            if event_count > 10_000_000:
                raise RuntimeError("event safety limit reached")
            transport.advance()
        process.wait(timeout=timeout)
        stdout_stream.flush(); stderr_stream.flush()
        stdout_stream.close(); stderr_stream.close()
        stdout, stderr = stdout_path.read_text(), stderr_path.read_text()
        if process.returncode != 0:
            raise RuntimeError(f"QEMU/guest exited {process.returncode}: {stderr[-4096:]}")
        entry = elf_entry(binary)
        if first_event is None or first_event["pc"] != entry:
            raise RuntimeError(f"first TB boundary {None if first_event is None else hex(first_event['pc'])} != ELF entry {entry:#x}")
        expected_hash = sha256(INPUT)
        if stdout != f"{expected_hash}  {INPUT}\n":
            raise RuntimeError("BusyBox sha256sum output differs from independently computed input digest")
        result = {
            "schema": SCHEMA, "command": command, "returncode": process.returncode,
            "stdout": stdout, "stderr": stderr, "expected_sha256": expected_hash,
            "elf_entry": entry, "handshake": {"pid": handshake.pid, "target": handshake.target},
            "event_count": event_count, "syscall_event_count": syscall_event_count,
            "trace_file": str(trace_path),
            "terminal": {"kind": "guest-process-exit", "status": process.returncode},
            "whole_program_completed": True,
            "observation_only": True, "semantic_validation": False,
        }
        output.write_text(json.dumps(result, indent=2) + "\n")
        return result
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        trace_stream.close()
        if stdout_stream is not None and not stdout_stream.closed:
            stdout_stream.close()
        if stderr_stream is not None and not stderr_stream.closed:
            stderr_stream.close()
        listener.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--binary", type=Path, default=Path("/tmp/carbonara-intel-integer-app/bin/busybox"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("timeout must be positive")
    observe(args.qemu, args.plugin, args.binary, args.output, args.timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
