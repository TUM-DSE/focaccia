"""Single-execution online TB validation of canonical static-musl QEMU #2248."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess

from focaccia.arch.aarch64 import ArchAArch64
from focaccia.qemu.transport import (
    EVENT_AARCH64_SVC_ENTRY,
    EVENT_AARCH64_SVC_SUCCESSOR,
    EVENT_STORE,
    EVENT_TRANSLATION_BLOCK,
    PluginLaunchIdentity,
    PluginListener,
    PluginTransport,
    manifest_sha256,
)
from focaccia.qemu.validation_server import PluginProgramState
from focaccia.symbolic import SymbolicTransform, SymbolicTransformComposer
from focaccia.tir_backend import decode_response

EXPECTED_CALLME = bytes.fromhex(
    "5f0003ebeca79f9a8b1d00127f010071ee039fdacd25c49aa01d4093c0035fd6"
)
CPU_PROFILE = {
    "architecture": {"isa": "aarch64", "endianness": "little"},
    "profile": "qemu-user-max-sve-off-v1",
}
MASK64 = (1 << 64) - 1
SVC_MASK = 0xFFE0001F
SVC_OPCODE = 0xD4000001


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def elf_loads(binary: Path) -> tuple[int, list[tuple[int, int, bytes]]]:
    data = binary.read_bytes()
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("expected little-endian ELF64")
    if struct.unpack_from("<HHI", data, 16) != (2, 183, 1):
        raise ValueError("expected static ET_EXEC AArch64 ELF")
    entry, phoff = struct.unpack_from("<QQ", data, 24)
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    if phentsize != 56 or not 1 <= phnum <= 256 or phoff + phentsize * phnum > len(data):
        raise ValueError("invalid ELF program headers")
    loads = []
    for index in range(phnum):
        kind, flags, offset, address, _, file_size, memory_size, _ = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + index * phentsize
        )
        if kind == 3:
            raise ValueError("static-musl fixture must not have an interpreter")
        if kind != 1:
            continue
        if file_size > memory_size or offset + file_size > len(data):
            raise ValueError("invalid ELF load segment")
        loads.append((address, flags, data[offset : offset + file_size]))
    if not loads or not any(address <= entry < address + len(raw) for address, _, raw in loads):
        raise ValueError("ELF entry is not file-backed")
    return entry, loads


def read_image(loads: list[tuple[int, int, bytes]], address: int, size: int) -> bytes:
    matches = [
        raw[address - base : address - base + size]
        for base, _, raw in loads
        if base <= address and address + size <= base + len(raw)
    ]
    if len(matches) != 1:
        raise ValueError(f"address {address:#x} is not in one file-backed segment")
    return matches[0]


def launch_identity(binary: Path) -> PluginLaunchIdentity:
    return PluginLaunchIdentity(
        file_sha256(binary), manifest_sha256([]), manifest_sha256([]),
        manifest_sha256(CPU_PROFILE),
    )


def plugin_option(
    plugin: str,
    socket_path: Path,
    identity: PluginLaunchIdentity,
    start: int,
    stop: int,
    *,
    online_blocks: bool = True,
) -> str:
    fields = [
        plugin, f"socket={socket_path}", f"start={start}", f"stop={stop}",
        f"binary-sha256={identity.binary_sha256}",
        f"argv-sha256={identity.argv_sha256}",
        f"env-sha256={identity.env_sha256}",
        f"cpu-sha256={identity.cpu_sha256}",
    ]
    if online_blocks:
        fields.append("online-blocks=on")
    return ",".join(fields)


@dataclass
class PendingBlock:
    first_pc: int
    last_pc: int
    instruction_count: int
    entry_sequence: int
    elf_bytes_sha256: str
    transform: SymbolicTransform | None
    expected_registers: dict[str, int]
    expected_stores: tuple[tuple[int, bytes], ...]
    expected_memory: dict[int, bytes]
    svc_pc: int | None


class OnlineTirValidator:
    """Lazily specialize each observed TB and validate it at the next safe boundary."""

    def __init__(
        self,
        binary: Path,
        loads: list[tuple[int, int, bytes]],
        oracle: str,
        transport: PluginTransport,
        pid: int,
    ) -> None:
        self.binary = binary
        self.loads = [(base, flags, raw) for base, flags, raw in loads if flags & 1]
        if not self.loads:
            raise ValueError("ELF has no executable file-backed load segment")
        self.oracle = oracle
        self.transport = transport
        self.pid = pid
        self.arch = ArchAArch64("little")
        self.state = PluginProgramState(self.arch, transport)
        self.state.execution_tid = pid
        self.instruction_cache: dict[tuple[int, bytes], dict] = {}
        self.block_cache: dict[tuple[int, bytes], SymbolicTransform | None] = {}
        self.active: PendingBlock | None = None
        self.pending_svc: dict | None = None
        self.errors: list[dict] = []
        self.blocks: list[dict] = []
        self.store_evidence: list[dict] = []
        self.syscall_evidence: list[dict] = []
        self.terminal: dict | None = None
        self.oracle_batches = 0
        self.specializations = 0

    @staticmethod
    def _is_svc(code: bytes) -> bool:
        return int.from_bytes(code, "little") & SVC_MASK == SVC_OPCODE

    def _specialize(self, instructions: list[tuple[int, bytes]]) -> None:
        missing = [(pc, code) for pc, code in instructions if (pc, code) not in self.instruction_cache]
        if not missing:
            return
        payload = "".join(f"{pc} {code.hex()}\n" for pc, code in missing)
        env = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("TIR_", "TIRAMISU_", "FOCACCIA_TIR_MODULE"))
        }
        completed = subprocess.run(
            [self.oracle, "--export-transitions"], input=payload, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600,
            check=False, env=env,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"TIR specialization failed: {completed.stderr[-4096:].strip()}")
        lines = completed.stdout.splitlines()
        if len(lines) != len(missing):
            raise RuntimeError("TIR batch response cardinality mismatch")
        for (pc, code), line in zip(missing, lines, strict=True):
            _next_pc, outputs = decode_response(line, pc, code)
            self.instruction_cache[(pc, code)] = outputs
        self.oracle_batches += 1
        self.specializations += len(missing)

    def _block_transform(self, pc: int, raw: bytes) -> tuple[SymbolicTransform | None, int | None]:
        key = (pc, raw)
        svc_offsets = [
            offset for offset in range(0, len(raw), 4)
            if self._is_svc(raw[offset : offset + 4])
        ]
        if svc_offsets and svc_offsets != [len(raw) - 4]:
            raise RuntimeError("SVC is not the final instruction of its translation block")
        svc_pc = pc + svc_offsets[0] if svc_offsets else None
        semantic_raw = raw[:-4] if svc_pc is not None else raw
        if key in self.block_cache:
            return self.block_cache[key], svc_pc
        instructions = [
            (pc + offset, semantic_raw[offset : offset + 4])
            for offset in range(0, len(semantic_raw), 4)
        ]
        self._specialize(instructions)
        composer = None
        for address, code in instructions:
            transform = SymbolicTransform(
                self.pid, self.instruction_cache[(address, code)], [], self.arch,
                address, address + 4,
            )
            if composer is None:
                composer = SymbolicTransformComposer(transform)
            else:
                composer.append(transform)
        result = composer.finish() if composer is not None else None
        self.block_cache[key] = result
        return result, svc_pc

    def _begin_block(self, event) -> None:
        if self.active is not None:
            self._compare_active(event.pc, event.sequence)
        if self.pending_svc is not None:
            raise RuntimeError("next TB arrived before SVC successor evidence")
        raw = read_image(self.loads, event.pc, event.size * 4)
        transform, svc_pc = self._block_transform(event.pc, raw)
        # The TB callback runs before its first instruction, so the plugin's
        # instruction scoreboard is intentionally stale.  The immutable TB
        # descriptor is the explicit boundary PC.
        self.state.flush_observations()
        self.state.write_register("PC", event.pc)
        if transform is None:
            expected_registers: dict[str, int] = {}
            expected_stores: tuple[tuple[int, bytes], ...] = ()
            expected_memory: dict[int, bytes] = {}
        else:
            expected_registers = transform.eval_validation_register_transforms(self.state)
            expected_stores = transform.eval_ordered_memory_transforms(self.state)
            expected_memory = transform.eval_memory_transforms(self.state)
        self.active = PendingBlock(
            event.pc, event.address, event.size, event.sequence,
            hashlib.sha256(raw).hexdigest(), transform, expected_registers,
            expected_stores, expected_memory, svc_pc,
        )
        self.transport.advance()

    def _compare_active(self, destination_pc: int, boundary_sequence: int) -> None:
        block = self.active
        if block is None:
            raise RuntimeError("no active TB at comparison boundary")
        self.state.flush_observations()
        self.state.write_register("PC", destination_pc)
        block_errors = []
        for register, expected in block.expected_registers.items():
            actual = destination_pc if register == "PC" else self.state.read_register(register)
            if actual != expected:
                error = {
                    "severity": "confirmed", "subject": register,
                    "expected": hex(expected), "actual": hex(actual),
                    "block_pc": hex(block.first_pc),
                }
                self.errors.append(error)
                block_errors.append(error)
        for address, expected in block.expected_memory.items():
            actual = self.state.read_memory(address, len(expected))
            if actual != expected:
                error = {
                    "severity": "confirmed", "subject": hex(address),
                    "expected": expected.hex(), "actual": actual.hex(),
                    "block_pc": hex(block.first_pc),
                }
                self.errors.append(error)
                block_errors.append(error)
        for ordinal, (address, value) in enumerate(block.expected_stores):
            self.store_evidence.append({
                "block_pc": block.first_pc, "ordinal": ordinal,
                "address": address, "value": value.hex(),
                "final_ranges_verified": True,
            })
        self.blocks.append({
            "first_pc": block.first_pc,
            "last_pc": block.last_pc,
            "instruction_count": block.instruction_count,
            "destination_pc": destination_pc,
            "event_span": boundary_sequence - block.entry_sequence,
            "elf_bytes_sha256": block.elf_bytes_sha256,
            "ordered_writes": [
                {"address": address, "value": value.hex()}
                for address, value in block.expected_stores
            ],
            "final_write_ranges": len(block.expected_memory),
            "errors": block_errors,
        })
        self.active = None

    def _svc_entry(self, event) -> None:
        if self.active is None or self.active.svc_pc != event.pc:
            raise RuntimeError("SVC evidence is not the final instruction of the active TB")
        self._compare_active(event.pc, event.sequence)
        evidence = {
            "sequence": event.sequence, "entry_epoch": event.epoch,
            "pc": event.pc, "number": event.auxiliary, "argument0": event.address,
        }
        self.syscall_evidence.append(evidence)
        if event.auxiliary == 94:
            self.terminal = {
                "pc": event.pc, "exit_status": event.address & 0xFF,
                "action": "exit_group", "sequence": event.sequence,
            }
            self.transport.finish()
            return
        if event.auxiliary != 96 or self.pending_svc is not None:
            raise RuntimeError(f"unsupported interior syscall {event.auxiliary}")
        self.pending_svc = evidence
        self.transport.advance()

    def _svc_successor(self, event) -> None:
        pending = self.pending_svc
        if pending is None or event.address != pending["pc"]:
            raise RuntimeError("SVC successor is not bound to its entry")
        if event.pc != 0 or event.auxiliary != self.pid:
            raise RuntimeError("set_tid_address result is not bound to the launch PID")
        pending.update({
            "successor_pc": event.pc, "successor_epoch": event.epoch,
            "result": event.auxiliary,
        })
        self.pending_svc = None
        self.transport.advance()

    def run(self) -> dict:
        while self.terminal is None:
            event = self.transport.receive_event()
            if event.kind == EVENT_TRANSLATION_BLOCK:
                self._begin_block(event)
            elif event.kind == EVENT_STORE:
                raise RuntimeError("online mode received an optimizer-barrier store event")
            elif event.kind == EVENT_AARCH64_SVC_ENTRY:
                self._svc_entry(event)
            elif event.kind == EVENT_AARCH64_SVC_SUCCESSOR:
                self._svc_successor(event)
            else:
                raise RuntimeError(f"unexpected online event kind {event.kind}")
        if self.active is not None or self.pending_svc is not None:
            raise RuntimeError("terminal action left an unvalidated block or syscall")
        return {
            "blocks": self.blocks,
            "errors": self.errors,
            "store_evidence": self.store_evidence,
            "syscall_evidence": self.syscall_evidence,
            "terminal": self.terminal,
            "cache": {
                "observed_block_shapes": len(self.block_cache),
                "specialized_instructions": self.specializations,
                "instruction_cache_entries": len(self.instruction_cache),
                "oracle_batches": self.oracle_batches,
            },
        }


def validate_report(document: dict, *, mismatch: bool, terminal_pc: int | None = None) -> None:
    expected_status = "mismatch" if mismatch else "accepted"
    if document.get("status") != expected_status:
        raise ValueError(f"expected {expected_status}, got {document.get('status')}")
    completion = document.get("completion", {})
    if not completion.get("complete") or not completion.get("execution_complete"):
        raise ValueError("whole-program terminal evidence is incomplete")
    if completion.get("scope") != "whole-program":
        raise ValueError("whole-program scope was not retained")
    if terminal_pc is not None and document.get("terminal", {}).get("pc") != terminal_pc:
        raise ValueError("terminal PC was not bound")
    errors = document.get("errors", [])
    if mismatch:
        if len(errors) != 1 or errors[0].get("severity") != "confirmed" or errors[0].get("subject") != "X0":
            raise ValueError(f"expected one confirmed localized X0 mismatch, got {errors}")
    elif errors:
        raise ValueError(f"fixed execution produced errors: {errors}")


def run_case(
    args, binary: Path, loads, entry: int, callme: int, directory: Path, *, mismatch: bool
) -> dict:
    directory.mkdir()
    identity = launch_identity(binary)
    executable_loads = [(base, raw) for base, flags, raw in loads if flags & 1]
    text_start = min(base for base, _ in executable_loads)
    text_stop = max(base + len(raw) - 4 for base, raw in executable_loads)
    socket_path = directory / "plugin.sock"
    listener = PluginListener(str(socket_path), ArchAArch64("little"), expected_identity=identity)
    listener.start()
    qemu_path = args.qemu_injected if mismatch else args.qemu_fixed
    plugin_path = args.plugin_injected if mismatch else args.plugin_fixed
    command = [
        qemu_path, "-cpu", "max,sve=off", "-plugin",
        plugin_option(plugin_path, socket_path, identity, text_start, text_stop),
        str(binary),
    ]
    (directory / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    with (directory / "qemu.stdout").open("wb") as stdout, (
        directory / "qemu.stderr"
    ).open("wb") as stderr:
        process = subprocess.Popen(command, env={}, stdout=stdout, stderr=stderr)
        transport: PluginTransport | None = None
        try:
            transport, handshake = listener.accept()
            validator = OnlineTirValidator(binary, loads, args.oracle, transport, handshake.pid)
            online = validator.run()
        except BaseException:
            if transport is not None and not transport.closed:
                try:
                    transport.abort()
                except BaseException:
                    pass
            process.wait(timeout=30)
            raise
        finally:
            listener.close()
        guest_status = process.wait(timeout=30)
    expected_status = 1 if mismatch else 0
    if guest_status != expected_status or (directory / "qemu.stdout").read_bytes():
        raise RuntimeError(
            f"guest did not naturally exit {expected_status} without output: {guest_status}"
        )
    terminal = online["terminal"]
    if terminal["exit_status"] != expected_status:
        raise RuntimeError("terminal action disagrees with parent-observed guest exit")
    if not online["blocks"] or online["blocks"][0]["first_pc"] != entry:
        raise RuntimeError("online TB coverage does not begin at the ELF entry")
    witness_blocks = [block for block in online["blocks"] if block["first_pc"] == callme]
    if (
        len(witness_blocks) != 1
        # The seven optimizer-sensitive dataflow instructions and trailing RET
        # must remain one uninterrupted translated unit.
        or witness_blocks[0]["instruction_count"] != 8
        or witness_blocks[0]["last_pc"] != callme + 28
        or witness_blocks[0]["event_span"] != 1
    ):
        raise RuntimeError("canonical #2248 witness was not one uninterrupted seven-instruction TB")
    report = {
        "schema": 3,
        "status": "mismatch" if online["errors"] else "accepted",
        "completion": {
            "scope": "whole-program", "complete": True,
            "execution_complete": True, "guest_exit_status": guest_status,
        },
        **online,
    }
    validate_report(report, mismatch=mismatch, terminal_pc=terminal["pc"])
    (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return {
        "status": report["status"], "guest_exit_status": guest_status,
        "qemu_executions": 1, "terminal_evidence": "complete",
        "block_count": len(report["blocks"]), "cache": report["cache"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--oracle", required=True)
    parser.add_argument("--qemu-fixed", required=True)
    parser.add_argument("--qemu-injected", required=True)
    parser.add_argument("--plugin-fixed", required=True)
    parser.add_argument("--plugin-injected", required=True)
    parser.add_argument("--tir-revision", required=True)
    parser.add_argument("--qemu-revision", required=True)
    parser.add_argument("--run-directory", required=True, type=Path)
    args = parser.parse_args()
    root = args.run_directory.resolve()
    root.mkdir(parents=True, exist_ok=False)
    try:
        binary = (args.fixture / "program.elf").resolve()
        fixture = json.loads((args.fixture / "manifest.json").read_text())
        entry, loads = elf_loads(binary)
        if fixture.get("schema") != 2 or fixture["entry"] != entry or fixture["sha256"] != file_sha256(binary):
            raise ValueError("fixture manifest mismatch")
        if read_image(loads, fixture["callme"], len(EXPECTED_CALLME)) != EXPECTED_CALLME:
            raise ValueError("fixture does not contain canonical callme.S bytes")
        cases = {
            "fixed": run_case(
                args, binary, loads, entry, fixture["callme"], root / "fixed", mismatch=False
            ),
            "injected": run_case(
                args, binary, loads, entry, fixture["callme"], root / "injected", mismatch=True
            ),
        }
        manifest = {
            "schema": 3, "architecture": "online-tb-tir", "scope": "whole-program",
            "binary": str(binary), "binary_sha256": file_sha256(binary),
            "main_sha256": fixture["main_sha256"], "callme_sha256": fixture["callme_sha256"],
            "entry": entry, "tir_revision": args.tir_revision,
            "qemu_revision": args.qemu_revision, "argv": [], "environment": [],
            "cpu_profile": CPU_PROFILE, "qemu_executions_per_case": 1,
            "dynamic_path_oracle": False, "record_replay": False,
            "miasm_semantics": False, "synthetic_state_mutation": False,
            "semantics": "TIR specialized lazily from immutable ELF bytes for observed TBs",
        }
        (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        result = {"schema": 3, "status": "passed", "scope": "whole-program", "cases": cases}
        (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
    except BaseException as error:
        (root / "result.json").write_text(json.dumps(
            {"schema": 3, "status": "failed", "error": str(error)}, indent=2
        ) + "\n")
        raise


if __name__ == "__main__":
    main()
