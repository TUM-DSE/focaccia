"""Whole-program static-musl #2248 validation with TIR and plugin events."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import time

from miasm.expression.expression import Expr, ExprId, ExprInt

from focaccia.arch.aarch64 import ArchAArch64
from focaccia.completion import TraceCompletion, TraceScope
from focaccia.execution import ExecutionOutcome, ExecutionState
from focaccia.no_replay import (
    ExitAction,
    ExitScope,
    NoReplayActionDescriptor,
    NoReplayActionKind,
    NoReplaySetTidBoundary,
)
from focaccia.parser import serialize_transformations
from focaccia.qemu.transport import (
    EVENT_AARCH64_SVC_ENTRY,
    EVENT_CUTPOINT,
    EVENT_STORE,
    PluginLaunchIdentity,
    PluginListener,
    manifest_sha256,
)
from focaccia.snapshot import ProgramState
from focaccia.symbolic import DisassemblyContext, SymbolicTransform
from focaccia.tir_backend import decode_response
from focaccia.trace import MaterializedTrace, TraceEnvironment

EXPECTED_CALLME = bytes.fromhex(
    "5f0003ebeca79f9a8b1d00127f010071ee039fdacd25c49aa01d4093c0035fd6"
)
CPU_PROFILE = {
    "architecture": {"isa": "aarch64", "endianness": "little"},
    "profile": "qemu-user-max-sve-off-v1",
}
MASK64 = (1 << 64) - 1


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
    matches = [raw[address - base : address - base + size]
               for base, _, raw in loads if base <= address and address + size <= base + len(raw)]
    if len(matches) != 1:
        raise ValueError(f"address {address:#x} is not in one file-backed segment")
    return matches[0]


def launch_identity(binary: Path) -> PluginLaunchIdentity:
    return PluginLaunchIdentity(
        file_sha256(binary), manifest_sha256([]), manifest_sha256([]),
        manifest_sha256(CPU_PROFILE),
    )


def plugin_option(plugin: str, socket_path: Path, identity: PluginLaunchIdentity,
                  start: int, stop: int, *, coarse: bool,
                  cutpoints: tuple[int, ...] = ()) -> str:
    fields = [
        plugin, f"socket={socket_path}", f"start={start}", f"stop={stop}",
        f"binary-sha256={identity.binary_sha256}",
        f"argv-sha256={identity.argv_sha256}",
        f"env-sha256={identity.env_sha256}",
        f"cpu-sha256={identity.cpu_sha256}",
    ]
    if coarse:
        fields.append("coarse=on")
    fields.extend(f"cutpoint={address}" for address in cutpoints)
    return ",".join(fields)


def discover_execution(binary: Path, qemu: str, plugin: str, directory: Path) -> dict:
    """Observe only control/action boundaries; all instruction semantics come from TIR."""
    entry, loads = elf_loads(binary)
    identity = launch_identity(binary)
    socket_path = directory / "discovery.sock"
    listener = PluginListener(str(socket_path), ArchAArch64("little"), expected_identity=identity)
    listener.start()
    text_start = min(base for base, flags, _ in loads if flags & 1)
    command = [qemu, "-cpu", "max,sve=off", "-plugin",
               plugin_option(plugin, socket_path, identity, text_start, MASK64,
                             coarse=False), str(binary)]
    (directory / "discovery-command.json").write_text(json.dumps(command, indent=2) + "\n")
    with (directory / "discovery.stdout").open("wb") as stdout, (
        directory / "discovery.stderr"
    ).open("wb") as stderr:
        process = subprocess.Popen(command, env={}, stdout=stdout, stderr=stderr)
        transport, handshake = listener.accept()
        sequence: list[tuple[int, str]] = []
        events: list[dict] = []
        terminal_pending = False
        try:
            while True:
                event = transport.receive_event()
                events.append({
                    "kind": event.kind, "sequence": event.sequence, "epoch": event.epoch,
                    "pc": event.pc, "address": event.address, "size": event.size,
                    "auxiliary": event.auxiliary, "value": event.value.hex(),
                })
                if event.kind == EVENT_STORE:
                    if transport.read_memory(event.address, event.size) != event.value:
                        raise RuntimeError("store event is not coherent at its declared epoch")
                elif event.kind == EVENT_AARCH64_SVC_ENTRY:
                    terminal_pending = event.auxiliary == 94
                elif event.kind == EVENT_CUTPOINT:
                    if transport.read_register("pc").value != event.pc:
                        raise RuntimeError("cutpoint PC disagrees with register state")
                    sequence.append((event.pc, transport.read_memory(event.pc, 4).hex()))
                    if terminal_pending:
                        transport.finish()
                        break
                transport.advance()
        finally:
            listener.close()
        returncode = process.wait(timeout=30)
    if returncode != 0 or (directory / "discovery.stdout").read_bytes():
        raise RuntimeError("fixed canonical execution did not naturally exit 0 without output")
    document = {
        "pid": handshake.pid, "returncode": returncode, "instructions": sequence,
        "events": events, "control_flow_source": "fixed plugin instruction events",
    }
    (directory / "discovery.json").write_text(json.dumps(document, indent=2) + "\n")
    return document


def discover_logged_execution(binary: Path, qemu: str, directory: Path, fixed: dict) -> dict:
    """Recover uninstrumented TB control flow; instruction semantics remain TIR-only."""
    log_path = directory / "qemu-exec.log"
    command = [qemu, "-cpu", "max,sve=off", "-d", "in_asm,exec,nochain",
               "-D", str(log_path), str(binary)]
    (directory / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    completed = subprocess.run(command, env={}, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=60, check=False)
    (directory / "stdout").write_bytes(completed.stdout)
    (directory / "stderr").write_bytes(completed.stderr)
    if completed.returncode != 1 or completed.stdout:
        raise RuntimeError(
            "regression-injected canonical execution did not naturally exit 1 without output"
        )
    blocks: dict[int, bytes] = {}
    traces: list[int] = []
    pending_pc = None
    pending_bytes = bytearray()
    for line in log_path.read_text().splitlines():
        address = re.match(r"0x([0-9a-f]+):", line)
        if address is not None and pending_pc is None:
            pending_pc = int(address.group(1), 16)
        encoded = re.match(r"OBJD-T: ([0-9a-f]+)$", line)
        if encoded is not None:
            pending_bytes.extend(bytes.fromhex(encoded.group(1)))
        executed = re.match(r"Trace \d+: .*\[[^/]*/([0-9a-f]{16})/", line)
        if executed is not None:
            pc = int(executed.group(1), 16)
            if pending_pc is not None:
                if pending_pc != pc or not pending_bytes or len(pending_bytes) % 4:
                    raise ValueError("malformed QEMU translation-block log")
                old = blocks.setdefault(pc, bytes(pending_bytes))
                if old != pending_bytes:
                    raise ValueError("one guest PC produced conflicting translation blocks")
                pending_pc, pending_bytes = None, bytearray()
            traces.append(pc)
    sequence = []
    for pc in traces:
        block = blocks.get(pc)
        if block is None:
            raise ValueError(f"execution log references unknown block {pc:#x}")
        sequence.extend((pc + offset, block[offset:offset + 4].hex())
                        for offset in range(0, len(block), 4))
    if not sequence:
        raise ValueError("empty injected dynamic instruction sequence")
    document = {
        "pid": fixed["pid"], "returncode": completed.returncode,
        "instructions": sequence, "events": fixed["events"],
        # Only path addresses come from the buggy implementation. Every instruction
        # transition is independently decoded by TIR from the immutable ELF below.
        "control_flow_source": "regression-injected uninstrumented QEMU TB execution log",
    }
    (directory / "discovery.json").write_text(json.dumps(document, indent=2) + "\n")
    return document


def generate_reference(binary: Path, discovery: dict, oracle: str, directory: Path,
                       *, expected_exit: int):
    entry, loads = elf_loads(binary)
    sequence = [(int(pc), bytes.fromhex(code)) for pc, code in discovery["instructions"]]
    if not sequence or sequence[0][0] != entry:
        raise ValueError("dynamic instruction sequence does not start at ELF entry")
    for pc, code in sequence:
        if len(code) != 4 or read_image(loads, pc, 4) != code:
            raise ValueError(f"path instruction at {pc:#x} is not bound to the fixture ELF")
    svc_entries = {
        event["pc"]: event for event in discovery["events"]
        if event["kind"] == EVENT_AARCH64_SVC_ENTRY
    }
    if [event["auxiliary"] for event in svc_entries.values()] != [96, 94]:
        raise ValueError("unexpected static-musl syscall profile")
    terminal_pc, terminal_code = sequence[-1]
    if any(pc not in {address for address, _ in sequence} for pc in svc_entries):
        raise ValueError("syscall evidence is not present on the selected control-flow path")
    if svc_entries.get(terminal_pc, {}).get("auxiliary") != 94 or terminal_code != b"\x01\0\0\xd4":
        raise ValueError("dynamic sequence does not end at exit_group SVC")

    unique = list(dict.fromkeys((pc, code) for pc, code in sequence[:-1] if pc not in svc_entries))
    payload = "".join(f"{pc} {code.hex()}\n" for pc, code in unique)
    completed = subprocess.run(
        [oracle, "--export-transitions"], input=payload, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600, check=True,
        env={key: value for key, value in os.environ.items() if not key.startswith(("TIR_", "TIRAMISU_"))},
    )
    lines = completed.stdout.splitlines()
    if len(lines) != len(unique):
        raise RuntimeError("TIR batch response cardinality mismatch")
    decoded = {
        key: decode_response(line, key[0], key[1])
        for key, line in zip(unique, lines, strict=True)
    }

    arch = ArchAArch64("little")
    image = ProgramState(arch)
    for base, flags, raw in loads:
        if flags & 1:
            image.write_memory(base, raw)
    context = DisassemblyContext(image)
    transforms = []
    set_tid_boundary = None
    for index, ((pc, code), (next_pc, _)) in enumerate(zip(sequence[:-1], sequence[1:], strict=True)):
        instruction = context.disassemble(pc)
        svc = svc_entries.get(pc)
        outputs: dict[Expr, Expr]
        if svc is None:
            _, outputs = decoded[(pc, code)]
        else:
            number = svc["auxiliary"]
            expected = {96: ExprId("__focaccia_execution_tid", 64)}.get(number)
            if expected is None:
                raise ValueError(f"unsupported interior syscall {number}")
            outputs = {ExprId("PC", 64): ExprInt(pc + 4, 64), ExprId("X0", 64): expected}
            if next_pc != pc + 4:
                raise ValueError("interior SVC did not resume at its architectural successor")
            if number == 96:
                descriptor = NoReplayActionDescriptor(arch.key, pc, NoReplayActionKind.SET_TID_ADDRESS)
                set_tid_boundary = NoReplaySetTidBoundary(
                    index, descriptor, svc["address"], discovery["pid"]
                )
        transforms.append(SymbolicTransform(1, outputs, [instruction], arch, pc, next_pc))

    if set_tid_boundary is None:
        raise ValueError("set_tid_address was not retained as an interior action")
    terminal_descriptor = NoReplayActionDescriptor(
        arch.key, terminal_pc, NoReplayActionKind.EXIT_GROUP
    )
    completion = TraceCompletion(
        terminal_pc, len(transforms), len(transforms) + 1,
        ExecutionOutcome(ExecutionState.EXITED, exit_status=expected_exit),
        terminal_descriptor, ExitAction(expected_exit, ExitScope.GROUP),
        no_replay_set_tid=(set_tid_boundary,),
    )
    environment = TraceEnvironment(
        str(binary), (), (), start_address=entry, stop_address=terminal_pc,
        architecture=arch.key,
    )
    trace = MaterializedTrace(
        transforms, environment, (pc for pc, _ in sequence[:-1]),
        scope=TraceScope.WHOLE_PROGRAM, completion=completion,
    )
    trace_path = directory / "oracle.json"
    serialize_transformations(trace, trace_path)

    audit = subprocess.run(
        [oracle, "--audit-classes"],
        input="".join(f"{pc} {code.hex()}\n" for pc, code in sequence), text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300, check=True,
        env={key: value for key, value in os.environ.items() if not key.startswith(("TIR_", "TIRAMISU_"))},
    )
    classes = [line.split(maxsplit=2)[2] for line in audit.stdout.splitlines()]
    audit_document = {
        "instruction_count": len(sequence),
        "transform_count": len(transforms),
        "classes": {name: classes.count(name) for name in sorted(set(classes))},
        "unique_opcode_count": len({code for _, code in sequence}),
        "svc_policy": {"96": "context-bound set_tid_address",
                       "94": f"terminal exit_group({expected_exit})"},
        "path_provenance": {
            "source": discovery["control_flow_source"],
            "instruction_sequence_sha256": hashlib.sha256(payload.encode()).hexdigest(),
            "binary_sha256": file_sha256(binary),
            "semantics": "TIR transitions decoded from immutable ELF instruction bytes",
        },
    }
    (directory / "instruction-audit.json").write_text(json.dumps(audit_document, indent=2) + "\n")
    return trace_path, trace, audit_document


def wait_for_file(path: Path, process: subprocess.Popen, timeout: float = 180.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if process.poll() is not None:
            raise RuntimeError(f"validator exited before terminal readiness: {process.returncode}")
        if time.monotonic() >= deadline:
            raise TimeoutError("terminal readiness timed out")
        time.sleep(0.01)


def validate_report(document: dict, *, mismatch: bool, terminal_pc: int) -> None:
    expected_status = "mismatch" if mismatch else "accepted"
    if document.get("status") != expected_status:
        raise ValueError(f"expected {expected_status}, got {document.get('status')}")
    if not document["completion"]["complete"] or not document["completion"]["execution_complete"]:
        raise ValueError("whole-program terminal evidence is incomplete")
    if document["completion"]["scope"] != TraceScope.WHOLE_PROGRAM.value:
        raise ValueError("whole-program scope was not retained")
    if document["trace"]["terminal_pc"] != terminal_pc:
        raise ValueError("terminal cutpoint was not bound")
    errors = [error for entry in document["validation"]["entries"] for error in entry["errors"]]
    if mismatch:
        if len(errors) != 1 or errors[0].get("severity") != "confirmed" or errors[0].get("subject") != "X0":
            raise ValueError(f"expected one confirmed localized X0 mismatch, got {errors}")
    elif errors:
        raise ValueError(f"fixed execution produced errors: {errors}")


def run_case(args, binary: Path, trace_path: Path, trace, directory: Path, *, mismatch: bool):
    directory.mkdir()
    identity = launch_identity(binary)
    terminal_pc = trace.completion.final_pc
    fixture = json.loads((args.fixture / "manifest.json").read_text())
    witness = fixture["witness_return"]
    socket_path = directory / "plugin.sock"
    ready_path, evidence_path = directory / "terminal-ready.json", directory / "terminal-evidence.json"
    report_path = directory / "report.json"
    qemu_path = args.qemu_injected if mismatch else args.qemu_fixed
    plugin_path = args.plugin_injected if mismatch else args.plugin_fixed
    addresses = trace.require_addresses()
    text_start = min(addresses)
    # Bound symbolic DAG depth without inserting a callback inside callme's
    # optimizer-sensitive instruction chain. Address cutpoints naturally recur
    # on loops and therefore also bound repeated dynamic paths.
    periodic = {
        address for address in addresses
        if not fixture["callme"] < address < fixture["callme_stop"]
    }
    cutpoints = tuple(sorted(periodic | {trace.env.start_address, witness, terminal_pc}))
    text_stop = max((*addresses, terminal_pc))
    plugin = plugin_option(plugin_path, socket_path, identity, text_start,
                           text_stop, coarse=True, cutpoints=cutpoints)
    qemu_command = [qemu_path, "-cpu", "max,sve=off", "-plugin", plugin, str(binary)]
    cutpoint_set = set(cutpoints) | {text_start, text_stop}
    dynamic_cutpoints = [
        address for address in (*addresses, terminal_pc) if address in cutpoint_set
    ]
    if not dynamic_cutpoints or dynamic_cutpoints[0] != trace.env.start_address \
            or dynamic_cutpoints[-1] != terminal_pc:
        raise RuntimeError("dynamic cutpoints do not bind entry and terminal boundaries")
    validator_command = [
        args.validator, "--use-socket", str(socket_path), "--guest-arch", "aarch64l",
        "--symb-trace", str(trace_path), "--report", str(report_path),
        "--output", str(directory / "states.json"),
        "--plugin-terminal-ready", str(ready_path),
        "--plugin-terminal-evidence", str(evidence_path),
    ]
    for address in dynamic_cutpoints:
        validator_command.extend(("--cutpoint-address", hex(address)))
    (directory / "commands.json").write_text(json.dumps(
        {"qemu": qemu_command, "validator": validator_command, "environment": [],
         "cpu_profile": CPU_PROFILE, "cutpoint_count": len(cutpoints)}, indent=2) + "\n")
    with (directory / "validator.log").open("wb") as validator_log, (
        directory / "qemu.stdout"
    ).open("wb") as qemu_stdout, (directory / "qemu.stderr").open("wb") as qemu_stderr:
        validator = subprocess.Popen(validator_command, env={}, stdout=validator_log,
                                     stderr=subprocess.STDOUT)
        wait_for_file(socket_path, validator)
        qemu = subprocess.Popen(qemu_command, env={}, stdout=qemu_stdout, stderr=qemu_stderr)
        wait_for_file(ready_path, validator)
        binding = json.loads(ready_path.read_text())
        qemu_status = qemu.wait(timeout=30)
        evidence_path.write_text(json.dumps({
            "schema": "focaccia-plugin-terminal-evidence-v1",
            "nonce": binding["nonce"], "pid": binding["pid"],
            "binarySha256": binding["binarySha256"], "returncode": qemu_status,
        }, sort_keys=True) + "\n")
        validator_status = validator.wait(timeout=30)
    expected_guest_status = 1 if mismatch else 0
    if qemu_status != expected_guest_status:
        raise RuntimeError(
            f"guest did not naturally exit {expected_guest_status}: {qemu_status}"
        )
    expected_validator_status = 1 if mismatch else 0
    if validator_status != expected_validator_status:
        raise RuntimeError(f"validator exit {validator_status}, expected {expected_validator_status}")
    document = json.loads(report_path.read_text())
    validate_report(document, mismatch=mismatch, terminal_pc=terminal_pc)
    return {
        "status": document["status"], "validator_exit_status": validator_status,
        "guest_exit_status": qemu_status, "terminal_evidence": "complete",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--oracle", required=True)
    parser.add_argument("--qemu-fixed", required=True)
    parser.add_argument("--qemu-injected", required=True)
    parser.add_argument("--plugin-fixed", required=True)
    parser.add_argument("--plugin-injected", required=True)
    parser.add_argument("--gdb")  # Retained CLI compatibility; never used.
    parser.add_argument("--validator", required=True)
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
        discovery_dir = root / "discovery-fixed"
        discovery_dir.mkdir()
        discovery = discover_execution(binary, args.qemu_fixed, args.plugin_fixed, discovery_dir)
        trace_path, trace, audit = generate_reference(
            binary, discovery, args.oracle, root, expected_exit=0
        )
        injected_discovery_dir = root / "discovery-injected"
        injected_discovery_dir.mkdir()
        injected_discovery = discover_logged_execution(
            binary, args.qemu_injected, injected_discovery_dir, discovery
        )
        injected_oracle_dir = root / "oracle-injected"
        injected_oracle_dir.mkdir()
        injected_trace_path, injected_trace, injected_audit = generate_reference(
            binary, injected_discovery, args.oracle, injected_oracle_dir, expected_exit=1
        )
        if set(audit["classes"]) != set(injected_audit["classes"]):
            raise ValueError("fixed and injected paths execute different instruction classes")
        assert trace.completion is not None
        manifest = {
            "schema": 2, "scope": "whole-program", "binary": str(binary),
            "binary_sha256": file_sha256(binary), "main_sha256": fixture["main_sha256"],
            "callme_sha256": fixture["callme_sha256"], "entry": entry,
            "terminal_pc": trace.completion.final_pc, "transform_count": len(trace),
            "oracle_sha256": file_sha256(trace_path),
            "injected_oracle_sha256": file_sha256(injected_trace_path),
            "path_oracles": {
                "fixed": audit["path_provenance"],
                "injected": injected_audit["path_provenance"],
            },
            "tir_revision": args.tir_revision,
            "qemu_revision": args.qemu_revision, "argv": [], "environment": [],
            "cpu_profile": CPU_PROFILE, "instruction_audit": audit,
            "record_replay": False, "miasm_semantics": False,
            "synthetic_state_mutation": False,
        }
        (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        cases = {
            "fixed": run_case(args, binary, trace_path, trace, root / "fixed", mismatch=False),
            "injected": run_case(
                args, binary, injected_trace_path, injected_trace,
                root / "injected", mismatch=True
            ),
        }
        result = {"schema": 2, "status": "passed", "scope": "whole-program", "cases": cases}
        (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
    except BaseException as error:
        (root / "result.json").write_text(json.dumps(
            {"schema": 2, "status": "failed", "error": str(error)}, indent=2
        ) + "\n")
        raise


if __name__ == "__main__":
    main()
