"""Live, bounded TIR/QEMU validation without native capture or record/replay.

The independent reference is generated from executable ELF bytes through TIR.
QEMU supplies only observed states. Setup and process exit are outside the
validated witness; the injected case deliberately corrupts a final guest flag.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import select
import struct
import tempfile
import time
import subprocess
import sys

from focaccia.arch.aarch64 import ArchAArch64
from focaccia.completion import TraceScope
from focaccia.parser import parse_snapshots, serialize_transformations
from focaccia.snapshot import ProgramState
from focaccia.symbolic import DisassemblyContext, SymbolicTransform
from focaccia.tir_backend import TirBackend
from focaccia.trace import MaterializedTrace, TraceEnvironment


def read_region(data: bytes, start: int, stop: int) -> bytes:
    """Read one bounded file-backed executable region of a static AArch64 ELF."""
    if (
        type(start) is not int
        or type(stop) is not int
        or start < 0
        or stop <= start
        or stop >= 1 << 64
        or start % 4
        or stop % 4
        or stop - start > 4096
    ):
        raise ValueError("invalid arithmetic witness bounds")
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("expected little-endian ELF64")
    if struct.unpack_from("<HHI", data, 16) != (2, 183, 1):
        raise ValueError("expected static ET_EXEC AArch64 ELF")
    offset = struct.unpack_from("<Q", data, 32)[0]
    header_size, entry_size, count = struct.unpack_from("<HHH", data, 52)
    if (
        header_size != 64
        or entry_size != 56
        or not 1 <= count <= 256
        or offset < 64
        or offset + entry_size * count > len(data)
    ):
        raise ValueError("invalid ELF program headers")
    matching = []
    for index in range(count):
        kind, flags, file_offset, address, _, file_size, memory_size, _ = struct.unpack_from(
            "<IIQQQQQQ", data, offset + entry_size * index
        )
        if kind == 3:
            raise ValueError("dynamic interpreter is outside the smoke fixture scope")
        if kind != 1:
            continue
        if (
            file_size > memory_size
            or file_offset + file_size > len(data)
            or address + memory_size > 1 << 64
        ):
            raise ValueError("invalid ELF load segment")
        if start < address + memory_size and address < stop:
            if flags & 7 != 5 or start < address or stop > address + file_size:
                raise ValueError(
                    "witness must be wholly inside read-only executable file-backed bytes"
                )
            matching.append(data[file_offset + start - address : file_offset + stop - address])
    if len(matching) != 1:
        raise ValueError("witness must have one unambiguous ELF load mapping")
    return matching[0]


def generate_reference(binary: Path, start: int, stop: int, oracle: str):
    image = binary.read_bytes()
    code = read_region(image, start, stop)
    arch = ArchAArch64("little")
    state = ProgramState(arch)
    state.write_memory(start, code)
    context = DisassemblyContext(state)
    backend = TirBackend(oracle)
    transforms = []
    for pc in range(start, stop, 4):
        state.write_register("PC", pc)
        instruction = context.disassemble(pc)
        next_pc, outputs = backend.generate(instruction, state, context)
        if next_pc is None or int(next_pc) != pc + 4:
            raise ValueError("smoke reference requires straight-line instruction transitions")
        transforms.append(SymbolicTransform(1, outputs, [instruction], arch, pc, pc + 4))
    env = TraceEnvironment(
        str(binary), (), (), start_address=start, stop_address=stop, architecture=arch.key
    )
    return MaterializedTrace(transforms, env, range(start, stop, 4), scope=TraceScope.WITNESS)


class PrivateGdbSocket:
    """Private local IPC, with event-driven readiness and no probe connection."""

    def __enter__(self):
        # Short pathname for sockaddr_un; TemporaryDirectory is owner-only (0700).
        self.directory = tempfile.TemporaryDirectory(prefix="tir-gdb-", dir="/tmp")
        self.path = Path(self.directory.name) / "gdb.sock"
        libc = ctypes.CDLL(None, use_errno=True)
        libc.inotify_init1.argtypes = [ctypes.c_int]
        libc.inotify_init1.restype = ctypes.c_int
        libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        libc.inotify_add_watch.restype = ctypes.c_int
        self.fd = libc.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
        if self.fd < 0:
            self.directory.cleanup()
            raise OSError(ctypes.get_errno(), "cannot watch debugger socket directory")
        if libc.inotify_add_watch(self.fd, os.fsencode(self.directory.name), 0x100) < 0:
            error = ctypes.get_errno()
            os.close(self.fd)
            self.directory.cleanup()
            raise OSError(error, "cannot watch debugger socket creation")
        return self

    def wait_ready(self, timeout: float = 20.0) -> None:
        # Connecting as a readiness probe would consume QEMU's GDB connection.
        # Watch the bind-created filesystem entry instead, before launching GDB.
        deadline = time.monotonic() + timeout
        while not self.path.is_socket():
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.fd], [], [], remaining)[0]:
                raise TimeoutError("QEMU did not create its debugger socket")
            os.read(self.fd, 65536)

    def __exit__(self, *_args):
        os.close(self.fd)
        self.directory.cleanup()


def validate_report(
    document: dict, *, stop: int, count: int, injected: bool, coarse: bool = False
) -> None:
    if document.get("schema") != "focaccia-qemu-validation-v1":
        raise ValueError("unexpected validation report schema")
    expected = "mismatch" if injected else "accepted"
    if document.get("status") != expected:
        raise ValueError(f"expected {expected}, got {document.get('status')}")
    trace = document["trace"]
    if (
        not trace["complete"]
        or not trace["terminal_reached"]
        or trace["terminal_pc"] != stop
        or trace["transform_count"] != count
        or trace["state_count"] != count + 1
    ):
        raise ValueError(f"incomplete witness observations: {trace}")
    if document["replay"]["active"] or document["replay"]["record_count"]:
        raise ValueError("record/replay unexpectedly participated in the smoke")
    if document["completion"]["scope"] != TraceScope.WITNESS.value:
        raise ValueError("bounded witness was misclassified as whole-program validation")
    validation = document["validation"]
    diagnostics = validation["diagnostics"]
    if validation["entry_count"] != count:
        raise ValueError("missing validation transitions")
    if coarse:
        if (
            len(diagnostics) != 1
            or diagnostics[0].get("level") != "info"
            or diagnostics[0].get("code") != "symbolic-transforms-composed"
            or diagnostics[0].get("concrete_index") != 1
            or diagnostics[0].get("transform_index") != 0
        ):
            raise ValueError("missing composition evidence or unexpected diagnostics")
    elif diagnostics:
        raise ValueError("unexpected validation diagnostics")
    errors = [error for entry in validation["entries"] for error in entry["errors"]]
    if injected:
        if not any(e["severity"] == "confirmed" and e["subject"] in ("C", "CPSR") for e in errors):
            raise ValueError("injected carry mismatch was not confirmed")
        if any(e["severity"] in ("possible", "incomplete") for e in errors):
            raise ValueError("injection result has incomplete validation evidence")
    elif errors:
        raise ValueError("clean execution produced validation errors")


def _run_case(
    args,
    binary: Path,
    trace_path: Path,
    directory: Path,
    stop: int,
    count: int,
    channel: PrivateGdbSocket,
    *,
    coarse: bool,
    injected: bool,
) -> dict:
    report_path = directory / "report.json"
    marker = directory / "injection.json"
    environment = dict(os.environ)
    environment.pop("FOCACCIA_SMOKE_INJECT_PC", None)
    environment.pop("FOCACCIA_SMOKE_INJECT_MARKER", None)
    if injected:
        environment["FOCACCIA_SMOKE_INJECT_PC"] = hex(stop)
        environment["FOCACCIA_SMOKE_INJECT_MARKER"] = str(marker)
    qemu_command = [args.qemu, "-g", str(channel.path), str(binary)]
    validate_command = [
        args.validator,
        "--gdb",
        args.gdb,
        "--symb-trace",
        str(trace_path),
        "--remote",
        str(channel.path),
        "--executable",
        str(binary),
        "--report",
        str(report_path),
        "--output",
        str(directory / "states.json"),
    ]
    if coarse:
        validate_command += ["--cutpoint-address", hex(stop)]
    (directory / "commands.json").write_text(
        json.dumps(
            {
                "qemu": qemu_command,
                "validator": validate_command,
                "injection": (
                    {"pc": stop, "register": "CPSR", "mask": 1 << 29} if injected else None
                ),
            },
            indent=2,
        )
        + "\n"
    )
    print(f"Running {directory.name}", flush=True)
    with (directory / "qemu.log").open("w") as qemu_log:
        qemu = subprocess.Popen(qemu_command, stdout=qemu_log, stderr=subprocess.STDOUT)
        try:
            channel.wait_ready()
            with (directory / "validator.log").open("w") as log:
                result = subprocess.run(
                    validate_command,
                    env=environment,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=90,
                    check=False,
                )
            if result.returncode != 0:
                raise RuntimeError(f"validator failed with exit {result.returncode}")
            document = json.loads(report_path.read_text())
            validate_report(document, stop=stop, count=count, injected=injected, coarse=coarse)
            if coarse:
                # Independently check the fixture's concrete arithmetic results,
                # including the upper half of the 32-bit destination write.
                with (directory / "states.json").open() as stream:
                    snapshots = parse_snapshots(stream)
                before, after = snapshots
                for name, value in {"X0": (1 << 64) - 1, "W1": 0x7FFFFFFF, "X2": 0}.items():
                    if before.read_register(name) != value:
                        raise ValueError(f"unexpected fixture input {name}")
                expected = {
                    "X0": 0,
                    "X1": 0x80000000,
                    "X2": (1 << 64) - 1,
                    "X3": 1,
                    "N": 0,
                    "Z": 1,
                    "C": int(not injected),
                    "V": 0,
                }
                for name, value in expected.items():
                    if after.read_register(name) != value:
                        raise ValueError(f"unexpected live fixture result {name}")
            if injected:
                evidence = json.loads(marker.read_text())
                if (
                    evidence["schema"] != 1
                    or evidence["pc"] != stop
                    or evidence["register"] != "CPSR"
                    or evidence["mask"] != 1 << 29
                    or evidence["before"] ^ evidence["after"] != 1 << 29
                ):
                    raise ValueError("missing or invalid live-injection evidence")
            elif marker.exists():
                raise ValueError("unexpected injection in clean execution")
            # The GDB wrapper detaches after validation, allowing the fixture's
            # unvalidated exit sequence to complete. Its exit is lifecycle
            # evidence, not a whole-program validation claim.
            exit_status = qemu.wait(timeout=10)
            if exit_status != 0:
                raise RuntimeError(f"guest did not exit cleanly after detach: {exit_status}")
            return {
                "status": document["status"],
                "scope": "witness",
                "transitions": count,
                "guest_exit_status": exit_status,
                "injected": injected,
            }
        except BaseException:
            for name in ("qemu.log", "validator.log", "report.json"):
                path = directory / name
                if path.exists():
                    print(
                        f"--- {path} ---\n{path.read_text(errors='replace')[-20000:]}",
                        file=sys.stderr,
                    )
            raise
        finally:
            if qemu.poll() is None:
                qemu.terminate()
                try:
                    qemu.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    qemu.kill()
                    qemu.wait(timeout=5)


def run_case(args, binary, trace_path, directory, stop, count, *, coarse, injected):
    directory.mkdir()
    with PrivateGdbSocket() as channel:
        return _run_case(
            args,
            binary,
            trace_path,
            directory,
            stop,
            count,
            channel,
            coarse=coarse,
            injected=injected,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--oracle", required=True)
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--gdb", required=True)
    parser.add_argument("--validator", required=True)
    parser.add_argument("--tir-revision", required=True)
    parser.add_argument("--run-directory", required=True, type=Path)
    args = parser.parse_args()
    root = args.run_directory.resolve()
    root.mkdir(parents=True, exist_ok=False)
    try:
        binary = (args.fixture / "program.elf").resolve()
        manifest = json.loads((args.fixture / "manifest.json").read_text())
        if manifest.get("schema") != 1:
            raise ValueError("unsupported fixture manifest schema")
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        if digest != manifest["sha256"]:
            raise ValueError("fixture executable hash mismatch")
        start, stop = manifest["start"], manifest["stop"]
        reference = generate_reference(binary, start, stop, args.oracle)
        trace_path = root / "oracle.json"
        serialize_transformations(reference, trace_path)
        plan = {
            "schema": 1,
            "binary": str(binary),
            "sha256": digest,
            "start": start,
            "stop": stop,
            "instruction_count": len(reference),
            "scope": "witness",
            "oracle": "ASL/TIR derived directly from ELF bytes",
            "tir_revision": args.tir_revision,
            "native_capture": False,
            "record_replay": False,
            "qemu_version": subprocess.check_output([args.qemu, "--version"], text=True),
        }
        (root / "manifest.json").write_text(json.dumps(plan, indent=2) + "\n")
        cases = {}
        for coarse in (False, True):
            for injected in (False, True):
                name = ("coarse" if coarse else "per-instruction") + (
                    "-injected" if injected else "-clean"
                )
                cases[name] = run_case(
                    args,
                    binary,
                    trace_path,
                    root / name,
                    stop,
                    1 if coarse else len(reference),
                    coarse=coarse,
                    injected=injected,
                )
        result = {"schema": 1, "status": "passed", "scope": "witness", "cases": cases}
        (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
    except BaseException as error:
        (root / "result.json").write_text(
            json.dumps({"schema": 1, "status": "failed", "error": str(error)}, indent=2) + "\n"
        )
        raise


if __name__ == "__main__":
    main()
