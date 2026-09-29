"""Live bounded #2248 TIR/QEMU validation without native capture or RR."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import select
import struct
import subprocess
import sys
import tempfile
import time

from focaccia.arch.aarch64 import ArchAArch64
from focaccia.completion import TraceScope
from focaccia.parser import parse_snapshots, serialize_transformations
from focaccia.snapshot import ProgramState
from focaccia.symbolic import DisassemblyContext, SymbolicTransform
from focaccia.tir_backend import TirBackend
from focaccia.trace import MaterializedTrace, TraceEnvironment

EXPECTED_CODE = bytes.fromhex(
    "5f0003eb"  # cmp x2, x3
    "eca79f9a"  # cset x12, lt
    "8b1d0012"  # and w11, w12, #0xff
    "7f010071"  # cmp w11, #0
    "ee039fda"  # csetm x14, ne
    "cd25c49a"  # lsr x13, x14, x4
    "a01d4093"  # sxtb x0, w13
)
MASK64 = (1 << 64) - 1


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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
        raise ValueError("invalid issue-2248 witness bounds")
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
            raise ValueError("dynamic interpreter is outside the fixture scope")
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
                raise ValueError("witness must be in read-only executable file-backed bytes")
            matching.append(data[file_offset + start - address : file_offset + stop - address])
    if len(matching) != 1:
        raise ValueError("witness must have one unambiguous ELF load mapping")
    return matching[0]


def generate_reference(binary: Path, start: int, stop: int, oracle: str):
    code = read_region(binary.read_bytes(), start, stop)
    if code != EXPECTED_CODE or stop - start != 7 * 4:
        raise ValueError("fixture is not the exact seven-instruction issue-2248 witness")
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
            raise ValueError("issue-2248 requires straight-line TIR transitions")
        transforms.append(SymbolicTransform(1, outputs, [instruction], arch, pc, pc + 4))
    env = TraceEnvironment(
        str(binary), (), (), start_address=start, stop_address=stop, architecture=arch.key
    )
    return MaterializedTrace(transforms, env, range(start, stop, 4), scope=TraceScope.WITNESS)


class PrivateGdbSocket:
    """Private local IPC, with event-driven readiness and no probe connection."""

    def __enter__(self):
        self.directory = tempfile.TemporaryDirectory(prefix="tir-2248-gdb-", dir="/tmp")
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
        deadline = time.monotonic() + timeout
        while not self.path.is_socket():
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.fd], [], [], remaining)[0]:
                raise TimeoutError("QEMU did not create its debugger socket")
            os.read(self.fd, 65536)

    def __exit__(self, *_args):
        os.close(self.fd)
        self.directory.cleanup()


def validate_report(document: dict, *, stop: int, mismatch: bool, coarse: bool) -> None:
    if document.get("schema") != "focaccia-qemu-validation-v1":
        raise ValueError("unexpected validation report schema")
    expected_status = "mismatch" if mismatch else "accepted"
    if document.get("status") != expected_status:
        raise ValueError(f"expected {expected_status}, got {document.get('status')}")
    count = 1 if coarse else 7
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
        raise ValueError("record/replay unexpectedly participated")
    if document["completion"]["scope"] != TraceScope.WITNESS.value:
        raise ValueError("bounded witness was misclassified")
    validation = document["validation"]
    diagnostics = validation["diagnostics"]
    if validation["entry_count"] != count:
        raise ValueError("missing validation transitions")
    if coarse:
        expected_diagnostic = {
            "level": "info",
            "code": "symbolic-transforms-composed",
            "concrete_index": 1,
            "transform_index": 0,
        }
        if len(diagnostics) != 1 or any(
            diagnostics[0].get(key) != value for key, value in expected_diagnostic.items()
        ):
            raise ValueError("missing coarse-composition evidence")
    elif diagnostics:
        raise ValueError("unexpected granular diagnostics")
    errors = [error for entry in validation["entries"] for error in entry["errors"]]
    if mismatch:
        if len(errors) != 1 or errors[0].get("severity") != "confirmed" or errors[0].get(
            "subject"
        ) != "X0":
            raise ValueError(f"expected one confirmed X0 mismatch, got {errors}")
    elif errors:
        raise ValueError(f"accepted execution produced errors: {errors}")
    if any(error.get("severity") in ("possible", "incomplete") for error in errors):
        raise ValueError("validation retained uncertain errors")


def _run_case(
    args, binary, trace_path, directory, start, stop, *, qemu_path, plugin_path, coarse, mismatch
):
    report_path = directory / "report.json"
    with PrivateGdbSocket() as channel:
        common = [
            "--symb-trace", str(trace_path),
            "--report", str(report_path),
            "--output", str(directory / "states.json"),
        ]
        if coarse:
            # Only source and destination callbacks are installed. There is no
            # debugger, breakpoint, or per-instruction transaction in the TB.
            plugin = (
                f"{plugin_path},socket={channel.path},start={start},stop={stop},coarse=on"
            )
            qemu_command = [qemu_path, "-plugin", plugin, str(binary)]
            validate_command = [
                args.validator, "--use-socket", str(channel.path),
                "--guest-arch", "aarch64l", "--cutpoint-address", hex(stop), *common,
            ]
        else:
            # Intentional negative control: GDB single-steps all seven
            # instructions, which suppresses the optimizer chain in bad QEMU.
            qemu_command = [qemu_path, "-g", str(channel.path), str(binary)]
            validate_command = [
                args.validator, "--gdb", args.gdb, "--remote", str(channel.path),
                "--executable", str(binary), *common,
            ]
        (directory / "commands.json").write_text(
            json.dumps({"qemu": qemu_command, "validator": validate_command}, indent=2) + "\n"
        )
        print(f"Running {directory.name}", flush=True)
        qemu = None
        validator = None
        try:
            with (directory / "qemu.log").open("w") as qemu_log, (
                directory / "validator.log"
            ).open("w") as validator_log:
                if coarse:
                    validator = subprocess.Popen(
                        validate_command, stdout=validator_log, stderr=subprocess.STDOUT
                    )
                    channel.wait_ready()
                    qemu = subprocess.Popen(
                        qemu_command, stdout=qemu_log, stderr=subprocess.STDOUT
                    )
                    validator_status = validator.wait(timeout=90)
                else:
                    qemu = subprocess.Popen(
                        qemu_command, stdout=qemu_log, stderr=subprocess.STDOUT
                    )
                    channel.wait_ready()
                    validator_status = subprocess.run(
                        validate_command,
                        stdout=validator_log,
                        stderr=subprocess.STDOUT,
                        timeout=90,
                        check=False,
                    ).returncode
            if validator_status != 0:
                raise RuntimeError(f"validator failed with exit {validator_status}")
            document = json.loads(report_path.read_text())
            validate_report(document, stop=stop, mismatch=mismatch, coarse=coarse)
            with (directory / "states.json").open() as stream:
                snapshots = parse_snapshots(stream)
            if len(snapshots) != (2 if coarse else 8):
                raise ValueError("unexpected concrete state cardinality")
            after = snapshots[-1]
            for name, value in {"X2": 0, "X3": 1, "X4": 2}.items():
                observed = next(
                    (state.read_register(name) for state in snapshots if state.test_register(name)),
                    None,
                )
                if observed != value:
                    raise ValueError(f"unexpected or unavailable fixture input {name}")
            actual_x0 = after.read_register("X0")
            if mismatch:
                if actual_x0 == MASK64:
                    raise ValueError("injected coarse execution did not reproduce #2248")
            elif actual_x0 != MASK64:
                raise ValueError(f"accepted execution produced X0={actual_x0:#x}")
            exit_status = qemu.wait(timeout=10)
            if exit_status != 0:
                raise RuntimeError(f"guest lifecycle failed after detach: {exit_status}")
            return {
                "status": document["status"],
                "backend": "plugin" if coarse else "gdb",
                "mode": "coarse" if coarse else "granular",
                "transitions": 1 if coarse else 7,
                "states": 2 if coarse else 8,
                "x0": hex(actual_x0),
                "guest_exit_status": exit_status,
            }
        except BaseException:
            for name in ("qemu.log", "validator.log", "report.json"):
                path = directory / name
                if path.exists():
                    print(f"--- {path} ---\n{path.read_text(errors='replace')[-20000:]}", file=sys.stderr)
            raise
        finally:
            for process in (validator, qemu):
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


def run_case(args, binary, trace_path, directory, start, stop, **options):
    directory.mkdir()
    return _run_case(args, binary, trace_path, directory, start, stop, **options)


def qemu_identity(path: str, plugin_path: str, *, injected: bool) -> dict:
    executable = Path(path).resolve()
    plugin = Path(plugin_path).resolve()
    return {
        "path": str(executable),
        "sha256": file_sha256(executable),
        "plugin_path": str(plugin),
        "plugin_sha256": file_sha256(plugin),
        "version": subprocess.check_output([path, "--version"], text=True).splitlines()[0],
        "regression_injected": injected,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--oracle", required=True)
    parser.add_argument("--qemu-fixed", required=True)
    parser.add_argument("--qemu-injected", required=True)
    parser.add_argument("--plugin-fixed", required=True)
    parser.add_argument("--plugin-injected", required=True)
    parser.add_argument("--gdb", required=True)
    parser.add_argument("--validator", required=True)
    parser.add_argument("--tir-revision", required=True)
    parser.add_argument("--qemu-revision", required=True)
    parser.add_argument("--run-directory", required=True, type=Path)
    args = parser.parse_args()
    root = args.run_directory.resolve()
    root.mkdir(parents=True, exist_ok=False)
    try:
        binary = (args.fixture / "program.elf").resolve()
        fixture_manifest = json.loads((args.fixture / "manifest.json").read_text())
        digest = file_sha256(binary)
        if fixture_manifest.get("schema") != 1 or digest != fixture_manifest.get("sha256"):
            raise ValueError("fixture manifest mismatch")
        start, stop = fixture_manifest["start"], fixture_manifest["stop"]
        reference = generate_reference(binary, start, stop, args.oracle)
        trace_path = root / "oracle.json"
        serialize_transformations(reference, trace_path)
        identities = {
            "fixed": qemu_identity(args.qemu_fixed, args.plugin_fixed, injected=False),
            "injected": qemu_identity(
                args.qemu_injected, args.plugin_injected, injected=True
            ),
        }
        plan = {
            "schema": 1,
            "binary": str(binary),
            "binary_sha256": digest,
            "source_sha256": fixture_manifest["source_sha256"],
            "wrapper_sha256": fixture_manifest["wrapper_sha256"],
            "oracle_sha256": file_sha256(trace_path),
            "start": start,
            "stop": stop,
            "instruction_count": len(reference),
            "instruction_bytes": EXPECTED_CODE.hex(),
            "scope": "witness",
            "semantics": "ASL/TIR derived directly from exact ELF bytes",
            "tir_revision": args.tir_revision,
            "qemu_revision": args.qemu_revision,
            "qemu": identities,
            "native_capture": False,
            "record_replay": False,
            "gdb_state_injection": False,
        }
        (root / "manifest.json").write_text(json.dumps(plan, indent=2) + "\n")
        cases = {
            "fixed-granular": run_case(
                args, binary, trace_path, root / "fixed-granular", start, stop,
                qemu_path=args.qemu_fixed, plugin_path=args.plugin_fixed,
                coarse=False, mismatch=False
            ),
            "fixed-coarse": run_case(
                args, binary, trace_path, root / "fixed-coarse", start, stop,
                qemu_path=args.qemu_fixed, plugin_path=args.plugin_fixed,
                coarse=True, mismatch=False
            ),
            "injected-granular": run_case(
                args, binary, trace_path, root / "injected-granular", start, stop,
                qemu_path=args.qemu_injected, plugin_path=args.plugin_injected,
                coarse=False, mismatch=False
            ),
            "injected-coarse": run_case(
                args, binary, trace_path, root / "injected-coarse", start, stop,
                qemu_path=args.qemu_injected, plugin_path=args.plugin_injected,
                coarse=True, mismatch=True
            ),
        }
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
