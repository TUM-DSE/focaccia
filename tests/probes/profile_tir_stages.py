"""Profile specialization on code from an existing validation artifact.

This development probe executes only the specification oracle. It never launches
QEMU, discovers a validation path, or supplies expected output from a trace.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import struct
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle", required=True)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=512)
    parser.add_argument("--class-cache", type=int, default=0)
    args = parser.parse_args()
    data = args.binary.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 183:
        raise ValueError("requires little-endian AArch64 ELF64")
    if not 1 <= args.limit <= 100000 or not 0 <= args.class_cache <= 64:
        raise ValueError("invalid profiling limits")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    segments = []
    for index in range(count):
        kind, flags, offset, address, _, length, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + size * index
        )
        if kind == 1 and flags & 1:
            segments.append((address, data[offset:offset + length]))
    instructions = {}
    for block in json.loads(args.report.read_text())["blocks"]:
        for pc in range(block["first_pc"], block["last_pc"] + 1, 4):
            matches = [raw[pc-base:pc-base+4] for base, raw in segments
                       if base <= pc and pc + 4 <= base + len(raw)]
            if len(matches) != 1:
                raise ValueError("code does not belong to one executable segment")
            raw = matches[0]
            if int.from_bytes(raw, "little") & 0xFFE0001F == 0xD4000001:
                continue  # The harness treats SVC as an action boundary.
            instructions.setdefault(pc, raw)
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("TIR_", "TIRAMISU_", "FOCACCIA_TIR_MODULE"))}
    env.update(FOCACCIA_ORACLE_PROFILE="1", FOCACCIA_ORACLE_CLASS_CACHE=str(args.class_cache))
    rows = []
    started = time.monotonic()
    with tempfile.TemporaryFile() as error_log:
        process = subprocess.Popen([args.oracle, "--export-transitions"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=error_log, env=env)
        try:
            for pc, raw in list(instructions.items())[:args.limit]:
                process.stdin.write(f"{pc} {raw.hex()}\n".encode())
                process.stdin.flush()
                if not select.select([process.stdout], [], [], 60)[0]:
                    raise TimeoutError("oracle response timeout")
                line = process.stdout.readline(8 * 1024 * 1024 + 1)
                if not line.endswith(b"\n") or len(line) > 8 * 1024 * 1024:
                    raise ValueError("missing or oversized oracle response")
                response = json.loads(line)
                if response["status"] != "ok":
                    raise ValueError(f"unsupported at {pc:#x}: {response.get('reason')}")
                digest = hashlib.sha256(json.dumps(response, sort_keys=True).encode()).hexdigest()
                rows.append(dict(pc=pc, instruction=raw.hex(), response_sha256=digest))
            process.stdin.close()
            if process.wait(timeout=30) != 0:
                raise RuntimeError("oracle failed")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
            if not process.stdin.closed:
                process.stdin.close()
        error_log.seek(0)
        logs = error_log.read().decode()
    profiles = [json.loads(line.removeprefix("FOCACCIA_ORACLE_PROFILE "))
                for line in logs.splitlines() if line.startswith("FOCACCIA_ORACLE_PROFILE ")]
    if len(profiles) != 1:
        raise ValueError("expected one aggregate stage profile")
    result = dict(seconds=time.monotonic()-started, profile=profiles[0],
                  class_cache=args.class_cache, instructions=rows)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k:v for k,v in result.items() if k != "instructions"}, indent=2), flush=True)


if __name__ == "__main__":
    main()
