"""Bounded offline cost probe. Fixture LLDB answers come from retained oracle text.

No debugger/target execution. This measures CPU and reuse, NOT live transport.
The input frames must be the retained systematic 512-record sample.
"""

import argparse
import hashlib
import json
import platform
import signal
import time
from pathlib import Path
from typing import cast

from miasm.analysis.binary import Container
from miasm.core.locationdb import LocationDB

import focaccia.native.tracer as native_tracer
import focaccia.persistence as persistence
from focaccia.native.lldb_target import LLDBConcreteTarget
from focaccia.native.tracer import _DisassemblyVerificationCache, _disassemble_instruction
from focaccia.snapshot import ReadableProgramState
from focaccia.symbolic import DisassemblyContext, Instruction


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frames", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    signal.alarm(180)
    selection = json.loads(args.selection.read_text())
    indices = selection["sample_indices"]
    if len(indices) != 512 or indices != [i * selection["item_count"] // 512 for i in range(512)]:
        raise ValueError("Expected exact systematic 512 selection")
    records = []
    with args.frames.open("rb") as stream:
        while (
            frame := persistence._read_msgpack_frame(stream, "sample", allow_eof=True)
        ) is not None:
            if not isinstance(frame, dict):
                raise ValueError("Sample frame must be an object")
            records.append(frame["item"])
    if len(records) != 512:
        raise ValueError("Expected 512 sample records")
    arch = persistence._architecture_from_id(records[0]["arch"], "arch")
    decode_cache = persistence._TransformDecodeCache.bounded()
    transforms = [
        persistence._validate_transform_document(
            record, arch, "sample", legacy=False, decode_cache=decode_cache
        )
        for record in records
    ]
    instructions = [transform.instructions[0] for transform in transforms]
    fixture = {instruction.addr: instruction for instruction in instructions}
    with args.binary.open("rb") as stream:
        image = Container.from_stream(stream, LocationDB())

    class OfflineTarget:
        def __init__(self):
            self.arch = arch
            self.counts = {}

        def bump(self, name):
            self.counts[name] = self.counts.get(name, 0) + 1

        def read_instructions(self, addr, size):
            self.bump("byte_reads")
            return image.bin_stream.getbytes(addr, size)

        def get_instruction_size(self, pc):
            self.bump("fixture_size_queries")
            return fixture[pc].length

        def get_disassembly(self, pc):
            self.bump("fixture_text_queries")
            return str(fixture[pc])

    original = Instruction.to_bytecode
    target = OfflineTarget()

    def counted(instruction):
        target.bump("assemblies")
        return original(instruction)

    setattr(Instruction, "to_bytecode", counted)
    backend = cast(LLDBConcreteTarget, target)
    ctx = DisassemblyContext(cast(ReadableProgramState, target))
    results = {
        "sample_count": 512,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "tracer_sha256": hashlib.sha256(Path(native_tracer.__file__).read_bytes()).hexdigest(),
        "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "unique_pcs": len(fixture),
        "sample_indices": indices,
        "selection": "systematic floor(i*N/512); warm repeats same 512 sample, not full-trace hit rate",
        "limitations": "real ELF bytes; fallback text/size are oracle fixtures, not LLDB observations or transport",
        "hashes": {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in [
                ("frames", args.frames),
                ("binary", args.binary),
                ("selection", args.selection),
            ]
        },
        "runs": [],
    }
    expected = None

    def measure(label, cache):
        nonlocal expected
        target.counts = {}
        wall, cpu = time.perf_counter(), time.process_time()
        decoded = [
            _disassemble_instruction(ctx, backend, instruction.addr, cache)
            for instruction in instructions
        ]
        timing = {"wall": time.perf_counter() - wall, "cpu": time.process_time() - cpu}
        signature = [(i.addr, i.length, str(i), tuple(i.instr.args)) for i in decoded]
        if expected is None:
            expected = signature
        if signature != expected:
            raise ValueError("Caching changed decoded output")
        row = {"stage": label, **timing, **target.counts}
        results["runs"].append(row)
        print(json.dumps(row), flush=True)

    for trial in range(3):
        cache = _DisassemblyVerificationCache(ctx, backend)
        if trial % 2 == 0:
            measure("uncached", None)
        measure("cold-cache", cache)
        measure("warm-cache", cache)
        if trial % 2:
            measure("uncached", None)
    args.output.write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
