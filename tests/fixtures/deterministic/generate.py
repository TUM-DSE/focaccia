"""Regenerate the tiny synthetic RR-v85 parser fixtures.

Run only through the project flake:

    nix develop -c python tests/fixtures/deterministic/generate.py

These files are built directly from the packaged schema. They are not RR
recordings and do not execute a guest, debugger, emulator, or RR.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import brotli

from focaccia.rr.adapter import RR_SCHEMA, RR_TRACE_VERSION


ROOT = Path(__file__).resolve().parent
BLOCK_HEADER = struct.Struct("<II")
X86_REGISTERS = struct.Struct("<27Q")
AARCH64_REGISTERS = struct.Struct("<35Qi4x")


def compressed_stream(*chunks: bytes) -> bytes:
    result = bytearray()
    for chunk in chunks:
        if not chunk:
            continue
        compressed = brotli.compress(chunk)
        result.extend(BLOCK_HEADER.pack(len(compressed), len(chunk)))
        result.extend(compressed)
    return bytes(result)


def header(arch: str, uuid_byte: int) -> bytes:
    message = RR_SCHEMA.Header.new_message()
    message.uuid = bytes([uuid_byte]) * 16
    message.ok = True
    message.nativeArch = arch
    return f"{RR_TRACE_VERSION}\n".encode("ascii") + message.to_bytes_packed()


def write_fixture(name: str, arch: str, files: dict[str, bytes], uuid_byte: int) -> None:
    destination = ROOT / name
    destination.mkdir(parents=True, exist_ok=True)
    complete = {"events": b"", "data": b"", "tasks": b"", "mmaps": b"", **files}
    complete["version"] = header(arch, uuid_byte)
    for filename, data in complete.items():
        (destination / filename).write_bytes(data)


def x86_registers(**overrides: int) -> bytes:
    names = (
        "r15",
        "r14",
        "r13",
        "r12",
        "rbp",
        "rbx",
        "r11",
        "r10",
        "r9",
        "r8",
        "rax",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "orig_rax",
        "rip",
        "cs",
        "eflags",
        "rsp",
        "ss",
        "fs_base",
        "gs_base",
        "ds",
        "es",
        "fs",
        "gs",
    )
    values = {
        "r15": 15,
        "r14": 14,
        "r13": 13,
        "r12": 12,
        "rbp": 6,
        "rbx": 3,
        "r11": 11,
        "r10": 10,
        "r9": 9,
        "r8": 8,
        "rax": 0,
        "rcx": 2,
        "rdx": 4,
        "rsi": 5,
        "rdi": 7,
        "orig_rax": 0,
        "rip": 0x1002,
        "cs": 0x33,
        "eflags": 0x202,
        "rsp": 0x7FFF0000,
        "ss": 0x2B,
        "fs_base": 0x70000000,
        "gs_base": 0,
        "ds": 0,
        "es": 0,
        "fs": 0,
        "gs": 0,
    }
    values.update(overrides)
    return X86_REGISTERS.pack(*(values[name] for name in names))


def syscall_frame(
    arch: str,
    registers: bytes,
    state: str,
    number: int,
    *,
    writes: tuple[tuple[int, int, tuple[tuple[int, int], ...]], ...] = (),
) -> bytes:
    frame = RR_SCHEMA.Frame.new_message()
    frame.tid = 101
    frame.ticks = 10
    frame.monotonicSec = 1.0
    frame.arch = arch
    frame.registers.raw = registers
    raw_writes = frame.init("memWrites", len(writes))
    for raw_write, (address, size, holes) in zip(raw_writes, writes, strict=True):
        raw_write.tid = 101
        raw_write.addr = address
        raw_write.size = size
        raw_write.sizeIsConservative = False
        raw_holes = raw_write.init("holes", len(holes))
        for raw_hole, (offset, hole_size) in zip(raw_holes, holes, strict=True):
            raw_hole.offset = offset
            raw_hole.size = hole_size
    syscall = frame.event.init("syscall")
    syscall.arch = arch
    syscall.number = number
    syscall.state = state
    syscall.failedDuringPreparation = False
    syscall.extra.none = None
    return frame.to_bytes_packed()


def generic_frame(arch: str, registers: bytes | None, variant: str) -> bytes:
    frame = RR_SCHEMA.Frame.new_message()
    frame.tid = 101
    frame.ticks = 11
    frame.monotonicSec = 2.0
    frame.arch = arch
    if registers is not None:
        frame.registers.raw = registers
    setattr(frame.event, variant, None)
    return frame.to_bytes_packed()


def clone_task() -> bytes:
    task = RR_SCHEMA.TaskEvent.new_message()
    task.frameTime = 1
    task.tid = 102
    clone = task.init("clone")
    clone.parentTid = 101
    clone.flags = 0x100
    clone.ownNsTid = 2
    return task.to_bytes_packed()


def exec_task() -> bytes:
    task = RR_SCHEMA.TaskEvent.new_message()
    task.frameTime = 1
    task.tid = 101
    execute = task.init("exec")
    execute.fileName = b"/fixture/program"
    command_line = execute.init("cmdLine", 2)
    command_line[0] = b"program"
    command_line[1] = b"argument"
    execute.exeBase = 0x400000
    execute.interpBase = 0x700000
    execute.interpName = b"/fixture/loader"
    execute.pacData.raw = b"pac"
    return task.to_bytes_packed()


def exit_task() -> bytes:
    task = RR_SCHEMA.TaskEvent.new_message()
    task.frameTime = 2
    task.tid = 102
    task.init("exit").exitStatus = 7
    return task.to_bytes_packed()


def detach_task() -> bytes:
    task = RR_SCHEMA.TaskEvent.new_message()
    task.frameTime = 3
    task.tid = 101
    detach = task.init("detach")
    detach.none = None
    return task.to_bytes_packed()


def mapping(frame_time: int, start: int, source: str) -> bytes:
    mmap = RR_SCHEMA.MMap.new_message()
    mmap.frameTime = frame_time
    mmap.start = start
    mmap.end = start + 0x1000
    mmap.fsname = b"fixture"
    mmap.prot = 3
    mmap.flags = 2
    mmap.fileOffsetBytes = 0
    if source == "file":
        file_source = mmap.source.init("file")
        file_source.backingFileName = b"fixture.bin"
    else:
        setattr(mmap.source, source, None)
    return mmap.to_bytes_packed()


def build() -> None:
    write_fixture("empty-x86", "x8664", {}, 0x10)

    entering = syscall_frame(
        "x8664",
        x86_registers(rax=(1 << 64) - 38, orig_rax=0, rip=0x1002),
        "entering",
        0,
    )
    exiting = syscall_frame(
        "x8664",
        x86_registers(rax=8, orig_rax=(1 << 64) - 1, rip=0x1002),
        "exiting",
        0,
        writes=(
            (0x2000, 8, ((2, 2), (6, 1))),
            (0x3000, 4, ((0, 1),)),
        ),
    )
    scheduled = generic_frame(
        "x8664", x86_registers(rax=8, rip=0x1010), "sched"
    )
    reset = generic_frame("x8664", None, "syscallbufReset")
    write_fixture(
        "x86-syscall",
        "x8664",
        {
            "events": compressed_stream(entering, exiting + scheduled, reset),
            "data": compressed_stream(b"ABCDE", b"XYZ"),
            "tasks": compressed_stream(
                clone_task() + exec_task(),
                exit_task() + detach_task(),
            ),
            "mmaps": compressed_stream(
                mapping(1, 0x400000, "file") + mapping(1, 0x500000, "zero"),
                mapping(4, 0x600000, "trace"),
            ),
        },
        0x20,
    )

    def arm_registers(*, pc: int, x0: int, orig_x0: int, orig_syscall: int) -> bytes:
        x = list(range(31))
        x[0] = x0
        x[8] = 64
        return AARCH64_REGISTERS.pack(
            *x,
            0x7FFF0000,
            pc,
            0x600003C5,
            orig_x0,
            orig_syscall,
        )

    arm_entering = syscall_frame(
        "aarch64",
        arm_registers(pc=0x4004, x0=999, orig_x0=42, orig_syscall=64),
        "entering",
        64,
    )
    arm_exiting = syscall_frame(
        "aarch64",
        arm_registers(pc=0x4004, x0=5, orig_x0=42, orig_syscall=64),
        "exiting",
        64,
    )
    write_fixture(
        "aarch64-syscall",
        "aarch64",
        {"events": compressed_stream(arm_entering, arm_exiting)},
        0x30,
    )

    expected = {
        "format": "synthetic-rr-v85",
        "schema_id": "0xcaa0b1486c12c629",
        "x86_event_count": 4,
        "x86_known_data": ["4142", "4344", "45", "58595a"],
        "x86_holes": [[2, 2], [6, 1], [0, 1]],
        "aarch64_event_count": 2,
    }
    (ROOT / "expected.json").write_text(
        json.dumps(expected, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    build()
