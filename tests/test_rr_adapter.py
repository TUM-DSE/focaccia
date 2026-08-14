from __future__ import annotations

import shutil
import struct
from importlib import resources
from pathlib import Path
from types import SimpleNamespace

import pytest

from focaccia.arch import supported_architectures
from focaccia.deterministic import (
    CloneTask,
    DetachTask,
    DeterministicLog,
    DeterministicLogFormatError,
    ExecTask,
    ExitTask,
    SyscallEvent,
)
from focaccia.rr import adapter
from focaccia.rr.adapter import (
    RR_SCHEMA_ID,
    RR_SCHEMA_RESOURCE,
    RR_SCHEMA_VERSION,
    RR_TRACE_VERSION,
    decode_aarch64_registers,
    decode_x86_64_registers,
    read_compressed_stream,
)


FIXTURES = (Path(__file__).parent / "fixtures" / "deterministic").resolve()
X86 = supported_architectures["x86_64"]
AARCH64 = supported_architectures["aarch64l"]
BLOCK_HEADER = struct.Struct("<II")


def test_packaged_schema_and_versioned_log_are_independent_of_cwd(
    monkeypatch, tmp_path
):
    schema_package = resources.files("focaccia.rr.schemas")
    schema = schema_package.joinpath(RR_SCHEMA_RESOURCE)
    assert schema.is_file()
    assert schema_package.joinpath("RR-LICENSE").is_file()
    monkeypatch.chdir(tmp_path)

    log = DeterministicLog(FIXTURES / "empty-x86")

    assert log.events() == ()
    assert log.tasks() == ()
    assert log.mmaps() == ()
    assert log.metadata is not None
    assert log.metadata.trace_version == RR_TRACE_VERSION
    assert log.metadata.schema_version == RR_SCHEMA_VERSION
    assert log.metadata.schema_id == RR_SCHEMA_ID
    assert f"{adapter.RR_SCHEMA.schema.node.id:#x}" == RR_SCHEMA_ID
    assert log.metadata.native_architecture == X86


def test_rr_version_mismatch_fails_before_substream_parsing(tmp_path):
    fixture = tmp_path / "wrong-version"
    shutil.copytree(FIXTURES / "empty-x86", fixture)
    version = (fixture / "version").read_bytes()
    (fixture / "version").write_bytes(b"84\n" + version.split(b"\n", 1)[1])

    with pytest.raises(DeterministicLogFormatError, match="unsupported RR trace version 84"):
        DeterministicLog(fixture)


def test_exact_x86_64_register_layout_and_normalized_alias_lookup():
    decoded = decode_x86_64_registers(bytes(216))

    assert len(decoded.registers) == 26
    assert decoded.original_syscall_number == 0
    assert decoded.registers["RIP"] == 0
    assert decoded.registers["rip"] == 0
    assert decoded.registers["EFLAGS"] == 0


@pytest.mark.parametrize(
    ("decoder", "size"),
    ((decode_x86_64_registers, 216), (decode_aarch64_registers, 288)),
)
def test_register_decoders_require_exact_payload_lengths(decoder, size):
    with pytest.raises(DeterministicLogFormatError, match="register payload has length"):
        decoder(bytes(size - 1))
    with pytest.raises(DeterministicLogFormatError, match="register payload has length"):
        decoder(bytes(size + 1))


def test_aarch64_fixture_uses_x0_through_x30_and_rr_private_tail():
    log = DeterministicLog(FIXTURES / "aarch64-syscall")
    events = log.events()

    assert log.metadata is not None
    assert log.metadata.native_architecture == AARCH64
    assert len(events) == 2
    pre, post = events
    assert isinstance(pre, SyscallEvent)
    assert isinstance(post, SyscallEvent)
    assert pre.pc == 0x4000
    assert pre.registers["X0"] == 42
    assert pre.registers["X8"] == 64
    assert pre.registers["X30"] == 30
    assert pre.registers["SP"] == 0x7FFF0000
    assert pre.registers["CPSR"] == 0x600003C5
    assert post.pc == 0x4004
    assert post.registers["X0"] == 5
    with pytest.raises(KeyError):
        _ = pre.registers["X31"]


def test_x86_fixture_decodes_pairs_multiple_blocks_writes_holes_and_tail():
    log = DeterministicLog(FIXTURES / "x86-syscall")
    events = log.events()

    assert len(events) == 4
    pre, post, scheduled, reset = events
    assert isinstance(pre, SyscallEvent)
    assert isinstance(post, SyscallEvent)
    assert pre.event_count == 1
    assert pre.pc == 0x1000
    assert pre.registers["RAX"] == 0
    assert pre.syscall_state == "entering"
    assert post.event_count == 2
    assert post.pc == 0x1002
    assert post.registers["RAX"] == 8
    assert post.syscall_state == "exiting"
    assert scheduled.event_count == 3
    assert scheduled.pc == 0x1010
    assert reset.event_count == 4
    assert reset.event_type == "syscallbufReset"
    assert reset.pc is None
    assert len(reset.registers) == 0

    first, second = post.mem_writes
    assert [(item.offset, item.data) for item in first.known_ranges] == [
        (0, b"AB"),
        (4, b"CD"),
        (7, b"E"),
    ]
    assert [(item.offset, item.size) for item in first.unknown_ranges] == [
        (2, 2),
        (6, 1),
    ]
    assert [(item.offset, item.data) for item in second.known_ranges] == [
        (1, b"XYZ")
    ]
    assert [(item.offset, item.size) for item in second.unknown_ranges] == [(0, 1)]
    assert first.encoded_data == b"ABCDE"
    assert second.encoded_data == b"XYZ"


def test_compressed_reader_concatenates_multiple_independent_blocks():
    path = FIXTURES / "x86-syscall" / "data"
    encoded = path.read_bytes()
    position = 0
    block_count = 0
    while position < len(encoded):
        compressed_size, _uncompressed_size = BLOCK_HEADER.unpack_from(encoded, position)
        position += BLOCK_HEADER.size + compressed_size
        block_count += 1

    assert position == len(encoded)
    assert block_count == 2
    assert read_compressed_stream(path) == b"ABCDEXYZ"


def test_all_task_variants_and_mapping_gaps_are_preserved():
    log = DeterministicLog(FIXTURES / "x86-syscall")

    tasks = log.tasks()
    assert len(tasks) == 4
    assert tasks[0] == CloneTask(1, 102, 101, 0x100, 2)
    assert tasks[1] == ExecTask(
        1,
        101,
        b"/fixture/program",
        (b"program", b"argument"),
        0x400000,
        0x700000,
        b"/fixture/loader",
        b"pac",
    )
    assert tasks[2] == ExitTask(2, 102, 7)
    assert tasks[3] == DetachTask(3, 101)
    mappings = log.mmaps()
    assert [item.event_count for item in mappings] == [1, 1, 4]
    assert [item.source for item in mappings] == ["file", "zero", "trace"]
    assert mappings[0].source_file == b"fixture.bin"


def test_memory_write_parser_rejects_unordered_or_overlapping_holes(tmp_path):
    raw_write = SimpleNamespace(
        tid=1,
        addr=0x2000,
        size=8,
        holes=(
            SimpleNamespace(offset=4, size=2),
            SimpleNamespace(offset=3, size=1),
        ),
        sizeIsConservative=False,
    )
    cursor = adapter._RawDataCursor(b"12345", tmp_path / "data")

    with pytest.raises(DeterministicLogFormatError, match="unordered or overlaps"):
        adapter._decode_memory_write(raw_write, cursor)


def test_unknown_task_and_event_variants_fail_explicitly(tmp_path):
    unknown_task = SimpleNamespace(
        frameTime=1,
        tid=1,
        which=lambda: "futureTaskVariant",
    )
    with pytest.raises(DeterministicLogFormatError, match="unknown variant"):
        adapter._task_from_record(unknown_task)

    registers = adapter._X86_64_REGISTERS.pack(*([0] * 27))
    unknown_event_union = SimpleNamespace(which=lambda: "futureEventVariant")
    unknown_frame = SimpleNamespace(
        tid=1,
        ticks=0,
        arch="x8664",
        event=unknown_event_union,
        registers=SimpleNamespace(raw=registers),
        extraRegisters=SimpleNamespace(raw=b""),
        memWrites=(),
    )
    cursor = adapter._RawDataCursor(b"", tmp_path / "data")
    with pytest.raises(DeterministicLogFormatError, match="unknown variant"):
        adapter._event_from_frame(unknown_frame, 1, cursor)


def test_rr_frames_preserve_and_decode_versioned_extra_register_payloads(tmp_path):
    cases = (
        (
            "x8664",
            adapter._X86_64_REGISTERS.pack(*([0] * 27)),
            bytearray(576),
            "x86-xsave-v1",
            "mxcsr",
            0x1F80,
        ),
        (
            "aarch64",
            adapter._AARCH64_REGISTERS.pack(*([0] * 36)),
            bytearray(528),
            "aarch64-nt-fpr-v1",
            "fpsr",
            0x1234,
        ),
    )
    for arch, registers, raw, expected_format, register, expected in cases:
        if arch == "x8664":
            raw[24:28] = expected.to_bytes(4, "little")
        else:
            raw[512:516] = expected.to_bytes(4, "little")
        frame = adapter.RR_SCHEMA.Frame.new_message()
        frame.tid = 1
        frame.arch = arch
        frame.registers.raw = registers
        frame.extraRegisters.raw = bytes(raw)
        frame.event.instructionTrap = None

        event = adapter._event_from_frame(
            frame,
            1,
            adapter._RawDataCursor(b"", tmp_path / "data"),
        )

        assert event.extra_registers is not None
        assert event.extra_registers.format == expected_format
        assert event.extra_registers.raw == bytes(raw)
        assert event.extra_registers.read_register(register) == expected


def test_rr_frame_rejects_truncated_extra_register_payload(tmp_path):
    frame = adapter.RR_SCHEMA.Frame.new_message()
    frame.tid = 1
    frame.arch = "aarch64"
    frame.registers.raw = adapter._AARCH64_REGISTERS.pack(*([0] * 36))
    frame.extraRegisters.raw = bytes(527)
    frame.event.instructionTrap = None

    with pytest.raises(DeterministicLogFormatError, match="expected 528"):
        adapter._event_from_frame(
            frame,
            1,
            adapter._RawDataCursor(b"", tmp_path / "data"),
        )
