from pathlib import Path
import runpy
import struct


PROBE = runpy.run_path(str(Path(__file__).parent / "probes/intel_snapshot_smoke.py"))


def test_elf_entry_reads_elf64_little_endian_entry(tmp_path):
    image = bytearray(64)
    image[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", image, 24, 0x401234)
    path = tmp_path / "image"
    path.write_bytes(image)
    assert PROBE["elf_entry"](path) == 0x401234


def test_snapshot_register_plan_covers_all_x86_simd_lanes():
    assert all(f"xmm{index}" in PROBE["SNAPSHOT_REGISTERS"] or
               f"xmm{index}" in PROBE["EXTRA_REGISTERS"] for index in range(16))


def test_elf_entry_rejects_non_elf(tmp_path):
    path = tmp_path / "not-elf"
    path.write_bytes(b"not an executable")
    try:
        PROBE["elf_entry"](path)
    except ValueError as error:
        assert "ELF64 little-endian" in str(error)
    else:
        raise AssertionError("invalid ELF unexpectedly accepted")
