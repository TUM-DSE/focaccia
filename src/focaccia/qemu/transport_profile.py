"""Explicit compatibility for independently identified debugger wire defects.

QEMU v6.1.0 target/i386/gdbstub.c passes (ZMM_Q(0), ZMM_Q(1)) to
include/exec/gdbstub.h's gdb_get_reg128(val_hi, val_lo). The x86 read packet
therefore sends the high lane first. Its write packet remains low-first.
This is not an instruction-semantics or observed-result-dependent correction.
"""
from dataclasses import dataclass
import hashlib
from pathlib import Path

XMM_READ_PROFILE = "qemu-6.1.0-xmm-read-high-first"
# Stock Nixpkgs QEMU 6.1.0, aarch64-linux host, independently tested with a
# MOVDQU load/store and asymmetric lanes. Other builds require separate audit.
XMM_READ_EXECUTABLE_SHA256 = "2e7470f3aa224d65f4334d2821802aa570dc7f8bded94b51069d78516edaf68d"


@dataclass(frozen=True)
class XmmReadTransportBinding:
    profile: str
    tid: int
    executable: Path
    device: int
    inode: int
    sha256: str

    def verify_identity(self, tid: int, *, proc_root: Path = Path('/proc')) -> None:
        if tid != self.tid:
            raise ValueError('Configured QEMU transport process changed.')
        executable = proc_root / str(tid) / 'exe'
        stat = executable.stat()
        if (stat.st_dev, stat.st_ino) != (self.device, self.inode):
            raise ValueError('Configured QEMU transport executable changed.')


def bind_xmm_read_transport(
    profile: str, tid: int, isa: str, endianness: str,
    *, proc_root: Path = Path('/proc'),
) -> XmmReadTransportBinding:
    if profile != XMM_READ_PROFILE or isa != 'x86_64' or endianness != 'little':
        raise ValueError('Unsupported QEMU XMM read transport profile or guest.')
    if tid <= 0:
        raise ValueError('Transport profile requires a local QEMU task.')
    executable = proc_root / str(tid) / 'exe'
    with executable.open('rb') as stream:
        import os
        stat = os.fstat(stream.fileno())
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != XMM_READ_EXECUTABLE_SHA256:
        raise ValueError('QEMU XMM read profile rejects this unaudited executable digest.')
    binding = XmmReadTransportBinding(
        profile, tid, executable.resolve(strict=True), stat.st_dev, stat.st_ino, digest,
    )
    binding.verify_identity(tid, proc_root=proc_root)
    return binding


def normalize_xmm_read(value: int, register: str, size: int) -> int:
    """Inverse the audited packet mapping, only for a complete XMM read."""
    if not (register.startswith('XMM') and register[3:].isdigit()
            and 0 <= int(register[3:]) < 32 and size == 128):
        raise ValueError('Audited transport supports only 128-bit XMM observations.')
    if not 0 <= value < 1 << 128:
        raise ValueError('XMM observation exceeds its wire width.')
    return ((value & ((1 << 64) - 1)) << 64) | (value >> 64)
