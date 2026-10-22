"""Stateful, fail-closed Linux syscall contracts for native whole-program runs.

The policy validates ABI/resource behavior; syscall return values remain inputs
from the operating-system environment rather than a predicted Linux oracle.
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
import os
from typing import Mapping

from .spec_validate import (
    SpecValidationError,
    UnsupportedNativeEvent,
    _byte,
    _diff,
    _mapping,
    _permission,
    _pc_name,
)

PAGE_SIZE = 4096
MAX_IO = 16 * 1024 * 1024
MAX_MAP = 16 * 1024 * 1024


def _field(mapping, name, default=None):
    aliases = {"start": "start_address", "end": "end_address"}
    if isinstance(mapping, Mapping):
        return mapping.get(name, mapping.get(aliases.get(name, ""), default))
    return getattr(mapping, name, getattr(mapping, aliases.get(name, ""), default))


def _signed_result(value):
    """Interpret a syscall result captured as an unsigned machine word."""
    if value is None:
        return None
    if value >= 1 << 63:
        return value - (1 << 64)
    return value


def _is_errno(value):
    return value is not None and -4095 <= value < 0


def _is_private(mapping):
    explicit = _field(mapping, "private", None)
    return explicit if isinstance(explicit, bool) else "p" in str(_field(mapping, "perms", ""))


def _mapping_lookup(snapshot):
    mappings = []
    for mapping in snapshot.mappings:
        start, end = _field(mapping, "start"), _field(mapping, "end")
        if type(start) is not int or type(end) is not int or not 0 <= start < end <= 1 << 64:
            raise SpecValidationError("Invalid mapping range in syscall snapshot.")
        mappings.append((start, end, mapping))
    mappings.sort(key=lambda item: item[0])
    for previous, current in zip(mappings, mappings[1:]):
        if current[0] < previous[1]:
            raise SpecValidationError("Overlapping mapping ranges in syscall snapshot.")
    starts = [item[0] for item in mappings]

    def signature(address):
        index = bisect_right(starts, address) - 1
        if index < 0:
            return None
        start, end, mapping = mappings[index]
        if address >= end:
            return None
        return (
            _permission(mapping, address),
            _is_private(mapping),
            _field(mapping, "name", ""),
        )

    return signature


def _validate_mapping_changes(pre, post, allowed_ranges):
    before = _mapping_lookup(pre)
    after = _mapping_lookup(post)
    boundaries = set()
    for snapshot in (pre, post):
        for mapping in snapshot.mappings:
            start, end = _field(mapping, "start"), _field(mapping, "end")
            if type(start) is int and type(end) is int and start < end:
                boundaries.update((start, end))
    for start, end in allowed_ranges:
        boundaries.update((start, end))
    points = sorted(boundaries)
    allowed_ranges = sorted(allowed_ranges)
    range_index = 0
    for start, end in zip(points, points[1:]):
        while range_index < len(allowed_ranges) and allowed_ranges[range_index][1] <= start:
            range_index += 1
        allowed = (
            range_index < len(allowed_ranges)
            and allowed_ranges[range_index][0] <= start
            and end <= allowed_ranges[range_index][1]
        )
        if not allowed and before(start) != after(start):
            raise SpecValidationError(f"syscall changed unauthorized mapping at {start:#x}")


@dataclass(frozen=True)
class SyscallToken:
    op: str
    number: int
    args: tuple[int, ...]
    arch: str
    pc: int
    path: bytes | None = None
    byte_limit: int | None = None
    fixed_replace: bool = False
    output_data: bytes | None = None


class NativeLinuxPolicy:
    """Stateful Linux syscall ABI policy; call preflight before stepping."""

    def __init__(
        self, *, stdin: bytes = b"", allowed_read_paths=(), uid=None, gid=None, page_size=PAGE_SIZE
    ):
        if type(page_size) is not int or page_size != PAGE_SIZE:
            raise ValueError("native Linux policy requires explicit 4096-byte hardware pages")
        self.stdin = bytes(stdin)
        self.stdin_offset = 0
        self.allowed_read_paths = frozenset(os.fsencode(path) for path in allowed_read_paths)
        self.uid = uid
        self.gid = gid
        if uid is not None and (type(uid) is not int or not 0 <= uid < 1 << 32):
            raise ValueError("uid must be an independently captured 32-bit identity")
        if gid is not None and (type(gid) is not int or not 0 <= gid < 1 << 32):
            raise ValueError("gid must be an independently captured 32-bit identity")
        self.owned_fds = {0, 1, 2}
        self.fd_paths = {}
        self.fd_offsets = {}
        self.brk_base = None
        self.brk_current = None
        self.brk_fresh_ranges = []
        self.brk_map_start = None
        self.brk_map_end = None
        self.mmaps = {}
        self.page_size = page_size

    def _abi(self, pre):
        arm = pre.arch.archname == "aarch64"
        if not arm and pre.arch.archname != "x86_64":
            raise UnsupportedNativeEvent("Unsupported native Linux architecture.")
        nrname = "X8" if arm else "RAX"
        argsnames = (
            ("X0", "X1", "X2", "X3", "X4", "X5")
            if arm
            else ("RDI", "RSI", "RDX", "R10", "R8", "R9")
        )
        missing = [n for n in (nrname, *argsnames) if n not in pre.registers]
        if missing:
            raise UnsupportedNativeEvent(
                f"Syscall pre-state omitted required argument registers: {missing}."
            )
        return arm, pre.registers[nrname], tuple(pre.registers[n] for n in argsnames)

    def _range(self, pre, address, size, access):
        if (
            type(address) is not int
            or type(size) is not int
            or size < 0
            or size > MAX_IO
            or address < 0
            or address + size > 1 << 64
        ):
            raise UnsupportedNativeEvent("Invalid or excessive syscall memory range.")
        end = address + size
        cursor = address
        while cursor < end:
            m = _mapping(pre.mappings, cursor)
            perms = _permission(m, cursor) if m is not None else ""
            mapping_end = _field(m, "end", cursor) if m is not None else cursor
            if (
                m is None
                or not _is_private(m)
                or access not in perms
                or (access == "w" and "r" not in perms)
                or mapping_end <= cursor
            ):
                raise UnsupportedNativeEvent(
                    f"Syscall buffer lacks private pre-state {access} permission at {cursor:#x}."
                )
            cursor = min(end, mapping_end)

    def _require_memory(self, pre, address, size):
        if any(_byte(pre.memory, address + offset) is None for offset in range(size)):
            raise UnsupportedNativeEvent(
                "Syscall input bytes are absent from private-memory evidence."
            )

    def _read_cstr(self, pre, addr):
        out = bytearray()
        for i in range(4096):
            self._range(pre, addr + i, 1, "r")
            b = _byte(pre.memory, addr + i)
            if b is None:
                raise UnsupportedNativeEvent(
                    "Pathname bytes are not present in private-memory evidence."
                )
            if b == 0:
                return bytes(out)
            out.append(b)
        raise UnsupportedNativeEvent("Unterminated/oversized pathname.")

    def preflight(self, pre):
        _mapping_lookup(pre)
        arm, nr, a = self._abi(pre)
        names = (
            {
                63: "read",
                64: "write",
                66: "writev",
                56: "openat",
                57: "close",
                80: "fstat",
                79: "newfstatat",
                93: "exit",
                94: "exit",
                214: "brk",
                96: "set_tid_address",
                99: "set_robust_list",
                261: "prlimit64",
                278: "getrandom",
                113: "clock_gettime",
                222: "mmap",
                215: "munmap",
                226: "mprotect",
            }
            if arm
            else {
                0: "read",
                1: "write",
                2: "open",
                3: "close",
                4: "stat",
                5: "fstat",
                9: "mmap",
                11: "munmap",
                12: "brk",
                14: "rt_sigprocmask",
                16: "ioctl",
                20: "writev",
                60: "exit",
                102: "getuid",
                104: "getgid",
                105: "setuid",
                106: "setgid",
                158: "arch_prctl",
                218: "set_tid_address",
                228: "clock_gettime",
                231: "exit",
                257: "openat",
                262: "newfstatat",
                273: "set_robust_list",
                302: "prlimit64",
                318: "getrandom",
                10: "mprotect",
            }
        )
        op = names.get(nr)
        if op is None:
            raise UnsupportedNativeEvent(
                f"Unsupported Linux syscall {nr}; rejected before execution."
            )
        pc = pre.registers[_pc_name(pre.registers, pre.arch)]
        path = None
        byte_limit = None
        fixed_replace = False
        output_data = None
        if op == "read":
            if a[0] != 0 and (a[0] not in self.owned_fds or a[0] not in self.fd_paths):
                raise UnsupportedNativeEvent(
                    "read requires stdin or a policy-owned readonly descriptor."
                )
            if a[2] > MAX_IO:
                raise UnsupportedNativeEvent("read exceeds policy bound")
            self._range(pre, a[1], a[2], "w")
        elif op == "write":
            if a[0] not in (1, 2):
                raise UnsupportedNativeEvent("Only stdout/stderr writes are supported.")
            if a[2] > MAX_IO:
                raise UnsupportedNativeEvent("write exceeds policy bound")
            self._range(pre, a[1], a[2], "r")
            self._require_memory(pre, a[1], a[2])
            output_data = bytes(_byte(pre.memory, a[1] + i) for i in range(a[2]))
        elif op == "writev":
            if a[0] not in (1, 2) or a[2] > 1024:
                raise UnsupportedNativeEvent("Only bounded stdout/stderr writev is supported.")
            self._range(pre, a[1], a[2] * 16, "r")
            total = 0
            output_parts = []
            for i in range(a[2]):
                base = a[1] + 16 * i
                values = [_byte(pre.memory, base + j) for j in range(16)]
                if any(x is None for x in values):
                    raise UnsupportedNativeEvent("writev iovec is absent from memory evidence")
                raw = bytes(values)
                ptr = int.from_bytes(raw[:8], "little")
                length = int.from_bytes(raw[8:], "little")
                total += length
                if length > MAX_IO or total > MAX_IO:
                    raise UnsupportedNativeEvent("writev exceeds bound")
                self._range(pre, ptr, length, "r")
                self._require_memory(pre, ptr, length)
                output_parts.append(bytes(_byte(pre.memory, ptr + j) for j in range(length)))
            byte_limit = total
            output_data = b"".join(output_parts)
        elif op in ("openat", "open"):
            flags = a[2] if op == "openat" else a[1]
            allowed_flags = 0x80000 | 0x800 | 0x4000 | 3
            if flags & ~allowed_flags or flags & 3:
                raise UnsupportedNativeEvent(
                    "open restricted to readonly, non-creating file access."
                )
            if op == "openat" and a[0] not in (-100, (1 << 64) - 100):
                raise UnsupportedNativeEvent("openat requires AT_FDCWD")
            path = self._read_cstr(pre, a[1] if op == "openat" else a[0])
            if path not in self.allowed_read_paths:
                raise UnsupportedNativeEvent(
                    "pathname is not an explicitly qualified read-only input."
                )
        elif op == "close":
            if a[0] not in self.owned_fds or a[0] in (0, 1, 2):
                raise UnsupportedNativeEvent("close requires an owned nonstandard descriptor.")
        elif op in ("fstat", "stat", "newfstatat"):
            fd = a[0]
            if op == "fstat" and fd not in self.owned_fds:
                raise UnsupportedNativeEvent("fstat requires a policy-owned descriptor.")
            if op == "newfstatat":
                if a[3] & ~0x1000:
                    raise UnsupportedNativeEvent("Unsupported newfstatat flags.")
                path = self._read_cstr(pre, a[1]) if a[1] else None
                at_cwd = fd in (-100, (1 << 64) - 100)
                if at_cwd:
                    if path not in self.allowed_read_paths:
                        raise UnsupportedNativeEvent(
                            "newfstatat path is not an explicitly qualified input."
                        )
                elif fd not in self.owned_fds or (
                    path is not None and path != self.fd_paths.get(fd)
                ):
                    raise UnsupportedNativeEvent(
                        "newfstatat requires a policy-owned input descriptor/path."
                    )
            if op == "stat":
                path = self._read_cstr(pre, a[0])
                if path not in self.allowed_read_paths:
                    raise UnsupportedNativeEvent(
                        "stat pathname is not an explicitly qualified readonly input"
                    )
            stat_size = 144 if pre.arch.archname == "x86_64" else 128
            stat_address = a[1] if op in ("stat", "fstat") else a[2]
            self._range(pre, stat_address, stat_size, "w")
        elif op in (
            "getrandom",
            "clock_gettime",
            "prlimit64",
            "set_tid_address",
            "set_robust_list",
            "rt_sigprocmask",
            "ioctl",
            "arch_prctl",
            "getuid",
            "getgid",
            "setuid",
            "setgid",
        ):
            if op == "getrandom":
                if a[2] & ~3 or a[1] > MAX_IO:
                    raise UnsupportedNativeEvent("Unsupported getrandom request")
                self._range(pre, a[0], a[1], "w")
            elif op == "clock_gettime":
                self._range(pre, a[1], 16, "w")
            elif op == "prlimit64":
                if a[0] != 0 or a[2] != 0:
                    raise UnsupportedNativeEvent(
                        "prlimit64 is limited to pid-0 query-only requests"
                    )
                if a[3]:
                    self._range(pre, a[3], 16, "w")
            elif op == "set_tid_address":
                if a[0]:
                    self._range(pre, a[0], 4, "w")
            elif op == "set_robust_list":
                if a[1] != 24:
                    raise UnsupportedNativeEvent("Unsupported robust-list ABI size")
                self._range(pre, a[0], 24, "r")
            elif op == "rt_sigprocmask":
                if a[0] not in (0, 1, 2) or a[3] != 8:
                    raise UnsupportedNativeEvent(
                        "rt_sigprocmask only supports bounded 64-bit signal masks"
                    )
                if a[1]:
                    self._range(pre, a[1], 8, "r")
                    self._require_memory(pre, a[1], 8)
                    mask = int.from_bytes(
                        bytes(_byte(pre.memory, a[1] + i) for i in range(8)), "little"
                    )
                    if mask:
                        raise UnsupportedNativeEvent(
                            "nonempty asynchronous signal masks are unsupported"
                        )
                if a[2]:
                    self._range(pre, a[2], 8, "w")
            elif op == "ioctl":
                if a[0] != 1 or a[1] != 21523 or not a[2]:
                    raise UnsupportedNativeEvent("Only stdout TIOCGWINSZ ioctl is supported")
                self._range(pre, a[2], 8, "w")
            elif op == "arch_prctl":
                if a[0] != 0x1002:
                    raise UnsupportedNativeEvent("Only ARCH_SET_FS is supported")
            elif op in ("setuid", "setgid"):
                identity = self.uid if op == "setuid" else self.gid
                if identity is None or a[0] != identity:
                    raise UnsupportedNativeEvent(
                        f"{op} requires explicitly captured current identity"
                    )
            elif op in ("getuid", "getgid"):
                if (self.uid if op == "getuid" else self.gid) is None:
                    raise UnsupportedNativeEvent(
                        f"{op} requires explicitly captured current identity"
                    )
            if op == "set_robust_list":
                self._range(pre, a[0], 24, "r")
                self._require_memory(pre, a[0], 24)
        elif op in ("mmap", "munmap", "mprotect"):
            if op in ("munmap", "mprotect"):
                if (
                    a[0] % self.page_size
                    or a[1] <= 0
                    or a[1] > MAX_MAP
                    or a[0] + a[1] > 1 << 64
                    or (op == "mprotect" and a[2] & ~7)
                ):
                    raise UnsupportedNativeEvent("Invalid mapping range/protection")
                length = (a[1] + self.page_size - 1) & ~(self.page_size - 1)
                if a[0] + length > 1 << 64:
                    raise UnsupportedNativeEvent("Mapping range overflows address space")
                for page in range(a[0], a[0] + length, self.page_size):
                    if not any(
                        base <= page and page + self.page_size <= base + size
                        for base, size in self.mmaps.items()
                    ):
                        raise UnsupportedNativeEvent(
                            f"{op} range is outside policy-owned anonymous mappings"
                        )
            if op == "mmap":
                if a[1] <= 0 or a[1] > MAX_MAP or a[2] & ~3:
                    raise UnsupportedNativeEvent("Invalid mmap size/protection")
                fixed_flags = 0x32
                regular_flags = 0x22
                if a[3] == fixed_flags:
                    if (
                        a[0] % self.page_size
                        or a[1] != self.page_size
                        or a[2] != 0
                        or a[4] != (1 << 64) - 1
                        or a[5] != 0
                    ):
                        raise UnsupportedNativeEvent(
                            "MAP_FIXED is limited to the owned one-page heap guard"
                        )
                    m = _mapping(pre.mappings, a[0])
                    if (
                        self.brk_base is None
                        or self.brk_current is None
                        or a[0] < self.brk_base
                        or a[0] + self.page_size > self.brk_current
                        or not any(
                            start <= a[0] and a[0] + self.page_size <= end
                            for start, end in self.brk_fresh_ranges
                        )
                        or m is None
                        or not _is_private(m)
                        or _field(m, "name", "") != "[heap]"
                        or "r" not in _permission(m, a[0])
                        or "w" not in _permission(m, a[0])
                        or "x" in _permission(m, a[0])
                    ):
                        raise UnsupportedNativeEvent(
                            "MAP_FIXED must replace one recently grown private RW heap page"
                        )
                    self._require_memory(pre, a[0], self.page_size)
                    if any(
                        _byte(pre.memory, a[0] + offset) != 0 for offset in range(self.page_size)
                    ):
                        raise UnsupportedNativeEvent(
                            "MAP_FIXED may replace only a fresh zero-filled heap page"
                        )
                    fixed_replace = True
                elif a[0] != 0 or a[3] != regular_flags or a[4] != (1 << 64) - 1 or a[5] != 0:
                    raise UnsupportedNativeEvent("Only bounded private anonymous mmap supported")
            if op != "mmap":
                for p in range(
                    a[0],
                    a[0] + ((a[1] + self.page_size - 1) & ~(self.page_size - 1)),
                    self.page_size,
                ):
                    m = _mapping(pre.mappings, p)
                    if m is None or not _is_private(m):
                        raise UnsupportedNativeEvent(f"{op} requires private mapped pages")
                    if op == "munmap" and "x" in _permission(m, p):
                        raise UnsupportedNativeEvent("Cannot unmap executable code")
                    if op == "mprotect":
                        current_readable = "r" in _permission(m, p)
                        requested_readable = bool(a[2] & 1)
                        if current_readable != requested_readable:
                            raise UnsupportedNativeEvent(
                                "mprotect readability changes are unsupported by syscall policy v1"
                            )
                        if a[2] & 4 and "x" not in _permission(m, p):
                            raise UnsupportedNativeEvent("Cannot create executable mappings")
        elif op == "brk":
            if self.brk_current is None and a[0] != 0:
                raise UnsupportedNativeEvent("brk baseline must first be discovered with brk(0)")
            if (
                self.brk_base is not None
                and a[0]
                and not (self.brk_base <= a[0] <= self.brk_base + MAX_MAP)
            ):
                raise UnsupportedNativeEvent("brk outside bounded initial heap growth")
        return SyscallToken(
            op, nr, a, pre.arch.archname, pc, path, byte_limit, fixed_replace, output_data
        )

    def validate(self, pre, post, event, token):
        arm = token.arch == "aarch64"
        if token.op == "exit":
            if event.kind != "exit" or event.exit_status != token.args[0]:
                raise SpecValidationError("exit argument/status mismatch")
            return
        if post is None or event.kind != "instruction":
            raise SpecValidationError("syscall failed to return normally")
        pcname = _pc_name(pre.registers, pre.arch)
        result_name = "X0" if arm else "RAX"
        ret = post.registers.get(result_name)
        signed_ret = _signed_result(ret)
        expected_pc = token.pc + (4 if arm else 2)
        if post.registers.get(pcname) != expected_pc:
            raise SpecValidationError("syscall resume PC mismatch")
        mutable = {pcname, result_name} | (set() if arm else {"RCX", "R11"})
        if token.op == "arch_prctl" and signed_ret == 0:
            mutable.add("FS_BASE")
        for k, v in pre.registers.items():
            name = str(k).upper()
            if name in mutable:
                continue
            actual = post.registers.get(name)
            if arm and name == "CPSR":
                # LLDB's raw CPSR includes debugger/PSTATE bits (notably SS)
                # outside the native architectural flag view. Preserve exactly
                # the source-modeled NZCV bits, matching instruction boundaries.
                mask = 0xF0000000
                if actual is None or ((actual ^ v) & mask):
                    raise SpecValidationError("syscall clobbered preserved register CPSR.NZCV")
            elif actual != v:
                raise SpecValidationError(f"syscall clobbered preserved register {name}")
        op, a = token.op, token.args
        if op in ("write", "writev"):
            stream = "stderr" if a[0] == 2 else "stdout"
            other = "stdout" if stream == "stderr" else "stderr"
            before_stream = getattr(pre, stream)
            after_stream = getattr(post, stream)
            if not after_stream.startswith(before_stream):
                raise SpecValidationError(f"{stream} evidence is not append-only")
            if getattr(post, other) != getattr(pre, other):
                raise SpecValidationError(f"unexpected {other} output during {op}")
        elif post.stdout != pre.stdout or post.stderr != pre.stderr:
            raise SpecValidationError(f"unexpected output during {op}")
        allowed = []
        output_ranges = []
        mapping_ranges = []
        if _is_errno(signed_ret) and op != "ioctl":
            if op == "brk":
                raise SpecValidationError("brk returned an errno instead of the current break")
            if _diff(pre.memory, post.memory):
                raise SpecValidationError("failed syscall changed memory")
            if pre.mappings != post.mappings:
                raise SpecValidationError("failed syscall changed memory mappings")
            if pre.stdout != post.stdout or pre.stderr != post.stderr:
                raise SpecValidationError("failed syscall changed output")
            return
        if op == "read":
            if signed_ret is None or signed_ret < 0 or signed_ret > min(a[2], MAX_IO):
                raise SpecValidationError("invalid read count")
            count = signed_ret
            if a[0] == 0:
                expected = self.stdin[self.stdin_offset : self.stdin_offset + count]
                if count > len(expected):
                    raise SpecValidationError("read returned more bytes than supplied stdin")
                for i, byte in enumerate(expected):
                    if _byte(post.memory, a[1] + i) != byte:
                        raise SpecValidationError("read buffer differs from supplied stdin")
                self.stdin_offset += count
            elif any(_byte(post.memory, a[1] + i) is None for i in range(count)):
                raise SpecValidationError("file read output is missing from memory evidence")
            allowed.append((a[1], a[1] + count))
            output_ranges.append((a[1], a[1] + count))
            if a[0] not in (0, 1, 2):
                self.fd_offsets[a[0]] = self.fd_offsets.get(a[0], 0) + count
        elif op in ("write", "writev"):
            limit = a[2] if op == "write" else token.byte_limit
            if signed_ret is None or signed_ret < 0 or signed_ret > limit:
                raise SpecValidationError("invalid write byte count")
            emitted = getattr(post, "stderr" if a[0] == 2 else "stdout")
            observed = emitted[len(getattr(pre, "stderr" if a[0] == 2 else "stdout")) :]
            if observed != token.output_data[:signed_ret]:
                raise SpecValidationError(f"{op} bytes differ from captured output evidence")
        elif op in ("openat", "open"):
            if signed_ret is None or signed_ret < 0 or signed_ret in self.owned_fds:
                raise SpecValidationError("invalid open descriptor result")
            self.owned_fds.add(signed_ret)
            self.fd_paths[signed_ret] = token.path
            self.fd_offsets[signed_ret] = 0
        elif op == "close":
            if signed_ret != 0:
                raise SpecValidationError("close failed")
            self.owned_fds.remove(a[0])
            self.fd_paths.pop(a[0], None)
            self.fd_offsets.pop(a[0], None)
        elif op in ("fstat", "stat", "newfstatat"):
            if signed_ret != 0:
                raise SpecValidationError("stat failed")
            addr = a[1] if op in ("stat", "fstat") else a[2]
            stat_size = 144 if token.arch == "x86_64" else 128
            allowed.append((addr, addr + stat_size))
            output_ranges.append((addr, addr + stat_size))
        elif op == "brk":
            initial_discovery = self.brk_current is None
            if signed_ret is None or signed_ret < 0:
                raise SpecValidationError("invalid brk result")
            if self.brk_current is None:
                if a[0] != 0:
                    raise SpecValidationError("brk baseline must be discovered with brk(0)")
                target = signed_ret
                self.brk_base = self.brk_current = target
                heap1 = next((m for m in post.mappings if _field(m, "name", "") == "[heap]"), None)
                if heap1 is not None and not _field(heap1, "start", 0) <= target <= _field(
                    heap1, "end", 0
                ):
                    raise SpecValidationError("initial brk is outside observed heap mapping")
            else:
                prior_break = self.brk_current
                if a[0] and signed_ret == prior_break:
                    if _diff(pre.memory, post.memory) or pre.mappings != post.mappings:
                        raise SpecValidationError("failed brk request changed memory or mappings")
                    return
                target = a[0] or prior_break
                if (
                    target < self.brk_base
                    or target > self.brk_base + MAX_MAP
                    or signed_ret != target
                ):
                    raise SpecValidationError("brk result outside policy")
            heap1 = next((m for m in post.mappings if _field(m, "name", "") == "[heap]"), None)
            if (
                a[0]
                and target > self.brk_current
                and (heap1 is None or _field(heap1, "end", 0) < target)
            ):
                raise SpecValidationError("brk mapping does not cover requested growth")
            prior = target if initial_discovery else self.brk_current
            lo, hi = sorted((prior, target))
            allowed.append((lo, hi))
            for address in range(lo, hi):
                value = _byte(post.memory, address)
                if target > prior and value != 0:
                    raise SpecValidationError("brk growth is not observable and zero initialized")
            if not initial_discovery and target > prior:
                self.brk_fresh_ranges = [(prior, target)]
            elif not initial_discovery and target < prior:
                self.brk_fresh_ranges = [
                    (start, min(end, target))
                    for start, end in self.brk_fresh_ranges
                    if start < target
                ]
            if not initial_discovery and target != prior:
                map_start = lo & ~(self.page_size - 1)
                map_end = (hi + self.page_size - 1) & ~(self.page_size - 1)
                mapping_ranges.append((map_start, map_end))
            self.brk_current = target
        elif op == "mmap":
            length = (a[1] + self.page_size - 1) & ~(self.page_size - 1)
            if (
                ret is None
                or ret >= 1 << 63
                or ret % self.page_size
                or (
                    not token.fixed_replace
                    and any(
                        _mapping(pre.mappings, p) for p in range(ret, ret + length, self.page_size)
                    )
                )
            ):
                raise SpecValidationError("invalid or overlapping mmap result")
            if token.fixed_replace and ret != a[0]:
                raise SpecValidationError("MAP_FIXED did not replace the authorized heap guard")
            for p in range(ret, ret + length, self.page_size):
                m = _mapping(post.mappings, p)
                expected = ("r" if a[2] & 1 else "-") + ("w" if a[2] & 2 else "-") + "-"
                if m is None or _permission(m, p)[:3] != expected or not _is_private(m):
                    raise SpecValidationError("mmap permission/private mapping mismatch")
            if a[2] & 1 and any(_byte(post.memory, p) != 0 for p in range(ret, ret + length)):
                raise SpecValidationError("anonymous mmap was not zero initialized")
            allowed.append((ret, ret + length))
            mapping_ranges.append((ret, ret + length))
            self.mmaps[ret] = length
            if token.fixed_replace:
                start, end = ret, ret + length
                fresh = []
                for lo, hi in self.brk_fresh_ranges:
                    if hi <= start or lo >= end:
                        fresh.append((lo, hi))
                    else:
                        if lo < start:
                            fresh.append((lo, start))
                        if hi > end:
                            fresh.append((end, hi))
                self.brk_fresh_ranges = fresh
        elif op in ("munmap", "mprotect"):
            length = (a[1] + self.page_size - 1) & ~(self.page_size - 1)
            if ret != 0:
                raise SpecValidationError(f"{op} failed")
            for p in range(a[0], a[0] + length, self.page_size):
                m = _mapping(post.mappings, p)
                if op == "munmap" and m is not None:
                    raise SpecValidationError("munmap left mapping present")
                if op == "mprotect" and (
                    m is None
                    or _permission(m, p)[:3]
                    != ("r" if a[2] & 1 else "-")
                    + ("w" if a[2] & 2 else "-")
                    + ("x" if a[2] & 4 else "-")
                ):
                    raise SpecValidationError("mprotect permission mismatch")
            mapping_ranges.append((a[0], a[0] + length))
            if op == "munmap":
                allowed.append((a[0], a[0] + length))
                end = a[0] + length
                remaining = {}
                for base, size in self.mmaps.items():
                    map_end = base + size
                    if map_end <= a[0] or base >= end:
                        remaining[base] = size
                        continue
                    if base < a[0]:
                        remaining[base] = a[0] - base
                    if map_end > end:
                        remaining[end] = map_end - end
                self.mmaps = remaining
        elif op == "ioctl":
            if signed_ret not in (0, -25):
                raise SpecValidationError("TIOCGWINSZ must succeed or report ENOTTY")
            if signed_ret == 0:
                allowed.append((a[2], a[2] + 8))
                output_ranges.append((a[2], a[2] + 8))
        elif op == "rt_sigprocmask":
            if signed_ret != 0:
                raise SpecValidationError("rt_sigprocmask failed")
            if a[2]:
                allowed.append((a[2], a[2] + 8))
                output_ranges.append((a[2], a[2] + 8))
        elif op == "arch_prctl":
            if signed_ret != 0 or post.registers.get("FS_BASE") != a[1]:
                raise SpecValidationError("ARCH_SET_FS did not set the requested FS base")
        elif op in ("getuid", "getgid"):
            expected = self.uid if op == "getuid" else self.gid
            if signed_ret != expected:
                raise SpecValidationError(
                    f"{op} result differs from independently captured identity"
                )
        elif op in ("setuid", "setgid"):
            if signed_ret != 0:
                raise SpecValidationError(f"{op} failed for the already-current identity")
        else:
            if op in ("set_tid_address",):
                if signed_ret is None or signed_ret <= 0:
                    raise SpecValidationError("invalid set_tid_address result")
            elif op in ("set_robust_list",):
                if ret != 0:
                    raise SpecValidationError("set_robust_list failed")
            elif op in ("clock_gettime", "prlimit64", "getrandom"):
                if signed_ret != 0 and op != "getrandom":
                    raise SpecValidationError(f"{op} failed")
                if op == "getrandom" and (signed_ret is None or signed_ret > a[1]):
                    raise SpecValidationError("getrandom returned an invalid byte count")
                if op == "clock_gettime" and ret == 0:
                    allowed.append((a[1], a[1] + 16))
                    output_ranges.append((a[1], a[1] + 16))
                elif op == "prlimit64" and ret == 0 and a[3]:
                    allowed.append((a[3], a[3] + 16))
                    output_ranges.append((a[3], a[3] + 16))
                elif op == "getrandom" and ret <= a[1]:
                    allowed.append((a[0], a[0] + ret))
                    output_ranges.append((a[0], a[0] + ret))
        _validate_mapping_changes(pre, post, mapping_ranges)
        changed = _diff(pre.memory, post.memory)
        unexpected = [
            address
            for address in changed
            if not any(start <= address < end for start, end in allowed)
        ]
        if unexpected:
            raise SpecValidationError(
                f"syscall changed unauthorized memory {sorted(unexpected)[:8]}"
            )
        for start, end in output_ranges:
            if any(_byte(post.memory, address) is None for address in range(start, end)):
                raise SpecValidationError("syscall output byte missing")
