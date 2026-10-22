"""Guarded native AArch64 vDSO clock_gettime observation boundary.

The vDSO routine is immutable OS code executed natively, not instruction-spec
validated. Its returned timespec is an environmental output, admitted only
when the exact call/return ABI and memory footprint have been checked.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct

from .spec_validate import NativeStep, UnsupportedNativeEvent, _capture, _mapping, _permission


class VDSOError(UnsupportedNativeEvent):
    """The observed target does not satisfy the vDSO service contract."""


@dataclass(frozen=True, slots=True)
class VDSOSymbol:
    name: str
    version: str
    offset: int
    size: int


@dataclass(frozen=True, slots=True)
class VDSOIdentity:
    start: int
    end: int
    sha256: str
    symbol: VDSOSymbol


@dataclass(frozen=True, slots=True)
class ClockGettimeToken:
    entry: int
    return_pc: int
    sp: int
    clock_id: int
    output: int
    saved: tuple[tuple[str, int], ...]
    stack_start: int
    stack_end: int
    identity: VDSOIdentity


@dataclass(frozen=True, slots=True)
class ClockGettimeResult:
    clock_id: int
    output_address: int
    timespec: bytes
    continuation_events: int
    internal_syscall_count: int
    stack_scratch_ranges: tuple[tuple[int, int], ...]
    abi_profile: str = "AAPCS64-x19-x29-d8-d15-low64-fpcr-tpidr"
    environment_output: bool = True
    internal_pc_trace_available: bool = False
    boundary_only_memory_evidence: bool = True
    service_contract_not_instruction_proof: bool = True
    vdso_internals_instruction_spec_checked: bool = False


def _bounds(data: bytes, off: int, size: int) -> bytes:
    if off < 0 or size < 0 or off + size > len(data):
        raise VDSOError("Malformed vDSO ELF bounds")
    return data[off : off + size]


def _cstring(data: bytes, off: int) -> str:
    if not 0 <= off < len(data):
        raise VDSOError("Malformed vDSO string-table offset")
    end = data.find(b"\0", off)
    if end < 0:
        raise VDSOError("Unterminated vDSO ELF string")
    try:
        return data[off:end].decode("ascii")
    except UnicodeDecodeError as e:
        raise VDSOError("Non-ASCII vDSO ELF name") from e


def parse_clock_symbol(data: bytes) -> VDSOSymbol:
    """Resolve the exact exported versioned AArch64 clock symbol from ELF bytes."""
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise VDSOError("Expected little-endian ELF64 vDSO")
    if struct.unpack_from("<H", data, 16)[0] != 3:
        raise VDSOError("vDSO ELF type is not ET_DYN")
    if struct.unpack_from("<H", data, 18)[0] != 183:
        raise VDSOError("vDSO ELF machine is not AArch64")
    shoff = struct.unpack_from("<Q", data, 40)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 58)
    if shentsize < 64 or not shnum or shstrndx >= shnum or shnum > 4096:
        raise VDSOError("Malformed vDSO section table")
    sections = []
    section_exec = []
    section_addrs = []
    for i in range(shnum):
        raw = _bounds(data, shoff + i * shentsize, 64)
        name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack(
            "<IIQQQQIIQQ", raw
        )
        _bounds(data, off, size)
        sections.append((name, typ, off, size, link, entsize))
        section_exec.append(bool(flags & 0x4))
        section_addrs.append(addr)
    _, _, noff, nsize, _, _ = sections[shstrndx]
    shnames = _bounds(data, noff, nsize)
    names = [_cstring(shnames, s[0]) for s in sections]
    dynsym_i = next((i for i, n in enumerate(names) if n == ".dynsym"), None)
    dynstr_i = next((i for i, n in enumerate(names) if n == ".dynstr"), None)
    versym_i = next((i for i, n in enumerate(names) if n == ".gnu.version"), None)
    verdef_i = next((i for i, n in enumerate(names) if n == ".gnu.version_d"), None)
    if None in (dynsym_i, dynstr_i, versym_i, verdef_i):
        raise VDSOError("vDSO lacks required dynamic symbol/version sections")
    _, _, doff, dsize, _, _ = sections[dynstr_i]
    dynstr = _bounds(data, doff, dsize)
    _, _, voff, vsize, _, _ = sections[versym_i]
    versym = _bounds(data, voff, vsize)
    _, _, foff, fsize, _, _ = sections[verdef_i]
    verdefs = _bounds(data, foff, fsize)
    versions: dict[int, str] = {}
    pos = 0
    while pos + 20 <= len(verdefs):
        version, flags, ndx, cnt, hash_, aux, nxt = struct.unpack_from("<HHHHIII", verdefs, pos)
        if version != 1 or not cnt or pos + aux + 8 > len(verdefs):
            raise VDSOError("Malformed vDSO GNU version definition")
        nameoff, _ = struct.unpack_from("<II", verdefs, pos + aux)
        versions[ndx & 0x7FFF] = _cstring(dynstr, nameoff)
        if not nxt:
            break
        if pos + nxt <= pos:
            raise VDSOError("Invalid vDSO version-definition chain")
        pos += nxt
    _, _, soff, ssize, _, entsize = sections[dynsym_i]
    if entsize < 24 or ssize % entsize:
        raise VDSOError("Malformed vDSO dynamic symbol table")
    candidates = []
    count = ssize // entsize
    if len(versym) < count * 2:
        raise VDSOError("Truncated vDSO symbol-version table")
    for i in range(count):
        nameoff, info, other, shndx, value, size = struct.unpack(
            "<IBBHQQ", _bounds(data, soff + i * entsize, 24)
        )
        if _cstring(dynstr, nameoff) != "__kernel_clock_gettime":
            continue
        version_index = struct.unpack_from("<H", versym, i * 2)[0] & 0x7FFF
        version = versions.get(version_index)
        if (
            info >> 4 == 1
            and shndx
            and shndx < len(sections)
            and size
            and version
            and sections[shndx][1] == 1
            and section_exec[shndx]
            and section_addrs[shndx] <= value
            and value + size <= section_addrs[shndx] + sections[shndx][3]
        ):
            candidates.append(VDSOSymbol("__kernel_clock_gettime", version, value, size))
    if len(candidates) != 1 or candidates[0].version != "LINUX_2.6.39":
        raise VDSOError("Missing, ambiguous, or unexpected vDSO clock symbol/version")
    symbol = candidates[0]
    if symbol.offset + symbol.size > len(data):
        raise VDSOError("vDSO clock symbol extends beyond image")
    return symbol


class NativeVDSOClockGettime:
    """One strict native vDSO service observer; runner integration is separate.

    The caller must first source-validate the ordinary user BLR that arrived at
    this symbol. This observer models only the named kernel-image service body.
    """

    _CALLEE_SAVED = (
        "SP",
        "X30",
        *(f"X{i}" for i in range(19, 30)),
        "FPCR",
        "TPIDR",
        *(f"V{i}" for i in range(8, 16)),
    )

    def __init__(
        self,
        target,
        *,
        syscall_policy=None,
        max_steps: int = 100_000,
        max_stack_bytes: int = 64 * 1024,
    ):
        if type(max_steps) is not int or not 0 < max_steps <= 1_000_000:
            raise ValueError("max_steps must be in 1..1000000")
        if type(max_stack_bytes) is not int or not 16 <= max_stack_bytes <= 1024 * 1024:
            raise ValueError("max_stack_bytes must be in 16..1048576")
        if (
            not callable(getattr(target, "set_timeout", None))
            or getattr(target, "_timeout_timer", None) is None
        ):
            raise ValueError("target must have its owned-process wall timeout armed")
        self.target = target
        self.syscall_policy = syscall_policy
        self.max_steps = max_steps
        self.max_stack_bytes = max_stack_bytes
        self.identity = self._identify()

    def _identify(self) -> VDSOIdentity:
        maps = [m for m in self.target.mappings() if getattr(m, "name", "") == "[vdso]"]
        if len(maps) != 1:
            raise VDSOError("Expected exactly one owned [vdso] mapping")
        m = maps[0]
        if not (m.read and m.execute and not m.write and m.private):
            raise VDSOError("Unexpected [vdso] permissions")
        image = self.target.read_memory(m.start, m.end - m.start)
        if len(image) != m.end - m.start:
            raise VDSOError("Incomplete [vdso] image read")
        symbol = parse_clock_symbol(image)
        return VDSOIdentity(m.start, m.end, hashlib.sha256(image).hexdigest(), symbol)

    def _verify_identity(self) -> None:
        matches = [m for m in self.target.mappings() if getattr(m, "name", "") == "[vdso]"]
        if len(matches) != 1:
            raise VDSOError("Owned [vdso] mapping changed")
        mapping = matches[0]
        image = self.target.read_memory(mapping.start, mapping.end - mapping.start)
        if (
            mapping.start != self.identity.start
            or mapping.end != self.identity.end
            or not mapping.read
            or mapping.write
            or not mapping.execute
            or not mapping.private
            or len(image) != mapping.end - mapping.start
            or hashlib.sha256(image).hexdigest() != self.identity.sha256
        ):
            raise VDSOError("Owned vDSO image identity changed")

    def preflight(self, pre) -> ClockGettimeToken:
        self._verify_identity()
        if getattr(pre.arch, "archname", None) != "aarch64":
            raise VDSOError("Only native AArch64 vDSO is supported")
        r = pre.registers
        entry = self.identity.start + self.identity.symbol.offset
        if r.get("PC") != entry:
            raise VDSOError("Not at the exact vDSO clock symbol entry")
        clock_id_arg = r.get("X0")
        output = r.get("X1")
        sp, lr = r.get("SP"), r.get("X30")
        if type(clock_id_arg) is not int or not 0 <= clock_id_arg < 1 << 64:
            raise VDSOError("Invalid clockid_t argument")
        # clockid_t is an AArch64 32-bit signed ABI argument; preserve its
        # exact low-word representation (including negative dynamic clock IDs).
        clock_id = clock_id_arg & 0xFFFFFFFF
        if type(output) is not int or output % 8:
            raise VDSOError("timespec output must be 8-byte aligned")
        outmap = _mapping(pre.mappings, output)
        if (
            outmap is None
            or "w" not in _permission(outmap, output)
            or "r" not in _permission(outmap, output)
            or not getattr(outmap, "private", False)
            or output + 16 > getattr(outmap, "end", 0)
        ):
            raise VDSOError("timespec output lacks contiguous private rw permissions")
        returnmap = _mapping(pre.mappings, lr) if type(lr) is int else None
        target_path = getattr(self.target, "binary", None)
        if (
            returnmap is None
            or "x" not in _permission(returnmap, lr)
            or "[vdso]" == getattr(returnmap, "name", "")
            or getattr(returnmap, "name", "") != target_path
        ):
            raise VDSOError("LR must be within the executable target ELF caller mapping")
        stack = _mapping(pre.mappings, sp) if type(sp) is int else None
        if (
            stack is None
            or "w" not in _permission(stack, sp)
            or not getattr(stack, "private", False)
            or sp % 16
        ):
            raise VDSOError("SP must be aligned private writable stack")
        names = self._CALLEE_SAVED
        saved = tuple(
            (n, r[n] & ((1 << 64) - 1) if n.startswith("V") else r[n]) for n in names if n in r
        )
        if len(saved) != len(names):
            raise VDSOError("Prestate omits AAPCS64 preserved FPCR/TLS/register evidence")
        return ClockGettimeToken(
            entry,
            lr,
            sp,
            clock_id,
            output,
            saved,
            stack.start,
            stack.end,
            self.identity,
        )

    def _service_syscall_sites(self) -> tuple[int, ...]:
        """Identify the symbol's SVC sites and reject recognized indirect branches.

        This is boundary metadata for a named OS-service contract, not an
        instruction trace or proof that every possible internal diversion is observed.
        """
        start = self.identity.start + self.identity.symbol.offset
        end = start + self.identity.symbol.size
        code = self.target.read_memory(start, self.identity.symbol.size)
        if len(code) != self.identity.symbol.size or len(code) % 4:
            raise VDSOError("Malformed AArch64 vDSO function instruction image")
        svc_sites = []
        for offset in range(0, len(code), 4):
            pc = start + offset
            word = int.from_bytes(code[offset : offset + 4], "little")
            target = None
            if word & 0x7C000000 == 0x14000000:  # B / BL imm26
                imm = word & 0x03FFFFFF
                if imm & (1 << 25):
                    imm -= 1 << 26
                target = pc + (imm << 2)
            elif word & 0xFF000010 == 0x54000000:  # B.cond imm19
                imm = (word >> 5) & 0x7FFFF
                if imm & (1 << 18):
                    imm -= 1 << 19
                target = pc + (imm << 2)
            elif word & 0x7E000000 == 0x34000000:  # CBZ/CBNZ imm19
                imm = (word >> 5) & 0x7FFFF
                if imm & (1 << 18):
                    imm -= 1 << 19
                target = pc + (imm << 2)
            elif word & 0x7E000000 == 0x36000000:  # TBZ/TBNZ imm14
                imm = (word >> 5) & 0x3FFF
                if imm & (1 << 13):
                    imm -= 1 << 14
                target = pc + (imm << 2)
            if target is not None and (target < start or target >= end or target % 4):
                raise VDSOError("vDSO direct control-flow target escapes pinned symbol")
            if word == 0xD65F03C0:  # RET X30; runtime LR checked at return
                continue
            if word & 0xFFFFFC1F in (0xD61F0000, 0xD63F0000):
                raise VDSOError("Indirect vDSO branch/call is not permitted")
            if word & 0xFFFFFC1F == 0xD65F0000:
                raise VDSOError("Only RET X30 is permitted in vDSO service")
            if word & 0xFFE00000 == 0xD4000000:
                if word != 0xD4000001:
                    raise VDSOError("Only SVC #0 is permitted in vDSO service")
                svc_sites.append(pc)
        return tuple(svc_sites)

    def _continue_guarded(
        self,
        token: ClockGettimeToken,
        svc_sites: tuple[int, ...],
        initial_stdout: bytes,
        initial_stderr: bytes,
    ) -> tuple[int, int, int]:
        """Continue between service boundaries; this is not an internal PC trace."""
        process = getattr(self.target, "_target", None)
        if process is None or not all(
            callable(getattr(process, name, None))
            for name in (
                "run",
                "execution_outcome",
                "read_pc",
                "set_breakpoint",
                "remove_breakpoint",
            )
        ):
            raise VDSOError("Owned LLDB target lacks guarded native-continuation API")
        sbtarget = getattr(process, "target", None)
        if sbtarget is None or not callable(getattr(sbtarget, "GetNumBreakpoints", None)):
            raise VDSOError("Cannot establish exclusive ownership of LLDB breakpoints")
        if sbtarget.GetNumBreakpoints() != 0:
            raise VDSOError("Refusing to run with pre-existing/unowned LLDB breakpoints")
        sites = tuple(dict.fromkeys((token.return_pc, *svc_sites)))
        original_bytes = {}
        for address in sites:
            mapping = _mapping(self.target.mappings(), address)
            if mapping is None or not mapping.execute:
                raise VDSOError("Breakpoint site is outside validated executable code mappings")
            if address != token.return_pc and not (
                self.identity.start + self.identity.symbol.offset
                <= address
                < self.identity.start + self.identity.symbol.offset + self.identity.symbol.size
            ):
                raise VDSOError("SVC breakpoint is outside validated vDSO function code")
            raw = self.target.read_memory(address, 4)
            if len(raw) != 4:
                raise VDSOError("Incomplete original instruction at breakpoint site")
            original_bytes[address] = raw

        breakpoints = {}

        def restore_and_verify():
            failures = []
            for address, breakpoint in tuple(breakpoints.items()):
                try:
                    process.remove_breakpoint(breakpoint)
                except Exception as error:  # cleanup must attempt every owned breakpoint
                    failures.append(f"remove {address:#x}: {error}")
                finally:
                    breakpoints.pop(address, None)
            for address, expected in original_bytes.items():
                try:
                    if self.target.read_memory(address, 4) != expected:
                        failures.append(f"original bytes not restored at {address:#x}")
                except Exception as error:
                    failures.append(f"verify {address:#x}: {error}")
            if failures:
                raise VDSOError(
                    "Breakpoint cleanup/restoration verification failed: " + "; ".join(failures)
                )

        def install_all():
            for address in sites:
                breakpoints[address] = process.set_breakpoint(address)

        syscalls = events = 0
        min_sp = token.sp
        try:
            install_all()
            for _ in range(self.max_steps):
                process.run()
                outcome = process.execution_outcome()
                if (
                    getattr(outcome.state, "value", None) != "stopped"
                    or outcome.stop_signal is not None
                ):
                    raise VDSOError("Unexpected signal or exit during native vDSO continuation")
                self.target.refresh_output()
                if (
                    bytes(getattr(self.target, "stdout", b"")) != initial_stdout
                    or bytes(getattr(self.target, "stderr", b"")) != initial_stderr
                ):
                    raise VDSOError("vDSO unexpectedly changed stdout/stderr")
                observed = self.target.read_registers()
                observed_sp = observed.get("SP")
                if (
                    type(observed_sp) is not int
                    or observed_sp % 16
                    or observed_sp > token.sp
                    or observed_sp < token.stack_start
                    or token.sp - observed_sp > self.max_stack_bytes
                ):
                    raise VDSOError("vDSO SP escaped aligned bounded downward stack window")
                min_sp = min(min_sp, observed_sp)
                pc = observed.get("PC")
                events += 1
                if pc == token.return_pc:
                    restore_and_verify()
                    return syscalls, events, min_sp
                if pc not in svc_sites:
                    raise VDSOError("Native continuation stopped outside verified SVC/return sites")
                restore_and_verify()
                pre = _capture(self.target)
                call = (
                    self.syscall_policy.preflight(pre) if self.syscall_policy is not None else None
                )
                if call is None or call.op != "clock_gettime":
                    raise VDSOError("Only NativeLinuxPolicy clock_gettime SVC is allowed")
                stepped = self.target.step()
                if (
                    getattr(getattr(stepped, "state", None), "value", None) != "stopped"
                    or getattr(stepped, "stop_signal", None) is not None
                ):
                    raise VDSOError("Unexpected signal or exit during vDSO clock syscall")
                self.target.refresh_output()
                if (
                    bytes(getattr(self.target, "stdout", b"")) != initial_stdout
                    or bytes(getattr(self.target, "stderr", b"")) != initial_stderr
                ):
                    raise VDSOError("vDSO unexpectedly changed stdout/stderr")
                post = _capture(self.target)
                self.syscall_policy.validate(pre, post, NativeStep("instruction"), call)
                syscalls += 1
                install_all()
            raise VDSOError("vDSO service exceeded guarded continuation budget")
        finally:
            if breakpoints:
                restore_and_verify()

    def execute(self, token: ClockGettimeToken) -> ClockGettimeResult:
        self._verify_identity()
        if (
            token.identity != self.identity
            or token.entry != self.identity.start + self.identity.symbol.offset
        ):
            raise VDSOError("Stale or forged vDSO service token")
        regs = self.target.read_registers()
        if (
            regs.get("PC") != token.entry
            or (regs.get("X0", -1) & 0xFFFFFFFF) != token.clock_id
            or regs.get("X1") != token.output
            or regs.get("SP") != token.sp
            or regs.get("X30") != token.return_pc
        ):
            raise VDSOError("Live call state does not match the preflight token")
        if any(
            (regs.get(name, -1) & ((1 << 64) - 1) if name.startswith("V") else regs.get(name))
            != value
            for name, value in token.saved
        ):
            raise VDSOError("Live preserved-register state differs from preflight token")
        live_maps = self.target.mappings()
        outputmap = _mapping(live_maps, token.output)
        if (
            outputmap is None
            or token.output % 8
            or token.output + 16 > outputmap.end
            or not outputmap.private
            or not outputmap.read
            or not outputmap.write
        ):
            raise VDSOError("Preflight timespec output permissions are stale")
        returnmap = _mapping(live_maps, token.return_pc)
        if returnmap is None or not returnmap.execute or getattr(returnmap, "name", "") == "[vdso]":
            raise VDSOError("Preflight caller return mapping is stale")
        stackmap = _mapping(live_maps, token.sp)
        if (
            stackmap is None
            or stackmap.start != token.stack_start
            or stackmap.end != token.stack_end
            or not stackmap.private
            or not stackmap.write
            or not stackmap.read
        ):
            raise VDSOError("Preflight stack mapping is stale")
        refresh = getattr(self.target, "refresh_output", None)
        if not callable(refresh):
            raise VDSOError("Target cannot refresh stdout/stderr boundary evidence")
        refresh()
        initial = _capture(self.target)
        initial_maps = tuple(initial.mappings)
        initial_stdout = bytes(getattr(self.target, "stdout", b""))
        initial_stderr = bytes(getattr(self.target, "stderr", b""))
        svc_sites = self._service_syscall_sites()
        internal_syscalls, continuation_events, min_sp = self._continue_guarded(
            token, svc_sites, initial_stdout, initial_stderr
        )
        self._verify_identity()
        refresh()
        if (
            bytes(getattr(self.target, "stdout", b"")) != initial_stdout
            or bytes(getattr(self.target, "stderr", b"")) != initial_stderr
        ):
            raise VDSOError("vDSO unexpectedly changed stdout/stderr")
        regs = self.target.read_registers()
        if (
            regs.get("PC") != token.return_pc
            or regs.get("SP") != token.sp
            or regs.get("X30") != token.return_pc
        ):
            raise VDSOError("vDSO return PC/SP/LR ABI mismatch")
        if regs.get("X0") != 0:
            raise VDSOError("vDSO clock service did not return success")
        if any(
            (regs.get(name, -1) & ((1 << 64) - 1) if name.startswith("V") else regs.get(name))
            != value
            for name, value in token.saved
        ):
            raise VDSOError("vDSO clobbered AAPCS64 preserved register/profile state")
        if tuple(self.target.mappings()) != initial_maps:
            raise VDSOError("vDSO changed memory mappings")
        after = _capture(self.target)
        # Stores are permitted only to the declared timespec and bounded stack
        # scratch. This is a boundary diff, not a claim to observe same-value stores.
        changed = []
        for base, before_bytes in initial.memory.items():
            after_bytes = after.memory.get(base)
            if after_bytes is None or len(after_bytes) != len(before_bytes):
                raise VDSOError("vDSO changed private-memory snapshot layout")
            changed.extend(
                base + i for i, (a, b) in enumerate(zip(before_bytes, after_bytes)) if a != b
            )
        if any(
            not (token.output <= a < token.output + 16) and not (min_sp <= a < token.sp)
            for a in changed
        ):
            raise VDSOError("vDSO wrote outside output and bounded private-stack scratch")
        scratch = sorted(a for a in changed if min_sp <= a < token.sp)
        scratch_ranges = []
        for address in scratch:
            if scratch_ranges and address == scratch_ranges[-1][1]:
                scratch_ranges[-1] = (scratch_ranges[-1][0], address + 1)
            else:
                scratch_ranges.append((address, address + 1))
        # Output is deliberately sampled only after all control/ABI/memory checks.
        m = _mapping(after.mappings, token.output)
        if m is None or token.output + 16 > m.end or not m.private or not m.read or not m.write:
            raise VDSOError("timespec output mapping changed or is not private rw")
        raw = self.target.read_memory(token.output, 16)
        if len(raw) != 16:
            raise VDSOError("Incomplete vDSO timespec output")
        nsec = int.from_bytes(raw[8:16], "little", signed=True)
        if not 0 <= nsec < 1_000_000_000:
            raise VDSOError("vDSO returned an invalid timespec nanosecond field")
        return ClockGettimeResult(
            token.clock_id,
            token.output,
            raw,
            continuation_events,
            internal_syscalls,
            tuple(scratch_ranges),
        )
