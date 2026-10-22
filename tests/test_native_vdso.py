from __future__ import annotations

import struct
from types import SimpleNamespace
from typing import cast

import pytest

from focaccia.native.vdso import NativeVDSOClockGettime, VDSOError, parse_clock_symbol


def synthetic_vdso(*, machine=183, version="LINUX_2.6.39"):
    """Minimal bounded ELF64 image sufficient for the vDSO symbol parser."""
    image = bytearray(0x440)
    image[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<H", image, 16, 3)
    struct.pack_into("<H", image, 18, machine)
    struct.pack_into("<Q", image, 40, 0x80)
    struct.pack_into("<HHH", image, 58, 64, 7, 6)
    dynstr = b"\0__kernel_clock_gettime\0" + version.encode() + b"\0"
    nameoff = 1
    versionoff = len(b"\0__kernel_clock_gettime\0")
    shstr = b"\0.text\0.dynstr\0.dynsym\0.gnu.version\0.gnu.version_d\0.shstrtab\0"
    shname = lambda name: shstr.index(name.encode() + b"\0")
    sections = [
        (0, 0, 0, 0, 0, 0, 0),
        (shname(".text"), 1, 4, 0x340, 0x340, 0xC0, 0),
        (shname(".dynstr"), 3, 0, 0, 0x240, len(dynstr), 0),
        (shname(".dynsym"), 11, 0, 0, 0x280, 48, 1),
        (shname(".gnu.version"), 0x6FFFFFFF, 0, 0, 0x2C0, 4, 2),
        (shname(".gnu.version_d"), 0x6FFFFFFD, 0, 0, 0x2D0, 28, 1),
        (shname(".shstrtab"), 3, 0, 0, 0x2F0, len(shstr), 0),
    ]
    image[0x240 : 0x240 + len(dynstr)] = dynstr
    # Null dynsym followed by global function symbol in executable section 1.
    struct.pack_into("<IBBHQQ", image, 0x298, nameoff, 0x12, 2, 1, 0x340, 32)
    struct.pack_into("<HH", image, 0x2C0, 0, 2)
    struct.pack_into("<HHHHIII", image, 0x2D0, 1, 0, 2, 1, 0, 20, 0)
    struct.pack_into("<II", image, 0x2E4, versionoff, 0)
    image[0x2F0 : 0x2F0 + len(shstr)] = shstr
    for i, (name, typ, flags, addr, off, size, link) in enumerate(sections):
        entsize = 24 if i == 3 else 2 if i == 4 else 0
        struct.pack_into(
            "<IIQQQQIIQQ",
            image,
            0x80 + i * 64,
            name,
            typ,
            flags,
            addr,
            off,
            size,
            link,
            0,
            8,
            entsize,
        )
    return bytes(image)


def test_parse_exact_clock_symbol_identity():
    symbol = parse_clock_symbol(synthetic_vdso())
    assert (symbol.name, symbol.version, symbol.offset, symbol.size) == (
        "__kernel_clock_gettime",
        "LINUX_2.6.39",
        0x340,
        32,
    )


@pytest.mark.parametrize(
    "image",
    [
        synthetic_vdso(machine=62),
        synthetic_vdso(version="LINUX_2.6.38"),
        b"not-elf",
        synthetic_vdso()[:100],
    ],
)
def test_rejects_nonmatching_or_malformed_vdso(image):
    with pytest.raises(VDSOError):
        parse_clock_symbol(image)


class Mapping:
    def __init__(self, start, end, name, *, read, write, execute, private=True):
        self.start, self.end, self.name = start, end, name
        self.read, self.write, self.execute, self.private = read, write, execute, private


class FakeLLDB:
    def __init__(self, owner):
        self.owner = owner
        self.target = SimpleNamespace(GetNumBreakpoints=lambda: len(self.breakpoints))
        self.breakpoints = {}
        self.next_id = 1
        self.outcome = SimpleNamespace(state=SimpleNamespace(value="stopped"), stop_signal=None)

    def set_breakpoint(self, address):
        ident = self.next_id
        self.next_id += 1
        self.breakpoints[ident] = address
        return ident

    def remove_breakpoint(self, ident):
        self.breakpoints.pop(ident)

    def run(self):
        pc = self.owner.read_registers()["PC"]
        if pc not in self.breakpoints.values():
            self.outcome = self.owner.step()

    def execution_outcome(self):
        return self.outcome

    def read_pc(self):
        return self.owner.read_registers()["PC"]


class FakeTarget:
    def __init__(self):
        self.image: bytes | bytearray = synthetic_vdso()
        self.maps = (
            Mapping(0x10000, 0x10400, "[vdso]", read=True, write=False, execute=True),
            Mapping(0x4000, 0x5000, "/test/program", read=True, write=False, execute=True),
            Mapping(0x6000, 0x7000, "[stack]", read=True, write=True, execute=False),
            Mapping(0x8000, 0x9000, "[heap]", read=True, write=True, execute=False),
        )
        self.binary = "/test/program"
        self._timeout_timer = object()
        self.stdout = self.stderr = b""
        self.registers = {}
        self._target = FakeLLDB(self)

    def mappings(self):
        return self.maps

    def read_memory(self, address, size):
        if 0x10000 <= address < 0x10400:
            offset = address - 0x10000
            return self.image[offset : offset + size]
        if address == 0x47FC and size == 4:
            return struct.pack("<I", 0xD63F0040)  # BLR X2
        if 0x4000 <= address < 0x5000:
            return bytes(size)
        raise AssertionError("unexpected read")

    def set_timeout(self, seconds):
        raise AssertionError("timeout should already be armed")

    def refresh_output(self):
        pass

    def read_registers(self):
        return dict(self.registers)

    def step(self):
        self.registers["PC"] = 0x4800
        self.registers["X0"] = 0
        return SimpleNamespace(state=SimpleNamespace(value="stopped"), stop_signal=None)


def snapshot(target, **overrides):
    registers = {"PC": 0x10340, "SP": 0x6800, "X0": 0, "X1": 0x8100, "X30": 0x4800}
    registers.update({f"X{i}": i for i in range(19, 30)})
    registers.update({f"V{i}": i | (0x1234 << 64) for i in range(8, 16)})
    registers.update(FPCR=0x1000000, TPIDR=0x12345678)
    registers.update(overrides)
    return SimpleNamespace(
        arch=SimpleNamespace(archname="aarch64"),
        registers=registers,
        mappings=target.maps,
        memory={},
    )


def test_observer_preflight_requires_exact_entry_output_return_and_stack():
    target = FakeTarget()
    observer = NativeVDSOClockGettime(target)
    token = observer.preflight(snapshot(target))
    assert token.entry == 0x10340
    assert token.return_pc == 0x4800
    assert token.clock_id == 0
    assert token.output == 0x8100
    assert token.stack_start == 0x6000
    assert token.stack_end == 0x7000
    for bad in (
        snapshot(target, PC=0x10344),
        snapshot(target, X1=0x8FF8),
        snapshot(target, X30=0x10340),
        snapshot(target, SP=0x6801),
    ):
        with pytest.raises(VDSOError):
            observer.preflight(bad)


def test_observer_returns_only_after_guarded_return_and_memory_checks(monkeypatch):
    from focaccia.native import vdso
    from focaccia.native.spec_validate import NativeSnapshot

    target = FakeTarget()
    observer = NativeVDSOClockGettime(target)
    before = snapshot(target)
    token = observer.preflight(before)
    timespec = (123).to_bytes(8, "little", signed=True) + (456).to_bytes(8, "little", signed=True)
    target.registers = dict(before.registers)
    target.registers["PC"] = token.entry
    target.registers["X1"] = token.output
    target.stdout = b""
    memory = {0x8000: bytes(0x1000), 0x6000: bytes(0x1000)}
    cast(SimpleNamespace, target).memory = memory

    def read_memory(address, size):
        if 0x10000 <= address < 0x10400:
            offset = address - 0x10000
            return target.image[offset : offset + size]
        if address == token.output:
            return timespec[:size]
        if address == token.return_pc:
            return bytes(4)
        raise AssertionError(f"unexpected native read at {address:#x}")

    def step():
        target.registers["PC"] = token.return_pc
        target.registers["X0"] = 0
        memory[0x8000] = timespec + bytes(0x1000 - 16)
        return SimpleNamespace(state=SimpleNamespace(value="stopped"), stop_signal=None)

    target.read_registers = lambda: dict(target.registers)
    target.read_memory = read_memory
    target.step = step
    target.stdout = b""
    maps = target.maps
    native = NativeSnapshot(
        before.arch, target.registers, memory, maps, "full-boundary-memory-diff", b"", b""
    )
    monkeypatch.setattr(vdso, "_capture", lambda _target: native)
    result = observer.execute(token)
    assert result.timespec == timespec
    assert result.environment_output
    assert result.vdso_internals_instruction_spec_checked is False
    assert result.service_contract_not_instruction_proof is True
    assert result.internal_pc_trace_available is False
    assert result.boundary_only_memory_evidence is True
    assert result.continuation_events == 1
    assert result.internal_syscall_count == 0
    assert result.stack_scratch_ranges == ()


@pytest.mark.parametrize(
    "register,value",
    [
        ("PC", 0x4800),
        ("X0", 1),
        ("X1", 0x8000),
        ("SP", 0x6810),
        ("X30", 0x4810),
        ("X19", 99),
        ("V8", 99),
        ("FPCR", 0),
        ("TPIDR", 0),
    ],
)
def test_execute_rejects_stale_or_forged_initial_state(register, value):
    target = FakeTarget()
    observer = NativeVDSOClockGettime(target)
    token = observer.preflight(snapshot(target))
    target.registers = dict(snapshot(target).registers)
    target.registers[register] = value
    target.read_registers = lambda: dict(target.registers)
    with pytest.raises(VDSOError, match="Live call state|Live preserved-register"):
        observer.execute(token)


def test_observer_rejects_unexpected_control_flow_or_bad_stack(monkeypatch):
    from focaccia.native import vdso
    from focaccia.native.spec_validate import NativeSnapshot

    target = FakeTarget()
    observer = NativeVDSOClockGettime(target)
    before = snapshot(target)
    token = observer.preflight(before)
    target.registers = dict(before.registers)
    target.registers["PC"] = token.entry
    target.registers["X1"] = token.output
    target.stdout = b""
    target.read_registers = lambda: dict(target.registers)
    target.read_memory = lambda address, size: (
        target.image[address - 0x10000 : address - 0x10000 + size]
        if 0x10000 <= address < 0x10400
        else bytes(size)
    )
    target.step = lambda: (
        target.registers.update(PC=0x4000)
        or SimpleNamespace(state=SimpleNamespace(value="stopped"), stop_signal=None)
    )
    native = NativeSnapshot(
        before.arch,
        target.registers,
        {0x8000: bytes(0x1000), 0x6000: bytes(0x1000)},
        target.maps,
        "full-boundary-memory-diff",
        b"",
        b"",
    )
    monkeypatch.setattr(vdso, "_capture", lambda _target: native)
    with pytest.raises(VDSOError, match="outside verified SVC/return sites"):
        observer.execute(token)


@pytest.mark.parametrize("bad_sp", [0x6810, 0x5FF0, 0x6780])
def test_observer_rejects_stack_growth_above_or_beyond_bounds(monkeypatch, bad_sp):
    from focaccia.native import vdso
    from focaccia.native.spec_validate import NativeSnapshot

    target = FakeTarget()
    observer = NativeVDSOClockGettime(target, max_stack_bytes=64)
    before = snapshot(target)
    token = observer.preflight(before)
    target.registers = dict(before.registers)
    target.read_registers = lambda: dict(target.registers)
    target.read_memory = lambda address, size: (
        target.image[address - 0x10000 : address - 0x10000 + size]
        if 0x10000 <= address < 0x10400
        else bytes(size)
    )
    target.step = lambda: (
        target.registers.update(PC=token.return_pc, SP=bad_sp, X0=0)
        or SimpleNamespace(state=SimpleNamespace(value="stopped"), stop_signal=None)
    )
    target.refresh_output = lambda: None
    native = NativeSnapshot(
        before.arch,
        target.registers,
        {0x8000: bytes(0x1000), 0x6000: bytes(0x1000)},
        target.maps,
        "full-boundary-memory-diff",
        b"",
        b"",
    )
    monkeypatch.setattr(vdso, "_capture", lambda _target: native)
    with pytest.raises(VDSOError, match="SP escaped"):
        observer.execute(token)


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_observer_refreshes_and_rejects_output_at_each_step(monkeypatch, stream):
    from focaccia.native import vdso
    from focaccia.native.spec_validate import NativeSnapshot

    target = FakeTarget()
    observer = NativeVDSOClockGettime(target)
    before = snapshot(target)
    token = observer.preflight(before)
    target.registers = dict(before.registers)
    target.read_registers = lambda: dict(target.registers)
    target.read_memory = lambda address, size: (
        target.image[address - 0x10000 : address - 0x10000 + size]
        if 0x10000 <= address < 0x10400
        else bytes(size)
    )
    target.stdout = target.stderr = b""
    calls = 0

    def refresh():
        nonlocal calls
        calls += 1
        if calls == 2:
            setattr(target, stream, b"changed")

    target.refresh_output = refresh
    target.step = lambda: (
        target.registers.update(PC=token.return_pc, X0=0)
        or SimpleNamespace(state=SimpleNamespace(value="stopped"), stop_signal=None)
    )
    native = NativeSnapshot(
        before.arch,
        target.registers,
        {0x8000: bytes(0x1000), 0x6000: bytes(0x1000)},
        target.maps,
        "full-boundary-memory-diff",
        b"",
        b"",
    )
    monkeypatch.setattr(vdso, "_capture", lambda _target: native)
    with pytest.raises(VDSOError, match="stdout/stderr"):
        observer.execute(token)
    assert calls >= 2


def test_observer_rejects_signal_on_internal_clock_syscall(monkeypatch):
    from focaccia.native import vdso
    from focaccia.native.spec_validate import NativeSnapshot

    class Policy:
        def preflight(self, _pre):
            return SimpleNamespace(op="clock_gettime")

        def validate(self, *_args):
            raise AssertionError("signal must reject before syscall validation")

    target = FakeTarget()
    target.image = bytearray(target.image)
    target.image[0x340:0x344] = b"\x01\x00\x00\xd4"
    target.image = bytes(target.image)
    observer = NativeVDSOClockGettime(target, syscall_policy=Policy())
    before = snapshot(target)
    token = observer.preflight(before)
    target.registers = dict(before.registers)
    target.registers["PC"] = token.entry
    target.read_registers = lambda: dict(target.registers)
    target.read_memory = lambda address, size: (
        target.image[address - 0x10000 : address - 0x10000 + size]
        if 0x10000 <= address < 0x10400
        else bytes(size)
    )
    target.refresh_output = lambda: None
    target.step = lambda: SimpleNamespace(state=SimpleNamespace(value="stopped"), stop_signal=11)
    native = NativeSnapshot(
        before.arch,
        target.registers,
        {0x8000: bytes(0x1000), 0x6000: bytes(0x1000)},
        target.maps,
        "full-boundary-memory-diff",
        b"",
        b"",
    )
    monkeypatch.setattr(vdso, "_capture", lambda _target: native)
    with pytest.raises(VDSOError, match="signal or exit during vDSO clock syscall"):
        observer.execute(token)


def _ready_fake_execution(monkeypatch):
    from focaccia.native import vdso
    from focaccia.native.spec_validate import NativeSnapshot

    target = FakeTarget()
    observer = NativeVDSOClockGettime(target)
    before = snapshot(target)
    token = observer.preflight(before)
    target.registers = dict(before.registers)
    target.read_registers = lambda: dict(target.registers)
    target.refresh_output = lambda: None
    calls = []
    native = NativeSnapshot(
        before.arch, target.registers, {}, target.maps, "full-boundary-memory-diff", b"", b""
    )
    monkeypatch.setattr(vdso, "_capture", lambda _target: calls.append(1) or native)
    return target, observer, token, calls


def test_observer_rejects_preexisting_unowned_breakpoint(monkeypatch):
    target, observer, token, _ = _ready_fake_execution(monkeypatch)
    target._target.breakpoints[99] = 0x4000
    with pytest.raises(VDSOError, match="pre-existing/unowned"):
        observer.execute(token)


def test_breakpoint_cleanup_failure_prevents_postcapture(monkeypatch):
    target, observer, token, captures = _ready_fake_execution(monkeypatch)
    original_remove = target._target.remove_breakpoint

    def fail_remove(ident):
        original_remove(ident)
        raise RuntimeError("deliberate cleanup failure")

    target._target.remove_breakpoint = fail_remove
    with pytest.raises(VDSOError, match="cleanup/restoration verification failed"):
        observer.execute(token)
    assert len(captures) == 1  # only the pre-boundary capture occurred


def test_breakpoint_original_bytes_must_be_restored_before_postcapture(monkeypatch):
    target, observer, token, captures = _ready_fake_execution(monkeypatch)
    original_read = target.read_memory
    corrupted = False

    def read_after_corruption(address, size):
        if corrupted and address == token.return_pc:
            return b"\\x01" * size
        return original_read(address, size)

    target.read_memory = read_after_corruption
    original_remove = target._target.remove_breakpoint

    def corrupt_after_remove(ident):
        nonlocal corrupted
        original_remove(ident)
        corrupted = True

    target._target.remove_breakpoint = corrupt_after_remove
    with pytest.raises(VDSOError, match="original bytes not restored"):
        observer.execute(token)
    assert len(captures) == 1


def test_observer_rejects_caller_frame_clobber_above_entry_sp(monkeypatch):
    from focaccia.native import vdso
    from focaccia.native.spec_validate import NativeSnapshot

    target = FakeTarget()
    observer = NativeVDSOClockGettime(target)
    before = snapshot(target)
    token = observer.preflight(before)
    target.registers = dict(before.registers)
    target.stdout = target.stderr = b""
    target.read_registers = lambda: dict(target.registers)
    target.read_memory = lambda address, size: (
        target.image[address - 0x10000 : address - 0x10000 + size]
        if 0x10000 <= address < 0x10400
        else bytes(size)
    )
    memory = {0x8000: bytes(0x1000), 0x6000: bytes(0x1000)}

    def step():
        target.registers.update(PC=token.return_pc, X0=0)
        stack = bytearray(memory[0x6000])
        stack[token.sp + 8 - 0x6000] = 1
        memory[0x6000] = bytes(stack)
        return SimpleNamespace(state=SimpleNamespace(value="stopped"), stop_signal=None)

    target.step = step
    target.refresh_output = lambda: None
    monkeypatch.setattr(
        vdso,
        "_capture",
        lambda _target: NativeSnapshot(
            before.arch,
            dict(target.registers),
            dict(memory),
            target.maps,
            "full-boundary-memory-diff",
            b"",
            b"",
        ),
    )
    with pytest.raises(VDSOError, match="outside output and bounded private-stack"):
        observer.execute(token)
