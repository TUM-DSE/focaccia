import importlib
import sys
from types import ModuleType
from typing import Any, cast

from focaccia.arch import aarch64
from focaccia.native import lldb_target
from focaccia.native.lldb_target import LLDBConcreteTarget


class FakeMemoryView:
    def __init__(self, data: bytes):
        self.data = data

    def tobytes(self) -> bytes:
        return self.data


class FakeProcess:
    def __init__(self, data: bytes):
        self.data = data

    def ReadMemory(self, _addr: int, size: int, _error) -> bytes:
        return self.data[:size]

    def read_memory(self, _addr: int, size: int) -> FakeMemoryView:
        return FakeMemoryView(self.data[:size])


def test_lldb_memory_bytes_stay_in_address_order_on_big_endian(monkeypatch):
    class FakeError:
        success = True

    raw = b"\x01\x02\x03\x04"
    monkeypatch.setattr(lldb_target.lldb, "SBError", FakeError)
    target = object.__new__(LLDBConcreteTarget)
    target.arch = aarch64.ArchAArch64("big")
    target.process = cast(Any, FakeProcess(raw))

    assert target.read_memory(0x1000, len(raw)) == raw


def test_gdb_memory_bytes_stay_in_address_order_on_big_endian(monkeypatch):
    gdb = ModuleType("gdb")
    for name in ("Breakpoint", "Frame", "Inferior", "Value"):
        setattr(gdb, name, object)
    setattr(gdb, "MemoryError", RuntimeError)
    monkeypatch.setitem(sys.modules, "gdb", gdb)
    sys.modules.pop("focaccia.qemu.target", None)

    target_module = importlib.import_module("focaccia.qemu.target")
    state = target_module.GDBProgramState(
        cast(Any, FakeProcess(b"\x10\x20\x30\x40")),
        cast(Any, object()),
        aarch64.ArchAArch64("big"),
    )

    assert state.read_register("XZR") == 0
    assert state.read_memory(0x2000, 4) == b"\x10\x20\x30\x40"
