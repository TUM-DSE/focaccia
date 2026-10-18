"""Opt-in real-model LOAD/STORE source-residual simulations."""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from focaccia.intel_client import IntelOracle
from focaccia.intel_symbolic import IntelSymbolicBackend, SymbolicIntelLiveModel
from focaccia.snapshot import MemoryAccessError


pytestmark = pytest.mark.skipif(
    not os.environ.get("INTEL_SYMBOLIC_ORACLE"),
    reason="private Intel symbolic exporter opt-in required",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _decoder_module():
    path = Path(os.environ.get("INTEL_SYMBOLIC_DECODER_MODULE", "../tir/scripts/intel_decode.py"))
    spec = importlib.util.spec_from_file_location("intel_symbolic_memory_decoder", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load Intel decoder module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _observations(pc: int, rdi: int, rax: int) -> dict[str, int]:
    values = {name: 0 for name in (
        "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
        "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
    )}
    values.update(RAX=rax, RDI=rdi, RIP=pc, RFLAGS=0x202, FS_BASE=0, GS_BASE=0)
    values.update({f"XMM{i}": 0 for i in range(16)})
    return values


class _Transport:
    def __init__(self, pc, code, data_address, data, data_permission):
        self.pc, self.code = pc, code
        self.data_address, self.data = data_address, data
        self.data_permission = data_permission
        self.data_reads = []
        self.data_permission_queries = []

    def read_memory(self, address, size):
        if address == self.pc:
            return self.code + b"\x90" * max(0, size - len(self.code))
        if self.data_address <= address and address + size <= self.data_address + len(self.data):
            self.data_reads.append((address, size))
            offset = address - self.data_address
            return self.data[offset:offset + size]
        raise MemoryAccessError(address, size, "outside synthetic source-memory fixture")

    def memory_permissions(self, address, size):
        if address == self.pc and size <= len(self.code):
            return 13  # mapped, readable, executable
        if self.data_address <= address and address + size <= self.data_address + len(self.data):
            self.data_permission_queries.append((address, size))
            return self.data_permission
        return 0


def _model(code, observed, data_address, data, data_permission):
    model_path = Path(os.environ.get(
        "INTEL_SYMBOLIC_MODEL", "/tmp/carbonara-usermode-full/typed.json",
    ))
    decoder_bin = Path(os.environ.get(
        "INTEL_SYMBOLIC_DECODER", "/tmp/carbonara-xed/bin/intel-xed-decode",
    ))
    decoder_module = _decoder_module()
    pc = observed["RIP"]
    transport = _Transport(pc, code, data_address, data, data_permission)
    oracle = IntelOracle(os.environ["INTEL_SYMBOLIC_ORACLE"], model_path, timeout=180)
    decoder = decoder_module.Decoder(decoder_bin, timeout=180)
    model = SymbolicIntelLiveModel(
        IntelSymbolicBackend(oracle, _sha256(model_path)), decoder, transport, 99,
        guest_limit=1 << 47,
    )
    model.boundary(observed)
    return model, transport, oracle, decoder


def test_actual_mov_load_uses_lazy_preboundary_bytes_at_fresh_values():
    pc, address = 0x1000, 0x3000
    code = bytes.fromhex("488b07")  # MOV RAX, [RDI]
    samples = [
        (bytes.fromhex("78563412efcdab90"), 0x90abcdef12345678),
        (bytes.fromhex("0100000000000000"), 1),
    ]
    for raw, expected in samples:
        observed = _observations(pc, address, 0)
        model, transport, oracle, decoder = _model(code, observed, address, raw, 9)
        try:
            prediction = model.predict(SimpleNamespace(pc=pc, address=pc, size=1))
            assert prediction.registers["RAX"].value == expected
            assert prediction.registers["RAX"].mask == (1 << 64) - 1
            assert model.memory == {address + i: byte for i, byte in enumerate(raw)}
            assert transport.data_permission_queries
            assert transport.data_reads
        finally:
            decoder.close()
            oracle.close()


def test_actual_mov_load_rejects_nonreadable_page_before_fetch():
    pc, address = 0x1000, 0x3000
    observed = _observations(pc, address, 0)
    model, transport, oracle, decoder = _model(
        bytes.fromhex("488b07"), observed, address, b"12345678", 8,
    )
    try:
        with pytest.raises(MemoryAccessError, match="read permission"):
            model.predict(SimpleNamespace(pc=pc, address=pc, size=1))
        assert not transport.data_reads
    finally:
        decoder.close()
        oracle.close()


def test_actual_mov_store_preserves_order_and_checks_write_permissions():
    pc, address, value = 0x1000, 0x4000, 0x1122334455667788
    observed = _observations(pc, address, value)
    model, transport, oracle, decoder = _model(
        bytes.fromhex("488907"), observed, address, b"\0" * 8, 11,
    )
    try:
        prediction = model.predict(SimpleNamespace(pc=pc, address=pc, size=1))
        assert prediction.ordered_writes == ((address, bytes.fromhex("8877665544332211")),)
        assert prediction.memory == {address: bytes.fromhex("8877665544332211")}
        assert not transport.data_reads
    finally:
        decoder.close()
        oracle.close()

    observed = _observations(pc, address, value)
    model, transport, oracle, decoder = _model(
        bytes.fromhex("488907"), observed, address, b"\0" * 8, 9,
    )
    try:
        with pytest.raises(MemoryAccessError, match="write permission"):
            model.predict(SimpleNamespace(pc=pc, address=pc, size=1))
        assert not transport.data_reads
    finally:
        decoder.close()
        oracle.close()
