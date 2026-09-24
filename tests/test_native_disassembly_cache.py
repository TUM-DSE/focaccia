"""Offline verification-reuse regressions; no debugger or native execution."""

from typing import cast

import pytest

from focaccia.arch import Arch, aarch64, x86
from focaccia.native.lldb_target import LLDBConcreteTarget, ConcreteMemoryError
from focaccia.native.tracer import (
    DisassemblyError,
    _DisassemblyVerificationCache,
    _disassemble_instruction,
)
from focaccia.snapshot import ReadableProgramState
from focaccia.symbolic import DisassemblyContext, Instruction


class CodeTarget:
    def __init__(self, code=b"\x90", text="NOP"):
        self.arch: Arch = x86.ArchX86()
        self.code = code
        self.text = text
        self.reads = 0
        self.text_reads = 0
        self.fail_read = False

    def read_instructions(self, addr, size):
        self.reads += 1
        if self.fail_read:
            raise ConcreteMemoryError("unreadable code")
        offset = addr - 0x1000
        return self.code[offset : offset + size]

    def get_instruction_size(self, pc):
        return len(self.code)

    def get_disassembly(self, pc):
        self.text_reads += 1
        return self.text


def setup(target, capacity=4096):
    ctx = DisassemblyContext(cast(ReadableProgramState, target))
    backend = cast(LLDBConcreteTarget, target)
    cache = _DisassemblyVerificationCache(ctx, backend, capacity)
    return ctx, backend, cache


def count_assembly(monkeypatch):
    calls = []
    original = Instruction.to_bytecode

    def assemble(instruction):
        calls.append((instruction.addr, str(instruction)))
        return original(instruction)

    monkeypatch.setattr(Instruction, "to_bytecode", assemble)
    return calls


def test_verification_reuse_still_decodes_and_reads_current_bytes(monkeypatch):
    calls = count_assembly(monkeypatch)
    target = CodeTarget()
    ctx, backend, cache = setup(target)
    first = _disassemble_instruction(ctx, backend, 0x1000, cache)
    reads = target.reads
    second = _disassemble_instruction(ctx, backend, 0x1000, cache)
    assert second is not first
    assert str(second) == str(first)
    assert target.reads > reads
    assert len(calls) == 1
    # A caller mutating its decoded object cannot corrupt later results.
    first.instr.name = "BROKEN"
    assert str(_disassemble_instruction(ctx, backend, 0x1000, cache)).strip() == "NOP"
    assert len(calls) == 1


def test_verification_reuse_self_modifying_code_and_length(monkeypatch):
    calls = count_assembly(monkeypatch)
    target = CodeTarget()
    ctx, backend, cache = setup(target)
    for code, text in [(b"\x90", "NOP"), (b"\xc3", "RET"), (b"\x66\x90", "NOP")]:
        target.code, target.text = code, text
        instruction = _disassemble_instruction(ctx, backend, 0x1000, cache)
        assert instruction.length == len(code)
        assert instruction.instr.name == text
    assert len(calls) == 3


def test_verification_reuse_alternate_encoding_requires_first_verification(monkeypatch):
    target = CodeTarget(bytes.fromhex("488d542420"), "LEA RDX, [RSP + 0x20]")
    ctx, backend, cache = setup(target)
    calls = []

    def alternate(instruction):
        calls.append(instruction)
        return bytes.fromhex("488d546420")

    monkeypatch.setattr(Instruction, "to_bytecode", alternate)
    for _ in range(2):
        assert _disassemble_instruction(ctx, backend, 0x1000, cache).instr.name == "LEA"
    assert len(calls) == 1
    assert target.text_reads == 1


def test_verification_reuse_changed_bytes_with_identical_decoded_text(monkeypatch):
    calls = count_assembly(monkeypatch)
    target = CodeTarget(bytes.fromhex("488d542420"), "LEA RDX, [RSP + 0x20]")
    ctx, backend, cache = setup(target)
    first = _disassemble_instruction(ctx, backend, 0x1000, cache)
    target.code = bytes.fromhex("488d546420")
    second = _disassemble_instruction(ctx, backend, 0x1000, cache)
    assert (first.addr, first.length, str(first)) == (second.addr, second.length, str(second))
    assert len(calls) == 2


def test_verification_reuse_context_target_and_architecture_isolation(monkeypatch):
    calls = count_assembly(monkeypatch)
    target = CodeTarget()
    ctx, backend, cache = setup(target)
    _disassemble_instruction(ctx, backend, 0x1000, cache)
    other_ctx, other_backend, other_cache = setup(CodeTarget())
    _disassemble_instruction(other_ctx, other_backend, 0x1000, other_cache)
    assert len(calls) == 2
    with pytest.raises(RuntimeError, match="another trace context"):
        _disassemble_instruction(other_ctx, backend, 0x1000, cache)
    with pytest.raises(RuntimeError, match="another trace context"):
        _disassemble_instruction(ctx, other_backend, 0x1000, cache)
    # Even an inconsistent caller changing just one architecture cannot hit.
    for arch in (aarch64.ArchAArch64("little"), aarch64.ArchAArch64("big")):
        target.arch = arch
        _disassemble_instruction(ctx, backend, 0x1000, cache)
    assert len(calls) == 4


def test_verification_reuse_address_context_and_lru_bound(monkeypatch):
    calls = count_assembly(monkeypatch)
    target = CodeTarget(b"\x90\x90\x90")
    ctx, backend, cache = setup(target, capacity=2)
    for pc in (0x1000, 0x1001, 0x1000, 0x1002, 0x1001):
        _disassemble_instruction(ctx, backend, pc, cache)
        assert len(cache._verified) <= 2
    assert [pc for pc, _ in calls] == [0x1000, 0x1001, 0x1002, 0x1001]
    with pytest.raises(ValueError, match="positive capacity"):
        _DisassemblyVerificationCache(ctx, backend, 0)


@pytest.mark.parametrize("failure", ["empty", "memory", "contradiction", "assembly"])
def test_verification_reuse_does_not_cache_errors(monkeypatch, failure):
    target = CodeTarget()
    ctx, backend, cache = setup(target)
    calls = count_assembly(monkeypatch)
    _disassemble_instruction(ctx, backend, 0x1000, cache)
    # A new byte key must reverify, even after success at the same PC.
    target.code = b"\xc3"
    if failure == "memory":
        target.fail_read = True
        target.text = ""
    elif failure == "empty":
        monkeypatch.setattr(
            ctx, "disassemble", lambda pc: (_ for _ in ()).throw(ValueError("empty"))
        )
        target.text = ""
    else:
        target.text = ""
        if failure == "assembly":

            def fail_assembly(instruction):
                raise NotImplementedError("cannot encode")

            monkeypatch.setattr(Instruction, "to_bytecode", fail_assembly)
        else:
            monkeypatch.setattr(Instruction, "to_bytecode", lambda instruction: b"\xcc")
    for _ in range(2):
        with pytest.raises(DisassemblyError):
            _disassemble_instruction(ctx, backend, 0x1000, cache)
    assert len(cache._verified) == 1
    assert len(calls) == 1
    assert target.text_reads >= 2


def test_verification_reuse_keeps_split_lock_prefix_verification(monkeypatch):
    class SplitTarget(CodeTarget):
        def get_instruction_size(self, pc):
            return 1 if pc == 0x1000 else 4

        def get_disassembly(self, pc):
            assert pc == 0x1001
            self.text_reads += 1
            return "CMPXCHG DWORD PTR [R9], ECX"

    target = SplitTarget(bytes.fromhex("f0410fb109"))
    ctx, backend, cache = setup(target)
    calls = []

    def alternate(instruction):
        calls.append(instruction)
        return bytes.fromhex("f0450fb109")

    monkeypatch.setattr(Instruction, "to_bytecode", alternate)
    for _ in range(2):
        instruction = _disassemble_instruction(ctx, backend, 0x1000, cache)
        assert str(instruction).startswith("LOCK CMPXCHG")
        assert instruction.length == 5
    assert len(calls) == target.text_reads == 1


def test_verification_reuse_keeps_rex_mmx_interpretation(monkeypatch):
    calls = count_assembly(monkeypatch)
    target = CodeTarget(bytes.fromhex("4f0f7ec0"), "MOVQ R8, MM0")
    ctx, backend, cache = setup(target)
    for _ in range(2):
        assert str(_disassemble_instruction(ctx, backend, 0x1000, cache)).split() == [
            "MOVQ",
            "R8,",
            "MM0",
        ]
    assert len(calls) == 1
    wrong = Instruction.from_string("MOVD R8D, MM0", target.arch, 0x1000, 4)
    monkeypatch.setattr(ctx, "disassemble", lambda pc: wrong)
    assert _disassemble_instruction(ctx, backend, 0x1000, cache).instr.name == "MOVQ"
    assert len(calls) == 2
    assert len(cache._verified) == 1


def test_verification_reuse_rechecks_changed_interpretation(monkeypatch):
    target = CodeTarget(bytes.fromhex("c5fe6f00"), "VMOVDQU YMM0, YMMWORD PTR [RAX]")
    ctx, backend, cache = setup(target)
    _disassemble_instruction(ctx, backend, 0x1000, cache)
    wrong = Instruction.from_string("REP OUTSD", target.arch, 0x1000, 3)
    monkeypatch.setattr(ctx, "disassemble", lambda pc: wrong)
    for _ in range(2):
        assert _disassemble_instruction(ctx, backend, 0x1000, cache).instr.name == "VMOVDQU"
    assert len(cache._verified) == 1
    assert target.text_reads >= 2
