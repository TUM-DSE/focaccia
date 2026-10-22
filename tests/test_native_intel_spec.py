"""Synthetic-state tests through exact XED and the actual private Intel model."""

from pathlib import Path
import os
from typing import cast

import pytest

from focaccia.arch.x86 import ArchX86
from focaccia.intel_symbolic import knownness_inputs_for_observation
from focaccia.native.intel_spec import IntelNativeOracle
from focaccia.native.spec_validate import NativeSnapshot, _predict_transition

MODEL = Path(os.environ.get("INTEL_MODEL", "/tmp/carbonara-usermode-full/typed.json"))
EVAL = os.environ.get("INTEL_EVAL", "/tmp/carbonara-intel-symbolic-package-final/bin/intel-eval")
XED = os.environ.get("INTEL_XED", "/tmp/carbonara-xed/bin/intel-xed-decode")
pytestmark = pytest.mark.skipif(
    not (MODEL.is_file() and Path(EVAL).is_file() and Path(XED).is_file()),
    reason="private Intel model/XED/evaluator unavailable",
)


class Mapping:
    start, end = 0x1000, 0x2000
    perms = "rwxp"
    read = write = execute = True


def snapshot(code):
    registers = {
        name: 0
        for name in (
            "RAX",
            "RCX",
            "RDX",
            "RBX",
            "RSP",
            "RBP",
            "RSI",
            "RDI",
            *(f"R{i}" for i in range(8, 16)),
            "RIP",
            "RFLAGS",
            *(f"XMM{i}" for i in range(16)),
            "FS_BASE",
            "GS_BASE",
        )
    }
    registers.update(RIP=0x1000, RFLAGS=2, RAX=7, RBX=0x1100)
    image = bytearray(0x1000)
    image[: len(code)] = code
    image[0x100:0x104] = bytes.fromhex("78563412")
    memory = {0x1000: bytes(image)}
    return NativeSnapshot(ArchX86(), registers, memory, (Mapping(),), "full-boundary-memory-diff")


def oracle():
    return IntelNativeOracle(MODEL, EVAL, XED)


def test_model_backed_add_executes_source_residual():
    model = oracle()
    try:
        transform = model(snapshot(bytes.fromhex("4801d8")))  # add rax, rbx
        assert transform is not None
        assert transform.source_owned
        assert transform.range == (0x1000, 0x1003)
        assert "RAX" in transform.changed_regs
        assert "RFLAGS" in transform.changed_regs
        assert model.backend.requests == 1
    finally:
        model.close()


def test_model_backed_load_and_store_use_prestate_memory():
    model = oracle()
    try:
        load = model(snapshot(bytes.fromhex("488b03")))  # mov rax, [rbx]
        assert load is not None
        assert load.source_owned and "RAX" in load.changed_regs
        state = snapshot(bytes.fromhex("488903"))  # mov [rbx], rax
        store = model(state)
        assert store is not None
        assert store.source_owned and store.memory_writes
    finally:
        model.close()


def test_undefined_af_knownness_persists_through_following_instruction():
    model = oracle()
    try:
        pre = snapshot(bytes.fromhex("31ed"))  # xor ebp, ebp makes AF undefined
        masks = knownness_inputs_for_observation(pre.registers)
        model.set_knownness_inputs(masks)
        xor = model(pre)
        assert xor is not None
        first = _predict_transition(xor, pre, masks)
        flags_mask = first.registers.get("RFLAGS")
        assert flags_mask is not None
        af = 1 << 4
        assert not flags_mask.mask & af
        masks["RFLAGS"] = flags_mask.mask
        model.set_knownness_inputs(masks)
        # A subsequent boundary binding must carry the partial RFLAGS mask,
        # rather than recreating all-ones knownness from the concrete value.
        knownness_inputs = model.knownness_inputs
        assert knownness_inputs is not None
        known_flags_mask = knownness_inputs["RFLAGS"]
        assert known_flags_mask == flags_mask.mask
        assert not known_flags_mask & af
    finally:
        model.close()


def test_syscall_source_prestate_is_predicted_before_external_boundary():
    model = oracle()
    try:
        state = snapshot(bytes.fromhex("0f05"))
        regs = dict(state.registers, RAX=1, RDI=1, RSI=0x1100, RDX=4)
        state = NativeSnapshot(
            state.arch, regs, state.memory, state.mappings, "full-boundary-memory-diff"
        )
        unknown_masks = knownness_inputs_for_observation(state.registers)
        unknown_masks["RAX"] = 0
        model.set_knownness_inputs(unknown_masks)
        with pytest.raises(Exception, match="undefined RAX input"):
            model(state)
        model.set_knownness_inputs(knownness_inputs_for_observation(state.registers))
        assert model(state) is None
        assert model.backend.requests == 1
        assert model.pending_syscall_prestate is not None
        model.validate_syscall_prestate(state)
        corrupt = dict(state.registers, RBX=state.registers["RBX"] ^ 1)
        with pytest.raises(Exception, match="SYSCALL source prestate mismatch"):
            model.validate_syscall_prestate(
                NativeSnapshot(
                    state.arch,
                    corrupt,
                    state.memory,
                    state.mappings,
                    "full-boundary-memory-diff",
                )
            )
        wrong_successor = NativeSnapshot(
            state.arch, dict(state.registers, RIP=0x1002), state.memory, state.mappings,
            "full-boundary-memory-diff",
        )
        # This equals the generic SYSCALL ABI length but deliberately differs
        # from the source-projected Next_IP used below.
        assert model.pending_syscall_next_ip == 0x1002  # actual imported source Next_IP
        model.pending_syscall_next_ip = 0x1003  # deliberate wrong source-control negative
        with pytest.raises(Exception, match="source Next_IP mismatch"):
            model.validate_syscall_successor(wrong_successor)
    finally:
        model.close()


def test_rep_source_composes_full_iteration_count_before_native_step():
    model = oracle()
    try:
        state = snapshot(bytes.fromhex("f3a4"))  # rep movsb
        registers = cast(dict[str, int], state.registers)
        registers["RCX"] = 2
        registers["RSI"] = 0x1100
        registers["RDI"] = 0x1110
        transform = model(state)
        assert transform is not None
        assert transform.source_owned
        assert transform.range == (0x1000, 0x1002)
        assert len(transform.memory_writes) == 2
        assert model.instructions == 2  # Do not count the second projection pass again.
        assert model.instruction_hint == {"pc": 0x1000, "iform": "REP_MOVSB"}
    finally:
        model.close()


def test_unsupported_instruction_fails_closed_without_fallback():
    model = oracle()
    try:
        with pytest.raises(Exception):
            model(snapshot(bytes.fromhex("0f0b")))  # UD2 has no assumed semantics
    finally:
        model.close()
