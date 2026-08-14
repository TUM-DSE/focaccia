from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from focaccia.arch import x86
from focaccia.deterministic import (
    ExtraRegisterState,
    KnownMemoryRange,
    MemoryWrite,
    SignalDescriptor,
    SignalEvent,
    SyscallEvent,
)
from focaccia.qemu.replay import (
    X86ReplayEngine,
    validate_x86_partial_signal_extra_transition,
)
from focaccia.qemu.syscall import (
    CoverageOutcome,
    MaterializedMemoryWrite,
    ReplayEventError,
    ReplayReconciliationError,
    UnsupportedReplayEffect,
)
from focaccia.qemu.x86 import (
    X86_64_FPSTATE_MIN_SIZE,
    X86_64_FPSTATE_SW_RESERVED_OFFSET,
    X86_64_FP_XSTATE_MAGIC1,
    X86_64_FP_XSTATE_MAGIC2,
    X86_64_KERNEL_SIGSET_SIZE,
    X86_64_PRETCODE_OFFSET,
    X86_64_SIGCONTEXT_CS_OFFSET,
    X86_64_SIGCONTEXT_FPSTATE_OFFSET,
    X86_64_SIGCONTEXT_FS_OFFSET,
    X86_64_SIGCONTEXT_GS_OFFSET,
    X86_64_SIGCONTEXT_REGISTER_OFFSETS,
    X86_64_SIGCONTEXT_SIZE,
    X86_64_SIGCONTEXT_SS_OFFSET,
    X86_64_SIGINFO_SIZE,
    X86_64_UCONTEXT_MCONTEXT_OFFSET,
    X86_64_UCONTEXT_OFFSET,
    X86_64_UCONTEXT_SIGMASK_OFFSET,
    X86_64_UCONTEXT_STACK_OFFSET,
    X86KernelSigaction,
    X86RecordedSignalFrame,
)
from focaccia.snapshot import ProgramState, ReadableProgramState


MASK64 = (1 << 64) - 1
TID = 101
SIGNAL = 10
SIGNAL_PC = 0x401234
HANDLER_PC = 0x402000
RESTORER_PC = 0x403000
FRAME_ADDRESS = 0x700000000008
UCONTEXT_ADDRESS = FRAME_ADDRESS + 8
SIGINFO_ADDRESS = FRAME_ADDRESS + 312
FPSTATE_ADDRESS = FRAME_ADDRESS + 440
FRAME_SIZE = 440 + 512
SAVED_MASK = 0x20
STACK_DELTA = 0x200000


class FakeSignalTarget:
    arch = x86.ArchX86()

    def __init__(
        self,
        registers: Mapping[str, int],
        *,
        execute: Callable[[FakeSignalTarget], ReadableProgramState | None] | None = None,
    ):
        self.state = ProgramState(self.arch)
        for register, value in registers.items():
            self.state.write_register(register, value)
        self.execute_callback = execute
        self.mutations: list[tuple[str, int, bytes | int]] = []
        self.steps = 0
        self.fp_resets = 0
        self.extra_writes: list[ExtraRegisterState] = []
        self.exited = False

    def current_state(self) -> ReadableProgramState:
        return self.state

    def skip(self, new_pc: int) -> None:
        self.mutations.append(("pc", new_pc, new_pc))
        self.state.write_register("rip", new_pc)

    def write_target_register(self, register: str, value: int) -> None:
        self.mutations.append(("register", 0, value))
        self.state.write_register(register, value)

    def write_target_memory(self, address: int, data: bytes) -> None:
        self.mutations.append(("memory", address, bytes(data)))
        self.state.write_memory(address, data)

    def write_signal_handler_extra_registers(
        self,
        extra_registers: ExtraRegisterState,
    ) -> None:
        assert extra_registers.format == "x86-xsave-v1"
        self.extra_writes.append(extra_registers)
        self.fp_resets += 1

    def execute_replay_instruction(
        self, expected_pc: int | None = None
    ) -> ReadableProgramState | None:
        del expected_pc
        self.steps += 1
        if self.execute_callback is None:
            raise AssertionError("Signal fake was not configured to execute.")
        return self.execute_callback(self)

    def is_exited(self) -> bool:
        return self.exited


def saved_registers() -> dict[str, int]:
    return {
        "r8": 0x108,
        "r9": 0x109,
        "r10": 0x110,
        "r11": 0x111,
        "r12": 0x112,
        "r13": 0x113,
        "r14": 0x114,
        "r15": 0x115,
        "rdi": 0x1D1,
        "rsi": 0x1D2,
        "rbp": 0x1B0,
        "rbx": 0x1B1,
        "rdx": 0x1D3,
        "rax": 0x1A0,
        "rcx": 0x1C0,
        "rsp": FRAME_ADDRESS + 0x2000,
        "rip": SIGNAL_PC,
        "rflags": 0x246,
        "cs": 0x33,
        "ss": 0x2B,
    }


def siginfo_bytes(signal_number: int = SIGNAL) -> bytes:
    data = bytearray(X86_64_SIGINFO_SIZE)
    data[0:4] = signal_number.to_bytes(4, "little", signed=True)
    data[4:8] = (7).to_bytes(4, "little", signed=True)
    data[8:12] = (-6).to_bytes(4, "little", signed=True)
    data[16:20] = TID.to_bytes(4, "little")
    data[20:24] = (1000).to_bytes(4, "little")
    data[64:72] = b"SIGINFO!"
    return bytes(data)


def build_frame(
    registers: Mapping[str, int],
    *,
    signal_number: int = SIGNAL,
    saved_mask: int = SAVED_MASK,
    restorer: int = RESTORER_PC,
) -> bytes:
    frame = bytearray(FRAME_SIZE)
    frame[X86_64_PRETCODE_OFFSET : X86_64_PRETCODE_OFFSET + 8] = restorer.to_bytes(8, "little")
    mcontext = X86_64_UCONTEXT_OFFSET + X86_64_UCONTEXT_MCONTEXT_OFFSET
    for register, offset in X86_64_SIGCONTEXT_REGISTER_OFFSETS.items():
        frame[mcontext + offset : mcontext + offset + 8] = registers[register].to_bytes(8, "little")
    frame[mcontext + X86_64_SIGCONTEXT_CS_OFFSET : mcontext + X86_64_SIGCONTEXT_CS_OFFSET + 2] = (
        registers["cs"].to_bytes(2, "little")
    )
    frame[mcontext + X86_64_SIGCONTEXT_GS_OFFSET : mcontext + X86_64_SIGCONTEXT_GS_OFFSET + 2] = (
        0
    ).to_bytes(2, "little")
    frame[mcontext + X86_64_SIGCONTEXT_SS_OFFSET : mcontext + X86_64_SIGCONTEXT_SS_OFFSET + 2] = (
        registers["ss"].to_bytes(2, "little")
    )
    frame[
        mcontext + X86_64_SIGCONTEXT_FPSTATE_OFFSET : mcontext
        + X86_64_SIGCONTEXT_FPSTATE_OFFSET
        + 8
    ] = FPSTATE_ADDRESS.to_bytes(8, "little")
    mask_offset = X86_64_UCONTEXT_OFFSET + X86_64_UCONTEXT_SIGMASK_OFFSET
    frame[mask_offset : mask_offset + 8] = saved_mask.to_bytes(8, "little")
    siginfo_offset = SIGINFO_ADDRESS - FRAME_ADDRESS
    frame[siginfo_offset : siginfo_offset + X86_64_SIGINFO_SIZE] = siginfo_bytes(signal_number)
    # A zero magic1 denotes the complete legacy 512-byte FXSAVE area. Fill a
    # few bytes to prove replay preserves opaque FP state rather than rebuilding it.
    fp_offset = FPSTATE_ADDRESS - FRAME_ADDRESS
    frame[fp_offset : fp_offset + 8] = b"FPSTATE!"
    frame[
        fp_offset + X86_64_FPSTATE_SW_RESERVED_OFFSET : fp_offset
        + X86_64_FPSTATE_SW_RESERVED_OFFSET
        + 4
    ] = (0).to_bytes(4, "little")
    return bytes(frame)


def full_write(address: int, data: bytes) -> MemoryWrite:
    return MemoryWrite(
        TID,
        address,
        len(data),
        (KnownMemoryRange(0, data),),
        (),
        is_conservative=True,
    )


def handler_xsave() -> ExtraRegisterState:
    raw = bytearray(512)
    raw[24:28] = (0x1F80).to_bytes(4, "little")
    raw[160:176] = bytes(range(16))
    return ExtraRegisterState(x86.ArchX86(), "x86-xsave-v1", bytes(raw))


def test_partial_signal_extra_transition_accepts_xmm_and_sse_metadata_changes():
    before = bytearray(576)
    before[24:28] = (0x1F80).to_bytes(4, "little")
    before[28:32] = (0xFFFF).to_bytes(4, "little")
    before[160:176] = bytes(range(16))
    before[512:520] = (0x203).to_bytes(8, "little")
    after = bytearray(before)
    after[28:32] = bytes(4)
    after[160:176] = bytes(16)
    after[512:520] = (0x201).to_bytes(8, "little")
    previous = ExtraRegisterState(x86.ArchX86(), "x86-xsave-v1", bytes(before))
    handler = ExtraRegisterState(x86.ArchX86(), "x86-xsave-v1", bytes(after))

    assert validate_x86_partial_signal_extra_transition(previous, handler) is handler


def test_partial_signal_extra_transition_rejects_changed_x87_state():
    before = handler_xsave()
    after = bytearray(before.raw)
    after[32] = 1
    handler = ExtraRegisterState(x86.ArchX86(), "x86-xsave-v1", bytes(after))

    with pytest.raises(UnsupportedReplayEffect, match="x87 or extended XSAVE"):
        validate_x86_partial_signal_extra_transition(before, handler)


def make_signal_pair(
    *,
    frame: bytes | None = None,
    signal_number: int = SIGNAL,
    include_handler_extra: bool = True,
    saved_overrides: Mapping[str, int] | None = None,
) -> tuple[SignalEvent, SignalEvent, dict[str, int]]:
    arch = x86.ArchX86()
    saved = {**saved_registers(), **(saved_overrides or {})}
    info = siginfo_bytes(signal_number)
    descriptor = SignalDescriptor(arch, info, False, "userHandler")
    pre = SignalEvent(
        SIGNAL_PC,
        TID,
        arch,
        saved,
        (),
        signal_number=descriptor,
        event_count=20,
        extra_registers=handler_xsave(),
    )
    post_registers = {
        **saved,
        "rip": HANDLER_PC,
        "rsp": FRAME_ADDRESS,
        "rax": 0,
        "rdi": signal_number,
        "rsi": SIGINFO_ADDRESS,
        "rdx": UCONTEXT_ADDRESS,
    }
    post = SignalEvent(
        HANDLER_PC,
        TID,
        arch,
        post_registers,
        (full_write(FRAME_ADDRESS, frame or build_frame(saved, signal_number=signal_number)),),
        signal_handler=descriptor,
        event_count=21,
        extra_registers=handler_xsave() if include_handler_extra else None,
    )
    return pre, post, saved


def make_sigreturn_pair(
    saved: Mapping[str, int],
) -> tuple[SyscallEvent, SyscallEvent]:
    arch = x86.ArchX86()
    entry_pc = RESTORER_PC + 7
    entry = {
        **saved,
        "rip": entry_pc,
        "rsp": FRAME_ADDRESS + 8,
        "rax": 15,
    }
    pre = SyscallEvent(
        entry_pc,
        TID,
        arch,
        entry,
        (),
        arch,
        15,
        "entering",
        False,
        event_count=22,
    )
    post = SyscallEvent(
        saved["rip"],
        TID,
        arch,
        saved,
        (),
        arch,
        15,
        "exiting",
        False,
        event_count=23,
    )
    return pre, post


def configure_action(engine: X86ReplayEngine, *, signal_number: int = SIGNAL) -> None:
    engine.state.signal_actions[signal_number] = X86KernelSigaction(
        HANDLER_PC,
        X86KernelSigaction.SA_SIGINFO | X86KernelSigaction.SA_RESTORER,
        RESTORER_PC,
        1 << 11,
    )
    engine.state.signal_mask = SAVED_MASK


def test_signal_uapi_offset_fixture_matches_python_layout():
    fixture = json.loads(
        (Path(__file__).parent / "fixtures/replay/x86_64-signal-uapi.json").read_text()
    )

    assert fixture["pretcode_offset"] == X86_64_PRETCODE_OFFSET
    assert fixture["ucontext_offset"] == X86_64_UCONTEXT_OFFSET
    assert fixture["ucontext_stack_offset"] == X86_64_UCONTEXT_STACK_OFFSET
    assert fixture["ucontext_mcontext_offset"] == X86_64_UCONTEXT_MCONTEXT_OFFSET
    assert fixture["sigcontext_size"] == X86_64_SIGCONTEXT_SIZE
    assert fixture["ucontext_sigmask_offset"] == X86_64_UCONTEXT_SIGMASK_OFFSET
    assert fixture["kernel_sigset_size"] == X86_64_KERNEL_SIGSET_SIZE
    assert fixture["siginfo_size"] == X86_64_SIGINFO_SIZE
    assert fixture["sigcontext_register_offsets"] == dict(X86_64_SIGCONTEXT_REGISTER_OFFSETS)
    assert fixture["sigcontext_segment_offsets"] == {
        "cs": X86_64_SIGCONTEXT_CS_OFFSET,
        "gs": X86_64_SIGCONTEXT_GS_OFFSET,
        "fs": X86_64_SIGCONTEXT_FS_OFFSET,
        "ss": X86_64_SIGCONTEXT_SS_OFFSET,
    }
    assert fixture["sigcontext_fpstate_offset"] == X86_64_SIGCONTEXT_FPSTATE_OFFSET
    assert fixture["fpstate_min_size"] == X86_64_FPSTATE_MIN_SIZE


def test_recorded_signal_frame_preserves_number_mask_context_restorer_and_fpstate():
    pre, post, saved = make_signal_pair()
    materialized = tuple(MaterializedMemoryWrite.from_recorded(write) for write in post.mem_writes)

    frame = X86RecordedSignalFrame.from_events(
        pre,
        post,
        materialized,
        action_uses_siginfo=True,
        action_restarts_syscalls=False,
    )

    assert frame.signal_number == SIGNAL
    assert frame.signal_mask == SAVED_MASK
    assert frame.altstack == bytes(24)
    assert frame.restorer_address == RESTORER_PC
    assert frame.fpstate_address == FPSTATE_ADDRESS
    assert frame.fpstate_size == X86_64_FPSTATE_MIN_SIZE
    assert frame.saved_registers["rip"] == saved["rip"]
    assert frame.saved_registers["rsp"] == saved["rsp"]


def test_rt_sigaction_replays_real_handler_mask_and_restorer_metadata():
    arch = x86.ArchX86()
    action_address = 0x5000
    flags = X86KernelSigaction.SA_SIGINFO | X86KernelSigaction.SA_RESTORER
    action_bytes = (
        HANDLER_PC.to_bytes(8, "little")
        + flags.to_bytes(8, "little")
        + RESTORER_PC.to_bytes(8, "little")
        + (1 << 11).to_bytes(8, "little")
    )
    pre_registers = {
        "rip": 0x4000,
        "rax": 13,
        "rcx": 0,
        "r11": 0x246,
        "rdi": SIGNAL,
        "rsi": action_address,
        "rdx": 0,
        "r10": 8,
        "r8": 0,
        "r9": 0,
    }
    post_registers = {
        **pre_registers,
        "rip": 0x4002,
        "rax": 0,
        "rcx": 0x4002,
    }
    pre = SyscallEvent(
        0x4000,
        TID,
        arch,
        pre_registers,
        (),
        arch,
        13,
        "entering",
        False,
        event_count=18,
    )
    post = SyscallEvent(
        0x4002,
        TID,
        arch,
        post_registers,
        (),
        arch,
        13,
        "exiting",
        False,
        event_count=19,
    )
    target = FakeSignalTarget(pre_registers)
    target.state.write_memory(action_address, action_bytes)
    engine = X86ReplayEngine(arch)

    engine.replay_syscall(target, pre, post)

    action = engine.state.snapshot().signal_actions[SIGNAL]
    assert action.handler == HANDLER_PC
    assert action.restorer == RESTORER_PC
    assert action.mask == 1 << 11


def test_signal_frame_validates_and_preserves_variable_xstate_tail():
    pre, _post, saved = make_signal_pair()
    extended_size = 836
    frame = bytearray(build_frame(saved))
    frame.extend(bytes(extended_size - X86_64_FPSTATE_MIN_SIZE))
    fp_offset = FPSTATE_ADDRESS - FRAME_ADDRESS
    sw = fp_offset + X86_64_FPSTATE_SW_RESERVED_OFFSET
    frame[sw : sw + 4] = X86_64_FP_XSTATE_MAGIC1.to_bytes(4, "little")
    frame[sw + 4 : sw + 8] = extended_size.to_bytes(4, "little")
    frame[sw + 8 : sw + 16] = (0x7).to_bytes(8, "little")
    frame[sw + 16 : sw + 20] = (extended_size - 4).to_bytes(4, "little")
    frame[-4:] = X86_64_FP_XSTATE_MAGIC2.to_bytes(4, "little")
    _unused, post, _saved = make_signal_pair(frame=bytes(frame))
    materialized = tuple(MaterializedMemoryWrite.from_recorded(write) for write in post.mem_writes)

    parsed = X86RecordedSignalFrame.from_events(
        pre,
        post,
        materialized,
        action_uses_siginfo=True,
        action_restarts_syscalls=False,
    )

    assert parsed.fpstate_size == extended_size
    assert materialized[0].data[-4:] == X86_64_FP_XSTATE_MAGIC2.to_bytes(4, "little")


def test_signal_delivery_replays_exact_frame_and_abi_registers_without_hardcoding_sigint():
    pre, post, saved = make_signal_pair(signal_number=SIGNAL)
    target = FakeSignalTarget(saved)
    engine = X86ReplayEngine(target.arch)
    configure_action(engine)

    state = engine.replay_signal(target, pre, post)

    assert state is not None
    assert target.steps == 0
    assert target.fp_resets == 1
    assert target.extra_writes == [post.extra_registers]
    assert state.read_pc() == HANDLER_PC
    assert state.read_register("rdi") == SIGNAL
    assert state.read_register("rsi") == SIGINFO_ADDRESS
    assert state.read_register("rdx") == UCONTEXT_ADDRESS
    assert state.read_register("rsp") == FRAME_ADDRESS
    assert state.read_memory(FRAME_ADDRESS, FRAME_SIZE) == build_frame(saved)
    assert state.read_memory(FPSTATE_ADDRESS, 8) == b"FPSTATE!"
    snapshot = engine.state.snapshot()
    assert snapshot.signal_depth == 1
    assert snapshot.signal_mask & (1 << (SIGNAL - 1))
    assert snapshot.signal_mask & (1 << 11)
    assert engine.coverage_report().records[-1].outcome is CoverageOutcome.HANDLED


def test_signal_delivery_relocates_recorded_frame_under_live_stack_delta():
    pre, post, saved = make_signal_pair()
    target_saved = {
        **saved,
        "rbp": saved["rbp"] + STACK_DELTA,
        "rsp": saved["rsp"] + STACK_DELTA,
    }
    recorded_frame = build_frame({**saved, "rbp": saved["rbp"]})
    pre, post, _saved = make_signal_pair(frame=recorded_frame)
    target = FakeSignalTarget(target_saved)
    engine = X86ReplayEngine(target.arch)
    configure_action(engine)

    state = engine.replay_signal(target, pre, post)

    target_frame = FRAME_ADDRESS + STACK_DELTA
    assert state is not None
    assert state.read_register("rsp") == target_frame
    assert state.read_register("rsi") == SIGINFO_ADDRESS + STACK_DELTA
    assert state.read_register("rdx") == UCONTEXT_ADDRESS + STACK_DELTA
    mcontext = target_frame + X86_64_UCONTEXT_OFFSET + X86_64_UCONTEXT_MCONTEXT_OFFSET
    assert (
        int.from_bytes(
            state.read_memory(mcontext + X86_64_SIGCONTEXT_REGISTER_OFFSETS["rsp"], 8),
            "little",
        )
        == saved["rsp"] + STACK_DELTA
    )
    assert (
        int.from_bytes(
            state.read_memory(mcontext + X86_64_SIGCONTEXT_REGISTER_OFFSETS["rbp"], 8),
            "little",
        )
        == saved["rbp"] + STACK_DELTA
    )
    assert (
        int.from_bytes(
            state.read_memory(mcontext + X86_64_SIGCONTEXT_FPSTATE_OFFSET, 8),
            "little",
        )
        == FPSTATE_ADDRESS + STACK_DELTA
    )
    assert state.read_memory(SIGINFO_ADDRESS + STACK_DELTA, X86_64_SIGINFO_SIZE) == siginfo_bytes()
    assert state.read_memory(FPSTATE_ADDRESS + STACK_DELTA, 8) == b"FPSTATE!"
    delivered = engine.state.signal_frames[-1]
    assert delivered.target_frame_address == target_frame
    assert delivered.target_saved_registers is not None
    assert delivered.target_saved_registers["rsp"] == saved["rsp"] + STACK_DELTA
    assert delivered.target_saved_registers["rbp"] == saved["rbp"] + STACK_DELTA


def test_signal_relocation_rejects_nonuniform_register_drift_before_writing_frame():
    pre, post, saved = make_signal_pair()
    target = FakeSignalTarget(
        {
            **saved,
            "rsp": saved["rsp"] + STACK_DELTA,
            "rbp": saved["rbp"] + STACK_DELTA + 8,
        }
    )
    engine = X86ReplayEngine(target.arch)
    configure_action(engine)

    with pytest.raises(ReplayReconciliationError, match="not the proven stack relocation"):
        engine.replay_signal(target, pre, post)

    assert target.mutations == []


def test_non_siginfo_signal_replays_opaque_frame_slot_from_recorded_bytes():
    _pre, _post, saved = make_signal_pair()
    frame = bytearray(build_frame(saved))
    siginfo_offset = SIGINFO_ADDRESS - FRAME_ADDRESS
    frame[siginfo_offset : siginfo_offset + X86_64_SIGINFO_SIZE] = bytes(X86_64_SIGINFO_SIZE)
    pre, post, _saved = make_signal_pair(frame=bytes(frame))
    target = FakeSignalTarget(saved)
    engine = X86ReplayEngine(target.arch)
    engine.state.signal_actions[SIGNAL] = X86KernelSigaction(
        HANDLER_PC,
        X86KernelSigaction.SA_RESTORER,
        RESTORER_PC,
        1 << 11,
    )
    engine.state.signal_mask = SAVED_MASK

    state = engine.replay_signal(target, pre, post)

    assert state is not None
    assert state.read_pc() == HANDLER_PC
    assert state.read_register("rdi") == SIGNAL
    assert state.read_memory(SIGINFO_ADDRESS, X86_64_SIGINFO_SIZE) == bytes(X86_64_SIGINFO_SIZE)
    assert engine.coverage_report().records[-1].outcome is CoverageOutcome.HANDLED


def test_siginfo_signal_rejects_frame_descriptor_mismatch():
    _pre, _post, saved = make_signal_pair()
    frame = bytearray(build_frame(saved))
    siginfo_offset = SIGINFO_ADDRESS - FRAME_ADDRESS
    frame[siginfo_offset : siginfo_offset + X86_64_SIGINFO_SIZE] = bytes(X86_64_SIGINFO_SIZE)
    pre, post, _saved = make_signal_pair(frame=bytes(frame))
    target = FakeSignalTarget(saved)
    engine = X86ReplayEngine(target.arch)
    configure_action(engine)

    with pytest.raises(ReplayEventError, match="siginfo differs"):
        engine.replay_signal(target, pre, post)

    assert target.mutations == []


def test_non_restarted_interrupted_syscall_normalizes_saved_rax_to_eintr():
    _pre, _post, saved = make_signal_pair()
    restart_result = (1 << 64) - 512
    interrupted_result = (1 << 64) - 4
    frame_saved = {**saved, "rax": interrupted_result}
    pre, post, _saved = make_signal_pair(
        frame=build_frame(frame_saved),
        saved_overrides={"rax": restart_result},
    )
    target = FakeSignalTarget({**saved, "rax": restart_result})
    engine = X86ReplayEngine(target.arch)
    engine.state.signal_actions[SIGNAL] = X86KernelSigaction(
        HANDLER_PC,
        X86KernelSigaction.SA_SIGINFO | X86KernelSigaction.SA_RESTORER,
        RESTORER_PC,
        1 << 11,
    )
    engine.state.signal_mask = SAVED_MASK

    state = engine.replay_signal(target, pre, post)

    assert state is not None
    assert engine.state.signal_frames[-1].frame.saved_registers["rax"] == interrupted_result


def test_restarted_interrupted_syscall_rejects_saved_rax_normalization():
    _pre, _post, saved = make_signal_pair()
    restart_result = (1 << 64) - 512
    frame_saved = {**saved, "rax": (1 << 64) - 4}
    pre, post, _saved = make_signal_pair(
        frame=build_frame(frame_saved),
        saved_overrides={"rax": restart_result},
    )
    target = FakeSignalTarget({**saved, "rax": restart_result})
    engine = X86ReplayEngine(target.arch)
    engine.state.signal_actions[SIGNAL] = X86KernelSigaction(
        HANDLER_PC,
        X86KernelSigaction.SA_SIGINFO | X86KernelSigaction.SA_RESTORER | 0x10000000,
        RESTORER_PC,
        1 << 11,
    )
    engine.state.signal_mask = SAVED_MASK

    with pytest.raises(ReplayEventError, match="Unsupported interrupted/restarted"):
        engine.replay_signal(target, pre, post)

    assert target.mutations == []


def test_x86_signal_requires_recorded_handler_xsave_before_frame_write():
    pre, post, saved = make_signal_pair(include_handler_extra=False)
    target = FakeSignalTarget(saved)
    engine = X86ReplayEngine(target.arch)
    configure_action(engine)

    with pytest.raises(ReplayEventError, match="lacks recorded XSAVE"):
        engine.replay_signal(target, pre, post)

    assert target.extra_writes == []
    assert target.mutations == []


def test_malformed_fpstate_pointer_is_rejected_before_frame_write():
    _pre, _post, saved = make_signal_pair()
    malformed = bytearray(build_frame(saved))
    pointer_offset = (
        X86_64_UCONTEXT_OFFSET + X86_64_UCONTEXT_MCONTEXT_OFFSET + X86_64_SIGCONTEXT_FPSTATE_OFFSET
    )
    malformed[pointer_offset : pointer_offset + 8] = (FPSTATE_ADDRESS + 1).to_bytes(8, "little")
    pre, post, _saved = make_signal_pair(frame=bytes(malformed))
    target = FakeSignalTarget(saved)
    engine = X86ReplayEngine(target.arch)
    configure_action(engine)

    with pytest.raises(ReplayEventError, match="not 64-byte aligned"):
        engine.replay_signal(target, pre, post)

    assert target.mutations == []
    failed = engine.coverage_report().records[-1]
    assert failed.effect == f"signal:{SIGNAL}"
    assert failed.outcome is CoverageOutcome.FAILED


def test_signal_frame_context_mismatch_is_rejected_instead_of_overwriting_target_state():
    _pre, _post, saved = make_signal_pair()
    malformed = bytearray(build_frame(saved))
    rax_offset = (
        X86_64_UCONTEXT_OFFSET
        + X86_64_UCONTEXT_MCONTEXT_OFFSET
        + X86_64_SIGCONTEXT_REGISTER_OFFSETS["rax"]
    )
    malformed[rax_offset : rax_offset + 8] = (saved["rax"] + 1).to_bytes(8, "little")
    pre, post, _saved = make_signal_pair(frame=bytes(malformed))
    target = FakeSignalTarget(saved)
    engine = X86ReplayEngine(target.arch)
    configure_action(engine)

    with pytest.raises(ReplayEventError, match="context saves rax"):
        engine.replay_signal(target, pre, post)

    assert target.mutations == []


def test_rt_sigreturn_executes_qemu_abi_restore_and_reconciles_all_gprs():
    signal_pre, signal_post, saved = make_signal_pair()
    target = FakeSignalTarget(saved)
    engine = X86ReplayEngine(target.arch)
    configure_action(engine)
    engine.replay_signal(target, signal_pre, signal_post)

    syscall_pre, syscall_post = make_sigreturn_pair(saved)
    for register, value in syscall_pre.registers.items():
        target.state.write_register(register, value)

    def restore(current: FakeSignalTarget) -> ReadableProgramState:
        for register, value in syscall_post.registers.items():
            current.state.write_register(register, value)
        return current.state

    target.execute_callback = restore
    state = engine.replay_syscall(target, syscall_pre, syscall_post)

    assert target.steps == 1
    assert state.read_pc() == SIGNAL_PC
    assert state.read_register("rsp") == saved["rsp"]
    assert state.read_register("rax") == saved["rax"]
    snapshot = engine.state.snapshot()
    assert snapshot.signal_depth == 0
    assert snapshot.signal_mask == SAVED_MASK


def test_relocated_rt_sigreturn_consumes_local_frame_and_reconciles_restored_stack():
    signal_pre, signal_post, saved = make_signal_pair()
    target_saved = {**saved, "rsp": saved["rsp"] + STACK_DELTA}
    target = FakeSignalTarget(target_saved)
    engine = X86ReplayEngine(target.arch)
    configure_action(engine)
    engine.replay_signal(target, signal_pre, signal_post)

    syscall_pre, syscall_post = make_sigreturn_pair(saved)
    for register, value in syscall_pre.registers.items():
        target.state.write_register(register, value)
    target.state.write_register("rsp", FRAME_ADDRESS + STACK_DELTA + 8)

    def restore(current: FakeSignalTarget) -> ReadableProgramState:
        for register, value in syscall_post.registers.items():
            current.state.write_register(register, value)
        current.state.write_register("rsp", saved["rsp"] + STACK_DELTA)
        return current.state

    target.execute_callback = restore
    state = engine.replay_syscall(target, syscall_pre, syscall_post)

    assert target.steps == 1
    assert state.read_pc() == SIGNAL_PC
    assert state.read_register("rsp") == saved["rsp"] + STACK_DELTA
    assert engine.state.snapshot().signal_depth == 0


def test_relocated_rt_sigreturn_accepts_handler_modified_relocated_stack_pointer():
    signal_pre, signal_post, saved = make_signal_pair()
    target_saved = {**saved, "rsp": saved["rsp"] + STACK_DELTA}
    target = FakeSignalTarget(target_saved)
    engine = X86ReplayEngine(target.arch)
    configure_action(engine)
    engine.replay_signal(target, signal_pre, signal_post)

    modified_recorded_rsp = saved["rsp"] - 0x80
    modified_target_rsp = modified_recorded_rsp + STACK_DELTA
    syscall_pre, syscall_post = make_sigreturn_pair(saved)
    post_registers = dict(syscall_post.registers)
    post_registers["RSP"] = modified_recorded_rsp
    syscall_post = SyscallEvent(
        syscall_post.pc,
        syscall_post.tid,
        syscall_post.arch,
        post_registers,
        syscall_post.mem_writes,
        syscall_post.syscall_arch,
        syscall_post.syscall_number,
        syscall_post.syscall_state,
        syscall_post.failed_during_preparation,
        event_count=syscall_post.event_count,
    )
    for register, value in syscall_pre.registers.items():
        target.state.write_register(register, value)
    target.state.write_register("rsp", FRAME_ADDRESS + STACK_DELTA + 8)
    mcontext = (
        FRAME_ADDRESS + STACK_DELTA + X86_64_UCONTEXT_OFFSET + X86_64_UCONTEXT_MCONTEXT_OFFSET
    )
    target.state.write_memory(
        mcontext + X86_64_SIGCONTEXT_REGISTER_OFFSETS["rsp"],
        modified_target_rsp.to_bytes(8, "little"),
    )

    def restore(current: FakeSignalTarget) -> ReadableProgramState:
        for register, value in syscall_post.registers.items():
            current.state.write_register(register, value)
        current.state.write_register("rsp", modified_target_rsp)
        return current.state

    target.execute_callback = restore
    state = engine.replay_syscall(target, syscall_pre, syscall_post)

    assert state.read_register("rsp") == modified_target_rsp
    assert engine.state.snapshot().signal_depth == 0


def test_relocated_rt_sigreturn_rejects_unrelocated_modified_stack_pointer():
    signal_pre, signal_post, saved = make_signal_pair()
    target_saved = {**saved, "rsp": saved["rsp"] + STACK_DELTA}
    target = FakeSignalTarget(target_saved)
    engine = X86ReplayEngine(target.arch)
    configure_action(engine)
    engine.replay_signal(target, signal_pre, signal_post)

    modified_recorded_rsp = saved["rsp"] - 0x80
    syscall_pre, syscall_post = make_sigreturn_pair(saved)
    post_registers = dict(syscall_post.registers)
    post_registers["RSP"] = modified_recorded_rsp
    syscall_post = SyscallEvent(
        syscall_post.pc,
        syscall_post.tid,
        syscall_post.arch,
        post_registers,
        syscall_post.mem_writes,
        syscall_post.syscall_arch,
        syscall_post.syscall_number,
        syscall_post.syscall_state,
        syscall_post.failed_during_preparation,
        event_count=syscall_post.event_count,
    )
    for register, value in syscall_pre.registers.items():
        target.state.write_register(register, value)
    target.state.write_register("rsp", FRAME_ADDRESS + STACK_DELTA + 8)
    mcontext = (
        FRAME_ADDRESS + STACK_DELTA + X86_64_UCONTEXT_OFFSET + X86_64_UCONTEXT_MCONTEXT_OFFSET
    )
    target.state.write_memory(
        mcontext + X86_64_SIGCONTEXT_REGISTER_OFFSETS["rsp"],
        modified_recorded_rsp.to_bytes(8, "little"),
    )

    with pytest.raises(ReplayReconciliationError, match="signal-frame rsp"):
        engine.replay_syscall(target, syscall_pre, syscall_post)

    assert target.steps == 0


def test_rt_sigreturn_rejects_wrong_stack_before_execution():
    signal_pre, signal_post, saved = make_signal_pair()
    target = FakeSignalTarget(saved)
    engine = X86ReplayEngine(target.arch)
    configure_action(engine)
    engine.replay_signal(target, signal_pre, signal_post)
    syscall_pre, syscall_post = make_sigreturn_pair(saved)
    for register, value in syscall_pre.registers.items():
        target.state.write_register(register, value)
    target.state.write_register("rsp", FRAME_ADDRESS + 16)

    with pytest.raises(ReplayEventError, match="rt_sigreturn RSP"):
        engine.replay_syscall(target, syscall_pre, syscall_post)

    assert target.steps == 0


def test_kernel_sigaction_rejects_missing_x86_64_restorer():
    data = (
        HANDLER_PC.to_bytes(8, "little")
        + X86KernelSigaction.SA_SIGINFO.to_bytes(8, "little")
        + (0).to_bytes(8, "little")
        + (0).to_bytes(8, "little")
    )

    with pytest.raises(ReplayEventError, match="require SA_RESTORER"):
        X86KernelSigaction.from_bytes(data)
