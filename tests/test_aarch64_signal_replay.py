from __future__ import annotations

from collections.abc import Callable, Mapping

import pytest

from focaccia.arch import aarch64
from focaccia.deterministic import (
    ExtraRegisterState,
    KnownMemoryRange,
    MemoryWrite,
    SignalDescriptor,
    SignalEvent,
    SyscallEvent,
)
from focaccia.qemu.aarch64 import (
    AARCH64_FPSIMD_CONTEXT_SIZE,
    AARCH64_FPSIMD_MAGIC,
    AARCH64_RT_SIGFRAME_SIZE,
    AArch64KernelSigaction,
)
from focaccia.qemu.replay import AArch64ReplayEngine
from focaccia.qemu.syscall import ReplayEventError, UnsupportedReplayEffect
from focaccia.snapshot import ProgramState, ReadableProgramState


ARCH = aarch64.ArchAArch64("little")
FRAME_ADDRESS = 0x700000
HANDLER_ADDRESS = 0x5000
RESTORER_ADDRESS = 0x6000
THREAD_ID = 77


class FakeSignalTarget:
    arch = ARCH

    def __init__(
        self,
        registers: Mapping[str, int],
        *,
        execute: Callable[[FakeSignalTarget], ReadableProgramState | None] | None = None,
        reject_extra: bool = False,
    ):
        self.state = ProgramState(self.arch)
        for register, value in registers.items():
            self.state.write_register(register, value)
        self.execute = execute
        self.reject_extra = reject_extra
        self.mutations: list[tuple[str, int, bytes | int]] = []
        self.extra_writes: list[ExtraRegisterState] = []

    def current_state(self) -> ReadableProgramState:
        return self.state

    def skip(self, new_pc: int) -> None:
        self.mutations.append(("pc", new_pc, new_pc))
        self.state.write_register("pc", new_pc)

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
        if self.reject_extra:
            raise UnsupportedReplayEffect("fixture backend rejects extra state")
        self.extra_writes.append(extra_registers)

    def execute_replay_instruction(self) -> ReadableProgramState | None:
        if self.execute is None:
            raise AssertionError("Unexpected execution.")
        return self.execute(self)

    def is_exited(self) -> bool:
        return False


def nt_fpr(seed: int) -> ExtraRegisterState:
    raw = bytearray(528)
    for index in range(32):
        raw[index * 16 : (index + 1) * 16] = (
            seed + index
        ).to_bytes(16, "little")
    raw[512:516] = (0x100 + seed).to_bytes(4, "little")
    raw[516:520] = (0x200 + seed).to_bytes(4, "little")
    return ExtraRegisterState(ARCH, "aarch64-nt-fpr-v1", bytes(raw))


def interrupted_registers() -> dict[str, int]:
    registers = {f"x{index}": 0x1000 + index for index in range(31)}
    registers.update({"sp": 0x800000, "pc": 0x4000, "cpsr": 0x600003C5})
    return registers


def make_frame(
    registers: Mapping[str, int],
    extra: ExtraRegisterState,
    siginfo: bytes,
    *,
    extension_magic: int = 0,
) -> bytes:
    frame = bytearray(AARCH64_RT_SIGFRAME_SIZE + 16)
    frame[:128] = siginfo
    ucontext = 128
    frame[ucontext + 16 : ucontext + 40] = bytes(range(24))
    frame[ucontext + 40 : ucontext + 48] = bytes(8)
    mcontext = ucontext + 176
    for index in range(31):
        offset = mcontext + 8 + index * 8
        frame[offset : offset + 8] = registers[f"x{index}"].to_bytes(8, "little")
    frame[mcontext + 256 : mcontext + 264] = registers["sp"].to_bytes(8, "little")
    frame[mcontext + 264 : mcontext + 272] = registers["pc"].to_bytes(8, "little")
    frame[mcontext + 272 : mcontext + 280] = registers["cpsr"].to_bytes(8, "little")

    fpsimd = mcontext + 288
    frame[fpsimd : fpsimd + 4] = AARCH64_FPSIMD_MAGIC.to_bytes(4, "little")
    frame[fpsimd + 4 : fpsimd + 8] = AARCH64_FPSIMD_CONTEXT_SIZE.to_bytes(
        4, "little"
    )
    frame[fpsimd + 8 : fpsimd + 12] = extra.read_register("fpsr").to_bytes(
        4, "little"
    )
    frame[fpsimd + 12 : fpsimd + 16] = extra.read_register("fpcr").to_bytes(
        4, "little"
    )
    for index in range(32):
        offset = fpsimd + 16 + index * 16
        frame[offset : offset + 16] = extra.read_register(f"v{index}").to_bytes(
            16, "little"
        )
    next_record = fpsimd + AARCH64_FPSIMD_CONTEXT_SIZE
    frame[next_record : next_record + 4] = extension_magic.to_bytes(4, "little")
    frame[AARCH64_RT_SIGFRAME_SIZE : AARCH64_RT_SIGFRAME_SIZE + 8] = registers[
        "x29"
    ].to_bytes(8, "little")
    frame[AARCH64_RT_SIGFRAME_SIZE + 8 : AARCH64_RT_SIGFRAME_SIZE + 16] = registers[
        "x30"
    ].to_bytes(8, "little")
    return bytes(frame)


def make_signal_pair(
    *,
    include_handler_extra: bool = True,
    extension_magic: int = 0,
) -> tuple[SignalEvent, SignalEvent, bytes, ExtraRegisterState]:
    before = interrupted_registers()
    pre_extra = nt_fpr(1)
    handler_extra = nt_fpr(100)
    siginfo = (10).to_bytes(4, "little", signed=True) + bytes(124)
    descriptor = SignalDescriptor(ARCH, siginfo, True, "userHandler")
    frame = make_frame(before, pre_extra, siginfo, extension_magic=extension_magic)
    after = dict(before)
    after.update(
        {
            "x0": 10,
            "x1": FRAME_ADDRESS,
            "x2": FRAME_ADDRESS + 128,
            "x29": FRAME_ADDRESS + AARCH64_RT_SIGFRAME_SIZE,
            "x30": RESTORER_ADDRESS,
            "sp": FRAME_ADDRESS,
            "pc": HANDLER_ADDRESS,
        }
    )
    pre = SignalEvent(
        before["pc"],
        THREAD_ID,
        ARCH,
        before,
        (),
        signal_number=descriptor,
        event_count=20,
        extra_registers=pre_extra,
    )
    post = SignalEvent(
        after["pc"],
        THREAD_ID,
        ARCH,
        after,
        (
            MemoryWrite(
                THREAD_ID,
                FRAME_ADDRESS,
                len(frame),
                (KnownMemoryRange(0, frame),),
                (),
            ),
        ),
        signal_handler=descriptor,
        event_count=21,
        extra_registers=handler_extra if include_handler_extra else None,
    )
    return pre, post, frame, handler_extra


def configured_engine() -> AArch64ReplayEngine:
    engine = AArch64ReplayEngine(ARCH)
    engine.state.signal_actions[10] = AArch64KernelSigaction(
        HANDLER_ADDRESS,
        AArch64KernelSigaction.SA_SIGINFO | AArch64KernelSigaction.SA_RESTORER,
        RESTORER_ADDRESS,
        0,
    )
    return engine


def test_aarch64_signal_frame_delivery_and_rt_sigreturn_round_trip():
    pre, post, frame, handler_extra = make_signal_pair()
    target = FakeSignalTarget(pre.registers)
    engine = configured_engine()

    state = engine.replay_signal(target, pre, post)

    assert state is target.state
    assert target.extra_writes == [handler_extra]
    assert target.state.read_memory(FRAME_ADDRESS, len(frame)) == frame
    assert target.state.read_pc() == HANDLER_ADDRESS
    assert target.state.read_register("sp") == FRAME_ADDRESS
    assert len(engine.state.signal_frames) == 1

    return_pre_registers = {
        **{f"x{index}": post.registers[f"x{index}"] for index in range(31)},
        "sp": post.registers["sp"],
        "pc": RESTORER_ADDRESS,
        "cpsr": post.registers["cpsr"],
        "x8": 139,
    }
    return_post_registers = interrupted_registers()
    return_pre = SyscallEvent(
        RESTORER_ADDRESS,
        THREAD_ID,
        ARCH,
        return_pre_registers,
        (),
        ARCH,
        139,
        "enteringPtrace",
        False,
        event_count=22,
    )
    return_post = SyscallEvent(
        interrupted_registers()["pc"],
        THREAD_ID,
        ARCH,
        return_post_registers,
        (),
        ARCH,
        139,
        "exiting",
        False,
        event_count=23,
    )
    for register, value in return_pre_registers.items():
        target.state.write_register(register, value)

    def restore(context: FakeSignalTarget) -> ReadableProgramState:
        for register, value in return_post_registers.items():
            context.state.write_register(register, value)
        return context.state

    target.execute = restore
    result = engine.replay_syscall(target, return_pre, return_post)

    assert result is target.state
    assert target.state.read_pc() == interrupted_registers()["pc"]
    assert engine.state.signal_frames == []
    assert engine.state.signal_mask == 0
    assert engine.state.altstack == bytes(range(24))


def test_aarch64_signal_rejects_missing_handler_extra_state_before_mutation():
    pre, post, _frame, _handler_extra = make_signal_pair(include_handler_extra=False)
    target = FakeSignalTarget(pre.registers)

    with pytest.raises(ReplayEventError, match="lacks recorded NT_FPR"):
        configured_engine().replay_signal(target, pre, post)

    assert target.mutations == []
    assert target.extra_writes == []


def test_aarch64_signal_rejects_sve_extension_before_mutation():
    pre, post, _frame, _handler_extra = make_signal_pair(extension_magic=0x53564501)
    target = FakeSignalTarget(pre.registers)

    with pytest.raises(ReplayEventError, match="SVE/SME"):
        configured_engine().replay_signal(target, pre, post)

    assert target.mutations == []
    assert target.extra_writes == []


def test_backend_extra_state_rejection_precedes_frame_or_gpr_mutation():
    pre, post, _frame, _handler_extra = make_signal_pair()
    target = FakeSignalTarget(pre.registers, reject_extra=True)

    with pytest.raises(UnsupportedReplayEffect, match="fixture backend"):
        configured_engine().replay_signal(target, pre, post)

    assert target.mutations == []
