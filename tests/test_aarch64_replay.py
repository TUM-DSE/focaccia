from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from focaccia.arch import aarch64
from focaccia.deterministic import (
    DeterministicLog,
    ExtraRegisterState,
    KnownMemoryRange,
    MemoryWrite,
    OpenedFileDescriptor,
    SignalDescriptor,
    SignalEvent,
    SyscallEvent,
    SyscallExtra,
)
from focaccia.qemu.aarch64 import AARCH64_SYSCALL_POLICIES
from focaccia.qemu.concurrency import UnsupportedConcurrencyError
from focaccia.qemu.replay import AArch64ReplayEngine, make_replay_engine
from focaccia.qemu.syscall import (
    CoverageOutcome,
    ReplayReconciliationError,
    ReplayStrategy,
    UnsupportedReplayEffect,
)
from focaccia.snapshot import ProgramState, ReadableProgramState


MASK64 = (1 << 64) - 1
ARCH = aarch64.ArchAArch64("little")
FIXTURES = Path(__file__).parent / "fixtures/deterministic"


class FakeReplayTarget:
    def __init__(
        self,
        registers: Mapping[str, int],
        memory: Mapping[int, int] | None = None,
        *,
        execute: Callable[[FakeReplayTarget], ReadableProgramState | None] | None = None,
    ):
        self.arch = ARCH
        self.state = ProgramState(self.arch)
        for register, value in registers.items():
            self.state.write_register(register, value)
        if memory:
            for address, value in memory.items():
                self.state.write_memory(address, bytes((value,)))
        self.execute_callback = execute
        self.steps = 0
        self.mutations: list[tuple[str, int, bytes | int]] = []
        self.exited = False

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
        del extra_registers
        raise AssertionError("This syscall-only fake must not receive signal state.")

    def execute_replay_instruction(self) -> ReadableProgramState | None:
        self.steps += 1
        if self.execute_callback is None:
            raise AssertionError("This fake target must not execute a system call.")
        return self.execute_callback(self)

    def is_exited(self) -> bool:
        return self.exited


def full_write(tid: int, address: int, data: bytes) -> MemoryWrite:
    ranges = (KnownMemoryRange(0, data),) if data else ()
    return MemoryWrite(tid, address, len(data), ranges, ())


def make_syscall_pair(
    number: int,
    *,
    tid: int = 101,
    pre_pc: int = 0x4000,
    post_pc: int = 0x4004,
    arguments: Mapping[str, int] | None = None,
    result: int = 0,
    post_writes: tuple[MemoryWrite, ...] = (),
    syscall_extra: SyscallExtra | None = None,
) -> tuple[SyscallEvent, SyscallEvent]:
    pre_values = {
        **{f"x{index}": 0 for index in range(9)},
        "sp": 0x7FFF0000,
        "pc": pre_pc,
        "cpsr": 0,
        "x8": number,
        **(arguments or {}),
    }
    post_values = {
        **pre_values,
        "pc": post_pc,
        "x0": result & MASK64,
    }
    pre = SyscallEvent(
        pre_pc,
        tid,
        ARCH,
        pre_values,
        (),
        ARCH,
        number,
        "entering",
        False,
        event_count=10,
    )
    post = SyscallEvent(
        post_pc,
        tid,
        ARCH,
        post_values,
        post_writes,
        ARCH,
        number,
        "exiting",
        False,
        syscall_extra,
        event_count=11,
    )
    return pre, post


def make_target(
    event: SyscallEvent,
    *,
    overrides: Mapping[str, int] | None = None,
    memory: Mapping[int, int] | None = None,
    execute: Callable[[FakeReplayTarget], ReadableProgramState | None] | None = None,
) -> FakeReplayTarget:
    registers = dict(event.registers.items())
    registers.update(overrides or {})
    return FakeReplayTarget(registers, memory, execute=execute)


def install_post_state(
    target: FakeReplayTarget,
    post: SyscallEvent,
) -> ReadableProgramState:
    target.state.write_register("pc", post.registers["pc"])
    target.state.write_register("x0", post.registers["x0"])
    return target.state


def test_rr_aarch64_fixture_dispatches_and_replays_recorded_write():
    pre, post = DeterministicLog(FIXTURES / "aarch64-syscall").events()
    assert isinstance(pre, SyscallEvent)
    assert isinstance(post, SyscallEvent)
    target = make_target(pre)

    engine = make_replay_engine(ARCH)
    state = engine.replay_syscall(target, pre, post)

    assert isinstance(engine, AArch64ReplayEngine)
    assert target.steps == 0
    assert state.read_pc() == 0x4004
    assert state.read_register("x0") == 5
    assert engine.coverage_report().by_strategy[ReplayStrategy.RECORDED] == 1


def test_recorded_read_translates_output_through_aarch64_argument_registers():
    pre, post = make_syscall_pair(
        63,
        arguments={"x1": 0x2000, "x2": 4},
        result=4,
        post_writes=(full_write(101, 0x2000, b"ARM!"),),
    )
    target = make_target(pre, overrides={"x1": 0x3000})
    engine = AArch64ReplayEngine(ARCH)

    state = engine.replay_syscall(target, pre, post)

    assert target.steps == 0
    assert state.read_register("x0") == 4
    assert state.read_memory(0x3000, 4) == b"ARM!"
    assert not target.state.mem.test(0x2000, 1)


def test_openat_and_close_update_virtual_descriptor_state_from_rr_provenance():
    opened = OpenedFileDescriptor(5, b"/tmp/input", 11, 12)
    open_pre, open_post = make_syscall_pair(
        56,
        arguments={"x0": MASK64 - 99},
        result=5,
        syscall_extra=SyscallExtra(kind="openedFds", opened_fds=(opened,)),
    )
    engine = AArch64ReplayEngine(ARCH)
    engine.replay_syscall(make_target(open_pre), open_pre, open_post)

    descriptor = engine.state.snapshot().descriptors[5]
    assert descriptor.kind == "openat:b'/tmp/input'"

    close_pre, close_post = make_syscall_pair(57, arguments={"x0": 5}, result=0)
    engine.replay_syscall(make_target(close_pre), close_pre, close_post)
    assert 5 not in engine.state.snapshot().descriptors


def test_aarch64_anonymous_mmap_executes_and_reconciles_but_file_mapping_rejects():
    pre, post = make_syscall_pair(
        222,
        arguments={"x0": 0, "x1": 0x1000, "x2": 3, "x3": 0x22, "x4": MASK64},
        result=0x70000000,
    )
    target = make_target(pre)
    target.execute_callback = lambda current: install_post_state(current, post)
    engine = AArch64ReplayEngine(ARCH)

    state = engine.replay_syscall(target, pre, post)
    assert target.steps == 1
    assert state.read_register("x0") == 0x70000000

    file_pre, file_post = make_syscall_pair(
        222,
        arguments={"x1": 0x1000, "x2": 1, "x3": 2, "x4": 3},
        result=0x71000000,
    )
    file_target = make_target(file_pre)
    with pytest.raises(UnsupportedReplayEffect, match="Only anonymous mmap"):
        engine.replay_syscall(file_target, file_pre, file_post)
    assert file_target.steps == 0
    assert file_target.mutations == []


def test_aarch64_execute_reconcile_does_not_patch_an_incorrect_mapping_result():
    pre, post = make_syscall_pair(
        222,
        arguments={"x1": 0x1000, "x2": 3, "x3": 0x22, "x4": MASK64},
        result=0x70000000,
    )
    target = make_target(pre)

    def execute_wrong(current: FakeReplayTarget) -> ReadableProgramState:
        install_post_state(current, post)
        current.state.write_register("x0", 0x71000000)
        return current.state

    target.execute_callback = execute_wrong
    with pytest.raises(ReplayReconciliationError, match="expects x0"):
        AArch64ReplayEngine(ARCH).replay_syscall(target, pre, post)


def test_aarch64_unknown_and_thread_creating_syscalls_fail_before_target_mutation():
    pre, post = make_syscall_pair(9999)
    target = make_target(pre)
    engine = AArch64ReplayEngine(ARCH)
    with pytest.raises(UnsupportedReplayEffect, match="Unclassified aarch64l.*9999"):
        engine.replay_syscall(target, pre, post)
    assert target.mutations == []
    assert target.steps == 0

    clone_pre, _clone_post = make_syscall_pair(220)
    with pytest.raises(UnsupportedConcurrencyError, match="clone"):
        engine.prepare_syscall(clone_pre)


def test_aarch64_terminal_exit_executes_without_a_post_event():
    pre, _post = make_syscall_pair(93, arguments={"x0": 7})

    def terminate(target: FakeReplayTarget) -> None:
        target.exited = True
        return None

    target = make_target(pre, execute=terminate)
    engine = AArch64ReplayEngine(ARCH)
    policy = engine.prepare_syscall(pre)
    assert not policy.requires_post_event

    with pytest.raises(StopIteration):
        engine.replay_syscall(target, pre, None, policy=policy)

    snapshot = engine.state.snapshot()
    assert snapshot.terminated
    assert engine.coverage_report().records[-1].detail == "terminal effect"


def test_aarch64_signal_delivery_without_replayed_action_fails_before_mutation():
    syscall_pre, _syscall_post = make_syscall_pair(134)
    engine = AArch64ReplayEngine(ARCH)
    assert engine.prepare_syscall(syscall_pre).state_action.value == "signal-action"

    siginfo = (10).to_bytes(4, "little", signed=True) + bytes(124)
    descriptor = SignalDescriptor(ARCH, siginfo, True, "userHandler")
    signal_pre = SignalEvent(
        0x4000,
        101,
        ARCH,
        {"pc": 0x4000},
        (),
        signal_number=descriptor,
        event_count=20,
    )
    signal_post = SignalEvent(
        0x5000,
        101,
        ARCH,
        {"pc": 0x5000},
        (),
        signal_handler=descriptor,
        event_count=21,
    )
    target = FakeReplayTarget({"pc": 0x4000})

    with pytest.raises(UnsupportedReplayEffect, match="no replayed user action"):
        engine.replay_signal(target, signal_pre, signal_post)

    assert target.mutations == []
    assert target.steps == 0
    record = engine.coverage_report().records[-1]
    assert record.outcome is CoverageOutcome.REJECTED
    assert record.effect == "signal:10"


def test_aarch64_policy_table_is_typed_and_uses_only_architecture_registers():
    assert AARCH64_SYSCALL_POLICIES[63].outputs.register_names() == frozenset({"x1", "x2"})
    assert AARCH64_SYSCALL_POLICIES[64].strategy is ReplayStrategy.RECORDED
    assert AARCH64_SYSCALL_POLICIES[134].strategy is ReplayStrategy.RECORDED
    assert all(
        ARCH.to_regname(register) is not None
        for policy in AARCH64_SYSCALL_POLICIES.values()
        for register in policy.register_names()
    )
