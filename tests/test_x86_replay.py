from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import cast

import pytest

from focaccia.arch import x86
from focaccia.deterministic import (
    Event,
    ExtraRegisterState,
    KnownMemoryRange,
    MemoryMapping,
    MemoryWrite,
    OpenedFileDescriptor,
    SyscallEvent,
    SyscallExtra,
    UnknownMemoryRange,
    UnknownMemoryRangeError,
)
from focaccia.qemu.concurrency import UnsupportedConcurrencyError
from focaccia.qemu.replay import X86InitialStackImage, X86ReplayEngine
from focaccia.qemu.syscall import (
    CoverageOutcome,
    DirectMemoryOutputs,
    DirectOutput,
    FixedExtent,
    IovecResultOutputs,
    NoMemoryOutputs,
    ReplayEventError,
    ReplayReconciliationError,
    ReplayStrategy,
    SyscallPolicy,
    UnsupportedReplayEffect,
    validate_policy_table,
)
from focaccia.qemu.x86 import X86_64_SYSCALL_POLICIES
from focaccia.snapshot import ProgramState, ReadableProgramState


MASK64 = (1 << 64) - 1
DEFAULT_FLAGS = 0x202


class FakeReplayTarget:
    arch = x86.ArchX86()

    def __init__(
        self,
        registers: Mapping[str, int],
        memory: Mapping[int, int] | None = None,
        *,
        execute: Callable[[FakeReplayTarget], ReadableProgramState | None] | None = None,
    ):
        self.state = ProgramState(self.arch)
        for register, value in registers.items():
            self.state.write_register(register, value)
        if memory:
            for address, value in memory.items():
                self.state.write_memory(address, bytes((value,)))
        self.execute_callback = execute
        self.steps = 0
        self.expected_execution_pcs: list[int | None] = []
        self.mutations: list[tuple[str, int, bytes | int]] = []
        self.mappings: list[tuple[int, int, int, int, int]] = []
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

    def map_target_memory(
        self,
        address: int,
        length: int,
        protection: int,
        flags: int,
        syscall_image_address: int,
    ) -> None:
        self.mappings.append(
            (address, length, protection, flags, syscall_image_address)
        )
        self.state.write_memory(address, bytes(length))

    def write_signal_handler_extra_registers(
        self,
        extra_registers: ExtraRegisterState,
    ) -> None:
        del extra_registers

    def execute_replay_instruction(
        self, expected_pc: int | None = None
    ) -> ReadableProgramState | None:
        self.steps += 1
        self.expected_execution_pcs.append(expected_pc)
        if self.execute_callback is None:
            raise AssertionError("This fake target must not execute a system call.")
        return self.execute_callback(self)

    def is_exited(self) -> bool:
        return self.exited


def full_write(tid: int, address: int, data: bytes) -> MemoryWrite:
    ranges = (KnownMemoryRange(0, data),) if data else ()
    return MemoryWrite(tid, address, len(data), ranges, ())


def initial_stack_bytes(
    stack_pointer: int,
    *,
    executable: bytes,
    argument: bytes = b"workload.lua",
    environment: bytes = b"MODE=recorded",
    vdso: int = 0x700000,
    random_bytes: bytes = bytes(range(16)),
) -> bytes:
    data = bytearray(0x1000)
    executable_address = stack_pointer + 0x300
    argument_address = stack_pointer + 0x380
    environment_address = stack_pointer + 0x3C0
    random_address = stack_pointer + 0x400
    platform_address = stack_pointer + 0x420
    words = [
        2,
        executable_address,
        argument_address,
        0,
        environment_address,
        0,
        33,
        vdso,
        25,
        random_address,
        31,
        executable_address,
        15,
        platform_address,
        0,
        0,
    ]
    for index, value in enumerate(words):
        data[index * 8 : index * 8 + 8] = value.to_bytes(8, "little")
    for address, value in (
        (executable_address, executable + b"\0"),
        (argument_address, argument + b"\0"),
        (environment_address, environment + b"\0"),
        (random_address, random_bytes),
        (platform_address, b"x86_64\0"),
    ):
        offset = address - stack_pointer
        data[offset : offset + len(value)] = value
    return bytes(data)


def make_syscall_pair(
    number: int,
    *,
    tid: int = 101,
    pre_pc: int = 0x1000,
    post_pc: int = 0x1002,
    arguments: Mapping[str, int] | None = None,
    result: int = 0,
    post_writes: tuple[MemoryWrite, ...] = (),
    post_registers: Mapping[str, int] | None = None,
    syscall_extra: SyscallExtra | None = None,
) -> tuple[SyscallEvent, SyscallEvent]:
    arch = x86.ArchX86()
    pre_values = {
        "rip": pre_pc,
        "rax": number,
        "rflags": DEFAULT_FLAGS,
        "rcx": 0xCAFE,
        "r11": DEFAULT_FLAGS,
        "rdi": 0,
        "rsi": 0,
        "rdx": 0,
        "r10": 0,
        "r8": 0,
        "r9": 0,
        **(arguments or {}),
    }
    post_values = {
        **pre_values,
        "rip": post_pc,
        "rax": result & MASK64,
        "rcx": post_pc,
        "r11": DEFAULT_FLAGS,
        **(post_registers or {}),
    }
    pre = SyscallEvent(
        pre_pc,
        tid,
        arch,
        pre_values,
        (),
        arch,
        number,
        "entering",
        False,
        event_count=10,
    )
    post = SyscallEvent(
        post_pc,
        tid,
        arch,
        post_values,
        post_writes,
        arch,
        number,
        "exiting",
        False,
        syscall_extra,
        event_count=11,
    )
    return pre, post


def make_target_for_event(
    event: SyscallEvent,
    *,
    overrides: Mapping[str, int] | None = None,
    memory: Mapping[int, int] | None = None,
    execute: Callable[[FakeReplayTarget], ReadableProgramState | None] | None = None,
) -> FakeReplayTarget:
    registers = {name: value for name, value in event.registers.items()}
    registers.update(overrides or {})
    return FakeReplayTarget(registers, memory, execute=execute)


def install_post_state(target: FakeReplayTarget, post: SyscallEvent) -> ReadableProgramState:
    for register in ("rip", "rax", "rcx", "r11"):
        target.state.write_register(register, post.registers[register])
    return target.state


def test_initial_stack_parser_relocates_internal_pointers_and_random_bytes():
    source_rsp = 0x8000
    source = initial_stack_bytes(source_rsp, executable=b"/qemu/app")
    image = X86InitialStackImage.read(
        source_rsp,
        lambda address, size: source[address - source_rsp : address - source_rsp + size],
    )

    relocated = image.relocate(0x4000, b"R" * 16)
    relocated_image = X86InitialStackImage.read(
        0x4000,
        lambda address, size: relocated[address - 0x4000 : address - 0x4000 + size],
    )

    assert relocated_image.arguments == (b"/qemu/app", b"workload.lua")
    assert relocated_image.random_bytes == b"R" * 16
    assert relocated_image.auxiliary_value(33) == 0x700000


def test_initial_exec_establishes_recorded_stack_with_live_vdso():
    arch = x86.ArchX86()
    source_rsp = 0x8000
    recorded_rsp = 0x4000
    source_stack = initial_stack_bytes(
        source_rsp,
        executable=b"/qemu/app",
        environment=b"MODE=qemu",
        vdso=0x900000,
        random_bytes=b"Q" * 16,
    )
    recorded_mapping = bytearray(0x2000)
    recorded_mapping[0x20] = 0xA5
    recorded_stack = initial_stack_bytes(
        recorded_rsp,
        executable=b"/rr/app",
        environment=b"MODE=recorded",
        vdso=0x700000,
        random_bytes=b"R" * 16,
    )
    recorded_mapping[0x1000:] = recorded_stack
    post_registers = {
        name: 0
        for name in (
            "r15",
            "r14",
            "r13",
            "r12",
            "rbp",
            "rbx",
            "r11",
            "r10",
            "r9",
            "r8",
            "rax",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
        )
    }
    post_registers.update(
        {
            "rip": 0x401000,
            "rsp": recorded_rsp,
            "rflags": 0x246,
            "fs_base": 0x12340000,
            "gs_base": 0,
        }
    )
    pre = SyscallEvent(
        0xDEAD,
        1,
        arch,
        {"rip": 0xDEAD, "rax": 59},
        (),
        arch,
        59,
        "entering",
        False,
        event_count=13,
    )
    post = SyscallEvent(
        0x401000,
        1,
        arch,
        post_registers,
        (full_write(1, 0x3000, bytes(recorded_mapping)),),
        arch,
        59,
        "exiting",
        False,
        event_count=14,
    )
    mapping = MemoryMapping(14, 0x3000, 0x5000, "trace", 0, 3, 258, b"[stack]")
    target = FakeReplayTarget({"rip": 0x401000, "rsp": source_rsp, "rflags": 0x202})
    target.state.write_memory(source_rsp, source_stack)

    state = X86ReplayEngine(arch).replay_initial_exec(target, pre, post, (mapping,))
    established = X86InitialStackImage.read(recorded_rsp, state.read_memory)

    assert target.mappings == [(0x3000, 0x2000, 3, 0x100122, 0x900000)]
    assert state.read_register("rsp") == recorded_rsp
    assert state.read_register("fs_base") == 0x12340000
    assert state.read_memory(0x3020, 1) == b"\xa5"
    assert established.arguments == (b"/rr/app", b"workload.lua")
    assert established.random_bytes == b"R" * 16
    assert established.auxiliary_value(33) == 0x900000
    assert b"MODE=recorded\0" in established.data
    assert b"MODE=qemu\0" not in established.data


def test_initial_exec_rejects_different_workload_arguments_before_mapping():
    arch = x86.ArchX86()
    source_rsp = 0x8000
    target = FakeReplayTarget({"rip": 0x401000, "rsp": source_rsp})
    target.state.write_memory(
        source_rsp,
        initial_stack_bytes(source_rsp, executable=b"/qemu/app", argument=b"other.lua"),
    )
    recorded = bytearray(0x2000)
    recorded[0x1000:] = initial_stack_bytes(0x4000, executable=b"/rr/app")
    registers = {
        **{
            name: 0
            for name in (
                "r15",
                "r14",
                "r13",
                "r12",
                "rbp",
                "rbx",
                "r11",
                "r10",
                "r9",
                "r8",
                "rax",
                "rcx",
                "rdx",
                "rsi",
                "rdi",
            )
        },
        "rip": 0x401000,
        "rsp": 0x4000,
        "fs_base": 0,
        "gs_base": 0,
    }
    pre = SyscallEvent(
        0xDEAD, 1, arch, {"rip": 0xDEAD, "rax": 59}, (), arch, 59, "entering", False, event_count=13
    )
    post = SyscallEvent(
        0x401000,
        1,
        arch,
        registers,
        (full_write(1, 0x3000, bytes(recorded)),),
        arch,
        59,
        "exiting",
        False,
        event_count=14,
    )
    mapping = MemoryMapping(14, 0x3000, 0x5000, "trace", 0, 3, 258, b"[stack]")

    with pytest.raises(ReplayEventError, match="arguments differ"):
        X86ReplayEngine(arch).replay_initial_exec(target, pre, post, (mapping,))

    assert target.mappings == []


def test_replay_coverage_for_recorded_read_translates_output_without_live_execution():
    pre, post = make_syscall_pair(
        0,
        arguments={"rsi": 0x2000, "rdx": 4},
        result=4,
        post_writes=(full_write(101, 0x2000, b"RR!!"),),
    )
    target = make_target_for_event(pre, overrides={"rsi": 0x3000})
    engine = X86ReplayEngine(target.arch)

    state = engine.replay_syscall(target, pre, post)

    assert target.steps == 0
    assert state.read_pc() == 0x1002
    assert state.read_register("rax") == 4
    assert state.read_register("rcx") == 0x1002
    assert state.read_memory(0x3000, 4) == b"RR!!"
    assert not target.state.mem.test(0x2000, 1)
    report = engine.coverage_report()
    assert report.by_strategy[ReplayStrategy.RECORDED] == 1
    assert report.by_outcome[CoverageOutcome.HANDLED] == 1


def test_unknown_syscall_fails_closed_before_target_mutation_or_step():
    pre, post = make_syscall_pair(9999)
    target = make_target_for_event(pre)
    engine = X86ReplayEngine(target.arch)

    with pytest.raises(UnsupportedReplayEffect, match="Unclassified.*9999"):
        engine.replay_syscall(target, pre, post)

    assert target.steps == 0
    assert target.mutations == []
    report = engine.coverage_report()
    assert report.records[-1].outcome is CoverageOutcome.REJECTED


def test_classified_unsafe_ioctl_is_rejected_without_execution():
    pre, post = make_syscall_pair(16, arguments={"rsi": 0xDEAD, "rdx": 0x2000})
    target = make_target_for_event(pre)
    engine = X86ReplayEngine(target.arch)

    with pytest.raises(ReplayEventError, match="requires rsi in.*0x5413"):
        engine.replay_syscall(target, pre, post)

    assert target.steps == 0
    assert target.mutations == []


def test_tiocgwinsz_replays_recorded_output_without_live_ioctl():
    pre, post = make_syscall_pair(
        16,
        arguments={"rsi": 0x5413, "rdx": 0x2000},
        result=-25,
        post_writes=(full_write(101, 0x2000, b"winsize!"),),
    )
    target = make_target_for_event(pre, overrides={"rdx": 0x3000})

    state = X86ReplayEngine(target.arch).replay_syscall(target, pre, post)

    assert target.steps == 0
    assert state.read_pc() == post.pc
    assert state.read_memory(0x3000, 8) == b"winsize!"


@pytest.mark.parametrize("command", (1, 2, 3, 6))
def test_supported_fcntl_commands_replay_without_live_execution(command):
    pre, post = make_syscall_pair(72, arguments={"rsi": command})
    target = make_target_for_event(pre)

    state = X86ReplayEngine(target.arch).replay_syscall(target, pre, post)

    assert target.steps == 0
    assert state.read_pc() == post.pc


def test_unknown_fcntl_command_fails_before_target_mutation():
    pre, post = make_syscall_pair(72, arguments={"rsi": 99})
    target = make_target_for_event(pre)

    with pytest.raises(ReplayEventError, match="requires rsi in"):
        X86ReplayEngine(target.arch).replay_syscall(target, pre, post)

    assert target.steps == 0
    assert target.mutations == []


def test_thread_creating_syscalls_are_rejected_before_target_access():
    pre, _post = make_syscall_pair(56)
    engine = X86ReplayEngine(x86.ArchX86())

    with pytest.raises(UnsupportedConcurrencyError, match="clone"):
        engine.prepare_syscall(pre)


def test_unknown_memory_holes_fail_before_target_mutation():
    write = MemoryWrite(
        101,
        0x2000,
        4,
        (KnownMemoryRange(0, b"ab"),),
        (UnknownMemoryRange(2, 2),),
    )
    pre, post = make_syscall_pair(
        0,
        arguments={"rsi": 0x2000, "rdx": 4},
        result=4,
        post_writes=(write,),
    )
    target = make_target_for_event(pre)
    engine = X86ReplayEngine(target.arch)

    with pytest.raises(UnknownMemoryRangeError, match="unknown ranges"):
        engine.replay_syscall(target, pre, post)

    assert target.steps == 0
    assert target.mutations == []
    assert engine.coverage_report().records[-1].outcome is CoverageOutcome.FAILED


def test_policy_validation_rejects_invalid_register_metadata():
    invalid = SyscallPolicy(
        1,
        "invalid",
        ReplayStrategy.RECORDED,
        DirectMemoryOutputs((DirectOutput("rdxi", FixedExtent(8)),)),
    )

    with pytest.raises(ValueError, match="rdxi"):
        validate_policy_table(x86.ArchX86(), {1: invalid})


def test_x86_policy_table_uses_typed_nested_and_correct_output_handlers():
    assert isinstance(X86_64_SYSCALL_POLICIES[19].outputs, IovecResultOutputs)
    assert X86_64_SYSCALL_POLICIES[262].outputs.register_names() == frozenset({"rdx"})
    assert X86_64_SYSCALL_POLICIES[53].outputs.register_names() == frozenset({"r10"})
    assert all(
        x86.ArchX86().to_regname(register) is not None
        for policy in X86_64_SYSCALL_POLICIES.values()
        for register in policy.register_names()
    )


def test_readv_nested_output_is_distributed_through_target_iovecs():
    recorded_writes = (
        full_write(101, 0xA000, b"abc"),
        full_write(101, 0xB000, b"defgh"),
    )
    pre, post = make_syscall_pair(
        19,
        arguments={"rsi": 0x5000, "rdx": 2},
        result=8,
        post_writes=recorded_writes,
    )
    target_iovecs = (
        (0x7000).to_bytes(8, "little")
        + (3).to_bytes(8, "little")
        + (0x8000).to_bytes(8, "little")
        + (8).to_bytes(8, "little")
    )
    memory = {0x6000 + index: value for index, value in enumerate(target_iovecs)}
    target = make_target_for_event(pre, overrides={"rsi": 0x6000}, memory=memory)

    state = X86ReplayEngine(target.arch).replay_syscall(target, pre, post)

    assert state.read_memory(0x7000, 3) == b"abc"
    assert state.read_memory(0x8000, 5) == b"defgh"
    assert target.steps == 0


def test_iovec_result_size_mismatch_fails_closed():
    pre, post = make_syscall_pair(
        19,
        arguments={"rsi": 0x5000, "rdx": 1},
        result=5,
        post_writes=(full_write(101, 0xA000, b"four"),),
    )
    iovec = (0x7000).to_bytes(8, "little") + (8).to_bytes(8, "little")
    memory = {0x5000 + index: value for index, value in enumerate(iovec)}
    target = make_target_for_event(pre, memory=memory)

    with pytest.raises(ReplayEventError, match="contains 4 output bytes"):
        X86ReplayEngine(target.arch).replay_syscall(target, pre, post)

    assert target.mutations == []


def test_anonymous_mmap_executes_and_reconciles_exact_result():
    pre, post = make_syscall_pair(
        9,
        arguments={
            "rdi": 0,
            "rsi": 0x1000,
            "rdx": 3,
            "r10": 0x22,
            "r8": MASK64,
            "r9": 0,
        },
        result=0x70000000,
    )
    target = make_target_for_event(pre)
    target.execute_callback = lambda current: install_post_state(current, post)
    engine = X86ReplayEngine(target.arch)

    state = engine.replay_syscall(target, pre, post)

    assert target.steps == 1
    assert target.expected_execution_pcs == [post.pc]
    assert state.read_register("rax") == 0x70000000
    assert engine.coverage_report().by_strategy[ReplayStrategy.EXECUTE_RECONCILE] == 1


def test_anonymous_mmap_null_forces_recorded_address_without_leaking_fixed_flags():
    pre, post = make_syscall_pair(
        9,
        arguments={
            "rdi": 0,
            "rsi": 0x1000,
            "rdx": 3,
            "r10": 0x22,
            "r8": MASK64,
            "r9": 0,
        },
        result=0x709567A6C000,
    )
    observed_inputs: list[tuple[int, int]] = []

    def execute(target: FakeReplayTarget) -> ReadableProgramState:
        observed_inputs.append(
            (target.state.read_register("rdi"), target.state.read_register("r10"))
        )
        return install_post_state(target, post)

    target = make_target_for_event(pre, execute=execute)

    state = X86ReplayEngine(target.arch).replay_syscall(target, pre, post)

    assert observed_inputs == [(0x709567A6C000, 0x22 | 0x100000)]
    assert state.read_register("rax") == 0x709567A6C000
    assert state.read_register("rdi") == 0
    assert state.read_register("r10") == 0x22


def test_anonymous_mmap_null_fails_if_recorded_address_cannot_be_established():
    pre, post = make_syscall_pair(
        9,
        arguments={
            "rdi": 0,
            "rsi": 0x1000,
            "rdx": 3,
            "r10": 0x22,
            "r8": MASK64,
            "r9": 0,
        },
        result=0x709567A6C000,
    )

    def execute(target: FakeReplayTarget) -> ReadableProgramState:
        install_post_state(target, post)
        target.state.write_register("rax", MASK64 - 16)
        return target.state

    target = make_target_for_event(pre, execute=execute)

    with pytest.raises(ReplayReconciliationError, match="expects rax"):
        X86ReplayEngine(target.arch).replay_syscall(target, pre, post)


def test_brk_zero_query_applies_recorded_address_but_nonzero_growth_remains_exact():
    pre, post = make_syscall_pair(
        12,
        arguments={"rdi": 0},
        result=0x33CC6000,
    )

    def query(target: FakeReplayTarget) -> ReadableProgramState:
        state = install_post_state(target, post)
        target.state.write_register("rax", 0x45D000)
        return state

    target = make_target_for_event(pre, execute=query)
    state = X86ReplayEngine(target.arch).replay_syscall(target, pre, post)

    assert target.steps == 1
    assert state.read_register("rax") == 0x33CC6000

    grow_pre, grow_post = make_syscall_pair(
        12,
        arguments={"rdi": 0x33CC8000},
        result=0x33CC8000,
    )

    def grow(target: FakeReplayTarget) -> ReadableProgramState:
        state = install_post_state(target, grow_post)
        target.state.write_register("rax", 0x45F000)
        return state

    grow_target = make_target_for_event(grow_pre, execute=grow)
    with pytest.raises(ReplayReconciliationError, match="expects rax"):
        X86ReplayEngine(grow_target.arch).replay_syscall(
            grow_target,
            grow_pre,
            grow_post,
        )


def test_executed_syscall_applies_recorded_rcx_and_r11_control_effects():
    pre, post = make_syscall_pair(
        12,
        arguments={"rdi": 0x70000000},
        result=0x70000000,
        post_registers={"rcx": MASK64, "r11": 0x246},
    )

    def execute(target: FakeReplayTarget) -> ReadableProgramState:
        state = install_post_state(target, post)
        target.state.write_register("rcx", 0)
        target.state.write_register("r11", 0)
        return state

    target = make_target_for_event(pre, execute=execute)

    state = X86ReplayEngine(target.arch).replay_syscall(target, pre, post)

    assert target.steps == 1
    assert state.read_register("rcx") == MASK64
    assert state.read_register("r11") == 0x246
    assert target.mutations[-2:] == [
        ("register", 0, MASK64),
        ("register", 0, 0x246),
    ]


def test_arch_prctl_replays_recorded_segment_bases_without_live_execution():
    pre, post = make_syscall_pair(
        158,
        arguments={"rdi": 0x1002, "rsi": 0x60FA18},
        post_registers={"fs_base": 0x60FA18, "gs_base": 0},
    )
    target = make_target_for_event(pre, overrides={"fs_base": 0, "gs_base": 0})
    engine = X86ReplayEngine(target.arch)

    state = engine.replay_syscall(target, pre, post)

    assert target.steps == 0
    assert state.read_pc() == 0x1002
    assert state.read_register("fs_base") == 0x60FA18
    assert state.read_register("gs_base") == 0
    report = engine.coverage_report()
    assert report.by_strategy[ReplayStrategy.RECORDED] == 1
    assert report.by_outcome[CoverageOutcome.HANDLED] == 1


def test_file_backed_mmap_is_rejected_before_execution():
    pre, post = make_syscall_pair(
        9,
        arguments={"rsi": 0x1000, "rdx": 1, "r10": 2, "r8": 3},
        result=0x70000000,
    )
    target = make_target_for_event(pre)
    engine = X86ReplayEngine(target.arch)

    with pytest.raises(UnsupportedReplayEffect, match="Only anonymous mmap"):
        engine.replay_syscall(target, pre, post)

    assert target.steps == 0
    assert target.mutations == []


def test_execute_and_reconcile_does_not_patch_an_incorrect_result():
    pre, post = make_syscall_pair(
        9,
        arguments={"rsi": 0x1000, "rdx": 3, "r10": 0x22, "r8": MASK64},
        result=0x70000000,
    )
    target = make_target_for_event(pre)

    def execute_wrong(current: FakeReplayTarget) -> ReadableProgramState:
        install_post_state(current, post)
        current.state.write_register("rax", 0x71000000)
        return current.state

    target.execute_callback = execute_wrong

    with pytest.raises(ReplayReconciliationError, match="expects rax"):
        X86ReplayEngine(target.arch).replay_syscall(target, pre, post)

    assert target.steps == 1
    assert target.state.read_register("rax") == 0x71000000


def test_safe_passthrough_is_explicit_and_reconciled():
    pre, post = make_syscall_pair(24)
    target = make_target_for_event(pre)
    target.execute_callback = lambda current: install_post_state(current, post)
    engine = X86ReplayEngine(target.arch)

    engine.replay_syscall(target, pre, post)

    assert target.steps == 1
    assert engine.coverage_report().by_strategy[ReplayStrategy.SAFE_PASSTHROUGH] == 1


def test_terminal_exit_executes_without_requiring_a_post_event():
    pre, _post = make_syscall_pair(60, arguments={"rdi": 7})

    def terminate(current: FakeReplayTarget) -> None:
        current.exited = True
        return None

    target = make_target_for_event(pre, execute=terminate)
    engine = X86ReplayEngine(target.arch)
    policy = engine.prepare_syscall(pre)
    assert not policy.requires_post_event

    with pytest.raises(StopIteration):
        engine.replay_syscall(target, pre, None, policy=policy)

    assert target.steps == 1
    assert engine.state.snapshot().terminated
    assert engine.coverage_report().records[-1].detail == "terminal effect"


def test_system_call_pair_with_second_tid_is_rejected():
    pre, post = make_syscall_pair(0, arguments={"rsi": 0x2000, "rdx": 0})
    other = SyscallEvent(
        cast(int, post.pc),
        202,
        post.arch,
        post.registers,
        post.mem_writes,
        post.syscall_arch,
        post.syscall_number,
        post.syscall_state,
        False,
        event_count=post.event_count,
    )
    target = make_target_for_event(pre)

    with pytest.raises(ReplayEventError, match="changes thread ID"):
        X86ReplayEngine(target.arch).replay_syscall(target, pre, other)

    assert target.mutations == []


def test_unclassified_rr_event_is_rejected_and_malformed_scheduler_has_coverage():
    arch = x86.ArchX86()
    event = Event(0x1000, 101, arch, {"rip": 0x1000}, (), "growMap", 12)
    target = FakeReplayTarget({"rip": 0x1000})
    engine = X86ReplayEngine(arch)

    with pytest.raises(UnsupportedReplayEffect, match="growMap"):
        engine.replay_bookkeeping_event(target, event)

    assert target.steps == 0
    assert target.mutations == []
    assert engine.coverage_report().records[-1].outcome is CoverageOutcome.REJECTED

    malformed_scheduler = Event(
        0x1000,
        101,
        arch,
        {"rip": 0x1000},
        (full_write(101, 0x2000, b"unexpected"),),
        "sched",
        13,
    )
    with pytest.raises(ReplayEventError, match="unexpectedly writes user memory"):
        engine.replay_bookkeeping_event(target, malformed_scheduler)

    failed = engine.coverage_report().records[-1]
    assert failed.effect == "rr-event:sched"
    assert failed.outcome is CoverageOutcome.FAILED
    assert target.mutations == []


def test_rr_extra_effects_must_be_explicitly_allowed_by_the_policy():
    pre, post = make_syscall_pair(
        39,
        result=101,
        syscall_extra=SyscallExtra(kind="writeOffset", write_offset=7),
    )
    target = make_target_for_event(pre)

    with pytest.raises(UnsupportedReplayEffect, match="unsupported RR extra effect"):
        X86ReplayEngine(target.arch).replay_syscall(target, pre, post)

    assert target.mutations == []


def test_opened_descriptor_provenance_is_retained_in_virtual_state():
    opened = OpenedFileDescriptor(5, b"/tmp/input", 11, 12)
    pre, post = make_syscall_pair(
        257,
        arguments={"rdi": MASK64 - 99},
        result=5,
        syscall_extra=SyscallExtra(kind="openedFds", opened_fds=(opened,)),
    )
    target = make_target_for_event(pre)
    engine = X86ReplayEngine(target.arch)

    engine.replay_syscall(target, pre, post)

    descriptor = engine.state.snapshot().descriptors[5]
    assert descriptor.kind == "openat:b'/tmp/input'"
    assert descriptor.source_event == 10


def test_no_memory_output_policy_rejects_unclassified_recorded_writes():
    pre, post = make_syscall_pair(
        1,
        post_writes=(full_write(101, 0x4000, b"unexpected"),),
    )
    target = make_target_for_event(pre)

    with pytest.raises(ReplayEventError, match="unexpected recorded memory"):
        X86ReplayEngine(target.arch).replay_syscall(target, pre, post)

    assert isinstance(X86_64_SYSCALL_POLICIES[1].outputs, NoMemoryOutputs)
    assert target.mutations == []
