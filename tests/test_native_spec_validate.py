import json
import runpy
import sys
import warnings

import pytest
from miasm.expression.expression import Expr, ExprId, ExprInt, ExprMem

from focaccia.arch.aarch64 import ArchAArch64
from focaccia.arch.x86 import ArchX86
from focaccia.native.spec_validate import (
    NativeSnapshot,
    NativeSpecValidator,
    NativeStep,
    SpecValidationError,
    UnsupportedNativeEvent,
    _capture,
    _decode_tir_response,
    _failure_context,
    _step,
    _validate_transition,
    _write_report,
)
from focaccia.symbolic import SymbolicTransform, UnsupportedInstructionError


class FakeTarget:
    def __init__(self, snapshots, events):
        self.snapshots, self.events = snapshots, events
        self.index = 0
        self.arch = snapshots[0].arch
        self.closed = False

    def snapshot(self):
        return self.snapshots[min(self.index, len(self.snapshots) - 1)]

    def step_one_hardware_instruction(self):
        event = self.events[min(self.index, len(self.events) - 1)]
        self.index += 1
        return event

    def refresh_output(self):
        self.refresh_count = getattr(self, "refresh_count", 0) + 1

    def close(self):
        self.closed = True


def snap(arch, regs, memory=None, perms="rw-"):
    memory = {0x1000: b"x"} if memory is None else memory
    maps = tuple(
        {
            "start": base,
            "end": base + len(data),
            "perms": perms,
            "private": True,
            "name": "[fixture]",
        }
        for base, data in memory.items()
    )
    return NativeSnapshot(arch, regs, memory, maps, "full-boundary-memory-diff")


def identity_pc(arch, name, end):
    output: dict[Expr, Expr] = {ExprId(name, 64): ExprInt(end, 64)}
    if arch.archname == "x86_64":
        return SymbolicTransform(
            1,
            output,
            [],
            arch,
            0x1000,
            end,
            defined_masks={"RIP": ExprInt((1 << 64) - 1, 64)},
            source_owned=True,
        )
    return SymbolicTransform(1, output, [], arch, 0x1000, end)


def full_x86(**overrides):
    from focaccia.intel_symbolic import REQUIRED_OUTPUTS

    return {name: overrides.get(name, 0) for name in REQUIRED_OUTPUTS}


def full_arm(**overrides):
    names = (
        *(f"X{i}" for i in range(31)),
        "SP",
        "PC",
        "CPSR",
        "TPIDR",
        *(f"V{i}" for i in range(32)),
        "FPCR",
        "FPSR",
    )
    return {name: overrides.get(name, 0) for name in names}


@pytest.mark.parametrize(
    ("arch", "pc", "extra"),
    [
        (ArchX86(), "RIP", {"RAX": 4}),
        (ArchAArch64("little"), "PC", {"X0": 4}),
    ],
)
def test_whole_program_instruction_to_validated_exit(arch, pc, extra):
    pre_regs = full_x86(RIP=0x1000, **extra) if pc == "RIP" else full_arm(PC=0x1000, **extra)
    post_regs = (
        full_x86(RIP=0x1001, RAX=60, RDI=0) if pc == "RIP" else full_arm(PC=0x1001, X8=93, X0=0)
    )
    pre = snap(arch, pre_regs)
    post = snap(arch, post_regs)
    target = FakeTarget([pre, post], [NativeStep("instruction"), NativeStep("exit", 0)])
    calls = []

    def oracle(state):
        if state.registers[pc] == 0x1001:
            return None  # source adapter recognizes the terminal syscall from pre-state
        calls.append(state)
        if pc == "RIP":
            outputs: dict[Expr, Expr] = {
                ExprId("RIP", 64): ExprInt(0x1001, 64),
                ExprId("RAX", 64): ExprInt(60, 64),
                ExprId("RDI", 64): ExprInt(0, 64),
            }
            masks: dict[str, Expr] = {
                name: ExprInt((1 << 64) - 1, 64) for name in ("RIP", "RAX", "RDI")
            }
            return SymbolicTransform(
                1, outputs, [], arch, 0x1000, 0x1001, defined_masks=masks, source_owned=True
            )
        arm_outputs: dict[Expr, Expr] = {
                ExprId("PC", 64): ExprInt(0x1001, 64),
                ExprId("X8", 64): ExprInt(93, 64),
                ExprId("X0", 64): ExprInt(0, 64),
        }
        return SymbolicTransform(
            1,
            arm_outputs,
            [],
            arch,
            0x1000,
            0x1001,
        )

    from focaccia.native.spec_syscalls import NativeLinuxPolicy

    result = NativeSpecValidator(target, oracle, syscall_policy=NativeLinuxPolicy()).run()
    assert len(calls) == 1
    assert result.exit_status == 0 and result.stdout == b""


@pytest.mark.parametrize("fault", ["pc", "register", "memory"])
def test_negative_controls_wrong_pc_register_and_unexpected_ram(fault):
    arch = ArchX86()
    before = snap(arch, full_x86(RIP=0x1000, RAX=7), {0x2000: b"abc"})
    after = snap(
        arch,
        full_x86(RIP=0x1002 if fault == "pc" else 0x1001, RAX=8 if fault == "register" else 7),
        {0x2000: b"aZc" if fault == "memory" else b"abc"},
    )
    with pytest.raises(SpecValidationError):
        _validate_transition(identity_pc(arch, "RIP", 0x1001), before, after)


def test_arm_cpsr_nzcv_is_compared_without_flag_alias_registers():
    arch = ArchAArch64("little")
    before = snap(arch, {"PC": 0x1000, "CPSR": 0, "X0": 3})
    after = snap(arch, {"PC": 0x1001, "CPSR": 0x80000000, "X0": 3})
    with pytest.raises(SpecValidationError, match="CPSR"):
        _validate_transition(identity_pc(arch, "PC", 0x1001), before, after)


def test_predicted_store_permission_and_memory_diff():
    arch = ArchAArch64("little")
    before = snap(arch, {"PC": 0x1000, "CPSR": 0, "X0": 0}, {0x2000: b"a"})
    after = snap(arch, {"PC": 0x1001, "CPSR": 0, "X0": 0}, {0x2000: b"b"})
    t = SymbolicTransform(
        1,
        {
            ExprId("PC", 64): ExprInt(0x1001, 64),
            ExprMem(ExprInt(0x2000, 64), 8): ExprInt(ord("b"), 8),
        },
        [],
        arch,
        0x1000,
        0x1001,
    )
    _validate_transition(t, before, after)
    readonly = NativeSnapshot(
        arch,
        before.registers,
        before.memory,
        ({"start": 0x2000, "end": 0x2001, "perms": "r--", "private": True},),
        "full-boundary-memory-diff",
    )
    with pytest.raises(SpecValidationError, match="write permission"):
        _validate_transition(t, readonly, after)


def test_failure_context_records_checked_boundaries_and_current_pc():
    from types import SimpleNamespace

    validator = SimpleNamespace(
        entry_pc=0x400000,
        current_pc=0x4006FC,
        validated_instruction_boundaries=17,
        validated_exclusive_regions=2,
        validated_vdso_services=1,
        validated_syscalls={"brk": 1},
    )
    details = _failure_context(
        SimpleNamespace(binary=None), None, validator, "aarch64-native", None
    )
    assert details["failed_boundary_pc_hex"] == "0x4006fc"
    assert details["validated_instruction_boundaries"] == 17
    assert details["validated_exclusive_regions"] == 2
    assert details["validated_vdso_services"] == 1
    assert details["validated_syscall_counts"] == {"brk": 1}


def test_tir_unsupported_source_instruction_is_reported_as_unsupported(monkeypatch):
    from focaccia import tir_backend

    def unsupported(*args, **kwargs):
        raise UnsupportedInstructionError("source semantics unavailable")

    monkeypatch.setattr(tir_backend, "decode_response", unsupported)
    with pytest.raises(UnsupportedNativeEvent, match="does not support instruction"):
        _decode_tir_response("{}", 0x4006FC, bytes.fromhex("1f2003d5"), None)


def test_snapshot_requires_capability_and_complete_nonoverlapping_private_bytes():
    arch = ArchX86()
    incomplete = NativeSnapshot(
        arch,
        {"RIP": 0x1000},
        {0x1000: b"a"},
        ({"start": 0x1000, "end": 0x1002, "perms": "r--", "private": True},),
        "full-boundary-memory-diff",
    )
    target = FakeTarget([incomplete], [NativeStep("instruction")])
    with pytest.raises(SpecValidationError, match="gap|incomplete"):
        _capture(target)
    missing_region = NativeSnapshot(
        arch,
        {"RIP": 0x1000},
        {},
        ({"start": 0x1000, "end": 0x1001, "perms": "r--", "private": True},),
        "full-boundary-memory-diff",
    )
    with pytest.raises(SpecValidationError, match="incomplete"):
        _capture(FakeTarget([missing_region], [NativeStep("instruction")]))
    missing_capability = NativeSnapshot(
        arch,
        {"RIP": 0x1000},
        {0x1000: b"a"},
        ({"start": 0x1000, "end": 0x1001, "perms": "r--", "private": True},),
        "none",
    )
    with pytest.raises(SpecValidationError, match="capability"):
        _capture(FakeTarget([missing_capability], [NativeStep("instruction")]))
    overlapping = NativeSnapshot(
        arch,
        {"RIP": 0x1000},
        {0x1000: b"ab"},
        (
            {"start": 0x1000, "end": 0x1002, "perms": "r--", "private": True},
            {"start": 0x1001, "end": 0x1002, "perms": "r--", "private": True},
        ),
        "full-boundary-memory-diff",
    )
    with pytest.raises(SpecValidationError, match="overlap"):
        _capture(FakeTarget([overlapping], [NativeStep("instruction")]))


def test_python_m_cli_uses_logical_exception_identity(monkeypatch, capsys):
    from focaccia.arch.aarch64 import ArchAArch64
    from focaccia.native import spec_target
    from focaccia.native.spec_syscalls import UnsupportedNativeEvent as PolicyUnsupported

    class Target:
        def __init__(self, binary, argv):
            self.arch = ArchAArch64("little")

        def configure_arm_profile(self, helper):
            raise PolicyUnsupported("policy preflight failure")

        def close(self):
            pass

    monkeypatch.setattr(spec_target, "NativeSpecTarget", Target)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "focaccia.native.spec_validate",
            "--binary",
            "fixture",
            "--hardware-profile-helper",
            "helper",
        ],
    )
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=RuntimeWarning, module="runpy")
        with pytest.raises(SystemExit) as raised:
            runpy.run_module("focaccia.native.spec_validate", run_name="__main__")
    assert raised.value.code == 2
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "unsupported"
    assert report["error"] == "policy preflight failure"


def test_cli_report_is_saved_as_complete_json(tmp_path, capsys):
    path = tmp_path / "report.json"
    _write_report(
        {"status": "accepted", "memory_evidence_capability": "full-private-memory-boundary-diff"},
        path,
    )
    rendered = capsys.readouterr().out.strip()
    assert path.read_text().strip() == rendered
    assert '"status": "accepted"' in rendered


def test_unsupported_syscall_is_rejected_before_hardware_step():
    arch = ArchX86()
    state = snap(arch, full_x86(RIP=0x1000, RAX=0x7FFFFFFF))
    target = FakeTarget([state], [NativeStep("instruction")])
    from focaccia.native.spec_syscalls import NativeLinuxPolicy

    with pytest.raises(UnsupportedNativeEvent, match="Unsupported Linux syscall"):
        NativeSpecValidator(target, lambda _: None, syscall_policy=NativeLinuxPolicy()).run()
    assert target.index == 0


def test_signal_and_missing_syscall_policy_are_fail_closed():
    from focaccia.native.spec_syscalls import NativeLinuxPolicy

    arch = ArchX86()
    state = snap(arch, full_x86(RIP=0x1000, RAX=60, RDI=0))
    target = FakeTarget([state], [NativeStep("signal", signal=11)])
    with pytest.raises(UnsupportedNativeEvent, match="signal"):
        NativeSpecValidator(
            target, lambda _: None, syscall_policy=NativeLinuxPolicy(), max_steps=1
        ).run()
    target = FakeTarget([state], [NativeStep("instruction")])
    with pytest.raises(UnsupportedNativeEvent, match="no stateful Linux policy"):
        NativeSpecValidator(target, lambda _: None, max_steps=1).run()


def test_source_owned_arm_guard_is_not_lost_in_native_projection():
    from focaccia.symbolic import SymbolEvaluationError

    arch = ArchAArch64("little")
    pre = snap(arch, full_arm(PC=0x1000))
    transform = SymbolicTransform(
        1, {ExprId("PC", 64): ExprInt(0x1004, 64)}, [], arch, 0x1000, 0x1004,
        source_owned=True, defined_masks={"PC": ExprInt((1 << 64) - 1, 64)},
        guards=(ExprInt(0, 1),),
    )
    target = FakeTarget([pre], [NativeStep("instruction")])
    with pytest.raises(SymbolEvaluationError, match="guard.*false"):
        NativeSpecValidator(target, lambda _: transform, max_steps=1).run()
    assert target.index == 0


def test_instruction_cannot_change_mapping_permissions_without_changing_bytes():
    arch = ArchAArch64("little")
    pre = snap(arch, full_arm(PC=0x1000), perms="rw-")
    post = snap(arch, full_arm(PC=0x1004), perms="r--")
    with pytest.raises(SpecValidationError, match="unauthorized mapping"):
        _validate_transition(identity_pc(arch, "PC", 0x1004), pre, post)


def test_instruction_cannot_emit_output_outside_an_os_boundary():
    from dataclasses import replace

    arch = ArchAArch64("little")
    pre = snap(arch, full_arm(PC=0x1000))
    post = replace(snap(arch, full_arm(PC=0x1004)), stdout=b"unexpected")
    with pytest.raises(SpecValidationError, match="Unexpected output"):
        _validate_transition(identity_pc(arch, "PC", 0x1004), pre, post)


def test_executable_store_is_rejected_before_execution_even_if_same_value():
    arch = ArchAArch64("little")
    pre = snap(arch, full_arm(PC=0x1000), perms="rwx")
    transform = SymbolicTransform(1, {
        ExprMem(ExprInt(0x1000, 64), 8): ExprInt(ord("x"), 8),
        ExprId("PC", 64): ExprInt(0x1004, 64),
    }, [], arch, 0x1000, 0x1004)
    target = FakeTarget([pre], [NativeStep("instruction")])
    with pytest.raises(UnsupportedNativeEvent, match="executable memory"):
        NativeSpecValidator(target, lambda _: transform, max_steps=1).run()
    assert target.index == 0


def test_llbd_stop_signal_is_not_mistaken_for_an_instruction():
    from focaccia.execution import ExecutionOutcome, ExecutionState

    outcome = ExecutionOutcome(ExecutionState.STOPPED, stop_signal=11)

    class Target:
        def step(self):
            return outcome

    assert _step(Target()) == NativeStep("signal", signal=11)


def test_stateful_policy_refreshes_syscall_output_before_post_snapshot():
    from focaccia.native.spec_syscalls import NativeLinuxPolicy

    arch = ArchX86()
    pre = snap(arch, full_x86(RIP=0x1000, RAX=1, RDI=1, RSI=0x2000, RDX=9), {0x2000: b"abcdefghi"})
    post = snap(arch, full_x86(RIP=0x1002, RAX=9, RDI=1, RSI=0x2000, RDX=9), {0x2000: b"abcdefghi"})
    post = NativeSnapshot(
        post.arch,
        post.registers,
        post.memory,
        post.mappings,
        post.memory_capability,
        stdout=b"abcdefghi",
    )
    target = FakeTarget([pre, post], [NativeStep("instruction")])
    policy = NativeLinuxPolicy()
    with pytest.raises(SpecValidationError, match="Step budget"):
        NativeSpecValidator(target, lambda _: None, syscall_policy=policy, max_steps=1).run()
    assert target.refresh_count == 1
    assert policy.owned_fds == {0, 1, 2}
