"""Bounded, single-attempt observation for AArch64 LDAXR/STLXR regions.

The backend runs the statically verified region without instruction-step traps.
Software breakpoints cover every exit in the supplied finite CFG. This observes
only the region boundary; it does not claim intermediate-PC/trace coverage.
"""

from __future__ import annotations

import math
import os
import signal
import threading
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Mapping

from focaccia.execution import ExecutionOutcome, ExecutionState
from focaccia.native.lldb_target import ConcreteExecutionError

MAX_REGION_INSTRUCTIONS = 64
MAX_REGION_EXITS = 16
MAX_REGION_BYTES = 256
FULL_MEMORY_CAPABILITY = "full-boundary-memory-diff"


@dataclass(frozen=True, slots=True)
class RegionInstruction:
    """One decoded AArch64 instruction and its static CFG successors."""

    pc: int
    code: bytes
    successors: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class ExclusiveRegion:
    """Stable shape shared with source-region JSONL candidates."""

    entry_pc: int
    instructions: tuple[tuple[int, bytes], ...]
    exit_pcs: tuple[int, ...]
    max_steps: int


@dataclass(frozen=True, slots=True)
class BoundaryEvidence:
    """Complete boundary evidence captured with exit breakpoints removed."""

    memory: object
    registers: Mapping[str, int]
    mappings: object
    stdout: bytes
    stderr: bytes

    def __post_init__(self) -> None:
        if getattr(self.memory, "capability", None) != FULL_MEMORY_CAPABILITY:
            raise ConcreteExecutionError(
                "Exclusive observation requires full private-memory evidence."
            )
        if not isinstance(self.registers, Mapping) or not self.registers:
            raise ConcreteExecutionError(
                "Exclusive observation requires complete register evidence."
            )
        if self.registers.get("PC") is None:
            raise ConcreteExecutionError("Exclusive boundary registers lack PC.")
        if (
            self.mappings is None
            or not isinstance(self.stdout, bytes)
            or not isinstance(self.stderr, bytes)
        ):
            raise ConcreteExecutionError("Exclusive boundary lacks mapping/output evidence.")
        object.__setattr__(self, "registers", MappingProxyType(dict(self.registers)))


@dataclass(frozen=True, slots=True)
class ExclusiveObservation:
    entry_pc: int
    exit_pc: int
    store_pc: int
    pre: BoundaryEvidence
    post: BoundaryEvidence
    region_boundary_only: bool = True


def _word(code: bytes) -> int:
    if len(code) != 4:
        raise ConcreteExecutionError("AArch64 region instruction is not four bytes.")
    return int.from_bytes(code, "little")


def _branch_target(pc: int, word: int, bits: int, shift: int = 0) -> int:
    raw = (word >> shift) & ((1 << bits) - 1)
    sign = 1 << (bits - 1)
    displacement = (raw ^ sign) - sign
    return pc + (displacement << 2)


def _control_flow(pc: int, code: bytes) -> tuple[str, tuple[int, ...]]:
    """Decode supported direct A64 control flow; reject calls/indirect/SVC."""
    w = _word(code)
    if (w & 0xFFE0001F) in (0xD4000001, 0xD4000002, 0xD4000003):
        raise ConcreteExecutionError(f"Syscall/privileged trap in exclusive region at {pc:#x}.")
    if (w & 0xFFFFFC1F) in (0xD61F0000, 0xD63F0000, 0xD65F0000):
        raise ConcreteExecutionError(f"Indirect branch/call/return in exclusive region at {pc:#x}.")
    if (w & 0x7C000000) == 0x14000000:  # B / BL
        if w & 0x80000000:
            raise ConcreteExecutionError(f"Call in exclusive region at {pc:#x}.")
        return "b", (_branch_target(pc, w, 26),)
    if (w & 0xFF000010) == 0x54000000:  # B.cond
        return "b.cond", (pc + 4, _branch_target(pc, w, 19, 5))
    if (w & 0x7E000000) == 0x34000000:  # CBZ/CBNZ
        return "cb", (pc + 4, _branch_target(pc, w, 19, 5))
    if (w & 0x7E000000) == 0x36000000:  # TBZ/TBNZ
        return "tb", (pc + 4, _branch_target(pc, w, 14, 5))
    # ERET, DRPS and system instructions that can leave the ordinary user flow.
    if (w & 0xFFFFFC1F) in (0xD69F03E0, 0xD6BF03E0):
        raise ConcreteExecutionError(f"Exception/privileged instruction at {pc:#x}.")
    return "ordinary", (pc + 4,)


def _is_ldaxr(word: int) -> bool:
    return (word & 0xFFFFFC00) in (0x885FFC00, 0xC85FFC00)


def is_exclusive_entry(code: bytes) -> bool:
    """Classify an execution boundary; instruction semantics come from TIR."""
    return _is_ldaxr(_word(code))


def _is_stlxr(word: int) -> bool:
    return (word & 0xFFE0FC00) in (0x8800FC00, 0xC800FC00)


def _allowed_integer_instruction(word: int) -> bool:
    """Admit only bounded integer ALU operations plus explicit benign hints."""
    if _is_ldaxr(word) or _is_stlxr(word) or word == 0xD503201F:  # NOP
        return True
    if (word & 0xFFFFF0FF) == 0xD503305F:  # CLREX
        return True
    op = word & 0x1F000000
    if op in {
        0x0A000000,  # logical shifted-register
        0x0B000000,  # add/sub shifted-register
        0x11000000,  # add/sub immediate
        0x12000000,  # logical immediate / move-wide
        0x13000000,  # bitfield
        0x13800000,  # extract
        0x1A000000,  # conditional select / integer data-processing register
        0x1B000000,  # integer multiply/add
    }:
        return True
    # Integer data-processing (one/two source) encodings have a different
    # sf/opcode field but share this major opcode. Exclude FP/SIMD and system.
    return (word & 0x5F000000) == 0x1A000000


def _native_target(target):
    """Accept either the rich native spec wrapper or its LLDB target."""
    checker = getattr(target, "_check_live", None)
    return checker() if checker is not None else target


def verify_region(region: ExclusiveRegion) -> int:
    """Validate source-region bytes and the complete finite forward CFG."""
    rows = tuple(
        RegionInstruction(pc, code, _control_flow(pc, code)[1]) for pc, code in region.instructions
    )
    ins = {item.pc: item for item in rows}
    exits = set(region.exit_pcs)
    if (
        len(ins) != len(rows)
        or not 1 <= len(ins) <= MAX_REGION_INSTRUCTIONS
        or len(exits) != len(region.exit_pcs)
        or not 1 <= len(exits) <= MAX_REGION_EXITS
        or region.entry_pc not in ins
        or len(ins) * 4 > MAX_REGION_BYTES
        or type(region.max_steps) is not int
        or not len(ins) <= region.max_steps <= MAX_REGION_INSTRUCTIONS
    ):
        raise ConcreteExecutionError("Invalid or over-budget exclusive CFG.")
    if any(type(pc) is not int or pc < 0 or pc & 3 for pc in (*ins, *exits)):
        raise ConcreteExecutionError("Unaligned or invalid exclusive CFG PC.")
    ordered = sorted(ins)
    if (
        region.entry_pc != ordered[0]
        or any(len(item.code) != 4 for item in ins.values())
        or any(b != a + 4 for a, b in zip(ordered, ordered[1:]))
    ):
        raise ConcreteExecutionError("Exclusive CFG is not contiguous AArch64 code.")
    loads, stores, conditional_branches = [], [], []
    graph: dict[int, tuple[int, ...]] = {}
    for pc, item in ins.items():
        w = _word(item.code)
        kind, decoded = _control_flow(pc, item.code)
        if kind == "ordinary" and not _allowed_integer_instruction(w):
            raise ConcreteExecutionError(f"Unsupported non-integer instruction at {pc:#x}.")
        if kind in {"cb", "tb", "b.cond"}:
            conditional_branches.append(pc)
        elif kind != "ordinary":
            raise ConcreteExecutionError(f"Unsupported control flow at {pc:#x}.")
        if any(dst <= pc and dst not in exits for dst in decoded):
            raise ConcreteExecutionError(f"Backward edge/cycle in exclusive CFG at {pc:#x}.")
        if _is_ldaxr(w):
            loads.append(pc)
        if _is_stlxr(w):
            stores.append(pc)
        graph[pc] = decoded
    if (
        loads != [region.entry_pc]
        or len(stores) != 1
        or len(conditional_branches) > 1
        or stores[0] != ordered[-1]
    ):
        raise ConcreteExecutionError(
            "Exclusive CFG must start with one LDAXR, at most one conditional branch, and end with one STLXR."
        )
    store_pc = stores[0]
    if store_pc + 4 not in exits:
        raise ConcreteExecutionError("STLXR must terminate at an exit before any retry branch.")
    reachable: set[int] = set()
    reached_exits: set[int] = set()
    pending = [region.entry_pc]
    while pending:
        pc = pending.pop()
        if pc in exits:
            reached_exits.add(pc)
            continue
        if pc in reachable:
            continue
        if pc not in graph:
            raise ConcreteExecutionError(f"CFG edge reaches undeclared PC {pc:#x}.")
        reachable.add(pc)
        pending.extend(graph[pc])
    if (
        reachable != set(ins)
        or reached_exits != exits
        or any(dst not in ins and dst not in exits for row in graph.values() for dst in row)
    ):
        raise ConcreteExecutionError("CFG contains unreachable code or an unlisted exit.")
    return store_pc


def _has_breakpoint_at(target, pc: int) -> bool:
    sbtarget = getattr(target, "target", None)
    if sbtarget is None:
        return False
    for index in range(sbtarget.GetNumBreakpoints()):
        breakpoint = sbtarget.GetBreakpointAtIndex(index)
        for location_index in range(breakpoint.GetNumLocations()):
            location = breakpoint.GetLocationAtIndex(location_index)
            address = location.GetAddress().GetLoadAddress(sbtarget)
            if address == pc:
                return True
    return False


def _capture(
    capture_boundary: Callable[[], BoundaryEvidence], expected_pc: int
) -> BoundaryEvidence:
    evidence = capture_boundary()
    if not isinstance(evidence, BoundaryEvidence) or evidence.registers.get("PC") != expected_pc:
        raise ConcreteExecutionError("Captured boundary evidence has an unexpected PC or shape.")
    return evidence


def observe_exclusive_attempt(
    target,
    region: ExclusiveRegion,
    capture_boundary: Callable[[], BoundaryEvidence],
    *,
    timeout_seconds: float = 2.0,
) -> ExclusiveObservation:
    """Run one uninterrupted attempt; capture all declared exit boundaries."""
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("Exclusive observation timeout must be finite and positive.")
    if getattr(target, "_gdb_remote", False):
        raise ConcreteExecutionError("Exclusive observation requires a local process.")
    store_pc = verify_region(region)
    exits = tuple(sorted(region.exit_pcs))
    code_addresses = dict(region.instructions)
    original = dict(code_addresses)
    for pc in exits:
        original[pc] = target.read_memory(pc, 4)
        if len(original[pc]) != 4:
            raise ConcreteExecutionError(f"Cannot snapshot exclusive exit instruction at {pc:#x}.")
    if any(_has_breakpoint_at(target, pc) for pc in exits):
        raise ConcreteExecutionError("An unowned breakpoint already occupies an exclusive exit.")
    for pc, code in code_addresses.items():
        if target.read_memory(pc, 4) != code:
            raise ConcreteExecutionError(f"Exclusive region identity changed at {pc:#x}.")
    maps = target.get_mappings()
    for pc in (*code_addresses, *exits):
        covering = [m for m in maps if m.start_address <= pc and m.end_address >= pc + 4]
        if len(covering) != 1 or "x" not in covering[0].perms:
            raise ConcreteExecutionError(
                f"Exclusive code/exit {pc:#x} is not in one executable mapping."
            )
    if target.read_pc() != region.entry_pc:
        raise ConcreteExecutionError("Native PC is not at the exclusive-region entry.")
    pre = _capture(capture_boundary, region.entry_pc)
    ids: list[int] = []
    primary: BaseException | None = None
    timeout_event = threading.Event()
    pidfd = None
    timer = None
    timeout_lock = threading.Lock()
    active_pidfd: list[int | None] = [None]
    exit_pc = None
    try:
        for pc in exits:
            ids.append(target.set_breakpoint(pc))
        process = getattr(target, "process", None)
        if process is None or not hasattr(process, "GetProcessID"):
            raise ConcreteExecutionError("Exclusive observer requires an owned LLDB process.")
        pid = int(process.GetProcessID())
        if pid <= 0 or not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            raise ConcreteExecutionError("Owned-process timeout is unavailable on this platform.")
        pidfd = os.pidfd_open(pid)
        active_pidfd[0] = pidfd

        def expire() -> None:
            with timeout_lock:
                owned_fd = active_pidfd[0]
                if owned_fd is None:
                    return
                try:
                    signal.pidfd_send_signal(owned_fd, signal.SIGKILL)
                except ProcessLookupError:
                    return
                timeout_event.set()

        timer = threading.Timer(timeout_seconds, expire)
        timer.daemon = True
        timer.start()
        target.run()
        if timeout_event.is_set():
            raise ConcreteExecutionError("Exclusive region timed out.")
        if target.is_exited():
            raise ConcreteExecutionError(
                "Exclusive region process exited before a verified boundary."
            )
        exit_pc = target.read_pc()
        if exit_pc not in exits:
            raise ConcreteExecutionError(f"Unexpected exclusive-region stop at {exit_pc:#x}.")
        outcome = target.execution_outcome()
        if (
            getattr(outcome, "state", None) is None
            or getattr(outcome.state, "name", None) != "STOPPED"
        ):
            raise ConcreteExecutionError("Exclusive region did not stop at a boundary breakpoint.")
        if getattr(outcome, "stop_signal", None) is not None:
            raise ConcreteExecutionError("Signal/fault interrupted exclusive-region execution.")
        try:
            import lldb

            thread = process.GetSelectedThread()
            if thread.GetStopReason() != lldb.eStopReasonBreakpoint:
                raise ConcreteExecutionError(
                    "Unexpected non-breakpoint stop inside exclusive region."
                )
            reason_data = [
                thread.GetStopReasonDataAtIndex(i) for i in range(thread.GetStopReasonDataCount())
            ]
            if not set(ids).intersection(reason_data):
                raise ConcreteExecutionError("Stop was not caused by an installed exit breakpoint.")
        except (AttributeError, ImportError) as error:
            raise ConcreteExecutionError(
                "Cannot verify the exclusive exit breakpoint stop reason."
            ) from error
    except BaseException as error:
        primary = error
        raise
    finally:
        if timer is not None:
            timer.cancel()
        close_error = None
        if pidfd is not None:
            with timeout_lock:
                active_pidfd[0] = None
                try:
                    os.close(pidfd)
                except OSError as error:
                    close_error = error
        cleanup_error = None
        for breakpoint_id in reversed(ids):
            try:
                target.remove_breakpoint(breakpoint_id)
            except BaseException as error:
                cleanup_error = cleanup_error or error
        if cleanup_error is not None:
            if primary is not None:
                primary.add_note(f"Breakpoint cleanup failed: {cleanup_error}")
            else:
                raise ConcreteExecutionError(
                    f"Unable to restore exclusive breakpoints: {cleanup_error}"
                )
        if close_error is not None:
            if primary is not None:
                primary.add_note(f"Unable to close owned-process pidfd: {close_error}")
            else:
                raise ConcreteExecutionError(f"Unable to close owned-process pidfd: {close_error}")
        if not target.is_exited():
            for pc, code in original.items():
                if target.read_memory(pc, len(code)) != code:
                    error = ConcreteExecutionError(
                        f"Breakpoint code restoration failed at {pc:#x}."
                    )
                    if primary is not None:
                        primary.add_note(str(error))
                    else:
                        raise error
    if timeout_event.is_set():
        raise ConcreteExecutionError("Exclusive region timed out.")
    if target.is_exited():
        raise ConcreteExecutionError("Exclusive region exited before post-state capture.")
    post = _capture(capture_boundary, exit_pc)
    return ExclusiveObservation(region.entry_pc, exit_pc, store_pc, pre, post)


def _boundary_provider(target) -> Callable[[], BoundaryEvidence]:
    """Use the runner's full private-RAM/register/mapping/output evidence API."""
    custom = getattr(target, "capture_exclusive_boundary", None)
    if custom is not None:
        return custom
    required = ("memory_snapshot", "read_registers", "mappings", "stdout", "stderr")
    if any(not hasattr(target, name) for name in required):
        raise ConcreteExecutionError(
            "Target lacks complete private-memory, register, mapping, and output evidence."
        )

    def capture() -> BoundaryEvidence:
        refresh_output = getattr(target, "refresh_output", None)
        if refresh_output is not None:
            refresh_output()
        return BoundaryEvidence(
            target.memory_snapshot(),
            target.read_registers(),
            target.mappings(),
            target.stdout,
            target.stderr,
        )

    return capture


def region_entry_contains_target(entry_pc: int, pc: int, target_pc: int) -> bool:
    return entry_pc <= target_pc <= pc + 4


def plan_region(target, entry_pc: int) -> ExclusiveRegion:
    """Discover the source site's finite compare-skip / first-STLXR CFG."""
    native = _native_target(target)
    arch = getattr(getattr(target, "arch", None), "archname", None) or getattr(
        native, "archname", None
    )
    if arch not in {"aarch64", "arm64"}:
        raise ConcreteExecutionError("Exclusive-region discovery requires native AArch64.")
    if type(entry_pc) is not int or entry_pc < 0 or entry_pc & 3 or native.read_pc() != entry_pc:
        raise ConcreteExecutionError("Invalid or non-current exclusive-region entry PC.")
    rows: list[tuple[int, bytes]] = []
    skip_exit = None
    branch_seen = False
    store_pc = None
    pc = entry_pc
    for _ in range(MAX_REGION_INSTRUCTIONS):
        code = native.read_memory(pc, 4)
        if len(code) != 4:
            raise ConcreteExecutionError(f"Cannot read instruction bytes at {pc:#x}.")
        word = _word(code)
        kind, successors = _control_flow(pc, code)
        if kind == "ordinary" and not _allowed_integer_instruction(word):
            raise ConcreteExecutionError(f"Unsupported non-integer instruction at {pc:#x}.")
        if not rows and not _is_ldaxr(word):
            raise ConcreteExecutionError("Exclusive region does not start with LDAXR.")
        rows.append((pc, code))
        if _is_stlxr(word):
            store_pc = pc
            break
        if kind in {"b.cond", "cb", "tb"}:
            if branch_seen or region_entry_contains_target(entry_pc, pc, successors[1]):
                raise ConcreteExecutionError("Unsupported comparison branch in exclusive CFG.")
            branch_seen = True
            skip_exit = successors[1]
        elif kind != "ordinary":
            raise ConcreteExecutionError(f"Unsupported control flow before first STLXR at {pc:#x}.")
        pc += 4
    if store_pc is None:
        raise ConcreteExecutionError("No complete first-STLXR region was found.")
    store_exit = store_pc + 4
    if skip_exit is not None and (skip_exit == store_exit or skip_exit in {row_pc for row_pc, _ in rows}):
        raise ConcreteExecutionError("Comparison-skip target overlaps the exclusive attempt.")
    exits = (store_exit,) if skip_exit is None else (store_exit, skip_exit)
    region = ExclusiveRegion(entry_pc, tuple(rows), exits, len(rows))
    verify_region(region)
    return region


def execute_region(target, region: ExclusiveRegion, *, timeout_seconds: float = 2.0):
    """Return a stopped boundary outcome and evidence; never classify expected results."""
    native = _native_target(target)
    capture = _boundary_provider(target)
    observation = observe_exclusive_attempt(
        native,
        region,
        capture,
        timeout_seconds=timeout_seconds,
    )
    return ExecutionOutcome(ExecutionState.STOPPED), {
        "observation": observation,
        "entry_pc": observation.entry_pc,
        "exit_pc": observation.exit_pc,
        "store_pc": observation.store_pc,
        "pre": observation.pre,
        "post": observation.post,
        "region_boundary_only": True,
        "internal_pc_trace_available": False,
    }
