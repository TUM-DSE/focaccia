"""Concolic Tracer for native programs."""

from __future__ import annotations

import logging

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from miasm.core.utils import Disasm_Exception
from miasm.expression.expression import Expr, ExprId, ExprInt, ExprMem, ExprOp
from miasm.jitter.csts import EXCEPT_SYSCALL

from focaccia.arch import Arch, x86
from focaccia.utils import timebound, TimeoutError
from focaccia.trace import MaterializedTrace, TraceEnvironment
from focaccia.miasm_util import MiasmSymbolResolver
from focaccia.snapshot import (
    MemoryAccessError,
    ReadableProgramState,
    RegisterAccessError,
)
from focaccia.symbolic import (
    DisassemblyContext,
    GapReason,
    Instruction,
    SymbolEvaluationError,
    eval_symbol,
    SymbolicCompositionError,
    SymbolicTraceItem,
    SymbolicTransform,
    TraceGap,
    UnsupportedInstructionError,
    run_instruction,
)
from focaccia.deterministic import (
    CursorState,
    DeterministicCursor,
    Event,
    EventSynchronizationError,
    SignalEvent,
    SyscallEvent,
)

from .profiling import ProfileComponent, TraceProfiler
from .lldb_target import (
    ConcreteExecutionError,
    ConcreteMemoryError,
    ConcreteRegisterError,
    LLDBConcreteTarget,
    LLDBLocalTarget,
    LLDBRemoteTarget,
)

logger = logging.getLogger("focaccia-symbolic")
debug = logger.debug
info = logger.info
warn = logger.warning

# Disable Miasm's disassembly logger
logging.getLogger("asmblock").setLevel(logging.CRITICAL)


class ValidationError(Exception):
    pass


class DisassemblyMismatchError(ValueError):
    """A decoded instruction disagrees with the concrete instruction bytes."""


class DisassemblyError(Exception):
    def __init__(self, pc: int, primary_error: Exception, fallback_error: Exception):
        self.pc = pc
        self.primary_error = primary_error
        self.fallback_error = fallback_error
        super().__init__(
            f"Unable to disassemble instruction at {hex(pc)}. "
            f"Miasm failed with: {primary_error}. "
            f"LLDB fallback failed with: {fallback_error}."
        )


_CONDITION_MNEMONIC_ALIASES = {
    "E": "Z",
    "NE": "NZ",
    "AE": "NB",
    "NC": "NB",
    "NAE": "B",
    "C": "B",
    "NA": "BE",
    "NBE": "A",
    "PE": "P",
    "PO": "NP",
    "NL": "GE",
    "NGE": "L",
    "NG": "LE",
    "NLE": "G",
}


def _normalized_disassembly_mnemonic(text: str) -> str:
    tokens = text.upper().split()
    while tokens and tokens[0] in ("LOCK", "REP", "REPE", "REPZ", "REPNE", "REPNZ"):
        tokens.pop(0)
    if not tokens:
        return ""
    mnemonic = tokens[0]
    for prefix in ("CMOV", "SET", "J"):
        if mnemonic.startswith(prefix):
            condition = mnemonic[len(prefix) :]
            return prefix + _CONDITION_MNEMONIC_ALIASES.get(condition, condition)
    return mnemonic


def _disassembly_mnemonics_compatible(primary: str, concrete: str) -> bool:
    primary_mnemonic = _normalized_disassembly_mnemonic(primary)
    concrete_mnemonic = _normalized_disassembly_mnemonic(concrete)
    if not primary_mnemonic or not concrete_mnemonic:
        return False
    if primary_mnemonic == concrete_mnemonic:
        return True
    for suffix in ("PS", "PD", "SS", "SD"):
        predicate_mnemonics = {
            f"CMP{predicate}{suffix}"
            for predicate in ("EQ", "LT", "LE", "UNORD", "NEQ", "NLT", "NLE", "ORD")
        }
        if concrete_mnemonic == f"CMP{suffix}" and primary_mnemonic in predicate_mnemonics:
            return True
    return False


def _concrete_disassembly(
    target: LLDBConcreteTarget,
    pc: int,
) -> tuple[int, bytes, str | None]:
    size = target.get_instruction_size(pc)
    bytecode = target.read_instructions(pc, size)
    if target.arch.archname == x86.archname and size == 1 and bytecode == b"\xf0":
        suffix_pc = pc + size
        suffix_size = target.get_instruction_size(suffix_pc)
        suffix_bytes = target.read_instructions(suffix_pc, suffix_size)
        suffix_text = target.get_disassembly(suffix_pc)
        return (
            size + suffix_size,
            bytecode + suffix_bytes,
            f"LOCK {suffix_text}",
        )
    return size, bytecode, None


def _validate_primary_disassembly(
    instruction: Instruction,
    target: LLDBConcreteTarget,
    pc: int,
) -> None:
    source_bytes = target.read_instructions(pc, instruction.length)
    encoding_error: Exception | None = None
    try:
        decoded_bytes = instruction.to_bytecode()
    except (Disasm_Exception, ValueError, NotImplementedError) as err:
        decoded_bytes = None
        encoding_error = err
    if decoded_bytes == source_bytes:
        return

    # Alternate encodings are common (short branches, ignored SIB scale bits,
    # and redundant REX bits). Consult LLDB only on a byte mismatch so the
    # normal tracing path does not pay for a second disassembly per instruction.
    concrete_size, concrete_bytes, concrete_text = _concrete_disassembly(target, pc)
    if instruction.length != concrete_size:
        raise DisassemblyMismatchError(
            f"Miasm decoded {instruction} as {instruction.length} bytes at "
            f"{hex(pc)}, but LLDB reports {concrete_size} bytes "
            f"({concrete_bytes.hex()})."
        )
    if concrete_text is None:
        concrete_text = target.get_disassembly(pc)
    if _disassembly_mnemonics_compatible(str(instruction), concrete_text):
        return
    decoded_description = (
        decoded_bytes.hex() if decoded_bytes is not None else f"unverifiable ({encoding_error})"
    )
    raise DisassemblyMismatchError(
        f"Miasm decoded {instruction} at {hex(pc)} as "
        f"{decoded_description}, but concrete bytes are "
        f"{concrete_bytes.hex()} and LLDB reports {concrete_text!r}."
    )


def _disassemble_instruction(
    ctx: DisassemblyContext, target: LLDBConcreteTarget, pc: int
) -> Instruction:
    try:
        instruction = ctx.disassemble(pc)
        _validate_primary_disassembly(instruction, target, pc)
        return instruction
    except (
        Disasm_Exception,
        ConcreteExecutionError,
        ConcreteMemoryError,
        MemoryAccessError,
        ValueError,
        NotImplementedError,
    ) as primary_error:
        try:
            disassembly = target.get_disassembly(pc)
            if not disassembly.strip():
                raise ConcreteExecutionError(f"LLDB returned empty disassembly at {hex(pc)}.")
            return Instruction.from_string(
                disassembly,
                ctx.arch,
                pc,
                target.get_instruction_size(pc),
            )
        except (
            Disasm_Exception,
            ConcreteExecutionError,
            ConcreteMemoryError,
            ValueError,
            NotImplementedError,
        ) as fallback_error:
            raise DisassemblyError(pc, primary_error, fallback_error) from fallback_error


def _events_for_environment(env: TraceEnvironment) -> tuple[Event, ...]:
    if env.detlog is None:
        return ()
    return env.detlog.events()


_EVENT_SYNC_BASE_REGISTERS = {
    "x86_64": frozenset(
        {
            "RAX",
            "RBX",
            "RCX",
            "RDX",
            "RSI",
            "RDI",
            "RBP",
            "RSP",
            "R8",
            "R9",
            "R10",
            "R11",
            "R12",
            "R13",
            "R14",
            "R15",
        }
    ),
    "aarch64": frozenset({*(f"X{index}" for index in range(31)), "SP"}),
}


def _is_pre_event(event: Event | None) -> bool:
    if isinstance(event, SyscallEvent):
        return event.syscall_state in ("entering", "enteringPtrace")
    if isinstance(event, SignalEvent):
        return event.signal_variant == "signal"
    return False


def _match_deterministic_event(
    cursor: DeterministicCursor[ReadableProgramState],
    target: ReadableProgramState,
) -> tuple[Event | None, Event | None, bool]:
    event = cursor.match(target)
    is_pre_event = _is_pre_event(event)
    if not is_pre_event:
        return event, None, False

    pending = cursor.peek()
    if isinstance(event, SyscallEvent) and pending is not None:
        if pending.event_type == "exit":
            return event, cursor.match_terminal(event), True
    return event, cursor.match_pair(event), True


def _is_terminal_event(event: Event | None) -> bool:
    return event is not None and event.event_type == "exit"


def _signal_action_transform(
    pre_event: SignalEvent,
    post_event: SignalEvent,
) -> SymbolicTransform:
    """Materialize a recorded signal delivery as an action transition."""
    if pre_event.pc is None or post_event.pc is None:
        raise EventSynchronizationError(
            "Signal action requires pre- and post-event program counters."
        )
    if pre_event.arch != post_event.arch or pre_event.tid != post_event.tid:
        raise EventSynchronizationError("Signal action pre/post events use different targets.")

    arch = pre_event.arch
    outputs: dict[Expr, Expr] = {}
    for regname in post_event.registers:
        accessor = arch.get_reg_accessor(regname)
        if accessor is None:
            raise EventSynchronizationError(f"Signal action contains unknown register {regname!r}.")
        outputs[ExprId(regname, accessor.num_bits)] = ExprInt(
            post_event.registers[regname],
            accessor.num_bits,
        )

    if post_event.extra_registers is not None:
        if arch.archname == "x86_64":
            candidates = (f"XMM{index}" for index in range(16))
        elif arch.archname == "aarch64":
            candidates = (
                *(f"V{index}" for index in range(32)),
                "FPSR",
                "FPCR",
            )
        else:
            candidates = ()
        for regname in candidates:
            accessor = arch.get_reg_accessor(regname)
            if accessor is None:
                continue
            try:
                value = post_event.extra_registers.read_register(regname)
            except KeyError:
                continue
            outputs[ExprId(regname, accessor.num_bits)] = ExprInt(
                value,
                accessor.num_bits,
            )

    for write in post_event.mem_writes:
        data = write.materialize()
        if not data:
            continue
        outputs[ExprMem(ExprInt(write.address, arch.ptr_size), len(data) * 8)] = ExprInt(
            int.from_bytes(data, arch.endianness), len(data) * 8
        )

    return SymbolicTransform(
        pre_event.tid,
        outputs,
        [],
        arch,
        pre_event.pc,
        post_event.pc,
    )


def _terminal_syscall_transition(
    destination: ExprInt | None,
    outputs: dict[Expr, Expr],
    event: Event | None,
    post_event: Event | None,
    instruction: Instruction,
    pc_output: Expr,
    arch: Arch,
) -> tuple[ExprInt | None, dict[Expr, Expr]]:
    if (
        not isinstance(event, SyscallEvent)
        or not _is_terminal_event(post_event)
        or not str(instruction).upper().startswith("SYSCALL")
    ):
        return destination, outputs

    terminal = ExprInt(0, arch.ptr_size)
    normalized = dict(outputs)
    normalized[pc_output] = terminal
    return terminal, normalized


def _architectural_outputs_for_recorded_syscall(
    outputs: dict[Expr, Expr],
    event: Event | None,
    post_event: Event | None,
    instruction: Instruction,
) -> dict[Expr, Expr]:
    if (
        not isinstance(event, SyscallEvent)
        or not (isinstance(post_event, SyscallEvent) or _is_terminal_event(post_event))
        or not str(instruction).upper().startswith("SYSCALL")
    ):
        return outputs

    marker = ExprId("exception_flags", 32)
    if outputs.get(marker) != ExprInt(EXCEPT_SYSCALL, 32):
        return outputs
    return {destination: value for destination, value in outputs.items() if destination != marker}


_LSL_ENVIRONMENT_OPERATIONS = frozenset({"load_segment_limit", "load_segment_limit_ok"})


def _contains_lsl_environment_operation(expression: Expr) -> bool:
    if isinstance(expression, ExprOp) and expression.op in _LSL_ENVIRONMENT_OPERATIONS:
        return True
    children = list(getattr(expression, "args", ()))
    children.extend(
        getattr(expression, attribute)
        for attribute in ("arg", "cond", "src1", "src2", "ptr")
        if hasattr(expression, attribute)
    )
    return any(
        _contains_lsl_environment_operation(child) for child in children if isinstance(child, Expr)
    )


def _requires_observed_lsl_specialization(
    instruction: Instruction,
    outputs: dict[Expr, Expr],
) -> bool:
    return str(instruction).split(maxsplit=1)[0].upper() == "LSL" and any(
        _contains_lsl_environment_operation(value) for value in outputs.values()
    )


def _specialize_observed_lsl_outputs(
    instruction: Instruction,
    outputs: dict[Expr, Expr],
    target: ReadableProgramState,
) -> dict[Expr, Expr]:
    """Record the observed LSL path without querying analyzer-host tables."""
    if not _requires_observed_lsl_specialization(instruction, outputs):
        return outputs

    if not instruction.instr.args or not isinstance(instruction.instr.args[0], ExprId):
        raise SymbolicCompositionError(
            f"Observed LSL specialization requires a register destination: {instruction}."
        )
    destination = instruction.instr.args[0]
    destination_reg = target.arch.to_regname(destination.name)
    if destination_reg is None:
        raise SymbolicCompositionError(f"Unknown LSL destination register {destination.name!r}.")

    specialized = {
        output: value
        for output, value in outputs.items()
        if not _contains_lsl_environment_operation(value)
    }
    zf = target.read_register("ZF")
    specialized[ExprId("zf", 1)] = ExprInt(zf, 1)
    if zf:
        specialized[destination] = ExprInt(
            target.read_register(destination_reg),
            destination.size,
        )
    return specialized


def _architectural_outputs_for_observed_division(
    outputs: dict[Expr, Expr],
    instruction: Instruction,
    state: ReadableProgramState,
) -> dict[Expr, Expr]:
    """Remove Miasm's internal divide-exception control on a successful path."""
    if str(instruction).split(maxsplit=1)[0].upper() not in {"DIV", "IDIV"}:
        return outputs

    marker = ExprId("exception_flags", 32)
    control = outputs.get(marker)
    if control is None:
        return outputs

    # ``exception_flags`` is Miasm-internal control state, not architectural
    # CPU state. Replace its prior value with the no-pending-exception value
    # and evaluate the control equation at the concrete pre-instruction state.
    # A nonzero result retains the marker and therefore fails closed.
    observed = eval_symbol(
        control.replace_expr({marker: ExprInt(0, marker.size)}),
        state,
    )
    if observed != 0:
        return outputs
    return {destination: value for destination, value in outputs.items() if destination != marker}


def match_event(event: Event, target: ReadableProgramState) -> bool:
    """Match one deterministic event using a named, architecture-specific subset."""
    if event.arch != target.arch:
        return False
    arch = target.arch
    if event.pc is None:
        return False
    try:
        if event.pc != target.read_pc():
            return False
    except (RegisterAccessError, ConcreteRegisterError):
        return False

    pc_name = arch.to_regname("PC")
    pc_accessor = arch.get_reg_accessor(pc_name) if pc_name is not None else None
    if pc_accessor is None:
        return False
    synchronized_bases = _EVENT_SYNC_BASE_REGISTERS.get(arch.archname, frozenset())
    if (
        isinstance(event, SyscallEvent)
        and arch.archname == "x86_64"
        and event.syscall_state in ("entering", "enteringPtrace")
    ):
        # RR's entering stop is recorded after SYSCALL has copied the return
        # PC and flags into RCX and R11. The adapter rewinds RIP and RAX to the
        # pre-instruction boundary, but those hardware-clobbered values cannot
        # be compared with the concrete state before SYSCALL executes.
        synchronized_bases -= {"RCX", "R11"}

    for name, expected in event.registers.items():
        canonical = arch.to_regname(name)
        if canonical is None:
            continue
        accessor = arch.get_reg_accessor(canonical)
        if accessor is None or accessor.base_reg == pc_accessor.base_reg:
            continue
        if accessor.base_reg not in synchronized_bases:
            continue
        try:
            actual = target.read_register(canonical)
        except (RegisterAccessError, ConcreteRegisterError):
            return False
        if actual != expected:
            return False
    return True


class NativeTarget(Protocol):
    arch: Arch

    def read_pc(self) -> int: ...
    def read_register(self, regname: str) -> int: ...
    def read_flags(self) -> dict[str, int | bool]: ...
    def read_memory(self, addr: int, size: int) -> bytes: ...
    def write_register(self, regname: str, value: int) -> None: ...
    def write_memory(self, addr: int, value: bytes) -> None: ...
    def step(self) -> None: ...
    def run(self) -> None: ...
    def run_until(self, address: int) -> None: ...
    def is_exited(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class MemoryCacheKey:
    address: int
    size: int

    @property
    def end(self) -> int:
        return self.address + self.size

    def overlaps(self, address: int, size: int) -> bool:
        return self.address < address + size and address < self.end


class SpeculativeDivergenceError(RuntimeError):
    """Raised when concrete execution does not reach the predicted PC."""

    def __init__(self, expected: int, actual: int | None, predictions: tuple[int, ...]):
        self.expected = expected
        self.actual = actual
        self.predictions = predictions
        expected_text = "process exit" if expected == 0 else hex(expected)
        actual_text = "process exit" if actual is None else hex(actual)
        super().__init__(
            f"Speculative execution expected {expected_text}, observed {actual_text}; "
            f"predicted path: {[hex(pc) for pc in predictions]}."
        )


class SpeculativeTracer(ReadableProgramState):
    def __init__(self, target: NativeTarget):
        super().__init__(target.arch)
        self.target = target
        self.pc = target.read_pc()
        self._predicted_pcs: list[int] = []
        self._register_cache: dict[str, int] = {}
        self._memory_cache: dict[MemoryCacheKey, bytes] = {}
        self._flags_cache: dict[str, int | bool] | None = None

    @property
    def speculative_pc(self) -> int | None:
        return self._predicted_pcs[-1] if self._predicted_pcs else None

    @property
    def speculative_count(self) -> int:
        return len(self._predicted_pcs)

    def _clear_cache(self) -> None:
        self._register_cache.clear()
        self._memory_cache.clear()
        self._flags_cache = None

    def _clear_predictions(self) -> None:
        self._predicted_pcs.clear()

    def _verify_observed_pc(
        self,
        expected: int,
        predictions: tuple[int, ...],
    ) -> int | None:
        if self.target.is_exited():
            self.pc = 0
            if expected == 0:
                return None
            raise SpeculativeDivergenceError(expected, None, predictions)

        actual = self.target.read_pc()
        self.pc = actual
        if expected == 0 or actual != expected:
            raise SpeculativeDivergenceError(expected, actual, predictions)
        return actual

    def speculate(self, new_pc: int | None) -> None:
        self._clear_cache()
        if new_pc is None:
            self.progress_execution()
            if self.target.is_exited():
                return
            self.target.step()
            self.pc = 0 if self.target.is_exited() else self.target.read_pc()
            return

        destination = int(new_pc)
        if destination < 0:
            raise ValueError("A speculative destination cannot be negative.")
        self._predicted_pcs.append(destination)

    def progress_execution(self, *, use_breakpoint: bool = False) -> int | None:
        if not self._predicted_pcs:
            return None if self.target.is_exited() else self.pc

        predictions = tuple(self._predicted_pcs)
        expected = predictions[-1]
        debug(
            f"Materializing {len(predictions)} speculative transitions at "
            f"{'exit' if expected == 0 else hex(expected)}"
        )
        try:
            if expected == 0:
                if len(predictions) > 1:
                    preterminal = predictions[-2]
                    self.target.run_until(preterminal)
                    self._verify_observed_pc(preterminal, predictions[:-1])
                if self.target.is_exited():
                    raise SpeculativeDivergenceError(expected, None, predictions)
                self.target.step()
            elif len(predictions) == 1:
                if use_breakpoint and expected != self.pc:
                    # RR's GDB server can implement one debugger instruction
                    # step across both a recorded syscall and the following
                    # instruction. A breakpoint at the known post-event
                    # boundary preserves that instruction as a separate
                    # transition.
                    self.target.run_until(expected)
                else:
                    self.target.step()
            elif expected == self.pc or expected in predictions[:-1]:
                # An address breakpoint cannot identify the final occurrence of
                # a repeated PC. In particular, run_until() is a no-op when a
                # speculative cycle ends at its concrete starting address.
                for position, predicted_pc in enumerate(predictions, start=1):
                    self.target.step()
                    self._verify_observed_pc(
                        predicted_pc,
                        predictions[:position],
                    )
                return self.pc
            else:
                self.target.run_until(expected)
            return self._verify_observed_pc(expected, predictions)
        finally:
            self._clear_predictions()
            self._clear_cache()

    def is_exited(self) -> bool:
        if self.speculative_pc == 0:
            self.progress_execution()
        return self.target.is_exited()

    def run_until(self, addr: int) -> None:
        self.progress_execution()
        if self.target.is_exited():
            raise RuntimeError(f"Cannot run an exited target to {hex(addr)}.")
        if self.pc == addr:
            return
        try:
            self.target.run_until(addr)
            self._verify_observed_pc(addr, (addr,))
        finally:
            self._clear_cache()

    def run_to_exit(self) -> None:
        self.progress_execution()
        if self.target.is_exited():
            self.pc = 0
            return
        try:
            # RR reports the recorded terminal signal as an intermediate stop
            # before a subsequent continue reports eStateExited. Keep this
            # transaction bounded so an unexpected stop cannot loop forever.
            for _ in range(4):
                self.target.run()
                if self.target.is_exited():
                    self.pc = 0
                    return
            actual = self.target.read_pc()
            self.pc = actual
            raise SpeculativeDivergenceError(0, actual, (0,))
        finally:
            self._clear_predictions()
            self._clear_cache()

    def step(self) -> None:
        self.progress_execution()
        if self.target.is_exited():
            return
        try:
            self.target.step()
            self.pc = 0 if self.target.is_exited() else self.target.read_pc()
        finally:
            self._clear_cache()

    def read_pc(self) -> int:
        return self.speculative_pc if self.speculative_pc is not None else self.pc

    def read_flags(self) -> dict[str, int | bool]:
        self.progress_execution()
        if self._flags_cache is None:
            self._flags_cache = self.target.read_flags()
        return self._flags_cache.copy()

    def read_register(self, reg: str) -> int:
        canonical = self.arch.to_regname(reg)
        if canonical is None:
            raise RegisterAccessError(reg, f"Not a register name: {reg}")
        self.progress_execution()
        if canonical not in self._register_cache:
            self._register_cache[canonical] = self.target.read_register(canonical)
        return self._register_cache[canonical]

    def _invalidate_register(self, regname: str) -> None:
        written = self.arch.get_reg_accessor(regname)
        if written is None:
            raise RegisterAccessError(regname, f"Not a register name: {regname}")
        zero_extends = self.arch.register_write_zero_extends(regname)
        for cached_name in tuple(self._register_cache):
            cached = self.arch.get_reg_accessor(cached_name)
            if cached is None or cached.base_reg != written.base_reg:
                continue
            if zero_extends or cached.mask & written.mask:
                del self._register_cache[cached_name]
        if self._flags_cache is not None:
            for flag_name in self._flags_cache:
                flag = self.arch.get_reg_accessor(flag_name)
                if flag is not None and flag.base_reg == written.base_reg:
                    self._flags_cache = None
                    break

    def write_register(self, regname: str, value: int) -> None:
        canonical = self.arch.to_regname(regname)
        if canonical is None:
            raise RegisterAccessError(regname, f"Not a register name: {regname}")
        self.progress_execution()
        self._invalidate_register(canonical)
        self.target.write_register(canonical, value)
        written = self.arch.get_reg_accessor(canonical)
        pc_name = self.arch.to_regname("PC")
        pc = self.arch.get_reg_accessor(pc_name) if pc_name is not None else None
        if written is not None and pc is not None and written.base_reg == pc.base_reg:
            self.pc = self.target.read_pc()

    def read_instructions(self, addr: int, size: int) -> bytes:
        return self.target.read_memory(addr, size)

    def read_memory(self, addr: int, size: int) -> bytes:
        if size < 0:
            raise ValueError("A memory read size cannot be negative.")
        self.progress_execution()
        key = MemoryCacheKey(addr, size)
        if key not in self._memory_cache:
            self._memory_cache[key] = self.target.read_memory(addr, size)
        return self._memory_cache[key]

    def write_memory(self, addr: int, value: bytes) -> None:
        self.progress_execution()
        for key in tuple(self._memory_cache):
            if key.overlaps(addr, len(value)):
                del self._memory_cache[key]
        self.target.write_memory(addr, value)

    def __getattr__(self, name: str):
        return getattr(self.target, name)


class SymbolicTracer:
    """A symbolic tracer that uses `LLDBConcreteTarget` with Miasm to simultaneously execute a
    program with concrete state and collect its symbolic transforms
    """

    def __init__(
        self,
        env: TraceEnvironment,
        remote: str | None = None,
        force: bool = False,
        cross_validate: bool = False,
        profiler: TraceProfiler | None = None,
    ):
        self.env = env
        self.force = force
        self.remote = remote
        self.cross_validate = cross_validate
        self.profiler = profiler
        self.target = SpeculativeTracer(self.create_debug_target())

    def _profile_start(self, component: ProfileComponent) -> float | None:
        profiler = getattr(self, "profiler", None)
        return None if profiler is None else profiler.start(component)

    def _profile_finish(
        self,
        component: ProfileComponent,
        started: float | None,
    ) -> None:
        profiler = getattr(self, "profiler", None)
        if profiler is not None:
            profiler.finish(component, started)

    def create_debug_target(self) -> LLDBConcreteTarget:
        binary = self.env.binary_name
        if binary is None:
            raise ValueError("A binary is required to create a native trace target.")
        if self.remote is None:
            debug(f"Launching local debug target {binary} {self.env.argv}")
            debug(f"Environment: {self.env}")
            return LLDBLocalTarget(
                binary,
                list(self.env.argv),
                list(self.env.envp),
                self.profiler,
            )

        debug(f"Connecting to remote debug target {self.remote}")
        target = LLDBRemoteTarget(self.remote, binary, self.profiler)

        module_name = target.determine_name()
        binary = str(Path(self.env.binary_name).resolve())
        if binary != module_name:
            warn(f"Discovered binary name {module_name} differs from specified name {binary}")

        return target

    def predict_next_state(self, instruction: Instruction, transform: SymbolicTransform):
        debug(f"Evaluating register and memory transforms for {instruction} to cross-validate")
        predicted_regs = transform.eval_validation_register_transforms(self.target)
        predicted_mems = transform.eval_memory_transforms(self.target)
        return predicted_regs, predicted_mems

    def validate(
        self,
        instruction: Instruction,
        transform: SymbolicTransform,
        predicted_regs: dict[str, int],
        predicted_mems: dict[int, bytes],
    ):
        # Verify last generated transform by comparing concrete state against
        # predicted values.
        if self.target.is_exited():
            return

        profile_start = self._profile_start("validation")
        try:
            debug("Cross-validating symbolic transforms by comparing actual to predicted values")
            for reg, val in predicted_regs.items():
                conc_val = self.target.read_register(reg)
                if conc_val != val:
                    raise ValidationError(
                        f"Symbolic execution backend generated false equation for"
                        f" [{hex(instruction.addr)}]: {instruction}:"
                        f" Predicted {reg} = {hex(val)}, but the"
                        f" concrete state has value {reg} = {hex(conc_val)}."
                        f"\nFaulty transformation: {transform}"
                    )
            for addr, data in predicted_mems.items():
                conc_data = self.target.read_memory(addr, len(data))
                if conc_data != data:
                    raise ValidationError(
                        f"Symbolic execution backend generated false equation for"
                        f" [{hex(instruction.addr)}]: {instruction}: Predicted"
                        f" mem[{hex(addr)}:{hex(addr + len(data))}] = {data},"
                        f" but the concrete state has value"
                        f" mem[{hex(addr)}:{hex(addr + len(data))}] = {conc_data}."
                        f"\nFaulty transformation: {transform}"
                    )
        finally:
            self._profile_finish("validation", profile_start)

    def progress(
        self,
        new_pc,
        step: bool = False,
        terminal: bool = False,
        recorded_syscall_destination: int | None = None,
    ) -> int | None:
        if terminal:
            info(f"Running terminal event at {hex(self.target.read_pc())}")
            self.target.run_to_exit()
            return None

        concrete_destination = recorded_syscall_destination if new_pc is None else new_pc
        self.target.speculate(concrete_destination)
        if step:
            info(f"Stepping through event at {hex(self.target.read_pc())}")
            self.target.progress_execution(use_breakpoint=recorded_syscall_destination is not None)
            if self.target.is_exited():
                return None
        return self.target.read_pc()

    def _trace_gap(
        self,
        tid: int,
        arch: Arch,
        start: int,
        end: int,
        reason: GapReason,
        error: BaseException,
        *,
        instruction: Instruction | None = None,
    ) -> TraceGap:
        return TraceGap(
            tid,
            arch,
            start,
            end,
            reason,
            str(error),
            instruction=instruction,
            cause=error,
        )

    def trace(self, time_limit: int | None = None) -> MaterializedTrace[SymbolicTraceItem]:
        """Execute a program and compute state transformations between executed
        instructions.

        :param start_addr: Address from which to start tracing.
        :param stop_addr: Address until which to trace.
        """
        # Set up concrete reference state
        if self.env.start_address is not None:
            self.target.run_until(self.env.start_address)

        ctx = DisassemblyContext(self.target)
        arch = ctx.arch

        event_matcher = DeterministicCursor(
            _events_for_environment(self.env),
            match_event,
        )
        if logger.isEnabledFor(logging.DEBUG):
            debug("Tracing program with the following non-deterministic events")
            for event in event_matcher.events:
                debug(event)

        # Trace concolically
        strace: list[SymbolicTraceItem] = []
        while not self.target.is_exited():
            pc = self.target.read_pc()

            if self.env.stop_address is not None and pc == self.env.stop_address:
                info(f"Reached stop address at {hex(pc)}")
                break

            # Disassemble instruction at the current PC
            symbolic_start = self._profile_start("symbolic")
            tid = self.target.get_current_tid()
            try:
                instruction = _disassemble_instruction(ctx, self.target, pc)
                info(f"[{tid}] Disassembled instruction {instruction} at {hex(pc)}")
            except DisassemblyError as err:
                if not self.force:
                    raise
                warn(f"[{tid}] {err} Recording an explicit trace gap.")
                self._profile_finish("symbolic", symbolic_start)
                self.target.step()
                next_pc = 0 if self.target.is_exited() else self.target.read_pc()
                strace.append(
                    self._trace_gap(
                        tid,
                        arch,
                        pc,
                        next_pc,
                        "disassembly-error",
                        err,
                    )
                )
                if self.target.is_exited():
                    break
                continue

            if event_matcher.state is CursorState.SYNCHRONIZED:
                pending_event = event_matcher.peek()
                if pending_event is not None and pending_event.pc is None:
                    raise EventSynchronizationError(
                        f"RR event {pending_event.event_count} "
                        f"({pending_event.event_type}) has no program counter and "
                        "cannot be synchronized by the native tracer."
                    )
            event, post_event, is_pre_event = _match_deterministic_event(
                event_matcher,
                self.target,
            )
            if isinstance(event, SignalEvent):
                if not isinstance(post_event, SignalEvent):
                    raise EventSynchronizationError(
                        "A signal pre-event requires a paired signal event."
                    )
                action = _signal_action_transform(event, post_event)
                predicted_regs: dict[str, int] = {}
                predicted_mems: dict[int, bytes] = {}
                if self.cross_validate:
                    predicted_regs, predicted_mems = self.predict_next_state(
                        instruction,
                        action,
                    )
                self._profile_finish("symbolic", symbolic_start)
                self.progress(post_event.pc, step=True)
                if self.cross_validate:
                    self.validate(
                        instruction,
                        action,
                        predicted_regs,
                        predicted_mems,
                    )
                strace.append(action)
                if self.target.is_exited():
                    break
                continue

            instruction_is_syscall = self.target.arch.is_instr_syscall(str(instruction))
            in_event = is_pre_event or instruction_is_syscall
            terminal_event = _is_terminal_event(post_event)
            recorded_syscall_destination = (
                int(post_event.pc)
                if (
                    is_pre_event
                    and isinstance(event, SyscallEvent)
                    and isinstance(post_event, SyscallEvent)
                    and post_event.pc is not None
                    and instruction_is_syscall
                )
                else None
            )

            # Run instruction
            conc_state = MiasmSymbolResolver(self.target, ctx.loc_db)

            symbolic_error: BaseException | None = None
            gap_reason: GapReason = "unsupported-semantics"
            try:
                new_pc, modified = timebound(
                    time_limit,
                    run_instruction,
                    instruction.instr,
                    conc_state,
                    ctx.lifter,
                )
                if terminal_event:
                    new_pc, modified = _terminal_syscall_transition(
                        new_pc,
                        modified,
                        event,
                        post_event,
                        instruction,
                        ctx.lifter.pc,
                        arch,
                    )
                modified = _architectural_outputs_for_recorded_syscall(
                    modified,
                    event,
                    post_event,
                    instruction,
                )
                modified = _architectural_outputs_for_observed_division(
                    modified,
                    instruction,
                    self.target,
                )
                if new_pc is None:
                    raise SymbolEvaluationError("Symbolic execution produced no destination PC.")
            except TimeoutError as error:
                if not self.force:
                    raise
                warn(
                    f"Running instruction {instruction} exceeded {time_limit} seconds; "
                    "recording an explicit trace gap."
                )
                symbolic_error = error
                gap_reason = "symbolic-timeout"
                new_pc, modified = None, {}
            except (
                UnsupportedInstructionError,
                SymbolEvaluationError,
                RegisterAccessError,
                MemoryAccessError,
                ConcreteRegisterError,
                ConcreteMemoryError,
                ValueError,
            ) as error:
                if not self.force:
                    raise
                warn(
                    f"Unable to run instruction symbolically: {error}; "
                    "recording an explicit trace gap."
                )
                symbolic_error = error
                new_pc, modified = None, {}

            self._profile_finish("symbolic", symbolic_start)

            if symbolic_error is not None:
                self.progress(
                    None,
                    step=bool(in_event),
                    terminal=terminal_event,
                    recorded_syscall_destination=recorded_syscall_destination,
                )
                observed_pc = 0 if self.target.is_exited() else self.target.read_pc()
                transform: SymbolicTraceItem = self._trace_gap(
                    tid,
                    arch,
                    pc,
                    observed_pc,
                    gap_reason,
                    symbolic_error,
                    instruction=instruction,
                )
            elif self.cross_validate:
                if new_pc is None:
                    raise SymbolEvaluationError("Cross-validation requires a destination PC.")
                # Verify generated equations against the concrete target before
                # retaining them. A forced failure is an explicit gap.
                destination = int(new_pc)
                progressed = False
                if _requires_observed_lsl_specialization(instruction, modified):
                    self.progress(
                        destination,
                        step=True,
                        terminal=terminal_event,
                        recorded_syscall_destination=recorded_syscall_destination,
                    )
                    progressed = True
                    modified = _specialize_observed_lsl_outputs(
                        instruction,
                        modified,
                        self.target,
                    )

                symbolic_start = self._profile_start("symbolic")
                candidate: SymbolicTransform | None = None
                cross_validation_error: BaseException | None = None
                failure_reason: GapReason = "cross-validation-error"
                try:
                    candidate = SymbolicTransform(
                        tid,
                        modified,
                        [instruction],
                        arch,
                        pc,
                        destination,
                    )
                except (SymbolicCompositionError, ValueError) as error:
                    if not self.force:
                        raise
                    cross_validation_error = error
                    failure_reason = "unsupported-semantics"
                self._profile_finish("symbolic", symbolic_start)

                pred_regs: dict[str, int] = {}
                pred_mems: dict[int, bytes] = {}
                if candidate is not None:
                    try:
                        try:
                            pred_regs, pred_mems = self.predict_next_state(
                                instruction,
                                candidate,
                            )
                        except (
                            SymbolEvaluationError,
                            RegisterAccessError,
                            MemoryAccessError,
                            ConcreteRegisterError,
                            ConcreteMemoryError,
                            ValueError,
                        ) as error:
                            if not self.force:
                                raise
                            cross_validation_error = error
                    finally:
                        if not progressed:
                            self.progress(
                                destination,
                                step=True,
                                terminal=terminal_event,
                                recorded_syscall_destination=recorded_syscall_destination,
                            )
                elif not progressed:
                    self.progress(
                        None,
                        step=bool(in_event),
                        terminal=terminal_event,
                        recorded_syscall_destination=recorded_syscall_destination,
                    )

                if candidate is not None and cross_validation_error is None:
                    try:
                        self.validate(instruction, candidate, pred_regs, pred_mems)
                    except (
                        ValidationError,
                        ConcreteRegisterError,
                        ConcreteMemoryError,
                        RegisterAccessError,
                        MemoryAccessError,
                    ) as error:
                        if not self.force:
                            raise
                        cross_validation_error = error

                if candidate is not None and cross_validation_error is None:
                    transform = candidate
                else:
                    assert cross_validation_error is not None
                    warn(
                        f"Symbolic construction/cross-validation failed: "
                        f"{cross_validation_error}; recording an explicit trace gap."
                    )
                    observed_pc = 0 if self.target.is_exited() else self.target.read_pc()
                    transform = self._trace_gap(
                        tid,
                        arch,
                        pc,
                        observed_pc,
                        failure_reason,
                        cross_validation_error,
                        instruction=instruction,
                    )
            else:
                if new_pc is None:
                    raise SymbolEvaluationError("A symbolic transform requires a destination PC.")
                predicted_destination = int(new_pc)
                symbolic_start = self._profile_start("symbolic")
                try:
                    candidate = SymbolicTransform(
                        tid,
                        modified,
                        [instruction],
                        arch,
                        pc,
                        predicted_destination,
                    )
                except (SymbolicCompositionError, ValueError) as error:
                    if not self.force:
                        raise
                    warn(
                        f"Unable to construct symbolic transform: {error}; "
                        "recording an explicit trace gap."
                    )
                    self.progress(
                        None,
                        step=bool(in_event),
                        terminal=terminal_event,
                        recorded_syscall_destination=recorded_syscall_destination,
                    )
                    observed_pc = 0 if self.target.is_exited() else self.target.read_pc()
                    transform = self._trace_gap(
                        tid,
                        arch,
                        pc,
                        observed_pc,
                        "unsupported-semantics",
                        error,
                        instruction=instruction,
                    )
                else:
                    progressed_pc = self.progress(
                        new_pc,
                        step=bool(in_event),
                        terminal=terminal_event,
                        recorded_syscall_destination=recorded_syscall_destination,
                    )
                    destination = 0 if progressed_pc is None else int(progressed_pc)
                    if destination == predicted_destination:
                        transform = candidate
                    else:
                        transform = SymbolicTransform(
                            tid,
                            modified,
                            [instruction],
                            arch,
                            pc,
                            destination,
                        )
                self._profile_finish("symbolic", symbolic_start)

            symbolic_start = self._profile_start("symbolic")
            strace.append(transform)
            self._profile_finish("symbolic", symbolic_start)

            if post_event:
                if _is_terminal_event(post_event):
                    debug("Completed exit event")
                elif post_event.pc == 0:
                    # Legacy terminal records used a zero-PC post-event.
                    debug("Completed exit event")
                    self.target.run()

                debug(f"Completed handling event: {post_event}")

        trace_env = self.env.with_architecture(arch.key)
        return MaterializedTrace(strace, trace_env, [transform.addr for transform in strace])
