"""Concolic Tracer for native programs."""

from __future__ import annotations

import time
import logging

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from miasm.core.utils import Disasm_Exception

from focaccia.arch import Arch
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
    SymbolicCompositionError,
    SymbolicTraceItem,
    SymbolicTransform,
    TraceGap,
    UnsupportedInstructionError,
    run_instruction,
)
from focaccia.deterministic import Event, EventMatcher

from .lldb_target import (
    ConcreteExecutionError,
    ConcreteMemoryError,
    ConcreteRegisterError,
    LLDBConcreteTarget,
    LLDBLocalTarget,
    LLDBRemoteTarget,
)

logger = logging.getLogger('focaccia-symbolic')
debug = logger.debug
info = logger.info
warn = logger.warning

# Disable Miasm's disassembly logger
logging.getLogger('asmblock').setLevel(logging.CRITICAL)

class ValidationError(Exception):
    pass

class DisassemblyError(Exception):
    def __init__(self, pc: int, primary_error: Exception, fallback_error: Exception):
        self.pc = pc
        self.primary_error = primary_error
        self.fallback_error = fallback_error
        super().__init__(
            f'Unable to disassemble instruction at {hex(pc)}. '
            f'Miasm failed with: {primary_error}. '
            f'LLDB fallback failed with: {fallback_error}.'
        )

def _disassemble_instruction(ctx: DisassemblyContext,
                             target: LLDBConcreteTarget,
                             pc: int) -> Instruction:
    try:
        return ctx.disassemble(pc)
    except (
        Disasm_Exception,
        ConcreteMemoryError,
        MemoryAccessError,
        ValueError,
        NotImplementedError,
    ) as primary_error:
        try:
            disassembly = target.get_disassembly(pc)
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

def _events_for_environment(env: TraceEnvironment) -> list[Event]:
    if env.detlog is None:
        return []
    return env.detlog.events()

_EVENT_SYNC_BASE_REGISTERS = {
    'x86_64': frozenset(
        {
            'RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RBP', 'RSP',
            'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15',
        }
    ),
    'aarch64': frozenset({*(f'X{index}' for index in range(31)), 'SP'}),
}


def match_event(event: Event, target: ReadableProgramState) -> bool:
    """Match one deterministic event using a named, architecture-specific subset."""
    # The legacy RR reader still supplies its schema enum here; Step 11 will
    # normalize that parser boundary. Enforce full identity for typed events.
    if isinstance(event.arch, Arch) and event.arch != target.arch:
        return False
    arch = target.arch
    try:
        if event.pc != target.read_pc():
            return False
    except (RegisterAccessError, ConcreteRegisterError):
        return False

    pc_name = arch.to_regname('PC')
    pc_accessor = arch.get_reg_accessor(pc_name) if pc_name is not None else None
    if pc_accessor is None:
        return False
    synchronized_bases = _EVENT_SYNC_BASE_REGISTERS.get(arch.archname, frozenset())

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
        expected_text = 'process exit' if expected == 0 else hex(expected)
        actual_text = 'process exit' if actual is None else hex(actual)
        super().__init__(
            f'Speculative execution expected {expected_text}, observed {actual_text}; '
            f'predicted path: {[hex(pc) for pc in predictions]}.'
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
            raise ValueError('A speculative destination cannot be negative.')
        self._predicted_pcs.append(destination)

    def progress_execution(self) -> int | None:
        if not self._predicted_pcs:
            return None if self.target.is_exited() else self.pc

        predictions = tuple(self._predicted_pcs)
        expected = predictions[-1]
        debug(
            f'Materializing {len(predictions)} speculative transitions at '
            f'{"exit" if expected == 0 else hex(expected)}'
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
                self.target.step()
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
            raise RuntimeError(f'Cannot run an exited target to {hex(addr)}.')
        if self.pc == addr:
            return
        try:
            self.target.run_until(addr)
            self._verify_observed_pc(addr, (addr,))
        finally:
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
            raise RegisterAccessError(reg, f'Not a register name: {reg}')
        self.progress_execution()
        if canonical not in self._register_cache:
            self._register_cache[canonical] = self.target.read_register(canonical)
        return self._register_cache[canonical]

    def _invalidate_register(self, regname: str) -> None:
        written = self.arch.get_reg_accessor(regname)
        if written is None:
            raise RegisterAccessError(regname, f'Not a register name: {regname}')
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
            raise RegisterAccessError(regname, f'Not a register name: {regname}')
        self.progress_execution()
        self._invalidate_register(canonical)
        self.target.write_register(canonical, value)
        written = self.arch.get_reg_accessor(canonical)
        pc_name = self.arch.to_regname('PC')
        pc = self.arch.get_reg_accessor(pc_name) if pc_name is not None else None
        if written is not None and pc is not None and written.base_reg == pc.base_reg:
            self.pc = self.target.read_pc()

    def read_instructions(self, addr: int, size: int) -> bytes:
        return self.target.read_memory(addr, size)

    def read_memory(self, addr: int, size: int) -> bytes:
        if size < 0:
            raise ValueError('A memory read size cannot be negative.')
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
    def __init__(self, 
                 env: TraceEnvironment, 
                 remote: str | None = None,
                 force: bool = False,
                 cross_validate: bool = False):
        self.env = env
        self.force = force
        self.remote = remote
        self.cross_validate = cross_validate
        self.target = SpeculativeTracer(self.create_debug_target())

        self.validation_time = 0

    def create_debug_target(self) -> LLDBConcreteTarget:
        binary = self.env.binary_name
        if binary is None:
            raise ValueError('A binary is required to create a native trace target.')
        if self.remote is None:
            debug(f'Launching local debug target {binary} {self.env.argv}')
            debug(f'Environment: {self.env}')
            return LLDBLocalTarget(binary, list(self.env.argv), list(self.env.envp))

        debug(f'Connecting to remote debug target {self.remote}')
        target = LLDBRemoteTarget(self.remote, binary)

        module_name = target.determine_name()
        binary = str(Path(self.env.binary_name).resolve())
        if binary != module_name:
            warn(f'Discovered binary name {module_name} differs from specified name {binary}')

        return target

    def predict_next_state(self, instruction: Instruction, transform: SymbolicTransform):
        debug(f'Evaluating register and memory transforms for {instruction} to cross-validate')
        predicted_regs = transform.eval_register_transforms(self.target)
        predicted_mems = transform.eval_memory_transforms(self.target)
        return predicted_regs, predicted_mems

    def validate(self,
                 instruction: Instruction,
                 transform: SymbolicTransform,
                 predicted_regs: dict[str, int],
                 predicted_mems: dict[int, bytes]):
        # Verify last generated transform by comparing concrete state against
        # predicted values.
        if self.target.is_exited():
            return

        start = time.time()
        debug('Cross-validating symbolic transforms by comparing actual to predicted values')
        for reg, val in predicted_regs.items():
            conc_val = self.target.read_register(reg)
            if conc_val != val:
                self.validation_time += time.time() - start
                raise ValidationError(f'Symbolic execution backend generated false equation for'
                                      f' [{hex(instruction.addr)}]: {instruction}:'
                                      f' Predicted {reg} = {hex(val)}, but the'
                                      f' concrete state has value {reg} = {hex(conc_val)}.'
                                      f'\nFaulty transformation: {transform}')
        for addr, data in predicted_mems.items():
            conc_data = self.target.read_memory(addr, len(data))
            if conc_data != data:
                self.validation_time += time.time() - start
                raise ValidationError(f'Symbolic execution backend generated false equation for'
                                      f' [{hex(instruction.addr)}]: {instruction}: Predicted'
                                      f' mem[{hex(addr)}:{hex(addr+len(data))}] = {data},'
                                      f' but the concrete state has value'
                                      f' mem[{hex(addr)}:{hex(addr+len(data))}] = {conc_data}.'
                                      f'\nFaulty transformation: {transform}')
        self.validation_time += time.time() - start

    def progress(self, new_pc, step: bool = False) -> int | None:
        self.target.speculate(new_pc)
        if step:
            info(f'Stepping through event at {hex(self.target.read_pc())}')
            self.target.progress_execution()
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
        symbolic_time = 0

        exec_start = time.time()
        if self.env.start_address is not None:
            self.target.run_until(self.env.start_address)

        ctx = DisassemblyContext(self.target)
        arch = ctx.arch

        event_matcher = EventMatcher(_events_for_environment(self.env), match_event, self.target)
        if logger.isEnabledFor(logging.DEBUG):
            debug('Tracing program with the following non-deterministic events')
            for event in event_matcher.events:
                debug(event)

        # Trace concolically
        strace: list[SymbolicTraceItem] = []
        while not self.target.is_exited():
            pc = self.target.read_pc()

            if self.env.stop_address is not None and pc == self.env.stop_address:
                info(f'Reached stop address at {hex(pc)}')
                break

            # Disassemble instruction at the current PC
            symbolic_start = time.time()
            tid = self.target.get_current_tid()
            try:
                instruction = _disassemble_instruction(ctx, self.target, pc)
                info(f'[{tid}] Disassembled instruction {instruction} at {hex(pc)}')
            except DisassemblyError as err:
                if not self.force:
                    raise
                warn(f'[{tid}] {err} Recording an explicit trace gap.')
                self.target.step()
                next_pc = 0 if self.target.is_exited() else self.target.read_pc()
                strace.append(
                    self._trace_gap(
                        tid,
                        arch,
                        pc,
                        next_pc,
                        'disassembly-error',
                        err,
                    )
                )
                if self.target.is_exited():
                    break
                continue

            event = event_matcher.match(self.target)
            post_event = event_matcher.match_pair(event)
            in_event = event is not None or self.target.arch.is_instr_syscall(
                str(instruction)
            )

            # Run instruction
            conc_state = MiasmSymbolResolver(self.target, ctx.loc_db)

            symbolic_error: BaseException | None = None
            gap_reason: GapReason = 'unsupported-semantics'
            try:
                new_pc, modified = timebound(
                    time_limit,
                    run_instruction,
                    instruction.instr,
                    conc_state,
                    ctx.lifter,
                )
                if new_pc is None:
                    raise SymbolEvaluationError(
                        'Symbolic execution produced no destination PC.'
                    )
            except TimeoutError as error:
                if not self.force:
                    raise
                warn(
                    f'Running instruction {instruction} exceeded {time_limit} seconds; '
                    'recording an explicit trace gap.'
                )
                symbolic_error = error
                gap_reason = 'symbolic-timeout'
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
                    f'Unable to run instruction symbolically: {error}; '
                    'recording an explicit trace gap.'
                )
                symbolic_error = error
                new_pc, modified = None, {}

            symbolic_time += time.time() - symbolic_start

            if symbolic_error is not None:
                self.progress(None, step=bool(in_event))
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
                    raise SymbolEvaluationError(
                        'Cross-validation requires a destination PC.'
                    )
                # Verify generated equations against the concrete target before
                # retaining them. A forced failure is an explicit gap.
                destination = int(new_pc)
                symbolic_start = time.time()
                candidate: SymbolicTransform | None = None
                cross_validation_error: BaseException | None = None
                failure_reason: GapReason = 'cross-validation-error'
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
                    failure_reason = 'unsupported-semantics'
                symbolic_time += time.time() - symbolic_start

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
                        self.progress(destination, step=True)
                else:
                    self.progress(None, step=bool(in_event))

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
                        f'Symbolic construction/cross-validation failed: '
                        f'{cross_validation_error}; recording an explicit trace gap.'
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
                    raise SymbolEvaluationError(
                        'A symbolic transform requires a destination PC.'
                    )
                predicted_destination = int(new_pc)
                symbolic_start = time.time()
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
                        f'Unable to construct symbolic transform: {error}; '
                        'recording an explicit trace gap.'
                    )
                    self.progress(None, step=bool(in_event))
                    observed_pc = 0 if self.target.is_exited() else self.target.read_pc()
                    transform = self._trace_gap(
                        tid,
                        arch,
                        pc,
                        observed_pc,
                        'unsupported-semantics',
                        error,
                        instruction=instruction,
                    )
                else:
                    progressed_pc = self.progress(new_pc, step=bool(in_event))
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
                symbolic_time += time.time() - symbolic_start

            symbolic_start = time.time()
            strace.append(transform)
            symbolic_time += time.time() - symbolic_start

            if post_event:
                if post_event.pc == 0:
                    # Exit sequence
                    debug('Completed exit event')
                    self.target.run()

                debug(f'Completed handling event: {post_event}')

        info(f'Execution time: {self.target.target.exec_time}')
        info(f'Symbolic time: {symbolic_time}')
        info(f'Validation time: {self.validation_time}')
        trace_env = self.env.with_architecture(arch.key)
        return MaterializedTrace(strace, trace_env, [transform.addr for transform in strace])

