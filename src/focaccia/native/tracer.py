"""Concolic Tracer for native programs."""

from __future__ import annotations

import time
import logging

from pathlib import Path

from focaccia.arch import Arch
from focaccia.utils import timebound, TimeoutError
from focaccia.trace import MaterializedTrace, TraceEnvironment
from focaccia.miasm_util import MiasmSymbolResolver
from focaccia.snapshot import ReadableProgramState, RegisterAccessError
from focaccia.symbolic import (
    DisassemblyContext,
    GapReason,
    Instruction,
    SymbolicTraceItem,
    SymbolicTransform,
    TraceGap,
    run_instruction,
)
from focaccia.deterministic import Event, EventMatcher

from .lldb_target import LLDBConcreteTarget, LLDBLocalTarget, LLDBRemoteTarget

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
    except Exception as primary_error:
        try:
            disassembly = target.get_disassembly(pc)
            return Instruction.from_string(
                disassembly,
                ctx.arch,
                pc,
                target.get_instruction_size(pc),
            )
        except Exception as fallback_error:
            raise DisassemblyError(pc, primary_error, fallback_error) from fallback_error

def _events_for_environment(env: TraceEnvironment) -> list[Event]:
    if env.detlog is None:
        return []
    return env.detlog.events()

def match_event(event: Event, target: ReadableProgramState) -> bool:
    # TODO: match the rest of the state to be sure
    if event.pc == target.read_pc():
        for reg, value in event.registers.items():
            if value == event.pc:
                continue
            try:
                if target.read_register(reg) != value:
                    print(f'Failed match for {reg}: {hex(value)} != {hex(target.read_register(reg))}')
                    return False
            except Exception as e:
                warn(f'Unable to read register: {e}')
        return True
    return False

class SpeculativeTracer(ReadableProgramState):
    def __init__(self, target: LLDBConcreteTarget):
        super().__init__(target.arch)
        self.target = target
        self.pc = target.read_pc()
        self.speculative_pc: int | None = None
        self.speculative_count: int = 0
        
        self.read_cache = {}

    def speculate(self, new_pc):
        self.read_cache.clear()
        if new_pc is None:
            self.progress_execution()
            self.target.step()
            self.pc = 0 if self.target.is_exited() else self.target.read_pc()
            self.speculative_pc = None
            self.speculative_count = 0
            return

        new_pc = int(new_pc)
        self.speculative_pc = new_pc
        self.speculative_count += 1

    def progress_execution(self) -> None:
        if self.speculative_pc is not None and self.speculative_count != 0:
            debug(f'Updating PC to {hex(self.speculative_pc)}')
            if self.speculative_count == 1:
                self.target.step()
            else:
                self.target.run_until(self.speculative_pc)

            self.pc = self.speculative_pc
            self.speculative_pc = None
            self.speculative_count = 0

            self.read_cache.clear()

    def run_until(self, addr: int):
        if self.speculative_pc:
            raise Exception('Attempting manual execution with speculative execution enabled')
        self.target.run_until(addr)
        self.pc = addr

    def step(self):
        self.progress_execution()
        if self.target.is_exited():
            return
        self.target.step()
        self.pc = 0 if self.target.is_exited() else self.target.read_pc()

    def _cache(self, name: str, value):
        self.read_cache[name] = value
        return value

    def read_pc(self) -> int:
        if self.speculative_pc is not None:
            return self.speculative_pc
        return self.pc

    def read_flags(self) -> dict[str, int | bool]:
        if 'flags' in self.read_cache:
            return self.read_cache['flags']
        self.progress_execution()
        return self._cache('flags', self.target.read_flags())

    def read_register(self, reg: str) -> int:
        regname = self.arch.to_regname(reg)
        if regname is None:
            raise RegisterAccessError(reg, f'Not a register name: {reg}')

        if reg in self.read_cache:
            return self.read_cache[reg]

        self.progress_execution()
        return self._cache(reg, self.target.read_register(regname))

    def write_register(self, regname: str, value: int):
        self.progress_execution()
        self.read_cache.pop(regname, None)
        self.target.write_register(regname, value)

    def read_instructions(self, addr: int, size: int) -> bytes:
        return self.target.read_memory(addr, size)

    def read_memory(self, addr: int, size: int) -> bytes:
        self.progress_execution()
        cache_name = f'{addr}_{size}' 
        if cache_name in self.read_cache:
            return self.read_cache[cache_name]
        return self._cache(cache_name, self.target.read_memory(addr, size))

    def write_memory(self, addr: int, value: bytes):
        self.progress_execution()
        self.read_cache.pop(addr, None)
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
                    raise RuntimeError('Symbolic execution produced no destination PC.')
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
            except Exception as error:
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
                assert new_pc is not None
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
                except Exception as error:
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
                        except Exception as error:
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
                    except Exception as error:
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
                assert new_pc is not None
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
                except Exception as error:
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

        print(f'Execution time: {self.target.target.exec_time}')
        print(f'Symbolic time: {symbolic_time}')
        print(f'Validation time: {self.validation_time}')
        trace_env = self.env.with_architecture(arch.key)
        return MaterializedTrace(strace, trace_env, [transform.addr for transform in strace])

