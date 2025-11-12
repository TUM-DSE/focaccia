"""Concolic Tracer for native programs."""

from __future__ import annotations

import sys
import logging

from pathlib import Path

from focaccia.utils import timebound, TimeoutError
from focaccia.trace import Trace, TraceEnvironment
from focaccia.miasm_util import MiasmSymbolResolver
from focaccia.snapshot import ReadableProgramState, RegisterAccessError
from focaccia.symbolic import SymbolicTransform, DisassemblyContext, run_instruction
from focaccia.deterministic import Event, DeterministicEventIterator

from .lldb_target import LLDBConcreteTarget, LLDBLocalTarget, LLDBRemoteTarget

logger = logging.getLogger('focaccia-symbolic')
debug = logger.debug
info = logger.info
warn = logger.warn

# Disable Miasm's disassembly logger
logging.getLogger('asmblock').setLevel(logging.CRITICAL)

class ValidationError(Exception):
    pass

def match_event(event: Event, target: ReadableProgramState) -> bool:
    # TODO: match the rest of the state to be sure
    if event.pc == target.read_pc():
        for reg, value in event.registers.items():
            if value == event.pc:
                continue
            if target.read_register(reg) != value:
                print(f'Failed match for {reg}: {hex(value)} != {hex(target.read_register(reg))}')
                return False
        return True
    return False

class SpeculativeTracer(ReadableProgramState):
    def __init__(self, target: LLDBConcreteTarget):
        super().__init__(target.arch)
        self.target = target
        self.pc = target.read_register('pc')
        self.speculative_pc: int | None = None
        self.speculative_count: int = 0
        
        self.read_cache = {}

    def speculate(self, new_pc):
        self.read_cache.clear()
        if new_pc is None:
            self.progress_execution()
            self.target.step()
            self.pc = self.target.read_register('pc')
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
        self.pc = self.target.read_register('pc')

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
                 remote: str | None=None,
                 force: bool=False,
                 cross_validate: bool=False):
        self.env = env
        self.force = force
        self.remote = remote
        self.cross_validate = cross_validate
        self.target = SpeculativeTracer(self.create_debug_target())

        self.nondet_events = DeterministicEventIterator(self.env.detlog, match_event)

    def create_debug_target(self) -> LLDBConcreteTarget:
        binary = self.env.binary_name
        if self.remote is False:
            debug(f'Launching local debug target {binary} {self.env.argv}')
            debug(f'Environment: {self.env}')
            return LLDBLocalTarget(binary, self.env.argv, self.env.envp)

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

        debug('Cross-validating symbolic transforms by comparing actual to predicted values')
        for reg, val in predicted_regs.items():
            conc_val = self.target.read_register(reg)
            if conc_val != val:
                raise ValidationError(f'Symbolic execution backend generated false equation for'
                                      f' [{hex(instruction.addr)}]: {instruction}:'
                                      f' Predicted {reg} = {hex(val)}, but the'
                                      f' concrete state has value {reg} = {hex(conc_val)}.'
                                      f'\nFaulty transformation: {transform}')
        for addr, data in predicted_mems.items():
            conc_data = self.target.read_memory(addr, len(data))
            if conc_data != data:
                raise ValidationError(f'Symbolic execution backend generated false equation for'
                                      f' [{hex(instruction.addr)}]: {instruction}: Predicted'
                                      f' mem[{hex(addr)}:{hex(addr+len(data))}] = {data},'
                                      f' but the concrete state has value'
                                      f' mem[{hex(addr)}:{hex(addr+len(data))}] = {conc_data}.'
                                      f'\nFaulty transformation: {transform}')

    def post_event(self) -> None:
        current_event = self.nondet_events.current_event()
        if current_event:
            if current_event.pc == 0:
                # Exit sequence
                debug('Completed exit event')
                self.target.run()

            debug(f'Completed handling event: {current_event}')
            self.nondet_events.next()

    def is_stepping_instr(self, instruction: Instruction) -> bool:
        if self.nondet_events.current_event():
            debug('Current instruction matches next event; stepping through it')
            self.nondet_events.next()
            return True
        else:
            if self.target.arch.is_instr_syscall(str(instruction)):
                return True
        return False

    def progress(self, new_pc, step: bool = False) -> int | None:
        self.target.speculate(new_pc)
        if step:
            self.target.progress_execution()
            if self.target.is_exited():
                return None
        return self.target.read_pc()

    def trace(self, time_limit: int | None = None) -> Trace[SymbolicTransform]:
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

        if logger.isEnabledFor(logging.DEBUG):
            debug('Tracing program with the following non-deterministic events')
            for event in self.nondet_events.events():
                debug(event)

        # Trace concolically
        strace: list[SymbolicTransform] = []
        while not self.target.is_exited():
            pc = self.target.read_pc()

            if self.env.stop_address is not None and pc == self.env.stop_address:
                break

            self.nondet_events.update(self.target)

            # Disassemble instruction at the current PC
            tid = self.target.get_current_tid()
            try:
                instruction = ctx.disassemble(pc)
                info(f'[{tid}] Disassembled instruction {instruction} at {hex(pc)}')
            except:
                err = sys.exc_info()[1]

                # Try to recovery by using the LLDB disassembly instead
                try:
                    alt_disas = self.target.get_disassembly(pc)
                    instruction = Instruction.from_string(alt_disas, ctx.arch, pc,
                                                         self.target.get_instruction_size(pc))
                    info(f'[{tid}] Disassembled instruction {instruction} at {hex(pc)}')
                except:
                    if self.force:
                        if alt_disas:
                            warn(f'[{tid}] Unable to handle instruction {alt_disas} at {hex(pc)} in Miasm.'
                                 f' Skipping.')
                        else:
                            warn(f'[{tid}] Unable to disassemble instruction {hex(pc)}: {err}.'
                                 f' Skipping.')
                        self.target.step()
                        continue
                    raise # forward exception

            is_event = self.is_stepping_instr(instruction)

            # Run instruction
            conc_state = MiasmSymbolResolver(self.target, ctx.loc_db)

            try:
                new_pc, modified = timebound(time_limit, run_instruction,
                                             instruction.instr, conc_state, ctx.lifter)
            except TimeoutError:
                warn(f'Running instruction {instruction} took longer than {time_limit} second. Skipping')
                new_pc, modified = None, {}

            if self.cross_validate and new_pc:
                # Predict next concrete state.
                # We verify the symbolic execution backend on the fly for some
                # additional protection from bugs in the backend.
                new_pc = int(new_pc)
                transform = SymbolicTransform(tid, modified, [instruction], arch, pc, new_pc)
                pred_regs, pred_mems = self.predict_next_state(instruction, transform)
                self.progress(new_pc, step=is_event)

                try:
                    self.validate(instruction, transform, pred_regs, pred_mems)
                except ValidationError as e:
                    if self.force:
                        warn(f'Cross-validation failed: {e}')
                        continue
                    raise
            else:
                new_pc = self.progress(new_pc, step=is_event)
                if new_pc is None:
                    transform = SymbolicTransform(tid, modified, [instruction], arch, pc, 0)
                    strace.append(transform)
                    continue # we're done
                transform = SymbolicTransform(tid, modified, [instruction], arch, pc, new_pc)

            strace.append(transform)

            if is_event:
                self.post_event()

        return Trace(strace, self.env)

