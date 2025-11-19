"""Invocable like this:

    gdb -n --batch -x qemu_tool.py

But please use `tools/validate_qemu.py` instead because we have some more setup
work to do.
"""

import re
import gdb
import logging
import traceback
from typing import Iterable, Optional

import focaccia.parser as parser
from focaccia.arch import supported_architectures, Arch
from focaccia.compare import compare_symbolic, Error, ErrorTypes
from focaccia.snapshot import ProgramState, ReadableProgramState, \
                              RegisterAccessError, MemoryAccessError
from focaccia.symbolic import SymbolicTransform, eval_symbol, ExprMem
from focaccia.trace import Trace, TraceEnvironment
from focaccia.utils import print_result
from focaccia.deterministic import (
    DeterministicLog,
    Event,
    EventMatcher,
    SyscallEvent,
    MemoryMapping,
)
from focaccia.qemu.deterministic import emulated_system_calls, passthrough_system_calls

from focaccia.tools.validate_qemu import make_argparser, verbosity

logger = logging.getLogger('focaccia-qemu-validator')
debug = logger.debug
info = logger.info
warn = logger.warning

qemu_crash = {
        "crashed": False,
        "pc": None,
        'txl': None,
        'ref': None,
        'errors': [Error(ErrorTypes.CONFIRMED, "QEMU crashed")],
        'snap': None,
}

def match_event(event: Event, target: ReadableProgramState) -> bool:
    # Match just on PC
    debug(f'Matching for PC {hex(target.read_pc())} with event {hex(event.pc)}')
    if event.pc == target.read_pc():
        return True
    return False

class GDBProgramState(ProgramState):
    from focaccia.arch import aarch64, x86

    flag_register_names = {
        aarch64.archname: 'cpsr',
        x86.archname: 'eflags',
    }

    flag_register_decompose = {
        aarch64.archname: aarch64.decompose_cpsr,
        x86.archname: x86.decompose_rflags,
    }

    def __init__(self, process: gdb.Inferior, frame: gdb.Frame, arch: Arch):
        super().__init__(arch)
        self._proc = process
        self._frame = frame

    @staticmethod
    def _read_vector_reg_aarch64(val: gdb.Value, size) -> int:
        try:
            return int(str(val['d']['u']), 10)
        except:
            try:
                return int(str(val['u']), 10)
            except:
                return int(str(val['q']['u']), 10)

    @staticmethod
    def _read_vector_reg_x86(val: gdb.Value, size) -> int:
        num_longs = size // 64
        vals = val[f'v{num_longs}_int64']
        res = 0
        for i in range(num_longs):
            val = int(vals[i].cast(gdb.lookup_type('unsigned long')))
            res += val << i * 64
        return res

    read_vector_reg = {
        aarch64.archname: _read_vector_reg_aarch64,
        x86.archname: _read_vector_reg_x86,
    }

    def read_register(self, reg: str) -> int:
        if reg == 'RFLAGS':
            reg = 'EFLAGS'

        try:
            val = self._frame.read_register(reg.lower())
            size = val.type.sizeof * 8

            # For vector registers, we need to apply architecture-specific
            # logic because GDB's interface is not consistent.
            if size >= 128:  # Value is a vector
                if self.arch.archname not in self.read_vector_reg:
                    raise NotImplementedError(
                        f'Reading vector registers is not implemented for'
                        f' architecture {self.arch.archname}.')
                return self.read_vector_reg[self.arch.archname](val, size)
            elif size < 64:
                return int(val.cast(gdb.lookup_type('unsigned int')))
            # For non-vector values, just return the 64-bit value
            return int(val.cast(gdb.lookup_type('unsigned long')))
        except ValueError as err:
            # Try to access the flags register with `reg` as a logical flag name
            if self.arch.archname in self.flag_register_names:
                flags_reg = self.flag_register_names[self.arch.archname]
                flags = int(self._frame.read_register(flags_reg))
                flags = self.flag_register_decompose[self.arch.archname](flags)
                if reg in flags:
                    return flags[reg]
            raise RegisterAccessError(reg,
                                      f'[GDB] Unable to access {reg}: {err}')

    def read_memory(self, addr: int, size: int) -> bytes:
        try:
            mem = self._proc.read_memory(addr, size).tobytes()
            if self.arch.endianness == 'little':
                return mem
            else:
                return bytes(reversed(mem))  # Convert to big endian
        except gdb.MemoryError as err:
            raise MemoryAccessError(addr, size, str(err))

class GDBServerStateIterator:
    def __init__(self, remote: str, deterministic_log: DeterministicLog):
        gdb.execute('set pagination 0')
        gdb.execute('set sysroot')
        gdb.execute('set python print-stack full') # enable complete Python tracebacks
        gdb.execute(f'target remote {remote}')
        self._deterministic_log = deterministic_log
        self._process = gdb.selected_inferior()
        self._first_next = True
        self._thread_num = 1

        # Try to determine the guest architecture. This is a bit hacky and
        # tailored to GDB's naming for the x86-64 architecture.
        split = self._process.architecture().name().split(':')
        archname = split[1] if len(split) > 1 else split[0]
        archname = archname.replace('-', '_')
        if archname not in supported_architectures:
            raise NotImplementedError(f'Platform {archname} is not supported by Focaccia')

        self.arch = supported_architectures[archname]
        self.binary = self._process.progspace.filename

        first_state = self.current_state()
        self._events = EventMatcher(self._deterministic_log.events(),
                                    match_event,
                                    from_state=first_state)
        event = self._events.match(first_state)
        info(f'Synchronized at PC={hex(first_state.read_pc())} to event:\n{event}')

    def current_state(self) -> ReadableProgramState:
        return GDBProgramState(self._process, gdb.selected_frame(), self.arch)

    def _handle_syscall(self, event: Event, post_event: Event) -> GDBProgramState:
        call = event.registers.get(self.arch.get_syscall_reg())

        syscall = emulated_system_calls[self.arch.archname].get(call, None)
        if syscall is not None:
            info(f'Replaying system call number {hex(call)}')

            self.skip(post_event.pc)
            next_state = self.current_state()

            patchup_regs = [self.arch.get_syscall_reg(), *(syscall.patchup_registers or [])]
            for reg in patchup_regs:
                gdb.parse_and_eval(f'${reg}={post_event.registers.get(reg)}')

            for mem in post_event.mem_writes:
                addr, data = mem.address, mem.data
                for reg, value in post_event.registers.items():
                    if value == addr:
                        addr = next_state.read_register(reg)
                        break

                info(f'Replaying write to {hex(addr)} with data:\n{data.hex(" ")}')

                # Insert holes into data
                for hole in mem.holes:
                    data[hole.offset:hole.offset] = b'\x00' * hole.size
                self._process.write_memory(addr, data)
                return next_state

            return next_state

        syscall = passthrough_system_calls[self.arch.archname].get(call, None)
        if syscall is not None:
            info(f'System call number {hex(call)} passed through')
            self._step()
            if self._is_exited():
                raise StopIteration
            # Check if new thread was created
            if syscall.creates_thread:
                new_tid = self.current_state().read_register(self.arch.get_syscall_reg())
                info(f'New thread created TID={hex(new_tid)} corresponds to native {hex(event.tid)}')

            return GDBProgramState(self._process, gdb.selected_frame(), self.arch)

        info(f'System call number {hex(call)} not replayed')
        self._step()
        if self._is_exited():
            raise StopIteration
        return GDBProgramState(self._process, gdb.selected_frame(), self.arch)

    def _handle_event(self, event: Event | None, post_event: Event | None) -> GDBProgramState:
        if not event:
            return self.current_state()

        if isinstance(event, SyscallEvent):
            return self._handle_syscall(event, post_event)

        warn(f'Event handling for events of type {event.event_type} not implemented')
        return self.current_state()

    def _is_exited(self) -> bool:
        return not self._process.is_valid() or len(self._process.threads()) == 0

    def __iter__(self):
        return self

    def __next__(self) -> ReadableProgramState:
        # The first call to __next__ should yield the first program state,
        # i.e. before stepping the first time
        if self._first_next:
            self._first_next = False
            return GDBProgramState(self._process, gdb.selected_frame(), self.arch)

        event, post_event = self._events.match_pair(self.current_state())
        if event:
            state = self._handle_event(event, post_event)
            if self._is_exited():
                raise StopIteration

            return state

        # Step
        pc = gdb.selected_frame().read_register('pc')
        new_pc = pc
        while pc == new_pc:  # Skip instruction chains from REP STOS etc.
            self._step()
            if self._is_exited():
                raise StopIteration
            new_pc = gdb.selected_frame().read_register('pc')

        return self.current_state()

    def run_until(self, addr: int) -> ReadableProgramState:
        events_handled = 0
        event = self._events.next()
        while event:
            state = self._run_until_any([addr, event.pc])
            if state.read_pc() == addr:
                # Check if we started at the very _start
                self._first_next = events_handled == 0
                return state

            event, post_event = self._events.match_pair(self.current_state())
            self._handle_event(event, post_event)

            event = self._events.next()
            events_handled += 1
        return self._run_until_any([addr])

    def _run_until_any(self, addresses: list[int]) -> ReadableProgramState:
        info(f'Executing until {[hex(x) for x in addresses]}')

        breakpoints = []
        for addr in addresses:
            breakpoints.append(gdb.Breakpoint(f'*{addr:#x}'))

        gdb.execute('continue')

        for bp in breakpoints:
            bp.delete()

        return GDBProgramState(self._process, gdb.selected_frame(), self.arch)

    def skip(self, new_pc: int):
        gdb.execute(f'set $pc = {hex(new_pc)}')

    def _step(self):
        gdb.execute('si', to_string=True)

    def context_switch(self, thread_number: int) -> None:
        gdb.execute(f'thread {thread_number}')
        self._thread_num = thread_number

    def get_sections(self) -> list[MemoryMapping]:
        mappings = []

        # Skip everything until the header line
        started = False

        text = gdb.execute('info proc mappings', to_string=True)
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue

            # Detect header line once
            if line.startswith("Start Addr"):
                started = True
                continue

            if not started:
                continue

            # Lines look like:
            # 0x0000000000400000 0x0000000000401000 0x1000 0x0 r--p /path
            # or:
            # 0x... 0x... 0x... 0x... rw-p  [vdso]
            parts = line.split(None, 6)

            if len(parts) < 5:
                continue

            start   = int(parts[0], 16)
            end     = int(parts[1], 16)
            size    = int(parts[2], 16)
            offset  = int(parts[3], 16)
            perms   = parts[4]

            file_or_tag = None
            is_special = False

            if len(parts) >= 6:
                tail = parts[5]

                # If it's [tag], mark as special
                if tail.startswith("[") and tail.endswith("]"):
                    file_or_tag = tail.strip()
                    is_special = True
                else:
                    # Might be a filename or absent
                    file_or_tag = tail

            mapping = MemoryMapping(0,
                                    start,
                                    end,
                                    '',
                                    offset,
                                    0,
                                    0)
            mappings.append(mapping)

        return mappings

def record_minimal_snapshot(prev_state: ReadableProgramState,
                            cur_state: ReadableProgramState,
                            prev_transform: SymbolicTransform,
                            cur_transform: SymbolicTransform) \
        -> ProgramState:
    """Record a minimal snapshot.

    A minimal snapshot must include values (registers and memory) that are
    accessed by two transformations:
      1. The values produced by the previous transformation (the
         transformation that is producing this snapshot) to check these
         values against expected values calculated from the previous
         program state.
      2. The values that act as inputs to the transformation acting on this
         snapshot, to calculate the expected values of the next snapshot.

    :param prev_transform: The symbolic transformation generating, or
                           leading to, `cur_state`. Values generated by
                           this transformation are included in the
                           snapshot.
    :param transform: The symbolic transformation operating on this
                      snapshot. Input values to this transformation are
                      included in the snapshot.
    """
    assert(cur_state.read_register('pc') == cur_transform.addr)
    assert(prev_transform.arch == cur_transform.arch)

    def get_written_addresses(t: SymbolicTransform):
        """Get all output memory accesses of a symbolic transformation."""
        return [ExprMem(a, v.size) for a, v in t.changed_mem.items()]

    def set_values(regs: Iterable[str], mems: Iterable[ExprMem],
                   cur_state: ReadableProgramState,
                   prev_state: ReadableProgramState,
                   out_state: ProgramState):
        """
        :param prev_state: Addresses of memory included in the snapshot are
                           resolved relative to this state.
        """
        for regname in regs:
            try:
                regval = cur_state.read_register(regname)
                out_state.write_register(regname, regval)
            except RegisterAccessError:
                pass
        for mem in mems:
            assert(mem.size % 8 == 0)
            addr = eval_symbol(mem.ptr, prev_state)
            try:
                mem = cur_state.read_memory(addr, int(mem.size / 8))
                out_state.write_memory(addr, mem)
            except MemoryAccessError:
                pass

    state = ProgramState(cur_transform.arch)
    state.write_register('PC', cur_transform.addr)

    set_values(prev_transform.changed_regs.keys(),
               get_written_addresses(prev_transform),
               cur_state,
               prev_state,  # Evaluate memory addresses based on previous
                            # state because they are that state's output
                            # addresses.
               state)
    set_values(cur_transform.get_used_registers(),
               cur_transform.get_used_memory_addresses(),
               cur_state,
               cur_state,
               state)
    return state

def collect_conc_trace(gdb: GDBServerStateIterator, \
                       strace: list[SymbolicTransform],
                       start_addr: int | None = None,
                       stop_addr: int | None = None) \
        -> tuple[list[ProgramState], list[SymbolicTransform]]:
    """Collect a trace of concrete states from GDB.

    Records minimal concrete states from GDB by using symbolic trace
    information to determine which register/memory values are required to
    verify the correctness of the program running in GDB.

    May drop symbolic transformations if the symbolic trace and the GDB trace
    diverge (e.g. because of differences in environment, etc.). Returns the
    new, possibly modified, symbolic trace that matches the returned concrete
    trace.

    :return: A list of concrete states and a list of corresponding symbolic
             transformations. The lists are guaranteed to have the same length.
    """
    def find_index(seq, target, access=lambda el: el):
        for i, el in enumerate(seq):
            if access(el) == target:
                return i
        return None

    if not strace:
        return [], []

    states = []
    matched_transforms = []

    state_iter = iter(gdb)
    cur_state = next(state_iter)
    symb_i = 0

    if logger.isEnabledFor(logging.DEBUG):
        debug('Tracing program with the following non-deterministic events:')
        for event in gdb._events.events:
            debug(event)

    # Skip to start
    pc = cur_state.read_register('pc')
    start_addr = start_addr if start_addr else pc
    try:
        if pc != start_addr:
            info(f'Executing until starting address {hex(start_addr)}')
            cur_state = state_iter.run_until(start_addr)
    except Exception as e:
        if pc != start_addr:
            raise Exception(f'Unable to reach start address {hex(start_addr)}: {e}')
        raise Exception(f'Unable to trace: {e}')

    # An online trace matching algorithm.
    info(f'Tracing QEMU between {hex(start_addr)}:{hex(stop_addr) if stop_addr else "end"}')
    while True:
        try:
            pc = cur_state.read_register('pc')
            if stop_addr and pc == stop_addr:
                break

            while pc != strace[symb_i].addr:
                warn(f'PC {hex(pc)} does not match next symbolic reference {hex(strace[symb_i].addr)}')

                next_i = find_index(strace[symb_i+1:], pc, lambda t: t.addr)

                # Drop the concrete state if no address in the symbolic trace
                # matches
                if next_i is None:
                    warn(f'Dropping concrete state {hex(pc)}, as no'
                         f' matching instruction can be found in the symbolic'
                         f' reference trace.')
                    cur_state = next(state_iter)
                    pc = cur_state.read_register('pc')
                    continue

                # Otherwise, jump to the next matching symbolic state
                symb_i += next_i + 1
                if symb_i >= len(strace):
                    break

            assert(cur_state.read_register('pc') == strace[symb_i].addr)
            info(f'Validating instruction at address {hex(pc)}')
            states.append(record_minimal_snapshot(
                states[-1] if states else cur_state,
                cur_state,
                matched_transforms[-1] if matched_transforms else strace[symb_i],
                strace[symb_i]))
            matched_transforms.append(strace[symb_i])
            cur_state = next(state_iter)
            symb_i += 1
            if symb_i >= len(strace):
                break
        except StopIteration:
            # TODO: The conditions may test for the same
            if stop_addr and pc != stop_addr:
                raise Exception(f'QEMU stopped at {hex(pc)} before reaching the stop address'
                                f' {hex(stop_addr)}')
            if symb_i+1 < len(strace):
                qemu_crash["crashed"] = True
                qemu_crash["pc"] = strace[symb_i].addr
                qemu_crash["ref"] = strace[symb_i]
                qemu_crash["snap"] = states[-1]
            break
        except Exception as e:
            print(traceback.format_exc())
            raise e

    # Note: this may occur when symbolic traces were gathered with a stop address
    if symb_i >= len(strace):
        warn(f'QEMU executed more states than native execution: {symb_i} vs {len(strace)-1}')

    return states, matched_transforms

def main():
    args = make_argparser().parse_args()

    logging_level = getattr(logging, args.error_level.upper(), logging.INFO)
    logging.basicConfig(level=logging_level, force=True)

    detlog = DeterministicLog(args.deterministic_log)
    if args.deterministic_log and detlog.base_directory is None:
        raise NotImplementedError(f'Deterministic log {args.deterministic_log} specified but '
                                   'Focaccia built without deterministic log support')

    try:
        gdb_server = GDBServerStateIterator(args.remote, detlog)
    except Exception as e:
        raise Exception(f'Unable to perform basic GDB setup: {e}')

    try:
        executable: str | None = None
        if args.executable is None:
            executable = gdb_server.binary
        else:
            executable = args.executable

        argv = []  # QEMU's GDB stub does not support 'info proc cmdline'
        envp = []  # Can't get the remote target's environment
        env = TraceEnvironment(executable, argv, envp, '?')
    except Exception as e:
        raise Exception(f'Unable to create trace environment for executable {executable}: {e}')

    # Read pre-computed symbolic trace
    try:
        with open(args.symb_trace, 'r') as strace:
            symb_transforms = parser.parse_transformations(strace)
    except Exception as e:
        raise Exception(f'Failed to parse state transformations from native trace: {e}')

    # Use symbolic trace to collect concrete trace from QEMU
    try:
        conc_states, matched_transforms = collect_conc_trace(
            gdb_server,
            symb_transforms.states,
            symb_transforms.env.start_address,
            symb_transforms.env.stop_address)
    except Exception as e:
        raise Exception(f'Failed to collect concolic trace from QEMU: {e}')

    # Verify and print result
    if not args.quiet:
        try:
            res = compare_symbolic(conc_states, matched_transforms)
            if qemu_crash["crashed"]:
                res.append({
                    'pc': qemu_crash["pc"],
                    'txl': None,
                    'ref': qemu_crash["ref"],
                    'errors': qemu_crash["errors"],
                    'snap': qemu_crash["snap"],
                })
            print_result(res, verbosity[args.error_level])
        except Exception as e:
            raise Exception('Error occured when comparing with symbolic equations: {e}')

    if args.output:
        from focaccia.parser import serialize_snapshots
        try:
            with open(args.output, 'w') as file:
                serialize_snapshots(Trace(conc_states, env), file)
        except Exception as e:
            raise Exception(f'Unable to serialize snapshots to file {args.output}: {e}')

if __name__ == "__main__":
    main()

