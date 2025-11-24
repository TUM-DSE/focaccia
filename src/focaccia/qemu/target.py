import re
import gdb
import socket
import logging
from typing import Optional

from focaccia.deterministic import (
    DeterministicLog,
    Event,
    EventMatcher,
    SyscallEvent,
    MemoryMapping,
)
from focaccia.snapshot import (
    ProgramState,
    ReadableProgramState,
    RegisterAccessError,
    MemoryAccessError,
)
from focaccia.arch import supported_architectures, Arch
from focaccia.qemu.deterministic import emulated_system_calls, passthrough_system_calls, vdso_system_calls

logger = logging.getLogger('focaccia-qemu-target')
debug = logger.debug
info = logger.info
warn = logger.warning

DEST = "/tmp/memcached_scheduler.sock"

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

class GDBServerConnector:
    def __init__(self, remote: str):
        gdb.execute('set pagination 0')
        gdb.execute('set sysroot')
        gdb.execute('set python print-stack full') # enable complete Python tracebacks
        gdb.execute(f'target remote {remote}')
        gdb.execute('set scheduler-locking on')
        self._process = gdb.selected_inferior()

        split = self._process.architecture().name().split(':')
        archname = split[1] if len(split) > 1 else split[0]
        archname = archname.replace('-', '_')
        if archname not in supported_architectures:
            raise NotImplementedError(f'Platform {archname} is not supported by Focaccia')

        self.arch = supported_architectures[archname]
        self.binary = self._process.progspace.filename

    def current_state(self) -> ReadableProgramState:
        return GDBProgramState(self._process, gdb.selected_frame(), self.arch)

    def skip(self, new_pc: int):
        gdb.execute(f'set $pc = {hex(new_pc)}')

    def _step(self):
        pc = gdb.selected_frame().read_register('pc')
        new_pc = pc
        while pc == new_pc:  # Skip instruction chains from REP STOS etc.
            gdb.execute('si', to_string=True)
            if self.is_exited():
                raise StopIteration
            new_pc = gdb.selected_frame().read_register('pc')
        return self.current_state()

    def is_exited(self) -> bool:
        return not self._process.is_valid() or len(self._process.threads()) == 0

    def current_tid(self) -> int:
        return gdb.selected_inferior().threads()[0].ptid[1]

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


class GDBServerStateIterator(GDBServerConnector):
    def __init__(self, remote: str, deterministic_log: DeterministicLog):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(DEST)
        super().__init__(remote)

        self._deterministic_log = deterministic_log
        self._first_next = True
        self._thread_num = 1

        events = self._deterministic_log.events()
        skipped_events = []
        for idx in range(len(events)):
            event = events[idx]
            if not isinstance(event, SyscallEvent):
                continue

            if event.syscall_number in vdso_system_calls[self.arch.archname]:
                skipped_events.append(idx)

        for idx in skipped_events:
            debug(f'Skip {events[idx]}')

        first_state = self.current_state()
        self._events = EventMatcher(events,
                                    match_event,
                                    from_state=first_state,
                                    skipped_events=skipped_events)
        event = self._events.match(first_state)
        
        self._thread_count = 1
        self._current_event_id = event.tid
        self._thread_map = {
            self._current_event_id: (self.current_tid(), self._thread_count)
        }
        self._thread_context = {
        }
        info(f'Synchronized at PC={hex(first_state.read_pc())} to event:\n{event}')
        debug(f'Thread mapping at this point: {hex(event.tid)}: {hex(self.current_tid())}')

    def _handle_syscall(self, event: Event, post_event: Event) -> ReadableProgramState:
        call = event.registers.get(self.arch.get_syscall_reg())
        next_state = None

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

        syscall = passthrough_system_calls[self.arch.archname].get(call, None)
        if syscall is not None:
            info(f'System call number {hex(call)} passed through')
            self._step()
            if self.is_exited():
                raise StopIteration

            # Check if new thread was created
            if syscall.creates_thread:
                new_tid = self.current_state().read_register(self.arch.get_syscall_reg())
                event_new_tid = post_event.registers[self.arch.get_syscall_reg()]
                self._thread_count += 1
                self._thread_map[event_new_tid] = (new_tid, self._thread_count)
                info(f'New thread created TID={hex(new_tid)} corresponds to native {hex(event_new_tid)}')
                debug('Thread mapping at this point:')
                for event_tid, (tid, _) in self._thread_map.items():
                    debug(f'{hex(event_tid)}: {hex(tid)}')

            next_state = GDBProgramState(self._process, gdb.selected_frame(), self.arch)

        if not next_state:
            info(f'System call number {hex(call)} not replayed')
            self._step()
            if self.is_exited():
                raise StopIteration
            next_state = GDBProgramState(self._process, gdb.selected_frame(), self.arch)

        return next_state

    def _handle_event(self) -> ReadableProgramState | None:
        event = self._events.match(self.current_state())       

        if not event:
            return None

        if isinstance(event, SyscallEvent):
            post_event = self._events.match_pair(event)
            assert(post_event is not None)

            # Context switch
            # TODO: handle return from pre-empt
            if post_event.tid != self._current_event_id:
                self._thread_context[self._current_event_id] = event
                self._current_event_id = post_event.tid
                tid, num = self._thread_map[self._current_event_id]
                self.context_switch(tid)
                state = self.current_state()
                debug(f'Scheduled {hex(tid)} that corresponds to native {hex(post_event.tid)}')

                if self._current_event_id in self._thread_context:
                    event = self._thread_context.pop(self._current_event_id)
                elif match_event(post_event, state):
                    event = post_event
                    post_event = self._events.match_pair(event)
                else:
                    debug(f'New thread {hex(tid)} started at non-event instruction')
                    self._events.unmatch()
                    self._step()
                    print(hex(self.current_state().read_pc()))
                    return self.current_state()

            return self._handle_syscall(event, post_event)

        warn(f'Event handling for events of type {event.event_type} not implemented')
        return None

    def __iter__(self):
        return self

    def __next__(self) -> ReadableProgramState:
        # The first call to __next__ should yield the first program state,
        # i.e. before stepping the first time
        if self._first_next:
            self._first_next = False
            return GDBProgramState(self._process, gdb.selected_frame(), self.arch)

        state = self._handle_event()
        if self.is_exited():
            raise StopIteration

        if not state:
            # Step
            state = self._step()

        return state

    def run_until(self, addr: int) -> ReadableProgramState:
        events_handled = 0
        event = self._events.next()
        while event:
            state = self._run_until_any([addr, event.pc])
            if state.read_pc() == addr:
                # Check if we started at the very _start
                self._first_next = events_handled == 0
                return state

            self._handle_event()
            if self.is_exited():
                raise Exception(f'Exited before reaching start address {hex(addr)}')

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

    def context_switch(self, thread_number: int) -> None:
        self.sock.send(bytes([thread_number]))

