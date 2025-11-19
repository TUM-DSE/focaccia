from .arch import Arch
from .snapshot import ReadableProgramState

from reprlib import repr as alt_repr
from typing import Callable, Tuple, Optional

class MemoryWriteHole:
    def __init__(self, offset: int, size: int):
        self.offset = offset
        self.size = size
        if self.size <= 0:
            raise ValueError(f'Write hole cannot have size {size}')

    def __repr__(self) -> str:
        return f'hole at {hex(self.offset)}:{hex(self.offset+self.size)}'

class MemoryWrite:
    def __init__(self,
                 tid: int,
                 address: int,
                 size: int,
                 holes: list[MemoryWriteHole],
                 is_conservative: bool,
                 data: bytes | None = None):
        self.tid = tid
        self.address = address
        self.size = size
        self.holes = holes
        self.is_conservative = is_conservative
        self.data = data

    def __repr__(self) -> str:
        return f'{{ tid: {hex(self.tid)}, addr: {hex(self.address)}:{hex(self.address+self.size)}\n' \
               f'   conservative? {self.is_conservative}, holes: {self.holes}\n' \
               f'   data: {self.data} }}'

class Event:
    def __init__(self,
                 pc: int,
                 tid: int,
                 arch: Arch,
                 registers: dict[str, int],
                 memory_writes: list[MemoryWrite],
                 event_type: str):
        self.pc = pc
        self.tid = tid
        self.arch = arch

        self.registers = registers
        self.mem_writes = memory_writes
        self.event_type = event_type

    def __repr__(self) -> str:
        reg_repr = f'{self.event_type} event\n'
        for reg, value in self.registers.items():
            reg_repr += f'{reg} = {hex(value)}\n'

        mem_write_repr = ''
        for mem_write in self.mem_writes:
            mem_write_repr += f'{alt_repr(mem_write)}\n'

        repr_str = f'Thread {hex(self.tid)} executed event {self.event_type} at {hex(self.pc)}\n'
        repr_str += f'Register set:\n{reg_repr}'

        if len(self.mem_writes):
            repr_str += f'\nMemory writes:\n{mem_write_repr}'

        return repr_str

class SyscallBufferFlushEvent(Event):
    def __init__(self,
                 pc: int,
                 tid: int,
                 arch: Arch,
                 registers: dict[str, int],
                 memory_writes: list[MemoryWrite],
                 mprotect_records: bytes):
        super().__init__(pc, tid, arch, registers, memory_writes, 'syscallBufFlush')
        self.mprotect_records = mprotect_records

    def __repr__(self):
        return f'{super().__repr__()}\nmprotect_records = {self.mprotect_records}'

class SyscallExtra:
    def __init__(self,
                 write_offset: int | None,
                 exec_fds_to_close: list[int] | None,
                 opened_fds: list[int] | None,
                 socket_local_address: bytes,
                 socket_remote_address: bytes):
        self.write_offset = write_offset
        self.exec_fds_to_close = exec_fds_to_close
        self.opened_fds = opened_fds
        self.socket_local_address = socket_local_address
        self.socket_remote_address = socket_remote_address

class SyscallEvent(Event):
    def __init__(self,
                 pc: int,
                 tid: int,
                 arch: Arch,
                 registers: dict[str, int],
                 memory_writes: list[MemoryWrite],
                 syscall_arch: Arch,
                 syscall_number: int,
                 syscall_state: str,
                 failed_during_preparation: bool,
                 syscall_extras: SyscallExtra | None = None):
        super().__init__(pc, tid, arch, registers, memory_writes, 'syscall')
        self.syscall_arch = syscall_arch
        self.syscall_number = syscall_number
        self.syscall_state = syscall_state
        self.failed_during_preparation = failed_during_preparation
        self.syscall_extras = syscall_extras

        if syscall_state not in ['entering', 'exiting', 'enteringPtrace']:
            raise NotImplementedError(f'Cannot handle system call state of type: {syscall_state}')

    def __repr__(self) -> str:
        return f'{super().__repr__()}\n' \
               f'system call architecture = {self.syscall_arch}\n' \
               f'system call number = {hex(self.syscall_number)}\n' \
               f'system call state = {self.syscall_state}\n' \
               f'failed during preparation? {self.failed_during_preparation}\n' \
               f'syscall extras: {self.syscall_extras}\n'

class SignalDescriptor:
    def __init__(self,
                 arch: Arch,
                 siginfo: bytes,
                 deterministic: bool,
                 disposition: str):
        self.arch = arch
        self.siginfo = siginfo
        self.deterministic = deterministic
        self.disposition = disposition

        if self.disposition not in ['fatal', 'userHandler', 'ignored']:
            raise NotImplementedError(f'Canot handle signal dispositions of type'
                                      f' {self.disposition}')

    def __repr__(self) -> str:
        return f'signal architecture: {self.arch}\n' \
               f'siginfo data:\n{self.siginfo}\n' \
               f'deterministic? {self.deterministic}\n' \
               f'disposition: {self.disposition}\n'

class SignalEvent(Event):
    def __init__(self,
                 pc: int,
                 tid: int,
                 arch: Arch,
                 registers: dict[str, int],
                 memory_writes: list[MemoryWrite],
                 signal_number: SignalDescriptor | None = None,
                 signal_delivery: SignalDescriptor | None = None,
                 signal_handler: SignalDescriptor | None = None):
        super().__init__(pc, tid, arch, registers, memory_writes, 'signal')
        self.signal_number = signal_number
        self.signal_delivery = signal_delivery
        self.signal_handler = signal_handler

        if [self.signal_number, self.signal_delivery, self.signal_handler].count(None) != 2:
            raise ValueError(f'A signal event may be either a signal number, delivery or handler event')

    def __repr__(self) -> str:
        repr_str = f'{super().__repr__()}\n'
        if self.signal_number:
            return repr_str + '{self.signal_number}'
        if self.signal_delivery:
            return repr_str + '{self.signal_delivery}'
        if self.signal_handler:
            return repr_str + '{self.signal_handler}'

class MemoryMapping:
    def __init__(self,
                 event_count: int,
                 start_address: int,
                 end_address: int,
                 source: str,
                 offset: int,
                 mmap_prot: int,
                 mmap_flags: int,
                 name: str | None = None):
        self.event_count = event_count
        self.start_address = start_address
        self.length = end_address - self.start_address
        self.source = source
        self.offset = offset
        self.mmap_prot = mmap_prot
        self.mmap_flags = mmap_flags
        self.name = name

    def __repr__(self) -> str:
        header = f'Memory mapping at event {self.event_count}\n'
        if self.name:
            header += f'name = {self.name}\n'
        return header + f'start = {hex(self.start_address)}\n' \
               f'length = {self.length}\n' \
               f'source = {self.source}\n' \
               f'offset = {self.offset}\n' \
               f'mmap_prot = {hex(self.mmap_prot)}\n' \
               f'mmap_flags = {hex(self.mmap_flags)}'

class Task:
    def __init__(self,
                 event_count: int,
                 tid: int):
        self.event_count = event_count
        self.tid = tid

    def __repr__(self) -> str:
        return f'For event index {self.event_count} at tid = {hex(self.tid)}'

class CloneTask(Task):
    def __init__(self,
                 event_count: int,
                 tid: int,
                 parent_tid: int,
                 clone_flags: int,
                 own_namespace_tid: int):
        super().__init__(event_count, tid)
        self.parent_tid = parent_tid
        self.clone_flags = clone_flags
        self.own_namespace_tid = own_namespace_tid

    def __repr__(self) -> str:
        return f'Clone task\n{super().__repr__()}\n' \
               f'parent tid = {hex(self.parent_tid)}\n' \
               f'clone flags = {hex(self.clone_flags)}\n' \
               f'own namespace tid = {hex(self.own_namespace_tid)}'

class ExecTask(Task):
    def __init__(self,
                 event_count: int,
                 tid: int,
                 filename: str,
                 commandline: list[str],
                 execution_base_address: int,
                 interpreter_base_address: int,
                 interpreter_name: str):
        super().__init__(event_count, tid)
        self.filename = filename
        self.commandline = commandline
        self.execution_base_address = execution_base_address
        self.interpreter_base_address = interpreter_base_address
        self.interpreter_name = interpreter_name

    def __repr__(self) -> str:
        return f'Exec task\n{super().__repr__()}\n' \
               f'filename = {self.filename}\n' \
               f'command-line = {self.commandline}\n' \
               f'execution base address = {hex(self.execution_base_address)}\n' \
               f'interpereter base address = {hex(self.interpreter_base_address)}\n' \
               f'interpreter name = {self.interpreter_name}'

class ExitTask(Task):
    def __init__(self,
                 event_count: int,
                 tid: int,
                 exit_status: int):
        super().__init__(event_count, tid)
        self.exit_status = exit_status

    def __repr__(self) -> str:
        return f'Exit task\n{super().__repr__()}\n' \
               f'exit status = {hex(self.exit_status)}'

class DetachTask(Task):
    def __init__(self,
                 event_count: int,
                 tid: int):
        super().__init__(event_count, tid)

    def __repr__(self) -> str:
        return f'Detach task\n{super().__repr__()}'

try:
    from ._deterministic_impl import DeterministicLog
except Exception:
    class DeterministicLog:
        def __init__(self, log_dir: str): 
            self.base_directory = None

        def events_file(self) -> str | None: return None
        def tasks_file(self) -> str | None: return None
        def mmaps_file(self) -> str | None: return None
        def events(self) -> list[Event]: return []
        def tasks(self) -> list[Task]: return []
        def mmaps(self) -> list[MemoryMapping]: return []
finally:
    class EventMatcher:
        def __init__(self, 
                     events: list[Event], 
                     match_fn: Callable,
                     from_state: ReadableProgramState | None = None):
            self.events = events
            self.matcher = match_fn

            self.matched_count = None
            if from_state:
                self.match(from_state)
                self.matched_count -= 1

        def match(self, state: ReadableProgramState) -> Event | None:
            if self.matched_count is None:
                # Need to synchronize
                # Search for match
                for idx in range(len(self.events)):
                    event = self.events[idx]
                    if self.matcher(event, state):
                        self.matched_count = idx + 1
                        return event

                if self.matched_count is None:
                    return None

            event = self.events[self.matched_count]
            if self.matcher(event, state):
                self.matched_count += 1 # proceed to next
                return event
            
            return None

        def next(self):
            if self.matched_count is None:
                raise ValueError('Cannot get next event with unsynchronized event matcher')
            if self.matched_count < len(self.events):
                return self.events[self.matched_count]
            return None

        def match_pair(self, state: ReadableProgramState):
            event = self.match(state)
            if event is None:
                return None, None
            if isinstance(event, SyscallEvent) and event.syscall_state == 'exiting':
                self.matched_count = None
                return None, None
            assert(self.matched_count is not None)
            post_event = self.events[self.matched_count]
            self.matched_count += 1
            return event, post_event

        def __bool__(self) -> bool:
            return len(self.events) > 0

    class MappingMatcher:
        def __init__(self, memory_mappings: list[MemoryMapping]):
            self.memory_mappings = memory_mappings
            self.matched_count = None

        def match(self, event_count: int) -> list[MemoryMapping]:
            if self.matched_count is None:
                # Need to synchronize
                # Search for match
                mappings = []
                for idx in range(len(self.memory_mappings)):
                    mapping = self.memory_mappings[idx]
                    if mapping.event_count == event_count:
                        self.matched_count = idx + 1
                        mappings.append(mapping)
                return mappings

            mappings = []
            while self.matched_count < len(self.memory_mappings):
                mapping = self.memory_mappings[self.matched_count]
                if mapping.event_count == event_count:
                    self.matched_count += 1 # proceed to next
                    mappings.append(mapping)

            return mappings

        def next(self):
            if self.matched_count is None:
                raise ValueError('Cannot get next mapping with unsynchronized mapping matcher')
            if self.matched_count < len(self.memory_mappings):
                return self.memory_mappings[self.matched_count]
            return None

        def __bool__(self) -> bool:
            return len(self.memory_mappings) > 0

    class LogStateMatcher:
        def __init__(self, 
                     events: list[Event], 
                     memory_mappings: list[MemoryMapping],
                     event_match_fn: Callable,
                     from_state: ReadableProgramState | None = None):
            self.event_matcher = EventMatcher(events, event_match_fn, from_state)
            self.mapping_matcher = MappingMatcher(memory_mappings)

        def events(self) -> list[Event]:
            return self.event_matcher.events

        def mappings(self) -> list[MemoryMapping]:
            return self.mapping_matcher.memory_mappings

        def matched_events(self) -> Optional[int]:
            return self.event_matcher.matched_count

        def match(self, state: ReadableProgramState) -> Tuple[Optional[Event], list[MemoryMapping]]:
            event = self.event_matcher.match(state)
            if not event:
                return None, []
            assert(self.event_matcher.matched_count is not None)
            mapping = self.mapping_matcher.match(self.event_matcher.matched_count)
            return event, mapping

        def match_pair(self, state: ReadableProgramState) -> Tuple[Optional[Event], Optional[Event], list[MemoryMapping]]:
            event, post_event = self.event_matcher.match_pair(state)
            if not event:
                return None, None, []
            assert(self.event_matcher.matched_count is not None)
            mapping = self.mapping_matcher.match(self.event_matcher.matched_count-1)
            return event, post_event, mapping

        def next(self) -> Tuple[Optional[Event], list[MemoryMapping]]:
            next_event = self.event_matcher.next()
            if not next_event:
                return None, []
            assert(self.event_matcher.matched_count is not None)
            return next_event, self.mapping_matcher.match(self.event_matcher.matched_count)

        def __bool__(self) -> bool:
            return bool(self.event_matcher)

