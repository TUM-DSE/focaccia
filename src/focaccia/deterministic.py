from .arch import Arch
from .snapshot import ReadableProgramState

from typing import Callable

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
            mem_write_repr += f'{mem_write}\n'

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

        if [self.signal_number, self.signal_delivery, self.signal_handler].count(None) != 1:
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
                 mmap_flags: int):
        self.event_count = event_count
        self.start_address = start_address
        self.length = end_address - self.start_address
        self.source = source
        self.offset = offset
        self.mmap_prot = mmap_prot
        self.mmap_flags = mmap_flags

    def __repr__(self) -> str:
        return f'Memory mapping at event {self.event_count}\n' \
               f'start = {hex(self.start_address)}\n' \
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
    class DeterministicEventIterator:
        def __init__(self, deterministic_log: DeterministicLog, match_fn: Callable):
            self._detlog = deterministic_log
            self._events = self._detlog.events()
            self._pc_to_event = {}
            self._match = match_fn
            self._idx: int | None = None # None represents no current event
            self._in_event: bool = False

            idx = 0
            for event in self._events:
                self._pc_to_event.setdefault(event.pc, []).append((event, idx))

        def events(self) -> list[Event]:
            return self._events

        def current_event(self) -> Event | None:
            # No event when not synchronized
            if self._idx is None or not self._in_event:
                return None
            return self._events[self._idx]

        def update(self, target: ReadableProgramState) -> Event | None:
            # Quick check
            candidates = self._pc_to_event.get(target.read_pc(), [])
            if len(candidates) == 0:
                self._in_event = False
                return None

            # Find synchronization point
            if self._idx is None:
                for event, idx in candidates:
                    if self._match(event, target):
                        self._idx = idx
                        self._in_event = True
                        return self.current_event()

            return self.next()

        def next(self) -> Event | None:
            if self._idx is None:
                raise ValueError('Attempted to get next event without synchronizing')

            self._idx += 1
            return self.current_event()

        def __bool__(self) -> bool:
            return len(self.events()) > 0

