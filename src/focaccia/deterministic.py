"""Parsing of JSON files containing snapshot data."""

import os
from typing import Union

import brotli

from .arch import Arch
from .snapshot import ReadableProgramState

try:
    import capnp
    rr_trace = capnp.load(file_name='./rr/src/rr_trace.capnp',
                          imports=[os.path.dirname(p) for p in capnp.__path__])
except Exception as e:
    print(f'Cannot load RR trace loader: {e}')
    exit(2)

Frame = rr_trace.Frame
TaskEvent = rr_trace.TaskEvent
MMap = rr_trace.MMap
SerializedObject = Union[Frame, TaskEvent, MMap]

def parse_x64_registers(enc_regs: bytes, signed: bool=False) -> dict[str, int]:
    idx = 0
    def parse_reg():
        nonlocal idx
        enc_reg = enc_regs[idx:(idx := idx + 8)]
        return int.from_bytes(enc_reg, byteorder='little', signed=signed)

    regs = {}

    regs['r15'] = parse_reg()
    regs['r14'] = parse_reg()
    regs['r13'] = parse_reg()
    regs['r12'] = parse_reg()
    regs['rbp'] = parse_reg()
    regs['rbx'] = parse_reg()

    # rcx is unreliable: parsed but ignored
    parse_reg()

    regs['r10'] = parse_reg()
    regs['r9'] = parse_reg()
    regs['r8'] = parse_reg()

    regs['rax'] = parse_reg()

    # rcx is unreliable: parsed but ignored
    parse_reg()

    regs['rdx'] = parse_reg()
    regs['rsi'] = parse_reg()
    regs['rdi'] = parse_reg()

    regs['orig_rax'] = parse_reg()

    regs['rip'] = parse_reg()
    regs['cs'] = parse_reg()

    # eflags is unreliable: parsed but ignored
    parse_reg()

    regs['rsp'] = parse_reg()
    regs['ss'] = parse_reg()
    regs['fs_base'] = parse_reg()
    regs['ds'] = parse_reg()
    regs['es'] = parse_reg()
    regs['fs'] = parse_reg()
    regs['gs'] = parse_reg()
    regs['gs_base'] = parse_reg()

    return regs

def parse_aarch64_registers(enc_regs: bytes, order: str='little', signed: bool=False) -> dict[str, int]:
    idx = 0
    def parse_reg():
        nonlocal idx
        enc_reg = enc_regs[idx:(idx := idx + 8)]
        return int.from_bytes(enc_reg, byteorder=order, signed=signed)

    regnames = []
    for i in range(32):
        regnames.append(f'x{i}')
    regnames.append('sp')
    regnames.append('pc')
    regnames.append('cpsr')

    regs = {}
    for i in range(len(regnames)):
        regs[regnames[i]] = parse_reg()
    
    return regs

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

    def match(self, pc: int, target: ReadableProgramState) -> bool:
        # TODO: match the rest of the state to be sure
        if self.pc == pc:
            for reg, value in self.registers.items():
                if value == self.pc:
                    continue
                if target.read_register(reg) != value:
                    print(f'Failed match for {reg}: {hex(value)} != {hex(target.read_register(reg))}')
                    return False
            return True
        return False

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

class DeterministicLog:
    def __init__(self, log_dir: str):
        self.base_directory = log_dir

    def events_file(self) -> str:
        return os.path.join(self.base_directory, 'events')

    def tasks_file(self) -> str:
        return os.path.join(self.base_directory, 'tasks')

    def mmaps_file(self) -> str:
        return os.path.join(self.base_directory, 'mmaps')

    def data_file(self) -> str:
        return os.path.join(self.base_directory, 'data')

    def _read(self, file) -> bytes:
        data = bytearray()
        with open(file, 'rb') as f:
            while True:
                try:
                    compressed_len = int.from_bytes(f.read(4), byteorder='little')
                    uncompressed_len = int.from_bytes(f.read(4), byteorder='little')
                except Exception as e:
                    raise Exception(f'Malformed deterministic log: {e}') from None

                chunk = f.read(compressed_len)
                if not chunk:
                    break

                chunk = brotli.decompress(chunk)
                if len(chunk) != uncompressed_len:
                    raise Exception(f'Malformed deterministic log: uncompressed chunk is not equal'
                                    f'to reported length {hex(uncompressed_len)}')
                data.extend(chunk)
        return bytes(data)

    def _read_structure(self, file, obj: SerializedObject) -> list[SerializedObject]:
        data = self._read(file)

        objects = []
        for deser in obj.read_multiple_bytes_packed(data):
            objects.append(deser)
        return objects

    def raw_events(self) -> list[Frame]:
        return self._read_structure(self.events_file(), Frame)

    def raw_tasks(self) -> list[TaskEvent]:
        return self._read_structure(self.tasks_file(), TaskEvent)

    def raw_mmaps(self) -> list[MMap]:
        return self._read_structure(self.mmaps_file(), MMap)

    def events(self) -> list[Event]:
        def parse_registers(event: Frame) -> Union[int, dict[str, int]]:
            arch = event.arch
            if arch == rr_trace.Arch.x8664:
                regs = parse_x64_registers(event.registers.raw)
                return regs['rip'], regs
            if arch == rr_trace.Arch.aarch64:
                regs = parse_aarch64_registers(event.registers.raw)
                return regs['pc'], regs
            raise NotImplementedError(f'Unable to parse registers for architecture {arch}')

        def fill_memory_writes(self, mem_writes: list[MemoryWrite]) -> list[MemoryWrite]:
            with open(self.data_file, 'rb') as f:
                for mem_write in mem_writes:
                    mem_write.data = f.read(mem_write.size)
            return mem_writes

    
        def parse_memory_writes(event: Frame, data_src: bytes, pos: int):
            writes = []
            for raw_write in event.memWrites:
                # Skip memory writes with 0 bytes
                if raw_write.size == 0:
                    continue

                holes = []
                for raw_hole in raw_write.holes:
                    holes.append(MemoryWriteHole(raw_hole.offset, raw_hole.size))

                data = bytearray()
                for hole in holes:
                    until_hole = hole.offset - pos
                    data.extend(data_src[pos:pos+until_hole])
                    data.extend(b'\x00' * hole.size)
                    pos += until_hole

                # No holes
                if len(data) == 0:
                    data = data_src[pos:pos+raw_write.size]
                    pos += raw_write.size

                mem_write = MemoryWrite(raw_write.tid,
                                        raw_write.addr,
                                        raw_write.size,
                                        holes,
                                        raw_write.sizeIsConservative,
                                        bytes(data))
                writes.append(mem_write)
            return writes, pos

        pos = 0
        data = self._read(self.data_file())

        events = []
        raw_events = self.raw_events()
        for raw_event in raw_events:
            pc, registers = parse_registers(raw_event)
            mem_writes, pos = parse_memory_writes(raw_event, data, pos)

            event = None

            tid = raw_event.tid
            arch = raw_event.arch
            event_type = raw_event.event.which()

            if event_type == 'syscall': 
                if raw_event.arch == rr_trace.Arch.x8664:
                    # On entry: substitute orig_rax for RAX
                    if raw_event.event.syscall.state == rr_trace.SyscallState.entering:
                        registers['rax'] = registers['orig_rax']
                    del registers['orig_rax']
                event = SyscallEvent(pc,
                                     tid,
                                     arch,
                                     registers,
                                     mem_writes,
                                     raw_event.event.syscall.arch,
                                     raw_event.event.syscall.number,
                                     raw_event.event.syscall.state,
                                     raw_event.event.syscall.failedDuringPreparation)

            if event_type == 'syscallbufFlush':
                event = SyscallBufferFlushEvent(pc,
                                                tid,
                                                arch,
                                                registers,
                                                mem_writes,
                                                raw_event.event.syscallbufFlush.mprotectRecords)
                raise NotImplementedError(f'Cannot support system call buffer events yet: {event}')
            if event_type == 'signal':
                signal = raw_event.event.signal
                signal_descriptor = SignalDescriptor(signal.arch,
                                                     signal.siginfo,
                                                     signal.deterministic,
                                                     signal.disposition)
                event = SignalEvent(pc, tid, arch, registers, mem_writes, 
                                    signal_number=signal_descriptor)

            if event_type == 'signalDelivery':
                signal = raw_event.event.signalDelivery
                signal_descriptor = SignalDescriptor(signal.arch,
                                                     signal.siginfo,
                                                     signal.deterministic,
                                                     signal.disposition)
                event = SignalEvent(pc, tid, arch, registers, mem_writes, 
                                    signal_delivery=signal_descriptor)

            if event_type == 'signalHandler':
                signal = raw_event.event.signalHandler
                signal_descriptor = SignalDescriptor(signal.arch,
                                                     signal.siginfo,
                                                     signal.deterministic,
                                                     signal.disposition)
                event = SignalEvent(pc, tid, arch, registers, mem_writes, 
                                    signal_handler=signal_descriptor)

            if event is None:
                event = Event(pc, tid, arch, registers, mem_writes, event_type)

            events.append(event)

        return events

    def tasks(self) -> list[Task]:
        tasks = []
        raw_tasks = self.raw_tasks()
        for raw_task in raw_tasks:
            task_type = raw_task.which()

            task = None
            if task_type == 'clone':
                task = CloneTask(raw_task.frameTime,
                                 raw_task.tid,
                                 raw_task.clone.parentTid,
                                 raw_task.clone.flags,
                                 raw_task.clone.ownNsTid)
            if task_type == 'exec':
                task = ExecTask(raw_task.frameTime,
                                raw_task.tid,
                                raw_task.exec.fileName,
                                raw_task.exec.cmdLine,
                                raw_task.exec.exeBase,
                                raw_task.exec.interpBase,
                                raw_task.exec.interpName)
            if task_type == 'exit':
                task = ExitTask(raw_task.frameTime, raw_task.tid, raw_task.exit.exitStatus)
            if task_type == 'detach':
                task = DetachTask(raw_task.frameTime, raw_task.tid)
            tasks.append(task)
        return tasks

    def mmaps(self) -> list[MemoryMapping]:
        def mapping_source(mmap: MMap) -> str:
            source_type = mmap.source.which()
            if source_type == 'zero' or source_type == 'trace':
                return source_type
            elif source_type == 'file':
                return mmap.source.file.backingFileName
            else:
                raise NotImplementedError(f'Unable to handle memory mappings from source type:'
                                          f' {source_type}')

        mmaps = []
        raw_mmaps = self.raw_mmaps()
        for raw_mmap in raw_mmaps:
            mmap = MemoryMapping(raw_mmap.frameTime,
                                 raw_mmap.start,
                                 raw_mmap.end,
                                 mapping_source(raw_mmap),
                                 raw_mmap.fileOffsetBytes,
                                 raw_mmap.prot,
                                 raw_mmap.flags)
            mmaps.append(mmap)
        return mmaps

