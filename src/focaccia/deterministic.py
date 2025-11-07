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

class Event:
    def __init__(self,
                 pc: int,
                 tid: int,
                 arch: Arch,
                 event_type: str,
                 registers: dict[str, int],
                 memory_writes: dict[int, int]):
        self.pc = pc
        self.tid = tid
        self.arch = arch
        self.event_type = event_type

        self.registers = registers
        self.mem_writes = memory_writes

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
        reg_repr = ''
        for reg, value in self.registers.items():
            reg_repr += f'{reg} = {hex(value)}\n'

        mem_write_repr = ''
        for addr, size in self.mem_writes.items():
            mem_write_repr += f'{hex(addr)}:{hex(addr+size)}\n'

        repr_str = f'Thread {hex(self.tid)} executed event {self.event_type} at {hex(self.pc)}\n'
        repr_str += f'Register set:\n{reg_repr}'
        
        if len(self.mem_writes):
            repr_str += f'\nMemory writes:\n{mem_write_repr}'

        return repr_str

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
        repr_str  = f'Clone task\n{super().__repr__()}\n'
        repr_str += f'parent tid = {hex(self.parent_tid)}\n' \
                    f'clone flags = {hex(self.clone_flags)}\n' \
                    f'own namespace tid = {hex(self.own_namespace_tid)}'
        return repr_str

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

    def __repr__(self):
        repr_str  = f'Exec task\n{super().__repr__()}\n'
        repr_str += f'filename = {self.filename}\n' \
                    f'command-line = {self.commandline}\n' \
                    f'execution base address = {hex(self.execution_base_address)}\n' \
                    f'interpereter base address = {hex(self.interpreter_base_address)}\n' \
                    f'interpreter name = {self.interpreter_name}'
        return repr_str

class ExitTask(Task):
    def __init__(self,
                 event_count: int,
                 tid: int,
                 exit_status: int):
        super().__init__(event_count, tid)
        self.exit_status = exit_status

    def __repr__(self):
        repr_str = f'Exit task\n{super().__repr__()}\n'
        repr_str += f'exit status = {hex(self.exit_status)}'
        return repr_str

class DetachTask(Task):
    def __init__(self,
                 event_count: int,
                 tid: int):
        super().__init__(event_count, tid)

    def __repr__(self):
        repr_str = f'Detach task\n{super().__repr__()}'
        return repr_str

class DeterministicLog:
    def __init__(self, log_dir: str):
        self.base_directory = log_dir

    def events_file(self) -> str:
        return os.path.join(self.base_directory, 'events')

    def tasks_file(self) -> str:
        return os.path.join(self.base_directory, 'tasks')

    def mmaps_file(self) -> str:
        return os.path.join(self.base_directory, 'mmaps')

    def _read(self, file, obj: SerializedObject) -> list[SerializedObject]:
        data = bytearray()
        objects = []
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

            for deser in obj.read_multiple_bytes_packed(data):
                objects.append(deser)
            return objects

    def raw_events(self) -> list[Frame]:
        return self._read(self.events_file(), Frame)

    def raw_tasks(self) -> list[TaskEvent]:
        return self._read(self.tasks_file(), TaskEvent)

    def raw_mmaps(self) -> list[MMap]:
        return self._read(self.mmaps_file(), MMap)

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
    
        def parse_memory_writes(event: Frame) -> dict[int, int]:
            writes = {}
            for raw_write in event.memWrites:
                writes[int(raw_write.addr)] = int(raw_write.size)
            return writes

        events = []
        raw_events = self.raw_events()
        for raw_event in raw_events:
            pc, registers = parse_registers(raw_event)
            mem_writes = parse_memory_writes(raw_event)

            event_type = raw_event.event.which()
            if event_type == 'syscall' and raw_event.arch == rr_trace.Arch.x8664:
                # On entry: substitute orig_rax for RAX
                if raw_event.event.syscall.state == rr_trace.SyscallState.entering:
                    registers['rax'] = registers['orig_rax']
                del registers['orig_rax']

            event = Event(pc,
                          raw_event.tid,
                          raw_event.arch,
                          event_type,
                          registers, mem_writes)
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

