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
    regs['r11'] = parse_reg()
    regs['r10'] = parse_reg()
    regs['r9'] = parse_reg()
    regs['r8'] = parse_reg()

    regs['rax'] = parse_reg()
    regs['rcx'] = parse_reg()
    regs['rdx'] = parse_reg()
    regs['rsi'] = parse_reg()
    regs['rdi'] = parse_reg()
    regs['orig_rax'] = parse_reg()
    regs['rip'] = parse_reg()
    regs['cs'] = parse_reg()
    regs['eflags'] = parse_reg()
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
        with open(file, 'rb') as f:
            f.read(8)
            data = brotli.decompress(f.read())
            return obj.read_multiple_bytes_packed(data)

    def raw_events(self) -> list[SerializedObject]:
        return self._read(self.events_file(), Frame)

    def raw_tasks(self) -> list[SerializedObject]:
        return self._read(self.tasks_file(), TaskEvent)

    def raw_mmaps(self) -> list[SerializedObject]:
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
            event = Event(pc,
                          raw_event.tid,
                          raw_event.arch,
                          raw_event.event.which(),
                          registers, mem_writes)
            events.append(event)

        # deduplicate
        deduped_events = []
        for i in range(0, len(events), 2):
            if events[i].event_type == 'syscall':
                if events[i+1].pc == 0:
                    deduped_events.append(events[i])
                    break
                if events[i+1].event_type != 'syscall':
                    raise Exception(f'Event {events[i+1]} should follow {events[i]} but does not')
                deduped_events.append(events[i+1])

        return deduped_events

