"""Parsing of JSON files containing snapshot data."""

import os
import io
import struct
from typing import Union, Optional

import brotli

from .deterministic import (
    MemoryWriteHole,
    MemoryWrite,
    Event,
    SyscallBufferFlushEvent,
    SyscallExtra,
    SyscallEvent,
    SignalDescriptor,
    SignalEvent,
    MemoryMapping,
    Task,
    CloneTask,
    ExecTask,
    ExitTask
)

import capnp
rr_trace = capnp.load(file_name='./rr/src/rr_trace.capnp',
                      imports=[os.path.dirname(p) for p in capnp.__path__])

Frame = rr_trace.Frame
TaskEvent = rr_trace.TaskEvent
MMap = rr_trace.MMap
SerializedObject = Union[Frame, TaskEvent, MMap]

class DeterministicLogReader(io.RawIOBase):
    """
    File-like reader for rr trace files.

    Each block in the file:
      uint32_t uncompressed_size
      uint32_t compressed_size
      [compressed_data...]
    Presents the concatenated uncompressed data as a sequential byte stream.
    """

    _HDR = struct.Struct("<II")

    def __init__(self, filename: str):
        super().__init__()
        self._f = open(filename, "rb", buffering=0)
        self._data_buffer = memoryview(b"")
        self._pos = 0
        self._eof = False

    def _load_chunk(self) -> None:
        """Load and decompress the next Brotli block."""
        header = self._f.read(self._HDR.size)
        if not header:
            self._eof = True
            self._data_buffer = memoryview(b"")
            return
        if len(header) != self._HDR.size:
            raise EOFError("Incomplete RR data block header")

        compressed_length, uncompressed_length = self._HDR.unpack(header)
        chunk = self._f.read(compressed_length)
        if len(chunk) != compressed_length:
            raise EOFError("Incomplete RR data block")

        chunk = brotli.decompress(chunk)
        if len(chunk) != uncompressed_length:
            raise Exception(f'Malformed deterministic log: uncompressed chunk is not equal'
                            f'to reported length {hex(uncompressed_length)}')

        self._data_buffer = memoryview(chunk)
        self._pos = 0

    def read(self, n: Optional[int] = -1) -> bytes:
        """Read up to n bytes from the uncompressed stream."""
        if n == 0:
            return b""

        chunks = bytearray()
        remaining = n if n is not None and n >= 0 else None

        while not self._eof and (remaining is None or remaining > 0):
            if self._pos >= len(self._data_buffer):
                self._load_chunk()
                if self._eof:
                    break

            available = len(self._data_buffer) - self._pos
            take = available if remaining is None else min(available, remaining)
            chunks += self._data_buffer[self._pos:self._pos + take]
            self._pos += take
            if remaining is not None:
                remaining -= take

        return bytes(chunks)

    def readable(self) -> bool:
        return True

    def close(self) -> None:
        if not self.closed:
            self._f.close()
        super().close()

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

class DeterministicLog:
    def __init__(self, log_dir: str):
        self.base_directory = log_dir

    def _get_file(self, file_name: str) -> str | None:
        candidate = os.path.join(self.base_directory, file_name)
        if os.path.isfile(candidate):
            return candidate
        return None

    def events_file(self) -> str | None:
        return self._get_file('events')

    def tasks_file(self) -> str | None:
        return self._get_file('tasks')

    def mmaps_file(self) -> str | None:
        return self._get_file('mmaps')

    def data_file(self) -> str | None:
        return self._get_file('data')

    def _read_structure(self, file, obj: SerializedObject) -> list[SerializedObject]:
        data = DeterministicLogReader(file).read()

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
                if event.event.which() == 'syscall':
                    regs['rip'] -= 2
                pc = regs['rip']
                return pc, regs
            if arch == rr_trace.Arch.aarch64:
                regs = parse_aarch64_registers(event.registers.raw)
                if event.event.which() == 'syscall':
                    regs['pc'] -= 4
                pc = regs['pc']
                return pc, regs
                return pc, regs
            raise NotImplementedError(f'Unable to parse registers for architecture {arch}')

        def parse_memory_writes(event: Frame, reader: io.RawIOBase) -> list[MemoryWrite]:
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
                    until_hole = hole.offset - reader.tell()
                    data.extend(reader.read(until_hole))
                    data.extend(b'\x00' * hole.size)

                # No holes
                if len(data) == 0:
                    data = reader.read(raw_write.size)

                mem_write = MemoryWrite(raw_write.tid,
                                        raw_write.addr,
                                        raw_write.size,
                                        holes,
                                        raw_write.sizeIsConservative,
                                        bytes(data))
                writes.append(mem_write)
            return writes

        data_reader = DeterministicLogReader(self.data_file())

        events = []
        raw_events = self.raw_events()
        for raw_event in raw_events:
            pc, registers = parse_registers(raw_event)
            mem_writes = parse_memory_writes(raw_event, data_reader)

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

