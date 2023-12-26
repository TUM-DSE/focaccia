"""Invocable like this:

    gdb -n --batch -x qemu_tool.py
"""

import argparse
import re
import shlex
import subprocess
from typing import TextIO

import parser
from arch import x86
from lldb_target import MemoryMap
from snapshot import ProgramState

def parse_memory_maps(stream: TextIO) -> tuple[list[MemoryMap], str]:
    """
    :return: Returns the list of parsed memory mappings as well as the first
             line in the stream that does not belong to the memory mapping
             information, i.e. the line that terminates the block of mapping
             information.
             The line is returned for the technical reason that the parser
             needs to read a line from the stream in order to determine that
             this line does no longer belong to the mapping information; but it
             might still contain other important information.
    """
    mappings = []
    while True:
        line = stream.readline()
        split = line.split(' ')
        if len(split) != 3 or not re.match('^[0-9a-f]+-[0-9a-f]+$', split[0]):
            return mappings, line

        addr_range, size, perms = split
        start, end = addr_range.split('-')
        start, end = int(start, 16), int(end, 16)
        mappings.append(MemoryMap(start, end, '[unnamed]', perms))

def copy_memory(proc, state: ProgramState, maps: list[MemoryMap]):
    """Copy memory from a GDB process to a ProgramState object.

    Problem: Reading large mappings via GDB takes way too long (~500ms for ~8MB).
    """
    for mapping in maps:
        # Only copy read- and writeable memory from the process. This is a
        # heuristic to try to copy only heap and stack.
        if 'rw' not in mapping.perms:
            continue

        map_size = mapping.end_address - mapping.start_address
        mem = proc.read_memory(mapping.start_address, map_size)
        assert(mem.contiguous)
        assert(mem.nbytes == len(mem.tobytes()))
        assert(mem.nbytes == map_size)
        state.write_memory(mapping.start_address, mem.tobytes())

def run_gdb(qemu_log: TextIO, qemu_port: int) -> list[ProgramState]:
    import gdb

    gdb.execute('set pagination 0')
    gdb.execute('set sysroot')
    gdb.execute(f'target remote localhost:{qemu_port}')
    process = gdb.selected_inferior()

    arch = x86.ArchX86()
    mappings: list[MemoryMap] = []
    states: list[ProgramState] = []

    while process.is_valid() and len(process.threads()) > 0:
        for line in qemu_log:
            if re.match('^start +end +size +prot$', line):
                mappings, line = parse_memory_maps(qemu_log)

            if line.startswith('Trace'):
                states.append(ProgramState(arch))
                copy_memory(process, states[-1], mappings)
                continue

            if states:
                parser._parse_qemu_line(line, states[-1])

        gdb.execute('si', to_string=True)

    return states

def make_argparser():
    prog = argparse.ArgumentParser()
    prog.add_argument('binary',
                      type=str,
                      help='The binary to run and record.')
    prog.add_argument('--binary-args',
                      type=str,
                      help='A string of arguments to be passed to the binary.')
    prog.add_argument('--output', '-o', help='Name of output file.')
    prog.add_argument('--gdbserver-port',  type=int, default=12421)
    prog.add_argument('--qemu',            type=str, default='qemu-x86_64',
                      help='QEMU binary to invoke. [Default: qemu-x86_64')
    prog.add_argument('--qemu-log',        type=str, default='qemu.log')
    prog.add_argument('--qemu-extra-args', type=str, default='',
                      help='Arguments passed to QEMU in addition to the'
                           ' default ones required by this script.')
    return prog

if __name__ == "__main__":
    args = make_argparser().parse_args()

    binary = args.binary
    binary_args = shlex.split(args.binary_args) if args.binary_args else ''

    qemu_bin = args.qemu
    gdbserver_port = args.gdbserver_port
    qemu_log_name = args.qemu_log
    qemu_args = [
        qemu_bin,
        '--trace', 'target_mmap*',
        '--trace', 'memory_notdirty_*',
        # We write QEMU's output to a log file, then read it from that file.
        # This is preferred over reading from the process's stdout pipe because
        # we require a non-blocking solution that returns when all available
        # lines have been read.
        '-D', qemu_log_name,
        '-d', 'cpu,fpu,exec,unimp,page,strace',
        '-g', str(gdbserver_port),
        *shlex.split(args.qemu_extra_args),
        binary,
        *binary_args,
    ]

    qemu = subprocess.Popen(qemu_args)

    with open(qemu_log_name, 'r') as qemu_log:
        snapshots = run_gdb(qemu_log, gdbserver_port)

    with open(args.output, 'w') as file:
        parser.serialize_snapshots(snapshots, file)
