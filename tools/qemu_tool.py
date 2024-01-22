"""Invocable like this:

    gdb -n --batch -x qemu_tool.py
"""

import gdb
import platform

import focaccia.parser as parser
from focaccia.arch import supported_architectures, Arch
from focaccia.compare import compare_symbolic, ErrorTypes
from focaccia.snapshot import ProgramState
from focaccia.symbolic import SymbolicTransform, eval_symbol
from focaccia.utils import print_result

from verify_qemu import make_argparser

class GDBProgramState:
    def __init__(self, process: gdb.Inferior, frame: gdb.Frame):
        self._proc = process
        self._frame = frame

    def read_register(self, regname: str) -> int | None:
        try:
            return int(self._frame.read_register(regname.lower()))
        except ValueError as err:
            from focaccia.arch import x86
            rflags = int(self._frame.read_register('eflags'))
            rflags = x86.decompose_rflags(rflags)
            if regname in rflags:
                return rflags[regname]

            print(f'{regname}: {err}')
            return None

    def read_memory(self, addr: int, size: int) -> bytes | None:
        try:
            return self._proc.read_memory(addr, size).tobytes()
        except gdb.MemoryError as err:
            print(f'@{size}[{hex(addr)}]: {err}')
            return None

class GDBServerStateIterator:
    def __init__(self, address: str, port: int):
        gdb.execute('set pagination 0')
        gdb.execute('set sysroot')
        gdb.execute(f'target remote {address}:{port}')
        self._process = gdb.selected_inferior()
        self._first_next = True

    def __iter__(self):
        return self

    def __next__(self):
        # The first call to __next__ should yield the first program state,
        # i.e. before stepping the first time
        if self._first_next:
            self._first_next = False
            return GDBProgramState(self._process, gdb.selected_frame())

        # Step
        pc = gdb.selected_frame().read_register('pc')
        new_pc = pc
        while pc == new_pc:
            gdb.execute('si', to_string=True)
            if not self._process.is_valid() or len(self._process.threads()) == 0:
                raise StopIteration
            new_pc = gdb.selected_frame().read_register('pc')

        return GDBProgramState(self._process, gdb.selected_frame())

def collect_conc_trace(arch: Arch, \
                       gdb: GDBServerStateIterator, \
                       strace: list[SymbolicTransform]) \
        -> list[ProgramState]:
    states = []
    for qemu, transform in zip(gdb, strace):
        qemu_pc = qemu.read_register('pc')
        assert(qemu_pc is not None)

        if qemu_pc != transform.addr:
            print(f'Fatal error: QEMU\'s program counter'
                  f' ({hex(qemu_pc)}) does not match the'
                  f' expected program counter in the symbolic trace'
                  f' ({hex(transform.addr)}).')
            print(f'Processing only partial trace up to this instruction.')
            return states

        state = ProgramState(arch)
        state.set_register('PC', transform.addr)

        accessed_regs = transform.get_used_registers()
        accessed_mems = transform.get_used_memory_addresses()
        for regname in accessed_regs:
            regval = qemu.read_register(regname)
            if regval is not None:
                state.set_register(regname, regval)
        for mem in accessed_mems:
            assert(mem.size % 8 == 0)
            addr = eval_symbol(mem.ptr, qemu)
            mem = qemu.read_memory(addr, int(mem.size / 8))
            if mem is not None:
                state.write_memory(addr, mem)
        states.append(state)

    return states

def main():
    args = make_argparser().parse_args()

    gdbserver_port = args.gdbserver_port
    with open(args.symb_trace, 'r') as strace:
        symb_transforms = parser.parse_transformations(strace)

    arch = supported_architectures[platform.machine()]
    conc_states = collect_conc_trace(
        arch,
        GDBServerStateIterator('localhost', gdbserver_port),
        symb_transforms)

    res = compare_symbolic(conc_states, symb_transforms)
    print_result(res, ErrorTypes.POSSIBLE)

if __name__ == "__main__":
    main()
