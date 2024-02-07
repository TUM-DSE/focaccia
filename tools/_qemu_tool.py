"""Invocable like this:

    gdb -n --batch -x qemu_tool.py

But please use `tools/verify_qemu.py` instead because we have some more setup
work to do.
"""

import gdb
import platform
from typing import Iterable

import focaccia.parser as parser
from focaccia.arch import supported_architectures, Arch
from focaccia.compare import compare_symbolic
from focaccia.snapshot import ProgramState, ReadableProgramState, \
                              RegisterAccessError, MemoryAccessError
from focaccia.symbolic import SymbolicTransform, eval_symbol, ExprMem
from focaccia.utils import print_result

from verify_qemu import make_argparser, verbosity

class GDBProgramState(ReadableProgramState):
    def __init__(self, process: gdb.Inferior, frame: gdb.Frame):
        self._proc = process
        self._frame = frame

    def read_register(self, reg: str) -> int:
        try:
            val = self._frame.read_register(reg.lower())
            return int(val) & 0xffffffffffffffff  # force int to be unsigned
        except ValueError as err:
            from focaccia.arch import x86
            rflags = int(self._frame.read_register('eflags'))
            rflags = x86.decompose_rflags(rflags)
            if reg in rflags:
                return rflags[reg]
            raise RegisterAccessError(reg, str(err))

    def read_memory(self, addr: int, size: int) -> bytes:
        try:
            mem = self._proc.read_memory(addr, size).tobytes()
            return bytes(reversed(mem))  # Convert to big endian
        except gdb.MemoryError as err:
            raise MemoryAccessError(addr, size, str(err))

class GDBServerStateIterator:
    def __init__(self, address: str, port: int):
        gdb.execute('set pagination 0')
        gdb.execute('set sysroot')
        gdb.execute(f'target remote {address}:{port}')
        self._process = gdb.selected_inferior()
        self._first_next = True

        # Try to determine the guest architecture. This is a bit hacky and
        # tailored to GDB's naming for the x86-64 architecture.
        split = self._process.architecture().name().split(':')
        archname = split[1] if len(split) > 1 else split[0]
        archname = archname.replace('-', '_')
        if archname not in supported_architectures:
            print(f'Error: Current platform ({archname}) is not'
                  f' supported by Focaccia. Exiting.')
            exit(1)

        self.arch = supported_architectures[archname]

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
        while pc == new_pc:  # Skip instruction chains from REP STOS etc.
            gdb.execute('si', to_string=True)
            if not self._process.is_valid() or len(self._process.threads()) == 0:
                raise StopIteration
            new_pc = gdb.selected_frame().read_register('pc')

        return GDBProgramState(self._process, gdb.selected_frame())

def collect_conc_trace(gdb: GDBServerStateIterator, \
                       strace: list[SymbolicTransform]) \
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
    def record_snapshot(prev_state: ReadableProgramState,
                        cur_state: GDBProgramState,
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
                               leading to, `gdb_state`. Values generated by
                               this transformation are included in the
                               snapshot.
        :param transform: The symbolic transformation operating on this
                          snapshot. Input values to this transformation are
                          included in the snapshot.
        """
        assert(cur_state.read_register('pc') == cur_transform.addr)

        def get_written_addresses(t: SymbolicTransform):
            """Get all output memory accesses of a symbolic transformation."""
            return [ExprMem(a, v.size) for a, v in t.changed_mem.items()]

        def set_values(regs: Iterable[str], mems: Iterable[ExprMem],
                       cur_state: GDBProgramState, prev_state: ReadableProgramState,
                       out_state: ProgramState):
            """
            :param prev_state: Addresses of memory included in the snapshot are
                               resolved relative to this state.
            """
            for regname in regs:
                regval = cur_state.read_register(regname)
                try:
                    out_state.set_register(regname, regval)
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

        state = ProgramState(gdb.arch)
        state.set_register('PC', cur_transform.addr)

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
    while True:
        try:
            pc = cur_state.read_register('pc')
            assert(pc is not None)

            while pc != strace[symb_i].addr:
                next_i = find_index(strace[symb_i+1:], pc, lambda t: t.addr)

                # Drop the concrete state if no address in the symbolic trace
                # matches
                if next_i is None:
                    print(f'Warning: Dropping concrete state {hex(pc)}, as no'
                          f' matching instruction can be found in the symbolic'
                          f' reference trace.')
                    cur_state = next(state_iter)
                    pc = cur_state.read_register('pc')
                    assert(pc is not None)
                    continue

                # Otherwise, jump to the next matching symbolic state
                symb_i += next_i + 1

            assert(cur_state.read_register('pc') == strace[symb_i].addr)
            states.append(record_snapshot(
                states[-1] if states else cur_state,
                cur_state,
                matched_transforms[-1] if matched_transforms else strace[symb_i],
                strace[symb_i]))
            matched_transforms.append(strace[symb_i])
            cur_state = next(state_iter)
            symb_i += 1
        except StopIteration:
            break

    return states, matched_transforms

def main():
    args = make_argparser().parse_args()

    gdbserver_addr = 'localhost'
    gdbserver_port = args.port

    # Read pre-computed symbolic trace
    with open(args.symb_trace, 'r') as strace:
        symb_transforms = parser.parse_transformations(strace)

    # Use symbolic trace to collect concrete trace from QEMU
    conc_states, matched_transforms = collect_conc_trace(
        GDBServerStateIterator(gdbserver_addr, gdbserver_port),
        symb_transforms)

    # Verify and print result
    if not args.quiet:
        res = compare_symbolic(conc_states, matched_transforms)
        print_result(res, verbosity[args.error_level])

    if args.output:
        from focaccia.parser import serialize_snapshots
        with open(args.output, 'w') as file:
            serialize_snapshots(conc_states, file)

if __name__ == "__main__":
    main()
