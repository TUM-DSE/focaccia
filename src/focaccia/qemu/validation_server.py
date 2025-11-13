#! /usr/bin/env python3

import os
import socket
import struct
import logging
from typing import Iterable

import focaccia.parser as parser
from focaccia.arch import supported_architectures, Arch
from focaccia.compare import compare_symbolic, ErrorTypes
from focaccia.snapshot import ProgramState, RegisterAccessError, MemoryAccessError
from focaccia.symbolic import SymbolicTransform, eval_symbol, ExprMem
from focaccia.trace import Trace
from focaccia.utils import print_result


logger = logging.getLogger('focaccia-qemu-validation-server')
debug = logger.debug
info = logger.info
warn = logger.warning


def endian_fmt(endianness: str) -> str:
    if endianness == 'little':
        return '<'
    else:
        return '>'

def mk_command(cmd: str, endianness: str, reg: str="", addr: int=0, size: int=0) -> bytes:
    # char[16]:regname | long long:addr long long:size | long long:unused
    # READ REG         | READ MEM                      | STEP ONE

    if cmd == 'read register':
        fmt = f'{endian_fmt(endianness)}16s9s'
        return struct.pack(fmt,reg.encode('utf-8'),"READ REG".encode('utf-8'))
    elif cmd == 'read memory':
        fmt = f'{endian_fmt(endianness)}QQ9s'
        return struct.pack(fmt, addr, size, "READ MEM".encode('utf-8'))
    elif cmd == 'step':
        fmt = f'{endian_fmt(endianness)}qq9s'
        return struct.pack(fmt, 0, 0, "STEP ONE".encode('utf-8'))
    else:
        raise ValueError(f'Unknown command {cmd}')
def unmk_memory(msg: bytes, endianness: str) -> tuple:
    # packed!
    # unsigned long long: addr
    # unsigned long: length
    fmt = f'{endian_fmt(endianness)}QQ'
    addr, length = struct.unpack(fmt, msg)

    return addr, length

def unmk_register(msg: bytes, endianness: str) -> tuple:
    # packed!
    # char[108]:regname | unsigned long:bytes | char[64]:value
    fmt = f'{endian_fmt(endianness)}108sQ64s'
    reg_name, size, val = struct.unpack(fmt, msg)
    reg_name = reg_name.decode('utf-8').rstrip('\x00')

    if reg_name == "UNKNOWN":
        raise RegisterAccessError(reg_name,
                                  f'[QEMU Plugin] Unable to access register {reg_name}.')

    val = val[:size]
    val = int.from_bytes(val, endianness)
    return val, size

class PluginProgramState(ProgramState):
    from focaccia.arch import aarch64, x86

    flag_register_names = {
        aarch64.archname: 'cpsr',
        x86.archname: 'eflags',
    }

    flag_register_decompose = {
        aarch64.archname: aarch64.decompose_cpsr,
        x86.archname: x86.decompose_rflags,
    }

    def _flush_caches(self):
        for r in self.regs.keys():
            self.regs[r] = None
        self.mem.drop_all()


    def __init__(self, arch: Arch):
        super().__init__(arch)
        self.strict = False

    def read_register(self, reg: str, no_cached: bool=False) -> int:
        global CONN

        if reg == 'RFLAGS':
            reg = 'EFLAGS'

        flags = self.flag_register_decompose[self.arch.archname](0).keys()
        if reg in flags and self.arch.archname in self.flag_register_names:
            reg_name = self.flag_register_names[self.arch.archname]
        else:
            reg_name = self.arch.to_regname(reg)

        if reg_name is None:
            raise RegisterAccessError(reg, f'Not a register name: {reg}')

        reg_acc = self.arch.get_reg_accessor(reg_name)
        if reg_acc is None:
            raise RegisterAccessError(reg, f'Not a enclosing register name: {reg}')
            exit(-1)
        reg_name = reg_acc.base_reg.lower()

        val = None
        from_cache = False
        if not no_cached and super().test_register(reg_name):
            val = super().read_register(reg_name)
            from_cache = True
        else:
            msg = mk_command("read register", self.arch.endianness, reg=reg_name)
            CONN.send(msg)

            try:
                resp = CONN.recv(180)
            except ConnectionResetError:
                raise StopIteration

            if len(resp) < 180:
                raise RegisterAccessError(reg, f'Invalid response length when reading {reg}: {len(resp)}'
                                          f' for response {resp}')

            val, size = unmk_register(resp, self.arch.endianness)

        # Try to access the flags register with `reg` as a logical flag name
        if reg in flags and self.arch.archname in self.flag_register_names:
            flags_reg = self.flag_register_names[self.arch.archname]
            _flags = self.flag_register_decompose[self.arch.archname](val)
            if reg in _flags:
                if not from_cache:
                    self.set_register(reg, _flags[reg])
                return _flags[reg]
            raise RegisterAccessError(f'Unable to access flag {reg}.')

        if not from_cache:
            self.set_register(reg, val)
        return val & reg_acc.mask >> reg_acc.start

    def read_memory(self, addr: int, size: int) -> bytes:
        global CONN

        if self.mem.test(addr):
            return super().read_memory(addr, size)

        # print(f'Reading memory at {addr:x}, size={size}')

        msg = mk_command("read memory", self.arch.endianness, addr=addr, size=size)
        CONN.send(msg)

        try:
            resp = CONN.recv(16)
        except ConnectionResetError:
            raise StopIteration
        _addr, length = unmk_memory(resp, self.arch.endianness)

        if _addr != addr or length == 0:
            raise MemoryAccessError(
                _addr, size,
                f'Unable to access memory at address {addr:x}, size={size}.')
            return b''

        mem = b''
        while len(mem) < length:
            try:
                resp = CONN.recv(length - len(mem))
            except ConnectionResetError:
                raise StopIteration
            mem += resp

        self.write_memory(addr, mem)
        return mem

    def step(self):
        global CONN

        self._flush_caches()
        msg = mk_command("step", self.arch.endianness)
        CONN.send(msg)


        return

class PluginStateIterator:

    def __init__(self, sock_path: str, arch: Arch):
        global SOCK
        global CONN

        self.sock_path = sock_path
        self.arch = arch
        self._first_next = True


        # Start the server that waits for QEMU to connect
        try:
            os.unlink(self.sock_path)
        except FileNotFoundError:
            pass
        # TODO: allow new connections when QEMU clones
        SOCK = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        print(f'Listening for QEMU Plugin connection at {self.sock_path}...')
        SOCK.bind(self.sock_path)
        SOCK.listen(1)

        CONN, qemu_addr = SOCK.accept()

        # Handshake with QEMU
        pid_b = CONN.recv(4)
        pid = struct.unpack('i', pid_b)[0]
        print(f'Connected to QEMU instance with PID {pid}.')

    def __iter__(self):
        return self

    def __next__(self):
        # The first call to __next__ should yield the first program state,
        # i.e. after stepping the first time
        if self._first_next:
            self._first_next = False
            self.state = PluginProgramState(self.arch)
            #self.state.step()
            return self.state

        # Step
        pc = self.state.read_register('pc')
        new_pc = pc
        while pc == new_pc:  # Skip instruction chains from REP STOS etc.
            self.state.step()
            new_pc = self.state.read_register('pc', True)

        return self.state

def record_minimal_snapshot(prev_state: ProgramState,
                            cur_state: PluginProgramState,
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
                           leading to, `cur_state`. Values generated by
                           this transformation are included in the
                           snapshot.
    :param transform: The symbolic transformation operating on this
                      snapshot. Input values to this transformation are
                      included in the snapshot.
    """
    assert(cur_state.read_register('pc') == cur_transform.addr)
    assert(prev_transform.arch == cur_transform.arch)

    def get_written_addresses(t: SymbolicTransform) -> Iterable[ExprMem]:
        """Get all output memory accesses of a symbolic transformation."""
        return [ExprMem(a, v.size) for a, v in t.changed_mem.items()]

    def set_values(regs: Iterable[str], mems: Iterable[ExprMem],
                   cur_state: PluginProgramState,
                   prev_state: PluginProgramState,
                   out_state: ProgramState):
        """
        :param prev_state: Addresses of memory included in the snapshot are
                           resolved relative to this state.
        """
        for regname in regs:
            try:
                regval = cur_state.read_register(regname)
                out_state.set_register(regname, regval)
            except RegisterAccessError:
                out_state.set_register(regname, 0)
        for mem in mems:
            assert(mem.size % 8 == 0)
            addr = eval_symbol(mem.ptr, prev_state)
            try:
                mem = cur_state.read_memory(addr, int(mem.size / 8))
                out_state.write_memory(addr, mem)
            except MemoryAccessError:
                pass

    state = ProgramState(cur_transform.arch)
    state.set_register('pc', cur_transform.addr)

    set_values(prev_transform.changed_regs.keys(),
               get_written_addresses(prev_transform),
               cur_state,
               prev_state,
               state)
    set_values(cur_transform.get_used_registers(),
               cur_transform.get_used_memory_addresses(),
               cur_state,
               cur_state,
               state)
    return state

def collect_conc_trace(qemu: PluginStateIterator, \
                       strace: list[SymbolicTransform]) \
        -> tuple[list[ProgramState], list[SymbolicTransform]]:
    """Collect a trace of concrete states from QEMU.

    Records minimal concrete states from QEMU by using symbolic trace
    information to determine which register/memory values are required to
    verify the correctness of QEMU.

    May drop symbolic transformations if the symbolic trace and the QEMU trace
    diverge (e.g. because of differences in environment, etc.). Returns the
    new, possibly modified, symbolic trace that matches the returned concrete
    trace.

    :return: A list of concrete states and a list of corresponding symbolic
             transformations. The lists are guaranteed to have the same length.
    """
    def find_index(seq, target, access=lambda el: el):
        for i, el in enumerate(seq):
            if access(el) == target:
                return i
        return None

    if not strace:
        return [], []

    states = []
    matched_transforms = []

    state_iter = iter(qemu)
    cur_state = next(state_iter)
    symb_i = 0

    # An online trace matching algorithm.
    while True:
        try:
            pc = cur_state.read_register('pc')

            while pc != strace[symb_i].addr:
                next_i = find_index(strace[symb_i+1:], pc, lambda t: t.addr)

                # Drop the concrete state if no address in the symbolic trace
                # matches
                if next_i is None:
                    print(f'Warning: Dropping concrete state {hex(pc)}, as no'
                          f' matching instruction can be found in the symbolic'
                          f' reference trace.')
                    cur_state = next(state_iter)
                    pc = cur_state.read_register('pc', True)
                    continue

                # Otherwise, jump to the next matching symbolic state
                symb_i += next_i + 1

            assert(cur_state.read_register('pc') == strace[symb_i].addr)
            states.append(record_minimal_snapshot(
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


def start_validation_server(symb_trace: str,
                            output: str,
                            socket: str,
                            guest_arch: str,
                            env,
                            verbosity: ErrorTypes,
                            is_quiet: bool = False):
    # Read pre-computed symbolic trace
    with open(symb_trace, 'r') as strace:
        symb_transforms = parser.parse_transformations(strace)

    arch = supported_architectures.get(guest_arch)

    qemu = PluginStateIterator(socket, arch)

    # Use symbolic trace to collect concrete trace from QEMU
    conc_states, matched_transforms = collect_conc_trace(
        qemu,
        symb_transforms.states)

    # Verify and print result
    if not is_quiet:
        res = compare_symbolic(conc_states, matched_transforms)
        print_result(res, verbosity)

    if output:
        from focaccia.parser import serialize_snapshots
        with open(output, 'w') as file:
            serialize_snapshots(Trace(conc_states, env), file)

