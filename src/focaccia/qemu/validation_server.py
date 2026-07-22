#! /usr/bin/env python3

import os
import socket
import struct
import logging
from collections.abc import Iterable

import focaccia.parser as parser
from focaccia.arch import supported_architectures, Arch
from focaccia.compare import compare_symbolic, ErrorTypes
from focaccia.match import MatchResult, TransitionMatcher
from focaccia.snapshot import ProgramState, RegisterAccessError, MemoryAccessError
from focaccia.symbolic import SymbolicTransform, eval_symbol, ExprMem
from focaccia.trace import MaterializedTrace, TraceEnvironment, TransformStream
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
        self.drop_registers()
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
                    self.write_register(reg, _flags[reg])
                return _flags[reg]
            raise RegisterAccessError(f'Unable to access flag {reg}.')

        if not from_cache:
            self.write_register(reg, val)
        return val & reg_acc.mask >> reg_acc.start

    def read_memory(self, addr: int, size: int) -> bytes:
        global CONN

        if self.mem.test(addr, size):
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

def record_minimal_snapshot(
    previous_state: ProgramState,
    current_state: ProgramState,
    incoming: SymbolicTransform | None,
    outgoing: SymbolicTransform | None,
) -> ProgramState:
    """Record inputs/outputs needed on either side of one retained boundary."""
    boundary_transform = incoming if incoming is not None else outgoing
    architecture = (
        boundary_transform.arch
        if boundary_transform is not None
        else current_state.arch
    )
    snapshot = ProgramState(architecture)
    snapshot.write_register("PC", current_state.read_pc())

    def written_memory(transform: SymbolicTransform) -> Iterable[ExprMem]:
        return [
            ExprMem(address, value.size)
            for address, value in transform.changed_mem.items()
        ]

    def copy_values(
        registers: Iterable[str],
        memory: Iterable[ExprMem],
        address_state: ProgramState,
    ) -> None:
        for register in registers:
            try:
                snapshot.write_register(register, current_state.read_register(register))
            except RegisterAccessError:
                pass
        for expression in memory:
            if expression.size % 8 != 0:
                raise ValueError(f"Non-byte memory expression width: {expression.size}.")
            address = eval_symbol(expression.ptr, address_state)
            try:
                data = current_state.read_memory(address, expression.size // 8)
            except MemoryAccessError:
                continue
            snapshot.write_memory(address, data)

    if incoming is not None:
        copy_values(
            incoming.changed_regs.keys(),
            written_memory(incoming),
            previous_state,
        )
    if outgoing is not None:
        copy_values(
            outgoing.get_used_registers(),
            outgoing.get_used_memory_addresses(),
            current_state,
        )
    return snapshot

def collect_conc_trace(
    qemu: Iterable[ProgramState],
    strace: MaterializedTrace[SymbolicTransform] | TransformStream[SymbolicTransform],
) -> MatchResult:
    """Collect a cardinality-valid concrete transition trace from the plugin."""
    matcher = TransitionMatcher(strace)
    retained_states: list[ProgramState] = []
    retained_transforms: list[SymbolicTransform] = []
    state_iterator = iter(qemu)

    while not matcher.done:
        try:
            current_state = next(state_iterator)
            pc = current_state.read_pc()
        except StopIteration:
            break
        except RegisterAccessError as error:
            matcher.fail_concrete_state(len(retained_states), error)
            break

        boundary = matcher.observe(pc)
        if boundary is None:
            continue
        previous_state = retained_states[-1] if retained_states else current_state
        snapshot = record_minimal_snapshot(
            previous_state,
            current_state,
            boundary.incoming,
            boundary.outgoing,
        )
        if boundary.incoming is not None:
            retained_transforms.append(boundary.incoming)
        retained_states.append(snapshot)

    return matcher.make_result(retained_states, retained_transforms)


def start_validation_server(symb_trace: str,
                            output: str,
                            socket: str,
                            guest_arch: str,
                            env: TraceEnvironment,
                            verbosity: ErrorTypes,
                            is_quiet: bool = False):
    # Read pre-computed symbolic trace
    with open(symb_trace, 'r') as strace:
        symb_transforms = parser.parse_transformations(strace)

    arch = supported_architectures.get(guest_arch)

    qemu = PluginStateIterator(socket, arch)

    # Use symbolic trace to collect concrete trace from QEMU
    matched = collect_conc_trace(qemu, symb_transforms)

    # Verify and print result
    if not is_quiet:
        report = compare_symbolic(
            matched.trace,
            diagnostics=matched.diagnostics,
        )
        print_result(report, verbosity)

    if output:
        from focaccia.parser import serialize_snapshots

        states = matched.trace.state_boundaries if matched.trace is not None else ()
        with open(output, 'w') as file:
            serialize_snapshots(MaterializedTrace(states, env), file)

