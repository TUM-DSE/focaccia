"""Tools and utilities for  execution with Miasm."""

from __future__ import annotations

import sys
import logging

from pathlib import Path

from miasm.analysis.machine import Machine
from miasm.core.cpu import instruction as miasm_instr
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import Expr, ExprId, ExprMem, ExprInt
from miasm.ir.ir import Lifter
from miasm.ir.symbexec import SymbolicExecutionEngine

from .arch import Arch, supported_architectures
from .lldb_target import (
    LLDBConcreteTarget,
    LLDBLocalTarget,
    LLDBRemoteTarget,
    ConcreteRegisterError,
    ConcreteMemoryError,
)
from .miasm_util import MiasmSymbolResolver, eval_expr, make_machine
from .snapshot import ReadableProgramState, RegisterAccessError, MemoryAccessError
from .trace import Trace, TraceEnvironment
from .utils import timebound, TimeoutError
from .deterministic import DeterministicEventIterator

logger = logging.getLogger('focaccia-symbolic')
debug = logger.debug
info = logger.info
warn = logger.warn

# Disable Miasm's disassembly logger
logging.getLogger('asmblock').setLevel(logging.CRITICAL)

class ValidationError(Exception):
    pass

def eval_symbol(symbol: Expr, conc_state: ReadableProgramState) -> int:
    """Evaluate a symbol based on a concrete reference state.

    :param conc_state: A concrete state.
    :return: The resolved value.

    :raise ValueError: If the concrete state does not contain a register value
                       that is referenced by the symbolic expression.
    :raise MemoryAccessError: If the concrete state does not contain memory
                              that is referenced by the symbolic expression.
    """
    class ConcreteStateWrapper(MiasmSymbolResolver):
        """Extend the state resolver with assumptions about the expressions
        that may be resolved with `eval_symbol`."""
        def __init__(self, conc_state: ReadableProgramState):
            super().__init__(conc_state, LocationDB())

        def resolve_register(self, regname: str) -> int:
            return self._state.read_register(self._miasm_to_regname(regname))

        def resolve_memory(self, addr: int, size: int) -> bytes:
            return self._state.read_memory(addr, size)

        def resolve_location(self, loc):
            raise ValueError('[In eval_symbol]: Unable to evaluate symbols'
                             ' that contain IR location expressions.')

    res = eval_expr(symbol, ConcreteStateWrapper(conc_state))

    # Must be either ExprInt or ExprLoc,
    # but ExprLocs are disallowed by the
    # ConcreteStateWrapper
    if not isinstance(res, ExprInt):
        raise Exception(f'{res} from symbol {symbol} is not an instance of ExprInt'
                        f' but only ExprInt can be evaluated')
    return int(res)

class Instruction:
    """An instruction."""
    def __init__(self,
                 instr: miasm_instr,
                 machine: Machine,
                 arch: Arch,
                 loc_db: LocationDB | None = None):
        self.arch = arch
        self.machine = machine

        if loc_db is not None:
            instr.args = instr.resolve_args_with_symbols(loc_db)
        self.instr: miasm_instr = instr
        """The underlying Miasm instruction object."""

        assert(instr.offset is not None)
        assert(instr.l is not None)
        self.addr: int = instr.offset
        self.length: int = instr.l

    @staticmethod
    def from_bytecode(asm: bytes, arch: Arch) -> Instruction:
        """Disassemble an instruction."""
        machine = make_machine(arch)
        assert(machine.mn is not None)
        _instr = machine.mn.dis(asm, arch.ptr_size)
        return Instruction(_instr, machine, arch, None)

    @staticmethod
    def from_string(s: str, arch: Arch, offset: int = 0, length: int = 0) -> Instruction:
        machine = make_machine(arch)
        assert(machine.mn is not None)
        _instr = machine.mn.fromstring(s, LocationDB(), arch.ptr_size)
        _instr.offset = offset
        _instr.l = length
        return Instruction(_instr, machine, arch, None)

    def to_bytecode(self) -> bytes:
        """Assemble the instruction to byte code."""
        assert(self.machine.mn is not None)
        return self.machine.mn.asm(self.instr)[0]

    def to_string(self) -> str:
        """Convert the instruction to an Intel-syntax assembly string."""
        return str(self.instr)

    def __repr__(self):
        return self.to_string()

class SymbolicTransform:
    """A symbolic transformation mapping one program state to another."""
    def __init__(self,
                 tid: int, 
                 transform: dict[Expr, Expr],
                 instrs: list[Instruction],
                 arch: Arch,
                 from_addr: int,
                 to_addr: int):
        """
        :param tid: The thread ID that executed the instructions effecting the transformation.
        :param transform: A map of input symbolic expressions and output symbolic expressions.
        :param instrs: A list of instructions. The transformation
                       represents the collective modifications to the program state
                       performed by these instructions.
        :param arch: The architecture of the symbolic transformation.
        :param from_addr: The starting address of the instruction effecting the symbolic
                          transformation.
        :param to_addr: The final address of the last instruction in the instructions list.
        """
        self.tid = tid
        self.arch = arch

        self.addr = from_addr
        """The instruction address of the program state on which the
        transformation operates. Equivalent to `self.range[0]`."""

        self.range = (from_addr, to_addr)
        """The range of addresses that the transformation covers.
        The transformation `t` maps the program state at instruction
        `t.range[0]` to the program state at instruction `t.range[1]`."""

        self.changed_regs: dict[str, Expr] = {}
        """Maps register names to expressions for the register's content.

        Contains only registers that are changed by the transformation.
        Register names are already normalized to a respective architecture's
        naming conventions."""

        self.changed_mem: dict[Expr, Expr] = {}
        """Maps memory addresses to memory content.

        For a dict tuple `(addr, value)`, `value.size` is the number of *bits*
        written to address `addr`. Memory addresses may depend on other
        symbolic values, such as register content, and are therefore symbolic
        themselves."""

        self.instructions: list[Instruction] = instrs
        """The sequence of instructions that comprise this transformation."""

        for dst, expr in transform.items():
            assert(isinstance(dst, ExprMem) or isinstance(dst, ExprId))

            if isinstance(dst, ExprMem):
                assert(dst.size == expr.size)
                assert(expr.size % 8 == 0)
                self.changed_mem[dst.ptr] = expr
            else:
                assert(isinstance(dst, ExprId))
                regname = arch.to_regname(dst.name)
                if regname is not None:
                    self.changed_regs[regname] = expr

    def concat(self, other: SymbolicTransform) -> SymbolicTransform:
        """Concatenate two transformations.

        The symbolic transform on which `concat` is called is the transform
        that is applied first, meaning: `(a.concat(b))(state) == b(a(state))`.

        Note that if transformation are concatenated that write to the same
        memory location when applied to a specific starting state, the
        concatenation may not recognize equivalence of syntactically different
        symbolic address expressions. In this case, if you calculate all memory
        values and store them at their address, the final result will depend on
        the random iteration order over the `changed_mem` dict.

        :param other: The transformation to concatenate to `self`.

        :return: Returns `self`. `self` is modified in-place.
        :raise ValueError: If the two transformations don't span a contiguous
                           range of instructions.
        """
        from typing import Callable
        from miasm.expression.expression import ExprLoc, ExprSlice, ExprCond, \
                                                ExprOp, ExprCompose
        from miasm.expression.simplifications import expr_simp_explicit

        if self.range[1] != other.range[0]:
            repr_range = lambda r: f'[{hex(r[0])} -> {hex(r[1])}]'
            raise ValueError(
                f'Unable to concatenate transformation'
                f' {repr_range(self.range)} with {repr_range(other.range)};'
                f' the concatenated transformations must span a'
                f' contiguous range of instructions.')

        def _eval_exprslice(expr: ExprSlice):
            arg = _concat_to_self(expr.arg)
            return ExprSlice(arg, expr.start, expr.stop)

        def _eval_exprcond(expr: ExprCond):
            cond = _concat_to_self(expr.cond)
            src1 = _concat_to_self(expr.src1)
            src2 = _concat_to_self(expr.src2)
            return ExprCond(cond, src1, src2)

        def _eval_exprop(expr: ExprOp):
            args = [_concat_to_self(arg) for arg in expr.args]
            return ExprOp(expr.op, *args)

        def _eval_exprcompose(expr: ExprCompose):
            args = [_concat_to_self(arg) for arg in expr.args]
            return ExprCompose(*args)

        expr_to_visitor: dict[type[Expr], Callable] = {
            ExprInt:     lambda e: e,
            ExprId:      lambda e: self.changed_regs.get(e.name, e),
            ExprLoc:     lambda e: e,
            ExprMem:     lambda e: ExprMem(_concat_to_self(e.ptr), e.size),
            ExprSlice:   _eval_exprslice,
            ExprCond:    _eval_exprcond,
            ExprOp:      _eval_exprop,
            ExprCompose: _eval_exprcompose,
        }

        def _concat_to_self(expr: Expr):
            visitor = expr_to_visitor[expr.__class__]
            return expr_simp_explicit(visitor(expr))

        new_regs = self.changed_regs.copy()
        for reg, expr in other.changed_regs.items():
            new_regs[reg] = _concat_to_self(expr)

        new_mem = self.changed_mem.copy()
        for addr, expr in other.changed_mem.items():
            new_addr = _concat_to_self(addr)
            new_expr = _concat_to_self(expr)
            new_mem[new_addr] = new_expr

        self.changed_regs = new_regs
        self.changed_mem = new_mem
        self.range = (self.range[0], other.range[1])
        self.instructions.extend(other.instructions)

        return self

    def get_used_registers(self) -> list[str]:
        """Find all registers used by the transformation as input.

        :return: A list of register names.
        """
        accessed_regs = set[str]()

        class RegisterCollector(MiasmSymbolResolver):
            def __init__(self, arch: Arch):
                self._arch = arch  # MiasmSymbolResolver needs this
            def resolve_register(self, regname: str) -> int | None:
                accessed_regs.add(self._miasm_to_regname(regname))
                return None
            def resolve_memory(self, addr: int, size: int): pass
            def resolve_location(self, loc): assert(False)

        resolver = RegisterCollector(self.arch)
        for expr in self.changed_regs.values():
            eval_expr(expr, resolver)
        for addr_expr, mem_expr in self.changed_mem.items():
            eval_expr(addr_expr, resolver)
            eval_expr(mem_expr, resolver)

        return list(accessed_regs)

    def get_used_memory_addresses(self) -> list[ExprMem]:
        """Find all memory addresses used by the transformation as input.

        :return: A list of memory access expressions.
        """
        from typing import Callable
        from miasm.expression.expression import ExprLoc, ExprSlice, ExprCond, \
                                                ExprOp, ExprCompose

        accessed_mem = set[ExprMem]()

        def _eval(expr: Expr):
            def _eval_exprmem(expr: ExprMem):
                accessed_mem.add(expr)  # <-- this is the only important line!
                _eval(expr.ptr)
            def _eval_exprcond(expr: ExprCond):
                _eval(expr.cond)
                _eval(expr.src1)
                _eval(expr.src2)
            def _eval_exprop(expr: ExprOp):
                for arg in expr.args:
                    _eval(arg)
            def _eval_exprcompose(expr: ExprCompose):
                for arg in expr.args:
                    _eval(arg)

            expr_to_visitor: dict[type[Expr], Callable] = {
                ExprInt:     lambda e: e,
                ExprId:      lambda e: e,
                ExprLoc:     lambda e: e,
                ExprMem:     _eval_exprmem,
                ExprSlice:   lambda e: _eval(e.arg),
                ExprCond:    _eval_exprcond,
                ExprOp:      _eval_exprop,
                ExprCompose: _eval_exprcompose,
            }
            visitor = expr_to_visitor[expr.__class__]
            visitor(expr)

        for expr in self.changed_regs.values():
            _eval(expr)
        for addr_expr, mem_expr in self.changed_mem.items():
            _eval(addr_expr)
            _eval(mem_expr)

        return list(accessed_mem)

    def eval_register_transforms(self, conc_state: ReadableProgramState) \
            -> dict[str, int]:
        """Calculate register transformations when applied to a concrete state.

        :param conc_state: A concrete program state that serves as the input
                           state on which the transformation operates.

        :return: A map from register names to the register values that were
                 changed by the transformation.
        :raise MemoryError:
        :raise ValueError:
        """
        res = {}
        for regname, expr in self.changed_regs.items():
            if not conc_state.strict and regname.upper() in self.arch.ignored_regs:
                continue
            res[regname] = eval_symbol(expr, conc_state)
        return res

    def eval_memory_transforms(self, conc_state: ReadableProgramState) \
            -> dict[int, bytes]:
        """Calculate memory transformations when applied to a concrete state.

        :param conc_state: A concrete program state that serves as the input
                           state on which the transformation operates.

        :return: A map from memory addresses to the bytes that were changed by
                 the transformation.
        :raise MemoryError:
        :raise ValueError:
        """
        res = {}
        for addr, expr in self.changed_mem.items():
            addr = eval_symbol(addr, conc_state)
            length = int(expr.size / 8)
            res[addr] = eval_symbol(expr, conc_state) \
                        .to_bytes(length, byteorder=self.arch.endianness)
        return res

    @classmethod
    def from_json(cls, data: dict) -> SymbolicTransform:
        """Parse a symbolic transformation from a JSON object.

        :raise KeyError: if a parse error occurs.
        """
        from miasm.expression.parser import str_to_expr as parse

        def decode_inst(obj: list, arch: Arch):
            length, text = obj
            try:
                return Instruction.from_string(text, arch, offset=0, length=length)
            except Exception as err:
                # Note: from None disables chaining in traceback
                raise ValueError(f'[In SymbolicTransform.from_json] Unable to parse'
                                 f' instruction string "{text}": {err}.') from None

        tid = int(data['tid'])
        arch = supported_architectures[data['arch']]
        start_addr = int(data['from_addr'])
        end_addr = int(data['to_addr'])

        t = SymbolicTransform(tid, {}, [], arch, start_addr, end_addr)
        t.changed_regs = { name: parse(val) for name, val in data['regs'].items() }
        t.changed_mem = { parse(addr): parse(val) for addr, val in data['mem'].items() }
        instrs = [decode_inst(b, arch) for b in data['instructions']]
        t.instructions = [inst for inst in instrs if inst is not None]

        # Recover the instructions' address information
        addr = t.addr
        for inst in t.instructions:
            inst.addr = addr
            addr += inst.length

        return t

    def to_json(self) -> dict:
        """Serialize a symbolic transformation as a JSON object."""
        def encode_inst(inst: Instruction):
            try:
                return [inst.length, inst.to_string()]
            except Exception as err:
                # Note: from None disables chaining in traceback
                raise Exception(f'[In SymbolicTransform.to_json] Unable to serialize'
                                f' "{inst}" as string: {err}') from None

        instrs = [encode_inst(inst) for inst in self.instructions]
        instrs = [inst for inst in instrs if inst is not None]
        return {
            'arch': self.arch.archname,
            'tid': self.tid,
            'from_addr': self.range[0],
            'to_addr': self.range[1],
            'instructions': instrs,
            'regs': { name: repr(expr) for name, expr in self.changed_regs.items() },
            'mem': { repr(addr): repr(val) for addr, val in self.changed_mem.items() },
        }

    def __repr__(self) -> str:
        start, end = self.range
        res = f'Symbolic state transformation [{self.tid}] {start} -> {end}:\n'
        res += '  [Symbols]\n'
        for reg, expr in self.changed_regs.items():
            res += f'    {reg:6s} = {expr}\n'
        for addr, expr in self.changed_mem.items():
            res += f'    {ExprMem(addr, expr.size)} = {expr}\n'
        res += '  [Instructions]\n'
        for inst in self.instructions:
            res += f'    {inst}\n'

        return res[:-1]  # Remove trailing newline

class MemoryBinstream:
    """A binary stream interface that reads bytes from a program state's
    memory."""
    def __init__(self, state: ReadableProgramState):
        self._state = state

    def __len__(self):
        return 0xffffffff

    def __getitem__(self, key: int | slice):
        if isinstance(key, slice):
            return self._state.read_instructions(key.start, key.stop - key.start)
        return self._state.read_instructions(key, 1)

class DisassemblyContext:
    def __init__(self, target: ReadableProgramState):
        self.loc_db = LocationDB()

        # Determine the binary's architecture
        self.machine = make_machine(target.arch)
        self.arch = target.arch

        # Create disassembly/lifting context
        assert(self.machine.dis_engine is not None)
        binstream = MemoryBinstream(target)
        self.mdis = self.machine.dis_engine(binstream, loc_db=self.loc_db)
        self.mdis.follow_call = True
        self.lifter = self.machine.lifter(self.loc_db)

    def disassemble(self, address: int) -> Instruction:
        miasm_instr = self.mdis.dis_instr(address)
        return Instruction(miasm_instr, self.machine, self.arch, self.loc_db)

def run_instruction(instr: miasm_instr,
                    conc_state: MiasmSymbolResolver,
                    lifter: Lifter,
                    force: bool = False) \
        -> tuple[ExprInt | None, dict[Expr, Expr]]:
    """Compute the symbolic equation of a single instruction.

    The concolic engine tries to express the instruction's equation as
    independent of the concrete state as possible.

    May fail if the instruction is not supported. Failure is signalled by
    returning `None` as the next program counter.

    :param instr:      The instruction to run.
    :param conc_state: A concrete reference state at `pc = instr.offset`. Used
                       to resolve symbolic program counters, i.e. to 'guide'
                       the symbolic execution on the correct path. This is the
                       concrete part of our concolic execution.
    :param lifter:     A lifter of the appropriate architecture. Get this from
                       a `DisassemblyContext` or a `Machine`.

    :return: The next program counter and a symbolic state. The PC is None if
             an error occurs or when the program exits. The returned state
             is `instr`'s symbolic transformation.
    """
    from miasm.expression.expression import ExprCond, LocKey
    from miasm.expression.simplifications import expr_simp

    def create_cond_state(cond: Expr, iftrue: dict, iffalse: dict) -> dict:
        """Combines states that are to be reached conditionally.

        Example:
            State A:
                RAX          = 0x42
                @[RBP - 0x4] = 0x123
            State B:
                RDI          = -0x777
                @[RBP - 0x4] = 0x5c32
            Condition:
                RCX > 0x4 ? A : B

            Result State:
                RAX          = (RCX > 0x4) ? 0x42 : RAX
                RDI          = (RCX > 0x4) ? RDI : -0x777
                @[RBP - 0x4] = (RCX > 0x4) ? 0x123 : 0x5c32
        """
        res = {}
        for dst, v in iftrue.items():
            if dst not in iffalse:
                res[dst] = expr_simp(ExprCond(cond, v, dst))
            else:
                res[dst] = expr_simp(ExprCond(cond, v, iffalse[dst]))
        for dst, v in iffalse.items():
            if dst not in iftrue:
                res[dst] = expr_simp(ExprCond(cond, dst, v))
        return res

    def _execute_location(loc, base_state: dict | None) \
            -> tuple[Expr, dict]:
        """Execute a single IR block via symbolic engine. No fancy stuff."""
        # Query the location's IR block
        irblock = ircfg.get_block(loc)
        if irblock is None:
            return loc, base_state if base_state is not None else {}

        # Apply IR block to the current state
        engine = SymbolicExecutionEngine(lifter, state=base_state)
        new_pc = engine.eval_updt_irblock(irblock)
        modified = dict(engine.modified())
        return new_pc, modified

    def execute_location(loc: Expr | LocKey) -> tuple[ExprInt, dict]:
        """Execute chains of IR blocks until a concrete program counter is
        reached."""
        seen_locs = set()  # To break out of loop instructions
        new_pc, modified = _execute_location(loc, None)

        # Run chained IR blocks until a real program counter is reached.
        # This used to be recursive (and much more elegant), but large RCX
        # values for 'REP ...' instructions could make the stack overflow.
        while not new_pc.is_int():
            seen_locs.add(new_pc)

            if new_pc.is_loc():
                # Jump to the next location.
                new_pc, modified = _execute_location(new_pc, modified)
            elif new_pc.is_cond():
                # Explore conditional paths manually by constructing
                # conditional states based on the possible outcomes.
                assert(isinstance(new_pc, ExprCond))
                cond = new_pc.cond
                pc_iftrue, pc_iffalse = new_pc.src1, new_pc.src2

                pc_t, state_t = _execute_location(pc_iftrue, modified.copy())
                pc_f, state_f = _execute_location(pc_iffalse, modified.copy())
                modified = create_cond_state(cond, state_t, state_f)
                new_pc = expr_simp(ExprCond(cond, pc_t, pc_f))
            else:
                # Concretisize PC in case it is, e.g., a memory expression
                new_pc = eval_expr(new_pc, conc_state)

            # Avoid infinite loops for loop instructions (REP ...) by making
            # the jump to the next loop iteration (or exit) concrete.
            if new_pc in seen_locs:
                new_pc = eval_expr(new_pc, conc_state)
                seen_locs.clear()

        assert(isinstance(new_pc, ExprInt))
        return new_pc, modified

    # Lift instruction to IR
    ircfg = lifter.new_ircfg()
    try:
        loc = lifter.add_instr_to_ircfg(instr, ircfg, None, False)
        assert(isinstance(loc, Expr) or isinstance(loc, LocKey))
    except NotImplementedError as err:
        msg = f'Unable to lift instruction {instr}: {err}'
        if force:
            warn(f'{msg}. Skipping')
            return None, {}
        else:
            raise Exception(msg)

    # Execute instruction symbolically
    new_pc, modified = execute_location(loc)
    modified[lifter.pc] = new_pc  # Add PC update to state

    return new_pc, modified

class SpeculativeTracer(ReadableProgramState):
    def __init__(self, target: LLDBConcreteTarget):
        super().__init__(target.arch)
        self.target = target
        self.pc = target.read_register('pc')
        self.speculative_pc: int | None = None
        self.speculative_count: int = 0
        
        self.read_cache = {}

    def speculate(self, new_pc):
        self.read_cache.clear()
        if new_pc is None:
            self.progress_execution()
            self.target.step()
            self.pc = self.target.read_register('pc')
            self.speculative_pc = None
            self.speculative_count = 0
            return

        new_pc = int(new_pc)
        self.speculative_pc = new_pc
        self.speculative_count += 1

    def progress_execution(self) -> None:
        if self.speculative_pc is not None and self.speculative_count != 0:
            debug(f'Updating PC to {hex(self.speculative_pc)}')
            if self.speculative_count == 1:
                self.target.step()
            else:
                self.target.run_until(self.speculative_pc)

            self.pc = self.speculative_pc
            self.speculative_pc = None
            self.speculative_count = 0

            self.read_cache.clear()

    def run_until(self, addr: int):
        if self.speculative_pc:
            raise Exception('Attempting manual execution with speculative execution enabled')
        self.target.run_until(addr)
        self.pc = addr

    def step(self):
        self.progress_execution()
        if self.target.is_exited():
            return
        self.target.step()
        self.pc = self.target.read_register('pc')

    def _cache(self, name: str, value):
        self.read_cache[name] = value
        return value

    def read_pc(self) -> int:
        if self.speculative_pc is not None:
            return self.speculative_pc
        return self.pc

    def read_flags(self) -> dict[str, int | bool]:
        if 'flags' in self.read_cache:
            return self.read_cache['flags']
        self.progress_execution()
        return self._cache('flags', self.target.read_flags())

    def read_register(self, reg: str) -> int:
        regname = self.arch.to_regname(reg)
        if regname is None:
            raise RegisterAccessError(reg, f'Not a register name: {reg}')

        if reg in self.read_cache:
            return self.read_cache[reg]

        self.progress_execution()
        return self._cache(reg, self.target.read_register(regname))

    def write_register(self, regname: str, value: int):
        self.progress_execution()
        self.read_cache.pop(regname, None)
        self.target.write_register(regname, value)

    def read_instructions(self, addr: int, size: int) -> bytes:
        return self.target.read_memory(addr, size)

    def read_memory(self, addr: int, size: int) -> bytes:
        self.progress_execution()
        cache_name = f'{addr}_{size}' 
        if cache_name in self.read_cache:
            return self.read_cache[cache_name]
        return self._cache(cache_name, self.target.read_memory(addr, size))

    def write_memory(self, addr: int, value: bytes):
        self.progress_execution()
        self.read_cache.pop(addr, None)
        self.target.write_memory(addr, value)

    def __getattr__(self, name: str):
        return getattr(self.target, name)

class SymbolicTracer:
    """A symbolic tracer that uses `LLDBConcreteTarget` with Miasm to simultaneously execute a
    program with concrete state and collect its symbolic transforms
    """
    def __init__(self, 
                 env: TraceEnvironment, 
                 remote: str | None=None,
                 force: bool=False,
                 cross_validate: bool=False):
        self.env = env
        self.force = force
        self.remote = remote
        self.cross_validate = cross_validate
        self.target = SpeculativeTracer(self.create_debug_target())

        self.nondet_events = DeterministicEventIterator(self.env.detlog)

    def create_debug_target(self) -> LLDBConcreteTarget:
        binary = self.env.binary_name
        if self.remote is False:
            debug(f'Launching local debug target {binary} {self.env.argv}')
            debug(f'Environment: {self.env}')
            return LLDBLocalTarget(binary, self.env.argv, self.env.envp)

        debug(f'Connecting to remote debug target {self.remote}')
        target = LLDBRemoteTarget(self.remote, binary)

        module_name = target.determine_name()
        binary = str(Path(self.env.binary_name).resolve())
        if binary != module_name:
            warn(f'Discovered binary name {module_name} differs from specified name {binary}')

        return target

    def predict_next_state(self, instruction: Instruction, transform: SymbolicTransform):
        debug(f'Evaluating register and memory transforms for {instruction} to cross-validate')
        predicted_regs = transform.eval_register_transforms(self.target)
        predicted_mems = transform.eval_memory_transforms(self.target)
        return predicted_regs, predicted_mems

    def validate(self,
                 instruction: Instruction,
                 transform: SymbolicTransform,
                 predicted_regs: dict[str, int],
                 predicted_mems: dict[int, bytes]):
        # Verify last generated transform by comparing concrete state against
        # predicted values.
        if self.target.is_exited():
            return

        debug('Cross-validating symbolic transforms by comparing actual to predicted values')
        for reg, val in predicted_regs.items():
            conc_val = self.target.read_register(reg)
            if conc_val != val:
                raise ValidationError(f'Symbolic execution backend generated false equation for'
                                      f' [{hex(instruction.addr)}]: {instruction}:'
                                      f' Predicted {reg} = {hex(val)}, but the'
                                      f' concrete state has value {reg} = {hex(conc_val)}.'
                                      f'\nFaulty transformation: {transform}')
        for addr, data in predicted_mems.items():
            conc_data = self.target.read_memory(addr, len(data))
            if conc_data != data:
                raise ValidationError(f'Symbolic execution backend generated false equation for'
                                      f' [{hex(instruction.addr)}]: {instruction}: Predicted'
                                      f' mem[{hex(addr)}:{hex(addr+len(data))}] = {data},'
                                      f' but the concrete state has value'
                                      f' mem[{hex(addr)}:{hex(addr+len(data))}] = {conc_data}.'
                                      f'\nFaulty transformation: {transform}')

    def post_event(self) -> None:
        current_event = self.nondet_events.current_event()
        if current_event:
            if current_event.pc == 0:
                # Exit sequence
                debug('Completed exit event')
                self.target.run()

            debug(f'Completed handling event: {current_event}')
            self.nondet_events.next()

    def is_stepping_instr(self, pc: int, instruction: Instruction) -> bool:
        # if self.nondet_events:
        print(f'{self.nondet_events.current_event()}')
        if self.nondet_events.current_event():
            debug('Current instruction matches next event; stepping through it')
            self.nondet_events.next()
            return True
        # else:
        #     if self.target.arch.is_instr_syscall(str(instruction)):
        #         return True
        return False

    def progress(self, new_pc, step: bool = False) -> int | None:
        self.target.speculate(new_pc)
        if step:
            self.target.progress_execution()
            if self.target.is_exited():
                return None
        return self.target.read_pc()

    def trace(self, time_limit: int | None = None) -> Trace[SymbolicTransform]:
        """Execute a program and compute state transformations between executed
        instructions.

        :param start_addr: Address from which to start tracing.
        :param stop_addr: Address until which to trace.
        """
        # Set up concrete reference state
        if self.env.start_address is not None:
            self.target.run_until(self.env.start_address)

        ctx = DisassemblyContext(self.target)
        arch = ctx.arch

        if logger.isEnabledFor(logging.DEBUG):
            debug('Tracing program with the following non-deterministic events')
            for event in self.nondet_events.events():
                debug(event)

        # Trace concolically
        strace: list[SymbolicTransform] = []
        while not self.target.is_exited():
            pc = self.target.read_pc()

            if self.env.stop_address is not None and pc == self.env.stop_address:
                break

            self.nondet_events.update(self.target)

            # Disassemble instruction at the current PC
            tid = self.target.get_current_tid()
            try:
                instruction = ctx.disassemble(pc)
                info(f'[{tid}] Disassembled instruction {instruction} at {hex(pc)}')
            except:
                err = sys.exc_info()[1]

                # Try to recovery by using the LLDB disassembly instead
                try:
                    alt_disas = self.target.get_disassembly(pc)
                    instruction = Instruction.from_string(alt_disas, ctx.arch, pc,
                                                         self.target.get_instruction_size(pc))
                    info(f'[{tid}] Disassembled instruction {instruction} at {hex(pc)}')
                except:
                    if self.force:
                        if alt_disas:
                            warn(f'[{tid}] Unable to handle instruction {alt_disas} at {hex(pc)} in Miasm.'
                                 f' Skipping.')
                        else:
                            warn(f'[{tid}] Unable to disassemble instruction {hex(pc)}: {err}.'
                                 f' Skipping.')
                        self.target.step()
                        continue
                    raise # forward exception

            is_event = self.is_stepping_instr(pc, instruction)

            # Run instruction
            conc_state = MiasmSymbolResolver(self.target, ctx.loc_db)

            try:
                new_pc, modified = timebound(time_limit, run_instruction,
                                             instruction.instr, conc_state, ctx.lifter)
            except TimeoutError:
                warn(f'Running instruction {instruction} took longer than {time_limit} second. Skipping')
                new_pc, modified = None, {}

            if self.cross_validate and new_pc:
                # Predict next concrete state.
                # We verify the symbolic execution backend on the fly for some
                # additional protection from bugs in the backend.
                new_pc = int(new_pc)
                transform = SymbolicTransform(tid, modified, [instruction], arch, pc, new_pc)
                pred_regs, pred_mems = self.predict_next_state(instruction, transform)
                self.progress(new_pc, step=is_event)

                try:
                    self.validate(instruction, transform, pred_regs, pred_mems)
                except ValidationError as e:
                    if self.force:
                        warn(f'Cross-validation failed: {e}')
                        continue
                    raise
            else:
                new_pc = self.progress(new_pc, step=is_event)
                if new_pc is None:
                    transform = SymbolicTransform(tid, modified, [instruction], arch, pc, 0)
                    strace.append(transform)
                    continue # we're done
                transform = SymbolicTransform(tid, modified, [instruction], arch, pc, new_pc)

            strace.append(transform)

            if is_event:
                self.post_event()

        return Trace(strace, self.env)

