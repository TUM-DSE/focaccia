"""Tools and utilities for symbolic execution with Miasm."""

from __future__ import annotations
from typing import Iterable
import logging
import sys

from miasm.analysis.binary import ContainerELF
from miasm.analysis.machine import Machine
from miasm.core.cpu import instruction as miasm_instr
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import Expr, ExprId, ExprMem, ExprInt
from miasm.ir.ir import Lifter
from miasm.ir.symbexec import SymbolicExecutionEngine

from .arch import Arch, supported_architectures
from .lldb_target import LLDBConcreteTarget, \
                         ConcreteRegisterError, \
                         ConcreteMemoryError
from .miasm_util import MiasmSymbolResolver, eval_expr, make_machine
from .snapshot import ProgramState, ReadableProgramState, \
                      RegisterAccessError, MemoryAccessError
from .trace import Trace, TraceEnvironment

logger = logging.getLogger('focaccia-symbolic')
warn = logger.warn

# Disable Miasm's disassembly logger
logging.getLogger('asmblock').setLevel(logging.CRITICAL)

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
            raise ValueError(f'[In eval_symbol]: Unable to evaluate symbols'
                             f' that contain IR location expressions.')

    res = eval_expr(symbol, ConcreteStateWrapper(conc_state))
    assert(isinstance(res, ExprInt))  # Must be either ExprInt or ExprLoc,
                                      # but ExprLocs are disallowed by the
                                      # ConcreteStateWrapper
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
                 transform: dict[Expr, Expr],
                 instrs: list[Instruction],
                 arch: Arch,
                 from_addr: int,
                 to_addr: int):
        """
        :param state: The symbolic transformation in the form of a SimState
                      object.
        :param first_inst: An instruction address. The transformation
                           represents the modifications to the program state
                           performed by this instruction.
        """
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

    def eval_register_transforms(self, conc_state: ProgramState) \
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
            res[regname] = eval_symbol(expr, conc_state)
        return res

    def eval_memory_transforms(self, conc_state: ProgramState) \
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

        def decode_inst(obj: Iterable[int], arch: Arch):
            b = b''.join(i.to_bytes(1) for i in obj)
            try:
                return Instruction.from_bytecode(b, arch)
            except Exception as err:
                warn(f'[In SymbolicTransform.from_json] Unable to disassemble'
                     f' bytes {obj}: {err}.')
                return None

        arch = supported_architectures[data['arch']]
        start_addr = int(data['from_addr'])
        end_addr = int(data['to_addr'])

        t = SymbolicTransform({}, [], arch, start_addr, end_addr)
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
                return [int(b) for b in inst.to_bytecode()]
            except Exception as err:
                warn(f'[In SymbolicTransform.to_json] Unable to assemble'
                     f' "{inst}" to bytecode: {err}. This instruction will not'
                     f' be serialized.')
                return None

        instrs = [encode_inst(inst) for inst in self.instructions]
        instrs = [inst for inst in instrs if inst is not None]
        return {
            'arch': self.arch.archname,
            'from_addr': self.range[0],
            'to_addr': self.range[1],
            'instructions': instrs,
            'regs': { name: repr(expr) for name, expr in self.changed_regs.items() },
            'mem': { repr(addr): repr(val) for addr, val in self.changed_mem.items() },
        }

    def __repr__(self) -> str:
        start, end = self.range
        res = f'Symbolic state transformation {hex(start)} -> {hex(end)}:\n'
        res += '  [Symbols]\n'
        for reg, expr in self.changed_regs.items():
            res += f'    {reg:6s} = {expr}\n'
        for addr, expr in self.changed_mem.items():
            res += f'    {ExprMem(addr, expr.size)} = {expr}\n'
        res += '  [Instructions]\n'
        for inst in self.instructions:
            res += f'    {inst}\n'

        return res[:-1]  # Remove trailing newline

class DisassemblyContext:
    def __init__(self, binary):
        self.loc_db = LocationDB()

        # Load the binary
        with open(binary, 'rb') as bin_file:
            cont = ContainerELF.from_stream(bin_file, self.loc_db)
        self.entry_point = cont.entry_point

        # Determine the binary's architecture
        self.machine = Machine(cont.arch)
        if self.machine.name not in supported_architectures:
            raise NotImplementedError(f'[ERROR] {self.machine.name} is not'
                                      f' supported.')
        self.arch = supported_architectures[self.machine.name]
        """Focaccia's description of an instruction set architecture."""

        # Create disassembly/lifting context
        assert(self.machine.dis_engine is not None)
        self.mdis = self.machine.dis_engine(cont.bin_stream, loc_db=self.loc_db)
        self.mdis.follow_call = True
        self.lifter = self.machine.lifter(self.loc_db)

def run_instruction(instr: miasm_instr,
                    conc_state: MiasmSymbolResolver,
                    lifter: Lifter) \
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
        warn(f'[WARNING] Unable to lift instruction {instr}: {err}. Skipping.')
        return None, {}  # Create an empty transform for the instruction

    # Execute instruction symbolically
    new_pc, modified = execute_location(loc)
    modified[lifter.pc] = new_pc  # Add PC update to state

    return new_pc, modified

class _LLDBConcreteState(ReadableProgramState):
    """A wrapper around `LLDBConcreteTarget` that provides access via a
    `ReadableProgramState` interface. Reads values directly from an LLDB
    target. This saves us the trouble of recording a full program state, and
    allows us instead to read values from LLDB on demand.
    """
    def __init__(self, target: LLDBConcreteTarget, arch: Arch):
        super().__init__(arch)
        self._target = target

    def read_register(self, reg: str) -> int:
        regname = self.arch.to_regname(reg)
        if regname is None:
            raise RegisterAccessError(reg, f'Not a register name: {reg}')

        try:
            return self._target.read_register(regname)
        except ConcreteRegisterError:
            raise RegisterAccessError(regname, '')

    def read_memory(self, addr: int, size: int) -> bytes:
        try:
            return self._target.read_memory(addr, size)
        except ConcreteMemoryError:
            raise MemoryAccessError(addr, size, 'Unable to read memory from LLDB.')

def collect_symbolic_trace(env: TraceEnvironment,
                           start_addr: int | None = None
                           ) -> Trace[SymbolicTransform]:
    """Execute a program and compute state transformations between executed
    instructions.

    :param binary: The binary to trace.
    :param args:   Arguments to the program.
    """
    binary = env.binary_name

    ctx = DisassemblyContext(binary)
    arch = ctx.arch

    # Set up concrete reference state
    target = LLDBConcreteTarget(binary, env.argv, env.envp)
    if start_addr is not None:
        target.run_until(start_addr)
    lldb_state = _LLDBConcreteState(target, arch)

    # Trace concolically
    strace: list[SymbolicTransform] = []
    while not target.is_exited():
        pc = target.read_register('pc')

        # Disassemble instruction at the current PC
        try:
            instr = ctx.mdis.dis_instr(pc)
        except:
            err = sys.exc_info()[1]
            warn(f'Unable to disassemble instruction at {hex(pc)}: {err}.'
                 f' Skipping.')
            target.step()
            continue

        # Run instruction
        conc_state = MiasmSymbolResolver(lldb_state, ctx.loc_db)
        new_pc, modified = run_instruction(instr, conc_state, ctx.lifter)

        # Create symbolic transform
        instruction = Instruction(instr, ctx.machine, ctx.arch, ctx.loc_db)
        if new_pc is None:
            new_pc = pc + instruction.length
        else:
            new_pc = int(new_pc)
        strace.append(SymbolicTransform(modified, [instruction], arch, pc, new_pc))

        # Step forward
        target.step()

    return Trace(strace, env)
