"""Tools and utilities for symbolic execution with Miasm."""

from __future__ import annotations

from miasm.analysis.binary import ContainerELF
from miasm.analysis.machine import Machine
from miasm.core.asmblock import AsmCFG
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.ir.ir import IRBlock
from miasm.expression.expression import Expr, ExprId, ExprMem, ExprInt

from .arch import Arch, supported_architectures
from .lldb_target import LLDBConcreteTarget, \
                         ConcreteRegisterError, \
                         ConcreteMemoryError
from .miasm_util import MiasmConcreteState, eval_expr
from .snapshot import ProgramState

def eval_symbol(symbol: Expr, conc_state: ProgramState) -> int:
    """Evaluate a symbol based on a concrete reference state.

    :param conc_state: A concrete state.
    :return: The resolved value.

    :raise ValueError: If the concrete state does not contain a register value
                       that is referenced by the symbolic expression.
    :raise MemoryAccessError: If the concrete state does not contain memory
                              that is referenced by the symbolic expression.
    """
    class ConcreteStateWrapper(MiasmConcreteState):
        """Extend the state resolver with assumptions about the expressions
        that may be resolved with `eval_symbol`."""
        def __init__(self, conc_state: ProgramState):
            super().__init__(conc_state, LocationDB())

        def resolve_register(self, regname: str) -> int:
            regname = regname.upper()
            regname = self.miasm_flag_aliases.get(regname, regname)
            return self._state.read_register(regname)

        def resolve_memory(self, addr: int, size: int) -> bytes:
            return self._state.read_memory(addr, size)

        def resolve_location(self, _):
            raise ValueError(f'[In eval_symbol]: Unable to evaluate symbols'
                             f' that contain IR location expressions.')

    res = eval_expr(symbol, ConcreteStateWrapper(conc_state))
    assert(isinstance(res, ExprInt))  # Must be either ExprInt or ExprLoc,
                                      # but ExprLocs are disallowed by the
                                      # ConcreteStateWrapper
    return int(res)

class SymbolicTransform:
    """A symbolic transformation mapping one program state to another."""
    def __init__(self,
                 transform: dict[Expr, Expr],
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

        return self

    def get_used_registers(self) -> list[str]:
        """Find all registers used by the transformation as input.

        :return: A list of register names.
        """
        accessed_regs = set[str]()

        class ConcreteStateWrapper(MiasmConcreteState):
            def __init__(self): pass
            def resolve_register(self, regname: str) -> int | None:
                accessed_regs.add(regname)
                return None
            def resolve_memory(self, addr: int, size: int):
                pass
            def resolve_location(self, _):
                assert(False)

        state = ConcreteStateWrapper()
        for expr in self.changed_regs.values():
            eval_expr(expr, state)
        for addr_expr, mem_expr in self.changed_mem.items():
            eval_expr(addr_expr, state)
            eval_expr(mem_expr, state)

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
            res[addr] = eval_symbol(expr, conc_state).to_bytes(length)
        return res

    def __repr__(self) -> str:
        start, end = self.range
        res = f'Symbolic state transformation {hex(start)} -> {hex(end)}:\n'
        for reg, expr in self.changed_regs.items():
            res += f'   {reg:6s} = {expr}\n'
        for addr, expr in self.changed_mem.items():
            res += f'   {ExprMem(addr, expr.size)} = {expr}\n'
        return res[:-1]  # Remove trailing newline

def parse_symbolic_transform(string: str) -> SymbolicTransform:
    """Parse a symbolic transformation from a string.
    :raise KeyError: if a parse error occurs.
    """
    import json
    from miasm.expression.parser import str_to_expr as parse

    data = json.loads(string)

    # We can use a None-arch because it's only used when the dict is not empty
    t = SymbolicTransform({}, None, int(data['from_addr']), int(data['to_addr']))
    t.changed_regs = { name: parse(val) for name, val in data['regs'].items() }
    t.changed_mem = { parse(addr): parse(val) for addr, val in data['mem'].items() }

    return t

def serialize_symbolic_transform(t: SymbolicTransform) -> str:
    """Serialize a symbolic transformation."""
    import json
    return json.dumps({
        'from_addr': t.range[0],
        'to_addr': t.range[1],
        'regs': { name: repr(expr) for name, expr in t.changed_regs.items() },
        'mem': { repr(addr): repr(val) for addr, val in t.changed_mem.items() },
    })

def _step_until(target: LLDBConcreteTarget, addr: int) -> list[int]:
    """Step a concrete target to a specific instruction.
    :return: Trace of all instructions executed.
    """
    trace = [target.read_register('pc')]
    target.step()
    while not target.is_exited() and target.read_register('pc') != addr:
        trace.append(target.read_register('pc'))
        target.step()
    return trace

class DisassemblyContext:
    def __init__(self, binary):
        self.loc_db = LocationDB()

        # Load the binary
        with open(binary, 'rb') as bin_file:
            cont = ContainerELF.from_stream(bin_file, self.loc_db)

        self.machine = Machine(cont.arch)
        self.entry_point = cont.entry_point

        # Create disassembly/lifting context
        self.lifter = self.machine.lifter(self.loc_db)
        self.mdis = self.machine.dis_engine(cont.bin_stream, loc_db=self.loc_db)
        self.mdis.follow_call = True
        self.asmcfg = AsmCFG(self.loc_db)
        self.ircfg = self.lifter.new_ircfg_from_asmcfg(self.asmcfg)

    def get_irblock(self, addr: int) -> IRBlock | None:
        irblock = self.ircfg.get_block(addr)

        # Initial disassembly might not find all blocks in the binary.
        # Disassemble code ad-hoc if the current address has not yet been
        # disassembled.
        if irblock is None:
            cfg = self.mdis.dis_multiblock(addr)
            for asmblock in cfg.blocks:
                try:
                    self.lifter.add_asmblock_to_ircfg(asmblock, self.ircfg)
                except NotImplementedError as err:
                    print(f'[WARNING] Unable to disassemble block at'
                          f' {hex(asmblock.get_range()[0])}:'
                          f' [Not implemented] {err}')
                    pass
            print(f'Disassembled {len(cfg.blocks):5} new blocks at {hex(int(addr))}.')
            irblock = self.ircfg.get_block(addr)

        # Might still be None if disassembly/lifting failed for the block
        # at `addr`.
        return irblock

class DisassemblyError(Exception):
    def __init__(self,
                 partial_trace: list[tuple[int, SymbolicTransform]],
                 faulty_pc: int,
                 err_msg: str):
        self.partial_trace = partial_trace
        self.faulty_pc = faulty_pc
        self.err_msg = err_msg

def _run_block(pc: int, conc_state: MiasmConcreteState, ctx: DisassemblyContext) \
        -> tuple[int | None, list[dict]]:
    """Run a basic block.

    Tries to run IR blocks until the end of an ASM block/basic block is
    reached. Skips 'virtual' blocks that purely exist in the IR.

    :param pc:         A program counter at which we start executing.
    :param conc_state: A concrete reference state at `pc`. Used to resolve
                       symbolic program counters, i.e. to 'guide' the symbolic
                       execution on the correct path. This is the concrete part
                       of our concolic execution.

    :return: The next program counter. None if no next program counter can be
             found. This happens when an error occurs or when the program
             exits.
    """
    # Start with a clean, purely symbolic state
    engine = SymbolicExecutionEngine(ctx.lifter)

    # A list of symbolic transformation for each single instruction
    symb_trace = []

    while True:
        irblock = ctx.get_irblock(pc)
        if irblock is None:
            raise DisassemblyError(
                symb_trace,
                pc,
                f'[ERROR] Unable to disassemble block at {hex(pc)}.'
            )

        # Execute each instruction in the current basic block and record the
        # resulting change in program state.
        for assignblk in irblock:
            # A clean engine for the single-instruction diff, otherwise
            # it concatenates the current instruction to the previous ones in
            # the block.
            _engine = SymbolicExecutionEngine(ctx.lifter)
            modified = _engine.eval_assignblk(assignblk)
            symb_trace.append((assignblk.instr.offset, modified))

            # Run a single instruction
            engine.eval_updt_assignblk(assignblk)

        # Obtain the next program counter after the basic block.
        symbolic_pc = engine.eval_expr(engine.lifter.IRDst)

        # The new program counter might be a symbolic value. Try to evaluate
        # it based on the last recorded concrete state at the start of the
        # current basic block.
        pc = eval_expr(symbolic_pc, conc_state)

        # If the resulting PC is an integer, i.e. a concrete address that can
        # be mapped to the assembly code, we return as we have reached the end
        # of a basic block. Otherwise we might have reached the end of an IR
        # block, in which case we keep executing until we reach the end of an
        # ASM block.
        #
        # Example: This happens for the REP STOS instruction, for which Miasm
        # generates multiple IR blocks.
        try:
            return int(pc), symb_trace
        except:
            # We reach this point when the program counter is an IR block
            # location (not an integer). That happens when single ASM
            # instructions are translated to multiple IR instructions.
            pass

class _LLDBConcreteState:
    """A back-end replacement for the `ProgramState` object from which
    `MiasmConcreteState` reads its values. This reads values directly from an
    LLDB target instead. This saves us the trouble of recording a full program
    state, and allows us instead to read values from LLDB on demand.
    """
    def __init__(self, target: LLDBConcreteTarget, arch: Arch):
        self._target = target
        self._arch = arch

    def read_register(self, reg: str) -> int | None:
        from focaccia.arch import x86

        regname = self._arch.to_regname(reg)
        if regname is None:
            return None

        try:
            return self._target.read_register(regname)
        except ConcreteRegisterError:
            # Special case for X86
            if self._arch.archname == x86.archname:
                rflags = x86.decompose_rflags(self._target.read_register('rflags'))
                if regname in rflags:
                    return rflags[regname]
            return None

    def read_memory(self, addr: int, size: int):
        try:
            return self._target.read_memory(addr, size)
        except ConcreteMemoryError:
            return None

def collect_symbolic_trace(binary: str,
                           args: list[str],
                           start_addr: int | None = None
                           ) -> list[SymbolicTransform]:
    """Execute a program and compute state transformations between executed
    instructions.

    :param binary: The binary to trace.
    :param args:   Arguments to the program.
    """
    ctx = DisassemblyContext(binary)

    # Find corresponding architecture
    mach_name = ctx.machine.name
    if mach_name not in supported_architectures:
        print(f'[ERROR] {mach_name} is not supported. Returning.')
        return []
    arch = supported_architectures[mach_name]

    if start_addr is None:
        pc = ctx.entry_point
    else:
        pc = start_addr

    target = LLDBConcreteTarget(binary, args)
    if target.read_register('pc') != pc:
        target.set_breakpoint(pc)
        target.run()
        target.remove_breakpoint(pc)
    conc_state = _LLDBConcreteState(target, arch)

    symb_trace = [] # The resulting list of symbolic transforms per instruction

    # Run until no more states can be reached
    while pc is not None:
        assert(target.read_register('pc') == pc)

        # Run symbolic execution
        # It uses the concrete state to resolve symbolic program counters to
        # concrete values.
        try:
            pc, strace = _run_block(
                pc,
                MiasmConcreteState(conc_state, ctx.loc_db),
                ctx)
        except DisassemblyError as err:
            # This happens if we encounter an instruction that is not
            # implemented by Miasm. Try to skip that instruction and continue
            # at the next one.
            print(f'[WARNING] Skipping instruction at {hex(err.faulty_pc)}...')

            # First, catch up to symbolic trace if required
            if err.faulty_pc != pc:
                ctrace = _step_until(target, err.faulty_pc)
                symb_trace.extend(err.partial_trace)
                assert(len(ctrace) - 1 == len(err.partial_trace))  # no ghost instr

            # Now step one more time to skip the faulty instruction
            target.step()
            if target.is_exited():
                break

            symb_trace.append((err.faulty_pc, {}))  # Generate empty transform
            pc = target.read_register('pc')
            continue

        if pc is None:
            break

        # Step concrete target forward.
        #
        # The concrete target now lags behind the symbolic execution by exactly
        # one basic block: the one that we just executed. Run the concrete
        # execution until it reaches the new PC.
        ctrace = _step_until(target, pc)

        # Sometimes, miasm generates ghost instructions at the end of basic
        # blocks. Don't include them in the symbolic trace.
        strace = strace[:len(ctrace)]
        symb_trace.extend(strace)

        # Use this for extensive trace debugging
        #if [a for a, _ in strace] != ctrace:
        #    print(f'[WARNING] Symbolic trace and concrete trace are not equal!'
        #          f'\n    symbolic: {[hex(a) for a, _ in strace]}'
        #          f'\n    concrete: {[hex(a) for a in ctrace]}')

        if target.is_exited():
            break

    res = []
    for (start, diff), (end, _) in zip(symb_trace[:-1], symb_trace[1:]):
        res.append(SymbolicTransform(diff, arch, start, end))
    start, diff = symb_trace[-1]
    res.append(SymbolicTransform(diff, arch, start, start))

    return res
