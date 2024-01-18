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

        self.changed_mem: dict[ExprMem, Expr] = {}
        """Maps memory addresses to memory content.

        Memory addresses may depend on other symbolic values, such as register
        content, and are therefore symbolic themselves.

        Remember: The memory content expression's `size` attribute is in bits,
        not bytes!"""

        for dst, expr in transform.items():
            assert(isinstance(dst, ExprMem) or isinstance(dst, ExprId))

            if isinstance(dst, ExprMem):
                self.changed_mem[dst] = expr
            else:
                assert(isinstance(dst, ExprId))
                regname = arch.to_regname(dst.name)
                if regname is not None:
                    self.changed_regs[regname] = expr

    def concat(self, other: SymbolicTransform) -> SymbolicTransform:
        """Concatenate two transformations.

        The symbolic transform on which `concat` is called is the transform
        that is applied first, meaning: `(a.concat(b))(state) == b(a(state))`.
        """
        class MiasmSymbolicState(MiasmConcreteState):
            """Drop-in replacement for MiasmConcreteState in eval_expr that
            returns the current transform's symbolic equations instead of
            concrete values. Calling eval_expr with this effectively nests the
            transformation into the concatenated transformation.

            We inherit from `MiasmConcreteState` only for the purpose of
            correct type checking.
            """
            def __init__(self, transform: SymbolicTransform):
                self.transform = transform

            def resolve_register(self, regname: str):
                return self.transform.changed_regs.get(regname, None)

            def resolve_memory(self, addr: int, size: int):
                mem = ExprMem(ExprInt(addr, 64), size)
                return self.transform.changed_mem.get(mem, None)

            def resolve_location(self, _):
                return None

        if self.range[1] != other.range[0]:
            repr_range = lambda r: f'[{hex(r[0])} -> {hex(r[1])}]'
            raise ValueError(
                f'Unable to concatenate transformation'
                f' {repr_range(self.range)} with {repr_range(other.range)};'
                f' the concatenated transformations must span a'
                f' contiguous range of instructions.')

        ref_state = MiasmSymbolicState(self)

        # Registers
        for reg, expr in other.changed_regs.items():
            if reg not in self.changed_regs:
                self.changed_regs[reg] = expr
            else:
                self.changed_regs[reg] = eval_expr(expr, ref_state)

        # Memory
        for dst, expr in other.changed_mem.items():
            dst = eval_expr(dst, ref_state)
            assert(isinstance(dst, ExprMem))
            if dst not in self.changed_mem:
                self.changed_mem[dst] = expr
            else:
                self.changed_mem[dst] = eval_expr(expr, ref_state)

        self.range = (self.range[0], other.range[1])

        return self

    def eval_register_transforms(self, conc_state: ProgramState) \
            -> dict[str, int]:
        """Calculate register transformations when applied to a concrete state.

        :param conc_state: A concrete program state that serves as the input
                           state on which the transformation operates.

        :return: A map from register names to the register values that were
                 changed by the transformation.
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
        for mem, expr in self.changed_mem.items():
            res += f'   {mem} = {expr}\n'
        return res[:-2]  # Remove trailing newline

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
            modified = engine.eval_assignblk(assignblk)
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
