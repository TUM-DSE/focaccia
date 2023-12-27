"""Tools and utilities for symbolic execution with Miasm."""

from __future__ import annotations
from typing import Self

from miasm.analysis.binary import ContainerELF
from miasm.analysis.machine import Machine
from miasm.core.asmblock import AsmCFG
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.ir.ir import IRBlock
from miasm.expression.expression import Expr, ExprId, ExprMem, ExprInt

from lldb_target import LLDBConcreteTarget
from miasm_util import MiasmConcreteState, eval_expr
from snapshot import ProgramState
from arch import Arch, supported_architectures

class SymbolicTransform:
    def __init__(self, from_addr: int, to_addr: int):
        self.addr = from_addr
        self.range = (from_addr, to_addr)

    def concat(self, other: Self) -> Self:
        """Concatenate another transform to this transform.

        The symbolic transform on which `concat` is called is the transform
        that is applied first, meaning: `(a.concat(b))(state) == b(a(state))`.
        """
        raise NotImplementedError('concat is abstract.')

    def calc_register_transform(self, conc_state: ProgramState) \
            -> dict[str, int]:
        raise NotImplementedError('calc_register_transform is abstract.')

    def calc_memory_transform(self, conc_state: ProgramState) \
            -> dict[int, bytes]:
        raise NotImplementedError('calc_memory_transform is abstract.')

    def __repr__(self) -> str:
        start, end = self.range
        return f'Symbolic state transformation {hex(start)} -> {hex(end)}'

class MiasmSymbolicTransform(SymbolicTransform):
    def __init__(self,
                 transform: dict[Expr, Expr],
                 arch: Arch,
                 start_addr: int,
                 end_addr: int):
        """
        :param state: The symbolic transformation in the form of a SimState
                      object.
        :param first_inst: An instruction address. The transformation
                           represents the modifications to the program state
                           performed by this instruction.
        """
        super().__init__(start_addr, end_addr)

        self.regs_diff: dict[str, Expr] = {}
        self.mem_diff: dict[ExprMem, Expr] = {}
        for dst, expr in transform.items():
            assert(isinstance(dst, ExprMem) or isinstance(dst, ExprId))

            if isinstance(dst, ExprMem):
                self.mem_diff[dst] = expr
            else:
                assert(isinstance(dst, ExprId))
                regname = arch.to_regname(dst.name)
                if regname is not None:
                    self.regs_diff[regname] = expr

        self.arch = arch

    def concat(self, other: MiasmSymbolicTransform) -> Self:
        class MiasmSymbolicState(MiasmConcreteState):
            """Drop-in replacement for MiasmConcreteState in eval_expr that
            returns the current transform's symbolic equations instead of
            symbolic values. Calling eval_expr with this effectively nests the
            transformation into the concatenated transformation.

            We inherit from `MiasmSymbolicTransform` only for the purpose of
            correct type checking.
            """
            def __init__(self, transform: MiasmSymbolicTransform):
                self.transform = transform

            def resolve_register(self, regname: str):
                return self.transform.regs_diff.get(regname, None)

            def resolve_memory(self, addr: int, size: int):
                mem = ExprMem(ExprInt(addr, 64), size)
                return self.transform.mem_diff.get(mem, None)

            def resolve_location(self, _):
                return None

        if self.range[1] != other.range[0]:
            raise ValueError(f'The concatenated transformations must span a'
                             f' contiguous range of instructions.')

        ref_state = MiasmSymbolicState(self)
        for reg, expr in other.regs_diff.items():
            if reg not in self.regs_diff:
                self.regs_diff[reg] = expr
            else:
                self.regs_diff[reg] = eval_expr(expr, ref_state)

        for dst, expr in other.mem_diff.items():
            dst = eval_expr(dst, ref_state)
            if dst not in self.mem_diff:
                self.mem_diff[dst] = expr
            else:
                self.mem_diff[dst] = eval_expr(expr, ref_state)

        self.range = (self.range[0], other.range[1])

        return self

    def calc_register_transform(self, conc_state: ProgramState) \
            -> dict[str, int]:
        # Construct a dummy location DB. At this point, expressions should
        # never contain IR locations.
        ref_state = MiasmConcreteState(conc_state, LocationDB())

        res = {}
        for regname, expr in self.regs_diff.items():
            res[regname] = int(eval_expr(expr, ref_state))
        return res

    def calc_memory_transform(self, conc_state: ProgramState) \
            -> dict[int, bytes]:
        # Construct a dummy location DB. At this point, expressions should
        # never contain IR locations.
        ref_state = MiasmConcreteState(conc_state, LocationDB())

        res = {}
        for addr, expr in self.mem_diff.items():
            addr = int(eval_expr(addr, ref_state))
            length = int(expr.size / 8)
            res[addr] = int(eval_expr(expr, ref_state)).to_bytes(length)
        return res

    def __repr__(self) -> str:
        start, end = self.range
        res = f'Symbolic state transformation {hex(start)} -> {hex(end)}:\n'
        for reg, expr in self.regs_diff.items():
            res += f'   {reg:6s} = {expr}\n'
        for mem, expr in self.mem_diff.items():
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
                 partial_trace: list[tuple[int, MiasmSymbolicTransform]],
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

def collect_symbolic_trace(binary: str,
                           argv: list[str],
                           start_addr: int | None = None
                           ) -> list[SymbolicTransform]:
    """Execute a program and compute state transformations between executed
    instructions.

    :param binary: The binary to trace.
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

    target = LLDBConcreteTarget(binary, argv)
    if target.read_register('pc') != pc:
        target.set_breakpoint(pc)
        target.run()
        target.remove_breakpoint(pc)

    symb_trace = [] # The resulting list of symbolic transforms per instruction

    # Run until no more states can be reached
    initial_state = target.record_snapshot()
    while pc is not None:
        assert(target.read_register('pc') == pc)

        # Run symbolic execution
        # It uses the concrete state to resolve symbolic program counters to
        # concrete values.
        try:
            pc, strace = _run_block(
                pc,
                MiasmConcreteState(initial_state, ctx.loc_db),
                ctx
            )
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
            initial_state = target.record_snapshot()
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
        if [a for a, _ in strace] != ctrace:
            print(f'[WARNING] Symbolic trace and concrete trace are not equal!'
                  f'\n    symbolic: {[hex(a) for a, _ in strace]}'
                  f'\n    concrete: {[hex(a) for a in ctrace]}')

        if target.is_exited():
            break

        # Query the new reference state for symbolic execution
        initial_state = target.record_snapshot()

    res = []
    for (start, diff), (end, _) in zip(symb_trace[:-1], symb_trace[1:]):
        res.append(MiasmSymbolicTransform(diff, arch, start, end))
    start, diff = symb_trace[-1]
    res.append(MiasmSymbolicTransform(diff, arch, start, start))

    return res
