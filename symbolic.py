"""Tools and utilities for symbolic execution with Miasm."""

from miasm.analysis.binary import ContainerELF
from miasm.analysis.machine import Machine
from miasm.core.asmblock import AsmCFG
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import Expr, ExprId, ExprMem

from lldb_target import LLDBConcreteTarget, record_snapshot
from miasm_util import MiasmConcreteState, eval_expr
from snapshot import ProgramState

class SymbolicTransform:
    def __init__(self, from_addr: int, to_addr: int):
        self.addr = from_addr
        self.range = (from_addr, to_addr)

    def calc_register_transform(self, conc_state: ProgramState) \
            -> dict[str, int]:
        raise NotImplementedError('calc_register_transform is abstract.')

    def calc_memory_transform(self, conc_state: ProgramState) \
            -> dict[int, bytes]:
        raise NotImplementedError('calc_memory_transform is abstract.')

class MiasmSymbolicTransform(SymbolicTransform):
    def __init__(self,
                 transform: dict[ExprId, Expr],
                 loc_db: LocationDB,
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
        for id, expr in transform.items():
            if isinstance(id, ExprMem):
                self.mem_diff[id.ptr] = expr
            elif id.name != 'IRDst':
                assert(isinstance(id, ExprId))
                self.regs_diff[id.name] = expr

        self.loc_db = loc_db

    def calc_register_transform(self, conc_state: ProgramState) \
            -> dict[str, int]:
        ref_state = MiasmConcreteState(conc_state, self.loc_db)

        res = {}
        for regname, expr in self.regs_diff.items():
            res[regname] = eval_expr(expr, ref_state)
        return res

    def calc_memory_transform(self, conc_state: ProgramState) \
            -> dict[int, bytes]:
        ref_state = MiasmConcreteState(conc_state, self.loc_db)

        res = {}
        for addr, expr in self.mem_diff.items():
            addr = int(eval_expr(addr, ref_state))
            length = int(expr.size / 8)
            res[addr] = int(eval_expr(expr, ref_state)).to_bytes(length)
        return res

    def __repr__(self) -> str:
        return f'Symbolic state transformation for instruction \
                 {hex(self.addr)}.'

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

def _run_block(pc: int, conc_state: MiasmConcreteState, lifter, ircfg, mdis) \
        -> tuple[int | None, list]:
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
    global disasm_time
    global symb_exec_time

    # Start with a clean, purely symbolic state
    engine = SymbolicExecutionEngine(lifter)

    # A list of symbolic transformation for each single instruction
    symb_trace = []

    while True:
        irblock = ircfg.get_block(pc)

        # Initial disassembly might not find all blocks in the binary.
        # Disassemble code ad-hoc if the current PC has not yet been
        # disassembled.
        if irblock is None:
            cfg = mdis.dis_multiblock(pc)
            for asmblock in cfg.blocks:
                try:
                    lifter.add_asmblock_to_ircfg(asmblock, ircfg)
                except NotImplementedError as err:
                    print(f'[ERROR] Unable to disassemble block at'
                          f' {hex(asmblock.get_range()[0])}:'
                          f' [Not implemented] {err}')
                    pass

            irblock = ircfg.get_block(pc)
            if irblock is None:
                print(f'[ERROR] Unable to disassemble block(s) at {hex(pc)}.')
                raise RuntimeError()
            print(f'Disassembled {len(cfg.blocks):4} new blocks at {hex(int(pc))}.')

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
    loc_db = LocationDB()
    with open(binary, 'rb') as bin_file:
        cont = ContainerELF.from_stream(bin_file, loc_db)
    machine = Machine(cont.arch)

    # Create disassembly/lifting context
    mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)
    mdis.follow_call = True
    asmcfg = AsmCFG(loc_db)

    lifter = machine.lifter(loc_db)
    ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

    if start_addr is None:
        pc = cont.entry_point
    else:
        pc = start_addr

    target = LLDBConcreteTarget(binary, argv)
    if target.read_register('pc') != pc:
        target.set_breakpoint(pc)
        target.run()
        target.remove_breakpoint(pc)

    symb_trace = [] # The resulting list of symbolic transforms per instruction

    # Run until no more states can be reached
    initial_state = record_snapshot(target)
    while pc is not None:
        assert(target.read_register('pc') == pc)

        # Run symbolic execution
        # It uses the concrete state to resolve symbolic program counters to
        # concrete values.
        pc, strace = _run_block(
            pc, MiasmConcreteState(initial_state, loc_db),
            lifter, ircfg, mdis)

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
        initial_state = record_snapshot(target)

    res = []
    for (start, diff), (end, _) in zip(symb_trace[:-1], symb_trace[1:]):
        res.append(MiasmSymbolicTransform(diff, loc_db, start, end))
    start, diff = symb_trace[-1]
    res.append(MiasmSymbolicTransform(diff, loc_db, start, start))

    return res
