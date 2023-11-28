import sys

from miasm.arch.x86.sem import Lifter_X86_64
from miasm.analysis.machine import Machine
from miasm.analysis.binary import ContainerELF
from miasm.core.asmblock import AsmCFG
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine, SymbolicState

from arch import x86
from gen_trace import record_trace
from lldb_target import LLDBConcreteTarget, SimConcreteMemoryError, \
                        SimConcreteRegisterError
from miasm_util import MiasmConcreteState, eval_expr
from snapshot import ProgramState

def print_blocks(asmcfg, file=sys.stdout):
    print('=' * 80, file=file)
    for block in asmcfg.blocks:
        print(block, file=file)
        print('-' * 60, file=file)
    print('=' * 80, file=file)

def print_state(state: SymbolicState):
    print('=' * 80)
    for reg, val in state.iteritems():
        print(f'{str(reg):10s} = {val}')
    print('=' * 80)

def step_through_trace(target: LLDBConcreteTarget, trace: list[int]):
    """Step a concrete target forward by some instructions."""
    assert(not trace or trace[0] == target.read_register('pc'))
    for i in range(len(trace)):
        assert(not target.is_exited())
        assert(target.read_register('pc') == trace[i])
        target.step()

def create_state(target: LLDBConcreteTarget) -> ProgramState:
    def standardize_flag_name(regname: str) -> str:
        regname = regname.upper()
        if regname in MiasmConcreteState.miasm_flag_aliases:
            return MiasmConcreteState.miasm_flag_aliases[regname]
        return regname

    state = ProgramState(x86.ArchX86())

    # Query and store register state
    rflags = x86.decompose_rflags(target.read_register('rflags'))
    for reg in machine.mn.regs.all_regs_ids_no_alias:
        regname = reg.name
        try:
            conc_val = target.read_register(regname)
            state.set(regname, conc_val)
        except KeyError:
            pass
        except SimConcreteRegisterError:
            regname = standardize_flag_name(regname)
            if regname in rflags:
                state.set(regname, rflags[regname])

    # Query and store memory state
    for mapping in target.get_mappings():
        assert(mapping.end_address > mapping.start_address)
        size = mapping.end_address - mapping.start_address
        try:
            data = target.read_memory(mapping.start_address, size)
            state.write_memory(mapping.start_address, data)
        except SimConcreteMemoryError:
            # Unable to read memory from mapping
            pass

    return state

binary = sys.argv[1]

loc_db = LocationDB()
cont = ContainerELF.from_stream(open(binary, 'rb'), loc_db)
machine = Machine(cont.arch)

pc = int(cont.entry_point)

# Disassemble binary
print(f'Disassembling "{binary}"...')
mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)
mdis.follow_call = True
asmcfg = AsmCFG(loc_db)

# Lift disassembly to IR
print(f'Lifting disassembly to IR...')
lifter: Lifter_X86_64 = machine.lifter(loc_db)
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

# TODO: To implement support for unimplemented instructions, add their
# ASM->IR implementations to the `mnemo_func` array in
# `miasm/arch/x86/sem.py:5142`.
#
# For XGETBV, I might have to add the extended control register XCR0 first.
# This might be a nontrivial patch to Miasm.

# Record concrete reference states to guide symbolic execution
print(f'Recording concrete program trace...')
conc_trace = record_trace(binary, func_name=None)
print(f'Recorded {len(conc_trace)} trace points.')
assert(conc_trace[0] == pc)

def run_block(pc: int, conc_state: MiasmConcreteState) \
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
            addr = int(pc)
            cfg = mdis.dis_multiblock(addr)
            for irblock in cfg.blocks:
                lifter.add_asmblock_to_ircfg(irblock, ircfg)
            print(f'Disassembled {len(cfg.blocks):4} new blocks at {hex(addr)}.')

            irblock = ircfg.get_block(pc)
            assert(irblock is not None)

        for assignblk in irblock:
            modified = engine.eval_assignblk(assignblk)
            symb_trace.append((assignblk.instr.offset, modified))

            # Run a single instruction
            engine.eval_updt_assignblk(assignblk)

        symbolic_pc = engine.eval_expr(engine.lifter.IRDst)

        # If the resulting PC is an integer, i.e. a concrete address that can
        # be mapped to the assembly code, we return as we have reached the end
        # of a basic block. Otherwise we might have reached the end of an IR
        # block, in which case we keep executing until we reach the end of an
        # ASM block.
        try:
            return int(symbolic_pc), symb_trace
        except:
            # The new program counter might be a symbolic value. Try to evaluate
            # it based on the last recorded concrete state at the start of the
            # current basic block.
            pc = eval_expr(symbolic_pc, conc_state)

symb_trace = [] # The list of generated symbolic transforms per instruction

target = LLDBConcreteTarget(binary)
initial_state = create_state(target)

# Run until no more states can be reached
print(f'Re-tracing symbolically...')
while pc is not None:
    # Run symbolic execution
    pc, strace = run_block(pc, MiasmConcreteState(initial_state, loc_db))

    if pc is None:
        break

    # Step concrete target forward.
    #
    # The concrete target now lags behind the symbolic execution by exactly
    # one basic block: the one that we just executed. Find the next program
    # counter in the concrete trace and run the target up to it.
    try:
        # Find number of instructions in the executed basic block.
        # Start at index 1 in case the next program counter is the same as the
        # current one.
        pc_index = conc_trace.index(pc, 1)
    except ValueError:
        # End of concrete trace has been reached.
        symb_trace.extend(strace[:len(conc_trace)])
        print(f'Next PC {hex(pc)} is not contained in the concrete trace.')
        break

    step_through_trace(target, conc_trace[:pc_index])
    conc_trace = conc_trace[pc_index:]
    initial_state = create_state(target)

    # Sometimes, miasm generates ghost instructions at the end of basic blocks.
    # Don't include them in the symbolic trace.
    symb_trace.extend(strace[:pc_index])

print(f'--- {len(symb_trace)} instructions traced.')
print(f'--- No new PC found. Exiting.')
