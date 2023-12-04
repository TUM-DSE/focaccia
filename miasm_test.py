import sys
import time

from miasm.analysis.binary import ContainerELF
from miasm.analysis.machine import Machine
from miasm.arch.x86.sem import Lifter_X86_64
from miasm.core.asmblock import AsmCFG
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine, SymbolicState

from arch import x86
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

def step_until(target: LLDBConcreteTarget, addr: int) -> list[int]:
    """Step a concrete target to a specific instruction.
    :return: Trace of all instructions executed.
    """
    trace = [target.read_register('pc')]
    target.step()
    while not target.is_exited() and target.read_register('pc') != addr:
        trace.append(target.read_register('pc'))
        target.step()
    return trace

def create_state(target: LLDBConcreteTarget) -> ProgramState:
    def standardize_flag_name(regname: str) -> str:
        regname = regname.upper()
        if regname in MiasmConcreteState.miasm_flag_aliases:
            return MiasmConcreteState.miasm_flag_aliases[regname]
        return regname

    state = ProgramState(x86.ArchX86())

    # Query and store register state
    rflags = x86.decompose_rflags(target.read_register('rflags'))
    for regname in x86.regnames:
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

symb_exec_time = 0
conc_exec_time = 0
disasm_time = 0

total_time_start = time.perf_counter_ns()

binary = sys.argv[1]

loc_db = LocationDB()
cont = ContainerELF.from_stream(open(binary, 'rb'), loc_db)
machine = Machine(cont.arch)

pc = int(cont.entry_point)
if len(sys.argv) > 2:
    pc = int(sys.argv[2], 16)

# Create disassembly/lifting context
mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)
mdis.follow_call = True
asmcfg = AsmCFG(loc_db)

lifter: Lifter_X86_64 = machine.lifter(loc_db)
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

# TODO: To implement support for unimplemented instructions, add their
# ASM->IR implementations to the `mnemo_func` array in
# `miasm/arch/x86/sem.py:5142`.
#
# For XGETBV, I might have to add the extended control register XCR0 first.
# This might be a nontrivial patch to Miasm.

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
            disasm_time_start = time.perf_counter_ns()
            cfg = mdis.dis_multiblock(pc)
            for irblock in cfg.blocks:
                lifter.add_asmblock_to_ircfg(irblock, ircfg)
            disasm_time += time.perf_counter_ns() - disasm_time_start
            print(f'Disassembled {len(cfg.blocks):4} new blocks at {hex(int(pc))}.')

            irblock = ircfg.get_block(pc)
            assert(irblock is not None)

        # Execute each instruction in the current basic block and record the
        # resulting change in program state.
        symb_exec_time_start = time.perf_counter_ns()
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

        symb_exec_time += time.perf_counter_ns() - symb_exec_time_start

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

symb_trace = [] # The list of generated symbolic transforms per instruction

conc_exec_time_start = time.perf_counter_ns()
target = LLDBConcreteTarget(binary)
initial_state = create_state(target)
conc_exec_time += time.perf_counter_ns() - conc_exec_time_start

if target.read_register('pc') != pc:
    target.set_breakpoint(pc)
    target.run()
    target.remove_breakpoint(pc)

# Run until no more states can be reached
print(f'Re-tracing symbolically...')
while pc is not None:
    assert(target.read_register('pc') == pc)

    # Run symbolic execution
    # It uses the concrete state to resolve symbolic program counters to
    # concrete values.
    pc, strace = run_block(pc, MiasmConcreteState(initial_state, loc_db))

    if pc is None:
        break

    # Step concrete target forward.
    #
    # The concrete target now lags behind the symbolic execution by exactly
    # one basic block: the one that we just executed. Run the concrete
    # execution until it reaches the new PC.
    conc_exec_time_start = time.perf_counter_ns()
    ctrace = step_until(target, pc)
    conc_exec_time += time.perf_counter_ns() - conc_exec_time_start

    # Sometimes, miasm generates ghost instructions at the end of basic blocks.
    # Don't include them in the symbolic trace.
    strace = strace[:len(ctrace)]
    symb_trace.extend(strace)

    # Use this for extensive trace debugging
    if [a for a, _ in strace] != ctrace:
        print(f'[WARNING] Symbolic trace and concrete trace are not equal!'
              f'\n    symbolic: {[hex(a) for a, _ in strace]}'
              f'\n    concrete: {[hex(a) for a in ctrace]}')

    if target.is_exited():
        print(f'Next PC {hex(pc)} is not contained in the concrete trace.')
        break

    # Query the new reference state for symbolic execution
    conc_exec_time_start = time.perf_counter_ns()
    initial_state = create_state(target)
    conc_exec_time += time.perf_counter_ns() - conc_exec_time_start

total_time = time.perf_counter_ns() - total_time_start
other_time = total_time - symb_exec_time - conc_exec_time - disasm_time

print(f'--- {len(symb_trace)} instructions traced.')
print(f'--- No new PC found. Exiting.')
print()
print(f' Total time:              {total_time * 1e-6:10.3f} ms')
print(f' Disassembly time:        {disasm_time * 1e-6:10.3f} ms')
print(f' Symbolic execution time: {symb_exec_time * 1e-6:10.3f} ms')
print(f' Concrete execution time: {conc_exec_time * 1e-6:10.3f} ms')
print(f' Other:                   {other_time * 1e-6:10.3f} ms')
