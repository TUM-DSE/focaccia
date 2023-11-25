import sys

import IPython

from miasm.arch.x86.sem import Lifter_X86_64
from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container, ContainerELF
from miasm.core.asmblock import disasmEngine, AsmCFG
from miasm.core.interval import interval
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import ExprId, ExprInt, ExprLoc
from miasm.ir.symbexec import SymbolicExecutionEngine, SymbolicState
from miasm.ir.ir import IRBlock, AsmBlock
from miasm.analysis.dse import DSEEngine

from lldb_target import LLDBConcreteTarget, SimConcreteMemoryError, \
                        SimConcreteRegisterError
from arch import x86
from miasm_util import MiasmProgramState, eval_expr

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

def decompose_rflags(rflags: int) -> dict[str, int]:
    """Decompose the RFLAGS register's value into its separate flags.

    :param rflags: The RFLAGS register value.
    :return: A dictionary mapping Miasm's flag names to their values.
    """
    return {
        # FLAGS
        'cf':     rflags & 0x0001,
        # reserved         0x0002
        'pf':     rflags & 0x0004,
        # reserved         0x0008
        'af':     rflags & 0x0010,
        # reserved         0x0020
        'zf':     rflags & 0x0040,
        'nf':     rflags & 0x0080,   # I think NF (Negative Flag) == SF (Sign Flag)?
        'tf':     rflags & 0x0100,
        'i_f':    rflags & 0x0200,
        'df':     rflags & 0x0400,
        'of':     rflags & 0x0800,
        'iopl_f': rflags & 0x3000,
        'nt':     rflags & 0x4000,

        # EFLAGS
        'rf':     rflags & 0x00010000,
        'vm':     rflags & 0x00020000,
        'ac':     rflags & 0x00040000,
        'vif':    rflags & 0x00080000,
        'vip':    rflags & 0x00100000,
        'i_d':    rflags & 0x00200000,
    }

def disasm_elf(addr, mdis: disasmEngine) -> AsmCFG:
    """Try to disassemble all contents of an ELF file.

    Based on the full-disassembly algorithm in
    `https://github.com/cea-sec/miasm/blob/master/example/disasm/full.py`
    (as of commit `a229f4e`).

    :return: An asmcfg.
    """
    # Settings for the engine
    mdis.follow_call = True

    # Initial run
    asmcfg = mdis.dis_multiblock(addr)

    todo = [addr]
    done = set()
    done_interval = interval()

    while todo:
        while todo:
            ad = todo.pop(0)
            if ad in done:
                continue
            done.add(ad)
            asmcfg = mdis.dis_multiblock(ad, asmcfg)

            for block in asmcfg.blocks:
                for l in block.lines:
                    done_interval += interval([(l.offset, l.offset + l.l)])

            # Process recursive functions
            for block in asmcfg.blocks:
                instr = block.get_subcall_instr()
                if not instr:
                    continue
                for dest in instr.getdstflow(mdis.loc_db):
                    if not dest.is_loc():
                        continue
                    offset = mdis.loc_db.get_location_offset(dest.loc_key)
                    todo.append(offset)

        # Disassemble all:
        for _, b in done_interval.intervals:
            if b in done:
                continue
            todo.append(b)

    return asmcfg

def create_state(target: LLDBConcreteTarget) -> MiasmProgramState:
    regs: dict[ExprId, ExprInt] = {}
    mem = []

    # Query and store register state
    rflags = decompose_rflags(target.read_register('rflags'))
    for reg in machine.mn.regs.all_regs_ids_no_alias:
        try:
            conc_val = target.read_register(reg.name)
            regs[reg] = ExprInt(conc_val, reg.size)
        except SimConcreteRegisterError:
            if reg.name in rflags:
                regs[reg] = ExprInt(rflags[reg.name], reg.size)

    # Query and store memory state
    for mapping in target.get_mappings():
        assert(mapping.end_address > mapping.start_address)
        size = mapping.end_address - mapping.start_address
        try:
            mem_state = target.read_memory(mapping.start_address, size)
        except SimConcreteMemoryError:
            mem_state = f'<unable to access "{mapping.name}">'
        mem.append((mapping, mem_state))

    return MiasmProgramState(regs, mem)

binary = 'test_program'

loc_db = LocationDB()
cont = ContainerELF.from_stream(open(binary, 'rb'), loc_db)
machine = Machine(cont.arch)

pc = int(cont.entry_point)

# Disassemble binary
print(f'Disassembling "{binary}"...')
mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)
asmcfg = disasm_elf(pc, mdis)
with open('full_disasm', 'w') as file:
    print(f'Entry point: {hex(pc)}\n', file=file)
    print_blocks(asmcfg, file)
print(f'--- Disassembled "{binary}". Log written to "full_disasm.log".')

# Lift disassembly to IR
print(f'Lifting disassembly to IR...')
lifter: Lifter_X86_64 = machine.lifter(loc_db)
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
with open('full_ir', 'w') as file:
    print('=' * 80, file=file)
    for block in ircfg.blocks.values():
        print(block, file=file)
        print('-' * 60, file=file)
    print('=' * 80, file=file)
print(f'--- Lifted disassembly to IR. Log written to "full_ir.log".')

def record_concrete_states(binary):
    states = {}
    target = LLDBConcreteTarget(binary)
    while not target.is_exited():
        states[target.read_register('pc')] = create_state(target)
        target.step()
    return states

print(f'Recording concrete program trace...')
conc_states = record_concrete_states(binary)
print(f'Recorded {len(conc_states)} trace points.')

def run_block(pc: int, conc_state: MiasmProgramState) -> int | None:
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

    while True:
        symbolic_pc = engine.run_block_at(ircfg, pc)

        # The new program counter might be a symbolic value. Try to evaluate
        # it based on the last recorded concrete state at the start of the
        # current basic block.
        pc = eval_expr(symbolic_pc, conc_state, loc_db)
        if ircfg.get_block(pc) is None:
            print(f'Unable to access IR block at PC {pc}'
                  f' (evaluated from the expression PC = {symbolic_pc}).')
            return None

        # If the resulting PC is an integer, i.e. a concrete address that can
        # be mapped to the assembly code, we return as we have reached the end
        # of a basic block. Otherwise we might have reached the end of an IR
        # block, in which case we keep executing until we reach the end of an
        # ASM block.
        try:
            return int(symbolic_pc)
        except:
            pass

last_pc = None  # Debugging info

# Run until no more states can be reached
print(f'Re-tracing symbolically...')
while pc is not None:
    assert(type(pc) is int)
    if pc not in conc_states:
        print(f'Next PC {hex(pc)} is not contained in the concrete program'
              f' trace. Last valid PC: {hex(last_pc)}')
        break
    last_pc = pc

    initial_state = conc_states[pc]
    pc = run_block(pc, initial_state)

print(f'--- No new PC found. Exiting.')
