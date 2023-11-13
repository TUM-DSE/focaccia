import argparse
import sys

import angr
import claripy as cp
from angr.exploration_techniques import Symbion

from arch import x86
from gen_trace import record_trace
from interpreter import eval, SymbolResolver, SymbolResolveError
from lldb_target import LLDBConcreteTarget
from symbolic import symbolize_state, collect_symbolic_trace

# Size of the memory region on the stack that is tracked symbolically
# We track [rbp - STACK_SIZE, rbp).
STACK_SIZE = 0x10

STACK_SYMBOL_NAME = 'stack'

class SimStateResolver(SymbolResolver):
    """A symbol resolver that resolves symbol names to program state in
    `angr.SimState` objects.
    """
    def __init__(self, state: angr.SimState):
        self._state = state

    def resolve(self, symbol_name: str) -> cp.ast.Base:
        # Process special (non-register) symbol names
        if symbol_name == STACK_SYMBOL_NAME:
            assert(self._state.regs.rbp.concrete)
            assert(type(self._state.regs.rbp.v) is int)
            rbp = self._state.regs.rbp.v
            return self._state.memory.load(rbp - STACK_SIZE, STACK_SIZE)

        # Try to interpret the symbol as a register name
        try:
            return self._state.regs.get(symbol_name.lower())
        except AttributeError:
            raise SymbolResolveError(symbol_name,
                                     f'[SimStateResolver]: No attribute'
                                     f' {symbol_name} in program state.')

def print_state(state: angr.SimState, file=sys.stdout, conc_state=None):
    """Print a program state in a fancy way.

    :param conc_state: Provide a concrete program state as a reference to
                       evaluate all symbolic values in `state` and print their
                       concrete values in addition to the symbolic expression.
    """
    if conc_state is not None:
        resolver = SimStateResolver(conc_state)
    else:
        resolver = None

    print('-' * 80, file=file)
    print(f'State at {hex(state.addr)}:', file=file)
    print('-' * 80, file=file)
    for reg in x86.regnames:
        try:
            val = state.regs.get(reg.lower())
        except angr.SimConcreteRegisterError: val = '<inaccessible>'
        except angr.SimConcreteMemoryError:   val = '<inaccessible>'
        except AttributeError:                val = '<inaccessible>'
        except KeyError:                      val = '<inaccessible>'
        if resolver is not None:
            concrete_value = eval(resolver, val)
            if type(concrete_value) is int:
                concrete_value = hex(concrete_value)
            print(f'{reg} = {val} ({concrete_value})', file=file)
        else:
            print(f'{reg} = {val}', file=file)

    # Print some of the stack
    print('\nStack:', file=file)
    try:
        # Ensure that the base pointer is concrete
        rbp = state.regs.rbp
        if not rbp.concrete:
            if resolver is None:
                raise SymbolResolveError(rbp,
                                         '[In print_state]: rbp is symbolic,'
                                         ' but no resolver is defined. Can\'t'
                                         ' print stack.')
            else:
                rbp = eval(resolver, rbp)

        stack_mem = state.memory.load(rbp - STACK_SIZE, STACK_SIZE)

        if resolver is not None:
            print(hex(eval(resolver, stack_mem)), file=file)
        print(stack_mem, file=file)
        stack = state.solver.eval(stack_mem, cast_to=bytes)
        print(' '.join(f'{b:02x}' for b in stack[::-1]), file=file)
    except angr.SimConcreteMemoryError:
        print('<unable to read stack memory>', file=file)
    print('-' * 80, file=file)

def parse_args():
    prog = argparse.ArgumentParser()
    prog.add_argument('binary', type=str)
    return prog.parse_args()

def collect_concrete_trace(binary: str) -> list[angr.SimState]:
    target = LLDBConcreteTarget(binary)
    proj = angr.Project(binary,
                        concrete_target=target,
                        use_sim_procedures=False)

    state = proj.factory.entry_state()
    state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
    state.options.add(angr.options.SYMBION_SYNC_CLE)

    result = []

    trace = record_trace(binary)
    for inst in trace:
        symbion = proj.factory.simgr(state)
        symbion.use_technique(Symbion(find=[inst]))

        conc_exploration = symbion.run()
        state = conc_exploration.found[0]
        result.append(state.copy())

    return result

def main():
    args = parse_args()
    binary = args.binary

    # Generate a program trace from a real execution
    concrete_trace = collect_concrete_trace(binary)
    trace = [int(state.addr) for state in concrete_trace]
    print(f'Found {len(trace)} trace points.')

    symbolic_trace = collect_symbolic_trace(binary, trace)

    with open('concrete.log', 'w') as conc_log:
        for state in concrete_trace:
            print_state(state, file=conc_log)
    with open('symbolic.log', 'w') as symb_log:
        for conc, symb in zip(concrete_trace, symbolic_trace):
            print_state(symb.state, file=symb_log, conc_state=conc)

if __name__ == "__main__":
    main()
    print('\nDone.')
