import argparse
import sys

import angr
import claripy as cp
from angr.exploration_techniques import Symbion

from arch import x86
from gen_trace import record_trace
from interpreter import eval, SymbolResolver, SymbolResolveError
from lldb_target import LLDBConcreteTarget

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
        assert(state.regs.rbp.concrete)
        stack_mem = state.memory.load(state.regs.rbp - STACK_SIZE, STACK_SIZE)
        if resolver is not None:
            print(hex(eval(resolver, stack_mem)), file=file)
        print(stack_mem, file=file)
        stack = state.solver.eval(stack_mem, cast_to=bytes)
        print(' '.join(f'{b:02x}' for b in stack[::-1]), file=file)
    except angr.SimConcreteMemoryError:
        print('<unable to read stack memory>', file=file)
    print('-' * 80, file=file)

def symbolize_state(state: angr.SimState,
                    exclude: list[str] = ['PC', 'RBP', 'RSP']) \
        -> angr.SimState:
    """Create a copy of a SimState and replace most of it with symbolic
    values.

    Leaves pc, rbp, and rsp concrete by default. This can be configured with
    the `exclude` parameter.

    :return: A symbolized SymState object.
    """
    state = state.copy()

    symb_stack = cp.BVS(STACK_SYMBOL_NAME, STACK_SIZE * 8, explicit_name=True)
    state.memory.store(state.regs.rbp - STACK_SIZE, symb_stack)

    _exclude = set(exclude)
    for reg in x86.regnames:
        if reg not in _exclude:
            symb_val = cp.BVS(reg, 64, explicit_name=True)
            try:
                state.regs.__setattr__(reg.lower(), symb_val)
            except AttributeError:
                pass
    return state

def parse_args():
    prog = argparse.ArgumentParser()
    prog.add_argument('binary', type=str)
    return prog.parse_args()

def main():
    args = parse_args()
    binary = args.binary

    conc_log = open('concrete.log', 'w')
    symb_log = open('symbolic.log', 'w')

    # Generate a program trace from a real execution
    trace = record_trace(binary)
    print(f'Found {len(trace)} trace points.')

    target = LLDBConcreteTarget(binary)
    proj = angr.Project(binary,
                        concrete_target=target,
                        use_sim_procedures=False)

    entry_state = proj.factory.entry_state()
    entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
    entry_state.options.add(angr.options.SYMBION_SYNC_CLE)

    for cur_inst, next_inst in zip(trace[0:-1], trace[1:]):
        symbion = proj.factory.simgr(entry_state)
        symbion.use_technique(Symbion(find=[cur_inst]))

        conc_exploration = symbion.run()
        conc_state = conc_exploration.found[0]

        # Start symbolic execution with the concrete ('truth') state and try
        # to reach the next instruction in the trace
        simgr = proj.factory.simgr(symbolize_state(conc_state))
        symb_exploration = simgr.explore(find=next_inst)
        if len(symb_exploration.found) == 0:
            print(f'Symbolic execution can\'t reach address {hex(next_inst)}'
                  f' from {hex(cur_inst)}. Exiting.')
            exit(1)

        print_state(conc_state, file=conc_log)
        print_state(symb_exploration.found[0], file=symb_log, conc_state=conc_state)

if __name__ == "__main__":
    main()
