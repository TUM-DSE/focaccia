import angr
import argparse
import claripy as cp
import sys

from angr.exploration_techniques import Symbion
from arch import x86
from gen_trace import record_trace
from lldb_target import LLDBConcreteTarget

def print_state(state: angr.SimState, file=sys.stdout):
    """Print a program state in a fancy way."""
    print('-' * 80, file=file)
    print(f'State at {hex(state.addr)}:', file=file)
    print('-' * 80, file=file)
    for reg in x86.regnames:
        try:
            val = state.regs.__getattr__(reg.lower())
            print(f'{reg} = {val}', file=file)
        except angr.SimConcreteRegisterError: pass
        except angr.SimConcreteMemoryError: pass
        except AttributeError: pass
        except KeyError: pass

    # Print some of the stack
    print('\nStack:', file=file)
    try:
        rbp = state.regs.rbp
        stack_size = 0xc
        stack_mem = state.memory.load(rbp - stack_size, stack_size)
        print(stack_mem, file=file)
        stack = state.solver.eval(stack_mem, cast_to=bytes)
        print(' '.join(f'{b:02x}' for b in stack[::-1]), file=file)
    except angr.SimConcreteMemoryError:
        print('<unable to read memory>', file=file)
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

    stack_size = 0xc
    symb_stack = cp.BVS('stack', stack_size * 8)
    state.memory.store(state.regs.rbp - stack_size, symb_stack)

    _exclude = set(exclude)
    for reg in x86.regnames:
        if reg not in _exclude:
            symb_val = cp.BVS(reg, 64)
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
        print_state(symb_exploration.found[0], file=symb_log)

if __name__ == "__main__":
    main()
