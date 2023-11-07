import angr
import angr_targets
import claripy as cp
import sys

from lldb_target import LLDBConcreteTarget

from arancini import parse_break_addresses
from arch import x86

def print_state(state: angr.SimState, file=sys.stdout):
    print('-' * 80)
    print(f'State at {hex(state.addr)}:')
    print('-' * 80)
    for reg in x86.regnames:
        try:
            val = state.regs.__getattr__(reg.lower())
            print(f'{reg} = {val}', file=file)
        except angr.SimConcreteRegisterError: pass
        except angr.SimConcreteMemoryError: pass
        except AttributeError: pass
        except KeyError: pass

    # Print some of the stack
    rbp = state.regs.rbp
    stack_size = 0xc
    stack_mem = state.memory.load(rbp - stack_size, stack_size)
    #stack = state.solver.eval(stack_mem, cast_to=bytes)
    print()
    print(f'Stack:')
    print(stack_mem)
    #print(' '.join(f'{b:02x}' for b in stack[::-1]))
    print('-' * 80)

def copy_state(src: angr_targets.ConcreteTarget, dst: angr.SimState):
    """Copy a concrete program state to an `angr.SimState` object."""
    # Copy register contents
    for reg in x86.regnames:
        regname = reg.lower()
        try:
            dst.regs.__setattr__(regname, src.read_register(regname))
        except angr.SimConcreteRegisterError:
            # Register does not exist (i.e. "flag ZF")
            pass

    # Copy memory contents
    for mapping in src.get_mappings():
        addr = mapping.start_address
        size = mapping.end_address - mapping.start_address
        try:
            dst.memory.store(addr, src.read_memory(addr, size), size)
        except angr.SimConcreteMemoryError:
            # Invalid memory access
            pass

X86_DEFAULT_CONCRETE_REGS = ['PC', 'RBP', 'RSP']

def symbolize_state(state: angr.SimState,
                    exclude: list[str] = X86_DEFAULT_CONCRETE_REGS) \
        -> angr.SimState:
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

def output_truth(breakpoints: set[int]):
    import run
    res = run.run_native_execution(BINARY, breakpoints)
    with open('truth.log', 'w') as file:
        for snapshot in res:
            print(hex(snapshot.regs['PC']), file=file)

class ConcreteExecution:
    def __init__(self, executable: str, breakpoints: list[int]):
        self.target = LLDBConcreteTarget(executable)
        self.proj = angr.Project(executable,
                                 concrete_target=self.target,
                                 use_sim_procedures=False)

        # Set the initial state
        state = self.proj.factory.entry_state()
        state.options.add(angr.options.SYMBION_SYNC_CLE)
        state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
        self.simgr = self.proj.factory.simgr(state)
        self.simgr.use_technique(
            angr.exploration_techniques.Symbion(find=breakpoints))

    def is_running(self):
        return not self.target.is_exited()

    def step(self) -> angr.SimState | None:
        self.simgr.run()
        self.simgr.unstash(to_stash='active', from_stash='found')
        if len(self.simgr.active) > 0:
            state = self.simgr.active[0]
            print(f'-- Concrete execution hit a breakpoint at {state.regs.pc}!')
            return state
        return None

class SymbolicExecution:
    def __init__(self, executable: str):
        self.proj = angr.Project(executable, use_sim_procedures=False)

        start_state = self.proj.factory.entry_state()
        start_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        self.simgr = self.proj.factory.simgr(start_state)

    def is_running(self):
        return len(self.simgr.active) > 0

    def step(self, find) -> angr.SimState | None:
        depth = 0
        while True:
            self.simgr.explore(find=find)
            self.simgr.unstash(to_stash='active', from_stash='found')

            print(f'-- Symbolic execution stopped.')
            print(f'   Found the following stashes: {self.simgr.stashes}')

            if len(self.simgr.active) == 0:
                print(f'No states found.')
                return None

            for state in self.simgr.active:
                pc = state.addr
                assert(type(pc) is int)
                if pc == find:
                    same_addr = [s for s in self.simgr.active if s.addr == find]
                    if len(same_addr) > 1:
                        print(f'We have {len(same_addr)} possible states at'
                              ' the same address, which is a problem. Here are'
                              ' all of them:')
                        for s in same_addr:
                            print_state(s)
                        return same_addr[0]

                    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
                    self.simgr = self.proj.factory.simgr(state)
                    return state

            print(f'None of the available states are the one we\'re searching for!')
            depth += 1
            print(f'Stepping into depth {depth}...')

BINARY = 'trivial_program'
BREAKPOINT_LOG = 'breakpoints'

def main():
    # Read breakpoint addresses from a file
    with open(BREAKPOINT_LOG, 'r') as file:
        breakpoints = set([int(line, 16) for line in file.readlines()])
    print(f'Found {len(breakpoints)} breakpoints.')

    output_truth(breakpoints)

    conc = ConcreteExecution(BINARY, list(breakpoints))
    symb = SymbolicExecution(BINARY)

    print(f'Memory mappings: ')
    for mapping in conc.target.get_mappings():
        print(f' - {mapping}')

    conc_log = open('concrete.log', 'w')
    symb_log = open('symbolic.log', 'w')
    print(hex(conc.simgr.active[0].addr), file=conc_log)
    print(hex(symb.simgr.active[0].addr), file=symb_log)

    while True:
        if not (conc.is_running() and symb.is_running()):
            assert(not conc.is_running() and not symb.is_running())
            print(f'Execution has exited.')
            exit(0)

        # It seems that we have to copy the program's state manually to the
        # state handed to the symbolic engine, otherwise the program emulation
        # is incorrect. Something in angr's emulation is scuffed.
        copy_state(conc.target, symb.simgr.active[0])

        # angr performs a sanity check to ensure that the address at which the
        # concrete engine stops actually is one of the breakpoints specified by
        # the user. This sanity check is faulty because it is performed before
        # the user has a chance determine whether the program has exited. If
        # the program counter is read after the concrete execution has exited,
        # LLDB returns a null value and the check fails, resulting in a crash.
        # This try/catch block prevents that.
        #
        # As of angr commit `cbeace5d7`, this faulty read of the program
        # counter can be found at `angr/engines/concrete.py:148`.
        try:
            conc_state = conc.step()
            if conc_state is None:
                print(f'Execution has exited: ConcreteExecution.step() returned null.')
                exit(0)
        except angr.SimConcreteRegisterError:
            print(f'Done.')
            exit(0)

        pc = conc_state.addr
        print(f'-- Trying to find address {hex(pc)} with symbolic execution...')

        non_symbolized = ['PC', 'RBP', 'RSP']#, 'RAX', 'RBX', 'RCX', 'RDX']
        symb_state = symbolize_state(symb.simgr.active[0], exclude=non_symbolized)
        symb.simgr = symb.proj.factory.simgr(symb_state)
        symb_state = symb.step(pc)

        # Check exit conditions
        if symb_state is None:
            print(f'Execution has exited: SymbolicExecution.step() returned null.')
            exit(0)
        assert(pc == symb_state.addr)

        # Log some stuff
        print(f'-- Concrete breakpoint {conc_state.addr}'
              f' vs symbolic breakpoint {symb_state.addr}')

        print_state(symb_state)

        print(hex(conc_state.addr), file=conc_log)
        print(hex(symb_state.addr), file=symb_log)


if __name__ == "__main__":
    main()
