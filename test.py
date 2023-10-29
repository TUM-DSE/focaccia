import angr
import angr_targets
import claripy as cp
import sys

from lldb_target import LLDBConcreteTarget

from arancini import parse_break_addresses
from arch import x86

def print_state(state, file=sys.stdout):
    for reg in x86.regnames:
        try:
            val = state.regs.__getattr__(reg.lower())
            print(f'{reg} = {val}', file=file)
        except angr.SimConcreteRegisterError:
            print(f'Unable to read value of register {reg}: register error',
                  file=file)
        except angr.SimConcreteMemoryError:
            print(f'Unable to read value of register {reg}: memory error',
                  file=file)
        except AttributeError:
            print(f'Unable to read value of register {reg}: AttributeError',
                  file=file)
        except KeyError:
            print(f'Unable to read value of register {reg}: KeyError',
                  file=file)

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

def symbolize_state(state: angr.SimState):
    for reg in x86.regnames:
        if reg != 'PC':
            symb_val = cp.BVS(reg, 64)
            try:
                state.regs.__setattr__(reg.lower(), symb_val)
            except AttributeError:
                pass

def output_truth(breakpoints: set[int]):
    import run
    res = run.run_native_execution(BINARY, breakpoints)
    with open('truth.log', 'w') as file:
        for snapshot in res:
            print(cp.BVV(snapshot.regs['PC'], 64), file=file)

BINARY = "hello-static-musl"
BREAKPOINT_LOG = "emulator-log.txt"

# Read breakpoint addresses from a file
with open(BREAKPOINT_LOG, "r") as file:
    breakpoints = parse_break_addresses(file.readlines())

print(f'Found {len(breakpoints)} breakpoints.')

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
        self.simgr = self.proj.factory.simgr(self.proj.factory.entry_state())

    def is_running(self):
        return len(self.simgr.active) > 0

    def step(self, find) -> angr.SimState | None:
        self.simgr.explore(find=find)
        self.simgr.unstash(to_stash='active', from_stash='found')
        if len(self.simgr.active) == 0:
            print(f'No states found. Stashes: {self.simgr.stashes}')
            return None

        state = self.simgr.active[0]
        assert(len(self.simgr.active) == 1)
        print(f'-- Symbolic execution stopped at {state.regs.pc}!')
        print(f'   Found the following stashes: {self.simgr.stashes}')

        return state

output_truth(breakpoints)

conc = ConcreteExecution(BINARY, list(breakpoints))
symb = SymbolicExecution(BINARY)

conc_log = open('concrete.log', 'w')
symb_log = open('symbolic.log', 'w')

while True:
    if not (conc.is_running() and symb.is_running()):
        assert(not conc.is_running() and not symb.is_running())
        print(f'Execution has exited.')
        exit(0)

    # It seems that we have to copy the program's state manually to the state
    # handed to the symbolic engine, otherwise the program emulation is
    # incorrect. Something in angr's emulation is scuffed.
    copy_state(conc.target, symb.simgr.active[0])

    # angr performs a sanity check to ensure that the address at which the
    # concrete engine stops actually is one of the breakpoints specified by
    # the user. This sanity check is faulty because it is performed before the
    # user has a chance determine whether the program has exited. If the
    # program counter is read after the concrete execution has exited, LLDB
    # returns a null value and the check fails, resulting in a crash. This
    # try/catch block prevents that.
    #
    # As of angr commit `cbeace5d7`, this faulty read of the program counter
    # can be found at `angr/engines/concrete.py:148`.
    try:
        conc_state = conc.step()
        if conc_state is None:
            print(f'Execution has exited: ConcreteExecution.step() returned null.')
            exit(0)
    except angr.SimConcreteRegisterError:
        print(f'Done.')
        exit(0)

    pc = conc_state.solver.eval(conc_state.regs.pc)
    print(f'-- Trying to find address {hex(pc)} with symbolic execution...')

    # TODO:
    #symbolize_state(symb.simgr.active[0])
    symb_state = symb.step(pc)

    # Check exit conditions
    if symb_state is None:
        print(f'Execution has exited: SymbolicExecution.step() returned null.')
        exit(0)
    assert(pc == symb_state.solver.eval(symb_state.regs.pc))

    # Log some stuff
    print(f'-- Concrete breakpoint {conc_state.regs.pc}'
          f' vs symbolic breakpoint {symb_state.regs.pc}')

    print(conc_state.regs.pc, file=conc_log)
    print(symb_state.regs.pc, file=symb_log)
