"""Tools and utilities for symbolic execution with angr."""

import angr
import claripy as cp
from angr.exploration_techniques import Symbion

from arch import Arch, x86
from interpreter import eval as eval_symbol, SymbolResolver
from lldb_target import LLDBConcreteTarget

def symbolize_state(state: angr.SimState,
                    arch: Arch = x86.ArchX86(),
                    exclude: list[str] = ['RIP', 'RBP', 'RSP'],
                    stack_name: str = 'stack',
                    stack_size: int = 0x10) \
        -> angr.SimState:
    """Create a copy of a SimState and replace most of it with symbolic
    values.

    Leaves pc, rbp, and rsp concrete by default. This can be configured with
    the `exclude` parameter. Add the string 'stack' to the exclude list to
    prevent stack memory from being replaced with a symbolic buffer.

    :return: A symbolized SymState object.
    """
    _exclude = set(exclude)
    state = state.copy()

    if stack_name not in _exclude:
        symb_stack = cp.BVS(stack_name, stack_size * 8, explicit_name=True)
        state.memory.store(state.regs.rsp - stack_size, symb_stack)

    for reg in arch.regnames:
        if reg not in _exclude:
            symb_val = cp.BVS(reg, 64, explicit_name=True)
            try:
                state.regs.__setattr__(reg.lower(), symb_val)
            except AttributeError:
                pass
    return state

class SymbolicTransform:
    def __init__(self,
                 state: angr.SimState,
                 first_inst: int,
                 last_inst: int,
                 end_inst: int):
        """
        :param state: The symbolic transformation in the form of a SimState
                      object.
        :param first_inst: An instruction address. The transformation operates
                           on the program state *before* this instruction is
                           executed.
        :param last_inst:  An instruction address. The last instruction that
                           is included in the transformation. This may be equal
                           to `prev_state` if the `SymbolicTransform`
                           represents the work done by a single instruction.
                           The transformation includes all instructions in the
                           range `[first_inst, last_inst]` (note the inclusive
                           right bound) of the specific program trace.
        :param end_inst:   An instruction address. The address of the *next*
                           instruction executed on the state that results from
                           the transformation.
        """
        self.state = state
        self.start_addr = first_inst
        self.last_inst = last_inst
        self.end_addr = end_inst

    def eval_register_transform(self, regname: str, resolver: SymbolResolver):
        """
        :param regname:  Name of the register to evaluate.
        :param resolver: A provider for the values to be plugged into the
                         symbolic equation.

        :raise angr.SimConcreteRegisterError: If the state contains no register
                                              named `regname`.
        """
        return eval_symbol(resolver, self.state.regs.get(regname))

    def __repr__(self) -> str:
        return f'Symbolic state transformation: \
                 {hex(self.start_addr)} -> {hex(self.end_addr)}'

def collect_symbolic_trace(binary: str, trace: list[int]) \
    -> list[SymbolicTransform]:
    """Execute a program and compute state transformations between executed
    instructions.

    :param binary: The binary to trace.
    :param trace:  A program trace that symbolic execution shall follow.
    """
    target = LLDBConcreteTarget(binary)
    proj = angr.Project(binary,
                        concrete_target=target,
                        use_sim_procedures=False)

    entry_state = proj.factory.entry_state(addr=trace[0])
    entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
    entry_state.options.add(angr.options.SYMBION_SYNC_CLE)

    # We keep a history of concrete states at their addresses because of the
    # backtracking approach described below.
    concrete_states = {}

    # All recorded symbolic transformations
    result = []

    for (cur_idx, cur_inst), next_inst in zip(enumerate(trace[0:-1]), trace[1:]):
        # The last instruction included in the generated transformation
        last_inst = cur_inst

        symbion = proj.factory.simgr(entry_state)
        symbion.use_technique(Symbion(find=[cur_inst]))

        try:
            if cur_inst != entry_state.addr:
                conc_exploration = symbion.run()
            else:
                symbion.move('active', 'found')
                conc_exploration = symbion
        except angr.AngrError as err:
            print(f'Angr error: {err} Returning partial result.')
            return result
        conc_state = conc_exploration.found[0]
        entry_state = conc_state

        concrete_states[conc_state.addr] = conc_state.copy()

        # Start symbolic execution with the concrete ('truth') state and try
        # to reach the next instruction in the trace
        #
        # -- Notes --
        # It does not even work when I feed the entirely concrete state
        # `conc_state` that I receive from Symbion into the symbolic simgr.
        simgr = proj.factory.simgr(symbolize_state(conc_state))
        symb_exploration = simgr.explore(find=next_inst)

        # Symbolic execution can't handle starting at some jump instructions.
        # When this occurs, we re-start symbolic execution at an earlier
        # instruction.
        #
        # Example:
        #   0x401155      cmp   -0x4(%rbp),%eax
        #   0x401158      jle   0x401162
        #   ...
        #   0x401162      addl  $0x1337,-0xc(%rbp)
        #
        # Here, symbolic execution can't find a valid state at `0x401162` when
        # starting at `0x401158`, but it finds it successfully when starting at
        # `0x401155`.
        while len(symb_exploration.found) == 0 and cur_idx > 0:
            print(f'[INFO] Symbolic execution can\'t reach address'
                  f' {hex(next_inst)} from {hex(cur_inst)}.'
                  f' Attempting to reach it from {hex(trace[cur_idx - 1])}...')
            cur_idx -= 1
            cur_inst = trace[cur_idx]
            conc_state = concrete_states[cur_inst]
            simgr = proj.factory.simgr(symbolize_state(conc_state))
            symb_exploration = simgr.explore(find=next_inst)

        if len(symb_exploration.found) == 0:
            print(f'Symbolic execution can\'t reach address {hex(next_inst)}.'
                  ' Exiting.')
            exit(1)

        result.append(SymbolicTransform(
            symb_exploration.found[0],
            cur_inst,
            last_inst,
            next_inst
        ))

    return result
