"""Functionality to execute native programs and collect snapshots via lldb."""

import platform
import sys
import lldb
from typing import Callable

# TODO: The debugger callback is currently specific to a single architecture.
#       We should make it generic.
from arch import Arch, x86
from snapshot import ProgramState

class SnapshotBuilder:
    """At every breakpoint, writes register contents to a stream.

    Generated snapshots are stored in and can be read from `self.states`.
    """
    def __init__(self, arch: Arch):
        self.arch = arch
        self.states = []
        self.regnames = set(arch.regnames)

    @staticmethod
    def parse_flags(flag_reg: int):
        flags = {'ZF': 0,
                 'CF': 0,
                 'OF': 0,
                 'SF': 0,
                 'PF': 0,
                 'DF': 0}

        # CF (Carry flag) Bit 0
        # PF (Parity flag) Bit 2
        # ZF (Zero flag) Bit 6
        # SF (Sign flag) Bit 7
        # TF (Trap flag) Bit 8
        # IF (Interrupt enable flag) Bit 9
        # DF (Direction flag) Bit 10
        # OF (Overflow flag) Bit 11
        flags['CF'] = int(0 != flag_reg & 1)
        flags['ZF'] = int(0 != flag_reg & (1 << 6))
        flags['OF'] = int(0 != flag_reg & (1 << 11))
        flags['SF'] = int(0 != flag_reg & (1 << 7))
        flags['DF'] = int(0 != flag_reg & (1 << 10))
        flags['PF'] = int(0 != flag_reg & (1 << 1))
        return flags

    def create_snapshot(self, frame):
        state = ProgramState(self.arch)
        state.set('PC', frame.GetPC())
        for reg in frame.GetRegisters():
            for sub_reg in reg:
                # Set the register's value in the current snapshot
                regname = sub_reg.GetName().upper()
                if regname in self.regnames:
                    regval = int(sub_reg.GetValue(), base=16)
                    if regname == 'RFLAGS':
                        flags = SnapshotBuilder.parse_flags(regval)
                        for flag, val in flags.items():
                            state.set(f'flag {flag}', val)
                    else:
                        state.set(regname, regval)
        return state

    def __call__(self, frame):
        snapshot = self.create_snapshot(frame)
        self.states.append(snapshot)

class Debugger:
    def __init__(self, program):
        self.debugger = lldb.SBDebugger.Create()
        self.debugger.SetAsync(False)
        self.target = self.debugger.CreateTargetWithFileAndArch(program,
                                                                lldb.LLDB_ARCH_DEFAULT)
        self.module = self.target.FindModule(self.target.GetExecutable())
        self.interpreter = self.debugger.GetCommandInterpreter()

    def set_breakpoint_by_addr(self, address: int):
        command = f"b -a {address} -s {self.module.GetFileSpec().GetFilename()}"
        result = lldb.SBCommandReturnObject()
        self.interpreter.HandleCommand(command, result)

    def get_breakpoints_count(self):
        return self.target.GetNumBreakpoints()

    def execute(self, callback: Callable):
        error = lldb.SBError()
        listener = self.debugger.GetListener()
        process = self.target.Launch(listener, None, None, None, None, None, None, 0,
                                     True, error)

        # Check if the process has launched successfully
        if process.IsValid():
            print(f'Launched process: {process}')
        else:
            print('Failed to launch process', file=sys.stderr)

        while True:
            state = process.GetState()
            if state == lldb.eStateStopped:
                 for thread in process:
                    callback(thread.GetFrameAtIndex(0))
                 process.Continue()
            if state == lldb.eStateExited:
                break

        print(f'Process state: {process.GetState()}')
        print('Program output:')
        print(process.GetSTDOUT(1024))
        print(process.GetSTDERR(1024))

def run_native_execution(oracle_program: str, breakpoints: set[int]):
    """Gather snapshots from a native execution via an external debugger.

    :param oracle_program: Program to execute.
    :param breakpoints: List of addresses at which to break and record the
                        program's state.

    :return: A list of snapshots gathered from the execution.
    """
    assert(platform.machine() == "x86_64")

    debugger = Debugger(oracle_program)

    # Set breakpoints
    for address in breakpoints:
        debugger.set_breakpoint_by_addr(address)
    assert(debugger.get_breakpoints_count() == len(breakpoints))

    # Execute the native program
    builder = SnapshotBuilder(x86.ArchX86())
    debugger.execute(builder)

    return builder.states
