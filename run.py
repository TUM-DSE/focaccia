"""Functionality to execute native programs and collect snapshots via lldb."""

import re
import sys
import lldb
from typing import Callable

# TODO: The debugger callback is currently specific to a single architexture.
#       We should make it generic.
from arch import x86
from utils import print_separator

verbose = False

class DebuggerCallback:
    """At every breakpoint, writes register contents to a stream."""

    def __init__(self, ostream=sys.stdout):
        self.stream = ostream
        self.regex = re.compile('(' + '|'.join(x86.regnames) + ')$')

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

    def print_regs(self, frame):
        for reg in frame.GetRegisters():
            for sub_reg in reg:
                match = self.regex.match(sub_reg.GetName().upper())
                if match and match.group() == 'RFLAGS':
                    flags = DebuggerCallback.parse_flags(int(sub_reg.GetValue(),
                                                             base=16))
                    for flag in flags:
                        print(f'flag {flag}:\t{hex(flags[flag])}',
                                                     file=self.stream)
                elif match:
                    print(f"{sub_reg.GetName().upper()}:\t\t {hex(int(sub_reg.GetValue(), base=16))}",
                          file=self.stream)

    def print_stack(self, frame, element_count: int):
        first = True
        for i in range(element_count):
            addr = frame.GetSP() + i * frame.GetThread().GetProcess().GetAddressByteSize()
            error = lldb.SBError()
            stack_value = int(frame.GetThread().GetProcess().ReadPointerFromMemory(addr, error))
            if error.Success() and not first:
                print(f'{hex(stack_value)}', file=self.stream)
            elif error.Success():
                print(f'{hex(stack_value)}\t\t<- rsp', file=self.stream)
            else:
                print(f"Error reading memory at address 0x{addr:x}",
                      file=self.stream)
            first=False

    def __call__(self, frame):
        pc = frame.GetPC()

        print_separator('=', stream=self.stream, count=20)
        print(f'INVOKE PC={hex(pc)}', file=self.stream)
        print_separator('=', stream=self.stream, count=20)

        print("Register values:", file=self.stream)
        self.print_regs(frame)
        print_separator(stream=self.stream)

        print("STACK:", file=self.stream)
        self.print_stack(frame, 20)

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

        if verbose:
            print(f'Set breakpoint at address {hex(address)}')

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

        self.debugger.Terminate()

        print(f'Process state: {process.GetState()}')
        print('Program output:')
        print(process.GetSTDOUT(1024))
        print(process.GetSTDERR(1024))

class ListWriter:
    def __init__(self):
        self.data = []

    def write(self, s):
        self.data.append(s)

    def __str__(self):
        return "".join(self.data)

def run_native_execution(oracle_program: str, breakpoints: set[int]):
    """Gather snapshots from a native execution via an external debugger.

    :param oracle_program: Program to execute.
    :param breakpoints: List of addresses at which to break and record the
                        program's state.

    :return: A textual log of the program's execution in arancini's log format.
    """
    debugger = Debugger(oracle_program)
    writer = ListWriter()

    # Set breakpoints
    for address in breakpoints:
        debugger.set_breakpoint_by_addr(address)
    assert(debugger.get_breakpoints_count() == len(breakpoints))

    # Execute the native program
    debugger.execute(DebuggerCallback(writer))

    return writer.data
