import lldb

from arch import x86
from snapshot import ProgramState

class MemoryMap:
    """Description of a range of mapped memory.

    Inspired by https://github.com/angr/angr-targets/blob/master/angr_targets/memory_map.py,
    meaning we initially used angr and I wanted to keep the interface when we
    switched to a different tool.
    """
    def __init__(self, start_address, end_address, name, perms):
        self.start_address = start_address
        self.end_address = end_address
        self.name = name
        self.perms = perms

    def __str__(self):
        return f'MemoryMap[0x{self.start_address:x}, 0x{self.end_address:x}]' \
               f': {self.name}'

class ConcreteRegisterError(Exception):
    pass

class ConcreteMemoryError(Exception):
    pass

class LLDBConcreteTarget:
    def __init__(self, executable: str, argv: list[str] = []):
        """Construct an LLDB concrete target. Stop at entry.

        :param argv: The full argv array, including the executable's path as
                     the first argument (as is convention).

        :raises RuntimeError: If the process is unable to launch.
        """
        self.debugger = lldb.SBDebugger.Create()
        self.debugger.SetAsync(False)
        self.target = self.debugger.CreateTargetWithFileAndArch(executable,
                                                                lldb.LLDB_ARCH_DEFAULT)
        self.module = self.target.FindModule(self.target.GetExecutable())
        self.interpreter = self.debugger.GetCommandInterpreter()

        # Set up objects for process execution
        self.error = lldb.SBError()
        self.listener = self.debugger.GetListener()
        self.process = self.target.Launch(self.listener,
                                          argv, None, None,
                                          None, None, None, 0,
                                          True, self.error)
        if not self.process.IsValid():
            raise RuntimeError(f'[In LLDBConcreteTarget.__init__]: Failed to'
                               f' launch process.')

    def set_breakpoint(self, addr):
        command = f'b -a {addr} -s {self.module.GetFileSpec().GetFilename()}'
        result = lldb.SBCommandReturnObject()
        self.interpreter.HandleCommand(command, result)

    def remove_breakpoint(self, addr):
        command = f'breakpoint delete {addr}'
        result = lldb.SBCommandReturnObject()
        self.interpreter.HandleCommand(command, result)

    def is_exited(self):
        """Signals whether the concrete process has exited.

        :return: True if the process has exited. False otherwise.
        """
        return self.process.GetState() == lldb.eStateExited

    def run(self):
        """Continue execution of the concrete process."""
        state = self.process.GetState()
        if state == lldb.eStateExited:
            raise RuntimeError(f'Tried to resume process execution, but the'
                               f' process has already exited.')
        assert(state == lldb.eStateStopped)
        self.process.Continue()

    def step(self):
        """Step forward by a single instruction."""
        thread: lldb.SBThread = self.process.GetThreadAtIndex(0)
        thread.StepInstruction(False)

    def _get_register(self, regname: str) -> lldb.SBValue:
        """Find a register by name.

        :raise SimConcreteRegisterError: If no register with the specified name
                                         can be found.
        """
        frame = self.process.GetThreadAtIndex(0).GetFrameAtIndex(0)
        reg = frame.FindRegister(regname)
        if reg is None:
            raise ConcreteRegisterError(
                f'[In LLDBConcreteTarget._get_register]: Register {regname}'
                f' not found.')
        return reg

    def read_register(self, regname: str) -> int:
        reg = self._get_register(regname)
        val = reg.GetValue()
        if val is None:
            raise ConcreteRegisterError(
                f'[In LLDBConcreteTarget.read_register]: Register has an'
                f' invalid value of {val}.')

        return int(val, 16)

    def write_register(self, regname: str, value: int):
        reg = self._get_register(regname)
        error = lldb.SBError()
        reg.SetValueFromCString(hex(value), error)
        if not error.success:
            raise ConcreteRegisterError(
                f'[In LLDBConcreteTarget.write_register]: Unable to set'
                f' {regname} to value {hex(value)}!')

    def read_memory(self, addr, size):
        err = lldb.SBError()
        content = self.process.ReadMemory(addr, size, err)
        if not err.success:
            raise ConcreteMemoryError(f'Error when reading {size} bytes at'
                                         f' address {hex(addr)}: {err}')
        return content

    def write_memory(self, addr, value):
        err = lldb.SBError()
        res = self.process.WriteMemory(addr, value, err)
        if not err.success or res != len(value):
            raise ConcreteMemoryError(f'Error when writing to address'
                                         f' {hex(addr)}: {err}')

    def get_mappings(self) -> list[MemoryMap]:
        mmap = []

        region_list = self.process.GetMemoryRegions()
        for i in range(region_list.GetSize()):
            region = lldb.SBMemoryRegionInfo()
            region_list.GetMemoryRegionAtIndex(i, region)

            perms = f'{"r" if region.IsReadable() else "-"}' \
                    f'{"w" if region.IsWritable() else "-"}' \
                    f'{"x" if region.IsExecutable() else "-"}'
            name = region.GetName()

            mmap.append(MemoryMap(region.GetRegionBase(),
                                  region.GetRegionEnd(),
                                  name if name is not None else '<none>',
                                  perms))
        return mmap

def record_snapshot(target: LLDBConcreteTarget) -> ProgramState:
    """Record a concrete target's state in a ProgramState object.

    :param target: The target from which to query state. Currently assumes an
                   X86 target.
    """
    state = ProgramState(x86.ArchX86())

    # Query and store register state
    rflags = x86.decompose_rflags(target.read_register('rflags'))
    for regname in x86.regnames:
        try:
            conc_val = target.read_register(regname)
            state.set(regname, conc_val)
        except KeyError:
            pass
        except ConcreteRegisterError:
            if regname in rflags:
                state.set(regname, rflags[regname])

    # Query and store memory state
    for mapping in target.get_mappings():
        assert(mapping.end_address > mapping.start_address)
        size = mapping.end_address - mapping.start_address
        try:
            data = target.read_memory(mapping.start_address, size)
            state.write_memory(mapping.start_address, data)
        except ConcreteMemoryError:
            # Unable to read memory from mapping
            pass

    return state
