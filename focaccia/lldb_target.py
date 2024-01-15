import lldb

from .arch import supported_architectures, x86
from .snapshot import ProgramState

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
                                          argv, None,        # argv, envp
                                          None, None, None,  # stdin, stdout, stderr
                                          None,              # working directory
                                          0,
                                          True, self.error)
        if not self.process.IsValid():
            raise RuntimeError(f'[In LLDBConcreteTarget.__init__]: Failed to'
                               f' launch process.')

        self.archname = self.target.GetPlatform().GetTriple().split('-')[0]

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

    def record_snapshot(self) -> ProgramState:
        """Record the concrete target's state in a ProgramState object."""
        # Determine current arch
        if self.archname not in supported_architectures:
            print(f'[ERROR] LLDBConcreteTarget: Recording snapshots is not'
                  f' supported for architecture {self.archname}!')
            raise NotImplementedError()
        arch = supported_architectures[self.archname]

        state = ProgramState(arch)

        # Query and store register state
        for regname in arch.regnames:
            try:
                conc_val = self.read_register(regname)
                state.set(regname, conc_val)
            except KeyError:
                pass
            except ConcreteRegisterError:
                # Special rule for flags on X86
                if arch.archname == x86.archname:
                    rflags = x86.decompose_rflags(self.read_register('rflags'))
                    if regname in rflags:
                        state.set(regname, rflags[regname])

        # Query and store memory state
        for mapping in self.get_mappings():
            assert(mapping.end_address > mapping.start_address)
            size = mapping.end_address - mapping.start_address
            try:
                data = self.read_memory(mapping.start_address, size)
                state.write_memory(mapping.start_address, data)
            except ConcreteMemoryError:
                pass

        return state

    def _get_register(self, regname: str) -> lldb.SBValue:
        """Find a register by name.

        :raise ConcreteRegisterError: If no register with the specified name
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
        """Read the value of a register.

        :raise ConcreteRegisterError: If `regname` is not a valid register name
                                      or the target is otherwise unable to read
                                      the register's value.
        """
        reg = self._get_register(regname)
        val = reg.GetValue()
        if val is None:
            raise ConcreteRegisterError(
                f'[In LLDBConcreteTarget.read_register]: Register has an'
                f' invalid value of {val}.')

        return int(val, 16)

    def write_register(self, regname: str, value: int):
        """Read the value of a register.

        :raise ConcreteRegisterError: If `regname` is not a valid register name
                                      or the target is otherwise unable to set
                                      the register's value.
        """
        reg = self._get_register(regname)
        error = lldb.SBError()
        reg.SetValueFromCString(hex(value), error)
        if not error.success:
            raise ConcreteRegisterError(
                f'[In LLDBConcreteTarget.write_register]: Unable to set'
                f' {regname} to value {hex(value)}!')

    def read_memory(self, addr, size):
        """Read bytes from memory.

        :raise ConcreteMemoryError: If unable to read `size` bytes from `addr`.
        """
        err = lldb.SBError()
        content = self.process.ReadMemory(addr, size, err)
        if not err.success:
            raise ConcreteMemoryError(f'Error when reading {size} bytes at'
                                      f' address {hex(addr)}: {err}')
        return content

    def write_memory(self, addr, value: bytes):
        """Write bytes to memory.

        :raise ConcreteMemoryError: If unable to write at `addr`.
        """
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

    def set_breakpoint(self, addr):
        command = f'b -a {addr} -s {self.module.GetFileSpec().GetFilename()}'
        result = lldb.SBCommandReturnObject()
        self.interpreter.HandleCommand(command, result)

    def remove_breakpoint(self, addr):
        command = f'breakpoint delete {addr}'
        result = lldb.SBCommandReturnObject()
        self.interpreter.HandleCommand(command, result)
