import lldb

from angr.errors import SimConcreteMemoryError, \
                        SimConcreteRegisterError
from angr_targets.concrete import ConcreteTarget
from angr_targets.memory_map import MemoryMap

class LLDBConcreteTarget(ConcreteTarget):
    def __init__(self, executable: str, args: list[str] = []):
        # Prepend the executable's path to argv, as is convention
        args.insert(0, executable)

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
                                          args, None, None,
                                          None, None, None, 0,
                                          True, self.error)
        if not self.process.IsValid():
            raise RuntimeError(f'[In LLDBConcreteTarget.__init__]: Failed to'
                               f' launch process.')

    def set_breakpoint(self, addr, **kwargs):
        command = f'b -a {addr} -s {self.module.GetFileSpec().GetFilename()}'
        result = lldb.SBCommandReturnObject()
        self.interpreter.HandleCommand(command, result)

    def remove_breakpoint(self, addr, **kwargs):
        command = f'breakpoint delete {addr}'
        result = lldb.SBCommandReturnObject()
        self.interpreter.HandleCommand(command, result)

    def is_running(self):
        return self.process.GetState() == lldb.eStateRunning

    def is_exited(self):
        """Not part of the angr interface, but much more useful than
        `is_running`.

        :return: True if the process has exited. False otherwise.
        """
        return self.process.GetState() == lldb.eStateExited

    def wait_for_running(self):
        while self.process.GetState() != lldb.eStateRunning:
            pass

    def wait_for_halt(self):
        while self.process.GetState() != lldb.eStateStopped:
            pass

    def run(self):
        state = self.process.GetState()
        if state == lldb.eStateExited:
            raise RuntimeError(f'Tried to resume process execution, but the'
                               f' process has already exited.')
        assert(state == lldb.eStateStopped)
        self.process.Continue()

    def step(self):
        thread: lldb.SBThread = self.process.GetThreadAtIndex(0)
        thread.StepInstruction(False)

    def stop(self):
        self.process.Stop()

    def exit(self):
        self.debugger.Terminate()
        print(f'Program exited with status {self.process.GetState()}')

    def _get_register(self, regname: str) -> lldb.SBValue:
        """Find a register by name.

        :raise SimConcreteRegisterError: If no register with the specified name
                                         can be found.
        """
        frame = self.process.GetThreadAtIndex(0).GetFrameAtIndex(0)
        reg = frame.FindRegister(regname)
        if reg is None:
            raise SimConcreteRegisterError(
                f'[In LLDBConcreteTarget._get_register]: Register {regname}'
                f' not found.')
        return reg

    def read_register(self, regname: str) -> int:
        reg = self._get_register(regname)
        val = reg.GetValue()
        if val is None:
            raise SimConcreteRegisterError(
                f'[In LLDBConcreteTarget.read_register]: Register has an'
                f' invalid value of {val}.')

        return int(val, 16)

    def write_register(self, regname: str, value: int):
        reg = self._get_register(regname)
        error = lldb.SBError()
        reg.SetValueFromCString(hex(value), error)
        if not error.success:
            raise SimConcreteRegisterError(
                f'[In LLDBConcreteTarget.write_register]: Unable to set'
                f' {regname} to value {hex(value)}!')

    def read_memory(self, addr, size):
        err = lldb.SBError()
        content = self.process.ReadMemory(addr, size, err)
        if not err.success:
            raise SimConcreteMemoryError(f'Error when reading {size} bytes at'
                                         f' address {hex(addr)}: {err}')
        return content

    def write_memory(self, addr, value):
        err = lldb.SBError()
        res = self.process.WriteMemory(addr, value, err)
        if not err.success or res != len(value):
            raise SimConcreteMemoryError(f'Error when writing to address'
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
                                  0,    # offset?
                                  name if name is not None else '<none>',
                                  perms))
        return mmap
