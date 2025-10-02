import os

import lldb

from .arch import supported_architectures
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

class ConcreteSectionError(Exception):
    pass

class LLDBConcreteTarget:
    from focaccia.arch import aarch64, x86

    flag_register_names = {
        aarch64.archname: 'cpsr',
        x86.archname: 'rflags',
    }

    flag_register_decompose = {
        aarch64.archname: aarch64.decompose_cpsr,
        x86.archname: x86.decompose_rflags,
    }

    def __init__(self,
                 executable: str,
                 argv: list[str] = [],
                 envp: list[str] | None = None):
        """Construct an LLDB concrete target. Stop at entry.

        :param argv: List of arguements. Does NOT include the conventional
                     executable name as the first entry.
        :param envp: List of environment entries. Defaults to current
                     `os.environ` if `None`.
        :raises RuntimeError: If the process is unable to launch.
        """
        if envp is None:
            envp = [f'{k}={v}' for k, v in os.environ.items()]

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
                                          argv, envp,        # argv, envp
                                          None, None, None,  # stdin, stdout, stderr
                                          None,              # working directory
                                          0,
                                          True, self.error)
        if not self.process.IsValid():
            raise RuntimeError(f'[In LLDBConcreteTarget.__init__]: Failed to'
                               f' launch process.')

        # Determine current arch
        self.archname = self.target.GetPlatform().GetTriple().split('-')[0]
        if self.archname not in supported_architectures:
            err = f'LLDBConcreteTarget: Architecture {self.archname} is not' \
                  f' supported by Focaccia.'
            print(f'[ERROR] {err}')
            raise NotImplementedError(err)
        self.arch = supported_architectures[self.archname]

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

    def run_until(self, address: int) -> None:
        """Continue execution until the address is arrived, ignores other breakpoints"""
        bp = self.target.BreakpointCreateByAddress(address)
        while self.read_register("pc") != address:
            self.run()
        self.target.BreakpointDelete(bp.GetID())

    def record_snapshot(self) -> ProgramState:
        """Record the concrete target's state in a ProgramState object."""
        state = ProgramState(self.arch)

        # Query and store register state
        for regname in self.arch.regnames:
            try:
                conc_val = self.read_register(regname)
                state.set_register(regname, conc_val)
            except KeyError:
                pass
            except ConcreteRegisterError:
                pass

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
        if not reg.IsValid():
            raise ConcreteRegisterError(
                f'[In LLDBConcreteTarget._get_register]: Register {regname}'
                f' not found.')
        return reg

    def read_flags(self) -> dict[str, int | bool]:
        """Read the current state flags.

        If the concrete target's architecture has state flags, read and return
        their current values.

        This handles the conversion from implementation details like flags
        registers to the logical flag values. For example: On X86, this reads
        the RFLAGS register and extracts the flag bits from its value.

        :return: Dictionary mapping flag names to values. The values may be
                 booleans in the case of true binary flags or integers in the
                 case of multi-byte flags. Is empty if the current architecture
                 does not have state flags of the access is not implemented for
                 it.
        """
        if self.archname not in self.flag_register_names:
            return {}

        flags_reg = self.flag_register_names[self.archname]
        flags_val = self._get_register(flags_reg).GetValueAsUnsigned()
        return self.flag_register_decompose[self.archname](flags_val)

    def read_register(self, regname: str) -> int:
        """Read the value of a register.

        :raise ConcreteRegisterError: If `regname` is not a valid register name
                                      or the target is otherwise unable to read
                                      the register's value.
        """
        try:
            reg = self._get_register(regname)
            assert(reg.IsValid())
            if reg.size > 8:  # reg is a vector register
                reg.data.byte_order = lldb.eByteOrderLittle
                val = 0
                for ui64 in reversed(reg.data.uint64s):
                    val <<= 64
                    val |= ui64
                return val
            return reg.GetValueAsUnsigned()
        except ConcreteRegisterError as err:
            flags = self.read_flags()
            if regname in flags:
                return flags[regname]
            raise ConcreteRegisterError(
                f'[In LLDBConcreteTarget.read_register]: Unable to read'
                f' register {regname}: {err}')

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
        if self.arch.endianness == 'little':
            return content
        else:
            return bytes(reversed(content))

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

    def get_basic_block(self, addr: int) -> list[lldb.SBInstruction]:
        """Returns a basic block pointed by addr
        a code section is considered a basic block only if
        the last instruction is a brach, e.g. JUMP, CALL, RET
        """
        block = []
        while not self.target.ReadInstructions(lldb.SBAddress(addr, self.target), 1)[0].is_branch:
            block.append(self.target.ReadInstructions(lldb.SBAddress(addr, self.target), 1)[0])
            addr += self.target.ReadInstructions(lldb.SBAddress(addr, self.target), 1)[0].size
        block.append(self.target.ReadInstructions(lldb.SBAddress(addr, self.target), 1)[0])

        return block

    def get_basic_block_inst(self, addr: int) -> list[str]:
        inst = []
        for bb in self.get_basic_block(addr):
            inst.append(f'{bb.GetMnemonic(self.target)} {bb.GetOperands(self.target)}')
        return inst

    def get_next_basic_block(self) -> list[lldb.SBInstruction]:
        return self.get_basic_block(self.read_register("pc"))

    def get_symbol(self, addr: int) -> lldb.SBSymbol:
        """Returns the symbol that belongs to the addr
        """
        for s in self.module.symbols:
            if (s.GetType() == lldb.eSymbolTypeCode and s.GetStartAddress().GetLoadAddress(self.target) <= addr  < s.GetEndAddress().GetLoadAddress(self.target)):
                return s
        raise ConcreteSectionError(f'Error getting the symbol to which address {hex(addr)} belongs to')

    def get_symbol_limit(self) -> int:
        """Returns the address after all the symbols"""
        addr = 0
        for s in self.module.symbols:
            if s.GetStartAddress().IsValid():
                if s.GetStartAddress().GetLoadAddress(self.target) > addr:
                    addr = s.GetEndAddress().GetLoadAddress(self.target)
        return addr
