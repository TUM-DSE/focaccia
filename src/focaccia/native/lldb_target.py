import os
import time
import logging

import lldb

from focaccia.snapshot import ProgramState
from focaccia.arch import supported_architectures

logger = logging.getLogger('focaccia-lldb-target')
debug = logger.debug
info = logger.info
warn = logger.warning

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

class ConcreteTargetError(RuntimeError):
    """Base error for LLDB target operations."""


class ConcreteRegisterError(ConcreteTargetError):
    pass


class ConcreteMemoryError(ConcreteTargetError):
    pass


class ConcreteSectionError(ConcreteTargetError):
    pass


class ConcreteExecutionError(ConcreteTargetError):
    pass


def _is_valid(value) -> bool:
    checker = getattr(value, 'IsValid', None)
    return value is not None and (bool(checker()) if checker is not None else True)


def _error_succeeded(error) -> bool:
    if error is None:
        return True
    if isinstance(error, bool):
        return error
    checker = getattr(error, 'Success', None)
    if checker is not None:
        return bool(checker())
    success = getattr(error, 'success', None)
    return bool(success) if success is not None else False


def _error_message(error) -> str:
    getter = getattr(error, 'GetCString', None)
    if getter is not None:
        message = getter()
        if message:
            return str(message)
    return str(error)

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

    # LLDB's x86-64 GDB-remote register map exposes EFLAGS as a four-byte
    # register even when it accepts the conventional ``rflags`` name. The
    # upper half of RFLAGS is reserved, and EFLAGS contains every modeled x86
    # flag field, so zero-extension at this boundary is lossless.
    flag_register_width_aliases = {
        x86.archname: {4: 'EFLAGS'},
    }

    register_retries = {
        aarch64.archname: {},
        x86.archname: {
            "rflags": ["eflags"]
        }
    }

    def __init__(self,
                 debugger: lldb.SBDebugger,
                 target: lldb.SBTarget,
                 process: lldb.SBProcess):
        """Construct an LLDB concrete target. Stop at entry.

        :param debugger: LLDB SBDebugger object representing an initialized debug session.
        :param target: LLDB SBTarget object representing an initialized target for the debugger.
        :param process: LLDB SBProcess object representing an initialized process (either local or remote).
        """
        if not _is_valid(debugger):
            raise ConcreteExecutionError('LLDB debugger is invalid.')
        if not _is_valid(target):
            raise ConcreteExecutionError('LLDB target is invalid.')
        if not _is_valid(process):
            raise ConcreteExecutionError('LLDB process is invalid.')

        self.debugger = debugger
        self.target = target
        self.process = process

        self.module = self.target.FindModule(self.target.GetExecutable())
        if not _is_valid(self.module):
            raise ConcreteExecutionError('LLDB target has no valid primary module.')
        self.interpreter = self.debugger.GetCommandInterpreter()
        if not _is_valid(self.interpreter):
            raise ConcreteExecutionError('LLDB command interpreter is invalid.')

        # LLDB 19 can return from synchronous ConnectRemote before its initial
        # stopped-state event has been consumed by the public listener. Drain
        # that bounded event transition instead of treating the stale
        # eStateUnloaded value as a failed connection.
        self.listener = self.debugger.GetListener()
        self._wait_for_process_state('initialize the target')
        if self.is_exited():
            raise ConcreteExecutionError('LLDB process exited before target initialization.')

        # Determine current arch
        self.archname = self.determine_arch()
        self.arch = supported_architectures[self.archname]

        self.exec_time = 0

    def determine_arch(self):
        platform = self.target.GetPlatform()
        if not _is_valid(platform):
            raise ConcreteExecutionError('LLDB target platform is invalid.')
        triple = platform.GetTriple()
        if not triple:
            raise ConcreteExecutionError('LLDB target platform has no architecture triple.')
        archname = triple.split('-')[0]
        if archname not in supported_architectures:
            err = f'LLDBConcreteTarget: Architecture {archname} is not' \
                  f' supported by Focaccia.'
            raise NotImplementedError(err)
        return archname

    def determine_name(self) -> str:
        return self.process.GetTarget().GetExecutable().fullpath

    def determine_arguments(self):
        launch_info = self.target.GetLaunchInfo()
        argc = self.target.GetLaunchInfo().GetNumArguments()
        return [launch_info.GetArgumentAtIndex(i) for i in range(argc)]

    def is_exited(self) -> bool:
        """Return whether the concrete process has exited."""
        return self.process.GetState() == lldb.eStateExited

    @staticmethod
    def _allowed_process_states() -> set[int]:
        return {
            getattr(lldb, name)
            for name in ('eStateStopped', 'eStateExited')
            if hasattr(lldb, name)
        }

    @staticmethod
    def _transient_process_states() -> set[int]:
        return {
            getattr(lldb, name)
            for name in (
                'eStateUnloaded',
                'eStateConnected',
                'eStateAttaching',
                'eStateLaunching',
                'eStateRunning',
                'eStateStepping',
                'eStateSuspended',
            )
            if hasattr(lldb, name)
        }

    @staticmethod
    def _process_state_description(state: int) -> str:
        for name in (
            'eStateInvalid',
            'eStateUnloaded',
            'eStateConnected',
            'eStateAttaching',
            'eStateLaunching',
            'eStateStopped',
            'eStateRunning',
            'eStateStepping',
            'eStateCrashed',
            'eStateDetached',
            'eStateExited',
            'eStateSuspended',
        ):
            if hasattr(lldb, name) and state == getattr(lldb, name):
                return f'{name} ({state!r})'
        return repr(state)

    def _check_process_state(self, operation: str) -> None:
        state = self.process.GetState()
        if state not in self._allowed_process_states():
            raise ConcreteExecutionError(
                'LLDB process entered unexpected state '
                f'{self._process_state_description(state)} while attempting to '
                f'{operation}.'
            )

    def _wait_for_process_state(
        self,
        operation: str,
        timeout_seconds: float = 5.0,
    ) -> None:
        """Consume LLDB state events until the process is stopped or exited."""
        if timeout_seconds <= 0:
            raise ValueError('An LLDB process-state timeout must be positive.')
        state = self.process.GetState()
        if state in self._allowed_process_states():
            return
        if state not in self._transient_process_states():
            self._check_process_state(operation)

        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            event = lldb.SBEvent()
            self.listener.WaitForEvent(1, event)
            state = self.process.GetState()
            if state in self._allowed_process_states():
                return
            if state not in self._transient_process_states():
                self._check_process_state(operation)

        raise ConcreteExecutionError(
            'Timed out waiting for LLDB process state while attempting to '
            f'{operation}; last state was {self._process_state_description(state)}.'
        )

    def run(self):
        """Continue execution of the concrete process."""
        state = self.process.GetState()
        if state == lldb.eStateExited:
            raise ConcreteExecutionError(
                'Tried to resume process execution, but the process has already exited.'
            )
        self._check_process_state('continue execution')
        error = self.process.Continue()
        if not _error_succeeded(error):
            raise ConcreteExecutionError(
                f'Unable to continue LLDB process: {_error_message(error)}.'
            )
        self._check_process_state('continue execution')

    def step(self):
        """Step forward by a single instruction."""
        start_time = time.time()
        if self.is_exited():
            raise ConcreteExecutionError('Cannot step an exited LLDB process.')
        self._check_process_state('step one instruction')
        thread: lldb.SBThread = self.process.GetSelectedThread()
        if not _is_valid(thread):
            raise ConcreteExecutionError('LLDB has no valid selected thread to step.')
        try:
            error = lldb.SBError()
            thread.StepInstruction(False, error)
            if not _error_succeeded(error):
                raise ConcreteExecutionError(
                    f'Unable to step LLDB process: {_error_message(error)}.'
                )
            self._check_process_state('step one instruction')
        finally:
            self.exec_time += time.time() - start_time

    def _create_address_breakpoint(self, address: int):
        breakpoint = self.target.BreakpointCreateByAddress(address)
        if not _is_valid(breakpoint):
            raise ConcreteExecutionError(
                f'Unable to create LLDB breakpoint at {hex(address)}.'
            )
        locations = getattr(breakpoint, 'GetNumLocations', None)
        if locations is not None and locations() == 0:
            breakpoint_id = breakpoint.GetID()
            cleanup_note = ''
            if not self.target.BreakpointDelete(breakpoint_id):
                cleanup_note = f' Breakpoint {breakpoint_id} also could not be deleted.'
            raise ConcreteExecutionError(
                f'LLDB breakpoint at {hex(address)} has no resolved location.'
                f'{cleanup_note}'
            )
        return breakpoint

    def _delete_breakpoint(self, breakpoint_id: int) -> None:
        if not self.target.BreakpointDelete(breakpoint_id):
            raise ConcreteExecutionError(
                f'Unable to delete LLDB breakpoint {breakpoint_id}.'
            )

    def run_until(self, address: int) -> None:
        """Continue until ``address`` or process exit, always removing the breakpoint."""
        start_time = time.time()
        if self.is_exited():
            raise ConcreteExecutionError(
                f'Cannot run an exited LLDB process to {hex(address)}.'
            )
        if self.read_pc() == address:
            return
        breakpoint = self._create_address_breakpoint(address)
        breakpoint_id = breakpoint.GetID()
        primary_error: BaseException | None = None
        observed_stops: set[int] = set()
        try:
            while True:
                self.run()
                if self.is_exited():
                    return
                observed_pc = self.read_pc()
                if observed_pc == address:
                    return
                if observed_pc in observed_stops:
                    raise ConcreteExecutionError(
                        f'LLDB repeatedly stopped at {hex(observed_pc)} while '
                        f'waiting for {hex(address)}.'
                    )
                observed_stops.add(observed_pc)
        except BaseException as error:
            primary_error = error
            raise
        finally:
            try:
                self._delete_breakpoint(breakpoint_id)
            except ConcreteExecutionError as cleanup_error:
                if primary_error is None:
                    raise
                primary_error.add_note(str(cleanup_error))
            self.exec_time += time.time() - start_time

    def record_snapshot(self) -> ProgramState:
        """Record the concrete target's state in a ProgramState object."""
        state = ProgramState(self.arch)

        # Query and store register state
        for regname in self.arch.regnames:
            try:
                conc_val = self.read_register(regname)
                state.write_register(regname, conc_val)
            except ConcreteRegisterError:
                pass

        # Query and store memory state
        for mapping in self.get_mappings():
            if mapping.end_address <= mapping.start_address:
                raise ConcreteMemoryError(
                    f'Invalid LLDB memory mapping {mapping}.'
                )
            size = mapping.end_address - mapping.start_address
            try:
                data = self.read_memory(mapping.start_address, size)
                state.write_memory(mapping.start_address, data)
            except ConcreteMemoryError:
                pass

        return state

    def _canonical_register_name(self, regname: str) -> str:
        canonical = self.arch.to_regname(regname)
        if canonical is None:
            raise ConcreteRegisterError(f'Not a register name: {regname}')
        return canonical

    def _get_register(self, regname: str) -> lldb.SBValue:
        """Find a register by name.

        :raise ConcreteRegisterError: If no register with the specified name
                                      can be found.
        """
        debug(f'Accessing register {regname}')

        thread = self.process.GetSelectedThread()
        if not _is_valid(thread):
            raise ConcreteRegisterError('LLDB has no valid selected thread.')
        frame = thread.GetFrameAtIndex(0)
        if not _is_valid(frame):
            raise ConcreteRegisterError('LLDB selected thread has no valid frame 0.')

        retry_list = self.register_retries[self.archname].get(regname, [])
        error_msg = f'[In LLDBConcreteTarget._get_register]: Register {regname} not found'

        reg = None
        for name in [regname, *retry_list]:
            reg = frame.FindRegister(name)
            if _is_valid(reg):
                break
        if not _is_valid(reg):
            raise ConcreteRegisterError(error_msg)
        return reg

    def _validate_register_size(self, reg: lldb.SBValue, regname: str) -> None:
        accessor = self.arch.get_reg_accessor(regname)
        if accessor is None:
            raise ConcreteRegisterError(f'No register accessor for {regname}.')
        expected_size = (accessor.num_bits + 7) // 8
        if reg.size != expected_size:
            raise ConcreteRegisterError(
                f'LLDB register {regname} has size {reg.size}, expected '
                f'{expected_size} bytes.'
            )

    def _scalar_observation_name(
        self,
        reg: lldb.SBValue,
        canonical: str,
    ) -> str:
        accessor = self.arch.get_reg_accessor(canonical)
        if accessor is None:
            return canonical
        expected_size = (accessor.num_bits + 7) // 8
        if reg.size == expected_size:
            return canonical
        observed = self.flag_register_width_aliases.get(self.archname, {}).get(
            reg.size
        )
        if (
            canonical == accessor.base_reg
            and observed is not None
            and self.arch.register_observation_zero_extends(observed)
        ):
            observed_accessor = self.arch.get_reg_accessor(observed)
            if (
                observed_accessor is not None
                and observed_accessor.base_reg == accessor.base_reg
            ):
                return observed
        return canonical

    def _read_scalar_register_value(self, reg: lldb.SBValue, regname: str) -> int:
        self._validate_register_size(reg, regname)
        error = lldb.SBError()
        value = reg.GetValueAsUnsigned(error, 0)
        if not _error_succeeded(error):
            raise ConcreteRegisterError(
                f'Unable to read LLDB register {regname}: {_error_message(error)}.'
            )
        return value

    def _read_wide_register_value(self, reg: lldb.SBValue, regname: str) -> int:
        self._validate_register_size(reg, regname)
        error = lldb.SBError()
        raw_data = reg.data.ReadRawData(error, 0, reg.size)
        if not _error_succeeded(error):
            raise ConcreteRegisterError(
                f'Unable to read LLDB register {regname}: {_error_message(error)}.'
            )
        raw = bytes(raw_data)
        if len(raw) != reg.size:
            raise ConcreteRegisterError(
                f'Short LLDB register read for {regname}: expected {reg.size} bytes, '
                f'received {len(raw)}.'
            )
        return int.from_bytes(raw, byteorder=self.arch.endianness)

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
        canonical = self._canonical_register_name(flags_reg)
        reg = self._get_register(flags_reg)
        read_name = self._scalar_observation_name(reg, canonical)
        flags_val = self._read_scalar_register_value(reg, read_name)
        return self.flag_register_decompose[self.archname](flags_val)

    def read_pc(self) -> int:
        """Read the architecture's canonical program counter."""
        return self.read_register('PC')

    def read_register(self, regname: str) -> int:
        """Read the value of a register.

        Register aliases and case are normalized before accessing LLDB.

        :raise ConcreteRegisterError: If `regname` is not a valid register name
                                      or the target is otherwise unable to read
                                      the register's value.
        """
        canonical = self._canonical_register_name(regname)
        if self.arch.is_constant_register(canonical):
            value = self.arch.get_constant_register_value(canonical)
            if value is None:
                raise ConcreteRegisterError(
                    f'Missing value for constant register {canonical}.'
                )
            return value

        try:
            reg = self._get_register(canonical.lower())
            if not _is_valid(reg):
                raise ConcreteRegisterError(f'LLDB register {canonical} is invalid.')
            if reg.size > 8:
                return self._read_wide_register_value(reg, canonical)
            read_name = self._scalar_observation_name(reg, canonical)
            return self._read_scalar_register_value(reg, read_name)
        except ConcreteRegisterError as err:
            flags_reg = self.arch.to_regname(
                self.flag_register_names.get(self.archname, '')
            )
            accessor = self.arch.get_reg_accessor(canonical)
            flags_accessor = (
                self.arch.get_reg_accessor(flags_reg)
                if flags_reg is not None
                else None
            )
            if (
                accessor is not None
                and flags_accessor is not None
                and accessor.base_reg == flags_accessor.base_reg
            ):
                flags = self.read_flags()
                if canonical in flags:
                    return flags[canonical]
            raise ConcreteRegisterError(
                f'[In LLDBConcreteTarget.read_register]: Unable to read'
                f' register {regname}: {err}')

    def write_register(self, regname: str, value: int):
        """Write a value to a register.

        :raise ConcreteRegisterError: If `regname` is not a valid register name
                                      or the target is otherwise unable to set
                                      the register's value.
        """
        canonical = self._canonical_register_name(regname)
        if self.arch.is_constant_register(canonical):
            return
        reg = self._get_register(canonical.lower())
        error = lldb.SBError()
        written = reg.SetValueFromCString(hex(value), error)
        if not written or not _error_succeeded(error):
            raise ConcreteRegisterError(
                f'[In LLDBConcreteTarget.write_register]: Unable to set'
                f' {regname} to value {hex(value)}!')

    def read_memory(self, addr: int, size: int) -> bytes:
        """Read bytes from memory.

        :raise ConcreteMemoryError: If unable to read `size` bytes from `addr`.
        """
        err = lldb.SBError()
        if size < 0:
            raise ValueError('A memory read size cannot be negative.')
        content = self.process.ReadMemory(addr, size, err)
        if not _error_succeeded(err):
            raise ConcreteMemoryError(
                f'Error when reading {size} bytes at address {hex(addr)}: '
                f'{_error_message(err)}'
            )
        data = bytes(content)
        if len(data) != size:
            raise ConcreteMemoryError(
                f'Short LLDB memory read at {hex(addr)}: expected {size} bytes, '
                f'received {len(data)}.'
            )
        return data

    def write_memory(self, addr: int, value: bytes):
        """Write bytes to memory.

        :raise ConcreteMemoryError: If unable to write at `addr`.
        """
        err = lldb.SBError()
        res = self.process.WriteMemory(addr, value, err)
        if not _error_succeeded(err) or res != len(value):
            raise ConcreteMemoryError(
                f'Error when writing {len(value)} bytes to address {hex(addr)}: '
                f'{_error_message(err)}; wrote {res} bytes.'
            )

    def get_mappings(self) -> list[MemoryMap]:
        mmap = []

        region_list = self.process.GetMemoryRegions()
        for i in range(region_list.GetSize()):
            region = lldb.SBMemoryRegionInfo()
            if not region_list.GetMemoryRegionAtIndex(i, region):
                raise ConcreteMemoryError(
                    f'LLDB could not read memory-region metadata at index {i}.'
                )

            perms = f'{"r" if region.IsReadable() else "-"}' \
                    f'{"w" if region.IsWritable() else "-"}' \
                    f'{"x" if region.IsExecutable() else "-"}'
            name = region.GetName()

            mmap.append(MemoryMap(region.GetRegionBase(),
                                  region.GetRegionEnd(),
                                  name if name is not None else '<none>',
                                  perms))
        return mmap

    def set_breakpoint(self, addr: int) -> int:
        """Create an address breakpoint and return its LLDB identifier."""
        return self._create_address_breakpoint(addr).GetID()

    def remove_breakpoint(self, breakpoint_id: int) -> None:
        """Delete a breakpoint by identifier, not by address."""
        self._delete_breakpoint(breakpoint_id)

    def _read_instruction(
        self,
        addr: int,
        flavor: str | None = None,
    ) -> lldb.SBInstruction:
        address = lldb.SBAddress(addr, self.target)
        if not _is_valid(address):
            raise ConcreteExecutionError(f'Invalid LLDB address {hex(addr)}.')
        instructions = (
            self.target.ReadInstructions(address, 1, flavor)
            if flavor is not None
            else self.target.ReadInstructions(address, 1)
        )
        if len(instructions) != 1 or not _is_valid(instructions[0]):
            raise ConcreteExecutionError(
                f'LLDB returned no instruction at {hex(addr)}.'
            )
        return instructions[0]

    def get_basic_block(self, addr: int) -> list[lldb.SBInstruction]:
        """Return the basic block starting at ``addr``."""
        block = []
        while True:
            instruction = self._read_instruction(addr)
            block.append(instruction)
            if instruction.is_branch:
                return block
            addr += instruction.size

    def get_basic_block_inst(self, addr: int) -> list[str]:
        inst = []
        for bb in self.get_basic_block(addr):
            inst.append(f'{bb.GetMnemonic(self.target)} {bb.GetOperands(self.target)}')
        return inst

    def get_next_basic_block(self) -> list[lldb.SBInstruction]:
        return self.get_basic_block(self.read_pc())

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

    def get_disassembly(self, addr: int) -> str:
        flavor = 'intel' if self.archname == self.x86.archname else None
        inst: lldb.SBInstruction = self._read_instruction(addr, flavor)
        mnemonic = inst.GetMnemonic(self.target)
        operands = inst.GetOperands(self.target)
        if mnemonic is None or operands is None:
            raise ConcreteExecutionError(
                f'LLDB returned incomplete disassembly at {hex(addr)}.'
            )
        return f'{mnemonic.upper()} {operands.upper().replace("0X", "0x")}'

    def get_disassembly_bytes(self, addr: int):
        error = lldb.SBError()
        buf = self.process.ReadMemory(addr, 64, error)
        inst = self.target.GetInstructions(lldb.SBAddress(addr, self.target), buf)[0]
        return inst.GetData(self.target).ReadRawData(error, 0, inst.GetByteSize())

    def get_instruction_size(self, addr: int) -> int:
        inst = self._read_instruction(addr)
        size = inst.GetByteSize()
        if size <= 0:
            raise ConcreteExecutionError(
                f'LLDB returned an invalid instruction size at {hex(addr)}.'
            )
        return size

    def get_current_tid(self) -> int:
        thread: lldb.SBThread = self.process.GetSelectedThread()
        if not _is_valid(thread):
            raise ConcreteExecutionError('LLDB has no valid selected thread.')
        return thread.GetThreadID()

class LLDBLocalTarget(LLDBConcreteTarget):
    def __init__(self,
                 executable: str,
                 argv: list[str] | None = None,
                 envp: list[str] | None = None):
        """Construct an LLDB local target. Stop at entry.

        :param executable: Name of executable to run under LLDB.
        :param argv: List of arguements. Does NOT include the conventional
                     executable name as the first entry.
        :param envp: List of environment entries. Defaults to current
                     `os.environ` if `None`.
        :raises RuntimeError: If the process is unable to launch.
        """
        if argv is None:
            argv = []
        if envp is None:
            envp = [f'{k}={v}' for k, v in os.environ.items()]

        debugger = lldb.SBDebugger.Create()
        if not _is_valid(debugger):
            raise ConcreteExecutionError('Unable to create an LLDB debugger.')
        debugger.SetAsync(False)
        target = debugger.CreateTargetWithFileAndArch(executable, lldb.LLDB_ARCH_DEFAULT)
        if not _is_valid(target):
            raise ConcreteExecutionError(f'Unable to create LLDB target for {executable}.')

        # Set up objects for process execution
        error = lldb.SBError()
        process = target.Launch(debugger.GetListener(),
                                argv, envp,        # argv, envp
                                None, None, None,  # stdin, stdout, stderr
                                None,              # working directory
                                0,
                                True, error)

        if not _error_succeeded(error) or not _is_valid(process):
            raise ConcreteExecutionError(
                f'Failed to launch LLDB target: {_error_message(error)}.'
            )

        super().__init__(debugger, target, process)

class LLDBRemoteTarget(LLDBConcreteTarget):
    def __init__(self, remote: str, executable: str | None = None):
        """Construct an LLDB remote target. Stop at entry.

        :param remote: String of the form <remote_name>:<port> (e.g. localhost:12345).
        :raises RuntimeError: If failing to attach to a remote debug session.
        """
        debugger = lldb.SBDebugger.Create()
        if not _is_valid(debugger):
            raise ConcreteExecutionError('Unable to create an LLDB debugger.')
        debugger.SetAsync(False)
        target = debugger.CreateTarget(executable)
        if not _is_valid(target):
            raise ConcreteExecutionError(
                f'Unable to create LLDB target for remote endpoint {remote}.'
            )

        # Set up objects for process execution
        error = lldb.SBError()
        process = target.ConnectRemote(debugger.GetListener(),
                                       f'connect://{remote}',
                                       None,
                                       error)
        if not _error_succeeded(error) or not _is_valid(process):
            raise ConcreteExecutionError(
                f'Failed to connect via LLDB to remote target: {_error_message(error)}.'
            )

        super().__init__(debugger, target, process)

