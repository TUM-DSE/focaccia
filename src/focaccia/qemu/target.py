import gdb
import time
import struct
import logging
from focaccia.deterministic import (
    DeterministicLog,
    Event,
    SignalEvent,
    EventMatcher,
    SyscallEvent,
    MemoryMapping,
)
from focaccia.snapshot import (
    ReadableProgramState,
    RegisterAccessError,
    MemoryAccessError,
)
from focaccia.arch import supported_architectures, Arch
from focaccia.qemu.concurrency import (
    reject_thread_creating_effect,
    require_event_thread,
    require_single_inferior,
)
from focaccia.qemu.deterministic import (
    emulated_system_calls,
    passthrough_system_calls,
    syscall_number_registers,
)
from focaccia.qemu.state import CachedBackendProgramState, RegisterObservation
from focaccia.qemu.x86 import SigContext, SigInfo, UContext, SigFrame

logger = logging.getLogger('focaccia-qemu-target')
debug = logger.debug
info = logger.info
warn = logger.warning


def match_event(event: Event, target: ReadableProgramState) -> bool:
    # Match just on PC
    debug(f'Matching for PC {hex(target.read_pc())} with event {hex(event.pc)}')
    if event.pc == target.read_pc():
        return True
    return False

class GDBProgramState(CachedBackendProgramState):
    """One stopped GDB inferior state with canonical sparse caching."""

    from focaccia.arch import aarch64, x86

    flag_backend_names = {
        aarch64.archname: "cpsr",
        x86.archname: "eflags",
    }

    def __init__(self, process: gdb.Inferior, frame: gdb.Frame, arch: Arch):
        super().__init__(arch)
        self._proc = process
        self._frame = frame
        flags_name = self.flag_backend_names.get(arch.archname)
        canonical_flags = arch.to_regname(flags_name) if flags_name else None
        flags = arch.get_reg_accessor(canonical_flags) if canonical_flags else None
        self._flags_base = flags.base_reg if flags is not None else None

    @staticmethod
    def _read_vector_reg_aarch64(value: gdb.Value, _size: int) -> int:
        errors = []
        for path in (("d", "u"), ("u",), ("q", "u")):
            try:
                current = value
                for component in path:
                    current = current[component]
                return int(str(current), 10)
            except (KeyError, TypeError, ValueError, gdb.error) as error:
                errors.append(error)
        raise ValueError(f"Unable to decode AArch64 vector register: {errors}.")

    @staticmethod
    def _read_vector_reg_x86(value: gdb.Value, size: int) -> int:
        if size % 64 != 0:
            raise ValueError(f"Unsupported x86 vector width {size}.")
        num_longs = size // 64
        values = value[f"v{num_longs}_int64"]
        result = 0
        for index in range(num_longs):
            component = int(
                values[index].cast(gdb.lookup_type("unsigned long"))
            )
            result |= component << (index * 64)
        return result

    read_vector_reg = {
        aarch64.archname: _read_vector_reg_aarch64,
        x86.archname: _read_vector_reg_x86,
    }

    def _read_backend_register(self, base_reg: str) -> RegisterObservation:
        wire_name = (
            self.flag_backend_names[self.arch.archname]
            if self._flags_base is not None and base_reg == self._flags_base
            else base_reg.lower()
        )
        canonical = self.arch.to_regname(wire_name)
        if canonical is None:
            raise RegisterAccessError(
                base_reg,
                f"GDB register {wire_name!r} is not in the guest architecture.",
            )
        try:
            value = self._frame.read_register(wire_name)
            size = value.type.sizeof * 8
            if size >= 128:
                reader = self.read_vector_reg.get(self.arch.archname)
                if reader is None:
                    raise ValueError(
                        f"Vector registers are unsupported for {self.arch}."
                    )
                numeric = reader(value, size)
            elif size <= 32:
                numeric = int(value.cast(gdb.lookup_type("unsigned int")))
            elif size == 64:
                numeric = int(value.cast(gdb.lookup_type("unsigned long")))
            else:
                raise ValueError(f"Unsupported scalar register width {size}.")
        except (ValueError, RuntimeError, gdb.error) as error:
            raise RegisterAccessError(
                base_reg,
                f"GDB cannot access register {wire_name}: {error}.",
            ) from error
        return RegisterObservation(canonical, numeric, size)

    def _read_backend_memory(self, addr: int, size: int) -> bytes:
        try:
            return self._proc.read_memory(addr, size).tobytes()
        except gdb.MemoryError as error:
            raise MemoryAccessError(addr, size, str(error)) from error

class GDBServerConnector:
    def __init__(self, remote: str):
        gdb.execute('set pagination 0')
        gdb.execute('set sysroot')
        gdb.execute('set python print-stack full') # enable complete Python tracebacks
        gdb.execute(f'target remote {remote}')
        gdb.execute('set scheduler-locking on')
        self._process = gdb.selected_inferior()
        require_single_inferior(len(self._process.threads()))

        split = self._process.architecture().name().split(':')
        archname = split[1] if len(split) > 1 else split[0]
        archname = archname.replace('-', '_')
        if archname not in supported_architectures:
            raise NotImplementedError(f'Platform {archname} is not supported by Focaccia')

        self.arch = supported_architectures[archname]
        self.binary = self._process.progspace.filename

    def current_state(self) -> ReadableProgramState:
        return GDBProgramState(self._process, gdb.selected_frame(), self.arch)

    def skip(self, new_pc: int):
        gdb.execute(f'set $pc = {hex(new_pc)}')

    def _step(self):
        pc = gdb.selected_frame().read_register('pc')
        new_pc = pc
        while pc == new_pc:  # Skip instruction chains from REP STOS etc.
            gdb.execute('si', to_string=True)
            if self.is_exited():
                raise StopIteration
            new_pc = gdb.selected_frame().read_register('pc')
        return self.current_state()

    def is_exited(self) -> bool:
        return not self._process.is_valid() or len(self._process.threads()) == 0

    def get_sections(self) -> list[MemoryMapping]:
        mappings = []

        # Skip everything until the header line
        started = False

        text = gdb.execute('info proc mappings', to_string=True)
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue

            # Detect header line once
            if line.startswith("Start Addr"):
                started = True
                continue

            if not started:
                continue

            # Lines look like:
            # 0x0000000000400000 0x0000000000401000 0x1000 0x0 r--p /path
            # or:
            # 0x... 0x... 0x... 0x... rw-p  [vdso]
            parts = line.split(None, 6)

            if len(parts) < 5:
                continue

            start   = int(parts[0], 16)
            end     = int(parts[1], 16)
            size    = int(parts[2], 16)
            offset  = int(parts[3], 16)
            perms   = parts[4]

            file_or_tag = None
            is_special = False

            if len(parts) >= 6:
                tail = parts[5]

                # If it's [tag], mark as special
                if tail.startswith("[") and tail.endswith("]"):
                    file_or_tag = tail.strip()
                    is_special = True
                else:
                    # Might be a filename or absent
                    file_or_tag = tail

            mapping = MemoryMapping(0,
                                    start,
                                    end,
                                    '',
                                    offset,
                                    0,
                                    0)
            mappings.append(mapping)

        return mappings


class GDBServerStateIterator(GDBServerConnector):
    def __init__(self, remote: str, deterministic_log: DeterministicLog):
        super().__init__(remote)

        self._deterministic_log = deterministic_log
        self._first_next = True

        self.event_start = time.time()
        events = self._deterministic_log.events()
        self.event_time = time.time() - self.event_start 

        self._signal_frames = []
        self._signal_restorers = {}

        first_state = self.current_state()
        self._events = EventMatcher(events,
                                    match_event,
                                    from_state=first_state)
        event = self._events.match(first_state)
        if event is None:
            raise RuntimeError(
                "Unable to synchronize QEMU with the deterministic event log."
            )
        self._replay_tid = event.tid

        # TODO: handle AT_RANDOM correctly
        # at_random = bytes([0xd1, 0x8f, 0x3a, 0x37, 0xb8, 0xba, 0x05, 0x54, 0x70, 0xdf, 0x3f, 0x89, 0x93, 0x64, 0xc2, 0x3c])
        # self._process.write_memory(0x7ffff6165d20, at_random)
        # actual_at_random = self._process.read_memory(0x7ffff6165d20, 16).tobytes()
        # assert(at_random == actual_at_random)
        
        info(f'Synchronized at PC={hex(first_state.read_pc())} to event:\n{event}')


    def _syscall_number_register(self) -> str:
        try:
            return syscall_number_registers[self.arch.archname]
        except KeyError as error:
            raise NotImplementedError(
                f'Syscall replay is unsupported for {self.arch.serialized_name}.'
            ) from error

    def _handle_syscall(self, event: Event, post_event: Event) -> ReadableProgramState:
        syscall_reg = self._syscall_number_register()
        call = event.registers.get(syscall_reg)
        state = self.current_state()
        next_state = None

        syscall = emulated_system_calls[self.arch.archname].get(call, None)
        if syscall is not None:
            if syscall.creates_thread:
                reject_thread_creating_effect(syscall.name)
            info(f'Replaying system call number {hex(call)}: {syscall.name}')

            self.skip(post_event.pc)
            next_state = GDBProgramState(self._process, gdb.selected_frame(), self.arch)

            patchup_regs = [syscall_reg, 'rip', *(syscall.patchup_registers or [])]
            for reg in patchup_regs:
                gdb.execute(f'set ${reg} = {post_event.registers.get(reg)}', to_string=True)
                next_state.write_register(reg, post_event.registers.get(reg))

            for mem in post_event.mem_writes:
                addr, data = mem.address, mem.data
                done = False
                for reg in syscall.patchup_address_registers:
                    value = post_event.registers[reg]
                    if value == addr:
                        addr = next_state.read_register(reg)
                        done = True
                        break

                if done is False:
                    raise RuntimeError(f'Cannot translate address {hex(addr)}')

                info(f'Replaying write to {hex(addr)} with data:\n{data.hex(" ")}')

                # Insert holes into data
                for hole in mem.holes:
                    data[hole.offset:hole.offset] = b'\x00' * hole.size
                self._process.write_memory(addr, data)

            if syscall.return_from_signal:
                frame = self._signal_frames.pop()
                debug(f'Handling return from signal with frame: {frame}')

                sc = frame.uctx.mcontext
                gdb.parse_and_eval(f'$r8 ={sc.r8}')
                gdb.parse_and_eval(f'$r9 ={sc.r9}')
                gdb.parse_and_eval(f'$r10 ={sc.r10}')
                gdb.parse_and_eval(f'$r11 ={sc.r11}')
                gdb.parse_and_eval(f'$r12 ={sc.r12}')
                gdb.parse_and_eval(f'$r13 ={sc.r13}')
                gdb.parse_and_eval(f'$r14 ={sc.r14}')
                gdb.parse_and_eval(f'$r15 ={sc.r15}')
                gdb.parse_and_eval(f'$rdi ={sc.rdi}')
                gdb.parse_and_eval(f'$rsi ={sc.rsi}')
                gdb.parse_and_eval(f'$rbp ={sc.rbp}')
                gdb.parse_and_eval(f'$rdx ={sc.rdx}')
                gdb.parse_and_eval(f'$rax ={sc.rax}')
                gdb.parse_and_eval(f'$rcx ={sc.rcx}')
                gdb.parse_and_eval(f'$rsp ={sc.rsp}')
                gdb.parse_and_eval(f'$rip ={sc.rip}')
                return self.current_state()

                # TODO: restart syscall

            if syscall.sets_signal_restorer:
                restorer_addr = self._process.read_memory(state.read_register('rsi') + 0x10, 8)
                restorer_addr = int.from_bytes(restorer_addr, byteorder='little')
                signo = event.registers['rdi']
                debug(f'System call {syscall.name} sets signal restorer for {signo} = {hex(restorer_addr)}')
                self._signal_restorers[signo] = restorer_addr

        syscall = passthrough_system_calls[self.arch.archname].get(call, None)
        if syscall is not None:
            assert(call is not None)
            if syscall.creates_thread:
                reject_thread_creating_effect(syscall.name)
            info(f'System call number {hex(call)} passed through')
            self._step()
            if self.is_exited():
                raise StopIteration

            next_state = GDBProgramState(self._process, gdb.selected_frame(), self.arch)

        if not next_state:
            info(f'System call number {hex(call)} not replayed')
            self._step()
            next_state = GDBProgramState(self._process, gdb.selected_frame(), self.arch)

        return next_state

    def _handle_signal(self, event: SignalEvent, post_event: SignalEvent):
        info('Handling signal event')
        sighandler_pc = post_event.pc

        state = self.current_state()
        rsp = state.read_register('rsp')

        sc = SigContext()
        sc.r8 = state.read_register('r8')
        sc.r9 = state.read_register('r9')
        sc.r10 = state.read_register('r10')
        sc.r11 = state.read_register('r11')
        sc.r12 = state.read_register('r12')
        sc.r13 = state.read_register('r13')
        sc.r14 = state.read_register('r14')
        sc.r15 = state.read_register('r15')
        sc.rdi = state.read_register('rdi')
        sc.rsi = state.read_register('rsi')
        sc.rbp = state.read_register('rbp')
        sc.rbx = state.read_register('rbx')
        sc.rdx = state.read_register('rdx')
        sc.rax = state.read_register('rax')
        sc.rcx = state.read_register('rcx')
        sc.rsp = state.read_register('rsp')
        sc.rip = state.read_register('rip')
        sc.eflags = state.read_register('eflags')

        sigmask = 0
        uctx = UContext(sigmask=sigmask, mcontext=sc)
        si_signo, si_errno, si_code = struct.unpack_from("<iii", event.signal_number.siginfo, 0)
        si_signo = 2
        siginfo = SigInfo(si_signo=si_signo, si_errno=si_errno, si_code=si_code,
                          si_pid=post_event.tid, si_uid=0)

        restorer_addr = self._signal_restorers[si_signo]
        frame = SigFrame(sp_new=rsp - 0xd78, pretcode=restorer_addr, uctx=uctx, siginfo=siginfo)
        self._process.write_memory(rsp - 0xd78, frame.to_bytes())

        gdb.execute(f'set $pc = {hex(sighandler_pc)}')
        patchup_regs = ['rdi']
        for reg in patchup_regs:
            gdb.parse_and_eval(f'${reg}={post_event.registers.get(reg)}')

        gdb.parse_and_eval('$rsp = $rsp - 0xd78')
        gdb.parse_and_eval('$rdx = $rsp + 0x8')
        gdb.parse_and_eval('$rsi = $rsp + 0x2c8')

        self._signal_frames.append(frame)
        return self.current_state()

    def _handle_event(self) -> ReadableProgramState | None:
        event = self._events.match(self.current_state())       

        if not event:
            return None

        require_event_thread(
            self._replay_tid,
            event.tid,
            context="Deterministic event",
        )
        self.event_start = time.time()
        if isinstance(event, SyscallEvent):
            post_event = self._events.match_pair(event)
            assert(post_event is not None)
            require_event_thread(
                self._replay_tid,
                post_event.tid,
                context="Paired system-call event",
            )

            self.event_time += time.time() - self.event_start
            return self._handle_syscall(event, post_event)

        if isinstance(event, SignalEvent):
            post_event = self._events.match_pair(event)
            assert(post_event is not None)
            require_event_thread(
                self._replay_tid,
                post_event.tid,
                context="Paired signal event",
            )
            self.event_time += time.time() - self.event_start
            return self._handle_signal(event, post_event)

        warn(f'Event handling for events of type {event.event_type} not implemented')
        return None

    def __iter__(self):
        return self

    def __next__(self) -> ReadableProgramState:
        # The first call to __next__ should yield the first program state,
        # i.e. before stepping the first time
        if self._first_next:
            self._first_next = False
            return GDBProgramState(self._process, gdb.selected_frame(), self.arch)

        state = self._handle_event()
        if self.is_exited():
            raise StopIteration

        if state is None:
            # Step
            debug('State is not provided; stepping')
            state = self._step()

        return state

    def run_until(self, addr: int) -> ReadableProgramState:
        events_handled = 0
        event = self._events.next()
        while event:
            state = self._run_until_any([addr, event.pc])
            if state.read_pc() == addr:
                # Check if we started at the very _start
                self._first_next = events_handled == 0
                return state

            self._handle_event()
            if self.is_exited():
                raise Exception(f'Exited before reaching start address {hex(addr)}')

            event = self._events.next()
            events_handled += 1
        return self._run_until_any([addr])

    def _run_until_any(self, addresses: list[int]) -> ReadableProgramState:
        info(f'Executing until {[hex(x) for x in addresses]}')

        breakpoints = []
        for addr in addresses:
            breakpoints.append(gdb.Breakpoint(f'*{addr:#x}'))

        gdb.execute('continue')

        for bp in breakpoints:
            bp.delete()

        return GDBProgramState(self._process, gdb.selected_frame(), self.arch)


