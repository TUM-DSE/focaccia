import gdb
import time
import logging
from focaccia.deterministic import (
    DeterministicLog,
    Event,
    EventSynchronizationError,
    SignalEvent,
    DeterministicCursor,
    CursorState,
    SyscallEvent,
    MemoryMapping,
)
from focaccia.snapshot import (
    ReadableProgramState,
    RegisterAccessError,
    MemoryAccessError,
)
from focaccia.arch import supported_architectures, Arch
from focaccia.qemu.concurrency import require_event_thread, require_single_inferior
from focaccia.qemu.replay import (
    AArch64ReplayEngine,
    X86ReplayEngine,
    make_replay_engine,
)
from focaccia.qemu.state import CachedBackendProgramState, RegisterObservation
from focaccia.qemu.syscall import (
    ReplayCoverageReport,
    SyscallPolicy,
    UnsupportedReplayEffect,
)

logger = logging.getLogger('focaccia-qemu-target')
debug = logger.debug
info = logger.info


def _is_synchronization_candidate(event: Event) -> bool:
    # Pair post-events are consumed transactionally and are never synchronization
    # candidates on their own.
    if isinstance(event, SyscallEvent):
        return event.syscall_state in ("entering", "enteringPtrace")
    if isinstance(event, SignalEvent):
        return event.signal_variant == "signal"
    return True


def match_event(event: Event, target: ReadableProgramState) -> bool:
    if not _is_synchronization_candidate(event):
        return False
    # Match just on PC. Some valid RR bookkeeping events record no registers.
    if event.pc is None:
        return False
    debug(f'Matching for PC {hex(target.read_pc())} with event {hex(event.pc)}')
    if event.pc == target.read_pc():
        return True
    return False


def require_event_pc(event: Event) -> int:
    if event.pc is None:
        raise EventSynchronizationError(
            f"RR event {event.event_count} ({event.event_type}) has no program counter "
            "and cannot be synchronized by the QEMU replay backend."
        )
    return event.pc


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

    def skip(self, new_pc: int) -> None:
        gdb.execute(f'set $pc = {hex(new_pc)}', to_string=True)

    def write_target_register(self, register: str, value: int) -> None:
        wire_name = "eflags" if register.lower() == "rflags" else register.lower()
        gdb.execute(f'set ${wire_name} = {hex(value)}', to_string=True)

    def write_target_memory(self, address: int, data: bytes) -> None:
        self._process.write_memory(address, data)

    def reset_signal_handler_fp_state(self) -> None:
        raise UnsupportedReplayEffect(
            "The QEMU GDB backend cannot reset the complete x86-64 signal-handler "
            "FP/XSTATE (the remote stub does not expose writable x87 tag state)."
        )

    def execute_replay_instruction(self) -> ReadableProgramState | None:
        try:
            return self._step()
        except StopIteration:
            return None

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
                                    'debugger',
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

        self._replay = make_replay_engine(self.arch) if events else None

        first_state = self.current_state()
        self._events = DeterministicCursor(events, match_event)
        event = self._events.synchronize(first_state)
        self._replay_tid = event.tid if event is not None else None

        # TODO: handle AT_RANDOM correctly
        # at_random = bytes([0xd1, 0x8f, 0x3a, 0x37, 0xb8, 0xba, 0x05, 0x54, 0x70, 0xdf, 0x3f, 0x89, 0x93, 0x64, 0xc2, 0x3c])
        # self._process.write_memory(0x7ffff6165d20, at_random)
        # actual_at_random = self._process.read_memory(0x7ffff6165d20, 16).tobytes()
        # assert(at_random == actual_at_random)
        
        if event is not None:
            require_event_pc(event)
            info(f'Synchronized at PC={hex(first_state.read_pc())} to event:\n{event}')
        elif events:
            self._next_synchronization_event()
            info(
                f'Started at PC={hex(first_state.read_pc())} before the first '
                'synchronizable RR event'
            )
        else:
            info(f'Started at PC={hex(first_state.read_pc())} without an RR event log')

    def _synchronize_at_state(self, state: ReadableProgramState) -> Event | None:
        event = self._events.synchronize(state)
        if event is not None:
            require_event_pc(event)
            if self._replay_tid is None:
                self._replay_tid = event.tid
            else:
                require_event_thread(
                    self._replay_tid,
                    event.tid,
                    context="Initial deterministic event",
                )
        return event

    def _next_synchronization_event(self) -> Event | None:
        if self._events.state is not CursorState.UNSYNCHRONIZED:
            return self._events.peek()
        for position, event in enumerate(self._events.events):
            event_count = event.event_count or position + 1
            if event_count in self._events.skipped_event_counts:
                continue
            if event.pc is not None and _is_synchronization_candidate(event):
                return event
        if self._events.events:
            raise EventSynchronizationError(
                "The deterministic log has no event with a program counter at which "
                "QEMU can synchronize."
            )
        return None

    def _require_replay_engine(self) -> X86ReplayEngine | AArch64ReplayEngine:
        if self._replay is None:
            raise RuntimeError("A deterministic event was found without a replay engine.")
        return self._replay

    def replay_coverage_report(self) -> ReplayCoverageReport | None:
        """Return an immutable effect-coverage snapshot, if replay is active."""
        return self._replay.coverage_report() if self._replay is not None else None

    def _handle_syscall(
        self,
        event: SyscallEvent,
        post_event: SyscallEvent | None,
        *,
        policy: SyscallPolicy | None = None,
    ) -> ReadableProgramState:
        replay = self._require_replay_engine()
        selected_policy = policy or replay.prepare_syscall(event)
        info(
            f"Handling system call {selected_policy.name} ({event.syscall_number:#x}) "
            f"with {selected_policy.strategy.value}"
        )
        return replay.replay_syscall(
            self,
            event,
            post_event,
            policy=selected_policy,
        )

    def _handle_signal(
        self,
        event: SignalEvent,
        post_event: SignalEvent,
    ) -> ReadableProgramState | None:
        info(f"Replaying signal {event.descriptor.signal_number}")
        return self._require_replay_engine().replay_signal(self, event, post_event)

    def _handle_event(self) -> ReadableProgramState | None:
        if self._events.state is CursorState.SYNCHRONIZED:
            pending_event = self._events.peek()
            if pending_event is not None:
                require_event_pc(pending_event)
        event = self._events.match(self.current_state())

        if not event:
            return None

        if self._replay_tid is None:
            self._replay_tid = event.tid
        require_event_thread(
            self._replay_tid,
            event.tid,
            context="Deterministic event",
        )
        self.event_start = time.time()
        if isinstance(event, SyscallEvent):
            policy = self._require_replay_engine().prepare_syscall(event)
            post_event = None
            if policy.requires_post_event:
                matched = self._events.match_pair(event)
                if not isinstance(matched, SyscallEvent):
                    raise RuntimeError(
                        "The deterministic cursor returned a non-syscall pair."
                    )
                require_event_thread(
                    self._replay_tid,
                    matched.tid,
                    context="Paired system-call event",
                )
                post_event = matched

            self.event_time += time.time() - self.event_start
            return self._handle_syscall(event, post_event, policy=policy)

        if isinstance(event, SignalEvent):
            post_event = self._events.match_pair(event)
            if not isinstance(post_event, SignalEvent):
                raise RuntimeError("The deterministic cursor returned a non-signal pair.")
            require_event_thread(
                self._replay_tid,
                post_event.tid,
                context="Paired signal event",
            )
            self.event_time += time.time() - self.event_start
            return self._handle_signal(event, post_event)

        self.event_time += time.time() - self.event_start
        return self._require_replay_engine().replay_bookkeeping_event(self, event)

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
        if self._replay is None:
            return self._run_until_any([addr])

        state = self.current_state()
        while (
            self._events.state is CursorState.UNSYNCHRONIZED
            and state.read_pc() != addr
        ):
            if self._synchronize_at_state(state) is not None:
                handled_state = self._handle_event()
                events_handled += 1
                if self.is_exited():
                    raise RuntimeError(
                        f'Exited before reaching start address {hex(addr)}'
                    )
                state = handled_state or self.current_state()
            else:
                try:
                    state = self._step()
                except StopIteration as error:
                    raise RuntimeError(
                        f'Exited before reaching start address {hex(addr)}'
                    ) from error

        if state.read_pc() == addr:
            self._synchronize_at_state(state)
            self._first_next = events_handled == 0
            return state
        if self._events.state is CursorState.EXHAUSTED:
            raise EventSynchronizationError(
                "The deterministic event log was exhausted before QEMU reached "
                f"the trace start address {addr:#x}."
            )

        event = self._next_synchronization_event()
        while event:
            event_pc = require_event_pc(event)
            state = self.current_state()
            self._synchronize_at_state(state)
            if state.read_pc() == addr:
                # Check if we started at the very _start
                self._first_next = events_handled == 0
                return state
            if state.read_pc() != event_pc:
                state = self._run_until_any(list(dict.fromkeys((addr, event_pc))))
                self._synchronize_at_state(state)
                if state.read_pc() == addr:
                    self._first_next = events_handled == 0
                    return state

            handled_state = self._handle_event()
            if self.is_exited():
                raise RuntimeError(f'Exited before reaching start address {hex(addr)}')
            if handled_state is None and self._events.state is CursorState.UNSYNCHRONIZED:
                raise EventSynchronizationError(
                    f"QEMU stopped at RR event PC {event_pc:#x} but the event log "
                    "did not synchronize."
                )

            event = self._next_synchronization_event()
            events_handled += 1
        state = self._run_until_any([addr])
        self._synchronize_at_state(state)
        return state

    def _run_until_any(self, addresses: list[int]) -> ReadableProgramState:
        info(f'Executing until {[hex(x) for x in addresses]}')

        breakpoints = []
        for addr in addresses:
            breakpoints.append(gdb.Breakpoint(f'*{addr:#x}'))

        gdb.execute('continue')

        for bp in breakpoints:
            bp.delete()

        return GDBProgramState(self._process, gdb.selected_frame(), self.arch)


