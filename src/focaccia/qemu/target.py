import gdb
import logging
import struct
from focaccia.deterministic import (
    DeterministicLog,
    Event,
    EventSynchronizationError,
    ExtraRegisterState,
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
from focaccia.qemu.report import TerminalReason
from focaccia.qemu.state import CachedBackendProgramState, RegisterObservation
from focaccia.qemu.syscall import (
    ReplayCoverageReport,
    SyscallPolicy,
    UnsupportedReplayEffect,
)

logger = logging.getLogger("focaccia-qemu-target")
debug = logger.debug
info = logger.info

_X86_SYSCALL_OPCODE = b"\x0f\x05"
_X86_SETUP_IMAGE_MAX_SIZE = 1 << 20
_X86_SETUP_SCAN_CHUNK_SIZE = 4096
_X86_ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
_X86_ELF_PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
_X86_ELF_MAX_PROGRAM_HEADERS = 128
_ELF_ET_DYN = 3
_ELF_EM_X86_64 = 62
_ELF_PT_LOAD = 1
_ELF_PF_X = 1
_ELF_PF_R = 4


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
    debug(f"Matching for PC {hex(target.read_pc())} with event {hex(event.pc)}")
    if event.pc == target.read_pc():
        return True
    return False


def _matching_initial_x86_exec(
    events: tuple[Event, ...], entry_pc: int
) -> tuple[int, SyscallEvent, SyscallEvent] | None:
    matches = tuple(
        (position, pre_event, post_event)
        for position, pre_event in enumerate(events[:-1])
        if isinstance(pre_event, SyscallEvent)
        and isinstance((post_event := events[position + 1]), SyscallEvent)
        and pre_event.syscall_number == 59
        and post_event.syscall_number == 59
        and post_event.syscall_state == "exiting"
        and post_event.pc == entry_pc
    )
    if len(matches) > 1:
        raise EventSynchronizationError(
            "RR log has multiple execve boundaries matching the QEMU ELF entry."
        )
    return matches[0] if matches else None


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
            component = int(values[index].cast(gdb.lookup_type("unsigned long")))
            result |= component << (index * 64)
        return result

    @staticmethod
    def _read_raw_register(value: gdb.Value, size: int) -> int:
        raw = bytes(value.bytes)
        if len(raw) != size // 8:
            raise ValueError(
                f"GDB returned {len(raw)} bytes for a {size}-bit register."
            )
        return int.from_bytes(raw, "little")

    read_vector_reg = {
        aarch64.archname: _read_vector_reg_aarch64,
        x86.archname: _read_vector_reg_x86,
    }

    def _read_backend_register(
        self,
        base_reg: str,
        requested_reg: str | None = None,
    ) -> RegisterObservation:
        requested = self.arch.get_reg_accessor(requested_reg) if requested_reg else None
        use_narrow_alias = requested is not None and requested.num_bits >= 128
        observation_name = requested_reg if use_narrow_alias else base_reg
        wire_name = (
            self.flag_backend_names[self.arch.archname]
            if self._flags_base is not None and base_reg == self._flags_base
            else observation_name.lower()
        )
        try:
            if self.arch.archname == self.x86.archname and base_reg.startswith("MM"):
                fstat = int(
                    self._frame.read_register("fstat").cast(
                        gdb.lookup_type("unsigned int")
                    )
                )
                wire_name = self.x86.mmx_logical_st_name(base_reg, fstat)
                value = self._frame.read_register(wire_name)
                size = value.type.sizeof * 8
                if size != 80:
                    raise ValueError(f"MMX backing register {wire_name} has width {size}.")
                numeric = self._read_raw_register(value, size) & ((1 << 64) - 1)
                return RegisterObservation(base_reg, numeric, 64)

            canonical = self.arch.to_regname(wire_name)
            if canonical is None:
                raise RegisterAccessError(
                    base_reg,
                    f"GDB register {wire_name!r} is not in the guest architecture.",
                )
            value = self._frame.read_register(wire_name)
            size = value.type.sizeof * 8
            if size >= 128:
                reader = self.read_vector_reg.get(self.arch.archname)
                if reader is None:
                    raise ValueError(f"Vector registers are unsupported for {self.arch}.")
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
        self._terminal_reason: TerminalReason | None = None
        gdb.events.stop.connect(self._record_stop_event)
        gdb.execute("set pagination 0")
        gdb.execute("set sysroot")
        gdb.execute("set python print-stack full")  # enable complete Python tracebacks
        gdb.execute(f"target remote {remote}")
        gdb.execute("set scheduler-locking on")
        self._process = gdb.selected_inferior()
        require_single_inferior(len(self._process.threads()))

        split = self._process.architecture().name().split(":")
        archname = split[1] if len(split) > 1 else split[0]
        archname = archname.replace("-", "_")
        if archname not in supported_architectures:
            raise NotImplementedError(f"Platform {archname} is not supported by Focaccia")

        self.arch = supported_architectures[archname]
        self.binary = self._process.progspace.filename

    def _record_stop_event(self, event: object) -> None:
        if not isinstance(event, gdb.SignalEvent):
            return
        try:
            pc = int(gdb.selected_frame().read_register("pc"))
        except (RuntimeError, ValueError, gdb.error):
            pc = None
        self._terminal_reason = TerminalReason(
            kind="signal",
            signal=str(event.stop_signal),
            pc=pc,
        )

    def terminal_reason(self) -> TerminalReason | None:
        return self._terminal_reason

    def current_state(self) -> ReadableProgramState:
        return GDBProgramState(self._process, gdb.selected_frame(), self.arch)

    def skip(self, new_pc: int) -> None:
        gdb.execute(f"set $pc = {hex(new_pc)}", to_string=True)

    def write_target_register(self, register: str, value: int) -> None:
        wire_name = "eflags" if register.lower() == "rflags" else register.lower()
        gdb.execute(f"set ${wire_name} = {hex(value)}", to_string=True)

    def write_target_memory(self, address: int, data: bytes) -> None:
        self._process.write_memory(address, data)

    def _x86_executable_image_ranges(
        self,
        image_address: int,
    ) -> tuple[tuple[int, int], ...]:
        state = self.current_state()
        encoded_header = state.read_memory(image_address, _X86_ELF_HEADER.size)
        (
            ident,
            elf_type,
            machine,
            version,
            _entry,
            program_header_offset,
            _section_header_offset,
            _flags,
            header_size,
            program_header_size,
            program_header_count,
            _section_header_size,
            _section_header_count,
            _section_name_index,
        ) = _X86_ELF_HEADER.unpack(encoded_header)
        if ident[:7] != b"\x7fELF\x02\x01\x01":
            raise UnsupportedReplayEffect("Initial setup image is not little-endian ELF64.")
        if elf_type != _ELF_ET_DYN or machine != _ELF_EM_X86_64 or version != 1:
            raise UnsupportedReplayEffect("Initial setup image is not x86-64 ET_DYN ELF.")
        if header_size != _X86_ELF_HEADER.size:
            raise UnsupportedReplayEffect("Initial setup image has an invalid ELF header size.")
        if (
            program_header_size != _X86_ELF_PROGRAM_HEADER.size
            or program_header_count <= 0
            or program_header_count > _X86_ELF_MAX_PROGRAM_HEADERS
        ):
            raise UnsupportedReplayEffect(
                "Initial setup image has an invalid ELF program-header table."
            )
        table_size = program_header_size * program_header_count
        table_end = program_header_offset + table_size
        if (
            program_header_offset < header_size
            or table_end < program_header_offset
            or table_end > _X86_SETUP_IMAGE_MAX_SIZE
        ):
            raise UnsupportedReplayEffect(
                "Initial setup ELF program-header table is outside the bounded image."
            )
        encoded_program_headers = state.read_memory(
            image_address + program_header_offset,
            table_size,
        )

        load_segments: list[tuple[int, int, int, int, int]] = []
        for index in range(program_header_count):
            start = index * program_header_size
            (
                segment_type,
                segment_flags,
                file_offset,
                virtual_address,
                _physical_address,
                file_size,
                memory_size,
                _alignment,
            ) = _X86_ELF_PROGRAM_HEADER.unpack_from(encoded_program_headers, start)
            if segment_type != _ELF_PT_LOAD:
                continue
            if file_size > memory_size or virtual_address + memory_size < virtual_address:
                raise UnsupportedReplayEffect(
                    "Initial setup ELF has an invalid load segment."
                )
            load_segments.append(
                (segment_flags, file_offset, virtual_address, file_size, memory_size)
            )

        header_segments = [
            segment
            for segment in load_segments
            if segment[1] == 0 and segment[3] >= table_end and segment[0] & _ELF_PF_R
        ]
        if len(header_segments) != 1:
            raise UnsupportedReplayEffect(
                "Initial setup ELF headers are not covered by one readable load segment."
            )
        load_bias = image_address - header_segments[0][2]
        executable_ranges: list[tuple[int, int]] = []
        for segment_flags, _file_offset, virtual_address, file_size, memory_size in load_segments:
            runtime_start = load_bias + virtual_address
            runtime_end = runtime_start + memory_size
            if (
                runtime_start < 0
                or runtime_end < runtime_start
                or runtime_start < image_address - _X86_SETUP_IMAGE_MAX_SIZE
                or runtime_end > image_address + _X86_SETUP_IMAGE_MAX_SIZE
            ):
                raise UnsupportedReplayEffect(
                    "Initial setup ELF load segment is outside the bounded runtime image."
                )
            if file_size and segment_flags & (_ELF_PF_R | _ELF_PF_X) == (
                _ELF_PF_R | _ELF_PF_X
            ):
                executable_ranges.append((runtime_start, file_size))
        if not executable_ranges:
            raise UnsupportedReplayEffect("Initial setup ELF has no executable load segment.")
        return tuple(executable_ranges)

    def _find_x86_syscall_instruction(
        self,
        image_address: int,
        mapping_start: int,
        mapping_end: int,
    ) -> int:
        executable_ranges = self._x86_executable_image_ranges(image_address)
        for start, size in executable_ranges:
            if mapping_start < start + size and mapping_end > start:
                raise UnsupportedReplayEffect(
                    "Initial target mapping overlaps the setup executable image."
                )
            overlap = b""
            for offset in range(0, size, _X86_SETUP_SCAN_CHUNK_SIZE):
                chunk_size = min(_X86_SETUP_SCAN_CHUNK_SIZE, size - offset)
                address = start + offset
                data = self.current_state().read_memory(address, chunk_size)
                search = overlap + data
                position = search.find(_X86_SYSCALL_OPCODE)
                if position >= 0:
                    return address - len(overlap) + position
                overlap = search[-1:]
        raise UnsupportedReplayEffect("Initial setup image has no x86 SYSCALL instruction.")

    def map_target_memory(
        self,
        address: int,
        length: int,
        protection: int,
        flags: int,
        syscall_image_address: int,
    ) -> None:
        if self.arch.archname != "x86_64":
            raise UnsupportedReplayEffect(
                "Initial target-memory setup is implemented only for x86-64."
            )
        if (
            address < 0
            or length <= 0
            or address + length > 1 << 64
            or address & 0xFFF
            or length & 0xFFF
        ):
            raise UnsupportedReplayEffect("Initial target mapping is not a valid page range.")
        if protection & ~0x7 or flags not in (0x100022, 0x100122):
            raise UnsupportedReplayEffect("Initial target mapping has unsupported flags.")

        setup_pc = self._find_x86_syscall_instruction(
            syscall_image_address,
            address,
            address + length,
        )
        if self.current_state().read_memory(setup_pc, 2) != _X86_SYSCALL_OPCODE:
            raise UnsupportedReplayEffect("Initial setup SYSCALL bytes changed before execution.")
        inputs = {
            "rax": 9,
            "rdi": address,
            "rsi": length,
            "rdx": protection,
            "r10": flags,
            "r8": (1 << 64) - 1,
            "r9": 0,
        }
        try:
            for register, value in inputs.items():
                self.write_target_register(register, value)
            self.skip(setup_pc)
            self._terminal_reason = None
            gdb.execute("si", to_string=True)
            if self._terminal_reason is not None or self.is_exited():
                raise UnsupportedReplayEffect("Initial mmap did not complete normally.")
            stopped_pc = int(gdb.selected_frame().read_register("pc"))
            if stopped_pc != setup_pc + 2:
                raise UnsupportedReplayEffect(
                    f"Initial mmap stopped at {stopped_pc:#x}, expected {setup_pc + 2:#x}."
                )
            result = int(gdb.selected_frame().read_register("rax")) & ((1 << 64) - 1)
            if result != address:
                raise UnsupportedReplayEffect(
                    f"Initial fixed mmap returned {result:#x}, expected {address:#x}."
                )
            if self.current_state().read_memory(setup_pc, 2) != _X86_SYSCALL_OPCODE:
                raise UnsupportedReplayEffect("Initial setup changed its SYSCALL bytes.")
        except (RegisterAccessError, MemoryAccessError, RuntimeError, ValueError, gdb.error) as error:
            if isinstance(error, UnsupportedReplayEffect):
                raise
            raise UnsupportedReplayEffect(f"Initial mmap setup failed: {error}.") from error

    def write_signal_handler_extra_registers(
        self,
        extra_registers: ExtraRegisterState,
    ) -> None:
        if extra_registers.format != "x86-xsave-v1":
            raise UnsupportedReplayEffect(
                f"The QEMU GDB backend cannot establish "
                f"{extra_registers.format} signal-handler state."
            )
        try:
            for index in range(16):
                value = extra_registers.read_register(f"xmm{index}")
                gdb.execute(
                    f"set $xmm{index}.uint128 = {value:#x}",
                    to_string=True,
                )
            mxcsr = extra_registers.read_register("mxcsr")
            gdb.execute(f"set $mxcsr = {mxcsr:#x}", to_string=True)

            state = self.current_state()
            for index in range(16):
                register = f"xmm{index}"
                expected = extra_registers.read_register(register)
                observed = state.read_register(register)
                if observed != expected:
                    raise RegisterAccessError(
                        register,
                        f"QEMU retained {observed:#x}, expected {expected:#x}.",
                    )
            observed_mxcsr = int(gdb.parse_and_eval("$mxcsr"))
            if observed_mxcsr != mxcsr:
                raise RegisterAccessError(
                    "mxcsr",
                    f"QEMU retained {observed_mxcsr:#x}, expected {mxcsr:#x}.",
                )
        except (KeyError, ValueError, RegisterAccessError, gdb.error) as error:
            raise UnsupportedReplayEffect(
                "The QEMU GDB backend could not write and verify the recorded "
                f"MXCSR/XMM signal-handler state: {error}."
            ) from error

    def execute_replay_instruction(
        self, expected_pc: int | None = None
    ) -> ReadableProgramState | None:
        try:
            if expected_pc is not None:
                return self._run_until_any([expected_pc])
            return self._step()
        except StopIteration:
            return None

    def _step(self):
        pc = gdb.selected_frame().read_register("pc")
        new_pc = pc
        while pc == new_pc:  # Skip instruction chains from REP STOS etc.
            self._terminal_reason = None
            gdb.execute("si", to_string=True)
            if self._terminal_reason is not None or self.is_exited():
                raise StopIteration
            new_pc = gdb.selected_frame().read_register("pc")
        return self.current_state()

    def is_exited(self) -> bool:
        return not self._process.is_valid() or len(self._process.threads()) == 0

    def get_sections(self) -> list[MemoryMapping]:
        mappings = []

        # Skip everything until the header line
        started = False

        text = gdb.execute("info proc mappings", to_string=True)
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

            start = int(parts[0], 16)
            end = int(parts[1], 16)
            size = int(parts[2], 16)
            offset = int(parts[3], 16)
            perms = parts[4]

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

            mapping = MemoryMapping(0, start, end, "debugger", offset, 0, 0)
            mappings.append(mapping)

        return mappings


class GDBServerStateIterator(GDBServerConnector):
    def __init__(self, remote: str, deterministic_log: DeterministicLog):
        super().__init__(remote)

        self._deterministic_log = deterministic_log
        self._first_next = True

        events = self._deterministic_log.events()

        self._replay = make_replay_engine(self.arch) if events else None

        first_state = self.current_state()
        initial_position = 0
        self._replay_tid = None
        if isinstance(self._replay, X86ReplayEngine):
            initial_exec = _matching_initial_x86_exec(events, first_state.read_pc())
            if initial_exec is not None:
                position, pre_event, post_event = initial_exec
                first_state = self._replay.replay_initial_exec(
                    self,
                    pre_event,
                    post_event,
                    self._deterministic_log.mmaps(),
                )
                initial_position = position + 2
                self._replay_tid = pre_event.tid

        # The setup transaction consumes the leading execve pair before the
        # first ordinary event-PC synchronization point. RR events carry their
        # original explicit counts, so slicing does not alter diagnostics.
        self._events = DeterministicCursor(events[initial_position:], match_event)
        event = self._events.synchronize(first_state)
        if event is not None:
            self._replay_tid = event.tid if self._replay_tid is None else self._replay_tid

        if event is not None:
            require_event_pc(event)
            info(f"Synchronized at PC={hex(first_state.read_pc())} to event:\n{event}")
        elif events:
            self._next_synchronization_event()
            info(
                f"Started at PC={hex(first_state.read_pc())} before the first "
                "synchronizable RR event"
            )
        else:
            info(f"Started at PC={hex(first_state.read_pc())} without an RR event log")

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
        if isinstance(event, SyscallEvent):
            policy = self._require_replay_engine().prepare_syscall(event)
            post_event = None
            if policy.requires_post_event:
                matched = self._events.match_pair(event)
                if not isinstance(matched, SyscallEvent):
                    raise RuntimeError("The deterministic cursor returned a non-syscall pair.")
                require_event_thread(
                    self._replay_tid,
                    matched.tid,
                    context="Paired system-call event",
                )
                post_event = matched

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
            return self._handle_signal(event, post_event)

        return self._require_replay_engine().replay_bookkeeping_event(self, event)

    def __iter__(self):
        return self

    def next_cutpoint_pc(self, matcher) -> int | None:
        """Declare the next symbolic destination before the inferior advances."""
        return matcher.current_destination_pc

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
            debug("State is not provided; stepping")
            state = self._step()

        return state

    def run_until(self, addr: int) -> ReadableProgramState:
        events_handled = 0
        if self._replay is None:
            return self._run_until_any([addr])

        state = self.current_state()
        while self._events.state is CursorState.UNSYNCHRONIZED and state.read_pc() != addr:
            if self._synchronize_at_state(state) is not None:
                handled_state = self._handle_event()
                events_handled += 1
                if self.is_exited():
                    raise RuntimeError(f"Exited before reaching start address {hex(addr)}")
                state = handled_state or self.current_state()
            else:
                try:
                    state = self._step()
                except StopIteration as error:
                    raise RuntimeError(
                        f"Exited before reaching start address {hex(addr)}"
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
                raise RuntimeError(f"Exited before reaching start address {hex(addr)}")
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
        info(f"Executing until {[hex(x) for x in addresses]}")

        breakpoints = []
        for addr in addresses:
            breakpoints.append(gdb.Breakpoint(f"*{addr:#x}"))

        self._terminal_reason = None
        try:
            gdb.execute("continue")
        finally:
            for bp in breakpoints:
                bp.delete()

        if self._terminal_reason is not None or self.is_exited():
            raise StopIteration
        return GDBProgramState(self._process, gdb.selected_frame(), self.arch)
