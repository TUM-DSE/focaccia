import gdb
import logging
import struct
from focaccia.qemu.transport_profile import bind_xmm_read_transport, normalize_xmm_read
import signal
from collections.abc import Callable
from pathlib import Path
from focaccia.execution import ExecutionOutcome, ExecutionState, TerminalComparison
from focaccia.completion import TraceCompletion
from focaccia.no_replay import (
    AnonymousMmapAction,
    ExitAction,
    ExitScope,
    NoReplayActionKind,
    describe_no_replay_action,
    no_replay_syscall_opcode,
    prepare_no_replay_action,
    MprotectNoneAction,
    NoReplayMmapBoundary,
    NoReplayMprotectBoundary,
    NoReplaySetFsBoundary,
    NoReplaySetTidBoundary,
    require_private_tid_storage,
    snapshot_set_tid_inputs,
    validate_set_tid_effect,
    validate_set_tid_transition,
    SetFsAction,
    snapshot_set_fs_inputs,
    validate_set_fs_effect,
    require_same_no_replay_action,
)
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
from focaccia.qemu.report import TerminalReason, TerminalActionValidation
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
_X86_SETUP_IMAGE_MAX_SPAN = 1 << 32
_X86_SETUP_SCAN_MAX_BYTES = 1 << 20
_X86_SETUP_SCAN_CHUNK_SIZE = 4096
_X86_ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
_X86_ELF_PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
_X86_ELF_MAX_PROGRAM_HEADERS = 128
_ELF_ET_EXEC = 2
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

    def __init__(
        self, process: gdb.Inferior, frame: gdb.Frame, arch: Arch,
        require_current: Callable[[], None] | None = None,
    ):
        super().__init__(arch)
        self._proc = process
        self._frame = frame
        # The connector proves the inferior stopped once when constructing this
        # boundary.  Per-register thread enumeration is both redundant and
        # expensive; this token instead rejects reads after any resume/write or
        # newly observed stop.
        self._require_current = require_current
        self._aarch64_cpu_context: str | None = None
        self._xmm_read_transport = False
        flags_name = self.flag_backend_names.get(arch.archname)
        canonical_flags = arch.to_regname(flags_name) if flags_name else None
        flags = arch.get_reg_accessor(canonical_flags) if canonical_flags else None
        self._flags_base = flags.base_reg if flags is not None else None

    @staticmethod
    def _read_vector_reg_aarch64(value: gdb.Value, _size: int) -> int:
        # GDB 16 exposes Value.bytes in little-endian significance order, even
        # when the formatted union renders its lanes as '{0, 0}'. Never parse
        # that display text as one decimal integer.
        try:
            raw = bytes(value.bytes)
        except AttributeError:
            pass
        else:
            if len(raw) != _size // 8:
                raise ValueError(f'GDB returned {len(raw)} vector bytes, expected {_size // 8}.')
            return int.from_bytes(raw, 'little')
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
        if self._require_current is not None:
            self._require_current()
        requested = self.arch.get_reg_accessor(requested_reg) if requested_reg else None
        use_narrow_alias = requested is not None and requested.num_bits >= 128
        observation_name = requested_reg if use_narrow_alias else base_reg
        wire_name = (
            self.flag_backend_names[self.arch.archname]
            if self._flags_base is not None and base_reg == self._flags_base
            else observation_name.lower()
        )
        # QEMU's dynamic AArch64 system-register XML retains ARMCPRegInfo.name,
        # unlike its lowercase core register names. Canonical TPIDR is EL0 TLS.
        if self.arch.archname == self.aarch64.archname:
            if base_reg == "TPIDR":
                wire_name = "TPIDR_EL0"
            elif base_reg == "DCZID_EL0":
                wire_name = "DCZID_EL0"
        try:
            if base_reg == 'DCZID_EL0' and self._aarch64_cpu_context is not None:
                # DCZID is ARM_CP_NO_RAW in Linux-user QEMU, so the GDB XML
                # omits it. The explicitly selected Neoverse-V1 model defines
                # BS=4 (64 bytes). Bind identity/control using OTHER exposed
                # registers, never the emulated MRS destination or native data.
                midr = int(self._frame.read_register('MIDR_EL1'))
                pstate = int(self._frame.read_register('cpsr'))
                sctlr = int(self._frame.read_register('SCTLR'))
                if (self.arch.archname != 'aarch64' or self._aarch64_cpu_context != 'neoverse-v1'
                        or midr != 0x411FD402 or pstate & 0x1F):
                    raise ValueError('AArch64 configured CPU identity/EL0 context differs.')
                return RegisterObservation(base_reg, 4 | (0 if sctlr & (1 << 14) else 16), 64)
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
                if self._xmm_read_transport:
                    numeric = normalize_xmm_read(numeric, canonical, size)
            elif size <= 32:
                numeric = int(value.cast(gdb.lookup_type("unsigned int")))
            elif size == 64:
                numeric = int(value.cast(gdb.lookup_type("unsigned long")))
            else:
                raise ValueError(f"Unsupported scalar register width {size}.")
            # GDB's x86 XML transports 16-bit selectors in 32-bit slots.
            # Reject nonzero padding rather than silently truncating bad data.
            if (
                self.arch.archname == self.x86.archname
                and canonical in {"CS", "DS", "ES", "FS", "GS", "SS"}
                and size == 32
            ):
                if not 0 <= numeric < 1 << 16:
                    raise ValueError(f"Nonzero reserved bits in GDB selector {canonical}.")
                size = 16
        except (ValueError, RuntimeError, gdb.error) as error:
            raise RegisterAccessError(
                base_reg,
                f"GDB cannot access register {wire_name}: {error}.",
            ) from error
        return RegisterObservation(canonical, numeric, size)

    def _read_backend_memory(self, addr: int, size: int) -> bytes:
        if self._require_current is not None:
            self._require_current()
        try:
            return self._proc.read_memory(addr, size).tobytes()
        except gdb.MemoryError as error:
            raise MemoryAccessError(addr, size, str(error)) from error


class GDBServerConnector:
    def __init__(self, remote: str):
        self._terminal_reason: TerminalReason | None = None
        self._exit_outcome: ExecutionOutcome | None = None
        self._stop_signal: int | None = None
        self._observers_connected = False
        self._stop_generation = 0
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
        self._clear_exit_signal()
        gdb.events.stop.connect(self._record_stop_event)
        gdb.events.exited.connect(self._record_exit_event)
        self._mutation_events = tuple(
            event
            for name in ("cont", "register_changed", "memory_changed")
            if (event := getattr(gdb.events, name, None)) is not None
        )
        for event in self._mutation_events:
            event.connect(self._record_debugger_mutation)
        self._observers_connected = True

    def _owns_event(self, event: object) -> bool:
        inferior = getattr(event, "inferior", None)
        thread = getattr(event, "inferior_thread", None)
        if inferior is None and thread is not None:
            inferior = thread.inferior
        if inferior is None:
            # All-stop StopEvents have no thread; ExitedEvents must identify
            # their inferior explicitly, never borrow the selected inferior.
            if not isinstance(event, gdb.StopEvent):
                return False
            inferior = gdb.selected_inferior()
        return inferior == self._process

    def _clear_exit_signal(self) -> None:
        # Convenience variables are global, not process-owned. Clear any old
        # value before execution so another process's exit cannot be reused.
        gdb.set_convenience_variable("_exitsignal", None)

    def _record_exit_event(self, event: object) -> None:
        if not self._owns_event(event):
            self._clear_exit_signal()
            return
        self._advance_stop_generation()
        status = getattr(event, "exit_code", None)
        if type(status) is int and 0 <= status <= 255:
            self._exit_outcome = ExecutionOutcome(
                ExecutionState.EXITED, exit_status=status, backend_status=status
            )
            return
        terminating_signal = None
        if status is None and gdb.selected_inferior() == self._process:
            try:
                value = gdb.convenience_variable("_exitsignal")
                if value is not None and value.type.code == gdb.TYPE_CODE_INT:
                    number = int(value)
                    if number > 0:
                        terminating_signal = number
            except (RuntimeError, ValueError, TypeError, gdb.error):
                pass
            if terminating_signal is None:
                # For remote targets that omit $_exitsignal, an owned exit
                # event raised synchronously by GDB's `signal NAME` operation
                # is its target-semantics confirmation of that termination.
                delivered = getattr(self, "_delivering_guest_signal", None)
                if type(delivered) is int and delivered > 0:
                    terminating_signal = delivered
        self._exit_outcome = ExecutionOutcome(
            ExecutionState.EXITED,
            termination_signal=terminating_signal,
            description=(None if terminating_signal is not None else
                         "GDB exit event has no valid termination cause."),
            backend_status=status if type(status) is int else None,
        )

    def execution_outcome(self) -> ExecutionOutcome:
        outcome = getattr(self, "_exit_outcome", None)
        if outcome is not None:
            return outcome
        observation_error = getattr(self, "_observation_error", None)
        if observation_error is not None:
            return ExecutionOutcome(ExecutionState.UNKNOWN, description=observation_error)
        try:
            if not self._process.is_valid():
                return ExecutionOutcome(ExecutionState.UNKNOWN, description="Invalid GDB inferior.")
            threads = self._process.threads()
            if not threads:
                return ExecutionOutcome(ExecutionState.UNKNOWN, description="No GDB threads; exit unobserved.")
            if any(thread.is_running() for thread in threads):
                return ExecutionOutcome(ExecutionState.RUNNING)
            if all(thread.is_stopped() for thread in threads):
                return ExecutionOutcome(
                    ExecutionState.STOPPED, stop_signal=getattr(self, "_stop_signal", None)
                )
        except (RuntimeError, gdb.error) as error:
            return ExecutionOutcome(ExecutionState.UNKNOWN, description=str(error))
        return ExecutionOutcome(ExecutionState.UNKNOWN, description="GDB thread state unavailable.")

    def _advance_stop_generation(self) -> None:
        self._stop_generation = getattr(self, "_stop_generation", 0) + 1

    def _require_stop_generation(
        self,
        generation: int,
        frame: gdb.Frame,
        thread: object,
    ) -> None:
        if getattr(self, "_exit_outcome", None) is not None:
            raise RuntimeError("Cannot read GDB state: exited.")
        unchanged = generation == getattr(self, "_stop_generation", 0)
        try:
            valid = self._process.is_valid() and frame.is_valid()
            selected = (
                gdb.selected_inferior() == self._process
                and gdb.selected_thread() == thread
                and gdb.selected_frame() == frame
            )
        except (RuntimeError, gdb.error):
            valid = selected = False
        if not unchanged or not valid or not selected:
            raise RuntimeError("Cannot read a GDB state after its stop context changed.")

    def _resume(self, command: str, *, to_string: bool = True) -> str | None:
        self._require_stopped()
        self._advance_stop_generation()
        self._terminal_reason = None
        self._stop_signal = None
        self._clear_exit_signal()
        try:
            return gdb.execute(command, to_string=to_string)
        except (gdb.error, EOFError) as error:
            self._observation_error = f"GDB execution failed: {error}"
            raise

    def _require_stopped(self) -> None:
        outcome = self.execution_outcome()
        if outcome.state is not ExecutionState.STOPPED:
            raise RuntimeError(f"Cannot read GDB state: {outcome.state.value}: {outcome.description}")
        if gdb.selected_inferior() != self._process:
            raise RuntimeError("Cannot read state from a different GDB inferior.")

    def close(self) -> None:
        """Release owned event subscriptions without terminating the inferior."""
        if self._observers_connected:
            gdb.events.stop.disconnect(self._record_stop_event)
            gdb.events.exited.disconnect(self._record_exit_event)
            for event in getattr(self, "_mutation_events", ()):
                event.disconnect(self._record_debugger_mutation)
            self._observers_connected = False

    def _record_debugger_mutation(self, event: object) -> None:
        """Invalidate cache tokens for writes made outside connector helpers."""
        frame = getattr(event, "frame", None)
        inferior = getattr(event, "inferior", None)
        if frame is not None:
            inferior = frame.inferior_thread().inferior
        if inferior is None:
            inferior = gdb.selected_inferior()
        if inferior == self._process:
            self._advance_stop_generation()

    def _record_stop_event(self, event: object) -> None:
        if not self._owns_event(event) or self.is_exited():
            return
        self._advance_stop_generation()
        self._stop_signal = None
        if not isinstance(event, gdb.SignalEvent):
            return
        number = getattr(signal, str(event.stop_signal), None)
        self._stop_signal = int(number) if number is not None else None
        try:
            self._require_stopped()
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

    def deliver_pending_guest_signal_once(self) -> ExecutionOutcome:
        """Deliver the owned GDB signal stop once and record what happens next.

        ``signal NAME`` is GDB's target-level signal-delivery operation.  It may
        terminate the guest, enter a user handler and later stop/exit, or lose
        observation.  None of those possibilities is inferred from the signal
        name, and a second delivery is forbidden.
        """
        reason = self._terminal_reason
        if reason is None or reason.kind != "signal":
            raise RuntimeError("No pending guest signal is available for delivery.")
        if reason.delivered:
            raise RuntimeError("The pending guest signal was already delivered.")
        raw_number = getattr(signal, reason.signal, None)
        number = int(raw_number) if raw_number is not None else None
        try:
            canonical = signal.Signals(number).name if number is not None else None
        except ValueError:
            canonical = None
        if canonical != reason.signal or self.execution_outcome().stop_signal != number:
            raise RuntimeError("The GDB signal stop has no unambiguous deliverable signal.")
        self._delivering_guest_signal = number
        try:
            self._resume(f"signal {reason.signal}")
        finally:
            self._delivering_guest_signal = None
        outcome = self.execution_outcome()
        self._terminal_reason = TerminalReason(
            kind=reason.kind,
            signal=reason.signal,
            pc=reason.pc,
            delivered=True,
            outcome=outcome,
        )
        return outcome

    def current_state(self) -> ReadableProgramState:
        self._require_stopped()
        generation = getattr(self, "_stop_generation", 0)
        frame = gdb.selected_frame()
        thread = gdb.selected_thread()
        state = GDBProgramState(
            self._process,
            frame,
            self.arch,
            lambda: self._require_stop_generation(generation, frame, thread),
        )
        transport = getattr(self, '_xmm_read_transport_binding', None)
        if transport is not None:
            transport.verify_identity(self._independent_task_tid())
            state._xmm_read_transport = True
        cpu_context = getattr(self, '_aarch64_cpu_context', None)
        if cpu_context is not None:
            if self._independent_task_tid() != self._aarch64_cpu_context_tid:
                raise UnsupportedReplayEffect('Configured AArch64 CPU process changed.')
            state._aarch64_cpu_context = cpu_context
        state.allocation_bases = tuple(getattr(self, "_no_replay_allocation_bases", ()))
        context_tid = getattr(self, "_no_replay_context_tid", None)
        if context_tid is not None:
            if self._independent_task_tid() != context_tid:
                raise UnsupportedReplayEffect("QEMU execution task identity changed.")
            state.execution_tid = context_tid
        return state

    def skip(self, new_pc: int) -> None:
        self._require_stopped()
        self._advance_stop_generation()
        gdb.execute(f"set $pc = {hex(new_pc)}", to_string=True)

    def write_target_register(self, register: str, value: int) -> None:
        self._require_stopped()
        self._advance_stop_generation()
        wire_name = "eflags" if register.lower() == "rflags" else register.lower()
        gdb.execute(f"set ${wire_name} = {hex(value)}", to_string=True)

    def write_target_memory(self, address: int, data: bytes) -> None:
        self._require_stopped()
        self._advance_stop_generation()
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
        if elf_type not in (_ELF_ET_EXEC, _ELF_ET_DYN) or machine != _ELF_EM_X86_64 or version != 1:
            raise UnsupportedReplayEffect("Initial setup image is not x86-64 ELF.")
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
            or table_end > _X86_SETUP_SCAN_MAX_BYTES
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
        if elf_type == _ELF_ET_EXEC and load_bias != 0:
            raise UnsupportedReplayEffect("Initial ET_EXEC setup image has a nonzero load bias.")
        executable_ranges: list[tuple[int, int]] = []
        for segment_flags, _file_offset, virtual_address, file_size, memory_size in load_segments:
            runtime_start = load_bias + virtual_address
            runtime_end = runtime_start + memory_size
            if (
                runtime_start < 0
                or runtime_end < runtime_start
                or runtime_start < image_address - _X86_SETUP_IMAGE_MAX_SPAN
                or runtime_end > image_address + _X86_SETUP_IMAGE_MAX_SPAN
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
        remaining_scan = _X86_SETUP_SCAN_MAX_BYTES
        for start, size in executable_ranges:
            if mapping_start < start + size and mapping_end > start:
                raise UnsupportedReplayEffect(
                    "Initial target mapping overlaps the setup executable image."
                )
            overlap = b""
            scan_size = min(size, remaining_scan)
            for offset in range(0, scan_size, _X86_SETUP_SCAN_CHUNK_SIZE):
                chunk_size = min(_X86_SETUP_SCAN_CHUNK_SIZE, scan_size - offset)
                address = start + offset
                data = self.current_state().read_memory(address, chunk_size)
                search = overlap + data
                position = search.find(_X86_SYSCALL_OPCODE)
                if position >= 0:
                    return address - len(overlap) + position
                overlap = search[-1:]
            remaining_scan -= scan_size
            if remaining_scan == 0:
                break
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
            successor = gdb.Breakpoint(f"*{setup_pc + 2:#x}", temporary=True)
            try:
                self._resume("continue")
            finally:
                if successor.is_valid():
                    successor.delete()
            if self._terminal_reason is not None or self.is_exited():
                raise UnsupportedReplayEffect("Initial mmap did not complete normally.")
            self._require_stopped()
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
            self._require_stopped()
            self._advance_stop_generation()
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
            if getattr(self, "_executing_terminal_action", False):
                # No REP-style retry or live tail is legal at an exit boundary.
                self._require_stopped()
                self._resume("si")
                if self.is_exited() or self._terminal_reason is not None:
                    return None
                return self.current_state()
            return self._step()
        except StopIteration:
            return None

    def _step(self):
        self._require_stopped()
        pc = gdb.selected_frame().read_register("pc")
        new_pc = pc
        while pc == new_pc:  # Skip instruction chains from REP STOS etc.
            guard = getattr(self, "_guard_no_replay_step", None)
            if guard is not None:
                guard()
            self._resume("si")
            if self._terminal_reason is not None or self.is_exited():
                raise StopIteration
            self._require_stopped()
            new_pc = gdb.selected_frame().read_register("pc")
        return self.current_state()

    def is_exited(self) -> bool:
        return self.execution_outcome().state is ExecutionState.EXITED

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
    def __init__(
        self, remote: str, deterministic_log: DeterministicLog, binary: str | None = None
    ):
        super().__init__(remote)
        # Older Linux-user stubs do not populate progspace.filename.  The CLI's
        # already hash-bound executable remains authoritative in that case.
        if binary is not None:
            self.binary = binary

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

    def enable_no_replay_exit_only(self, expected: TraceCompletion) -> None:
        """Guard every live instruction; no replay writes or unobserved run-until."""
        if self._replay is not None or self._events.events or expected.no_replay_exit is None:
            raise UnsupportedReplayEffect("Exit-only collection requires no RR log and full exit evidence.")
        if len(self._process.threads()) != 1:
            raise UnsupportedReplayEffect("Exit-only collection requires exactly one guest thread.")
        self._no_replay_exit_only = expected
        self._no_replay_set_fs_position = 0
        self._observed_no_replay_set_fs: list[NoReplaySetFsBoundary] = []
        self._no_replay_set_tid_position = 0
        self._observed_no_replay_set_tid: list[NoReplaySetTidBoundary] = []
        self._no_replay_mmap_position = 0
        self._no_replay_mprotect_position = 0
        self._observed_no_replay_mmap: list[NoReplayMmapBoundary] = []
        self._observed_no_replay_mprotect: list[NoReplayMprotectBoundary] = []
        self._no_replay_allocation_bases: list[int] = []
        self._no_replay_context_tid = self._independent_task_tid() if expected.no_replay_set_tid else None
        self._no_replay_source: tuple[int, int | None, int] | None = None

    def has_pending_no_replay_actions(self) -> bool:
        expected = getattr(self, '_no_replay_exit_only', None)
        if expected is None:
            return False
        return (
            self._no_replay_mprotect_position < len(expected.no_replay_mprotect)
            or self._no_replay_mmap_position < len(expected.no_replay_mmap)
            or self._no_replay_set_fs_position < len(expected.no_replay_set_fs)
            or self._no_replay_set_tid_position < len(expected.no_replay_set_tid)
            or expected.no_replay_exit is not None
        )

    def configure_xmm_read_transport(self, profile: str) -> None:
        self._require_stopped()
        self._xmm_read_transport_binding = bind_xmm_read_transport(
            profile, self._independent_task_tid(), self.arch.key.isa, self.arch.endianness,
        )
        logger.info('Bound XMM read transport %s to %s SHA256=%s',
                    profile, self._xmm_read_transport_binding.executable,
                    self._xmm_read_transport_binding.sha256)

    def configure_aarch64_cpu_context(self, model: str) -> None:
        """Opt-in local Linux-user model binding; no guest register writes.

        Neoverse-V1's model-defined DCZ size is audited in QEMU cpu64.c. Its
        process must explicitly select that model; MIDR and SCTLR are read
        independently through GDB. This is not a general remote/system-mode
        fallback and cannot learn the expected value from emulator MRS output.
        """
        if model != 'neoverse-v1' or self.arch.archname != 'aarch64' or self.arch.endianness != 'little':
            raise UnsupportedReplayEffect('Unsupported configured AArch64 CPU context.')
        if getattr(self, '_no_replay_exit_only', None) is None:
            raise UnsupportedReplayEffect('CPU model binding requires guarded no-replay Linux-user mode.')
        tid = self._independent_task_tid()
        root = Path(f'/proc/{tid}')
        try:
            executable = (root / 'exe').resolve(strict=True)
            argv = (root / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
        except OSError as error:
            raise UnsupportedReplayEffect('CPU model binding requires the actual local QEMU process.') from error
        if (executable.name not in ('qemu-aarch64', '.qemu-aarch64-wrapped')
                or argv.count(b'-cpu') != 1
                or argv.index(b'-cpu') + 1 >= len(argv)
                or argv[argv.index(b'-cpu') + 1] != model.encode()):
            raise UnsupportedReplayEffect('Live QEMU process must explicitly select -cpu neoverse-v1 without model overrides.')
        self._aarch64_cpu_context = model
        self._aarch64_cpu_context_tid = tid
        self.current_state().read_register('DCZID_EL0')  # validate independent MIDR/EL0/control now

    def authorize_no_replay_source(self, pc: int, original_index: int | None, retained_index: int) -> None:
        self._no_replay_source = (pc, original_index, retained_index)

    def _independent_task_tid(self) -> int:
        """Pinned Linux-user RSP thread ID is ts_tid, not the process ID field.

        qemu/gdbstub/user-target.c gdb_get_cpu_index reads TaskState.ts_tid;
        linux-user/main.c initializes it with SYS_gettid before guest execution.
        This is independent of guest set_tid_address's return. System-mode and
        synthetic thread-ID stubs are outside this Linux-user backend contract.
        """
        threads = self._process.threads()
        if len(threads) != 1:
            raise UnsupportedReplayEffect("Context-relative TID requires exactly one guest task.")
        ptid = threads[0].ptid
        if not isinstance(ptid, tuple) or len(ptid) != 3:
            raise UnsupportedReplayEffect("QEMU RSP task identity is unavailable.")
        tids = [value for value in ptid[1:] if value != 0]
        if len(tids) != 1 or type(tids[0]) is not int or not 0 < tids[0] < 1 << 31:
            raise UnsupportedReplayEffect("QEMU RSP task identity is ambiguous or malformed.")
        return tids[0]

    def _execute_no_replay_mmap(self) -> ReadableProgramState | None:
        expected = getattr(self, "_no_replay_exit_only", None)
        if expected is None or self._no_replay_mmap_position == len(expected.no_replay_mmap):
            return None
        boundary = expected.no_replay_mmap[self._no_replay_mmap_position]
        state = self.current_state()
        if state.read_pc() != boundary.descriptor.pc:
            return None
        source = self._no_replay_source
        if source is None or source[:2] != (boundary.descriptor.pc, boundary.transform_index):
            raise UnsupportedReplayEffect("mmap reached at a different ordered occurrence.")
        if state.read_memory(state.read_pc(), 2) != b"\x0f\x05":
            raise UnsupportedReplayEffect("mmap instruction differs.")
        action = prepare_no_replay_action(
            state, single_thread=True, descriptor=boundary.descriptor
        )
        if not isinstance(action, AnonymousMmapAction) or action.length != boundary.length:
            raise UnsupportedReplayEffect("mmap action arguments differ from the oracle contract.")
        successor = gdb.Breakpoint(f"*{state.read_pc() + 2:#x}", internal=True)
        try:
            self._resume("continue")
        finally:
            successor.delete()
        if self.is_exited() or self._terminal_reason is not None:
            raise UnsupportedReplayEffect("mmap has no live post-call boundary.")
        after = self.current_state()
        base = action.validate_observed_result(after.read_register("RAX"), after.read_memory)
        if boundary.occurrence != len(self._no_replay_allocation_bases):
            raise UnsupportedReplayEffect("mmap allocation occurrence is not contiguous.")
        self._no_replay_allocation_bases.append(base)
        after.allocation_bases = tuple(self._no_replay_allocation_bases)
        self._observed_no_replay_mmap.append(NoReplayMmapBoundary(
            source[2], boundary.descriptor, boundary.length, boundary.occurrence,
        ))
        self._no_replay_mmap_position += 1
        return after

    def _execute_no_replay_mprotect(self) -> ReadableProgramState | None:
        expected = getattr(self, "_no_replay_exit_only", None)
        if expected is None or self._no_replay_mprotect_position == len(expected.no_replay_mprotect):
            return None
        boundary = expected.no_replay_mprotect[self._no_replay_mprotect_position]
        state = self.current_state()
        if state.read_pc() != boundary.descriptor.pc:
            return None
        source = self._no_replay_source
        if source is None or source[:2] != (boundary.descriptor.pc, boundary.transform_index):
            raise UnsupportedReplayEffect("mprotect reached at a different ordered occurrence.")
        action = prepare_no_replay_action(state, single_thread=True, descriptor=boundary.descriptor)
        expected_action = MprotectNoneAction(boundary.occurrence, boundary.offset, boundary.length)
        if action != expected_action:
            raise UnsupportedReplayEffect("mprotect local allocation-relative arguments differ.")
        successor = gdb.Breakpoint(f"*{state.read_pc() + 2:#x}", internal=True)
        try:
            self._resume("continue")
        finally:
            successor.delete()
        if self.is_exited() or self._terminal_reason is not None:
            raise UnsupportedReplayEffect("mprotect has no live post-call boundary.")
        after = self.current_state()
        expected_action.validate_return(after.read_register("RAX"))
        self._observed_no_replay_mprotect.append(NoReplayMprotectBoundary(
            source[2], boundary.descriptor, boundary.occurrence, boundary.offset, boundary.length,
        ))
        self._no_replay_mprotect_position += 1
        return after

    def _execute_no_replay_set_tid(self) -> ReadableProgramState | None:
        expected = getattr(self, "_no_replay_exit_only", None)
        if expected is None or self._no_replay_set_tid_position == len(expected.no_replay_set_tid):
            return None
        boundary = expected.no_replay_set_tid[self._no_replay_set_tid_position]
        state = self.current_state()
        if state.read_pc() != boundary.descriptor.pc:
            return None
        source = self._no_replay_source
        if source is None or source[:2] != (boundary.descriptor.pc, boundary.transform_index):
            raise UnsupportedReplayEffect("SET_TID_ADDRESS reached at a different ordered occurrence.")
        opcode = no_replay_syscall_opcode(self.arch.key)
        if describe_no_replay_action(state) != boundary.descriptor or state.read_memory(state.read_pc(), len(opcode)) != opcode:
            raise UnsupportedReplayEffect("SET_TID_ADDRESS instruction/descriptor differs.")
        tid = self._independent_task_tid()
        if tid != self._no_replay_context_tid:
            raise UnsupportedReplayEffect("QEMU execution task identity changed.")
        argument_register = "X0" if self.arch.key.isa == "aarch64" else "RDI"
        if state.read_register(argument_register) != boundary.address:
            raise UnsupportedReplayEffect("SET_TID_ADDRESS registration address changed.")
        require_private_tid_storage(self.binary, boundary.address, self.arch.key)
        before = snapshot_set_tid_inputs(state)
        self._require_stopped()
        # Linux-user/GDB syscall stepping may include the next instruction.
        # Resume this already-checked action only to its immediate architectural
        # successor; this is not ordinary-prefix run-until or a skipped cutpoint.
        instruction_size = 4 if self.arch.key.isa == 'aarch64' else 2
        successor = gdb.Breakpoint(
            f'*{state.read_pc() + instruction_size:#x}', internal=True
        )
        try:
            self._resume('continue')
        finally:
            successor.delete()
        if self.is_exited() or self._terminal_reason is not None:
            raise UnsupportedReplayEffect("SET_TID_ADDRESS has no live post-call boundary.")
        after = self.current_state()
        if self.arch.key.isa == "x86_64":
            # As for SET_FS, known SYSCALL register semantics belong to the
            # ordinary matcher once the local kernel effect is established.
            validate_set_tid_effect(before, after, tid)
        else:
            validate_set_tid_transition(before, after, tid)
        self._observed_no_replay_set_tid.append(NoReplaySetTidBoundary(
            source[2], boundary.descriptor, boundary.address, tid,
        ))
        self._no_replay_set_tid_position += 1
        return after

    def _execute_no_replay_set_fs(self) -> ReadableProgramState | None:
        expected = getattr(self, "_no_replay_exit_only", None)
        if expected is None or self._no_replay_set_fs_position == len(expected.no_replay_set_fs):
            return None
        boundary = expected.no_replay_set_fs[self._no_replay_set_fs_position]
        state = self.current_state()
        if state.read_pc() != boundary.descriptor.pc:
            return None
        source = self._no_replay_source
        if source is None or source[:2] != (boundary.descriptor.pc, boundary.transform_index):
            raise UnsupportedReplayEffect("SET_FS was skipped or reached at a different ordered action occurrence.")
        if describe_no_replay_action(state) != boundary.descriptor or state.read_memory(state.read_pc(), 2) != b"\x0f\x05":
            raise UnsupportedReplayEffect("SET_FS instruction/descriptor differs from the native action.")
        before = snapshot_set_fs_inputs(state)
        local_action = prepare_no_replay_action(before, single_thread=True)
        require_same_no_replay_action(SetFsAction(boundary.base), local_action)
        self._require_stopped()
        # Linux-user single-step can execute the instruction after SYSCALL.
        # Stop at the checked action's immediate successor, never a witness bound.
        successor = gdb.Breakpoint(f"*{state.read_pc() + 2:#x}", internal=True)
        try:
            self._resume("continue")
        finally:
            successor.delete()
        if self.is_exited() or self._terminal_reason is not None:
            raise UnsupportedReplayEffect("SET_FS has no live post-call boundary.")
        after = self.current_state()
        # Once the independently observed kernel effect and immediate successor
        # are established, return the actual state.  The ordinary matcher owns
        # architectural RCX/R11/etc. comparison, so a real mistranslation is a
        # structured mismatch rather than a fatal loss of later diagnostics.
        validate_set_fs_effect(before, after)
        self._observed_no_replay_set_fs.append(NoReplaySetFsBoundary(source[2], boundary.descriptor, boundary.base))
        self._no_replay_set_fs_position += 1
        return after

    def _guard_no_replay_step(self) -> None:
        if getattr(self, "_no_replay_exit_only", None) is None:
            return
        state = self.current_state()
        pc = state.read_pc()
        if self.arch.key.isa == "aarch64":
            # Reject every exception-generating instruction (SVC/HVC/SMC,
            # BRK/HLT/DCPS), including unsupported immediate variants.
            opcode = int.from_bytes(state.read_memory(pc, 4), "little")
            if opcode & 0xFF000000 == 0xD4000000:
                raise UnsupportedReplayEffect("Unmatched no-replay AArch64 exception/action boundary.")
            return
        prefixes = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3, *range(0x40, 0x50)}
        for offset in range(15):
            opcode = state.read_memory(pc + offset, 2)
            if opcode[0] not in prefixes:
                break
        else:
            raise UnsupportedReplayEffect("Overlong instruction at no-replay boundary.")
        if opcode in (b"\x0f\x05", b"\x0f\x34") or opcode[:1] == b"\xcd":
            raise UnsupportedReplayEffect(
                "Unmatched no-replay action boundary; refusing to execute a syscall in the ordinary prefix."
            )

    def execute_terminal_action(
        self, expected: TraceCompletion, *, retained_transform_count: int
    ) -> tuple[TraceCompletion, TerminalActionValidation]:
        """Execute exactly the final observed exit, never an untraced tail.

        With RR, the marker is required even when the inferior reports exit. Its memory
        writes are unsupported cleanup effects, not permission to discard them.
        This transaction never obtains a register state after execution.
        """
        state = self.current_state()
        descriptor = describe_no_replay_action(state)
        if descriptor != expected.terminal_action or descriptor.kind not in (
            NoReplayActionKind.EXIT, NoReplayActionKind.EXIT_GROUP
        ):
            raise UnsupportedReplayEffect("Final live action does not match the oracle descriptor.")
        observed_action = prepare_no_replay_action(
            state, single_thread=True, descriptor=descriptor
        )
        if not isinstance(observed_action, ExitAction):
            raise UnsupportedReplayEffect("Only exit actions can terminate whole-program collection.")
        # Check instruction identity, not just ABI registers containing an exit number.
        opcode = no_replay_syscall_opcode(self.arch.key)
        if state.read_memory(state.read_pc(), len(opcode)) != opcode:
            raise UnsupportedReplayEffect("Final live instruction is not the supported syscall opcode.")
        if expected.no_replay_exit is not None:
            if getattr(self, "_no_replay_exit_only", None) != expected:
                raise UnsupportedReplayEffect("Exit-only prefix guards were not established.")
            if self._replay is not None or self._events.events:
                raise UnsupportedReplayEffect("No-replay terminal evidence cannot consume an RR log.")
            if self._no_replay_mprotect_position != len(expected.no_replay_mprotect):
                raise UnsupportedReplayEffect("Unconsumed ordered mprotect actions precede terminal exit.")
            if self._no_replay_mmap_position != len(expected.no_replay_mmap):
                raise UnsupportedReplayEffect("Unconsumed ordered mmap actions precede terminal exit.")
            if self._no_replay_set_tid_position != len(expected.no_replay_set_tid):
                raise UnsupportedReplayEffect("Unconsumed ordered SET_TID_ADDRESS actions precede terminal exit.")
            if self._no_replay_set_fs_position != len(expected.no_replay_set_fs):
                raise UnsupportedReplayEffect("Unconsumed ordered SET_FS actions precede terminal exit.")
            expected_action = expected.no_replay_exit
            action_comparison = (
                TerminalComparison.MATCH
                if expected_action == observed_action
                else TerminalComparison.MISMATCH
            )
            self._executing_terminal_action = True
            try:
                destination = self.execute_replay_instruction()
            finally:
                self._executing_terminal_action = False
            if destination is not None:
                raise EventSynchronizationError("Exit-only syscall returned a live destination state.")
            outcome = self.execution_outcome()
            observed = TraceCompletion(
                descriptor.pc, retained_transform_count, retained_transform_count + 1,
                outcome, descriptor, no_replay_exit=observed_action,
                no_replay_set_fs=tuple(self._observed_no_replay_set_fs),
                no_replay_set_tid=tuple(self._observed_no_replay_set_tid),
                no_replay_mmap=tuple(self._observed_no_replay_mmap),
                no_replay_mprotect=tuple(self._observed_no_replay_mprotect),
            )
            return observed, TerminalActionValidation(
                expected_action, observed_action, action_comparison
            )
        replay = self._require_replay_engine()
        event = self._events.match(state)
        if not isinstance(event, SyscallEvent):
            raise EventSynchronizationError("Final live action has no matching RR syscall entry.")
        require_event_thread(self._replay_tid, event.tid, context="Terminal system call")
        policy = replay.prepare_syscall(event)
        if policy.requires_post_event:
            raise UnsupportedReplayEffect("Final RR event is not a terminal system call.")
        argument = replay._event_register(event, replay.syscall_argument_registers[0])
        expected_action = ExitAction(
            argument,
            ExitScope.GROUP if event.syscall_number == replay.exit_group_syscall else ExitScope.THREAD,
        )
        if expected_action != observed_action:
            raise EventSynchronizationError("Terminal syscall full argument differs from RR.")
        terminal = self._events.match_terminal(event)
        if terminal.mem_writes or terminal.extra_registers is not None or event.syscall_extras.kind != "none":
            raise UnsupportedReplayEffect("Terminal RR cleanup effects are not supported.")
        if self._events.peek() is not None:
            raise EventSynchronizationError("RR events remain after the terminal marker.")
        self._executing_terminal_action = True
        try:
            self._handle_syscall(event, None, policy=policy)
        except StopIteration:
            pass
        else:
            raise EventSynchronizationError("Terminal replay returned a live destination state.")
        finally:
            self._executing_terminal_action = False
        outcome = self.execution_outcome()
        if outcome.state not in (ExecutionState.EXITED, ExecutionState.UNKNOWN):
            raise EventSynchronizationError("Terminal replay did not observe process termination.")
        observed = TraceCompletion(
            descriptor.pc, retained_transform_count, retained_transform_count + 1,
            outcome, descriptor,
        )
        return observed, TerminalActionValidation(
            expected_action, observed_action, TerminalComparison.MATCH
        )

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
            return self.current_state()

        state = self._execute_no_replay_mprotect()
        if state is not None:
            return state
        state = self._execute_no_replay_mmap()
        if state is not None:
            return state
        state = self._execute_no_replay_set_tid()
        if state is not None:
            return state
        state = self._execute_no_replay_set_fs()
        if state is None:
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
        if self.has_pending_no_replay_actions():
            raise UnsupportedReplayEffect(
                "Exit-only collection cannot run-until past pending ordered actions."
            )
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

        try:
            self._resume("continue", to_string=False)
        finally:
            for bp in breakpoints:
                bp.delete()

        if self._terminal_reason is not None or self.is_exited():
            raise StopIteration
        return self.current_state()
