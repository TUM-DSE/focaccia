#!/usr/bin/env python3

"""QEMU plugin state collection and validation."""

from __future__ import annotations

import json
import logging
import os
import secrets
import time
from collections.abc import Iterable
from contextlib import nullcontext
from dataclasses import dataclass, replace
from pathlib import Path

import focaccia.parser as parser
from focaccia.arch import Arch, supported_architectures
from focaccia.compare import compare_symbolic
from focaccia.execution import ExecutionOutcome, ExecutionState, TerminalComparison
from focaccia.no_replay import (
    ExitAction,
    NoReplayActionKind,
    describe_no_replay_action,
    no_replay_syscall_opcode,
    prepare_no_replay_action,
)
from focaccia.match import MatchResult, TransitionMatcher
from focaccia.qemu.snapshot import (
    collect_snapshot_plan,
    merge_snapshot_plans,
    plan_minimal_snapshot,
    plan_symbolic_dependencies,
    snapshot_diagnostics,
)
from focaccia.qemu.state import CachedBackendProgramState, RegisterObservation
from focaccia.qemu.profiling import (
    QEMUValidationProfiler,
    write_qemu_validation_profile,
)
from focaccia.qemu.report import TerminalActionValidation, write_validation_report
from focaccia.qemu.transport import (
    EVENT_AARCH64_SVC_ENTRY,
    EVENT_AARCH64_SVC_SUCCESSOR,
    EVENT_CUTPOINT,
    EVENT_STORE,
    PluginEvent,
    PluginLaunchIdentity,
    PluginListener,
    PluginTransport,
    manifest_sha256,
)
from focaccia.snapshot import ProgramState, ReadableProgramState, RegisterAccessError
from focaccia.symbolic import SymbolicTraceItem
from focaccia.trace import (
    MaterializedTrace,
    TraceEnvironment,
    TransformStream,
)
from focaccia.utils import ErrorSeverity, print_result


@dataclass(frozen=True, slots=True)
class AArch64SvcEvidence:
    entry_pc: int
    successor_pc: int
    number: int
    argument0: int
    result: int
    entry_epoch: int
    successor_epoch: int


logger = logging.getLogger("focaccia-qemu-validation-server")
debug = logger.debug
info = logger.info


class PluginProgramState(CachedBackendProgramState):
    """Live plugin state with canonical register and sparse-memory caching."""

    from focaccia.arch import aarch64, x86

    flag_backend_names = {
        aarch64.archname: "cpsr",
        x86.archname: "eflags",
    }

    def __init__(self, arch: Arch, transport: PluginTransport):
        super().__init__(arch)
        self.transport = transport
        flags_name = self.flag_backend_names.get(arch.archname)
        canonical_flags = arch.to_regname(flags_name) if flags_name else None
        flags = arch.get_reg_accessor(canonical_flags) if canonical_flags else None
        self._flags_base = flags.base_reg if flags is not None else None

    def _read_backend_register(
        self,
        base_reg: str,
        requested_reg: str | None = None,
    ) -> RegisterObservation:
        requested = self.arch.get_reg_accessor(requested_reg) if requested_reg else None
        use_narrow_alias = requested is not None and requested.num_bits >= 128
        if self.arch.archname == self.x86.archname and base_reg.startswith("MM"):
            fstat = self.transport.read_register("fstat")
            if fstat.num_bits != 32:
                raise RegisterAccessError(
                    base_reg,
                    f"QEMU plugin returned {fstat.num_bits}-bit FSTAT.",
                )
            wire_name = self.x86.mmx_logical_st_name(base_reg, fstat.value)
            backing = self.transport.read_register(wire_name)
            if backing.num_bits != 80:
                raise RegisterAccessError(
                    base_reg,
                    f"QEMU plugin returned {backing.num_bits}-bit {wire_name}.",
                )
            return RegisterObservation(base_reg, backing.value & ((1 << 64) - 1), 64)

        selected_name = requested_reg if use_narrow_alias else base_reg
        assert selected_name is not None
        if self.arch.archname == self.aarch64.archname and base_reg.startswith("V"):
            wire_name = f"v{base_reg[1:]}"
        elif self.arch.archname == self.aarch64.archname and base_reg == "TPIDR":
            wire_name = "TPIDR_EL0"
        elif self.arch.archname == self.aarch64.archname and base_reg == "DCZID_EL0":
            wire_name = "DCZID_EL0"
        else:
            wire_name = (
                self.flag_backend_names[self.arch.archname]
                if self._flags_base is not None and base_reg == self._flags_base
                else selected_name.lower()
            )
        return self.transport.read_register(wire_name)

    def _read_backend_memory(self, addr: int, size: int) -> bytes:
        return self.transport.read_memory(addr, size)

    def advance(self) -> None:
        """Release one event boundary; QEMU executes normally until the next event."""
        advance = getattr(self.transport, "advance", self.transport.step)
        advance()
        self.flush_observations()

    def step(self) -> None:
        # Compatibility for callers; this is event-to-event continuation, not
        # debugger or instruction stepping.
        self.advance()


class PluginStateIterator:
    """Own a plugin listener/transport and expose successive guest states."""

    def __init__(
        self,
        socket_path: str,
        arch: Arch,
        *,
        listener: PluginListener | None = None,
        cutpoint_addresses: tuple[int, ...] = (),
        launch_identity: PluginLaunchIdentity | None = None,
    ):
        self.socket_path = socket_path
        self.arch = arch
        self._first_next = True
        self._closed = False
        self.cutpoint_addresses = cutpoint_addresses
        self._cutpoint_index = 0
        self.events: list[PluginEvent] = []
        self.svc_evidence: list[AArch64SvcEvidence] = []
        self.store_evidence: list[PluginEvent] = []
        self._pending_svc: PluginEvent | None = None
        self._event_protocol = True
        if any(type(address) is not int or not 0 <= address < 1 << 64
               for address in cutpoint_addresses):
            raise ValueError("Plugin cutpoints must be ordered 64-bit addresses.")
        if listener is None and launch_identity is None:
            raise ValueError("Plugin launch identity is required for a listening iterator.")
        self._listener = listener or PluginListener(
            socket_path, arch, expected_identity=launch_identity
        )
        try:
            self._listener.start()
            info(f"Listening for QEMU plugin connection at {socket_path}.")
            self.transport, handshake = self._listener.accept()
        except BaseException:
            self._listener.close()
            raise
        info(f"Connected to QEMU plugin process {handshake.pid}.")
        self.pid = handshake.pid
        self.state = PluginProgramState(arch, self.transport)
        self.state.execution_tid = handshake.pid

    @classmethod
    def from_transport(
        cls,
        transport: PluginTransport,
        arch: Arch,
        *,
        cutpoint_addresses: tuple[int, ...] = (),
    ) -> PluginStateIterator:
        """Build a non-listening iterator for deterministic backend tests."""
        result = object.__new__(cls)
        result.socket_path = "<injected>"
        result.arch = arch
        result._first_next = True
        result._closed = False
        result.cutpoint_addresses = cutpoint_addresses
        result._cutpoint_index = 0
        result.events = []
        result.svc_evidence = []
        result.store_evidence = []
        result._pending_svc = None
        result._event_protocol = hasattr(transport, "receive_event")
        result._listener = None
        result.pid = None
        result.transport = transport
        result.state = PluginProgramState(arch, transport)
        return result

    def __iter__(self) -> PluginStateIterator:
        return self

    def next_cutpoint_pc(self, matcher: TransitionMatcher) -> int | None:
        """Declare the next dynamic cutpoint before advancing."""
        if self._cutpoint_index < len(self.cutpoint_addresses):
            return self.cutpoint_addresses[self._cutpoint_index]
        return matcher.current_destination_pc

    def _receive_cutpoint(self) -> None:
        while True:
            event = self.transport.receive_event()
            self.events.append(event)
            if event.kind == EVENT_STORE:
                # A store event is emitted at the next instruction callback,
                # after QEMU committed the write and before that instruction
                # executes. Bind its epoch to an immediate coherent read.
                if self.transport.read_memory(event.address, event.size) != event.value:
                    raise RuntimeError("Plugin store event is not coherent with guest memory.")
                self.store_evidence.append(event)
            elif event.kind == EVENT_AARCH64_SVC_ENTRY:
                if self._pending_svc is not None:
                    raise RuntimeError("Nested AArch64 SVC entry events are invalid.")
                self._pending_svc = event
            elif event.kind == EVENT_AARCH64_SVC_SUCCESSOR:
                if self._pending_svc is None or event.address != self._pending_svc.pc:
                    raise RuntimeError("AArch64 SVC successor is not bound to its entry.")
                entry = self._pending_svc
                self.svc_evidence.append(AArch64SvcEvidence(
                    entry.pc, event.pc, entry.auxiliary, entry.address,
                    event.auxiliary, entry.epoch, event.epoch,
                ))
                self._pending_svc = None
            if event.kind == EVENT_CUTPOINT:
                if self.cutpoint_addresses:
                    if self._cutpoint_index >= len(self.cutpoint_addresses):
                        raise RuntimeError("Plugin produced an undeclared extra cutpoint.")
                    expected = self.cutpoint_addresses[self._cutpoint_index]
                    if event.pc != expected:
                        raise RuntimeError(
                            f"Plugin cutpoint {event.pc:#x} does not match declared "
                            f"dynamic cutpoint {expected:#x}."
                        )
                    self._cutpoint_index += 1
                return
            self.transport.advance()

    def __next__(self) -> PluginProgramState:
        if self._closed:
            raise StopIteration
        if not self._event_protocol:
            if self._first_next:
                self._first_next = False
                return self.state
            pc = self.state.read_pc()
            new_pc = pc
            while pc == new_pc:
                self.state.step()
                new_pc = self.state.read_pc()
            return self.state
        if not self._first_next:
            self.transport.advance()
            self.state.flush_observations()
        self._first_next = False
        self._receive_cutpoint()
        self.state.flush_observations()
        return self.state

    def finish(self) -> None:
        """Detach the plugin after the terminal snapshot is durable."""
        if not self._closed:
            self.transport.finish()
            self._closed = True
            if self._listener is not None:
                self._listener.close()

    def abort(self) -> None:
        """Fail the plugin peer closed after a validation-side error."""
        if not self._closed:
            try:
                self.transport.abort()
            finally:
                self._closed = True
                if self._listener is not None:
                    self._listener.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._listener is not None:
            self._listener.close()
        else:
            self.transport.close()

    def __enter__(self) -> PluginStateIterator:
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()


def collect_conc_trace(
    qemu: Iterable[ReadableProgramState],
    strace: MaterializedTrace[SymbolicTraceItem] | TransformStream[SymbolicTraceItem],
    *,
    skip_unmatched: bool = False,
    profiler: QEMUValidationProfiler | None = None,
) -> MatchResult:
    """Collect a cardinality-valid concrete transition trace from the plugin."""
    matcher = TransitionMatcher(strace, skip_unmatched=skip_unmatched)
    retained_states: list[ProgramState] = []
    retained_transforms: list[SymbolicTraceItem] = []
    diagnostics = []
    state_iterator = iter(qemu)

    while not matcher.done:
        try:
            measurement = (
                profiler.measure("execution") if profiler is not None else nullcontext()
            )
            with measurement:
                current_state = next(state_iterator)
            pc = current_state.read_pc()
        except StopIteration:
            break
        except RegisterAccessError as error:
            matcher.fail_concrete_state(len(retained_states), error)
            break

        boundary = matcher.observe(pc)
        if boundary is None:
            continue
        previous_state = retained_states[-1] if retained_states else current_state
        plans = [
            plan_minimal_snapshot(
                current_state,
                boundary.incoming,
                boundary.outgoing,
            )
        ]
        if boundary.outgoing is not None and not skip_unmatched:
            next_cutpoint = getattr(state_iterator, "next_cutpoint_pc", None)
            destination_pc = next_cutpoint(matcher) if next_cutpoint is not None else None
            if destination_pc is not None:
                planned = matcher.plan_destination(destination_pc)
                if planned is not None:
                    plans.append(
                        plan_minimal_snapshot(
                            current_state,
                            boundary.incoming,
                            planned,
                        )
                    )
            else:
                dependencies = matcher.plan_successor_dependencies()
                if dependencies is not None:
                    plans.append(plan_symbolic_dependencies(current_state, dependencies))
        collection = collect_snapshot_plan(
            previous_state,
            current_state,
            merge_snapshot_plans(*plans),
        )
        diagnostics.extend(
            snapshot_diagnostics(
                collection,
                len(retained_states),
                len(retained_transforms) if boundary.incoming is not None else None,
            )
        )
        if boundary.incoming is not None:
            retained_transforms.append(boundary.incoming)
        retained_states.append(collection.state)

    result = matcher.make_result(retained_states, retained_transforms)
    return MatchResult(
        result.trace,
        (*result.diagnostics, *diagnostics),
        result.pending_transform,
        result.consumed_transform_count,
    )


def _write_atomic_json(path: str, document: dict[str, object]) -> None:
    destination = Path(path)
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, destination)


def _plugin_terminal_completion(
    qemu: PluginStateIterator,
    symbolic: MaterializedTrace[SymbolicTraceItem] | TransformStream[SymbolicTraceItem],
    matched: MatchResult,
    ready_path: str,
    evidence_path: str,
    timeout_seconds: float,
):
    expected = symbolic.completion
    if expected is None or matched.trace is None or matched.pending_transform is not None:
        raise RuntimeError("Whole-program plugin collection lacks a bound final boundary.")
    states = matched.trace.state_boundaries
    if (
        matched.consumed_transform_count != expected.transform_count
        or not states
        or states[-1].read_pc() != expected.final_pc
    ):
        raise RuntimeError("Whole-program plugin collection did not bind the declared final boundary.")
    if expected.no_replay_exit is None:
        raise RuntimeError("Plugin completion lacks independently instantiable exit-action evidence.")
    final_state = states[-1]
    action_state = qemu.state
    if action_state.read_pc() != expected.final_pc:
        raise RuntimeError("Plugin live terminal action is not at the bound final boundary.")
    descriptor = describe_no_replay_action(action_state)
    if descriptor != expected.terminal_action or descriptor.kind not in (
        NoReplayActionKind.EXIT,
        NoReplayActionKind.EXIT_GROUP,
    ):
        raise RuntimeError("Plugin final live action does not match the oracle descriptor.")
    opcode = no_replay_syscall_opcode(action_state.arch.key)
    if action_state.read_memory(expected.final_pc, len(opcode)) != opcode:
        raise RuntimeError("Plugin final live instruction is not the supported terminal syscall.")
    observed_action = prepare_no_replay_action(
        action_state, single_thread=True, descriptor=descriptor
    )
    if not isinstance(observed_action, ExitAction):
        raise RuntimeError("Plugin final live action is not a supported exit action.")

    nonce = secrets.token_hex(32)
    binding = {
        "schema": "focaccia-plugin-terminal-ready-v1",
        "nonce": nonce,
        "pid": qemu.pid,
        "binarySha256": symbolic.env.binary_hash,
        "finalPc": expected.final_pc,
        "transformCount": expected.transform_count,
        "stateCount": expected.state_count,
    }
    qemu.finish()
    _write_atomic_json(ready_path, binding)
    deadline = time.monotonic() + timeout_seconds
    evidence_file = Path(evidence_path)
    while not evidence_file.is_file():
        if time.monotonic() >= deadline:
            raise TimeoutError("Timed out waiting for independent plugin process outcome evidence.")
        time.sleep(0.05)
    evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
    if not isinstance(evidence, dict) or evidence.get("schema") != "focaccia-plugin-terminal-evidence-v1":
        raise ValueError("Malformed plugin terminal evidence.")
    for key in ("nonce", "pid", "binarySha256"):
        if evidence.get(key) != binding[key]:
            raise ValueError(f"Plugin terminal evidence has mismatched {key} binding.")
    returncode = evidence.get("returncode")
    if type(returncode) is not int:
        raise ValueError("Plugin terminal evidence lacks an integer process return code.")
    outcome = (
        ExecutionOutcome(ExecutionState.EXITED, exit_status=returncode)
        if returncode >= 0
        else ExecutionOutcome(ExecutionState.EXITED, termination_signal=-returncode)
    )
    # Adaptive matching may retain fewer concrete cutpoints than oracle
    # transforms.  Completion accounts for the consumed/composed semantic
    # prefix, while the concrete trace keeps its own N+1 retained-boundary
    # cardinality.
    from focaccia.no_replay import NoReplaySetTidBoundary

    set_tid_events = [item for item in getattr(qemu, "svc_evidence", ()) if item.number == 96]
    if len(set_tid_events) != len(expected.no_replay_set_tid):
        raise RuntimeError("Plugin SVC evidence does not cover ordered SET_TID_ADDRESS actions.")
    observed_set_tid = tuple(
        NoReplaySetTidBoundary(
            boundary.transform_index,
            boundary.descriptor,
            event.argument0,
            event.result,
        )
        for boundary, event in zip(expected.no_replay_set_tid, set_tid_events, strict=True)
    )
    if qemu.pid is None or any(event.result != qemu.pid for event in set_tid_events):
        raise RuntimeError("SET_TID_ADDRESS result is not bound to the plugin process identity.")
    observed = replace(
        expected,
        transform_count=matched.consumed_transform_count,
        state_count=matched.consumed_transform_count + 1,
        outcome=outcome,
        terminal_action=descriptor,
        no_replay_exit=observed_action,
        no_replay_set_fs=(),
        no_replay_set_tid=observed_set_tid,
        no_replay_mmap=(),
    )
    comparison = (
        TerminalComparison.MATCH
        if expected.no_replay_exit == observed_action
        else TerminalComparison.MISMATCH
    )
    return observed, TerminalActionValidation(
        expected.no_replay_exit, observed_action, comparison
    )


def start_validation_server(
    symb_trace: str,
    output: str | None,
    socket_path: str,
    guest_arch: str,
    env: TraceEnvironment,
    verbosity: ErrorSeverity,
    is_quiet: bool = False,
    trace_type: str = "json",
    skip_unmatched: bool = False,
    report_path: str | None = None,
    profile_path: str | None = None,
    terminal_ready_path: str | None = None,
    terminal_evidence_path: str | None = None,
    terminal_timeout_seconds: float = 1800.0,
    cutpoint_addresses: tuple[int, ...] = (),
) -> MatchResult:
    architecture = supported_architectures.get(guest_arch)
    if architecture is None:
        raise ValueError(f"Unsupported guest architecture {guest_arch!r}.")
    if env.architecture != architecture.key:
        raise ValueError(
            f"Plugin environment architecture {env.architecture} does not match "
            f"guest architecture {architecture.key}."
        )

    profiler = QEMUValidationProfiler() if profile_path is not None else None
    if profiler is not None:
        profiler.start_total()

    if trace_type == "msgpack":
        trace_file = open(symb_trace, "rb")
        symb_transforms = parser.stream_transformation(trace_file)
    elif trace_type == "json":
        trace_file = open(symb_trace, "r")
        symb_transforms = parser.parse_transformations(trace_file)
    else:
        raise ValueError(f"Unsupported symbolic trace type {trace_type!r}.")

    with trace_file:
        from focaccia.completion import TraceScope

        whole_program = symb_transforms.scope is TraceScope.WHOLE_PROGRAM
        if whole_program and (terminal_ready_path is None or terminal_evidence_path is None):
            raise ValueError("Plugin whole-program validation requires typed terminal evidence paths.")
        identity_env = symb_transforms.env
        if identity_env.binary_hash is None:
            raise ValueError("Plugin validation requires a bound binary SHA-256 identity.")
        launch_identity = PluginLaunchIdentity(
            identity_env.binary_hash,
            manifest_sha256(list(identity_env.argv)),
            manifest_sha256(list(identity_env.envp)),
            manifest_sha256({
                "architecture": {
                    "isa": architecture.key.isa,
                    "endianness": architecture.key.endianness,
                },
                "profile": "qemu-user-max-sve-off-v1",
            }),
        )
        launch_identity.digests()
        with PluginStateIterator(
            socket_path, architecture, cutpoint_addresses=cutpoint_addresses,
            launch_identity=launch_identity,
        ) as qemu:
            try:
                tracing_measurement = (
                    profiler.measure("tracing") if profiler is not None else nullcontext()
                )
                with tracing_measurement:
                    matched = collect_conc_trace(
                        qemu,
                        symb_transforms,
                        skip_unmatched=skip_unmatched,
                        profiler=profiler,
                    )
                validation_measurement = (
                    profiler.measure("validation")
                    if profiler is not None
                    else nullcontext()
                )
                with validation_measurement:
                    validation_report = compare_symbolic(
                        matched.trace,
                        diagnostics=matched.diagnostics,
                    )
                structurally_incomplete = (
                    matched.trace is None or matched.pending_transform is not None
                )
                if (whole_program and structurally_incomplete) or (
                    not whole_program and not matched.complete
                ):
                    raise RuntimeError(
                        "Plugin validation did not produce a structurally complete transition trace."
                    )

                if output:
                    from focaccia.parser import serialize_snapshots

                    serialization_measurement = (
                        profiler.measure("serialization")
                        if profiler is not None
                        else nullcontext()
                    )
                    with serialization_measurement:
                        states = (
                            matched.trace.state_boundaries
                            if matched.trace is not None
                            else ()
                        )
                        with open(output, "w") as output_file:
                            serialize_snapshots(MaterializedTrace(states, env), output_file)

                observed_completion = None
                terminal_action_validation = None
                if whole_program:
                    assert terminal_ready_path is not None
                    assert terminal_evidence_path is not None
                    observed_completion, terminal_action_validation = _plugin_terminal_completion(
                        qemu,
                        symb_transforms,
                        matched,
                        terminal_ready_path,
                        terminal_evidence_path,
                        terminal_timeout_seconds,
                    )

                if report_path:
                    write_validation_report(
                        report_path,
                        validation_report,
                        None,
                        matched,
                        scope=symb_transforms.scope,
                        expected_completion=getattr(symb_transforms, "completion", None),
                        observed_completion=observed_completion,
                        terminal_action_validation=terminal_action_validation,
                    )

                if profiler is not None:
                    profiler.finish_total()
                    write_qemu_validation_profile(profile_path, profiler.snapshot())

                # Witness traces detach after artifacts are durable. Whole-program
                # traces detached before waiting for independently observed exit.
                if not whole_program:
                    qemu.finish()
            except Exception:
                try:
                    qemu.abort()
                except Exception:
                    logger.exception("Unable to abort QEMU plugin peer cleanly.")
                raise

    if not is_quiet:
        print_result(validation_report, verbosity)

    return matched
