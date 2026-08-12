#!/usr/bin/env python3

"""QEMU plugin state collection and validation."""

from __future__ import annotations

import logging
from collections.abc import Iterable

import focaccia.parser as parser
from focaccia.arch import Arch, supported_architectures
from focaccia.compare import ErrorTypes, compare_symbolic
from focaccia.match import MatchResult, TransitionMatcher
from focaccia.qemu.snapshot import (
    collect_snapshot_plan,
    merge_snapshot_plans,
    plan_minimal_snapshot,
    plan_symbolic_dependencies,
    snapshot_diagnostics,
)
from focaccia.qemu.state import CachedBackendProgramState, RegisterObservation
from focaccia.qemu.transport import PluginListener, PluginTransport
from focaccia.snapshot import ProgramState, ReadableProgramState, RegisterAccessError
from focaccia.symbolic import SymbolicTraceItem
from focaccia.trace import (
    MaterializedTrace,
    TraceEnvironment,
    TransformStream,
)
from focaccia.utils import print_result


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
        wire_name = (
            self.flag_backend_names[self.arch.archname]
            if self._flags_base is not None and base_reg == self._flags_base
            else (requested_reg if use_narrow_alias else base_reg).lower()
        )
        return self.transport.read_register(wire_name)

    def _read_backend_memory(self, addr: int, size: int) -> bytes:
        return self.transport.read_memory(addr, size)

    def step(self) -> None:
        self.transport.step()
        self.flush_observations()


class PluginStateIterator:
    """Own a plugin listener/transport and expose successive guest states."""

    def __init__(
        self,
        socket_path: str,
        arch: Arch,
        *,
        listener: PluginListener | None = None,
    ):
        self.socket_path = socket_path
        self.arch = arch
        self._first_next = True
        self._closed = False
        self._listener = listener or PluginListener(socket_path, arch)
        try:
            self._listener.start()
            info(f"Listening for QEMU plugin connection at {socket_path}.")
            self.transport, handshake = self._listener.accept()
        except BaseException:
            self._listener.close()
            raise
        info(
            f"Connected to QEMU plugin process {handshake.pid} using protocol "
            f"version {handshake.version}."
        )
        self.state = PluginProgramState(arch, self.transport)

    @classmethod
    def from_transport(
        cls,
        transport: PluginTransport,
        arch: Arch,
    ) -> PluginStateIterator:
        """Build a non-listening iterator for deterministic backend tests."""
        result = object.__new__(cls)
        result.socket_path = "<injected>"
        result.arch = arch
        result._first_next = True
        result._closed = False
        result._listener = None
        result.transport = transport
        result.state = PluginProgramState(arch, transport)
        return result

    def __iter__(self) -> PluginStateIterator:
        return self

    def next_cutpoint_pc(self, matcher: TransitionMatcher) -> int | None:
        """Declare the next symbolic destination before the guest advances."""
        return matcher.current_destination_pc

    def __next__(self) -> PluginProgramState:
        if self._closed:
            raise StopIteration
        if self._first_next:
            self._first_next = False
            return self.state

        pc = self.state.read_pc()
        new_pc = pc
        while pc == new_pc:
            self.state.step()
            new_pc = self.state.read_pc()
        return self.state

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
) -> MatchResult:
    """Collect a cardinality-valid concrete transition trace from the plugin."""
    matcher = TransitionMatcher(strace, skip_unmatched=skip_unmatched)
    retained_states: list[ProgramState] = []
    retained_transforms: list[SymbolicTraceItem] = []
    diagnostics = []
    state_iterator = iter(qemu)

    while not matcher.done:
        try:
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
    )


def start_validation_server(
    symb_trace: str,
    output: str | None,
    socket_path: str,
    guest_arch: str,
    env: TraceEnvironment,
    verbosity: ErrorTypes,
    is_quiet: bool = False,
    trace_type: str = "json",
    skip_unmatched: bool = False,
) -> MatchResult:
    architecture = supported_architectures.get(guest_arch)
    if architecture is None:
        raise ValueError(f"Unsupported guest architecture {guest_arch!r}.")
    if env.architecture != architecture.key:
        raise ValueError(
            f"Plugin environment architecture {env.architecture} does not match "
            f"guest architecture {architecture.key}."
        )

    mode = "rb" if trace_type == "msgpack" else "r"
    with open(symb_trace, mode) as trace_file:
        if trace_type == "msgpack":
            symb_transforms = parser.stream_transformation(trace_file)
        elif trace_type == "json":
            symb_transforms = parser.parse_transformations(trace_file)
        else:
            raise ValueError(f"Unsupported symbolic trace type {trace_type!r}.")

        with PluginStateIterator(socket_path, architecture) as qemu:
            matched = collect_conc_trace(
                qemu,
                symb_transforms,
                skip_unmatched=skip_unmatched,
            )

    if not is_quiet:
        report = compare_symbolic(
            matched.trace,
            diagnostics=matched.diagnostics,
        )
        print_result(report, verbosity)

    if output:
        from focaccia.parser import serialize_snapshots

        states = matched.trace.state_boundaries if matched.trace is not None else ()
        with open(output, "w") as output_file:
            serialize_snapshots(MaterializedTrace(states, env), output_file)

    return matched
