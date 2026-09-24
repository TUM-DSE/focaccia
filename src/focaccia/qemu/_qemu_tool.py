"""Invocable like this:

    gdb -n --batch -x qemu_tool.py

But please use `tools/validate_qemu.py` instead because we have some more setup
work to do.
"""

import argparse
import logging
import os
from contextlib import nullcontext

import focaccia.parser as parser
from focaccia.compare import compare_symbolic, Error, ErrorTypes
from focaccia.match import MatchResult, TransitionMatcher
from focaccia.completion import TraceCompletion, TraceScope
from focaccia.snapshot import ProgramState, RegisterAccessError
from focaccia.symbolic import SymbolicTraceItem
from focaccia.trace import (
    MaterializedTrace,
    TransformStream,
)
from focaccia.utils import print_result
from focaccia.deterministic import DeterministicLog

from focaccia.tools.validate_qemu import (
    decode_gdb_arguments,
    make_argparser,
    make_gdb_trace_environment,
    validate_backend_options,
    verbosity,
)
from focaccia.qemu.integration import (
    load_replay_run_manifest,
    validate_replay_run_manifest,
)
from focaccia.qemu.profiling import (
    QEMUValidationProfiler,
    write_qemu_validation_profile,
)
from focaccia.qemu.report import (
    TerminalReason,
    TerminalActionValidation,
    write_validation_failure_report,
    write_validation_report,
)
from focaccia.qemu.snapshot import (
    collect_snapshot_plan,
    merge_snapshot_plans,
    plan_minimal_snapshot,
    plan_aarch64_scalar_context,
    plan_x86_scalar_context,
    plan_symbolic_dependencies,
    snapshot_diagnostics,
    unavailable_validation_outputs,
)
from focaccia.qemu.target import GDBServerStateIterator

logger = logging.getLogger("focaccia-qemu-validator")
debug = logger.debug
info = logger.info


def _has_interior_no_replay_actions(completion: TraceCompletion | None) -> bool:
    return completion is not None and any(
        (
            completion.no_replay_set_fs,
            completion.no_replay_set_tid,
            completion.no_replay_mmap,
            completion.no_replay_mprotect,
        )
    )


def collect_conc_trace(
    gdb: GDBServerStateIterator,
    strace: MaterializedTrace[SymbolicTraceItem] | TransformStream[SymbolicTraceItem],
    *,
    skip_unmatched: bool = False,
    cutpoint_addresses: tuple[int, ...] = (),
    profiler: QEMUValidationProfiler | None = None,
) -> MatchResult:
    """Collect matched concrete boundaries while preserving the terminal state."""
    declared_completion = getattr(strace, "declared_completion", strace.completion)
    if declared_completion is not None and declared_completion.no_replay_exit is not None:
        if skip_unmatched:
            raise ValueError("Exit-only whole-program collection prohibits skipped observations.")
    matcher = TransitionMatcher(strace, skip_unmatched=skip_unmatched)
    retained_states: list[ProgramState] = []
    retained_transforms: list[SymbolicTraceItem] = []
    diagnostics = []
    state_iterator = iter(gdb)

    if logger.isEnabledFor(logging.DEBUG):
        debug("Tracing program with the following non-deterministic events:")
        for event in gdb._events.events:
            debug(event)

    try:
        current_state = next(state_iterator)
    except StopIteration:
        return matcher.make_result(retained_states, retained_transforms)

    pc = current_state.read_pc()
    start_address = strace.env.start_address
    if start_address is None:
        start_address = pc

    if pc != start_address:
        info(f"Executing until starting address {hex(start_address)}")
        current_state = state_iterator.run_until(start_address)

    info(
        f"Tracing QEMU between {hex(start_address)}:"
        f"{hex(strace.env.stop_address) if strace.env.stop_address is not None else 'end'}"
    )

    cutpoint_index = 0
    while not matcher.done:
        try:
            pc = current_state.read_pc()
        except RegisterAccessError as error:
            matcher.fail_concrete_state(len(retained_states), error)
            break

        while (
            cutpoint_index < len(cutpoint_addresses)
            and cutpoint_addresses[cutpoint_index] == pc
        ):
            cutpoint_index += 1
        declared_destination = (
            cutpoint_addresses[cutpoint_index]
            if cutpoint_index < len(cutpoint_addresses)
            else None
        )

        boundary = matcher.observe(pc)
        execution_destination = declared_destination
        if boundary is not None:
            previous_state = retained_states[-1] if retained_states else current_state
            plans = [
                plan_minimal_snapshot(
                    current_state,
                    boundary.incoming,
                    boundary.outgoing,
                )
            ]
            if (strace.scope is TraceScope.WHOLE_PROGRAM
                    and declared_completion is not None and declared_completion.no_replay_exit is not None):
                if current_state.arch.archname == 'aarch64':
                    plans.append(plan_aarch64_scalar_context(
                        current_state, include_dczid=getattr(gdb, '_aarch64_cpu_context', None) is not None,
                    ))
                elif current_state.arch.archname == 'x86_64':
                    plans.append(plan_x86_scalar_context(current_state))
            if boundary.outgoing is not None and not skip_unmatched:
                next_cutpoint = getattr(state_iterator, "next_cutpoint_pc", None)
                destination_pc = declared_destination
                planned = None
                if destination_pc is None:
                    unavailable = unavailable_validation_outputs(
                        current_state, boundary.outgoing
                    )
                    materialized = matcher.plan_materialized_destination(unavailable)
                    if materialized is not None:
                        destination_pc, planned = materialized
                        execution_destination = destination_pc
                    elif next_cutpoint is not None:
                        destination_pc = next_cutpoint(matcher)
                if destination_pc is not None:
                    if planned is None:
                        planned = matcher.plan_destination(destination_pc)
                    if planned is None and declared_destination is not None:
                        raise ValueError(
                            f"Declared cutpoint {hex(destination_pc)} is not a reachable "
                            "symbolic destination."
                        )
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

        if matcher.done:
            break
        if _has_interior_no_replay_actions(declared_completion):
            gdb.authorize_no_replay_source(
                pc, matcher.current_transform_index, len(retained_transforms)
            )
        try:
            measurement = (
                profiler.measure("execution") if profiler is not None else nullcontext()
            )
            with measurement:
                if execution_destination is None:
                    current_state = next(state_iterator)
                elif not state_iterator.has_pending_no_replay_actions():
                    current_state = state_iterator.run_until(execution_destination)
                else:
                    # Ordered replay actions prohibit a debugger run-until, but
                    # they do not require every stepped state to become a
                    # validation cutpoint. Advance through the normal iterator
                    # so actions remain replayed, retaining only the planned
                    # composed destination.
                    while True:
                        current_state = next(state_iterator)
                        if current_state.read_pc() == execution_destination:
                            break
        except StopIteration:
            break

    result = matcher.make_result(retained_states, retained_transforms)
    return MatchResult(
        result.trace,
        (*result.diagnostics, *diagnostics),
        result.pending_transform,
        result.consumed_transform_count,
    )


def collect_terminal_completion(
    gdb: GDBServerStateIterator,
    strace: MaterializedTrace[SymbolicTraceItem] | TransformStream[SymbolicTraceItem],
    matched: MatchResult,
) -> tuple[TraceCompletion | None, TerminalActionValidation | None]:
    """Execute a proven final action after all oracle transforms are consumed.

    Incomplete comparisons do not make execution unsafe: explicit unknown
    snapshot inputs remain coverage gaps, while the independently observed
    final PC/instruction/action still permits conservative terminal evidence.
    """
    expected = strace.completion
    if (
        strace.scope is not TraceScope.WHOLE_PROGRAM
        or expected is None
        or matched.pending_transform is not None
        or matched.trace is None
        or matched.consumed_transform_count != expected.transform_count
        or not matched.trace.state_boundaries
        or matched.trace.state_boundaries[-1].read_pc() != expected.final_pc
    ):
        return None, None
    return gdb.execute_terminal_action(
        expected, retained_transform_count=len(matched.trace.transforms)
    )


def _pending_transition_error(reason: TerminalReason | None) -> Error:
    if reason is not None and reason.kind == "signal" and reason.pc is not None:
        return Error(
            ErrorTypes.CONFIRMED,
            f"QEMU guest stopped with signal {reason.signal} at {reason.pc:#x} "
            "before the pending transition produced a destination state.",
            code="unexpected-guest-signal",
            subject=reason.signal,
        )
    if reason is not None and reason.kind == "signal":
        return Error(
            ErrorTypes.INCOMPLETE,
            f"QEMU guest stopped with signal {reason.signal}, but its faulting "
            "program counter is unavailable.",
            code="unlocalized-guest-signal",
            subject=reason.signal,
        )
    return Error(
        ErrorTypes.INCOMPLETE,
        "QEMU stopped before the pending transition produced a destination "
        "state, but no terminal reason is available.",
        code="terminal-reason-unavailable",
    )


def _parse_run_inputs(values: list[str]) -> dict[str, str]:
    inputs: dict[str, str] = {}
    for value in values:
        name, separator, path = value.partition("=")
        if not separator or not name or not path:
            raise ValueError(f"Invalid --run-input {value!r}; expected NAME=PATH.")
        if name in inputs:
            raise ValueError(f"Duplicate --run-input name {name!r}.")
        inputs[name] = path
    return inputs


def _write_failure_report(
    args: argparse.Namespace,
    error: Exception,
    gdb_server: GDBServerStateIterator | None,
) -> None:
    if args.report is None:
        return
    coverage = gdb_server.replay_coverage_report() if gdb_server is not None else None
    try:
        write_validation_failure_report(args.report, error, coverage)
    except OSError as report_error:
        logger.error("Unable to write validation failure report: %s", report_error)


def main() -> None:
    argument_parser = make_argparser()
    forwarded_arguments = decode_gdb_arguments(os.environ)
    args = argument_parser.parse_args(forwarded_arguments)
    validate_backend_options(argument_parser, args)

    logging_level = getattr(logging, args.error_level.upper(), logging.INFO)
    logging.basicConfig(level=logging_level, force=True)

    gdb_server: GDBServerStateIterator | None = None
    report_written = False
    profiler = QEMUValidationProfiler() if args.profile_report is not None else None
    if profiler is not None:
        profiler.start_total()

    # Keep streaming trace input open until collection consumes it.
    mode = "r" if args.trace_type == "json" else "rb"
    try:
        detlog = DeterministicLog(args.deterministic_log)
        with open(args.symb_trace, mode) as trace_file:
            if args.trace_type == "json":
                symb_transforms = parser.parse_transformations(trace_file)
            else:
                symb_transforms = parser.stream_transformation(trace_file)

            no_replay_exit_only = (
                symb_transforms.scope is TraceScope.WHOLE_PROGRAM and not detlog.events()
            )
            declared_completion = getattr(
                symb_transforms, "declared_completion", symb_transforms.completion
            )
            if no_replay_exit_only and (
                declared_completion is None
                or declared_completion.no_replay_exit is None
                or symb_transforms.env.detlog is not None
            ):
                raise ValueError("No-log whole-program collection requires explicit exit-only action evidence.")

            if args.run_manifest is not None:
                manifest = load_replay_run_manifest(args.run_manifest)
                validate_replay_run_manifest(
                    manifest,
                    binary_path=args.executable,
                    input_paths=_parse_run_inputs(args.run_input),
                    argv=manifest.argv,
                    oracle_path=args.symb_trace,
                    trace_environment=symb_transforms.env,
                    deterministic_log=detlog,
                )

            gdb_server = GDBServerStateIterator(args.remote, detlog, args.executable)
            if getattr(args, 'qemu_xmm_read_profile', None) is not None:
                gdb_server.configure_xmm_read_transport(args.qemu_xmm_read_profile)
            executable = gdb_server.binary if args.executable is None else args.executable
            env = make_gdb_trace_environment(executable)
            if no_replay_exit_only:
                from focaccia.no_replay import require_exit_only_entry
                require_exit_only_entry(
                    executable, symb_transforms.env.binary_hash,
                    gdb_server.current_state().read_pc(), gdb_server.arch.key,
                )
                if declared_completion is None:
                    raise ValueError("Exit-only completion declaration is missing.")
                gdb_server.enable_no_replay_exit_only(declared_completion)
            if getattr(args, 'qemu_aarch64_cpu_model', None) is not None:
                if not no_replay_exit_only:
                    raise ValueError('Configured AArch64 CPU context currently requires whole-program no-replay mode.')
                gdb_server.configure_aarch64_cpu_context(args.qemu_aarch64_cpu_model)
            tracing_measurement = (
                profiler.measure("tracing") if profiler is not None else nullcontext()
            )
            with tracing_measurement:
                matched = collect_conc_trace(
                    gdb_server,
                    symb_transforms,
                    skip_unmatched=args.skip_unmatched,
                    cutpoint_addresses=tuple(args.cutpoint_address),
                    profiler=profiler,
                )
                if (
                    isinstance(symb_transforms, TransformStream)
                    and declared_completion is not None
                    and matched.consumed_transform_count == declared_completion.transform_count
                    and not symb_transforms.exhausted
                ):
                    try:
                        next(symb_transforms)
                    except StopIteration:
                        pass

        observed_completion, terminal_action_validation = collect_terminal_completion(
            gdb_server, symb_transforms, matched
        )
        terminal_reason = gdb_server.terminal_reason()
        if (
            no_replay_exit_only
            and matched.pending_transform is not None
            and terminal_reason is not None
            and terminal_reason.kind == "signal"
        ):
            # The stopped signal is localization evidence, not termination.
            # Deliver that exact pending guest signal once through GDB and
            # retain the resulting process observation independently.
            gdb_server.deliver_pending_guest_signal_once()
            terminal_reason = gdb_server.terminal_reason()
        validation_measurement = (
            profiler.measure("validation") if profiler is not None else nullcontext()
        )
        with validation_measurement:
            validation_report = compare_symbolic(
                matched.trace,
                diagnostics=matched.diagnostics,
            )
        if matched.pending_transform is not None:
            source = matched.trace.state_boundaries[-1] if matched.trace is not None else None
            validation_report = validation_report.with_entry(
                {
                    "pc": matched.pending_transform.addr,
                    "txl": None,
                    "ref": matched.pending_transform,
                    "errors": [_pending_transition_error(terminal_reason)],
                    "snap": source,
                }
            )
        replay_coverage = gdb_server.replay_coverage_report()
        if args.report:
            write_validation_report(
                args.report,
                validation_report,
                replay_coverage,
                matched,
                terminal_reason,
                scope=symb_transforms.scope,
                expected_completion=declared_completion,
                observed_completion=observed_completion,
                terminal_action_validation=terminal_action_validation,
            )
            report_written = True

        if args.output:
            from focaccia.parser import serialize_snapshots

            serialization_measurement = (
                profiler.measure("serialization")
                if profiler is not None
                else nullcontext()
            )
            with serialization_measurement:
                states = matched.trace.state_boundaries if matched.trace is not None else ()
                output_env = env
                if states:
                    output_env = env.with_architecture(states[0].arch.key)
                elif symb_transforms.env.architecture is not None:
                    output_env = env.with_architecture(symb_transforms.env.architecture)
                output_path = os.fspath(args.output)
                output_directory = os.path.dirname(output_path) or "."
                temporary_output = os.path.join(
                    output_directory,
                    f".{os.path.basename(output_path)}.tmp",
                )
                try:
                    with open(temporary_output, "w") as file:
                        serialize_snapshots(
                            MaterializedTrace(
                                states, output_env, scope=symb_transforms.scope,
                                completion=observed_completion,
                            ), file,
                        )
                    os.replace(temporary_output, output_path)
                finally:
                    try:
                        os.unlink(temporary_output)
                    except FileNotFoundError:
                        pass

        if profiler is not None:
            profiler.finish_total()
            write_qemu_validation_profile(args.profile_report, profiler.snapshot())

        if not args.quiet:
            print_result(validation_report, verbosity[args.error_level])
    except Exception as error:
        if not report_written:
            _write_failure_report(args, error, gdb_server)
        raise


if __name__ == "__main__":
    main()
