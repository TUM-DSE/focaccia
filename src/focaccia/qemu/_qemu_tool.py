"""Invocable like this:

    gdb -n --batch -x qemu_tool.py

But please use `tools/validate_qemu.py` instead because we have some more setup
work to do.
"""

import argparse
import logging
import os

import focaccia.parser as parser
from focaccia.compare import compare_symbolic, Error, ErrorTypes
from focaccia.match import MatchResult, TransitionMatcher
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
from focaccia.qemu.report import (
    write_validation_failure_report,
    write_validation_report,
)
from focaccia.qemu.snapshot import (
    collect_snapshot_plan,
    merge_snapshot_plans,
    plan_minimal_snapshot,
    plan_symbolic_dependencies,
    snapshot_diagnostics,
)
from focaccia.qemu.target import GDBServerStateIterator

logger = logging.getLogger("focaccia-qemu-validator")
debug = logger.debug
info = logger.info


def collect_conc_trace(
    gdb: GDBServerStateIterator,
    strace: MaterializedTrace[SymbolicTraceItem] | TransformStream[SymbolicTraceItem],
    *,
    skip_unmatched: bool = False,
) -> MatchResult:
    """Collect matched concrete boundaries while preserving the terminal state."""
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

    while not matcher.done:
        try:
            pc = current_state.read_pc()
        except RegisterAccessError as error:
            matcher.fail_concrete_state(len(retained_states), error)
            break

        boundary = matcher.observe(pc)
        if boundary is not None:
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

        if matcher.done:
            break
        try:
            current_state = next(state_iterator)
        except StopIteration:
            break

    result = matcher.make_result(retained_states, retained_transforms)
    return MatchResult(
        result.trace,
        (*result.diagnostics, *diagnostics),
        result.pending_transform,
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

    # Keep streaming trace input open until collection consumes it.
    mode = "r" if args.trace_type == "json" else "rb"
    try:
        detlog = DeterministicLog(args.deterministic_log)
        with open(args.symb_trace, mode) as trace_file:
            if args.trace_type == "json":
                symb_transforms = parser.parse_transformations(trace_file)
            else:
                symb_transforms = parser.stream_transformation(trace_file)

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

            gdb_server = GDBServerStateIterator(args.remote, detlog)
            executable = gdb_server.binary if args.executable is None else args.executable
            env = make_gdb_trace_environment(executable)
            matched = collect_conc_trace(
                gdb_server,
                symb_transforms,
                skip_unmatched=args.skip_unmatched,
            )

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
                    "errors": [
                        Error(
                            ErrorTypes.CONFIRMED,
                            "QEMU stopped before the pending transition "
                            "produced a destination state.",
                        )
                    ],
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
            )
            report_written = True

        if args.output:
            from focaccia.parser import serialize_snapshots

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
                    serialize_snapshots(MaterializedTrace(states, output_env), file)
                os.replace(temporary_output, output_path)
            finally:
                try:
                    os.unlink(temporary_output)
                except FileNotFoundError:
                    pass

        if not args.quiet:
            print_result(validation_report, verbosity[args.error_level])
    except Exception as error:
        if not report_written:
            _write_failure_report(args, error, gdb_server)
        raise


if __name__ == "__main__":
    main()
