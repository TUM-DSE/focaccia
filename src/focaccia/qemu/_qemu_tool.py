"""Invocable like this:

    gdb -n --batch -x qemu_tool.py

But please use `tools/validate_qemu.py` instead because we have some more setup
work to do.
"""

import logging
import os
import time

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
from focaccia.qemu.snapshot import collect_minimal_snapshot, snapshot_diagnostics
from focaccia.qemu.target import GDBServerStateIterator

logger = logging.getLogger('focaccia-qemu-validator')
debug = logger.debug
info = logger.info

def collect_conc_trace(
    gdb: GDBServerStateIterator,
    strace: MaterializedTrace[SymbolicTraceItem] | TransformStream[SymbolicTraceItem],
) -> MatchResult:
    """Collect matched concrete boundaries while preserving the terminal state."""
    matcher = TransitionMatcher(strace)
    retained_states: list[ProgramState] = []
    retained_transforms: list[SymbolicTraceItem] = []
    diagnostics = []
    state_iterator = iter(gdb)

    execution_time = 0.0
    tracing_time = 0.0

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

    execution_start = time.time()
    if pc != start_address:
        info(f"Executing until starting address {hex(start_address)}")
        current_state = state_iterator.run_until(start_address)
    execution_time += time.time() - execution_start

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
            tracing_start = time.time()
            previous_state = retained_states[-1] if retained_states else current_state
            collection = collect_minimal_snapshot(
                previous_state,
                current_state,
                boundary.incoming,
                boundary.outgoing,
            )
            diagnostics.extend(
                snapshot_diagnostics(
                    collection,
                    len(retained_states),
                    len(retained_transforms)
                    if boundary.incoming is not None
                    else None,
                )
            )
            if boundary.incoming is not None:
                retained_transforms.append(boundary.incoming)
            retained_states.append(collection.state)
            tracing_time += time.time() - tracing_start

        if matcher.done:
            break
        execution_start = time.time()
        try:
            current_state = next(state_iterator)
        except StopIteration:
            break
        execution_time += time.time() - execution_start

    execution_time -= gdb.event_time
    debug(f"Execution time: {execution_time}")
    debug(f"Tracing time: {tracing_time}")
    result = matcher.make_result(retained_states, retained_transforms)
    return MatchResult(
        result.trace,
        (*result.diagnostics, *diagnostics),
        result.pending_transform,
    )

def main():
    argument_parser = make_argparser()
    forwarded_arguments = decode_gdb_arguments(os.environ)
    args = argument_parser.parse_args(forwarded_arguments)
    validate_backend_options(argument_parser, args)

    logging_level = getattr(logging, args.error_level.upper(), logging.INFO)
    logging.basicConfig(level=logging_level, force=True)

    detlog = DeterministicLog(args.deterministic_log)
    if args.deterministic_log and detlog.base_directory is None:
        raise NotImplementedError(f'Deterministic log {args.deterministic_log} specified but '
                                   'Focaccia built without deterministic log support')

    gdb_server = GDBServerStateIterator(args.remote, detlog)

    executable = (
        gdb_server.binary if args.executable is None else args.executable
    )
    env = make_gdb_trace_environment(executable)

    # Keep streaming trace input open until collection consumes it.
    mode = "r" if args.trace_type == "json" else "rb"
    try:
        with open(args.symb_trace, mode) as trace_file:
            if args.trace_type == "json":
                symb_transforms = parser.parse_transformations(trace_file)
            else:
                symb_transforms = parser.stream_transformation(trace_file)
            matched = collect_conc_trace(gdb_server, symb_transforms)
    except (OSError, ValueError) as error:
        raise RuntimeError(
            f"Failed to parse or collect the QEMU trace: {error}"
        ) from error

    # Verify and print result
    if not args.quiet:
        validation_start = time.time()
        report = compare_symbolic(
            matched.trace,
            diagnostics=matched.diagnostics,
        )
        if matched.pending_transform is not None:
            source = (
                matched.trace.state_boundaries[-1]
                if matched.trace is not None
                else None
            )
            report = report.with_entry(
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
        validation_time = time.time() - validation_start
        print(f"Validation time: {validation_time}")
        print_result(report, verbosity[args.error_level])

    if args.output:
        from focaccia.parser import serialize_snapshots

        states = (
            matched.trace.state_boundaries
            if matched.trace is not None
            else ()
        )
        output_env = env
        if states:
            output_env = env.with_architecture(states[0].arch.key)
        elif symb_transforms.env.architecture is not None:
            output_env = env.with_architecture(symb_transforms.env.architecture)
        with open(args.output, "w") as file:
            serialize_snapshots(MaterializedTrace(states, output_env), file)

if __name__ == "__main__":
    main()

