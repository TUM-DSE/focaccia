"""Invocable like this:

    gdb -n --batch -x qemu_tool.py

But please use `tools/validate_qemu.py` instead because we have some more setup
work to do.
"""

import time
import logging
from typing import Iterable

import focaccia.parser as parser
from focaccia.compare import compare_symbolic, Error, ErrorTypes
from focaccia.match import MatchResult, TransitionMatcher
from focaccia.snapshot import (
    ProgramState,
    ReadableProgramState,
    RegisterAccessError,
    MemoryAccessError,
)
from focaccia.symbolic import SymbolicTransform, eval_symbol, ExprMem
from focaccia.trace import (
    MaterializedTrace,
    TraceEnvironment,
    TransformStream,
)
from focaccia.utils import print_result
from focaccia.deterministic import DeterministicLog

from focaccia.tools.validate_qemu import make_argparser, verbosity
from focaccia.qemu.target import GDBServerStateIterator

logger = logging.getLogger('focaccia-qemu-validator')
debug = logger.debug
info = logger.info

def record_minimal_snapshot(
    previous_state: ReadableProgramState,
    current_state: ReadableProgramState,
    incoming: SymbolicTransform | None,
    outgoing: SymbolicTransform | None,
) -> ProgramState:
    """Record inputs/outputs needed on either side of one retained boundary."""
    boundary_transform = incoming if incoming is not None else outgoing
    architecture = (
        boundary_transform.arch
        if boundary_transform is not None
        else current_state.arch
    )
    snapshot = ProgramState(architecture)
    snapshot.write_register("PC", current_state.read_pc())

    def written_memory(transform: SymbolicTransform) -> Iterable[ExprMem]:
        return [
            ExprMem(address, value.size)
            for address, value in transform.changed_mem.items()
        ]

    def copy_values(
        registers: Iterable[str],
        memory: Iterable[ExprMem],
        address_state: ReadableProgramState,
    ) -> None:
        for register in registers:
            try:
                snapshot.write_register(register, current_state.read_register(register))
            except RegisterAccessError:
                pass
        for expression in memory:
            if expression.size % 8 != 0:
                raise ValueError(f"Non-byte memory expression width: {expression.size}.")
            address = eval_symbol(expression.ptr, address_state)
            try:
                data = current_state.read_memory(address, expression.size // 8)
            except MemoryAccessError:
                continue
            snapshot.write_memory(address, data)

    if incoming is not None:
        copy_values(
            incoming.changed_regs.keys(),
            written_memory(incoming),
            previous_state,
        )
    if outgoing is not None:
        copy_values(
            outgoing.get_used_registers(),
            outgoing.get_used_memory_addresses(),
            current_state,
        )
    return snapshot

def collect_conc_trace(
    gdb: GDBServerStateIterator,
    strace: MaterializedTrace[SymbolicTransform] | TransformStream[SymbolicTransform],
) -> MatchResult:
    """Collect matched concrete boundaries while preserving the terminal state."""
    matcher = TransitionMatcher(strace)
    retained_states: list[ProgramState] = []
    retained_transforms: list[SymbolicTransform] = []
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
    try:
        if pc != start_address:
            info(f"Executing until starting address {hex(start_address)}")
            current_state = state_iterator.run_until(start_address)
    except Exception as error:
        raise RuntimeError(
            f"Unable to reach start address {hex(start_address)}: {error}"
        ) from error
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
            snapshot = record_minimal_snapshot(
                previous_state,
                current_state,
                boundary.incoming,
                boundary.outgoing,
            )
            if boundary.incoming is not None:
                retained_transforms.append(boundary.incoming)
            retained_states.append(snapshot)
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
    return matcher.make_result(retained_states, retained_transforms)

def main():
    args = make_argparser().parse_args()

    logging_level = getattr(logging, args.error_level.upper(), logging.INFO)
    logging.basicConfig(level=logging_level, force=True)

    detlog = DeterministicLog(args.deterministic_log)
    if args.deterministic_log and detlog.base_directory is None:
        raise NotImplementedError(f'Deterministic log {args.deterministic_log} specified but '
                                   'Focaccia built without deterministic log support')

    try:
        gdb_server = GDBServerStateIterator(args.remote, detlog, args.schedule)
    except Exception as e:
        raise Exception(f'Unable to perform basic GDB setup: {e}')

    try:
        executable: str | None = None
        if args.executable is None:
            executable = gdb_server.binary
        else:
            executable = args.executable

        argv = []  # QEMU's GDB stub does not support 'info proc cmdline'
        envp = []  # Can't get the remote target's environment
        env = TraceEnvironment(executable, argv, envp, '?')
    except Exception as e:
        raise Exception(f'Unable to create trace environment for executable {executable}: {e}')

    # Read pre-computed symbolic trace
    try:
        if args.trace_type == 'json':
            file = open(args.symb_trace, 'r')
            symb_transforms = parser.parse_transformations(file)
        else:
            file = open(args.symb_trace, 'rb')
            symb_transforms = parser.stream_transformation(file)
    except Exception as e:
        raise Exception(f'Failed to parse state transformations from native trace: {e}')

    # Use symbolic trace to collect concrete trace from QEMU
    try:
        matched = collect_conc_trace(gdb_server, symb_transforms)
    except Exception as error:
        raise RuntimeError(
            f"Failed to collect concolic trace from QEMU: {error}"
        ) from error

    # Verify and print result
    if not args.quiet:
        try:
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
        except Exception as error:
            raise RuntimeError(
                f"Error comparing with symbolic equations: {error}"
            ) from error

    if args.output:
        from focaccia.parser import serialize_snapshots

        try:
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
        except Exception as error:
            raise RuntimeError(
                f"Unable to serialize snapshots to file {args.output}: {error}"
            ) from error

if __name__ == "__main__":
    main()

