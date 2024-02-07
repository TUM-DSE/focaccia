#!/usr/bin/env python3

import argparse
import platform
from typing import Iterable, Tuple

from focaccia.arch import supported_architectures
from focaccia.compare import compare_simple, compare_symbolic, ErrorTypes
from focaccia.lldb_target import LLDBConcreteTarget
from focaccia.match import fold_traces, match_traces
from focaccia.parser import parse_arancini, parse_snapshots
from focaccia.snapshot import ProgramState
from focaccia.symbolic import collect_symbolic_trace
from focaccia.utils import print_result
from focaccia.reproducer import Reproducer
from focaccia.compare import ErrorSeverity



verbosity = {
    'info':    ErrorTypes.INFO,
    'warning': ErrorTypes.POSSIBLE,
    'error':   ErrorTypes.CONFIRMED,
}

def collect_concrete_trace(oracle_program: str, breakpoints: Iterable[int]) \
        -> Tuple[list[ProgramState], list]:
    """Gather snapshots from a native execution via an external debugger.

    :param oracle_program: Program to execute.
    :param breakpoints: List of addresses at which to break and record the
                        program's state.

    :return: A list of snapshots gathered from the execution.
    """
    target = LLDBConcreteTarget(oracle_program)

    # Set breakpoints
    for address in breakpoints:
        target.set_breakpoint(address)

    # Execute the native program
    snapshots = []
    basic_blocks = []
    while not target.is_exited():
        snapshots.append(target.record_snapshot())
        basic_blocks.append(target.get_next_basic_block())
        target.run()

    return snapshots, basic_blocks

def parse_arguments():
    parser = argparse.ArgumentParser(description='Comparator for emulator logs to reference')
    parser.add_argument('-p', '--program',
                        type=str,
                        required=True,
                        help='Path to oracle program')
    parser.add_argument('-a', '--program-arg',
                        type=str,
                        default=[],
                        action='append',
                        help='Arguments to the program specified with --program.')
    parser.add_argument('-t', '--txl',
                        type=str,
                        required=True,
                        help='Path to the translation log (gathered via Arancini)')
    parser.add_argument('--symbolic',
                        action='store_true',
                        default=False,
                        help='Use an advanced algorithm that uses symbolic'
                             ' execution to determine accurate data'
                             ' transformations. This improves the quality of'
                             ' generated errors significantly, but will take'
                             ' more time to complete.')
    parser.add_argument('--error-level',
                        type=str,
                        default='warning',
                        choices=list(verbosity.keys()),
                        help='Verbosity of reported errors. \'error\' only'
                             ' reports mismatches that have been detected as'
                             ' errors in the translation with certainty.'
                             ' \'warning\' will report possible errors that'
                             ' may as well stem from incomplete input data.'
                             ' \'info\' will report absolutely everything.'
                             ' [Default: warning]')
    parser.add_argument('-r', '--reproducer',
                        action='store_true',
                        default=False,
                        help='Enable reproducer to get assembly code'
                             ' which should replicate the first error.')
    parser.add_argument('--trace-type',
                        type=str,
                        default='qemu',
                        choices=['qemu', 'arancini'],
                        help='Trace type of the emulator.'
                             ' Currently only Qemu and Arancini traces are accepted.'
                             ' Use \'qemu\' for Qemu and \'arancini\' for Arancini.'
                             ' [Default: qemu]')
    args = parser.parse_args()
    return args

def print_reproducer(result, min_severity: ErrorSeverity, oracle, oracle_args):
    for res in result:
        errs = [e for e in res['errors'] if e.severity >= min_severity]
        #breakpoint()
        if errs:
            rep = Reproducer(oracle, oracle_args, res['snap'], res['ref'])
            print(rep.asm())
            return


def main():
    args = parse_arguments()

    # Determine the current machine's architecture. The log type must match the
    # architecture on which focaccia is executed because focaccia wants to
    # execute the reference program concretely.
    if platform.machine() not in supported_architectures:
        print(f'Machine {platform.machine()} is not supported! Exiting.')
        exit(1)
    arch = supported_architectures[platform.machine()]

    txl_path = args.txl
    oracle = args.program
    oracle_args = args.program_arg

    # Parse reference trace
    with open(txl_path, "r") as txl_file:
        if args.trace_type == 'qemu':
            test_states = parse_snapshots(txl_file)
        elif args.trace_type == 'arancini':
            test_states = parse_arancini(txl_file, arch)
        else:
            test_states = parse_snapshots(txl_file)

    # Compare reference trace to a truth
    if args.symbolic:
        print(f'Tracing {oracle} symbolically with arguments {oracle_args}...')
        transforms = collect_symbolic_trace(oracle, oracle_args)
        test_states, transforms = match_traces(test_states, transforms)
        #fold_traces(test_states, transforms)
        result = compare_symbolic(test_states, transforms)
    else:
        # Record truth states from a concrete execution of the oracle
        breakpoints = [state.read_register('PC') for state in test_states]
        truth = collect_concrete_trace(oracle, breakpoints)
        result = compare_simple(test_states, truth)

    print_result(result, verbosity[args.error_level])

    if args.reproducer:
        print_reproducer(result, verbosity[args.error_level], oracle, oracle_args)

if __name__ == '__main__':
    main()
