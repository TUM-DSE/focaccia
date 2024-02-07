#! /usr/bin/env python3

import argparse
import platform
from typing import Iterable

from focaccia.arch import supported_architectures
from focaccia.compare import compare_simple, compare_symbolic, ErrorTypes
from focaccia.lldb_target import LLDBConcreteTarget
from focaccia.match import fold_traces
from focaccia.parser import parse_arancini
from focaccia.snapshot import ProgramState
from focaccia.symbolic import collect_symbolic_trace
from focaccia.utils import print_result

verbosity = {
    'info':    ErrorTypes.INFO,
    'warning': ErrorTypes.POSSIBLE,
    'error':   ErrorTypes.CONFIRMED,
}

def collect_concrete_trace(oracle_program: str, breakpoints: Iterable[int]) \
        -> list[ProgramState]:
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
    while not target.is_exited():
        snapshots.append(target.record_snapshot())
        target.run()

    return snapshots

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
    args = parser.parse_args()
    return args

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
        test_states = parse_arancini(txl_file, arch)

    # Compare reference trace to a truth
    if args.symbolic:
        print(f'Tracing {oracle} symbolically with arguments {oracle_args}...')
        transforms = collect_symbolic_trace(oracle, oracle_args)
        fold_traces(test_states, transforms)
        result = compare_symbolic(test_states, transforms)
    else:
        # Record truth states from a concrete execution of the oracle
        breakpoints = [state.read_register('PC') for state in test_states]
        truth = collect_concrete_trace(oracle, breakpoints)
        result = compare_simple(test_states, truth)

    print_result(result, verbosity[args.error_level])

if __name__ == '__main__':
    main()
