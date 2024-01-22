#! /bin/python3

import argparse
import platform
from typing import Iterable

from focaccia.arch import x86
from focaccia.compare import compare_simple, compare_symbolic, \
                             ErrorSeverity, ErrorTypes
from focaccia.lldb_target import LLDBConcreteTarget
from focaccia.parser import parse_arancini
from focaccia.snapshot import ProgramState
from focaccia.symbolic import SymbolicTransform, collect_symbolic_trace
from focaccia.utils import print_result

def run_native_execution(oracle_program: str, breakpoints: Iterable[int]):
    """Gather snapshots from a native execution via an external debugger.

    :param oracle_program: Program to execute.
    :param breakpoints: List of addresses at which to break and record the
                        program's state.

    :return: A list of snapshots gathered from the execution.
    """
    assert(platform.machine() == "x86_64")

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

def match_traces(test: list[ProgramState], truth: list[SymbolicTransform]):
    if not test or not truth:
        return [], []

    assert(test[0].read_register('pc') == truth[0].addr)

    def index(seq, target, access=lambda el: el):
        for i, el in enumerate(seq):
            if access(el) == target:
                return i
        return None

    i = 0
    for next_state in test[1:]:
        next_pc = next_state.read_register('pc')
        index_in_truth = index(truth[i:], next_pc, lambda el: el.range[1])

        # If no next element (i.e. no foldable range) is found in the truth
        # trace, assume that the test trace contains excess states. Remove one
        # and try again. This might skip testing some states, but covers more
        # of the entire trace.
        if index_in_truth is None:
            test.pop(i + 1)
            continue

        # Fold the range of truth states until the next test state
        for _ in range(index_in_truth):
            truth[i].concat(truth.pop(i + 1))

        assert(truth[i].range[1] == truth[i + 1].addr)

        i += 1
        if len(truth) <= i:
            break

    return test, truth

def parse_inputs(txl_path, program):
    # Our architecture
    arch = x86.ArchX86()

    with open(txl_path, "r") as txl_file:
        txl = parse_arancini(txl_file, arch)

    with open(txl_path, "r") as txl_file:
        breakpoints = [state.read_register('PC') for state in txl]
        ref = run_native_execution(program, breakpoints)

    return txl, ref

def parse_arguments():
    parser = argparse.ArgumentParser(description='Comparator for emulator logs to reference')
    parser.add_argument('-p', '--program',
                        type=str,
                        required=True,
                        help='Path to oracle program')
    parser.add_argument('-a', '--program-arg',
                        type=str,
                        required=False,
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
                             ' generated errors significantly, but may take'
                             ' more time to run.')
    parser.add_argument('--error-level',
                        type=str,
                        default='verbose',
                        choices=['verbose', 'errors', 'restricted'],
                        help='Verbosity of reported errors. \'errors\' reports'
                             ' everything that might be an error in the'
                             ' translation, while \'verbose\' may report'
                             ' additional errors from incomplete input'
                             ' data, etc. [Default: verbose]')
    args = parser.parse_args()
    return args

def main():
    verbosity = {
        'verbose': ErrorTypes.INFO,
        'errors': ErrorTypes.POSSIBLE,
        'restricted': ErrorTypes.CONFIRMED,
    }
    args = parse_arguments()

    txl_path = args.txl
    program = args.program
    prog_args = args.program_arg
    txl, ref = parse_inputs(txl_path, program)

    if args.symbolic:
        assert(program is not None)

        print(f'Tracing {program} symbolically with arguments {prog_args}...')
        transforms = collect_symbolic_trace(program, prog_args)
        txl, transforms = match_traces(txl, transforms)
        result = compare_symbolic(txl, transforms)
    else:
        result = compare_simple(txl, ref)

    print_result(result, verbosity[args.error_level])

if __name__ == '__main__':
    main()
