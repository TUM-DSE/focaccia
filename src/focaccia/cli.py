#!/usr/bin/env python3

import argparse
import platform
from typing import Callable, Iterable

import focaccia.parser as parser
from focaccia.arch import supported_architectures, Arch
from focaccia.compare import compare_simple, compare_symbolic, ErrorTypes
from focaccia.lldb_target import LLDBConcreteTarget
from focaccia.match import fold_traces, match_traces
from focaccia.snapshot import ProgramState
from focaccia.symbolic import collect_symbolic_trace, SymbolicTransform
from focaccia.utils import print_result, get_envp
from focaccia.reproducer import Reproducer
from focaccia.compare import ErrorSeverity
from focaccia.trace import Trace, TraceEnvironment

verbosity = {
    'info':    ErrorTypes.INFO,
    'warning': ErrorTypes.POSSIBLE,
    'error':   ErrorTypes.CONFIRMED,
}

concrete_trace_parsers = {
    'focaccia': lambda f, _: parser.parse_snapshots(f),
    'qemu':     parser.parse_qemu,
    'arancini': parser.parse_arancini,
    'box64': parser.parse_box64,
}

_MatchingAlgorithm = Callable[
    [list[ProgramState], list[SymbolicTransform]],
    tuple[list[ProgramState], list[SymbolicTransform]]
]

matching_algorithms: dict[str, _MatchingAlgorithm] = {
    'none':   lambda c, s: (c, s),
    'simple': match_traces,
    'fold':   fold_traces,
}

def collect_concrete_trace(env: TraceEnvironment, breakpoints: Iterable[int]) \
        -> list[ProgramState]:
    """Gather snapshots from a native execution via an external debugger.

    :param env: Program to execute and the environment in which to execute it.
    :param breakpoints: List of addresses at which to break and record the
                        program's state.

    :return: A list of snapshots gathered from the execution.
    """
    target = LLDBConcreteTarget(env.binary_name, env.argv, env.envp)

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
    parser = argparse.ArgumentParser()
    parser.description = '''An emulator tester and verifier.

You can pre-record symbolic traces with `tools/capture_transforms.py`, then pass
them to the verifier with the --oracle-trace argument.
'''

    # Specification of the symbolic truth trace
    symb_trace = parser.add_mutually_exclusive_group(required=True)
    symb_trace.add_argument('-p', '--oracle-program',
                            help='A program from which a symbolic truth will be'
                                 ' recorded.')
    symb_trace.add_argument('-o', '--oracle-trace', '--symb-trace',
                            help='A symbolic trace that serves as a truth state'
                                 ' for comparison.')
    parser.add_argument('-a', '--oracle-args',
                        nargs='*',
                        default=[],
                        help='Arguments to the oracle program.')
    parser.add_argument('-e', '--oracle-env',
                        nargs='*',
                        help='Override the oracle program\'s environment during'
                             ' symbolic and concrete execution.')

    # Specification of the concrete test trace
    parser.add_argument('-t', '--test-trace',
                        required=True,
                        help='The concrete test states to test against the'
                             ' symbolic truth.')
    parser.add_argument('--test-trace-type',
                        default='focaccia',
                        choices=list(concrete_trace_parsers.keys()),
                        help='Log file format of the tested program trace.'
                             ' [Default: focaccia]')

    # Algorithm and output control
    parser.add_argument('--match',
                        choices=list(matching_algorithms.keys()),
                        default='simple',
                        help='Select an algorithm to match the test trace to'
                             ' the truth trace. Only applicable if --symbolic'
                             ' is enabled.'
                             ' [Default: simple]')
    parser.add_argument('--symbolic',
                        action='store_true',
                        default=False,
                        help='Use an advanced algorithm that uses symbolic'
                             ' execution to determine accurate data'
                             ' transformations. This improves the quality of'
                             ' generated errors significantly, but will take'
                             ' more time to complete.')
    parser.add_argument('--error-level',
                        default='warning',
                        choices=list(verbosity.keys()),
                        help='Verbosity of reported errors. \'error\' only'
                             ' reports mismatches that have been detected as'
                             ' errors in the translation with certainty.'
                             ' \'warning\' will report possible errors that'
                             ' may as well stem from incomplete input data.'
                             ' \'info\' will report absolutely everything.'
                             ' [Default: warning]')
    parser.add_argument('--no-verifier',
                        action='store_true',
                        default=False,
                        help='Don\'t print verifier output.')

    # Reproducer
    parser.add_argument('--reproducer',
                        action='store_true',
                        default=False,
                        help='Generate repoducer executables for detected'
                             ' errors.')

    return parser.parse_args()

def print_reproducer(result, min_severity: ErrorSeverity, oracle, oracle_args):
    for res in result:
        errs = [e for e in res['errors'] if e.severity >= min_severity]
        #breakpoint()
        if errs:
            rep = Reproducer(oracle, oracle_args, res['snap'], res['ref'])
            print(rep.asm())
            return

def get_test_trace(args, arch: Arch) -> Trace[ProgramState]:
    path = args.test_trace
    parser = concrete_trace_parsers[args.test_trace_type]
    with open(path, 'r') as txl_file:
        return parser(txl_file, arch)

def get_truth_env(args) -> TraceEnvironment:
    oracle = args.oracle_program
    oracle_args = args.oracle_args
    if args.oracle_env:
        oracle_env = args.oracle_env
    else:
        oracle_env = get_envp()
    return TraceEnvironment(oracle, oracle_args, oracle_env)

def get_symbolic_trace(args):
    if args.oracle_program:
        env = get_truth_env(args)
        print('Tracing', env)
        return collect_symbolic_trace(env)
    elif args.oracle_trace:
        with open(args.oracle_trace, 'r') as file:
            return parser.parse_transformations(file)
    raise AssertionError()

def main():
    args = parse_arguments()

    # Determine the current machine's architecture. The log type must match the
    # architecture on which focaccia is executed because focaccia wants to
    # execute the reference program concretely.
    if platform.machine() not in supported_architectures:
        print(f'Machine {platform.machine()} is not supported! Exiting.')
        exit(1)
    arch = supported_architectures[platform.machine()]

    # Parse reference trace
    test_trace = get_test_trace(args, arch)

    # Compare reference trace to a truth
    if args.symbolic:
        symb_trace = get_symbolic_trace(args)
        match = matching_algorithms[args.match]
        conc, symb = match(test_trace.states, symb_trace.states)

        result = compare_symbolic(conc, symb)
        oracle_env = symb_trace.env
    else:
        if not args.oracle_program:
            print('Argument --oracle-program is required for non-symbolic'
                  ' verification!')
            exit(1)

        # Record truth states from a concrete execution of the oracle
        breakpoints = [state.read_register('PC') for state in test_trace]
        env = get_truth_env(args)
        truth_trace = collect_concrete_trace(env, breakpoints)

        result = compare_simple(test_trace.states, truth_trace)
        oracle_env = env

    if not args.no_verifier:
        print_result(result, verbosity[args.error_level])

    if args.reproducer:
        print_reproducer(result,
                         verbosity[args.error_level],
                         oracle_env.binary_name,
                         oracle_env.argv)

if __name__ == '__main__':
    main()
