#! /bin/python3

import argparse

import arancini
from arch import x86
from compare import compare_simple
from run import run_native_execution
from utils import check_version, print_separator

def parse_inputs(txl_path, ref_path, program):
    # Our architecture
    arch = x86.ArchX86()

    txl = []
    with open(txl_path, "r") as txl_file:
        txl = arancini.parse(txl_file.readlines(), arch)

    ref = []
    if program is not None:
        with open(txl_path, "r") as txl_file:
            breakpoints = arancini.parse_break_addresses(txl_file.readlines())
        ref = run_native_execution(program, breakpoints)
    else:
        assert(ref_path is not None)
        with open(ref_path, "r") as native_file:
            ref = arancini.parse(native_file.readlines(), arch)

    return txl, ref

def parse_arguments():
    parser = argparse.ArgumentParser(description='Comparator for emulator logs to reference')
    parser.add_argument('-p', '--program',
                        type=str,
                        help='Path to oracle program')
    parser.add_argument('-r', '--ref',
                        type=str,
                        required=True,
                        help='Path to the reference log (gathered with run.sh)')
    parser.add_argument('-t', '--txl',
                        type=str,
                        required=True,
                        help='Path to the translation log (gathered via Arancini)')
    parser.add_argument('-s', '--stats',
                        action='store_true',
                        default=False,
                        help='Run statistics on comparisons')
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        default=True,
                        help='Path to oracle program')
    parser.add_argument('--progressive',
                        action='store_true',
                        default=False,
                        help='Try to match exhaustively before declaring \
                        mismatch')
    args = parser.parse_args()
    return args

def main():
    args = parse_arguments()

    txl_path = args.txl
    reference_path = args.ref
    program = args.program

    stats = args.stats
    verbose = args.verbose
    progressive = args.progressive

    if verbose:
        print("Enabling verbose program output")
        print(f"Verbose: {verbose}")
        print(f"Statistics: {stats}")
        print(f"Progressive: {progressive}")

    if program is None and reference_path is None:
        raise ValueError('Either program or path to native file must be'
                         'provided')

    txl, ref = parse_inputs(txl_path, reference_path, program)

    if program != None and reference_path != None:
        with open(reference_path, 'w') as w:
            for snapshot in ref:
                print(snapshot, file=w)

    result = compare_simple(txl, ref)

    # Print results
    for res in result:
        pc = res['pc']
        print_separator()
        print(f'For PC={hex(pc)}')
        print_separator()

        txl = res['txl']
        ref = res['ref']
        for err in res['errors']:
            reg = err['reg']
            print(f'Content of register {reg} is possibly false.'
                  f' Expected difference: {err["expected"]}, actual difference'
                  f' in the translation: {err["actual"]}.\n'
                  f'    (txl) {reg}: {hex(txl.regs[reg])}\n'
                  f'    (ref) {reg}: {hex(ref.regs[reg])}')

if __name__ == "__main__":
    check_version('3.7')
    main()
