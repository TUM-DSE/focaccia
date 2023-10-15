#! /bin/python3

import argparse

import arancini
from arch import x86
from compare import compare_simple
from run import run_native_execution
from utils import check_version, print_separator

def read_logs(txl_path, native_path, program):
    txl = []
    with open(txl_path, "r") as txl_file:
        txl = txl_file.readlines()

    native = []
    if program is not None:
        breakpoints = arancini.parse_break_addresses(txl)
        native = run_native_execution(program, breakpoints)
    else:
        assert(native_path is not None)
        with open(native_path, "r") as native_file:
            native = native_file.readlines()

    return txl, native

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
    native_path = args.ref
    program = args.program

    stats = args.stats
    verbose = args.verbose
    progressive = args.progressive

    # Our architexture
    arch = x86.ArchX86()

    if verbose:
        print("Enabling verbose program output")
        print(f"Verbose: {verbose}")
        print(f"Statistics: {stats}")
        print(f"Progressive: {progressive}")

    if program is None and native_path is None:
        raise ValueError('Either program or path to native file must be'
                         'provided')

    txl, native = read_logs(txl_path, native_path, program)

    if program != None and native_path != None:
        with open(native_path, 'w') as w:
            w.write(''.join(native))

    txl = arancini.parse(txl, arch)
    native = arancini.parse(native, arch)
    result = compare_simple(txl, native)

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
