import argparse

from focaccia.symbolic import collect_symbolic_trace

def main():
    program = argparse.ArgumentParser()
    program.add_argument('binary')
    program.add_argument('argv', action='store', nargs=argparse.REMAINDER)
    program.add_argument('--start-addr',
                         help='Instruction at which to start')
    args = program.parse_args()

    binary = args.binary
    argv = args.argv

    pc = None
    if args.start_addr:
        try:
            pc = int(args.start_addr, 16)
        except ValueError:
            print(f'Start address must be a hexadecimal number. Exiting.')
            exit(1)

    strace = collect_symbolic_trace(binary, argv, pc)

    print(f'--- {len(strace)} instructions traced.')
    print(f'--- No new PC found. Exiting.')

if __name__ == "__main__":
    main()

# TODO: To implement support for unimplemented instructions, add their
# ASM->IR implementations to the `mnemo_func` array in
# `miasm/arch/x86/sem.py:5142`.
#
# For XGETBV, I might have to add the extended control register XCR0 first.
# This might be a nontrivial patch to Miasm.
