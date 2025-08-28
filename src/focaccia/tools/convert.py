#!/usr/bin/env python3

import argparse
import sys

import focaccia.parser as parser
from focaccia.arch import supported_architectures

convert_funcs = {
    'qemu':     parser.parse_qemu,
    'arancini': parser.parse_arancini,
}

def main():
    """Main."""
    prog = argparse.ArgumentParser()
    prog.description = 'Convert other programs\' logs to focaccia\'s log format.'
    prog.add_argument('file', help='The log to convert.')
    prog.add_argument('--type',
                      required=True,
                      choices=convert_funcs.keys(),
                      help='The log type of `file`')
    prog.add_argument('--output', '-o',
                      help='Output file (default is stdout)')
    prog.add_argument('--arch',
                      default='x86_64',
                      choices=supported_architectures.keys(),
                      help='Processor architecture of input log (default is x86)')
    args = prog.parse_args()

    # Parse arancini log
    arch = supported_architectures[args.arch]
    parse_log = convert_funcs[args.type]
    with open(args.file, 'r') as in_file:
        try:
            snapshots = parse_log(in_file, arch)
        except parser.ParseError as err:
            print(f'Parse error: {err}. Exiting.', file=sys.stderr)
            exit(1)

    # Write log in focaccia's format
    if args.output:
        with open(args.output, 'w') as out_file:
            parser.serialize_snapshots(snapshots, out_file)
    else:
        parser.serialize_snapshots(snapshots, sys.stdout)

if __name__ == '__main__':
    main()
