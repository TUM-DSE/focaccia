#!/usr/bin/env python3

import argparse
import logging

from focaccia import parser
from focaccia.symbolic import collect_symbolic_trace

def main():
    prog = argparse.ArgumentParser()
    prog.description = 'Trace an executable concolically to capture symbolic' \
                       ' transformations among instructions.'
    prog.add_argument('binary', help='The program to analyse.')
    prog.add_argument('args', action='store', nargs=argparse.REMAINDER,
                      help='Arguments to the program.')
    prog.add_argument('-o', '--output',
                      default='trace.out',
                      help='Name of output file. (default: trace.out)')
    args = prog.parse_args()

    logging.disable(logging.CRITICAL)
    trace = collect_symbolic_trace(args.binary, args.args, None)
    with open(args.output, 'w') as file:
        parser.serialize_transformations(trace, file)

if __name__ == "__main__":
    main()
