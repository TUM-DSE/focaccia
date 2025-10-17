#!/usr/bin/env python3

import argparse

from focaccia import parser, utils
from focaccia.symbolic import collect_symbolic_trace
from focaccia.trace import TraceEnvironment

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
    prog.add_argument('-c', '--cross-validate',
                      default=False,
                      action='store_true',
                      help='Cross-validate symbolic equations with concrete values')
    prog.add_argument('-r', '--remote',
                      default=False,
                      help='Remote target to trace (e.g. 127.0.0.1:12345)')
    args = prog.parse_args()

    env = TraceEnvironment(args.binary, args.args, args.cross_validate, utils.get_envp())
    trace = collect_symbolic_trace(env, None, remote=args.remote)
    with open(args.output, 'w') as file:
        parser.serialize_transformations(trace, file)

if __name__ == "__main__":
    main()
