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
    args = prog.parse_args()

    env = TraceEnvironment(args.binary, args.args, utils.get_envp())
    trace = collect_symbolic_trace(env, None)
    with open(args.output, 'w') as file:
        parser.serialize_transformations(trace, file)

if __name__ == "__main__":
    main()
