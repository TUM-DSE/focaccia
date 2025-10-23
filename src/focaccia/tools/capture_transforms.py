#!/usr/bin/env python3

import argparse
import logging

from focaccia import parser, utils
from focaccia.symbolic import SymbolicTracer
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
    prog.add_argument('--log-level',
                      help='Set the logging level')
    prog.add_argument('--force',
                      default=False,
                      action='store_true',
                      help='Force Focaccia to continue tracing even when something goes wrong')
    prog.add_argument('--debug',
                      default=False,
                      action='store_true',
                      help='Capture transforms in debug mode to identify errors in Focaccia itself')
    args = prog.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG) # will be override by --log-level

    # Set default logging level
    if args.log_level:
        level = getattr(logging, args.log_level.upper(), logging.INFO)
        logging.basicConfig(level=level, force=True)
    else:
        logging.basicConfig(level=logging.INFO)

    env = TraceEnvironment(args.binary, args.args, utils.get_envp())
    tracer = SymbolicTracer(env, remote=args.remote, cross_validate=args.cross_validate,
                            force=args.force)
    trace = tracer.trace()
    with open(args.output, 'w') as file:
        parser.serialize_transformations(trace, file)

