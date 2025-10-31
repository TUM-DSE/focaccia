#!/usr/bin/env python3

import sys
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
    prog.add_argument('-l', '--deterministic-log',
                      help='Path of the directory storing the deterministic log produced by RR')
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
    prog.add_argument('--start-address',
                      default=None,
                      type=utils.to_int,
                      help='Set a starting address from which to collect the symoblic trace')
    prog.add_argument('--stop-address',
                      default=None,
                      type=utils.to_int,
                      help='Set a final address up until which to collect the symoblic trace')
    prog.add_argument('--insn-time-limit',
                      default=None,
                      type=utils.to_num,
                      help='Set a time limit for executing an instruction symbolically, skip'
                           'instruction when limit is exceeded')
    args = prog.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG) # will be override by --log-level

    # Set default logging level
    if args.log_level:
        level = getattr(logging, args.log_level.upper(), logging.INFO)
        logging.basicConfig(level=level, force=True)
    else:
        logging.basicConfig(level=logging.INFO)

    detlog = None
    if args.deterministic_log:
        from focaccia.deterministic import DeterministicLog
        detlog = DeterministicLog(args.deterministic_log)
    else:
        class NullDeterministicLog:
            def __init__(self): pass
            def events_file(self): return None
            def tasks_file(self): return None
            def mmaps_file(self): return None
            def events(self): return []
            def tasks(self): return []
            def mmaps(self): return []
        detlog = NullDeterministicLog()

    env = TraceEnvironment(args.binary, args.args, utils.get_envp(), nondeterminism_log=detlog)
    tracer = SymbolicTracer(env, remote=args.remote, cross_validate=args.debug,
                            force=args.force)

    trace = tracer.trace(start_addr=args.start_address,
                         stop_addr=args.stop_address,
                         time_limit=args.insn_time_limit)

    with open(args.output, 'w') as file:
        parser.serialize_transformations(trace, file)

