#!/usr/bin/env python3

import os
import sys
import logging
import argparse
import sysconfig
import subprocess

import focaccia.benchmark
from focaccia.arch import supported_architectures
from focaccia import utils, parser
from focaccia.trace import TraceEnvironment
from focaccia.native.tracer import SymbolicTracer
from focaccia.deterministic import DeterministicLog
from focaccia.benchmark.timer import Timer

def make_argparser():
    prog = argparse.ArgumentParser()
    prog.description = 'Focaccia benchmark'
    prog.add_argument('binary', help='The program to analyse.')
    prog.add_argument('args', action='store', nargs=argparse.REMAINDER,
                      help='Arguments to the program.')
    prog.add_argument('--guest-arch',
                      type=str,
                      choices=supported_architectures.keys(),
                      help='Architecture of the emulated guest')
    prog.add_argument('-p', '--port',
                      default='12345',
                      help='Port to use for connection with QEMU')
    prog.add_argument('-r', '--remote',
                      default=False,
                      help='Remote target to trace (e.g. 127.0.0.1:12345)')
    prog.add_argument('-n', '--iterations',
                      default='10',
                      help='Number of iterations per benchmark')
    prog.add_argument('-l', '--deterministic-log',
                      help='Path of the directory storing the deterministic log produced by RR')
    prog.add_argument('--gdb',
                      type=str,
                      default='gdb',
                      help='GDB binary to invoke.')
    prog.add_argument('-o', '--output',
                      default='./benchmark.txt',
                      help='Output file to save results')
    return prog

def quoted(s: str) -> str:
    return f'"{s}"'

def try_remove(l: list, v):
    try:
        l.remove(v)
    except ValueError:
        pass

def main():
    argparser = make_argparser()
    args = argparser.parse_args()

    logging.basicConfig(level=logging.ERROR)

    # Test native tracing
    detlog = DeterministicLog(args.deterministic_log)
    if args.deterministic_log and detlog.base_directory is None:
        raise NotImplementedError(f'Deterministic log {args.deterministic_log} specified but '
                                   'Focaccia built without deterministic log support')

    timer = Timer("Native tracing", iterations=args.iterations, file_path=args.output)
    timer.write_binary(args.binary)
    for i in range(timer.iterations):
        env = TraceEnvironment(args.binary, args.args, utils.get_envp(),
                               nondeterminism_log=detlog,
                               start_address=None,
                               stop_address=None)
        tracer = SymbolicTracer(env, remote=args.remote, cross_validate=False,
                            force=True)
        trace = tracer.trace(time_limit=None)
    timer.log_time()

    with open(f"/tmp/benchmark-{args.binary.split('/')[-1]}-symbolic.trace", 'w') as file:
        parser.serialize_transformations(trace, file)

    # Emu exec plain
    try:
        timer = Timer("Emulator execution (plain)", iterations=args.iterations)
        for i in range(timer.iterations):
            qemu_process = subprocess.run(
                [f"qemu-{args.guest_arch}", args.binary],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        timer.log_time()
    except Exception as e:
        raise Exception(f'Unable to benchmark QEMU: {e}')

    # Emu exec one instruction per block
    try:
        timer = Timer("Emulator execution (-one-insn-per-tb)", iterations=args.iterations)
        for i in range(timer.iterations):
            qemu_process = subprocess.run(
                [f"qemu-{args.guest_arch}", "-one-insn-per-tb", args.binary],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        timer.log_time()
    except Exception as e:
        raise Exception(f'Unable to benchmark QEMU: {e}')

    # Get environment
    env = os.environ.copy()
    # QEMU GDB interface
    script_dirname = os.path.dirname(focaccia.benchmark.__file__)
    benchmark_path = os.path.join(script_dirname, '_benchmark.py')

    # We have to remove all arguments we don't want to pass to the qemu tool
    # manually here. Not nice, but what can you do..
    argv = sys.argv
    try_remove(argv, '--gdb')
    try_remove(argv, args.gdb)

    # Assemble the argv array passed to the qemu tool. GDB does not have a
    # mechanism to pass arguments to a script that it executes, so we
    # overwrite `sys.argv` manually before invoking the script.
    argv_str = f'[{", ".join(quoted(a) for a in argv)}]'
    path_str = f'[{", ".join(quoted(s) for s in sys.path)}]'

    paths = sysconfig.get_paths()
    candidates = [paths["purelib"], paths["platlib"]]
    entries = [p for p in candidates if p and os.path.isdir(p)]
    venv_site = entries[0]
    env["PYTHONPATH"] = ','.join([script_dirname, venv_site])

    print(f"GDB started with Python Path: {env['PYTHONPATH']}")
    gdb_cmd = [
        args.gdb,
        '-nx',  # Don't parse any .gdbinits
        '--batch',
        '-ex',  'py import sys',
        '-ex', f'py sys.argv = {argv_str}',
        '-ex', f'py sys.path = {path_str}',
        "-ex", f'py import site; site.addsitedir({venv_site!r})',
        "-ex", f'py import site; site.addsitedir({script_dirname!r})',
        '-x', benchmark_path
    ]
    proc = subprocess.Popen(gdb_cmd, env=env)

    ret = proc.wait()
    exit(ret)

