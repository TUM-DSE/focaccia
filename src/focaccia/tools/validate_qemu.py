#!/usr/bin/env python3

"""
Spawn GDB, connect to QEMU's GDB server, and read test states from that.

We need two scripts (this one and the primary `qemu_tool.py`) because we can't
pass arguments to scripts executed via `gdb -x <script>`.

Alternatively, we connect to the Focaccia QEMU plugin when a socket is given.

This script (`validate_qemu.py`) is the one the user interfaces with. It
eventually calls `execv` to spawn a GDB process that calls the main
`qemu_tool.py` script; `python validate_qemu.py` essentially behaves as if
something like `gdb --batch -x qemu_tool.py` were executed instead. Before it
starts GDB, though, it parses command line arguments and applies some weird but
necessary logic to pass them to `qemu_tool.py`.
"""

import os
import sys
import logging
import argparse
import sysconfig
import subprocess

from focaccia.compare import ErrorTypes
from focaccia.arch import supported_architectures
from focaccia.tools.validation_server import start_validation_server

verbosity = {
    'info':    ErrorTypes.INFO,
    'warning': ErrorTypes.POSSIBLE,
    'error':   ErrorTypes.CONFIRMED,
}

def make_argparser():
    """This is also used by the GDB-invoked script to parse its args."""
    prog = argparse.ArgumentParser()
    prog.description = """Use Focaccia to test QEMU.

Uses QEMU's GDB-server feature to read QEMU's emulated state and test its
transformation during emulation against a symbolic truth.

In fact, this tool could be used to test any emulator that provides a
GDB-server interface. The server must support reading registers, reading
memory, and stepping forward by single instructions.
"""
    prog.add_argument('--symb-trace',
                      required=True,
                      help='A pre-computed symbolic transformation trace to' \
                           ' be used for verification. Generate this with' \
                           ' the `tools/capture_transforms.py` tool.')
    prog.add_argument('-q', '--quiet',
                      default=False,
                      action='store_true',
                      help='Don\'t print a verification result.')
    prog.add_argument('-o', '--output',
                      type=str,
                      help='If specified with a file name, the recorded'
                           ' emulator states will be written to that file.')
    prog.add_argument('--error-level',
                      default='warning',
                      choices=list(verbosity.keys()))
    prog.add_argument('--executable',
                      default=None,
                      help='The executable executed under QEMU, overrides the auto-detected' \
                            'executable')
    prog.add_argument('--use-socket',
                      type=str,
                      nargs='?',
                      const='/tmp/focaccia.sock',
                      help='Use QEMU plugin interface given by socket instead of GDB')
    prog.add_argument('--guest-arch',
                      type=str,
                      choices=supported_architectures.keys(),
                      help='Architecture of the emulated guest'
                           '(Only required when using --use-socket)')
    prog.add_argument('--remote',
                      type=str,
                      help='The hostname:port pair at which to find a QEMU GDB server.')
    prog.add_argument('--gdb',
                      type=str,
                      default='gdb',
                      help='GDB binary to invoke.')
    prog.add_argument('--deterministic', default=None,
                      help='The directory containing rr traces')
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

    # Get environment
    env = os.environ.copy()

    # Differentiate between the QEMU GDB server and QEMU plugin interfaces
    if args.use_socket:
        if not args.guest_arch:
            argparser.error('--guest-arch is required when --use-socket is specified')

        logging_level = getattr(logging, args.error_level.upper(), logging.INFO)
        logging.basicConfig(level=logging_level, force=True)

        # QEMU plugin interface
        start_validation_server(args.symb_trace,
                                args.output,
                                args.use_socket,
                                args.guest_arch,
                                env,
                                verbosity[args.error_level],
                                args.quiet)
    else:
        # QEMU GDB interface
        script_dirname = os.path.dirname(__file__)
        qemu_tool_path = os.path.join(script_dirname, '_qemu_tool.py')

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
            '-x', qemu_tool_path
        ]
        proc = subprocess.Popen(gdb_cmd, env=env)

        ret = proc.wait()
        exit(ret)

