"""
Spawn GDB, connect to QEMU's GDB server, and read test states from that.

We need two scripts (this one and the primary `qemu_tool.py`) because we can't
pass arguments to scripts executed via `gdb -x <script>`.

This script (`verify_qemu.py`) is the one the user interfaces with. It
eventually calls `execv` to spawn a GDB process that calls the main
`qemu_tool.py` script; `python verify_qemu.py` essentially behaves as if
something like `gdb --batch -x qemu_tool.py` were executed instead. Before it
starts GDB, though, it parses command line arguments and applies some weird but
necessary logic to pass them to `qemu_tool.py`.
"""

import argparse
import os
import subprocess
import sys

def make_argparser():
    """This is also used by the GDB-invoked script to parse its args."""
    prog = argparse.ArgumentParser()
    prog.add_argument('--symb-trace',
                      required=True,
                      help='A symbolic transformation trace to be used for' \
                           ' verification.')
    prog.add_argument('--output', '-o', help='Name of output file.')
    prog.add_argument('gdbserver_port', type=int)
    return prog

def quoted(s: str) -> str:
    return f'"{s}"'

def try_remove(l: list, v):
    try:
        l.remove(v)
    except ValueError:
        pass

if __name__ == "__main__":
    prog = make_argparser()
    prog.add_argument('--gdb', default='/bin/gdb',
                      help='GDB binary to invoke')
    prog.add_argument('--quiet', '-q', action='store_true',
                      help='Suppress all output')
    args = prog.parse_args()

    filepath = os.path.realpath(__file__)
    qemu_tool_path = os.path.join(os.path.dirname(filepath), 'qemu_tool.py')

    # We have to remove all arguments we don't want to pass to the qemu tool
    # manually here. Not nice, but what can you do..
    argv = sys.argv
    try_remove(argv, '--gdb')
    try_remove(argv, args.gdb)
    try_remove(argv, '--quiet')
    try_remove(argv, '-q')

    # Assemble the argv array passed to the qemu tool. GDB does not have a
    # mechanism to pass arguments to a script that it executes, so we
    # overwrite `sys.argv` manually before invoking the script.
    argv_str = f'[{", ".join(quoted(a) for a in argv)}]'
    path_str = f'[{", ".join(quoted(s) for s in sys.path)}]'

    gdb_cmd = [
        args.gdb,
        '-nx',  # Don't parse any .gdbinits
        '--batch-silent' if args.quiet else '--batch',
        '-ex', f'py import sys',
        '-ex', f'py sys.argv = {argv_str}',
        '-ex', f'py sys.path = {path_str}',
        '-x', qemu_tool_path
    ]
    proc = subprocess.Popen(gdb_cmd)

    ret = proc.wait()
    exit(ret)
