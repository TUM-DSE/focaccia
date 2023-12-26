"""
This mechanism exists to retrieve per-instruction program snapshots from QEMU,
specifically including memory dumps. This is surprisingly nontrivial (we don't
have a log option like `-d memory`), and the mechanism we have implemented to
achieve this is accordingly complicated.

In short: We use QEMU's feature to interact with the emulation via a GDB server
interface together with parsing QEMU's logs to record register and memory state
at single-instruction intervals.

We need QEMU's log in addition to the GDB server because QEMU's GDB server does
not support querying memory mapping information. We need this information to
know from where we need to read memory, so we parse memory mappings from the
log (option `-d page`).

We need two scripts (this one and the primary `qemu_tool.py`) because we can't
pass arguments to scripts executed via `gdb -x <script>`.

This script (`invoke_qemu_tool.py`) is the one the user interfaces with. It
eventually calls `execv` to spawn a GDB process that calls the main
`qemu_tool.py` script; `python invoke_qemu_tool.py` essentially behaves as if
something like `gdb --batch -x qemu_tool.py` were executed instead. Before it
starts GDB, though, it parses command line arguments and applies some weird but
necessary logic to pass them to `qemu_tool.py`.

The main script `qemu_tool.py`, which runs inside of GDB, finally forks a QEMU
instance that provides a GDB server and writes its logs to a file. It then
connects GDB to that server and incrementally reads the QEMU logs while
stepping through the program. Doing that, it generates program snapshots at
each instruction.
"""

import os
import sys

from qemu_tool import make_argparser

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

    os.execv(args.gdb, [
        args.gdb,
        '-nx',  # Don't parse any .gdbinits
        '--batch-silent' if args.quiet else '--batch',
        '-ex', f'py import sys',
        '-ex', f'py sys.argv = {argv_str}',
        '-x', qemu_tool_path
    ])
