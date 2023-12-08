"""Tools for working with arancini's output."""

import re
from functools import partial as bind

from snapshot import ProgramState
from arch.arch import Arch

def parse_break_addresses(lines: list[str]) -> set[int]:
    """Parse all breakpoint addresses from an arancini log."""
    addresses = set()
    for l in lines:
        if l.startswith('INVOKE'):
            addr = int(l.split('=')[1].strip(), base=16)
            addresses.add(addr)

    return addresses

def parse(lines: list[str], arch: Arch) -> list[ProgramState]:
    """Parse an arancini log into a list of snapshots.

    :return: A list of program snapshots.
    """

    labels = get_labels()

    # The regex decides for a line whether it contains a register
    # based on a match with that register's label.
    regex = re.compile("|".join(labels.keys()))

    def try_parse_line(line: str) -> tuple[str, int] | None:
        """Try to parse a register name and that register's value from a line.

        :return: A register name and a register value if the line contains
                 that information. None if parsing fails.
        """
        match = regex.match(line)
        if match:
            label = match.group(0)
            register, get_reg_value = labels[label]
            return register, get_reg_value(line)
        return None

    # Parse a list of program snapshots
    snapshots = []
    for line in lines:
        if 'Backwards' in line and len(snapshots) > 0:
            # snapshots[-1].set_backwards()
            continue

        match = try_parse_line(line)
        if match:
            reg, value = match
            if reg == 'PC':
                snapshots.append(ProgramState(arch))
            snapshots[-1].set(reg, value)

    return snapshots

def get_labels():
    """Construct a helper structure for the arancini log parser."""
    split_value = lambda x,i: int(x.split()[i], 16)

    split_first = bind(split_value, i=1)
    split_second = bind(split_value, i=2)

    split_equal = lambda x,i: int(x.split('=')[i], 16)

    # A mapping from regex patterns to the register name and a
    # function that extracts that register's value from the line
    labels = {'INVOKE':  ('PC',      bind(split_equal, i=1)),
              'RAX':     ('RAX',     split_first),
              'RBX':     ('RBX',     split_first),
              'RCX':     ('RCX',     split_first),
              'RDX':     ('RDX',     split_first),
              'RSI':     ('RSI',     split_first),
              'RDI':     ('RDI',     split_first),
              'RBP':     ('RBP',     split_first),
              'RSP':     ('RSP',     split_first),
              'R8':      ('R8',      split_first),
              'R9':      ('R9',      split_first),
              'R10':     ('R10',     split_first),
              'R11':     ('R11',     split_first),
              'R12':     ('R12',     split_first),
              'R13':     ('R13',     split_first),
              'R14':     ('R14',     split_first),
              'R15':     ('R15',     split_first),
              'flag ZF': ('ZF', split_second),
              'flag CF': ('CF', split_second),
              'flag OF': ('OF', split_second),
              'flag SF': ('SF', split_second),
              'flag PF': ('PF', split_second),
              'flag DF': ('DF', split_second)}
    return labels
