#! /bin/python3
import re
import sys
import shutil
import argparse
from typing import List, Callable
from functools import partial as bind

from utils import check_version
from utils import print_separator

from run import Runner

progressive = False

class ContextBlock:
    regnames = ['PC',
                'RAX',
                'RBX',
                'RCX',
                'RDX',
                'RSI',
                'RDI',
                'RBP',
                'RSP',
                'R8',
                'R9',
                'R10',
                'R11',
                'R12',
                'R13',
                'R14',
                'R15',
                'flag ZF',
                'flag CF',
                'flag OF',
                'flag SF',
                'flag PF',
                'flag DF']

    def __init__(self):
        dict_type = dict[str, int|None]  # A register may not have a value
        self.regs = dict_type({reg: None for reg in ContextBlock.regnames})
        self.has_backwards = False
        self.matched = False

    def set_backwards(self):
        self.has_backwards = True

    def set(self, reg: str, value: int):
        """Assign a value to a register.

        :raises RuntimeError: if the register already has a value.
        """
        if self.regs[reg] != None:
            raise RuntimeError("Reassigning register")
        self.regs[reg] = value

    def __repr__(self):
        return self.regs.__repr__()

class Constructor:
    """Builds a list of context blocks."""
    def __init__(self, structure: dict[str, tuple[str, Callable[[str], int]]]):
        self.cblocks = list[ContextBlock]()
        self.labels = structure
        self.regex = re.compile("|".join(structure.keys()))

    def match(self, line: str) -> (tuple[str, int] | None):
        """Find a register name and that register's value in a line.

        :return: A register name and a register value.
        """
        match = self.regex.match(line)
        if match:
            label = match.group(0)
            register, get_reg_value = self.labels[label]
            return register, get_reg_value(line)

        return None

    def add_backwards(self):
        self.cblocks[-1].set_backwards()

    def add(self, reg: str, value: int):
        if reg == 'PC':
            self.cblocks.append(ContextBlock())
        self.cblocks[-1].set(reg, value)

def parse(lines: list[str], labels: dict):
    """Parse a list of lines into a list of cblocks."""
    ctor = Constructor(labels)
    for line in lines:
        if 'Backwards' in line:
            ctor.add_backwards()
            continue

        match = ctor.match(line)
        if match:
            key, value = match
            ctor.add(key, value)

    return ctor.cblocks

def get_labels():
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
              'flag ZF': ('flag ZF', split_second),
              'flag CF': ('flag CF', split_second),
              'flag OF': ('flag OF', split_second),
              'flag SF': ('flag SF', split_second),
              'flag PF': ('flag PF', split_second),
              'flag DF': ('flag DF', split_second)}
    return labels

def calc_transformation(previous: ContextBlock, current: ContextBlock):
    """Calculate the difference between two context blocks.

    :return: A context block that contains in its registers the difference
             between the corresponding input blocks' register values.
    """
    transformation = ContextBlock()
    for reg in ContextBlock.regnames:
        prev_val, cur_val = previous.regs[reg], current.regs[reg]
        if prev_val is not None and cur_val is not None:
            transformation.regs[reg] = cur_val - prev_val

    return transformation

def equivalent(val1, val2, transformation, previous_translation):
    if val1 == val2:
        return True

    # TODO: maybe incorrect
    return val1 - previous_translation == transformation

def verify(translation: ContextBlock, reference: ContextBlock,
           transformation: ContextBlock, previous_translation: ContextBlock):
    if translation.regs["PC"] != reference.regs["PC"]:
        return 1

    print_separator()
    print(f'For PC={hex(translation.regs["PC"])}')
    print_separator()
    for reg in ContextBlock.regnames:
        if translation.regs[reg] is None:
            print(f'Element not available in translation: {reg}')
        elif reference.regs[reg] is None:
            print(f'Element not available in reference: {reg}')
        elif not equivalent(translation.regs[reg], reference.regs[reg],
                            transformation.regs[reg],
                            previous_translation.regs[reg]):
            txl = hex(translation.regs[reg])
            ref = hex(reference.regs[reg])
            print(f'Difference for {reg}: {txl} != {ref}')

    return 0

def compare(txl: List[ContextBlock], native: List[ContextBlock], stats: bool = False):
    if len(txl) != len(native):
        print(f'Different number of blocks discovered translation: {len(txl)} vs. '
              f'reference: {len(native)}', file=sys.stdout)

    previous_reference = native[0]
    previous_translation = txl[0]

    unmatched_pcs = {}
    pc_to_skip = ""
    if progressive:
        i = 0
        for translation in txl:
            previous = i

            while i < len(native):
                reference = native[i]
                transformation = calc_transformation(previous_reference, reference)
                if verify(translation, reference, transformation, previous_translation) == 0:
                    reference.matched = True
                    break

                i += 1

            matched = True

            # Didn't find anything
            if i == len(native):
                matched = False
                # TODO: add verbose output
                print_separator(stream=sys.stdout)
                print(f'No match for PC {hex(translation.regs["PC"])}', file=sys.stdout)
                if translation.regs['PC'] not in unmatched_pcs:
                    unmatched_pcs[translation.regs['PC']] = 0
                unmatched_pcs[translation.regs['PC']] += 1

                i = previous

            # Necessary since we may have run out of native BBs to check and
            # previous becomes len(native)
            #
            # We continue checking to report unmatched translation PCs
            if i < len(native):
                previous_reference = native[i]

            previous_translation = translation

            # Skip next reference when there is a backwards branch
            # NOTE: if a reference was skipped, don't skip it again
            #       necessary for loops which may have multiple backwards
            #       branches
            if translation.has_backwards and translation.regs['PC'] != pc_to_skip:
                pc_to_skip = translation.regs['PC']
                i += 1

            if matched:
                i += 1
    else:
        for translation, reference in zip(txl, native):
            transformation = calc_transformation(previous_reference, reference)
            if verify(translation, reference, transformation, previous_translation) == 1:
                # TODO: add verbose output
                print_separator(stream=sys.stdout)
                print(f'No match for PC {hex(translation.regs["PC"])}', file=sys.stdout)
                if translation.regs['PC'] not in unmatched_pcs:
                    unmatched_pcs[translation.regs['PC']] = 0
                unmatched_pcs[translation.regs['PC']] += 1
            else:
                reference.matched = True

            if translation.has_backwards:
                next(native)

            previous_reference = reference
            previous_translation = translation

    if stats:
        print_separator()
        print('Statistics:')
        print_separator()

        for pc in unmatched_pcs:
            print(f'PC {hex(pc)} unmatched {unmatched_pcs[pc]} times')

        # NOTE: currently doesn't handle mismatched due backward branches
        current = ""
        unmatched_count = 0
        for ref in native:
            ref_pc = ref.regs['PC']
            if ref_pc != current:
                if unmatched_count:
                    print(f'Reference PC {hex(current)} unmatched {unmatched_count} times')
                current = ref_pc

            if ref.matched == False:
                unmatched_count += 1
    return 0

def read_logs(txl_path, native_path, program):
    txl = []
    with open(txl_path, "r") as txl_file:
        txl = txl_file.readlines()

    native = []
    if program is not None:
        runner = Runner(txl, program)
        native = runner.run()
    else:
        with open(native_path, "r") as native_file:
            native = native_file.readlines()

    return txl, native

def parse_arguments():
    parser = argparse.ArgumentParser(description='Comparator for emulator logs to reference')
    parser.add_argument('-p', '--program',
                        type=str,
                        help='Path to oracle program')
    parser.add_argument('-r', '--ref',
                        type=str,
                        required=True,
                        help='Path to the reference log (gathered with run.sh)')
    parser.add_argument('-t', '--txl',
                        type=str,
                        required=True,
                        help='Path to the translation log (gathered via Arancini)')
    parser.add_argument('-s', '--stats',
                        action='store_true',
                        default=False,
                        help='Run statistics on comparisons')
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        default=True,
                        help='Path to oracle program')
    parser.add_argument('--progressive',
                        action='store_true',
                        default=False,
                        help='Try to match exhaustively before declaring \
                        mismatch')
    args = parser.parse_args()
    return args

if __name__ == "__main__":
    check_version('3.7')

    args = parse_arguments()

    txl_path = args.txl
    native_path = args.ref
    program = args.program

    stats = args.stats
    verbose = args.verbose
    progressive = args.progressive

    if verbose:
        print("Enabling verbose program output")
        print(f"Verbose: {verbose}")
        print(f"Statistics: {stats}")
        print(f"Progressive: {progressive}")

    if program is None and native_path is None:
        raise ValueError('Either program or path to native file must be'
                         'provided')

    txl, native = read_logs(txl_path, native_path, program)

    if program != None and native_path != None:
        with open(native_path, 'w') as w:
            w.write(''.join(native))

    txl = parse(txl, get_labels())
    native = parse(native, get_labels())
    compare(txl, native, stats)
