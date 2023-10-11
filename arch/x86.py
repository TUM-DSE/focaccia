"""Architexture-specific configuration."""

from .arch import Arch

# Names of registers in the architexture
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
            'RFLAGS',
            'flag ZF',
            'flag CF',
            'flag OF',
            'flag SF',
            'flag PF',
            'flag DF']

class ArchX86(Arch):
    def __init__(self):
        super().__init__(regnames)
