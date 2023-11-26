"""Architexture-specific configuration."""

from .arch import Arch

# Names of registers in the architexture
regnames = [
    'RIP',
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
    # FLAGS
    'CF', 'PF', 'AF', 'ZF', 'SF', 'TF', 'IF', 'DF', 'OF', 'IOPL', 'NT',
    # EFLAGS
    'RF', 'VM', 'AC', 'VIF', 'VIP', 'ID',
]

# A dictionary mapping aliases to standard register names.
regname_aliases = {
    'PC': 'RIP',
}

def decompose_rflags(rflags: int) -> dict[str, int]:
    """Decompose the RFLAGS register's value into its separate flags.

    Uses flag name abbreviation conventions from
    `https://en.wikipedia.org/wiki/FLAGS_register`.

    :param rflags: The RFLAGS register value.
    :return: A dictionary mapping Miasm's flag names to their values.
    """
    return {
        # FLAGS
        'CF':     rflags & 0x0001,
                         # 0x0002   reserved
        'PF':     rflags & 0x0004,
                         # 0x0008   reserved
        'AF':     rflags & 0x0010,
                         # 0x0020   reserved
        'ZF':     rflags & 0x0040,
        'SF':     rflags & 0x0080,
        'TF':     rflags & 0x0100,
        'IF':     rflags & 0x0200,
        'DF':     rflags & 0x0400,
        'OF':     rflags & 0x0800,
        'IOPL':   rflags & 0x3000,
        'NT':     rflags & 0x4000,

        # EFLAGS
        'RF':     rflags & 0x00010000,
        'VM':     rflags & 0x00020000,
        'AC':     rflags & 0x00040000,
        'VIF':    rflags & 0x00080000,
        'VIP':    rflags & 0x00100000,
        'ID':     rflags & 0x00200000,
    }

class ArchX86(Arch):
    def __init__(self):
        super().__init__("X86", regnames)

    def to_regname(self, name: str) -> str | None:
        """The X86 override of the standard register name lookup.

        Applies certain register name aliases.
        """
        reg = super().to_regname(name)
        if reg in regname_aliases:
            return regname_aliases[reg]
        return reg
