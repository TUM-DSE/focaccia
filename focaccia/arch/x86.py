"""Architecture-specific configuration."""

from .arch import Arch

archname = 'x86_64'

# Names of registers in the architecture
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

    # x87 float registers
    'ST0', 'ST1', 'ST2', 'ST3', 'ST4', 'ST5', 'ST6', 'ST7',

    # Vector registers
    'YMM0', 'YMM1', 'YMM2', 'YMM3', 'YMM4',
    'YMM5', 'YMM6', 'YMM7', 'YMM8', 'YMM9',
    'YMM10', 'YMM11', 'YMM12', 'YMM13', 'YMM14', 'YMM15',

    # Segment registers
    'CS', 'DS', 'SS', 'ES', 'FS', 'GS',
    'FS_BASE', 'GS_BASE',

    # FLAGS
    'CF', 'PF', 'AF', 'ZF', 'SF', 'TF', 'IF', 'DF', 'OF', 'IOPL', 'NT',

    # EFLAGS
    'RF', 'VM', 'AC', 'VIF', 'VIP', 'ID',
]

# A dictionary mapping aliases to standard register names.
regname_aliases = {
    'PC': 'RIP',
    'NF': 'SF',   # negative flag == sign flag in Miasm?
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
        'CF':     (rflags & 0x0001) != 0,
                          # 0x0002   reserved
        'PF':     (rflags & 0x0004) != 0,
                          # 0x0008   reserved
        'AF':     (rflags & 0x0010) != 0,
                          # 0x0020   reserved
        'ZF':     (rflags & 0x0040) != 0,
        'SF':     (rflags & 0x0080) != 0,
        'TF':     (rflags & 0x0100) != 0,
        'IF':     (rflags & 0x0200) != 0,
        'DF':     (rflags & 0x0400) != 0,
        'OF':     (rflags & 0x0800) != 0,
        'IOPL':   (rflags & 0x3000) != 0,
        'NT':     (rflags & 0x4000) != 0,

        # EFLAGS
        'RF':     (rflags & 0x00010000) != 0,
        'VM':     (rflags & 0x00020000) != 0,
        'AC':     (rflags & 0x00040000) != 0,
        'VIF':    (rflags & 0x00080000) != 0,
        'VIP':    (rflags & 0x00100000) != 0,
        'ID':     (rflags & 0x00200000) != 0,
    }

def compose_rflags(rflags: dict[str, int]) -> int:
    """Compose separate flags into RFLAGS register's value.

    Uses flag name abbreviation conventions from
    `https://en.wikipedia.org/wiki/FLAGS_register`.

    :param rflags: A dictionary mapping Miasm's flag names to their alues.
    :return: The RFLAGS register value.
    """
    return (
        # FLAGS
        (0x0001 if rflags['CF']   else 0) |
                        # 0x0002   reserved
        (0x0004 if rflags['PF']   else 0) |
                        # 0x0008   reserved
        (0x0010 if rflags['AF']   else 0) |
                        # 0x0020   reserved
        (0x0040 if rflags['ZF']   else 0) |
        (0x0080 if rflags['SF']   else 0) |
        (0x0100 if rflags['TF']   else 0) |
        (0x0200 if rflags['IF']   else 0) |
        (0x0400 if rflags['DF']   else 0) |
        (0x0800 if rflags['OF']   else 0) |
        (0x3000 if rflags['IOPL'] else 0) |
        (0x4000 if rflags['NT']   else 0) |

        # EFLAGS
        (0x00010000 if rflags['RF']  else 0) |
        (0x00020000 if rflags['VM']  else 0) |
        (0x00040000 if rflags['AC']  else 0) |
        (0x00080000 if rflags['VIF'] else 0) |
        (0x00100000 if rflags['VIP'] else 0) |
        (0x00200000 if rflags['ID']  else 0)
    )

class ArchX86(Arch):
    def __init__(self):
        super().__init__(archname, regnames)

    def to_regname(self, name: str) -> str | None:
        """The X86 override of the standard register name lookup.

        Applies certain register name aliases.
        """
        reg = super().to_regname(name)
        if reg is not None:
            return reg

        # Apply custom register alias rules
        return regname_aliases.get(name.upper(), None)
