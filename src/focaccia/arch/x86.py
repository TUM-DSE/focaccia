"""Architecture-specific configuration."""

from .arch import Arch, RegisterDescription as _Reg

archname = 'x86_64'

registers = [
    # General-purpose registers
    _Reg(('RIP', 0, 64), ('EIP', 0, 32), ('IP', 0, 16)),
    _Reg(('RAX', 0, 64), ('EAX', 0, 32), ('AX', 0, 16), ('AL', 0, 8), ('AH', 8, 16)),
    _Reg(('RBX', 0, 64), ('EBX', 0, 32), ('BX', 0, 16), ('BL', 0, 8), ('BH', 8, 16)),
    _Reg(('RCX', 0, 64), ('ECX', 0, 32), ('CX', 0, 16), ('CL', 0, 8), ('CH', 8, 16)),
    _Reg(('RDX', 0, 64), ('EDX', 0, 32), ('DX', 0, 16), ('DL', 0, 8), ('DH', 8, 16)),
    _Reg(('RSI', 0, 64), ('ESI', 0, 32), ('SI', 0, 16), ('SIL', 0, 8)),
    _Reg(('RDI', 0, 64), ('EDI', 0, 32), ('DI', 0, 16), ('DIL', 0, 8)),
    _Reg(('RBP', 0, 64), ('EBP', 0, 32), ('BP', 0, 16), ('BPL', 0, 8)),
    _Reg(('RSP', 0, 64), ('ESP', 0, 32), ('SP', 0, 16), ('SPL', 0, 8)),
    _Reg(('R8',  0, 64), ('R8D',  0, 32), ('R8W',  0, 16), ('R8B',  0, 8)),
    _Reg(('R9',  0, 64), ('R9D',  0, 32), ('R9W',  0, 16), ('R9B',  0, 8)),
    _Reg(('R10', 0, 64), ('R10D', 0, 32), ('R10W', 0, 16), ('R10B', 0, 8)),
    _Reg(('R11', 0, 64), ('R11D', 0, 32), ('R11W', 0, 16), ('R11B', 0, 8)),
    _Reg(('R12', 0, 64), ('R12D', 0, 32), ('R12W', 0, 16), ('R12B', 0, 8)),
    _Reg(('R13', 0, 64), ('R13D', 0, 32), ('R13W', 0, 16), ('R13B', 0, 8)),
    _Reg(('R14', 0, 64), ('R14D', 0, 32), ('R14W', 0, 16), ('R14B', 0, 8)),
    _Reg(('R15', 0, 64), ('R15D', 0, 32), ('R15W', 0, 16), ('R15B', 0, 8)),

    # RFLAGS
    _Reg(('RFLAGS', 0, 64), ('EFLAGS', 0, 32), ('FLAGS', 0, 16),
         ('CF',   0, 1),
         ('PF',   2, 3),
         ('AF',   4, 5),
         ('ZF',   6, 7),
         ('SF',   7, 8),
         ('TF',   8, 9),
         ('IF',   9, 10),
         ('DF',   10, 11),
         ('OF',   11, 12),
         ('IOPL', 12, 14),
         ('NT',   14, 15),
         ('MD',   15, 16),

         ('RF',   16, 17),
         ('VM',   17, 18),
         ('AC',   18, 19),
         ('VIF',  19, 20),
         ('VIP',  20, 21),
         ('ID',   21, 22),
         ('AI',   31, 32),
     ),

    # Segment registers
    _Reg(('CS', 0, 16)),
    _Reg(('DS', 0, 16)),
    _Reg(('SS', 0, 16)),
    _Reg(('ES', 0, 16)),
    _Reg(('FS', 0, 16)),
    _Reg(('GS', 0, 16)),
    _Reg(('FS_BASE', 0, 64)),
    _Reg(('GS_BASE', 0, 64)),

    # x87 floating-point registers
    _Reg(('ST0', 0, 80)),
    _Reg(('ST1', 0, 80)),
    _Reg(('ST2', 0, 80)),
    _Reg(('ST3', 0, 80)),
    _Reg(('ST4', 0, 80)),
    _Reg(('ST5', 0, 80)),
    _Reg(('ST6', 0, 80)),
    _Reg(('ST7', 0, 80)),

    # Vector registers
    _Reg(('ZMM0',  0, 512), ('YMM0',  0, 256), ('XMM0',  0, 128), ('MM0', 0, 64)),
    _Reg(('ZMM1',  0, 512), ('YMM1',  0, 256), ('XMM1',  0, 128), ('MM1', 0, 64)),
    _Reg(('ZMM2',  0, 512), ('YMM2',  0, 256), ('XMM2',  0, 128), ('MM2', 0, 64)),
    _Reg(('ZMM3',  0, 512), ('YMM3',  0, 256), ('XMM3',  0, 128), ('MM3', 0, 64)),
    _Reg(('ZMM4',  0, 512), ('YMM4',  0, 256), ('XMM4',  0, 128), ('MM4', 0, 64)),
    _Reg(('ZMM5',  0, 512), ('YMM5',  0, 256), ('XMM5',  0, 128), ('MM5', 0, 64)),
    _Reg(('ZMM6',  0, 512), ('YMM6',  0, 256), ('XMM6',  0, 128), ('MM6', 0, 64)),
    _Reg(('ZMM7',  0, 512), ('YMM7',  0, 256), ('XMM7',  0, 128), ('MM7', 0, 64)),
    _Reg(('ZMM8',  0, 512), ('YMM8',  0, 256), ('XMM8',  0, 128)),
    _Reg(('ZMM9',  0, 512), ('YMM9',  0, 256), ('XMM9',  0, 128)),
    _Reg(('ZMM10', 0, 512), ('YMM10', 0, 256), ('XMM10', 0, 128)),
    _Reg(('ZMM11', 0, 512), ('YMM11', 0, 256), ('XMM11', 0, 128)),
    _Reg(('ZMM12', 0, 512), ('YMM12', 0, 256), ('XMM12', 0, 128)),
    _Reg(('ZMM13', 0, 512), ('YMM13', 0, 256), ('XMM13', 0, 128)),
    _Reg(('ZMM14', 0, 512), ('YMM14', 0, 256), ('XMM14', 0, 128)),
    _Reg(('ZMM15', 0, 512), ('YMM15', 0, 256), ('XMM15', 0, 128)),

    _Reg(('ZMM16', 0, 512), ('YMM16', 0, 256), ('XMM16', 0, 128)),
    _Reg(('ZMM17', 0, 512), ('YMM17', 0, 256), ('XMM17', 0, 128)),
    _Reg(('ZMM18', 0, 512), ('YMM18', 0, 256), ('XMM18', 0, 128)),
    _Reg(('ZMM19', 0, 512), ('YMM19', 0, 256), ('XMM19', 0, 128)),
    _Reg(('ZMM20', 0, 512), ('YMM20', 0, 256), ('XMM20', 0, 128)),
    _Reg(('ZMM21', 0, 512), ('YMM21', 0, 256), ('XMM21', 0, 128)),
    _Reg(('ZMM22', 0, 512), ('YMM22', 0, 256), ('XMM22', 0, 128)),
    _Reg(('ZMM23', 0, 512), ('YMM23', 0, 256), ('XMM23', 0, 128)),
    _Reg(('ZMM24', 0, 512), ('YMM24', 0, 256), ('XMM24', 0, 128)),
    _Reg(('ZMM25', 0, 512), ('YMM25', 0, 256), ('XMM25', 0, 128)),
    _Reg(('ZMM26', 0, 512), ('YMM26', 0, 256), ('XMM26', 0, 128)),
    _Reg(('ZMM27', 0, 512), ('YMM27', 0, 256), ('XMM27', 0, 128)),
    _Reg(('ZMM28', 0, 512), ('YMM28', 0, 256), ('XMM28', 0, 128)),
    _Reg(('ZMM29', 0, 512), ('YMM29', 0, 256), ('XMM29', 0, 128)),
    _Reg(('ZMM30', 0, 512), ('YMM30', 0, 256), ('XMM30', 0, 128)),
    _Reg(('ZMM31', 0, 512), ('YMM31', 0, 256), ('XMM31', 0, 128)),
]

# Names of registers in the architecture
regnames = [desc.base.base_reg for desc in registers]

# A dictionary mapping aliases to standard register names.
regname_aliases = {
    'PC': 'RIP',
    'NF': 'SF',
    'I_F': 'IF',
    'IOPL_F': 'IOPL',
    'I_D': 'ID',
}

rflag_names = [
    'CF', 'PF', 'AF', 'ZF', 'SF', 'TF', 'IF', 'DF', 'OF', 'IOPL', 'NT',
    'RF', 'VM', 'AC', 'VIF', 'VIP', 'ID',
]

def decompose_rflags(rflags: int) -> dict[str, int]:
    """Decompose RFLAGS fields using the architecture register accessors."""
    return ArchX86().decompose_register('RFLAGS', rflags, rflag_names)

def compose_rflags(rflags: dict[str, int]) -> int:
    """Compose RFLAGS fields using their declared bit widths."""
    fields = {name: rflags.get(name, 0) for name in rflag_names}
    return ArchX86().compose_register('RFLAGS', fields)

class ArchX86(Arch):
    def __init__(self):
        super().__init__(archname, registers, 64)
        self.ignored_regs = [
            'EFLAGS', 'CF', 'PF', 'AF', 'ZF', 'SF', 'TF', 'IF', 'DF', 'OF',
            'CS', 'DS', 'SS', 'ES', 'FS', 'GS',
        ]

    def to_regname(self, name: str) -> str | None:
        """The X86 override of the standard register name lookup.

        Applies certain register name aliases.
        """
        reg = super().to_regname(name)
        if reg is not None:
            return reg

        # Apply custom register alias rules
        return regname_aliases.get(name.upper(), None)

    def register_write_zero_extends(self, regname: str) -> bool:
        accessor = self.get_reg_accessor(regname)
        if accessor is None or accessor.start != 0 or accessor.num_bits != 32:
            return False
        return accessor.base_reg in {
            'RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RBP', 'RSP',
            'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15',
        }

    def is_instr_uarch_dep(self, instr: str) -> bool:
        if "XGETBV" in instr.upper():
            return True
        return False

    def is_instr_syscall(self, instr: str) -> bool:
        if instr.upper().startswith("SYSCALL"):
            return True
        if instr.upper().startswith("INT"):
            return True
        return False

