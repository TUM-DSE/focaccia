from typing import Literal
from collections.abc import Callable

class RegisterAccessor:
    def __init__(self, regname: str, start_bit: int, end_bit: int):
        """An accessor that describes a range of bits.

        Builds a bit range [start_bit, end_bit), meaning `end_bit` is excluded
        from the range.

        Example: An object `RegisterAccessor(0, 1)` accesses exactly the first
        bit of a value. `RegisterAccessor(0, 0)` is invalid as it references
        a range of zero bits.

        :param start_bit: First bit included in the range. This is the least
                          significant bit in the range.
        :param end_bit: First bit *not* included in the range. This is the most
                        significant bit of the range.
        """
        assert(start_bit < end_bit)
        self.base_reg = regname
        self.start = start_bit
        self.end = end_bit

        self.num_bits = end_bit - start_bit
        self.mask = 0
        for i in range(start_bit, end_bit):
            self.mask |= 1 << i

    def __repr__(self) -> str:
        return f'{self.base_reg}[{self.start}:{self.end - 1}]'

class RegisterDescription:
    def __init__(self, base: tuple[str, int, int], *subsets: tuple[str, int, int]):
        self.base = RegisterAccessor(*base)
        self.subsets = [(name, RegisterAccessor(base[0], s, e)) for name, s, e in subsets]

class Arch():
    Endianness = Literal['little', 'big']

    def __init__(self,
                 archname: str,
                 registers: list[RegisterDescription],
                 ptr_size: int,
                 endianness: Endianness = 'little'):
        self.archname = archname
        self.ptr_size = ptr_size
        self.endianness: Literal['little', 'big'] = endianness
        self.ignored_regs: list[str] = []

        self._accessors = {}
        for desc in registers:
            self._accessors[desc.base.base_reg.upper()] = desc.base
            self._accessors |= {name: acc for name, acc in desc.subsets}

        self.regnames = set(desc.base.base_reg.upper() for desc in registers)
        """Names of the architecture's base registers."""

        self.all_regnames = set(self._accessors.keys())
        """Names of the architecture's registers, including register aliases."""

    def to_regname(self, name: str) -> str | None:
        """Transform a string into a standard register name.

        :param name: The possibly non-standard name to look up.
        :return: The 'corrected' register name, or None if `name` cannot be
                 transformed into a register name.
        """
        name = name.upper()
        if name in self._accessors:
            return name
        return None

    def get_reg_accessor(self, regname: str) -> RegisterAccessor | None:
        """Get an accessor for a register name, which may be an alias.

        It is used internally by ProgramState to access aliased registers.
        """
        _regname = self.to_regname(regname)
        return self._accessors.get(_regname, None)

    def get_reg_reader(self, regname: str) -> Callable[[], int] | None:
        """Read a register directly from Focaccia

        :param name: The register to read.
        :return: The register value.

        It is used to enable reading registers that would otherwise not be accessible by other
        means. Only meant to replace reading from the program directly for system-level constants.
        """
        return None

    def __eq__(self, other):
        return self.archname == other.archname

    def __repr__(self) -> str:
        return self.archname
