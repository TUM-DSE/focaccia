from typing import Iterable

class Arch():
    def __init__(self,
                 archname: str,
                 regnames: Iterable[str],
                 ptr_size: int):
        self.archname = archname
        self.regnames = set(name.upper() for name in regnames)
        self.ptr_size = ptr_size

    def to_regname(self, name: str) -> str | None:
        """Transform a string into a standard register name.

        Override to implement things like name aliases etc.

        :param name: The possibly non-standard name to look up.
        :return: The 'corrected' register name, or None if `name` cannot be
                 transformed into a register name.
        """
        name = name.upper()
        if name in self.regnames:
            return name
        return None

    def __eq__(self, other):
        return self.archname == other.archname

    def __repr__(self) -> str:
        return self.archname
