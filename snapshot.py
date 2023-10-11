from arch.arch import Arch

class ProgramState():
    """A snapshot of the program's state."""
    def __init__(self, arch: Arch):
        self.arch = arch

        dict_t = dict[str, int]
        self.regs = dict_t({ reg: None for reg in arch.regnames })
        self.has_backwards = False
        self.matched = False

    def set_backwards(self):
        self.has_backwards = True

    def set(self, reg: str, value: int):
        """Assign a value to a register.

        :raises RuntimeError: if the register already has a value.
        """
        assert(reg in self.arch.regnames)

        if self.regs[reg] != None:
            raise RuntimeError("Reassigning register")
        self.regs[reg] = value

    def as_repr(self, reg: str):
        """Get a representational string of a register's value."""
        assert(reg in self.arch.regnames)

        value = self.regs[reg]
        if value is not None:
            return hex(value)
        else:
            return "<none>"

    def __repr__(self):
        return self.regs.__repr__()
