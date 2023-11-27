from arch.arch import Arch

class ProgramState:
    """A snapshot of the program's state."""
    def __init__(self, arch: Arch):
        self.arch = arch

        dict_t = dict[str, int | None]
        self.regs: dict_t = { reg: None for reg in arch.regnames }

    def read(self, reg: str) -> int:
        """Read a register's value.

        :raise KeyError:   If `reg` is not a register name.
        :raise ValueError: If the register has no value.
        """
        regname = self.arch.to_regname(reg)
        if regname is None:
            raise KeyError(f'Not a register name: {reg}')

        assert(regname in self.regs)
        regval = self.regs[regname]
        if regval is None:
            raise ValueError(f'Unable to read value of register {reg} (aka.'
                             f' {regname}): The register contains no value.')
        return regval

    def set(self, reg: str, value: int):
        """Assign a value to a register.

        :raise KeyError:   If `reg` is not a register name.
        """
        regname = self.arch.to_regname(reg)
        if regname is None:
            raise KeyError(f'Not a register name: {regname}')

        self.regs[regname] = value

    def __repr__(self):
        return repr(self.regs)

class SnapshotSymbolResolver(SymbolResolver):
    def __init__(self, snapshot: ProgramState):
        self._state = snapshot

    def resolve(self, symbol: str):
        if symbol not in self._state.arch.regnames:
            raise SymbolResolveError(symbol, 'Symbol is not a register name.')
        return self._state.read(symbol)
