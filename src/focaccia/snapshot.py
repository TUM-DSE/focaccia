from .arch.arch import Arch

class RegisterAccessError(Exception):
    """Raised when a register access fails."""
    def __init__(self, regname: str, msg: str):
        super().__init__(msg)
        self.regname = regname

class MemoryAccessError(Exception):
    """Raised when a memory access fails."""
    def __init__(self, addr: int, size: int, msg: str):
        super().__init__(msg)
        self.mem_addr = addr
        self.mem_size = size

class SparseMemory:
    """Sparse memory.

    Note that out-of-bound reads are possible when performed on unwritten
    sections of existing pages and that there is no safeguard check for them.
    """
    def __init__(self, page_size=256):
        self.page_size = page_size
        self._pages: dict[int, bytes] = {}

    def _to_page_addr_and_offset(self, addr: int) -> tuple[int, int]:
        off = addr % self.page_size
        return addr - off, off

    def drop_all(self):
        self._pages.clear()

    def test(self, addr: int) -> bool:
        page_addr, off = self._to_page_addr_and_offset(addr)
        return page_addr in self._pages

    def read(self, addr: int, size: int) -> bytes:
        """Read a number of bytes from memory.
        :param addr: The offset from where to read.
        :param size: The number of bytes to read, starting at at `addr`.

        :return: `size` bytes of data.
        :raise MemoryAccessError: If `[addr, addr + size)` is not entirely
                                  contained in the set of stored bytes.
        :raise ValueError: If `size < 0`.
        """
        if size < 0:
            raise ValueError(f'A negative size is not allowed!')

        res = bytes()
        while size > 0:
            page_addr, off = self._to_page_addr_and_offset(addr)
            if page_addr not in self._pages:
                raise MemoryAccessError(addr, size,
                                        f'Address {hex(addr)} is not contained'
                                        f' in the sparse memory.')
            data = self._pages[page_addr]
            assert(len(data) == self.page_size)
            read_size = min(size, self.page_size - off)
            res += data[off:off+read_size]

            size -= read_size
            addr += read_size
        return res

    def write(self, addr: int, data: bytes):
        """Store bytes in the memory.
        :param addr: The address at which to store the data.
        :param data: The data to store at `addr`.
        """
        offset = 0  # Current offset into `data`
        while offset < len(data):
            page_addr, off = self._to_page_addr_and_offset(addr)
            if page_addr not in self._pages:
                self._pages[page_addr] = bytes(self.page_size)
            page = self._pages[page_addr]
            assert(len(page) == self.page_size)

            write_size = min(len(data) - offset, self.page_size - off)
            new_page = page[:off] + data[offset:offset + write_size] + page[off+write_size:]
            assert(len(new_page) == self.page_size)
            self._pages[page_addr] = new_page

            offset += write_size
            addr += write_size

        assert(len(data) == offset)  # Exactly all data was written

class ReadableProgramState:
    """Interface for read-only program states."""
    def __init__(self, arch: Arch):
        self.arch = arch

    def read_register(self, reg: str) -> int:
        """Read a register's value.

        :raise RegisterAccessError: If `reg` is not a register name, or if the
                                    register has no value.
        """
        raise NotImplementedError('ReadableProgramState.read_register is abstract.')

    def read_memory(self, addr: int, size: int) -> bytes:
        """Read a number of bytes from memory.

        :param addr: The address from which to read data.
        :param data: Number of bytes to read, starting at `addr`. Must be
                     at least zero.

        :raise MemoryAccessError: If `[addr, addr + size)` is not entirely
                                  contained in the set of stored bytes.
        :raise ValueError: If `size < 0`.
        """
        raise NotImplementedError('ReadableProgramState.read_memory is abstract.')

class ProgramState(ReadableProgramState):
    """A snapshot of the program's state."""
    def __init__(self, arch: Arch):
        super().__init__(arch=arch)

        self.regs: dict[str, int | None] = {reg: None for reg in arch.regnames}
        self.mem = SparseMemory()

    def test_register(self, reg: str) -> bool:
        """Test whether a register has a value assigned.

        :raise RegisterAccessError: If `reg` is not a register name.
        """
        acc = self.arch.get_reg_accessor(reg)
        if acc is None:
            raise RegisterAccessError(reg, f'Not a register name: {reg}')

        assert(acc.base_reg in self.regs)
        return self.regs[acc.base_reg] is not None

    def read_register(self, reg: str) -> int:
        """Read a register's value.

        :raise RegisterAccessError: If `reg` is not a register name, or if the
                                    register has no value.
        """
        acc = self.arch.get_reg_accessor(reg)
        if acc is None:
            raise RegisterAccessError(reg, f'Not a register name: {reg}')

        assert(acc.base_reg in self.regs)
        regval = self.regs[acc.base_reg]
        if regval is None:
            raise RegisterAccessError(
                acc.base_reg,
                f'[In ProgramState.read_register]: Unable to read value of'
                f' register {reg} (a.k.a. {acc}): The register is not set.'
                f' Full state: {self}')

        return (regval & acc.mask) >> acc.start

    def set_register(self, reg: str, value: int):
        """Assign a value to a register.

        :raise RegisterAccessError: If `reg` is not a register name.
        """
        acc = self.arch.get_reg_accessor(reg)
        if acc is None:
            raise RegisterAccessError(reg, f'Not a register name: {reg}')

        assert(acc.base_reg in self.regs)
        base_reg_size = self.arch.get_reg_accessor(acc.base_reg).num_bits

        val = self.regs[acc.base_reg]
        if val is None:
            val = 0
        val &= (~acc.mask & ((1 << base_reg_size) - 1))    # Clear bits in range
        val |= (value << acc.start) & acc.mask         # Set bits in range

        self.regs[acc.base_reg] = val

    def read_memory(self, addr: int, size: int) -> bytes:
        """Read a number of bytes from memory.

        :param addr: The address from which to read data.
        :param data: Number of bytes to read, starting at `addr`. Must be
                     at least zero.

        :raise MemoryAccessError: If `[addr, addr + size)` is not entirely
                                  contained in the set of stored bytes.
        :raise ValueError: If `size < 0`.
        """
        return self.mem.read(addr, size)

    def write_memory(self, addr: int, data: bytes):
        """Write a number of bytes to memory.

        :param addr: The address at which to store the data.
        :param data: The data to store at `addr`.
        """
        self.mem.write(addr, data)

    def __repr__(self):
        regs = {r: hex(v) for r, v in self.regs.items() if v is not None}
        return f'Snapshot ({self.arch.archname}): {regs}'
