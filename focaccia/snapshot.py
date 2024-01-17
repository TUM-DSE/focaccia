from .arch.arch import Arch

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
    def __init__(self, page_size=4096):
        self.page_size = page_size
        self._pages: dict[int, bytes] = {}

    def _to_page_addr_and_offset(self, addr: int) -> tuple[int, int]:
        off = addr % self.page_size
        return addr - off, off

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

class ProgramState:
    """A snapshot of the program's state."""
    def __init__(self, arch: Arch):
        self.arch = arch

        dict_t = dict[str, int | None]
        self.regs: dict_t = { reg: None for reg in arch.regnames }
        self.mem = SparseMemory()

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

        :raise KeyError: If `reg` is not a register name.
        """
        regname = self.arch.to_regname(reg)
        if regname is None:
            raise KeyError(f'Not a register name: {reg}')

        self.regs[regname] = value

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
        return f'Snapshot ({self.arch.archname}): ' \
               + repr({r: hex(v) for r, v in self.regs.items() if v is not None})
