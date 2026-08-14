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
    """Sparse byte storage with explicit per-byte validity."""

    def __init__(self, page_size: int = 256):
        if page_size <= 0:
            raise ValueError("Sparse memory page size must be positive.")
        self.page_size = page_size
        self._pages: dict[int, bytearray] = {}
        self._valid_masks: dict[int, int] = {}

    def _to_page_addr_and_offset(self, addr: int) -> tuple[int, int]:
        off = addr % self.page_size
        return addr - off, off

    @staticmethod
    def _range_mask(offset: int, size: int) -> int:
        if size == 0:
            return 0
        return ((1 << size) - 1) << offset

    def drop_all(self) -> None:
        self._pages.clear()
        self._valid_masks.clear()

    def test(self, addr: int, size: int = 1) -> bool:
        """Return whether every byte in ``[addr, addr + size)`` is known."""
        if size < 0:
            raise ValueError("A negative size is not allowed.")
        if size == 0:
            return True

        remaining = size
        while remaining > 0:
            page_addr, offset = self._to_page_addr_and_offset(addr)
            chunk_size = min(remaining, self.page_size - offset)
            required = self._range_mask(offset, chunk_size)
            if self._valid_masks.get(page_addr, 0) & required != required:
                return False
            addr += chunk_size
            remaining -= chunk_size
        return True

    def read(self, addr: int, size: int) -> bytes:
        """Read known bytes from ``[addr, addr + size)``.

        A zero-length read always returns ``b""``. Unknown bytes raise
        ``MemoryAccessError`` rather than being materialized as zero.
        """
        if size < 0:
            raise ValueError("A negative size is not allowed.")
        if size == 0:
            return b""

        result = bytearray()
        remaining = size
        while remaining > 0:
            page_addr, offset = self._to_page_addr_and_offset(addr)
            chunk_size = min(remaining, self.page_size - offset)
            valid_mask = self._valid_masks.get(page_addr, 0)
            required = self._range_mask(offset, chunk_size)
            if valid_mask & required != required:
                for index in range(chunk_size):
                    if valid_mask & (1 << (offset + index)) == 0:
                        missing = addr + index
                        raise MemoryAccessError(
                            missing,
                            1,
                            f"Address {hex(missing)} is unknown in sparse memory.",
                        )
                raise RuntimeError("Sparse memory validity check was inconsistent.")

            page = self._pages[page_addr]
            result.extend(page[offset : offset + chunk_size])
            addr += chunk_size
            remaining -= chunk_size

        return bytes(result)

    def write(self, addr: int, data: bytes) -> None:
        """Store bytes at increasing addresses beginning at ``addr``."""
        offset = 0
        while offset < len(data):
            page_addr, page_offset = self._to_page_addr_and_offset(addr)
            page = self._pages.setdefault(page_addr, bytearray(self.page_size))

            write_size = min(len(data) - offset, self.page_size - page_offset)
            page[page_offset : page_offset + write_size] = data[offset : offset + write_size]
            self._valid_masks[page_addr] = self._valid_masks.get(page_addr, 0) | self._range_mask(
                page_offset, write_size
            )

            offset += write_size
            addr += write_size

    def known_ranges(self) -> list[tuple[int, bytes]]:
        """Return maximal known ranges in increasing address order."""
        ranges: list[tuple[int, bytes]] = []
        current_start: int | None = None
        current_data = bytearray()
        previous_address: int | None = None

        for page_addr in sorted(self._pages):
            page = self._pages[page_addr]
            validity = self._valid_masks.get(page_addr, 0)
            for offset, value in enumerate(page):
                if validity & (1 << offset) == 0:
                    continue

                address = page_addr + offset
                if previous_address is None or address != previous_address + 1:
                    if current_start is not None:
                        ranges.append((current_start, bytes(current_data)))
                    current_start = address
                    current_data = bytearray()
                current_data.append(value)
                previous_address = address

        if current_start is not None:
            ranges.append((current_start, bytes(current_data)))
        return ranges


class ReadableProgramState:
    """Interface for read-only program states."""

    def __init__(self, arch: Arch):
        self.arch = arch
        self.strict = True

    def read_pc(self) -> int:
        """Read the architecture's program counter."""
        return self.read_register("pc")

    def read_register(self, reg: str) -> int:
        raise NotImplementedError("ReadableProgramState.read_register is abstract.")

    def read_memory(self, addr: int, size: int) -> bytes:
        raise NotImplementedError("ReadableProgramState.read_memory is abstract.")


class ProgramState(ReadableProgramState):
    """A concrete program-state observation with explicit validity."""

    def __init__(self, arch: Arch):
        super().__init__(arch=arch)
        self.regs: dict[str, int | None] = {reg: None for reg in arch.regnames}
        self._valid_register_bits: dict[str, int] = {reg: 0 for reg in arch.regnames}
        self.mem = SparseMemory()

    def test_register(self, reg: str) -> bool:
        """Return whether every bit of ``reg`` is known."""
        accessor = self.arch.get_reg_accessor(reg)
        if accessor is None:
            raise RegisterAccessError(reg, f"Not a register name: {reg}")
        if self.arch.is_constant_register(reg):
            return True

        if accessor.base_reg not in self.regs:
            raise RegisterAccessError(reg, f"Register has no mutable storage: {reg}")
        validity = self._valid_register_bits[accessor.base_reg]
        return validity & accessor.mask == accessor.mask

    def read_register(self, reg: str) -> int:
        """Read a register only when all requested bits are known."""
        accessor = self.arch.get_reg_accessor(reg)
        if accessor is None:
            raise RegisterAccessError(reg, f"Not a register name: {reg}")

        if self.arch.is_constant_register(reg):
            value = self.arch.get_constant_register_value(reg)
            if value is None:
                raise RuntimeError(f"Missing value for constant register {reg}.")
            return value

        if accessor.base_reg not in self.regs:
            raise RegisterAccessError(reg, f"Register has no mutable storage: {reg}")
        validity = self._valid_register_bits[accessor.base_reg]
        if validity & accessor.mask != accessor.mask:
            missing = accessor.mask & ~validity
            raise RegisterAccessError(
                accessor.base_reg,
                f"Unable to read {reg} ({accessor}): unknown bit mask {hex(missing)}.",
            )

        value = self.regs[accessor.base_reg]
        if value is None:
            raise RuntimeError(
                f"Register {accessor.base_reg} has valid bits but no stored value."
            )
        return (value & accessor.mask) >> accessor.start

    def write_register(self, reg: str, value: int) -> None:
        """Record observed bits without inferring values for unobserved bits."""
        accessor = self.arch.get_reg_accessor(reg)
        if accessor is None:
            raise RegisterAccessError(reg, f"Not a register name: {reg}")
        if self.arch.is_constant_register(reg):
            return

        if accessor.base_reg not in self.regs:
            raise RegisterAccessError(reg, f"Register has no mutable storage: {reg}")
        base_accessor = self.arch.get_reg_accessor(accessor.base_reg)
        if base_accessor is None:
            raise RuntimeError(f"Missing base accessor for {accessor.base_reg}.")

        stored = self.regs[accessor.base_reg]
        if stored is None:
            stored = 0
        stored &= ~accessor.mask & ((1 << base_accessor.num_bits) - 1)
        stored |= value << accessor.start & accessor.mask

        self.regs[accessor.base_reg] = stored
        self._valid_register_bits[accessor.base_reg] |= accessor.mask

    def write_register_bits(self, reg: str, value: int, valid_mask: int) -> None:
        """Record selected known bits of ``reg`` without inventing the rest."""
        accessor = self.arch.get_reg_accessor(reg)
        if accessor is None:
            raise RegisterAccessError(reg, f"Not a register name: {reg}")
        if value < 0 or value >= 1 << accessor.num_bits:
            raise ValueError(f"Value does not fit in register {reg}.")
        if valid_mask < 0 or valid_mask >= 1 << accessor.num_bits:
            raise ValueError(f"Validity mask does not fit in register {reg}.")
        if self.arch.is_constant_register(reg) or valid_mask == 0:
            return
        if accessor.base_reg not in self.regs:
            raise RegisterAccessError(reg, f"Register has no mutable storage: {reg}")

        shifted_validity = valid_mask << accessor.start & accessor.mask
        shifted_value = value << accessor.start & shifted_validity
        stored = self.regs[accessor.base_reg]
        if stored is None:
            stored = 0
        stored = (stored & ~shifted_validity) | shifted_value
        self.regs[accessor.base_reg] = stored
        self._valid_register_bits[accessor.base_reg] |= shifted_validity

    def write_register_zero_extended(self, reg: str, value: int) -> None:
        """Apply an explicit low-register write with architectural zero extension."""
        accessor = self.arch.get_reg_accessor(reg)
        if accessor is None:
            raise RegisterAccessError(reg, f"Not a register name: {reg}")
        if self.arch.is_constant_register(reg):
            return
        if accessor.start != 0:
            raise ValueError(f"Register {reg} is not a low-bit slice and cannot zero-extend.")

        base_accessor = self.arch.get_reg_accessor(accessor.base_reg)
        if base_accessor is None or accessor.base_reg not in self.regs:
            raise RegisterAccessError(reg, f"Register has no mutable storage: {reg}")

        self.regs[accessor.base_reg] = value & ((1 << accessor.num_bits) - 1)
        self._valid_register_bits[accessor.base_reg] = (1 << base_accessor.num_bits) - 1

    def drop_registers(self) -> None:
        """Mark every mutable register bit unknown."""
        for reg in self.regs:
            self.regs[reg] = None
            self._valid_register_bits[reg] = 0

    def known_register_bits(self) -> dict[str, tuple[int, int]]:
        """Return base-register values paired with their exact validity masks."""
        observations: dict[str, tuple[int, int]] = {}
        for base_reg in sorted(self.regs):
            valid_mask = self._valid_register_bits[base_reg]
            if valid_mask == 0:
                continue
            value = self.regs[base_reg]
            if value is None:
                raise RuntimeError(f"Register {base_reg} has valid bits but no stored value.")
            observations[base_reg] = (value & valid_mask, valid_mask)
        return observations

    def known_register_values(self, *, include_partial: bool = False) -> dict[str, int]:
        """Return known mutable registers without materializing unknown bits.

        Fully known bases are emitted once. When ``include_partial`` is true,
        known aliases of a partially observed base are emitted so persistence
        can retain those observations without inventing the remaining bits.
        """
        values: dict[str, int] = {}
        for base_reg in sorted(self.arch.regnames):
            if self.test_register(base_reg):
                values[base_reg] = self.read_register(base_reg)
                continue
            if not include_partial:
                continue

            for regname in sorted(self.arch.all_regnames):
                accessor = self.arch.get_reg_accessor(regname)
                if (
                    accessor is not None
                    and accessor.base_reg == base_reg
                    and regname != base_reg
                    and self.test_register(regname)
                ):
                    values[regname] = self.read_register(regname)
        return values

    def read_memory(self, addr: int, size: int) -> bytes:
        return self.mem.read(addr, size)

    def write_memory(self, addr: int, data: bytes) -> None:
        self.mem.write(addr, data)

    def __repr__(self) -> str:
        regs = {
            reg: hex(value)
            for reg, value in self.known_register_values(include_partial=True).items()
        }
        return f"Snapshot ({self.arch.serialized_name}): {regs}"
