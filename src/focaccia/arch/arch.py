from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Literal


Endianness = Literal["little", "big"]


@dataclass(frozen=True)
class ArchitectureKey:
    isa: str
    endianness: Endianness


class RegisterAccessor:
    def __init__(self, regname: str, start_bit: int, end_bit: int):
        """Describe the half-open bit range ``[start_bit, end_bit)``."""
        if start_bit < 0 or start_bit >= end_bit:
            raise ValueError(
                f"Invalid register range {regname}[{start_bit}:{end_bit}]: "
                "the start must be non-negative and less than the end."
            )

        self.base_reg = regname.upper()
        self.start = start_bit
        self.end = end_bit
        self.num_bits = end_bit - start_bit
        self.mask = ((1 << self.num_bits) - 1) << self.start

    def __repr__(self) -> str:
        return f"{self.base_reg}[{self.start}:{self.end - 1}]"


class RegisterDescription:
    def __init__(self, base: tuple[str, int, int], *subsets: tuple[str, int, int]):
        self.base = RegisterAccessor(*base)
        self.subsets = [
            (name.upper(), RegisterAccessor(base[0], start, end))
            for name, start, end in subsets
        ]


class ConstantRegisterDescription(RegisterDescription):
    def __init__(
        self,
        value: int,
        base: tuple[str, int, int],
        *subsets: tuple[str, int, int],
    ):
        super().__init__(base, *subsets)
        if value < 0 or value >= 1 << self.base.num_bits:
            raise ValueError(f"Constant value does not fit in {self.base.base_reg}.")
        self.value = value


class Arch:
    Endianness = Endianness

    def __init__(
        self,
        archname: str,
        registers: list[RegisterDescription],
        ptr_size: int,
        endianness: Endianness = "little",
        *,
        serialized_name: str | None = None,
        constant_registers: list[ConstantRegisterDescription] | None = None,
    ):
        if endianness not in ("little", "big"):
            raise ValueError(f"Unsupported endianness: {endianness}")

        self.archname = archname
        self.isa = archname
        self.ptr_size = ptr_size
        self.endianness: Endianness = endianness
        self.key = ArchitectureKey(self.isa, self.endianness)
        self.serialized_name = serialized_name or archname
        self.ignored_regs: list[str] = []

        constants = constant_registers or []
        self._accessors: dict[str, RegisterAccessor] = {}
        self._constant_values: dict[str, int] = {}

        for description in [*registers, *constants]:
            self._add_register_description(description)

        for description in constants:
            self._constant_values[description.base.base_reg] = description.value

        self.regnames = {description.base.base_reg for description in registers}
        """Names of mutable base registers."""

        self.constant_regnames = {
            description.base.base_reg for description in constants
        }
        """Names of architectural constant base registers."""

        self.all_regnames = set(self._accessors)
        """Names of mutable and constant registers, including aliases."""

        self._register_signature = tuple(
            sorted(
                (name, accessor.base_reg, accessor.start, accessor.end)
                for name, accessor in self._accessors.items()
            )
        )
        self._constant_signature = tuple(sorted(self._constant_values.items()))

    def _add_register_description(self, description: RegisterDescription) -> None:
        accessors = [
            (description.base.base_reg, description.base),
            *description.subsets,
        ]
        for name, accessor in accessors:
            if name in self._accessors:
                raise ValueError(f"Duplicate register name: {name}")
            self._accessors[name] = accessor

    def to_regname(self, name: str) -> str | None:
        """Transform a possibly non-standard name into a registered name."""
        name = name.upper()
        if name in self._accessors:
            return name
        return None

    def get_reg_accessor(self, regname: str) -> RegisterAccessor | None:
        """Get the accessor for a mutable or constant register name."""
        normalized = self.to_regname(regname)
        return self._accessors.get(normalized) if normalized is not None else None

    def is_constant_register(self, regname: str) -> bool:
        accessor = self.get_reg_accessor(regname)
        return accessor is not None and accessor.base_reg in self._constant_values

    def get_constant_register_value(self, regname: str) -> int | None:
        accessor = self.get_reg_accessor(regname)
        if accessor is None or accessor.base_reg not in self._constant_values:
            return None
        value = self._constant_values[accessor.base_reg]
        return (value & accessor.mask) >> accessor.start

    def decompose_register(
        self,
        base_reg: str,
        value: int,
        fields: Iterable[str],
    ) -> dict[str, int]:
        base_accessor = self.get_reg_accessor(base_reg)
        if base_accessor is None:
            raise ValueError(f"Not a register name: {base_reg}")

        result = {}
        for field in fields:
            accessor = self.get_reg_accessor(field)
            if accessor is None or accessor.base_reg != base_accessor.base_reg:
                raise ValueError(f"{field} is not a field of {base_accessor.base_reg}.")
            result[field] = (value & accessor.mask) >> accessor.start
        return result

    def compose_register(
        self,
        base_reg: str,
        fields: dict[str, int],
        *,
        initial_value: int = 0,
    ) -> int:
        base_accessor = self.get_reg_accessor(base_reg)
        if base_accessor is None:
            raise ValueError(f"Not a register name: {base_reg}")

        result = initial_value & ((1 << base_accessor.num_bits) - 1)
        for field, value in fields.items():
            accessor = self.get_reg_accessor(field)
            if accessor is None or accessor.base_reg != base_accessor.base_reg:
                raise ValueError(f"{field} is not a field of {base_accessor.base_reg}.")
            if value < 0 or value >= 1 << accessor.num_bits:
                raise ValueError(
                    f"Value {value} does not fit in {field} ({accessor.num_bits} bits)."
                )
            result &= ~accessor.mask
            result |= value << accessor.start
        return result

    def get_reg_reader(self, regname: str) -> Callable[[], int] | None:
        """Return a target-independent register reader.

        Architecture implementations must not read analyzer-host registers here.
        Target-dependent values have to come from the concrete target or remain
        explicit unknown environment symbols.
        """
        return None

    def register_write_zero_extends(self, regname: str) -> bool:
        """Return whether writing ``regname`` clears its base register's high bits."""
        return False

    def is_instr_uarch_dep(self, instr: str) -> bool:
        """Return whether an instruction has microarchitecture-dependent results."""
        return False

    def is_instr_syscall(self, instr: str) -> bool:
        return False

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Arch):
            return False
        return (
            type(self) is type(other)
            and self.key == other.key
            and self.ptr_size == other.ptr_size
            and self._register_signature == other._register_signature
            and self._constant_signature == other._constant_signature
        )

    def __hash__(self) -> int:
        return hash(
            (
                type(self),
                self.key,
                self.ptr_size,
                self._register_signature,
                self._constant_signature,
            )
        )

    def __repr__(self) -> str:
        return self.serialized_name
