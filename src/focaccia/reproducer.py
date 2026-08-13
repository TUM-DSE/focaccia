from collections.abc import Iterable
from dataclasses import dataclass
from os import PathLike
from typing import Callable, Protocol

from .arch import x86
from .snapshot import MemoryAccessError, ProgramState, RegisterAccessError
from .symbolic import SymbolEvaluationError, SymbolicTransform, eval_symbol
from .trace import MaterializedTrace, TraceEnvironment


DEFAULT_PAGE_SIZE = 4096
_X86_ADDRESS_SPACE_SIZE = 1 << 64
_X86_GPR_RESTORE_ORDER = (
    "RAX",
    "RBX",
    "RCX",
    "RDX",
    "RSI",
    "RDI",
    "RBP",
    "R8",
    "R9",
    "R12",
    "R13",
    "R14",
    "R15",
    "R10",
    "R11",
)
_X86_RESTORABLE_FLAG_NAMES = ("CF", "PF", "AF", "ZF", "SF", "DF", "OF")


class ReproducerMemoryError(Exception):
    """Raised when exact reproducer memory cannot be planned or materialized."""


class ReproducerBasicBlockError(Exception):
    pass


class ReproducerRegisterError(Exception):
    pass


class ReproducerFragmentError(Exception):
    """Raised when executable bytes cannot form an exact reproduced fragment."""


@dataclass(frozen=True, slots=True)
class ExecutableFragment:
    """Exact instruction bytes retained at their original guest addresses."""

    start: int
    end: int
    data: bytes

    def __post_init__(self) -> None:
        if self.start < 0 or self.end <= self.start:
            raise ValueError("A reproducer fragment must have a non-empty address range.")
        if self.end > _X86_ADDRESS_SPACE_SIZE:
            raise ValueError("The reproducer fragment exceeds x86-64 address width.")
        object.__setattr__(self, "data", bytes(self.data))
        if len(self.data) != self.end - self.start:
            raise ValueError("Reproducer fragment byte length does not match its address range.")


@dataclass(frozen=True, slots=True)
class EntryPrefix:
    """A straight-line executable prefix ending at the reproduced transition."""

    start: int
    data: bytes

    def __post_init__(self) -> None:
        if self.start < 0 or self.start >= _X86_ADDRESS_SPACE_SIZE:
            raise ValueError("The reproducer entry prefix start does not fit in 64 bits.")
        object.__setattr__(self, "data", bytes(self.data))
        if not self.data:
            raise ValueError("A reproducer entry prefix cannot be empty.")
        if self.end > _X86_ADDRESS_SPACE_SIZE:
            raise ValueError("The reproducer entry prefix exceeds x86-64 address width.")

    @property
    def end(self) -> int:
        return self.start + len(self.data)


@dataclass(frozen=True, slots=True)
class FixedMemoryMapping:
    """One exact page-aligned anonymous mapping required by a reproducer."""

    address: int
    size: int

    def __post_init__(self) -> None:
        if self.address < 0:
            raise ValueError("A fixed mapping address cannot be negative.")
        if self.size <= 0:
            raise ValueError("A fixed mapping must have a positive size.")

    @property
    def end(self) -> int:
        return self.address + self.size


@dataclass(frozen=True, slots=True)
class MemoryInitialization:
    """One contiguous byte range to copy after fixed mappings are established."""

    address: int
    data: bytes

    def __post_init__(self) -> None:
        if self.address < 0:
            raise ValueError("A memory initialization address cannot be negative.")
        if not self.data:
            raise ValueError("A memory initialization cannot be empty.")
        object.__setattr__(self, "data", bytes(self.data))

    @property
    def end(self) -> int:
        return self.address + len(self.data)


@dataclass(frozen=True, slots=True)
class ReproducerMemoryPlan:
    """Exact mappings and bytes needed to recreate symbolic memory inputs."""

    mappings: tuple[FixedMemoryMapping, ...]
    initializations: tuple[MemoryInitialization, ...]


@dataclass(frozen=True, slots=True)
class RegisterRestore:
    """One complete x86-64 general-purpose register input value."""

    register: str
    value: int

    def __post_init__(self) -> None:
        if self.register not in {*_X86_GPR_RESTORE_ORDER, "RSP"}:
            raise ValueError(f"Unsupported x86-64 restore register {self.register}.")
        if self.value < 0 or self.value >= _X86_ADDRESS_SPACE_SIZE:
            raise ValueError(f"Value for {self.register} does not fit in 64 bits.")


@dataclass(frozen=True, slots=True)
class X86StateRestorePlan:
    """Inputs that can be restored without calls after the final state write."""

    target_pc: int
    registers: tuple[RegisterRestore, ...]
    stack_pointer: RegisterRestore | None
    flags_mask: int
    flags_value: int

    def __post_init__(self) -> None:
        if self.target_pc < 0 or self.target_pc >= _X86_ADDRESS_SPACE_SIZE:
            raise ValueError("The reproducer target PC does not fit in 64 bits.")
        if self.flags_mask < 0 or self.flags_mask >= _X86_ADDRESS_SPACE_SIZE:
            raise ValueError("The reproducer flag mask does not fit in 64 bits.")
        if self.flags_value & ~self.flags_mask:
            raise ValueError("The reproducer flag value contains unrequested bits.")


def plan_reproducer_memory(
    ranges: Iterable[tuple[int, bytes]],
    *,
    mapped_ranges: Iterable[tuple[int, int]] = (),
    page_size: int = DEFAULT_PAGE_SIZE,
) -> ReproducerMemoryPlan:
    """Merge concrete input bytes and cover them with exact page mappings."""
    if page_size <= 0 or page_size & (page_size - 1):
        raise ValueError("The reproducer page size must be a positive power of two.")

    concrete_bytes: dict[int, int] = {}
    required_mappings: list[tuple[int, int]] = []
    for address, raw_data in ranges:
        data = bytes(raw_data)
        if address < 0:
            raise ReproducerMemoryError(f"Cannot reproduce a negative memory address: {address}.")
        end = address + len(data)
        if end > _X86_ADDRESS_SPACE_SIZE:
            raise ReproducerMemoryError(
                f"Memory range [{address:#x}, {end:#x}) exceeds x86-64 address width."
            )
        if data:
            required_mappings.append((address, len(data)))
        for offset, value in enumerate(data):
            byte_address = address + offset
            previous = concrete_bytes.get(byte_address)
            if previous is not None and previous != value:
                raise ReproducerMemoryError(
                    f"Conflicting values requested at {byte_address:#x}: "
                    f"{previous:#x} and {value:#x}."
                )
            concrete_bytes[byte_address] = value

    for address, size in mapped_ranges:
        if address < 0 or size < 0:
            raise ReproducerMemoryError(f"Cannot map negative range [{address}, {address + size}).")
        end = address + size
        if end > _X86_ADDRESS_SPACE_SIZE:
            raise ReproducerMemoryError(
                f"Mapped range [{address:#x}, {end:#x}) exceeds x86-64 address width."
            )
        if size:
            required_mappings.append((address, size))

    initializations: list[MemoryInitialization] = []
    current_start: int | None = None
    previous_address: int | None = None
    current_data = bytearray()
    for address in sorted(concrete_bytes):
        if previous_address is None or address != previous_address + 1:
            if current_start is not None:
                initializations.append(MemoryInitialization(current_start, bytes(current_data)))
            current_start = address
            current_data = bytearray()
        current_data.append(concrete_bytes[address])
        previous_address = address
    if current_start is not None:
        initializations.append(MemoryInitialization(current_start, bytes(current_data)))

    page_mask = page_size - 1
    aligned_ranges = sorted(
        (
            address & ~page_mask,
            (address + size + page_mask) & ~page_mask,
        )
        for address, size in required_mappings
    )
    mappings: list[FixedMemoryMapping] = []
    if aligned_ranges:
        mapping_start, mapping_end = aligned_ranges[0]
        for start, end in aligned_ranges[1:]:
            if start > mapping_end:
                mappings.append(FixedMemoryMapping(mapping_start, mapping_end - mapping_start))
                mapping_start, mapping_end = start, end
            else:
                mapping_end = max(mapping_end, end)
        mappings.append(FixedMemoryMapping(mapping_start, mapping_end - mapping_start))

    return ReproducerMemoryPlan(tuple(mappings), tuple(initializations))


def plan_x86_state_restore(
    snapshot: ProgramState,
    used_registers: Iterable[str],
    *,
    target_pc: int,
) -> X86StateRestorePlan:
    """Plan a call-free x86-64 transition into the reproduced fragment."""
    arch = snapshot.arch
    if arch.archname != x86.archname or arch.endianness != "little" or arch.ptr_size != 64:
        raise ReproducerRegisterError(
            f"State restoration is not implemented for {arch.serialized_name}."
        )

    def read_required(register: str, *, complete_base: bool = False) -> int:
        try:
            return snapshot.read_register(register)
        except RegisterAccessError as error:
            requirement = "A complete base-register value" if complete_base else "A known value"
            raise ReproducerRegisterError(
                f"{requirement} is required for {error.regname}: {error}"
            ) from error

    snapshot_pc = read_required("PC")
    if snapshot_pc != target_pc:
        raise ReproducerRegisterError(
            f"Snapshot PC {snapshot_pc:#x} differs from target {target_pc:#x}."
        )

    restorable_flag_mask = 0
    for name in _X86_RESTORABLE_FLAG_NAMES:
        accessor = arch.get_reg_accessor(name)
        if accessor is None:
            raise RuntimeError(f"x86-64 has no {name} flag accessor.")
        restorable_flag_mask |= accessor.mask

    required_bases: set[str] = set()
    flags_mask = 0
    flags_value = 0
    for requested_name in sorted(set(used_registers)):
        normalized = arch.to_regname(requested_name)
        accessor = arch.get_reg_accessor(normalized) if normalized is not None else None
        if accessor is None:
            raise ReproducerRegisterError(
                f"Symbolic input {requested_name!r} is not an x86-64 register."
            )
        base = accessor.base_reg
        if base == "RIP":
            observed = read_required(normalized)
            expected = (target_pc & accessor.mask) >> accessor.start
            if observed != expected:
                raise ReproducerRegisterError(
                    f"Input {normalized} is {observed:#x}, but fragment placement "
                    f"provides {expected:#x}."
                )
            continue
        if base == "RFLAGS":
            unsupported = accessor.mask & ~restorable_flag_mask
            if unsupported:
                raise ReproducerRegisterError(
                    f"Input {normalized} requires flag bits {unsupported:#x} that cannot "
                    "be safely restored by the user-mode trampoline."
                )
            value = read_required(normalized) << accessor.start
            flags_mask |= accessor.mask
            flags_value = (flags_value & ~accessor.mask) | (value & accessor.mask)
            continue
        if base == "RSP" or base in _X86_GPR_RESTORE_ORDER:
            required_bases.add(base)
            continue
        raise ReproducerRegisterError(f"Input {normalized} uses unsupported register class {base}.")

    restores: list[RegisterRestore] = []
    stack_pointer: RegisterRestore | None = None
    for register in _X86_GPR_RESTORE_ORDER:
        if register in required_bases:
            restores.append(
                RegisterRestore(
                    register,
                    read_required(register, complete_base=True),
                )
            )
    if "RSP" in required_bases:
        stack_pointer = RegisterRestore(
            "RSP",
            read_required("RSP", complete_base=True),
        )

    return X86StateRestorePlan(
        target_pc,
        tuple(restores),
        stack_pointer,
        flags_mask,
        flags_value & flags_mask,
    )


def extract_executable_fragment(
    binary: str | PathLike[str],
    start: int,
    end: int,
    *,
    require_fallthrough: bool = False,
) -> ExecutableFragment:
    """Read an x86-64 ELF virtual-address range without launching the program."""
    if start < 0 or end <= start or end > _X86_ADDRESS_SPACE_SIZE:
        raise ReproducerFragmentError(f"Invalid executable fragment range [{start:#x}, {end:#x}).")

    from miasm.analysis.binary import Container
    from miasm.analysis.machine import Machine
    from miasm.core.locationdb import LocationDB

    location_db = LocationDB()
    try:
        with open(binary, "rb") as stream:
            container = Container.from_stream(stream, location_db)
            if container.arch != "x86_64":
                raise ReproducerFragmentError(
                    f"Reproducer fragment extraction requires x86-64, not {container.arch}."
                )
            data = bytes(container.bin_stream.getbytes(start, end - start))
            if require_fallthrough:
                disassembler = Machine(container.arch).dis_engine(
                    container.bin_stream,
                    loc_db=location_db,
                )
                address = start
                while address < end:
                    instruction = disassembler.dis_instr(address)
                    length = instruction.l
                    if instruction.offset != address or length <= 0 or address + length > end:
                        raise ReproducerFragmentError(
                            f"Executable prefix is not instruction-aligned at {address:#x}."
                        )
                    if instruction.breakflow():
                        raise ReproducerFragmentError(
                            f"Executable prefix changes control flow at {address:#x}."
                        )
                    address += length
    except ReproducerFragmentError:
        raise
    except (OSError, ValueError, KeyError, IndexError) as error:
        raise ReproducerFragmentError(
            f"Unable to extract executable range [{start:#x}, {end:#x}) " f"from {binary}: {error}"
        ) from error

    if len(data) != end - start:
        raise ReproducerFragmentError(
            f"Executable returned {len(data)} bytes for range [{start:#x}, {end:#x})."
        )
    return ExecutableFragment(start, end, data)


def single_transition_reproducer_trace(
    transform: SymbolicTransform,
    binary: str | PathLike[str],
) -> MaterializedTrace[SymbolicTransform]:
    """Bind one localized transition to the generated executable's identity."""
    start, end = transform.range
    environment = TraceEnvironment(
        str(binary),
        (),
        (),
        start_address=start,
        stop_address=end,
        architecture=transform.arch.key,
    )
    return MaterializedTrace((transform,), environment, (start,))


class _ReproducerTarget(Protocol):
    def get_basic_block_inst(self, addr: int) -> list[str]: ...
    def get_symbol_limit(self) -> int: ...


_TargetFactory = Callable[[str, list[str]], _ReproducerTarget]


def _make_local_target(oracle: str, argv: list[str]) -> _ReproducerTarget:
    from .native.lldb_target import LLDBLocalTarget

    return LLDBLocalTarget(oracle, argv)


class Reproducer:
    def __init__(
        self,
        oracle: str,
        argv: list[str],
        snap: ProgramState,
        sym: SymbolicTransform,
        target_factory: _TargetFactory | None = None,
        *,
        fragment: ExecutableFragment | None = None,
        entry_prefix: EntryPrefix | None = None,
        required_registers: Iterable[str] = (),
        condition_code_seed: int | None = None,
    ) -> None:
        self.pc = snap.read_register("pc")
        self.snap = snap
        self.sym = sym
        self.fragment = fragment
        self.entry_prefix = entry_prefix
        self.required_registers = tuple(required_registers)
        if condition_code_seed is not None and not 0 <= condition_code_seed <= 0x7FFFFFFF:
            raise ReproducerRegisterError(
                "The x86 condition-code seed must fit in a non-negative signed immediate."
            )
        if condition_code_seed is not None and entry_prefix is not None:
            raise ReproducerRegisterError(
                "A condition-code seed cannot be inserted into an exact entry prefix."
            )
        self.condition_code_seed = condition_code_seed

        if fragment is not None:
            if fragment.start != self.pc:
                raise ReproducerFragmentError(
                    f"Fragment starts at {fragment.start:#x}, but snapshot PC is {self.pc:#x}."
                )
            symbolic_range = getattr(sym, "range", None)
            if symbolic_range is not None and tuple(symbolic_range) != (
                fragment.start,
                fragment.end,
            ):
                raise ReproducerFragmentError(
                    f"Fragment range {fragment.start:#x}->{fragment.end:#x} differs "
                    f"from symbolic range {tuple(symbolic_range)!r}."
                )
            if entry_prefix is not None and entry_prefix.end != fragment.start:
                raise ReproducerFragmentError(
                    f"Entry prefix ends at {entry_prefix.end:#x}, not fragment start "
                    f"{fragment.start:#x}."
                )
            self.bb: list[str] = []
            self.sl = 0
        else:
            if entry_prefix is not None:
                raise ReproducerFragmentError(
                    "An entry prefix requires an exact executable fragment."
                )
            if target_factory is None:
                target_factory = _make_local_target
            target = target_factory(oracle, argv)
            self.bb = target.get_basic_block_inst(self.pc)
            self.sl = target.get_symbol_limit()

    @property
    def link_address(self) -> int:
        """Virtual address at which the emitted text section must begin."""
        if self.entry_prefix is not None:
            return self.entry_prefix.start
        return self.pc

    @staticmethod
    def _byte_directives(data: bytes) -> tuple[str, ...]:
        return tuple(
            ".byte " + ", ".join(f"{value:#x}" for value in data[offset : offset + 16])
            for offset in range(0, len(data), 16)
        )

    def get_bb(self) -> str:
        labels = (".global focaccia_reproducer_transition", "focaccia_reproducer_transition:")
        if self.fragment is not None:
            return "\n".join(
                (
                    f"_bb_{self.pc:#x}:",
                    *labels,
                    *self._byte_directives(self.fragment.data),
                    "jmp _exit",
                    "",
                )
            )
        if not self.bb:
            raise ReproducerBasicBlockError(
                f"No basic-block instructions were found at {self.pc:#x}."
            )
        return "\n".join(
            (
                f"_bb_{self.pc:#x}:",
                *labels,
                *self.bb[:-1],
                "jmp _exit",
                "",
            )
        )

    def register_plan(self) -> X86StateRestorePlan:
        symbolic_arch = getattr(self.sym, "arch", self.snap.arch)
        if symbolic_arch != self.snap.arch:
            raise ReproducerRegisterError(
                "The symbolic transform and concrete snapshot use different architectures."
            )
        validation_inputs = getattr(self.sym, "get_validation_input_registers", None)
        if callable(validation_inputs):
            used_registers = validation_inputs()
        else:
            used_registers = self.sym.get_used_registers()
        return plan_x86_state_restore(
            self.snap,
            (*used_registers, *self.required_registers),
            target_pc=self.pc,
        )

    def get_regs(self) -> str:
        plan = self.register_plan()
        lines = ["_restore_state:"]
        if plan.flags_mask:
            lines.extend(
                (
                    "pushfq",
                    "popq %r11",
                    f"movabsq ${plan.flags_mask:#x}, %r10",
                    "notq %r10",
                    "andq %r10, %r11",
                    f"movabsq ${plan.flags_value:#x}, %r10",
                    "orq %r10, %r11",
                    "pushq %r11",
                    "popfq",
                )
            )
        for restore in plan.registers:
            lines.append(f"movabsq ${restore.value:#x}, %{restore.register.lower()}")
        if self.condition_code_seed is not None:
            if plan.flags_mask:
                raise ReproducerRegisterError(
                    "A condition-code seed would overwrite required input flags."
                )
            lines.append(f"cmpq ${self.condition_code_seed:#x}, %r11")
        if plan.stack_pointer is not None:
            lines.append(
                f"movabsq ${plan.stack_pointer.value:#x}, "
                f"%{plan.stack_pointer.register.lower()}"
            )
        lines.extend((f"jmp _bb_{plan.target_pc:#x}", ""))
        return "\n".join(lines)

    def memory_plan(self) -> ReproducerMemoryPlan:
        """Plan exact runtime mappings for every symbolic memory input."""
        ranges: list[tuple[int, bytes]] = []
        mapped_ranges: list[tuple[int, int]] = []
        try:
            for memory in self.sym.get_used_memory_addresses():
                if memory.size <= 0 or memory.size % 8 != 0:
                    raise ReproducerMemoryError(f"Memory input has non-byte width {memory.size}.")
                address = eval_symbol(memory.ptr, self.snap)
                ranges.append((address, self.snap.read_memory(address, memory.size // 8)))
            for write in getattr(self.sym, "memory_writes", ()):
                address = eval_symbol(write.address, self.snap)
                mapped_ranges.append((address, write.size_bytes))
        except ReproducerMemoryError:
            raise
        except (
            MemoryAccessError,
            RegisterAccessError,
            SymbolEvaluationError,
            ValueError,
        ) as error:
            raise ReproducerMemoryError(
                f"Unable to plan memory at reproducer PC {self.pc:#x}: {error}"
            ) from error
        return plan_reproducer_memory(ranges, mapped_ranges=mapped_ranges)

    def get_mem(self) -> str:
        """Retained API: memory is now initialized at runtime, never with `.org`."""
        return ""

    def get_dyn(self) -> str:
        plan = self.memory_plan()
        lines = ["_setup_dyn:"]
        for mapping in plan.mappings:
            lines.extend(
                (
                    f"movabsq ${mapping.address:#x}, %rdi",
                    f"movabsq ${mapping.size:#x}, %rsi",
                    "call _alloc",
                )
            )
        for initialization in plan.initializations:
            lines.append(f"movabsq ${initialization.address:#x}, %rax")
            for index, value in enumerate(initialization.data):
                lines.append(f"movb ${value:#x}, (%rax)")
                if index + 1 != len(initialization.data):
                    lines.append("incq %rax")
        lines.extend(("ret", ""))
        return "\n".join(lines)

    def get_start(self) -> str:
        return "\n".join(
            (
                "_start:",
                "call _setup_dyn",
                "jmp _restore_state",
                "",
            )
        )

    def get_exit(self) -> str:
        return "\n".join(
            (
                "_exit:",
                "movq $0, %rdi",
                "jmp _exit_with_status",
                "_reproducer_fail:",
                "movq $125, %rdi",
                "_exit_with_status:",
                "movq $60, %rax",
                "syscall",
                "",
            )
        )

    def get_alloc(self) -> str:
        return "\n".join(
            (
                "_alloc:",
                "movq $(PROT_READ | PROT_WRITE), %rdx",
                "movq $(MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE), %r10",
                "movq $-1, %r8",
                "movq $0, %r9",
                "movq $syscall_mmap, %rax",
                "syscall",
                "cmpq %rdi, %rax",
                "jne _reproducer_fail",
                "ret",
                "",
            )
        )

    def get_code(self) -> str:
        lines = [".section .text", ".global _start", ""]
        if self.entry_prefix is not None:
            lines.extend(
                (
                    "_start:",
                    *self._byte_directives(self.entry_prefix.data),
                    self.get_bb(),
                    self.get_exit(),
                )
            )
        else:
            lines.extend(
                (
                    self.get_bb(),
                    self.get_start(),
                    self.get_exit(),
                    self.get_alloc(),
                    self.get_regs(),
                    self.get_dyn(),
                )
            )
        return "\n".join(lines)

    def get_data(self) -> str:
        asm = ""
        asm += f".section .data\n"
        asm += f"PROT_READ  = 0x1\n"
        asm += f"PROT_WRITE = 0x2\n"
        asm += f"MAP_PRIVATE = 0x2\n"
        asm += f"MAP_ANONYMOUS = 0x20\n"
        asm += f"MAP_FIXED_NOREPLACE = 0x100000\n"
        asm += f"syscall_mmap = 9\n"
        asm += f"\n"

        return asm

    def asm(self) -> str:
        return "\n".join(
            (
                self.get_code(),
                self.get_data(),
                '.section .note.GNU-stack,"",@progbits',
                "",
            )
        )
