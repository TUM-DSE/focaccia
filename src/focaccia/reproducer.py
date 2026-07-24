from collections.abc import Iterable
from dataclasses import dataclass
from typing import Callable, Protocol

from .arch import x86
from .snapshot import MemoryAccessError, ProgramState, RegisterAccessError
from .symbolic import SymbolEvaluationError, SymbolicTransform, eval_symbol


DEFAULT_PAGE_SIZE = 4096
_X86_ADDRESS_SPACE_SIZE = 1 << 64


class ReproducerMemoryError(Exception):
    """Raised when exact reproducer memory cannot be planned or materialized."""


class ReproducerBasicBlockError(Exception):
    pass


class ReproducerRegisterError(Exception):
    pass


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


def plan_reproducer_memory(
    ranges: Iterable[tuple[int, bytes]],
    *,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> ReproducerMemoryPlan:
    """Merge concrete input bytes and cover them with exact page mappings."""
    if page_size <= 0 or page_size & (page_size - 1):
        raise ValueError("The reproducer page size must be a positive power of two.")

    concrete_bytes: dict[int, int] = {}
    for address, raw_data in ranges:
        data = bytes(raw_data)
        if address < 0:
            raise ReproducerMemoryError(
                f"Cannot reproduce a negative memory address: {address}."
            )
        end = address + len(data)
        if end > _X86_ADDRESS_SPACE_SIZE:
            raise ReproducerMemoryError(
                f"Memory range [{address:#x}, {end:#x}) exceeds x86-64 address width."
            )
        for offset, value in enumerate(data):
            byte_address = address + offset
            previous = concrete_bytes.get(byte_address)
            if previous is not None and previous != value:
                raise ReproducerMemoryError(
                    f"Conflicting values requested at {byte_address:#x}: "
                    f"{previous:#x} and {value:#x}."
                )
            concrete_bytes[byte_address] = value

    if not concrete_bytes:
        return ReproducerMemoryPlan((), ())

    initializations: list[MemoryInitialization] = []
    current_start: int | None = None
    previous_address: int | None = None
    current_data = bytearray()
    for address in sorted(concrete_bytes):
        if previous_address is None or address != previous_address + 1:
            if current_start is not None:
                initializations.append(
                    MemoryInitialization(current_start, bytes(current_data))
                )
            current_start = address
            current_data = bytearray()
        current_data.append(concrete_bytes[address])
        previous_address = address
    if current_start is None:
        raise RuntimeError("Non-empty reproducer memory lost its first address.")
    initializations.append(MemoryInitialization(current_start, bytes(current_data)))

    page_mask = page_size - 1
    pages = sorted({address & ~page_mask for address in concrete_bytes})
    mappings: list[FixedMemoryMapping] = []
    mapping_start = pages[0]
    previous_page = pages[0]
    for page in pages[1:]:
        if page != previous_page + page_size:
            mappings.append(
                FixedMemoryMapping(mapping_start, previous_page + page_size - mapping_start)
            )
            mapping_start = page
        previous_page = page
    mappings.append(
        FixedMemoryMapping(mapping_start, previous_page + page_size - mapping_start)
    )

    return ReproducerMemoryPlan(tuple(mappings), tuple(initializations))

class _ReproducerTarget(Protocol):
    def get_basic_block_inst(self, addr: int) -> list[str]: ...
    def get_symbol_limit(self) -> int: ...

_TargetFactory = Callable[[str, list[str]], _ReproducerTarget]

def _make_local_target(oracle: str, argv: list[str]) -> _ReproducerTarget:
    from .native.lldb_target import LLDBLocalTarget

    return LLDBLocalTarget(oracle, argv)

class Reproducer():
    def __init__(self,
                 oracle: str,
                 argv: list[str],
                 snap: ProgramState,
                 sym: SymbolicTransform,
                 target_factory: _TargetFactory | None = None) -> None:
        if target_factory is None:
            target_factory = _make_local_target
        target = target_factory(oracle, argv)

        self.pc = snap.read_register("pc")
        self.bb = target.get_basic_block_inst(self.pc)
        self.sl = target.get_symbol_limit()
        self.snap = snap
        self.sym = sym

    def get_bb(self) -> str:
        try:
            asm = ""
            asm += f'_bb_{hex(self.pc)}:\n'
            for i in self.bb[:-1]:
                asm += f'{i}\n'
            asm += f'ret\n'
            asm += f'\n'

            return asm
        except:
            raise ReproducerBasicBlockError(f'{hex(self.pc)}\n{self.snap}\n{self.sym}\n{self.bb}')

    def get_regs(self) -> str:
        general_regs = ['RIP', 'RAX', 'RBX','RCX','RDX', 'RSI','RDI','RBP','RSP','R8','R9','R10','R11','R12','R13','R14','R15',]
        flag_regs = ['CF', 'PF', 'AF', 'ZF', 'SF', 'TF', 'IF', 'DF', 'OF', 'IOPL', 'NT',]
        eflag_regs = ['RF', 'VM', 'AC', 'VIF', 'VIP', 'ID',]

        try:
            asm = ""
            asm += f'_setup_regs:\n'
            for reg in self.sym.get_used_registers():
                if reg in general_regs:
                    asm += f'mov ${hex(self.snap.read_register(reg))}, %{reg.lower()}\n'

            if 'RFLAGS' in self.sym.get_used_registers():
                asm += f'pushfq ${hex(self.snap.read_register("RFLAGS"))}\n'

            if any(reg in self.sym.get_used_registers() for reg in flag_regs+eflag_regs):
                asm += f'pushfd ${hex(x86.compose_rflags(self.snap.regs))}\n'
            asm += f'ret\n'
            asm += f'\n'

            return asm
        except:
            raise ReproducerRegisterError(f'{hex(self.pc)}\n{self.snap}\n{self.sym}\n{self.bb}')

    def memory_plan(self) -> ReproducerMemoryPlan:
        """Plan exact runtime mappings for every symbolic memory input."""
        ranges: list[tuple[int, bytes]] = []
        try:
            for memory in self.sym.get_used_memory_addresses():
                if memory.size <= 0 or memory.size % 8 != 0:
                    raise ReproducerMemoryError(
                        f"Memory input has non-byte width {memory.size}."
                    )
                address = eval_symbol(memory.ptr, self.snap)
                ranges.append(
                    (address, self.snap.read_memory(address, memory.size // 8))
                )
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
        return plan_reproducer_memory(ranges)

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
        asm = ""
        asm += f'_start:\n'
        asm += f'call _setup_dyn\n'
        asm += f'call _setup_regs\n'
        asm += f'call _bb_{hex(self.pc)}\n'
        asm += f'call _exit\n'
        asm += f'\n'

        return asm

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
        asm = ""
        asm += f'.section .text\n'
        asm += f'.global _start\n'
        asm += f'\n'
        asm += f'.org {hex(self.pc)}\n'
        asm += self.get_bb()
        asm += self.get_start()
        asm += self.get_exit()
        asm += self.get_alloc()
        asm += self.get_regs()
        asm += self.get_dyn()

        return asm

    def get_data(self) -> str:
        asm = ""
        asm += f'.section .data\n'
        asm += f'PROT_READ  = 0x1\n'
        asm += f'PROT_WRITE = 0x2\n'
        asm += f'MAP_PRIVATE = 0x2\n'
        asm += f'MAP_ANONYMOUS = 0x20\n'
        asm += f'MAP_FIXED_NOREPLACE = 0x100000\n'
        asm += f'syscall_mmap = 9\n'
        asm += f'\n'

        return asm

    def asm(self) -> str:
        asm = ""
        asm += self.get_code()
        asm += self.get_data()

        return asm
