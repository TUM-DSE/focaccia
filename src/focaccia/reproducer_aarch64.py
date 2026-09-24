"""Narrow, source-only AArch64 little-endian reproducer backend.

The caller supplies the complete retained block (including any optimizer-sensitive
entry prefix), its entry state, and *all* entry dependencies. No dependency or
control-flow inference, execution, or same-mismatch claim is made here. Assemble
and statically link the two returned sources together, without PIE or additional
objects (for example: cc -nostdlib -static -no-pie -Wl,--build-id=none
-Wl,-T,reproducer.ld reproducer.s -o reproducer). The linker script is mandatory:
relocating the bytes is not supported. Generated code/data are ELF PT_LOAD
segments, not runtime-copied instructions requiring cache maintenance.
Unknown required bits/bytes, SIMD/system state, overlapping load pages, and far
bootstrap branches fail closed. Unrequested state is not claimed to be restored.
"""

from collections.abc import Iterable
from dataclasses import dataclass

from .snapshot import MemoryAccessError, ProgramState, RegisterAccessError


class AArch64ReproducerError(ValueError):
    """The requested exact context cannot be emitted by this backend."""


@dataclass(frozen=True)
class AArch64Block:
    """Original contiguous bytes, entered at start, with a localized transition.

    Bytes before transition_pc are preserved as an entry prefix, not replaced by
    equivalent setup instructions. Bytes after it retain the rest of the block.
    The caller must include every executed instruction required by the witness.
    """

    start: int
    data: bytes
    transition_pc: int

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes):
            raise AArch64ReproducerError("Block bytes must be concrete bytes.")
        _range(self.start, len(self.data))
        if self.start % 4 or len(self.data) % 4:
            raise AArch64ReproducerError("AArch64 instructions require four-byte alignment.")
        if (type(self.transition_pc) is not int or self.transition_pc % 4
                or not self.start <= self.transition_pc < self.end):
            raise AArch64ReproducerError("Localized transition is outside the retained block.")

    @property
    def end(self) -> int:
        return self.start + len(self.data)


@dataclass(frozen=True)
class AArch64ReproducerSource:
    assembly: str
    linker_script: str
    entry_pc: int
    transition_pc: int
    # Exact input bytes only; ELF page padding is not an observed input.
    memory: tuple[tuple[int, bytes], ...]


def _range(address: int, size: int) -> None:
    if (type(address) is not int or type(size) is not int or address < 0
            or size <= 0 or address + size > 1 << 64):
        raise AArch64ReproducerError("Invalid nonempty 64-bit address range.")


def _load(register: str, value: int) -> list[str]:
    # Four fixed-width instructions: no literal pool, relocation, or flag writes.
    return [f"    movz {register}, #{value & 0xffff:#x}"] + [
        f"    movk {register}, #{(value >> shift) & 0xffff:#x}, lsl #{shift}"
        for shift in (16, 32, 48)
    ]


def _bytes(data: bytes) -> list[str]:
    return ["    .byte " + ", ".join(f"0x{v:02x}" for v in data[i:i + 16])
            for i in range(0, len(data), 16)]


def generate_aarch64_reproducer(
    state: ProgramState,
    block: AArch64Block,
    *,
    required_registers: Iterable[str],
    memory_ranges: Iterable[tuple[int, int]] = (),
    bootstrap_address: int = 0x10000,
    page_size: int = 65536,
) -> AArch64ReproducerSource:
    """Emit exact fixed-address ELF assembly and its mandatory linker script.

    State must describe block.start, not the later localized transition. Required
    W aliases conservatively require their complete X base; unknown upper bits
    are never zero-filled. Individual N/Z/C/V inputs are supported without
    requiring unrelated CPSR fields. NZCV requests all four flag bits.
    Memory ranges include exact initial bytes for both reads and write targets;
    write-only unknown destinations are deliberately unsupported in this slice.

    Page size must match or exceed the runner's page size (64 KiB by default).
    The resulting artifact still needs independent assembly/layout and
    native/buggy/reference validation before it establishes reproducer support.
    """
    if state.arch.isa != "aarch64" or state.arch.endianness != "little":
        raise AArch64ReproducerError("Only little-endian AArch64 is supported.")
    if not state.strict:
        raise AArch64ReproducerError("Non-strict state cannot establish exact inputs.")
    if (type(page_size) is not int or page_size < 4096
            or page_size > 65536 or page_size & (page_size - 1)):
        raise AArch64ReproducerError("Unsupported load page size.")
    _range(bootstrap_address, page_size)
    if bootstrap_address % page_size:
        raise AArch64ReproducerError("Bootstrap must start at a page boundary.")

    registers: dict[str, int] = {}
    flags: dict[str, int] = {}
    try:
        if state.read_pc() != block.start:
            raise AArch64ReproducerError("State PC must match the retained block entry.")
        for requested in required_registers:
            name = requested.upper()
            if name == "PC":
                continue
            if name == "NZCV":
                flags.update((flag, state.read_register(flag)) for flag in "NZCV")
                continue
            if name in {"N", "Z", "C", "V"}:
                flags[name] = state.read_register(name)
                continue
            accessor = state.arch.get_reg_accessor(name)
            if accessor is None:
                raise AArch64ReproducerError(f"Unsupported register: {name}.")
            if name in {"XZR", "WZR"}:
                continue
            base = accessor.base_reg
            if base not in {*(f"X{i}" for i in range(31)), "SP"}:
                raise AArch64ReproducerError(f"Unsupported register: {name}.")
            registers[base] = state.read_register(base)
        concrete: dict[int, int] = {}
        for address, size in memory_ranges:
            _range(address, size)
            data = state.read_memory(address, size)
            if len(data) != size:
                raise AArch64ReproducerError("Short memory observation.")
            for offset, value in enumerate(data):
                concrete[address + offset] = value
    except (RegisterAccessError, MemoryAccessError) as error:
        raise AArch64ReproducerError(f"Unknown required input: {error}") from error

    # Code observations overlapping a memory dependency must agree exactly.
    for address in tuple(concrete):
        if block.start <= address < block.end:
            if concrete[address] != block.data[address - block.start]:
                raise AArch64ReproducerError("Memory input conflicts with retained code bytes.")
            # Writing code needs cache/protection handling beyond this backend.
            raise AArch64ReproducerError("Code/data aliasing is unsupported.")

    runs: list[tuple[int, bytearray]] = []
    for address in sorted(concrete):
        if runs and address == runs[-1][0] + len(runs[-1][1]):
            runs[-1][1].append(concrete[address])
        else:
            runs.append((address, bytearray([concrete[address]])))
    memory = [(address, bytes(data)) for address, data in runs]

    instructions: list[str] = []
    if flags:
        instructions.append("    mrs x16, nzcv")
        for flag, bit in (("N", 31), ("Z", 30), ("C", 29), ("V", 28)):
            if flag in flags:
                instructions += [f"    movz x17, #{flags[flag]}",
                                 f"    bfi x16, x17, #{bit}, #1"]
        instructions.append("    msr nzcv, x16")
    if "SP" in registers:
        instructions += _load("x16", registers["SP"])
        instructions.append("    mov sp, x16")
    # Restore scratch registers after their final use. No stack/call/flag clobber.
    for name in sorted(registers):
        if name != "SP":
            instructions += _load(name.lower(), registers[name])
    branch_pc = bootstrap_address + 4 * len(instructions)
    if not -(1 << 27) <= block.start - branch_pc < 1 << 27:
        raise AArch64ReproducerError("Block is outside direct bootstrap branch range.")
    instructions.append("    b reproduced_entry")
    bootstrap_size = 4 * len(instructions)
    if bootstrap_size > page_size:
        raise AArch64ReproducerError("Bootstrap exceeds its reserved page.")

    # The destination state is captured at block.end. Keep that address mapped
    # and executable so the consumer can install a stop breakpoint before the
    # landing instruction; otherwise process termination can overwrite result
    # registers before they are observed.
    fragment_size = len(block.data) + 4
    _range(block.start, fragment_size)
    sections = [("bootstrap", bootstrap_address, bootstrap_size, "ax", 5),
                ("fragment", block.start, fragment_size, "ax", 5)] + [
        (f"memory_{i}", address, len(data), "aw", 6)
        for i, (address, data) in enumerate(memory)
    ]
    pages: list[tuple[int, int]] = []
    for _, address, size, _, _ in sections:
        low = address // page_size * page_size
        high = (address + size + page_size - 1) // page_size * page_size
        if low == 0 or any(low < end and start < high for start, end in pages):
            raise AArch64ReproducerError("Load pages overlap or require the null page.")
        pages.append((low, high))

    assembly = [".arch armv8-a", '.section .bootstrap,"ax",@progbits',
                ".global _start", "_start:", *instructions,
                '.section .fragment,"ax",@progbits',
                ".global reproduced_entry", "reproduced_entry:"]
    prefix_size = block.transition_pc - block.start
    assembly += _bytes(block.data[:prefix_size])
    assembly += [".global reproduced_transition", "reproduced_transition:"]
    assembly += _bytes(block.data[prefix_size:])
    assembly += [".global reproduced_stop", "reproduced_stop:",
                 "    .byte 0x1f, 0x20, 0x03, 0xd5"]
    for i, (_, data) in enumerate(memory):
        assembly += [f'.section .memory_{i},"aw",@progbits', *_bytes(data)]
    assembly.append('.section .note.GNU-stack,"",@progbits')
    linker = ["OUTPUT_FORMAT(elf64-littleaarch64)", "OUTPUT_ARCH(aarch64)",
              "ENTRY(_start)", "PHDRS {",
              *(f"  p_{name} PT_LOAD FLAGS({flags});"
                for name, _, _, _, flags in sections), "}", "SECTIONS {"]
    for name, address, size, _, _ in sorted(sections, key=lambda section: section[1]):
        linker += [f"  .{name} {address:#x} : {{ KEEP(*(.{name})) }} :p_{name}",
                   f'  ASSERT(SIZEOF(.{name}) == {size}, "Unexpected {name} size")']
    linker += ["  /DISCARD/ : { *(.note.GNU-stack) *(.comment) }", "}"]
    return AArch64ReproducerSource("\n".join(assembly) + "\n",
                                   "\n".join(linker) + "\n", block.start,
                                   block.transition_pc, tuple(memory))
