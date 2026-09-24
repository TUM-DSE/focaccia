"""Tools and utilities for execution with Miasm."""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
import re
from typing import Literal

from miasm.ir.ir import Lifter
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.core.cpu import instruction as miasm_instr
from miasm.core.utils import Disasm_Exception
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import (
    Expr,
    ExprCompose,
    ExprCond,
    ExprId,
    ExprInt,
    ExprLoc,
    ExprMem,
    ExprOp,
    ExprSlice,
)

from .snapshot import ReadableProgramState, MemoryAccessError
from .arch import Arch, supported_architectures
from .arch.arch import RegisterAccessor
from .miasm_util import (
    MiasmSymbolResolver,
    eval_expr,
    expr_simp,
    expression_children,
    expression_depth,
    iter_expression_dag,
    make_machine,
    simplify_if_shallow,
)


EXECUTION_TID = ExprId("__focaccia_execution_tid", 64)
ALLOCATION_BASE_PREFIX = "__focaccia_allocation_base_"


def allocation_base_symbol(occurrence: int) -> ExprId:
    if type(occurrence) is not int or occurrence < 0:
        raise ValueError("Allocation occurrence must be nonnegative.")
    return ExprId(f"{ALLOCATION_BASE_PREFIX}{occurrence}", 64)


def _allocation_occurrence(name: str) -> int | None:
    if not name.startswith(ALLOCATION_BASE_PREFIX):
        return None
    suffix = name.removeprefix(ALLOCATION_BASE_PREFIX)
    if not suffix.isdecimal() or str(int(suffix)) != suffix:
        raise SymbolEvaluationError("Malformed allocation-context symbol.")
    return int(suffix)


_ARCHITECTURAL_UNKNOWN_PREFIX = "FOCACCIA_UNDEFINED_"


def _architectural_unknown(register: str, instruction_address: int, size: int) -> ExprId:
    return ExprId(
        f"{_ARCHITECTURAL_UNKNOWN_PREFIX}{register}_{instruction_address:X}",
        size,
    )


def _is_architectural_unknown(expression: Expr) -> bool:
    return (
        isinstance(expression, ExprId)
        and isinstance(expression.name, str)
        and expression.name.startswith(_ARCHITECTURAL_UNKNOWN_PREFIX)
    )


def _contains_architectural_unknown(expression: Expr) -> bool:
    return any(_is_architectural_unknown(node) for node in iter_expression_dag(expression))


class SymbolEvaluationError(ValueError):
    """Raised when an expression cannot be reduced from a concrete state."""


class SymbolicCompositionError(ValueError):
    """Raised when symbolic transforms cannot be composed soundly."""


class UnsupportedInstructionError(NotImplementedError):
    """Raised when Miasm cannot lift an instruction."""


_DEFERRED_MEMORY_BYTE_OP = "focaccia_memory_byte"


def eval_symbol(symbol: Expr, conc_state: ReadableProgramState) -> int:
    """Evaluate a symbol based on a concrete reference state.

    :param conc_state: A concrete state.
    :return: The resolved value.

    :raise ValueError: If the concrete state does not contain a register value
                       that is referenced by the symbolic expression.
    :raise MemoryAccessError: If the concrete state does not contain memory
                              that is referenced by the symbolic expression.
    """

    class ConcreteStateWrapper(MiasmSymbolResolver):
        """Extend the state resolver with assumptions about the expressions
        that may be resolved with `eval_symbol`."""

        def __init__(self, conc_state: ReadableProgramState):
            super().__init__(conc_state, LocationDB())

        def resolve_register(self, regname: str) -> int:
            if regname == EXECUTION_TID.name:
                tid = self._state.execution_tid
                if type(tid) is not int or not 0 < tid < 1 << 31:
                    raise SymbolEvaluationError("Independent execution TID is missing or invalid.")
                return tid
            occurrence = _allocation_occurrence(regname)
            if occurrence is not None:
                if occurrence >= len(self._state.allocation_bases):
                    raise SymbolEvaluationError("Independent allocation context is missing.")
                return self._state.allocation_bases[occurrence]
            return self._state.read_register(self._miasm_to_regname(regname))

        def resolve_memory(self, addr: int, size: int) -> bytes:
            return self._state.read_memory(addr, size)

        def resolve_location(self, loc):
            raise ValueError(
                "[In eval_symbol]: Unable to evaluate symbols that contain IR location expressions."
            )

    for node in iter_expression_dag(symbol):
        if isinstance(node, ExprId) and isinstance(node.name, str):
            contextual = node.name == EXECUTION_TID.name or _allocation_occurrence(node.name) is not None
            if contextual and node.size != 64:
                raise SymbolEvaluationError("Execution-context expression must have width 64.")
    res = eval_expr(symbol, ConcreteStateWrapper(conc_state))

    # Must be either ExprInt or ExprLoc,
    # but ExprLocs are disallowed by the
    # ConcreteStateWrapper
    if not isinstance(res, ExprInt):
        raise SymbolEvaluationError(
            f"Expression {symbol} remains unresolved as {res}; a concrete value is required."
        )
    return int(res)


def _miasm_mode(arch: Arch) -> int | str:
    if arch.archname == "aarch64":
        return arch.endianness[0]
    return arch.ptr_size


class _AArch64DupGeneral(miasm_instr):
    """Project-side AdvSIMD DUP(general), absent from pinned Miasm.

    Arm DUP (general): size=LowestSetBit(imm5[3:0]); higher imm5 bits
    are ignored. Q=0 clears the upper 64 destination bits. No FP arithmetic,
    flags, memory or TLS effects occur. This is the Linux userspace AdvSIMD
    instruction model; disabled/trapped AdvSIMD still fails native validation.
    """

    def __init__(self, word: int, offset: int = 0):
        imm5, q = (word >> 16) & 31, (word >> 30) & 1
        low = imm5 & 15
        if not low or (low == 8 and q == 0):
            raise UnsupportedInstructionError("Reserved AArch64 DUP(general) size/Q encoding.")
        width = 8 * (low & -low)
        source = ('X' if width == 64 else 'W') + (str((word >> 5) & 31) if ((word >> 5) & 31) != 31 else 'ZR')
        super().__init__('DUP', 'l', [ExprId(f'V{word & 31}', 128),
                                     ExprId(source, 64 if width == 64 else 32)], word)
        self.offset = offset
        self.l = 4

    @property
    def element_width(self) -> int:
        low = (self.additional_info >> 16) & 15
        return 8 * (low & -low)

    @property
    def vector_width(self) -> int:
        return 64 << ((self.additional_info >> 30) & 1)

    @staticmethod
    def arg2str(expr, index=None, loc_db=None):
        return str(expr)

    def to_string(self, loc_db=None):
        suffix = {8: 'B', 16: 'H', 32: 'S', 64: 'D'}[self.element_width]
        return f'DUP {self.args[0]}.{self.vector_width // self.element_width}{suffix}, {self.args[1]}'


def _decode_aarch64_dup(data: bytes, arch: Arch, offset: int = 0) -> _AArch64DupGeneral | None:
    if arch.archname != 'aarch64' or arch.endianness != 'little' or len(data) < 4:
        return None
    word = int.from_bytes(data[:4], 'little')
    # Not DUP(element), INS, SMOV/UMOV, scalar DUP or SVE DUP.
    if word & 0xBFE0FC00 != 0x0E000C00:
        return None
    return _AArch64DupGeneral(word, offset)


def _parse_aarch64_dup(text: str, arch: Arch, offset: int, length: int) -> _AArch64DupGeneral | None:
    if arch.archname != 'aarch64' or not re.match(r'^\s*DUP\b', text, re.IGNORECASE):
        return None
    match = re.fullmatch(r'\s*DUP\s+V([0-9]+)\.(8B|16B|4H|8H|2S|4S|2D),\s*([WX])([0-9]+|ZR)\s*', text.upper())
    if arch.endianness != 'little' or match is None or length not in (0, 4):
        raise UnsupportedInstructionError('Unsupported AArch64 DUP form, mode or length.')
    d, arrangement, source_width, register = match.groups()
    width = {'B': 8, 'H': 16, 'S': 32, 'D': 64}[arrangement[-1]]
    datasize = int(arrangement[:-1]) * width
    n = 31 if register == 'ZR' else int(register)
    if not 0 <= int(d) < 32 or not 0 <= n < 32 or (register != 'ZR' and n == 31) or source_width != ('X' if width == 64 else 'W'):
        raise UnsupportedInstructionError('Invalid AArch64 DUP general registers.')
    return _AArch64DupGeneral(0x0E000C00 | ((datasize == 128) << 30) | ((width // 8) << 16) | (n << 5) | int(d), offset)


class _AArch64DcZva(miasm_instr):
    """Narrow DC ZVA decode; memory semantics retain a target DCZID guard."""

    def __init__(self, word: int, offset: int = 0):
        n = word & 31
        super().__init__('DC', 'l', [ExprId('XZR' if n == 31 else f'X{n}', 64)], word)
        self.offset = offset
        self.l = 4

    @staticmethod
    def arg2str(expr, index=None, loc_db=None):
        return str(expr)

    def to_string(self, loc_db=None):
        return f'DC ZVA, {self.args[0]}'


def _decode_aarch64_dczva(data: bytes, arch: Arch, offset: int = 0) -> _AArch64DcZva | None:
    if arch.archname != 'aarch64' or arch.endianness != 'little' or len(data) < 4:
        return None
    word = int.from_bytes(data[:4], 'little')
    return _AArch64DcZva(word, offset) if word & 0xFFFFFFE0 == 0xD50B7420 else None


def _parse_aarch64_dczva(text: str, arch: Arch, offset: int, length: int) -> _AArch64DcZva | None:
    if arch.archname != 'aarch64' or not re.match(r'^\s*DC\b', text, re.IGNORECASE):
        return None
    match = re.fullmatch(r'\s*DC\s+ZVA,\s*X([0-9]+|ZR)\s*', text.upper())
    if arch.endianness != 'little' or match is None or length not in (0, 4):
        raise UnsupportedInstructionError('Unsupported AArch64 DC form, mode or length.')
    n = 31 if match[1] == 'ZR' else int(match[1])
    if not 0 <= n < 32 or (n == 31 and match[1] != 'ZR'):
        raise UnsupportedInstructionError('Invalid AArch64 DC ZVA register.')
    return _AArch64DcZva(0xD50B7420 | n, offset)


class _X86Vmovdqa(miasm_instr):
    """VEX.256.66.0F.WIG aligned moves, RIP+disp32 or RSP+disp8 only."""

    def __init__(self, raw: bytes, offset: int = 0):
        if (len(raw) not in (6, 8) or raw[:2] != b'\xc5\xfd'
                or raw[2] not in (0x6f, 0x7f)
                or not ((len(raw) == 8 and raw[3] == 5 and raw[2] == 0x6f)
                        or (len(raw) == 6 and raw[3:5] == b'\x44\x24'))):
            raise UnsupportedInstructionError('Unsupported VMOVDQA encoding.')
        base = 'RIP' if len(raw) == 8 else 'RSP'
        displacement = int.from_bytes(raw[4:] if base == 'RIP' else raw[5:], 'little', signed=True)
        pointer = ExprId(base, 64) + ExprInt(displacement + (len(raw) if base == 'RIP' else 0), 64)
        memory, register = ExprMem(pointer, 256), ExprId('YMM0', 256)
        args = [register, memory] if raw[2] == 0x6f else [memory, register]
        super().__init__('VMOVDQA', 64, args, raw)
        self.offset, self.l = offset, len(raw)

    def validate(self):
        expected = _X86Vmovdqa(self.additional_info, self.offset)
        if self.mode != 64 or self.l != expected.l or self.args != expected.args or self.name != expected.name:
            raise UnsupportedInstructionError('VMOVDQA operands, width or length disagree with encoding.')

    @staticmethod
    def arg2str(expr, index=None, loc_db=None):
        return str(expr)


def _decode_x86_vmovdqa(data: bytes, arch: Arch, offset: int = 0):
    if arch.archname != 'x86_64' or data[:2] != b'\xc5\xfd' or len(data) < 4 or data[2] not in (0x6f, 0x7f):
        return None
    length = 8 if data[3] == 5 else 6
    return _X86Vmovdqa(data[:length], offset)


class _X86AvxLogic(miasm_instr):
    """Only the four exact AVX forms observed in the retained vector ELF.

    VEX XOR has bitwise (not FP) semantics. VZEROUPPER clears bits
    MAXVL-1:128 of registers 0..15, leaving registers 16..31 untouched.
    VPTEST tests all 256 bits, not just packed-element sign bits.
    """

    def __init__(self, raw: bytes, offset: int = 0):
        xmm, ymm = ExprId('XMM0', 128), ExprId('YMM0', 256)
        forms = {
            bytes.fromhex('c5f9efc0'): ('VPXOR', [xmm, xmm, xmm]),
            bytes.fromhex('c5f877'): ('VZEROUPPER', []),
            bytes.fromhex('c5fc574424e0'): ('VXORPS', [ymm, ymm, ExprMem(ExprId('RSP', 64) + ExprInt(-32, 64), 256)]),
            bytes.fromhex('c4e27d17c0'): ('VPTEST', [ymm, ymm]),
        }
        if raw not in forms:
            raise UnsupportedInstructionError('Unsupported AVX logic encoding.')
        name, args = forms[raw]
        super().__init__(name, 64, args, raw)
        self.offset, self.l = offset, len(raw)

    def validate(self):
        expected = _X86AvxLogic(self.additional_info, self.offset)
        if self.mode != 64 or self.l != expected.l or self.args != expected.args or self.name != expected.name:
            raise UnsupportedInstructionError('AVX logic operands, width or length disagree with encoding.')

    @staticmethod
    def arg2str(expr, index=None, loc_db=None):
        return str(expr)


def _decode_x86_avx_logic(data: bytes, arch: Arch, offset: int = 0):
    if arch.archname != 'x86_64':
        return None
    for raw in (bytes.fromhex('c5f9efc0'), bytes.fromhex('c5f877'),
                bytes.fromhex('c5fc574424e0'), bytes.fromhex('c4e27d17c0')):
        if data.startswith(raw):
            return _X86AvxLogic(raw, offset)
    return None


def _parse_x86_project_instruction(
    text: str, arch: Arch, offset: int, length: int,
) -> miasm_instr | None:
    """Parse the exact project-owned AVX forms emitted by ``str(instr)``."""
    if arch.archname != 'x86_64':
        return None
    normalized = ' '.join(text.upper().split())
    logic_forms = {
        ('VPXOR XMM0, XMM0, XMM0', 4): bytes.fromhex('c5f9efc0'),
        ('VZEROUPPER', 3): bytes.fromhex('c5f877'),
        ('VXORPS YMM0, YMM0, @256[RSP + 0XFFFFFFFFFFFFFFE0]', 6): bytes.fromhex('c5fc574424e0'),
        ('VPTEST YMM0, YMM0', 5): bytes.fromhex('c4e27d17c0'),
    }
    raw = logic_forms.get((normalized, length))
    if raw is not None:
        return _X86AvxLogic(raw, offset)
    stack_match = re.fullmatch(
        r'VMOVDQA (?:(@256\[RSP \+ 0X([0-9A-F]+)\]), YMM0|YMM0, @256\[RSP \+ 0X([0-9A-F]+)\])',
        normalized,
    )
    if stack_match is not None and length == 6:
        load = stack_match.group(3) is not None
        unsigned = int(stack_match.group(3) if load else stack_match.group(2), 16)
        displacement = unsigned - (1 << 64) if unsigned >= (1 << 63) else unsigned
        if not -128 <= displacement < 128:
            raise UnsupportedInstructionError('VMOVDQA RSP displacement is not signed 8-bit.')
        return _X86Vmovdqa(
            bytes.fromhex('c5fd6f4424' if load else 'c5fd7f4424')
            + displacement.to_bytes(1, 'little', signed=True),
            offset,
        )
    match = re.fullmatch(r'VMOVDQA YMM0, @256\[RIP \+ 0X([0-9A-F]+)\]', normalized)
    if match is None or length != 8:
        return None
    pointer_displacement = int(match.group(1), 16)
    encoded_displacement = pointer_displacement - length
    if not -(1 << 31) <= encoded_displacement < (1 << 31):
        raise UnsupportedInstructionError('VMOVDQA RIP displacement is not signed 32-bit.')
    raw = bytes.fromhex('c5fd6f05') + encoded_displacement.to_bytes(4, 'little', signed=True)
    return _X86Vmovdqa(raw, offset)


class Instruction:
    """An instruction."""

    def __init__(
        self, instr: miasm_instr, machine: Machine, arch: Arch, loc_db: LocationDB | None = None
    ):
        self.arch = arch
        self.machine = machine

        if loc_db is not None:
            instr.args = instr.resolve_args_with_symbols(loc_db)
        self.instr: miasm_instr = instr
        """The underlying Miasm instruction object."""

        assert instr.offset is not None
        assert instr.l is not None
        self.addr: int = instr.offset
        self.length: int = instr.l

    @staticmethod
    def from_bytecode(asm: bytes, arch: Arch) -> Instruction:
        """Disassemble an instruction."""
        machine = make_machine(arch)
        assert machine.mn is not None
        _instr = _decode_x86_avx_logic(asm, arch) or _decode_x86_vmovdqa(asm, arch) or _decode_aarch64_dup(asm, arch) or _decode_aarch64_dczva(asm, arch) or machine.mn.dis(asm, _miasm_mode(arch))
        return Instruction(_instr, machine, arch, None)

    @staticmethod
    def from_string(s: str, arch: Arch, offset: int = 0, length: int = 0) -> Instruction:
        machine = make_machine(arch)
        assert machine.mn is not None
        if arch.archname == 'aarch64':
            # Arm's unsigned carry aliases are identical condition encodings.
            s = re.sub(r'^\s*B\.(LO|HS)(?=\s|$)',
                       lambda match: {'LO': 'B.CC', 'HS': 'B.CS'}[match[1].upper()],
                       s, flags=re.IGNORECASE)
        _instr = (_parse_x86_project_instruction(s, arch, offset, length)
                  or _parse_aarch64_dup(s, arch, offset, length)
                  or _parse_aarch64_dczva(s, arch, offset, length)
                  or machine.mn.fromstring(s, LocationDB(), _miasm_mode(arch)))
        _instr.offset = offset
        _instr.l = length or (4 if isinstance(_instr, (_AArch64DupGeneral, _AArch64DcZva)) else 0)
        return Instruction(_instr, machine, arch, None)

    def to_bytecode(self) -> bytes:
        """Assemble the instruction to byte code."""
        if isinstance(self.instr, (_X86Vmovdqa, _X86AvxLogic)):
            self.instr.validate()
            return self.instr.additional_info
        if isinstance(self.instr, (_AArch64DupGeneral, _AArch64DcZva)):
            return self.instr.additional_info.to_bytes(4, 'little')
        if self.arch.archname == 'aarch64' and self.instr.name in ('B.CC', 'B.CS'):
            # Project instructions carry resolved absolute targets; Miasm's
            # assembler instead expects an imm19 displacement. Preserve the
            # semantic operand, and encode/check the signed displacement here.
            if (self.instr.mode != _miasm_mode(self.arch) or self.length not in (0, 4)
                    or len(self.instr.args) != 1 or not isinstance(self.instr.args[0], ExprInt)):
                raise UnsupportedInstructionError('Invalid AArch64 carry-branch mode or operands.')
            displacement = (int(self.instr.args[0]) - self.addr) & ((1 << 64) - 1)
            if displacement >= 1 << 63:
                displacement -= 1 << 64
            if displacement % 4 or not -(1 << 20) <= displacement < (1 << 20):
                raise UnsupportedInstructionError('AArch64 carry-branch target is unaligned or out of range.')
            condition = 3 if self.instr.name == 'B.CC' else 2
            word = 0x54000000 | ((displacement // 4 & 0x7FFFF) << 5) | condition
            return word.to_bytes(4, self.arch.endianness)
        assert self.machine.mn is not None
        return self.machine.mn.asm(self.instr)[0]

    def to_string(self) -> str:
        """Convert the instruction to an Intel-syntax assembly string."""
        return str(self.instr)

    def __repr__(self):
        return self.to_string()


@dataclass(frozen=True, slots=True)
class InstructionRecord:
    """Serializable instruction metadata retained for gap diagnostics."""

    addr: int
    length: int
    text: str

    def to_string(self) -> str:
        return self.text

    def __repr__(self) -> str:
        return self.text


@dataclass(frozen=True, slots=True)
class MemoryWrite:
    """One ordered symbolic memory write in increasing-address byte order."""

    address: Expr
    value: Expr

    def __post_init__(self) -> None:
        if self.value.size <= 0 or self.value.size % 8 != 0:
            raise ValueError("Symbolic memory writes must contain whole bytes.")

    @property
    def size_bytes(self) -> int:
        return self.value.size // 8

    @property
    def destination(self) -> ExprMem:
        return ExprMem(self.address, self.value.size)


class _TransformEvaluator(MiasmSymbolResolver):
    """Evaluate a transform with an indexed concrete ordered-write history."""

    def __init__(
        self,
        state: ReadableProgramState,
        writes: list[MemoryWrite],
    ):
        super().__init__(state, LocationDB())
        self._writes = writes
        self._versions: dict[int, list[tuple[int, int]]] = {}
        self._concrete_writes: list[tuple[int, bytes]] = []
        self._indexed_write_count = 0
        self._building_index = False

    def resolve_register(self, regname: str) -> int | None:
        if regname == EXECUTION_TID.name:
            tid = self._state.execution_tid
            if tid is None:
                raise SymbolEvaluationError("Independent execution TID context is missing.")
            return tid
        occurrence = _allocation_occurrence(regname)
        if occurrence is not None:
            if occurrence >= len(self._state.allocation_bases):
                raise SymbolEvaluationError("Independent allocation context is missing.")
            return self._state.allocation_bases[occurrence]
        return super().resolve_register(regname)

    def _ensure_write_index(self) -> None:
        if self._indexed_write_count == len(self._writes) or self._building_index:
            return
        self._building_index = True
        try:
            for index in range(self._indexed_write_count, len(self._writes)):
                write = self._writes[index]
                address = self.evaluate(write.address)
                value = self.evaluate(write.value)
                data = value.to_bytes(write.size_bytes, byteorder=self.endianness)
                self._concrete_writes.append((address, data))
                version = index + 1
                for offset, byte in enumerate(data):
                    self._versions.setdefault(address + offset, []).append((version, byte))
                self._indexed_write_count = version
        finally:
            self._building_index = False

    def resolve_memory(self, addr: int, size: int) -> bytes:
        return self._state.read_memory(addr, size)

    def resolve_environment_operation(
        self,
        operation: str,
        args: tuple[Expr, ...],
    ) -> Expr | None:
        if operation != _DEFERRED_MEMORY_BYTE_OP:
            return super().resolve_environment_operation(operation, args)
        if len(args) != 2 or not all(isinstance(arg, ExprInt) for arg in args):
            return None
        address, prefix = map(int, args)
        self._ensure_write_index()
        versions = self._versions.get(address, ())
        offset = bisect_right(versions, (prefix, 0xFF))
        if offset:
            return ExprInt(versions[offset - 1][1], args[0].size)
        data = self.resolve_memory(address, 1)
        if data is None or len(data) != 1:
            return None
        return ExprInt(data[0], args[0].size)

    def evaluate(self, expression: Expr) -> int:
        for node in iter_expression_dag(expression):
            if isinstance(node, ExprId) and isinstance(node.name, str):
                contextual = node.name == EXECUTION_TID.name or _allocation_occurrence(node.name) is not None
                if contextual and node.size != 64:
                    raise SymbolEvaluationError("Execution context requires 64-bit expression width.")
        result = eval_expr(expression, self)
        if not isinstance(result, ExprInt):
            raise SymbolEvaluationError(
                f"Expression {expression} remains unresolved as {result}; "
                "a concrete value is required."
            )
        return int(result)

    def concrete_writes(self) -> tuple[tuple[int, bytes], ...]:
        self._ensure_write_index()
        return tuple(self._concrete_writes)


GapReason = Literal[
    "disassembly-error",
    "symbolic-timeout",
    "unsupported-semantics",
    "cross-validation-error",
    "unmatched-transform-skip",
]


class TraceGap:
    """An explicitly unknown state transition.

    A gap records that concrete execution advanced while symbolic semantics were
    unavailable.  It is never equivalent to an empty ``SymbolicTransform``.
    """

    def __init__(
        self,
        tid: int,
        arch: Arch,
        from_addr: int,
        to_addr: int,
        reason: GapReason,
        message: str,
        *,
        instruction: Instruction | InstructionRecord | None = None,
        cause: BaseException | None = None,
        recorded_cause_type: str | None = None,
    ):
        if from_addr < 0 or to_addr < 0:
            raise ValueError("Trace-gap addresses must be non-negative.")
        if reason not in {
            "disassembly-error",
            "symbolic-timeout",
            "unsupported-semantics",
            "cross-validation-error",
            "unmatched-transform-skip",
        }:
            raise ValueError(f"Unsupported trace-gap reason: {reason}.")
        if not message:
            raise ValueError("A trace gap requires a diagnostic message.")
        self.tid = tid
        self.arch = arch
        self.addr = from_addr
        self.range = (from_addr, to_addr)
        self.reason = reason
        self.message = message
        self.instruction = instruction
        self.cause = cause
        self._recorded_cause_type = recorded_cause_type

    @property
    def instructions(self) -> list[Instruction | InstructionRecord]:
        return [] if self.instruction is None else [self.instruction]

    @property
    def cause_type(self) -> str | None:
        if self.cause is None:
            return self._recorded_cause_type
        cls = type(self.cause)
        return f"{cls.__module__}.{cls.__qualname__}"

    def __repr__(self) -> str:
        start, end = self.range
        return f"Trace gap [{self.tid}] {hex(start)} -> {hex(end)} ({self.reason}): {self.message}"


class SymbolicTransform:
    """A symbolic transformation mapping one program state to another."""

    def __init__(
        self,
        tid: int,
        transform: dict[Expr, Expr],
        instrs: list[Instruction],
        arch: Arch,
        from_addr: int,
        to_addr: int,
    ):
        """
        :param tid: The thread ID that executed the instructions effecting the transformation.
        :param transform: A map of input symbolic expressions and output symbolic expressions.
        :param instrs: A list of instructions. The transformation
                       represents the collective modifications to the program state
                       performed by these instructions.
        :param arch: The architecture of the symbolic transformation.
        :param from_addr: The starting address of the instruction effecting the symbolic
                          transformation.
        :param to_addr: The final address of the last instruction in the instructions list.
        """
        self.tid = tid
        self.arch = arch

        self.addr = from_addr
        """The instruction address of the program state on which the
        transformation operates. Equivalent to `self.range[0]`."""

        self.range = (from_addr, to_addr)
        """The range of addresses that the transformation covers.
        The transformation `t` maps the program state at instruction
        `t.range[0]` to the program state at instruction `t.range[1]`."""

        self.changed_regs: dict[str, Expr] = {}
        """Maps register names to expressions for the register's content.

        Contains only registers that are changed by the transformation.
        Register names are already normalized to a respective architecture's
        naming conventions."""

        self.memory_writes: list[MemoryWrite] = []
        """Ordered symbolic writes performed by the transformation."""

        self.instructions: list[Instruction] = instrs
        """The sequence of instructions that comprise this transformation."""

        for dst, expr in transform.items():
            assert isinstance(dst, ExprMem) or isinstance(dst, ExprId)

            if isinstance(dst, ExprMem):
                if dst.ptr.size != arch.ptr_size:
                    raise ValueError(
                        f"Memory address has width {dst.ptr.size}, expected {arch.ptr_size}."
                    )
                if dst.size != expr.size or expr.size % 8 != 0:
                    raise ValueError("Memory destination and value widths must match in bytes.")
                self.memory_writes.append(MemoryWrite(dst.ptr, expr))
            else:
                assert isinstance(dst, ExprId)
                regname = arch.to_regname(dst.name)
                if regname is None:
                    if isinstance(dst.name, str) and dst.name.upper() == "IRDST":
                        continue
                    raise SymbolicCompositionError(
                        f"Unsupported symbolic destination {dst.name!r}."
                    )
                if arch.is_constant_register(regname):
                    continue
                accessor = arch.get_reg_accessor(regname)
                if accessor is None or accessor.num_bits != expr.size:
                    raise ValueError(
                        f"Expression width for {regname} is {expr.size}, "
                        f"expected {accessor.num_bits if accessor else 'unknown'}."
                    )
                self.changed_regs[regname] = expr

        self.normalize_architectural_unknowns()
        self._reset_validation_register_names()
        self._register_output_cache_key: tuple[tuple[str, Expr], ...] | None = None
        self._canonical_register_output_cache: dict[str, Expr] = {}
        self._validation_register_output_cache_key: tuple[
            tuple[tuple[str, Expr], ...], frozenset[str]
        ] | None = None
        self._validation_register_output_cache: dict[str, Expr] = {}

    def _reset_validation_register_names(self) -> None:
        names: set[str] = set()
        for regname, expression in self.changed_regs.items():
            if _contains_architectural_unknown(expression):
                continue
            accessor = self.arch.get_reg_accessor(regname)
            if accessor is None:
                raise SymbolicCompositionError(
                    f"Missing accessor for symbolic destination {regname}."
                )
            names.add(accessor.base_reg if self.arch.register_write_zero_extends(regname) else regname)
        self._validation_register_names = names

    def normalize_architectural_unknowns(self) -> None:
        """Replace analyzer values for architecturally undefined x86 flags."""
        if self.arch.archname != "x86_64" or len(self.instructions) != 1:
            return
        instruction = self.instructions[0]
        underlying = getattr(instruction, "instr", None)
        if underlying is None:
            return
        mnemonic = str(getattr(underlying, "name", "")).upper()
        shifts = {"SAL", "SAR", "SHL", "SHR"}
        rotates = {"RCL", "RCR", "ROL", "ROR"}
        if mnemonic not in shifts | rotates or len(underlying.args) < 2:
            return

        destination = underlying.args[0]
        count = underlying.args[-1]
        destination_size = int(destination.size)
        effective_count: int | None = None
        if isinstance(count, ExprInt):
            count_mask = 0x3F if destination_size == 64 else 0x1F
            effective_count = int(count) & count_mask
            if mnemonic in {"RCL", "RCR"} and destination_size in {8, 16}:
                effective_count %= destination_size + 1
            elif mnemonic in {"ROL", "ROR"} and destination_size in {8, 16}:
                effective_count %= destination_size
        if effective_count == 0:
            return

        def make_unknown(register: str) -> None:
            accessor = self.arch.get_reg_accessor(register)
            if accessor is None:
                raise SymbolicCompositionError(
                    f"Missing accessor for undefined x86 flag {register}."
                )
            self.changed_regs[register] = _architectural_unknown(
                register,
                instruction.addr,
                accessor.num_bits,
            )

        if effective_count != 1:
            make_unknown("OF")
        if mnemonic in shifts:
            make_unknown("AF")
            if effective_count is None or effective_count >= destination_size:
                make_unknown("CF")

    def composed_with(self, other: SymbolicTransform) -> SymbolicTransform:
        """Return the sound sequential composition ``other(self(state))``."""
        return _compose_symbolic_transforms(self, other)

    def concat(self, other: SymbolicTransform) -> SymbolicTransform:
        """Compatibility mutator implemented by the symbolic-state composer."""
        composed = self.composed_with(other)
        self.changed_regs = composed.changed_regs
        self._validation_register_names = composed._validation_register_names
        self.memory_writes = list(composed.memory_writes)
        self.range = composed.range
        self.instructions = list(composed.instructions)
        return self

    def canonical_register_outputs(self) -> dict[str, Expr]:
        """Return base-register outputs expressed over the transition source."""
        # changed_regs remains public for compatibility, so key the cache by its
        # actual content rather than assuming callers only mutate via concat().
        key = tuple(self.changed_regs.items())
        if key != self._register_output_cache_key:
            self._canonical_register_output_cache = _canonical_register_outputs(self)
            self._register_output_cache_key = key
        return self._canonical_register_output_cache.copy()

    def get_used_registers(self) -> list[str]:
        """Find all register inputs using an iterative DAG traversal."""
        accessed_regs: set[str] = set()
        expressions = [
            *self.canonical_register_outputs().values(),
            *(write.address for write in self.memory_writes),
            *(write.value for write in self.memory_writes),
        ]
        for expression in expressions:
            for node in iter_expression_dag(expression):
                if not isinstance(node, ExprId) or not isinstance(node.name, str):
                    continue
                canonical = self.arch.to_regname(node.name)
                if canonical is not None:
                    accessed_regs.add(canonical)
        return list(accessed_regs)

    def get_validation_input_registers(self) -> list[str]:
        """Return source aliases needed to validate defined outputs and writes.

        Composition uses canonical base-register equations, but concrete backends
        should not be asked for an unavailable ZMM register when a retained XMM
        or YMM expression needs only that narrower architectural alias.
        """
        validation_accessors = [
            accessor
            for name in self.validation_register_outputs()
            if (accessor := self.arch.get_reg_accessor(name)) is not None
        ]
        expressions = [
            expression
            for name, expression in self.changed_regs.items()
            if (
                (changed := self.arch.get_reg_accessor(name)) is not None
                and any(
                    changed.base_reg == output.base_reg
                    and changed.mask & output.mask
                    for output in validation_accessors
                )
            )
        ]
        expressions.extend(write.address for write in self.memory_writes)
        expressions.extend(write.value for write in self.memory_writes)

        registers: set[str] = set()
        for expression in expressions:
            pending = [expression]
            visited: set[int] = set()
            while pending:
                node = pending.pop()
                if id(node) in visited:
                    continue
                visited.add(id(node))
                if isinstance(node, ExprSlice) and isinstance(node.arg, ExprId):
                    identifier = node.arg
                    canonical = (
                        self.arch.to_regname(identifier.name)
                        if isinstance(identifier.name, str)
                        else None
                    )
                    accessor = (
                        self.arch.get_reg_accessor(canonical)
                        if canonical is not None
                        else None
                    )
                    if accessor is not None and accessor.num_bits == identifier.size:
                        absolute_start = accessor.start + node.start
                        absolute_end = accessor.start + node.stop
                        aliases = sorted(
                            name
                            for name in self.arch.all_regnames
                            if (
                                (alias := self.arch.get_reg_accessor(name)) is not None
                                and alias.base_reg == accessor.base_reg
                                and alias.start == absolute_start
                                and alias.end == absolute_end
                            )
                        )
                        if aliases:
                            registers.add(aliases[0])
                            continue
                if isinstance(node, ExprId) and isinstance(node.name, str):
                    canonical = self.arch.to_regname(node.name)
                    if canonical is not None:
                        registers.add(canonical)
                pending.extend(reversed(expression_children(node)))
        return sorted(registers)

    def get_used_memory_addresses(self) -> list[ExprMem]:
        """Find all memory inputs using an iterative DAG traversal."""
        accessed_mem: dict[tuple[int, int], ExprMem] = {}
        expressions = [
            *self.changed_regs.values(),
            *(write.address for write in self.memory_writes),
            *(write.value for write in self.memory_writes),
        ]
        for expression in expressions:
            for node in iter_expression_dag(expression):
                if isinstance(node, ExprMem):
                    accessed_mem[(id(node.ptr), node.size)] = node
                elif (
                    isinstance(node, ExprOp)
                    and node.op == _DEFERRED_MEMORY_BYTE_OP
                    and len(node.args) == 2
                ):
                    accessed_mem[(id(node.args[0]), 8)] = ExprMem(node.args[0], 8)
        return list(accessed_mem.values())

    def validation_register_outputs(self) -> dict[str, Expr]:
        """Return only register ranges whose values this transform defines.

        Canonical base-register equations remain the composition contract, but
        validation omits architecturally undefined outputs while retaining
        independent defined slices. Architecturally zero-extending writes are
        validated through their complete base register.
        """
        changed_key = tuple(self.changed_regs.items())
        cache_key = (changed_key, frozenset(self._validation_register_names))
        if cache_key == self._validation_register_output_cache_key:
            return self._validation_register_output_cache.copy()

        canonical_outputs = self.canonical_register_outputs()
        outputs: dict[str, Expr] = {}
        for regname in sorted(self._validation_register_names):
            accessor = self.arch.get_reg_accessor(regname)
            if accessor is None:
                raise SymbolicCompositionError(
                    f"Missing accessor for validation output {regname}."
                )
            overlapping = [
                changed_name
                for changed_name in self.changed_regs
                if (
                    (changed := self.arch.get_reg_accessor(changed_name)) is not None
                    and changed.base_reg == accessor.base_reg
                    and changed.mask & accessor.mask
                )
            ]
            direct = self.changed_regs.get(regname)
            if direct is not None and overlapping == [regname]:
                expression = direct
            else:
                base = canonical_outputs.get(accessor.base_reg)
                if base is None:
                    continue
                expression = (
                    base
                    if accessor.start == 0 and accessor.end == base.size
                    else expr_simp(ExprSlice(base, accessor.start, accessor.end))
                )
            if not _contains_architectural_unknown(expression):
                outputs[regname] = expression
        self._validation_register_output_cache = outputs
        self._validation_register_output_cache_key = cache_key
        return outputs.copy()

    def eval_validation_register_transforms(
        self,
        conc_state: ReadableProgramState,
    ) -> dict[str, int]:
        """Evaluate register slices defined by this transform for validation."""
        evaluator = _TransformEvaluator(conc_state, self.memory_writes)
        result: dict[str, int] = {}
        for regname, expression in self.validation_register_outputs().items():
            if not conc_state.strict and regname.upper() in self.arch.ignored_regs:
                continue
            result[regname] = evaluator.evaluate(expression)
        return result

    def eval_register_transforms(self, conc_state: ReadableProgramState) -> dict[str, int]:
        """Calculate register transformations when applied to a concrete state.

        :param conc_state: A concrete program state that serves as the input
                           state on which the transformation operates.

        :return: A map from register names to the register values that were
                 changed by the transformation.
        :raise MemoryError:
        :raise ValueError:
        """
        evaluator = _TransformEvaluator(conc_state, self.memory_writes)
        res = {}
        for regname, expr in self.canonical_register_outputs().items():
            if not conc_state.strict and regname.upper() in self.arch.ignored_regs:
                continue
            res[regname] = evaluator.evaluate(expr)
        return res

    def eval_memory_address(self, expression: Expr, conc_state: ReadableProgramState) -> int:
        """Evaluate an output address with this transform's ordered-store context."""
        return _TransformEvaluator(conc_state, self.memory_writes).evaluate(expression)

    def eval_memory_transforms(self, conc_state: ReadableProgramState) -> dict[int, bytes]:
        """Calculate memory transformations when applied to a concrete state.

        :param conc_state: A concrete program state that serves as the input
                           state on which the transformation operates.

        :return: A map from memory addresses to the bytes that were changed by
                 the transformation.
        :raise MemoryError:
        :raise ValueError:
        """
        evaluator = _TransformEvaluator(conc_state, self.memory_writes)
        final_bytes: dict[int, int] = {}
        for address, data in evaluator.concrete_writes():
            for offset, byte in enumerate(data):
                final_bytes[address + offset] = byte

        if not final_bytes:
            return {}
        ranges: dict[int, bytes] = {}
        start: int | None = None
        previous: int | None = None
        data = bytearray()
        for address in sorted(final_bytes):
            if previous is None or address != previous + 1:
                if start is not None:
                    ranges[start] = bytes(data)
                start = address
                data = bytearray()
            data.append(final_bytes[address])
            previous = address
        assert start is not None
        ranges[start] = bytes(data)
        return ranges

    @classmethod
    def from_json(cls, data: dict) -> SymbolicTransform:
        """Parse a symbolic transformation from a JSON object.

        :raise KeyError: if a parse error occurs.
        """
        from miasm.expression.parser import str_to_expr as parse

        def decode_inst(obj: list, arch: Arch):
            length, text = obj
            try:
                return Instruction.from_string(text, arch, offset=0, length=length)
            except Exception as err:
                # Note: from None disables chaining in traceback
                raise ValueError(
                    f"[In SymbolicTransform.from_json] Unable to parse"
                    f' instruction string "{text}": {err}.'
                ) from None

        tid = int(data["tid"])
        arch = supported_architectures[data["arch"]]
        start_addr = int(data["from_addr"])
        end_addr = int(data["to_addr"])

        t = SymbolicTransform(tid, {}, [], arch, start_addr, end_addr)
        for name, encoded_expression in data["regs"].items():
            canonical = arch.to_regname(name)
            if canonical is None or arch.is_constant_register(canonical):
                raise ValueError(f"Unsupported symbolic destination {name!r}.")
            expression = parse(encoded_expression)
            accessor = arch.get_reg_accessor(canonical)
            if accessor is None or expression.size != accessor.num_bits:
                raise ValueError(f"Invalid expression width for register {canonical}.")
            t.changed_regs[canonical] = expression
        if "memory_writes" in data:
            t.memory_writes = [
                MemoryWrite(parse(write["address"]), parse(write["value"]))
                for write in data["memory_writes"]
            ]
        else:
            t.memory_writes = [
                MemoryWrite(parse(addr), parse(val)) for addr, val in data["mem"].items()
            ]
        instrs = [decode_inst(b, arch) for b in data["instructions"]]
        t.instructions = [inst for inst in instrs if inst is not None]

        # Recover the instructions' address information
        addr = t.addr
        for inst in t.instructions:
            inst.addr = addr
            addr += inst.length
        t.normalize_architectural_unknowns()
        t._reset_validation_register_names()

        return t

    def to_json(self) -> dict:
        """Serialize a symbolic transformation as a JSON object."""

        def encode_inst(inst: Instruction):
            try:
                return [inst.length, inst.to_string()]
            except Exception as err:
                # Note: from None disables chaining in traceback
                raise Exception(
                    f'[In SymbolicTransform.to_json] Unable to serialize "{inst}" as string: {err}'
                ) from None

        instrs = [encode_inst(inst) for inst in self.instructions]
        instrs = [inst for inst in instrs if inst is not None]
        return {
            "arch": self.arch.serialized_name,
            "tid": self.tid,
            "from_addr": self.range[0],
            "to_addr": self.range[1],
            "instructions": instrs,
            "regs": {name: repr(expr) for name, expr in self.changed_regs.items()},
            "validation_registers": sorted(self._validation_register_names),
            "memory_writes": [
                {"address": repr(write.address), "value": repr(write.value)}
                for write in self.memory_writes
            ],
        }

    def __repr__(self) -> str:
        start, end = self.range
        res = f"Symbolic state transformation [{self.tid}] {start} -> {end}:\n"
        res += "  [Symbols]\n"
        for reg, expr in self.changed_regs.items():
            res += f"    {reg:6s} = {expr}\n"
        for write in self.memory_writes:
            res += f"    {write.destination} = {write.value}\n"
        res += "  [Instructions]\n"
        for inst in self.instructions:
            res += f"    {inst}\n"

        return res[:-1]  # Remove trailing newline


@dataclass(frozen=True, slots=True)
class SymbolicDependencies:
    """Source-state inputs required by one or more symbolic outputs."""

    arch: Arch
    registers: frozenset[str]
    memory: tuple[ExprMem, ...]


@dataclass(slots=True)
class _SymbolicState:
    arch: Arch
    registers: dict[str, Expr]
    register_depths: dict[str, int]
    memory_writes: list[MemoryWrite]

    @classmethod
    def identity(cls, arch: Arch) -> _SymbolicState:
        registers: dict[str, Expr] = {}
        register_depths: dict[str, int] = {}
        for base_reg in sorted(arch.regnames):
            accessor = arch.get_reg_accessor(base_reg)
            if accessor is None:
                raise SymbolicCompositionError(f"Missing accessor for {base_reg}.")
            registers[base_reg] = ExprId(base_reg, accessor.num_bits)
            register_depths[base_reg] = 0
        return cls(arch, registers, register_depths, [])


def _simplify_with_depth(expression: Expr, depth: int) -> tuple[Expr, int]:
    """Simplify a shallow node and retain its depth without rescanning deep children."""
    result = simplify_if_shallow(expression, depth)
    if result is expression:
        return result, depth
    # Simplification is attempted only below the recursive depth limit, so a
    # changed result is bounded and inexpensive to measure exactly.
    return result, expression_depth(result)


def _pointer_with_offset(pointer: Expr, depth: int, offset: int) -> tuple[Expr, int]:
    if offset == 0:
        return pointer, depth
    mask = (1 << pointer.size) - 1
    expression = pointer + ExprInt(offset & mask, pointer.size)
    return _simplify_with_depth(expression, depth + 1)


def _constant_address_delta(left: Expr, right: Expr) -> int | None:
    if left.size != right.size:
        raise SymbolicCompositionError(
            f"Cannot compare {left.size}- and {right.size}-bit memory addresses."
        )
    difference = expr_simp(left - right)
    if not isinstance(difference, ExprInt):
        return None
    value = int(difference)
    sign_bit = 1 << (difference.size - 1)
    return value - (1 << difference.size) if value & sign_bit else value


def _memory_value_byte(write: MemoryWrite, offset: int, endianness: Arch.Endianness) -> Expr:
    if not 0 <= offset < write.size_bytes:
        raise IndexError(offset)
    value_index = offset if endianness == "little" else write.size_bytes - offset - 1
    start = value_index * 8
    return expr_simp(ExprSlice(write.value, start, start + 8))


def _assemble_memory_bytes(
    values: list[tuple[Expr, int]],
    endianness: Arch.Endianness,
) -> tuple[Expr, int]:
    if not values:
        raise SymbolicCompositionError("Cannot assemble an empty memory read.")
    significance_order = values if endianness == "little" else list(reversed(values))
    if len(significance_order) == 1:
        return significance_order[0]
    expression = ExprCompose(*(value for value, _depth in significance_order))
    depth = 1 + max(depth for _value, depth in significance_order)
    return _simplify_with_depth(expression, depth)


def _read_symbolic_memory(
    address: Expr,
    address_depth: int,
    size_bits: int,
    state: _SymbolicState,
) -> tuple[Expr, int]:
    if size_bits <= 0 or size_bits % 8 != 0:
        raise SymbolicCompositionError(f"Symbolic memory read has non-byte width {size_bits}.")

    prefix = ExprInt(len(state.memory_writes), state.arch.ptr_size)
    values: list[tuple[Expr, int]] = []
    for load_offset in range(size_bits // 8):
        load_address, load_address_depth = _pointer_with_offset(address, address_depth, load_offset)
        deferred = ExprOp(_DEFERRED_MEMORY_BYTE_OP, load_address, prefix)
        deferred_depth = load_address_depth + 1
        value = ExprSlice(deferred, 0, 8)
        values.append((value, deferred_depth + 1))
    return _assemble_memory_bytes(values, state.arch.endianness)


def _read_symbolic_register(
    identifier: ExprId,
    state: _SymbolicState,
) -> tuple[Expr, int]:
    if not isinstance(identifier.name, str):
        return identifier, 0
    if identifier.name == EXECUTION_TID.name or _allocation_occurrence(identifier.name) is not None:
        if identifier.size != 64:
            raise SymbolicCompositionError("Execution-context expression must have width 64.")
        # Execution context is immutable across transforms, not register storage.
        return identifier, 0
    canonical = state.arch.to_regname(identifier.name)
    if canonical is None:
        return identifier, 0
    accessor = state.arch.get_reg_accessor(canonical)
    if accessor is None:
        raise SymbolicCompositionError(f"Missing accessor for symbolic register {canonical}.")
    if accessor.num_bits != identifier.size:
        raise SymbolicCompositionError(
            f"Symbolic register {identifier.name} has width {identifier.size}, "
            f"expected {accessor.num_bits}."
        )
    if state.arch.is_constant_register(canonical):
        value = state.arch.get_constant_register_value(canonical)
        if value is None:
            raise SymbolicCompositionError(f"Missing constant value for {canonical}.")
        return ExprInt(value, accessor.num_bits), 0

    base = state.registers.get(accessor.base_reg)
    base_depth = state.register_depths.get(accessor.base_reg)
    if base is None or base_depth is None:
        raise SymbolicCompositionError(
            f"Missing symbolic base register {accessor.base_reg} for {identifier.name}."
        )
    if accessor.start == 0 and accessor.end == base.size:
        return base, base_depth
    return _simplify_with_depth(ExprSlice(base, accessor.start, accessor.end), base_depth + 1)


def _rewrite_symbolic_expression(
    expression: Expr,
    state: _SymbolicState,
    memory_dependencies: tuple[list[ExprMem], set[tuple[int, int]]] | None = None,
) -> tuple[Expr, int]:
    """Rewrite an expression DAG iteratively and memoize shared subexpressions."""
    results: dict[int, Expr] = {}
    depths: dict[int, int] = {}
    pending: list[tuple[Expr, bool]] = [(expression, False)]
    while pending:
        current, expanded = pending.pop()
        key = id(current)
        if key in results:
            continue
        children = expression_children(current)
        if not expanded:
            pending.append((current, True))
            pending.extend(
                (child, False) for child in reversed(children) if id(child) not in results
            )
            continue

        if isinstance(current, (ExprInt, ExprLoc)):
            rewritten = current
        elif isinstance(current, ExprId):
            rewritten, replacement_depth = _read_symbolic_register(current, state)
        elif isinstance(current, ExprMem):
            rewritten_pointer = results[id(current.ptr)]
            if memory_dependencies is not None:
                dependencies, keys = memory_dependencies
                dependency_key = (id(rewritten_pointer), current.size)
                if dependency_key not in keys:
                    keys.add(dependency_key)
                    dependencies.append(ExprMem(rewritten_pointer, current.size))
            rewritten, replacement_depth = _read_symbolic_memory(
                rewritten_pointer,
                depths[id(current.ptr)],
                current.size,
                state,
            )
        elif isinstance(current, ExprSlice):
            rewritten = ExprSlice(results[id(current.arg)], current.start, current.stop)
        elif isinstance(current, ExprCond):
            rewritten = ExprCond(
                results[id(current.cond)],
                results[id(current.src1)],
                results[id(current.src2)],
            )
        elif isinstance(current, ExprOp):
            arguments = tuple(results[id(argument)] for argument in current.args)
            if current.op == _DEFERRED_MEMORY_BYTE_OP:
                if len(arguments) != 2 or not isinstance(arguments[1], ExprInt):
                    raise SymbolicCompositionError("Malformed deferred memory read.")
                if memory_dependencies is not None:
                    dependencies, keys = memory_dependencies
                    dependency_key = (id(arguments[0]), 8)
                    if dependency_key not in keys:
                        keys.add(dependency_key)
                        dependencies.append(ExprMem(arguments[0], 8))
                prefix = int(arguments[1]) + len(state.memory_writes)
                arguments = (arguments[0], ExprInt(prefix, arguments[1].size))
            rewritten = ExprOp(current.op, *arguments)
        elif isinstance(current, ExprCompose):
            rewritten = ExprCompose(*(results[id(argument)] for argument in current.args))
        else:
            raise SymbolicCompositionError(
                f"Unsupported symbolic expression class {type(current).__name__}."
            )
        if isinstance(current, ExprId) and rewritten is not current:
            depth = replacement_depth
        elif isinstance(current, ExprMem):
            depth = replacement_depth
        else:
            depth = 1 + max((depths[id(child)] for child in children), default=-1)
        result, result_depth = _simplify_with_depth(rewritten, depth)
        results[key] = result
        depths[key] = result_depth
    return results[id(expression)], depths[id(expression)]


def _write_symbolic_register(
    current: Expr,
    current_depth: int,
    accessor: RegisterAccessor,
    value: Expr,
    value_depth: int,
    *,
    zero_extend: bool,
) -> tuple[Expr, int]:
    if value.size != accessor.num_bits:
        raise SymbolicCompositionError(
            f"Register write to {accessor} has {value.size} bits, expected {accessor.num_bits}."
        )
    if accessor.start == 0 and accessor.end == current.size:
        return value, value_depth

    parts: list[tuple[Expr, int]] = []
    if accessor.start:
        parts.append((ExprSlice(current, 0, accessor.start), current_depth + 1))
    parts.append((value, value_depth))
    if accessor.end < current.size:
        if zero_extend:
            parts.append((ExprInt(0, current.size - accessor.end), 0))
        else:
            parts.append((ExprSlice(current, accessor.end, current.size), current_depth + 1))
    if len(parts) == 1:
        return parts[0]
    expression = ExprCompose(*(part for part, _depth in parts))
    depth = 1 + max(depth for _part, depth in parts)
    return _simplify_with_depth(expression, depth)


def _apply_symbolic_transform(
    state: _SymbolicState,
    transform: SymbolicTransform,
    memory_dependencies: tuple[list[ExprMem], set[tuple[int, int]]] | None = None,
) -> None:
    # Register outputs within one transform are simultaneous, so they need a
    # snapshot of the incoming register map. Memory writes are appended only
    # after every expression has been rewritten and can therefore share the
    # incoming ordered-write list without copying its complete history.
    before = _SymbolicState(
        state.arch,
        state.registers.copy(),
        state.register_depths.copy(),
        state.memory_writes,
    )
    register_updates: list[tuple[str, RegisterAccessor, Expr, int]] = []
    written_masks: dict[str, int] = {}
    for regname, expression in transform.changed_regs.items():
        canonical = state.arch.to_regname(regname)
        if canonical is None:
            raise SymbolicCompositionError(f"Unknown symbolic destination register {regname}.")
        accessor = state.arch.get_reg_accessor(canonical)
        if accessor is None:
            raise SymbolicCompositionError(f"Missing accessor for {canonical}.")
        previous_mask = written_masks.get(accessor.base_reg, 0)
        if previous_mask & accessor.mask:
            raise SymbolicCompositionError(
                f"Transform has overlapping writes to {accessor.base_reg}."
            )
        written_masks[accessor.base_reg] = previous_mask | accessor.mask
        rewritten, rewritten_depth = _rewrite_symbolic_expression(
            expression,
            before,
            memory_dependencies,
        )
        register_updates.append((canonical, accessor, rewritten, rewritten_depth))

    memory_updates = []
    for write in transform.memory_writes:
        address, _address_depth = _rewrite_symbolic_expression(
            write.address,
            before,
            memory_dependencies,
        )
        value, _value_depth = _rewrite_symbolic_expression(
            write.value,
            before,
            memory_dependencies,
        )
        memory_updates.append(MemoryWrite(address, value))

    for canonical, accessor, value, value_depth in register_updates:
        current = state.registers[accessor.base_reg]
        current_depth = state.register_depths[accessor.base_reg]
        updated, updated_depth = _write_symbolic_register(
            current,
            current_depth,
            accessor,
            value,
            value_depth,
            zero_extend=state.arch.register_write_zero_extends(canonical),
        )
        state.registers[accessor.base_reg] = updated
        state.register_depths[accessor.base_reg] = updated_depth
    state.memory_writes.extend(memory_updates)


def _canonical_register_outputs(transform: SymbolicTransform) -> dict[str, Expr]:
    state = _SymbolicState.identity(transform.arch)
    _apply_symbolic_transform(state, transform)
    identity = _SymbolicState.identity(transform.arch)
    return {
        base_reg: expression
        for base_reg, expression in state.registers.items()
        if expression != identity.registers[base_reg]
    }


class SymbolicTransformComposer:
    """Incrementally compose a contiguous transform sequence in one symbolic state."""

    def __init__(self, first: SymbolicTransform, *, track_dependencies: bool = False):
        self._arch = first.arch
        self._tid = first.tid
        self._start = first.range[0]
        self._end = first.range[0]
        self._state = _SymbolicState.identity(first.arch)
        self._instructions: list[Instruction] = []
        self._validation_register_names: set[str] = set()
        self._track_dependencies = track_dependencies
        self._dependency_registers: set[str] = set()
        self._dependency_memory: list[ExprMem] = []
        self._dependency_memory_keys: set[tuple[int, int]] = set()
        self.append(first)

    def append(self, transform: SymbolicTransform) -> None:
        if self._arch != transform.arch:
            raise SymbolicCompositionError(
                f"Cannot compose architectures {self._arch} and {transform.arch}."
            )
        if self._tid != transform.tid:
            raise SymbolicCompositionError(
                f"Cannot compose thread {self._tid} with thread {transform.tid}."
            )
        if self._end != transform.range[0]:
            previous_range = (self._start, self._end)
            raise SymbolicCompositionError(
                f"Cannot compose discontinuous ranges {previous_range!r} and {transform.range!r}."
            )

        for changed_name in transform.changed_regs:
            changed_accessor = self._arch.get_reg_accessor(changed_name)
            if changed_accessor is None:
                raise SymbolicCompositionError(
                    f"Missing accessor for symbolic destination {changed_name}."
                )
            self._validation_register_names = {
                validation_name
                for validation_name in self._validation_register_names
                if (
                    (validation_accessor := self._arch.get_reg_accessor(validation_name))
                    is not None
                    and (
                        validation_accessor.base_reg != changed_accessor.base_reg
                        or not validation_accessor.mask & changed_accessor.mask
                    )
                )
            }
        self._validation_register_names.update(transform._validation_register_names)

        if self._track_dependencies:
            expressions = [
                *transform.changed_regs.values(),
                *(write.address for write in transform.memory_writes),
                *(write.value for write in transform.memory_writes),
            ]
            for expression in expressions:
                for node in iter_expression_dag(expression):
                    if not isinstance(node, ExprId) or not isinstance(node.name, str):
                        continue
                    canonical = self._arch.to_regname(node.name)
                    if canonical is not None:
                        self._dependency_registers.add(canonical)
        _apply_symbolic_transform(
            self._state,
            transform,
            (self._dependency_memory, self._dependency_memory_keys)
            if self._track_dependencies
            else None,
        )
        self._instructions.extend(transform.instructions)
        self._end = transform.range[1]

    def dependencies(self) -> SymbolicDependencies:
        """Return the union of source inputs seen at every appended prefix."""
        if not self._track_dependencies:
            raise SymbolicCompositionError("This composer is not tracking source dependencies.")
        return SymbolicDependencies(
            self._arch,
            frozenset(self._dependency_registers),
            tuple(self._dependency_memory),
        )

    def finish(self) -> SymbolicTransform:
        result = SymbolicTransform(
            self._tid,
            {},
            list(self._instructions),
            self._arch,
            self._start,
            self._end,
        )
        identity = _SymbolicState.identity(self._arch)
        result.changed_regs = {
            base_reg: expression
            for base_reg, expression in self._state.registers.items()
            if expression != identity.registers[base_reg]
        }
        result._validation_register_names = {
            name
            for name in self._validation_register_names
            if name in result.arch.all_regnames
        }
        result.memory_writes = list(self._state.memory_writes)
        return result


def _compose_symbolic_transforms(
    first: SymbolicTransform,
    second: SymbolicTransform,
) -> SymbolicTransform:
    composer = SymbolicTransformComposer(first)
    composer.append(second)
    return composer.finish()


SymbolicTraceItem = SymbolicTransform | TraceGap


class MemoryBinstream:
    """A binary stream interface that reads bytes from a program state's
    memory."""

    def __init__(self, state: ReadableProgramState):
        self._state = state

    def __len__(self):
        return 0xFFFFFFFF

    def __getitem__(self, key: int | slice):
        if isinstance(key, slice):
            return self._state.read_instructions(key.start, key.stop - key.start)
        return self._state.read_instructions(key, 1)


class DisassemblyContext:
    def __init__(self, target: ReadableProgramState):
        self.loc_db = LocationDB()

        # Determine the binary's architecture
        self.machine = make_machine(target.arch)
        self.arch = target.arch
        self._target = target

        # Create disassembly/lifting context
        assert self.machine.dis_engine is not None
        binstream = MemoryBinstream(target)
        self.mdis = self.machine.dis_engine(binstream, loc_db=self.loc_db)
        self.mdis.follow_call = True
        self.lifter = self.machine.lifter(self.loc_db)

    def disassemble(self, address: int) -> Instruction:
        try:
            miasm_instr = self.mdis.dis_instr(address)
        except (IndexError, Disasm_Exception, MemoryAccessError) as err:
            # Probe the narrow extension only on decode failure, not with an
            # additional target memory read for every supported instruction.
            if self.arch.archname == 'aarch64' and self.arch.endianness == 'little':
                raw = self._target.read_instructions(address, 4)
                extension = _decode_aarch64_dup(raw, self.arch, address) or _decode_aarch64_dczva(raw, self.arch, address)
                if extension is not None:
                    return Instruction(extension, self.machine, self.arch, self.loc_db)
            if self.arch.archname == 'x86_64':
                prefix = self._target.read_instructions(address, 3)
                lengths = {b'\xc5\xf9\xef': 4, b'\xc5\xf8\x77': 3,
                           b'\xc5\xfc\x57': 6, b'\xc4\xe2\x7d': 5}
                if prefix in lengths:
                    raw = self._target.read_instructions(address, lengths[prefix])
                    extension = _decode_x86_avx_logic(raw, self.arch, address)
                    if extension is not None:
                        return Instruction(extension, self.machine, self.arch, self.loc_db)
                prefix = self._target.read_instructions(address, 4)
                if prefix[:2] == b'\xc5\xfd' and prefix[2] in (0x6f, 0x7f):
                    raw = self._target.read_instructions(address, 8 if prefix[3] == 5 else 6)
                    extension = _decode_x86_vmovdqa(raw, self.arch, address)
                    if extension is not None:
                        return Instruction(extension, self.machine, self.arch, self.loc_db)
            # Miasm's dis_instr indexes block.lines[0] for an empty block.
            if isinstance(err, IndexError):
                raise Disasm_Exception(f"Miasm decoded no instruction at {hex(address)}.") from err
            raise
        # Pinned Miasm labels this SYS encoding as IC rather than DC ZVA.
        # Override only the exact DC ZVA word, never all cache operations.
        if self.arch.archname == 'aarch64' and self.arch.endianness == 'little' and miasm_instr.name == 'IC':
            extension = _decode_aarch64_dczva(self._target.read_instructions(address, 4), self.arch, address)
            if extension is not None:
                return Instruction(extension, self.machine, self.arch, self.loc_db)
        return Instruction(miasm_instr, self.machine, self.arch, self.loc_db)


def run_instruction(
    instr: miasm_instr, conc_state: MiasmSymbolResolver, lifter: Lifter
) -> tuple[ExprInt | None, dict[Expr, Expr]]:
    """Compute the symbolic equation of a single instruction.

    The concolic engine tries to express the instruction's equation as
    independent of the concrete state as possible.

    May fail if the instruction is not supported. Failure is signalled by
    returning `None` as the next program counter.

    :param instr:      The instruction to run.
    :param conc_state: A concrete reference state at `pc = instr.offset`. Used
                       to resolve symbolic program counters, i.e. to 'guide'
                       the symbolic execution on the correct path. This is the
                       concrete part of our concolic execution.
    :param lifter:     A lifter of the appropriate architecture. Get this from
                       a `DisassemblyContext` or a `Machine`.

    :return: The next program counter and a symbolic state. The PC is None if
             an error occurs or when the program exits. The returned state
             is `instr`'s symbolic transformation.
    """
    from miasm.expression.expression import ExprCond, LocKey
    from miasm.expression.simplifications import expr_simp

    def create_cond_state(cond: Expr, iftrue: dict, iffalse: dict) -> dict:
        """Combines states that are to be reached conditionally.

        Example:
            State A:
                RAX          = 0x42
                @[RBP - 0x4] = 0x123
            State B:
                RDI          = -0x777
                @[RBP - 0x4] = 0x5c32
            Condition:
                RCX > 0x4 ? A : B

            Result State:
                RAX          = (RCX > 0x4) ? 0x42 : RAX
                RDI          = (RCX > 0x4) ? RDI : -0x777
                @[RBP - 0x4] = (RCX > 0x4) ? 0x123 : 0x5c32
        """
        res = {}
        for dst, v in iftrue.items():
            if dst not in iffalse:
                res[dst] = expr_simp(ExprCond(cond, v, dst))
            else:
                res[dst] = expr_simp(ExprCond(cond, v, iffalse[dst]))
        for dst, v in iffalse.items():
            if dst not in iftrue:
                res[dst] = expr_simp(ExprCond(cond, dst, v))
        return res

    def _execute_location(loc, base_state: dict | None) -> tuple[Expr, dict]:
        """Execute a single IR block via symbolic engine. No fancy stuff."""
        # Query the location's IR block
        irblock = ircfg.get_block(loc)
        if irblock is None:
            return loc, base_state if base_state is not None else {}

        # Apply IR block to the current state
        engine = SymbolicExecutionEngine(lifter, state=base_state)
        new_pc = engine.eval_updt_irblock(irblock)
        modified = dict(engine.modified())
        return new_pc, modified

    def execute_location(loc: Expr | LocKey) -> tuple[ExprInt, dict]:
        """Execute chains of IR blocks until a concrete program counter is
        reached."""
        seen_locs = set()  # To break out of loop instructions
        new_pc, modified = _execute_location(loc, None)

        # Run chained IR blocks until a real program counter is reached.
        # This used to be recursive (and much more elegant), but large RCX
        # values for 'REP ...' instructions could make the stack overflow.
        while not new_pc.is_int():
            seen_locs.add(new_pc)

            if new_pc.is_loc():
                # Jump to the next location.
                new_pc, modified = _execute_location(new_pc, modified)
            elif new_pc.is_cond():
                # Explore conditional paths manually by constructing
                # conditional states based on the possible outcomes.
                if not isinstance(new_pc, ExprCond):
                    raise SymbolEvaluationError(
                        f"Conditional program counter has invalid type {type(new_pc)!r}."
                    )
                cond = new_pc.cond
                pc_iftrue, pc_iffalse = new_pc.src1, new_pc.src2

                pc_t, state_t = _execute_location(pc_iftrue, modified.copy())
                pc_f, state_f = _execute_location(pc_iffalse, modified.copy())
                modified = create_cond_state(cond, state_t, state_f)
                new_pc = expr_simp(ExprCond(cond, pc_t, pc_f))
            else:
                # Concretisize PC in case it is, e.g., a memory expression
                new_pc = eval_expr(new_pc, conc_state)

            # Avoid infinite loops for loop instructions (REP ...) by making
            # the jump to the next loop iteration (or exit) concrete.
            if new_pc in seen_locs:
                new_pc = eval_expr(new_pc, conc_state)
                seen_locs.clear()

        if not isinstance(new_pc, ExprInt):
            raise SymbolEvaluationError(f"Program counter remains unresolved as {new_pc!r}.")
        return new_pc, modified

    if isinstance(instr, _X86AvxLogic):
        instr.validate()
        if str(lifter.pc) != 'RIP' or lifter.attrib != 64:
            raise UnsupportedInstructionError('AVX logic requires an x86-64 lifter.')
        next_pc = ExprInt(instr.offset + instr.l, 64)
        outputs = {lifter.pc: next_pc, lifter.IRDst: next_pc}
        if instr.name == 'VZEROUPPER':
            outputs.update({ExprId(f'ZMM{n}', 512): ExprId(f'XMM{n}', 128).zeroExtend(512)
                            for n in range(16)})
        elif instr.name in ('VPXOR', 'VXORPS'):
            outputs[ExprId('ZMM0', 512)] = expr_simp(instr.args[1] ^ instr.args[2]).zeroExtend(512)
        else:
            lhs, rhs = instr.args
            outputs[ExprId('zf', 1)] = expr_simp(ExprCond(lhs & rhs, ExprInt(0, 1), ExprInt(1, 1)))
            outputs[ExprId('cf', 1)] = expr_simp(ExprCond((lhs ^ ExprInt((1 << 256) - 1, 256)) & rhs,
                                                       ExprInt(0, 1), ExprInt(1, 1)))
            outputs.update({ExprId(flag, 1): ExprInt(0, 1) for flag in ('of', 'sf', 'af', 'pf')})
        return next_pc, outputs

    if isinstance(instr, _X86Vmovdqa):
        instr.validate()
        if instr.mode != 64 or str(lifter.pc) != 'RIP' or instr.l != len(instr.additional_info):
            raise UnsupportedInstructionError('VMOVDQA requires an x86-64 lifter and exact encoding.')
        dst, src = instr.args
        memory = src if isinstance(src, ExprMem) else dst
        value = src + ExprOp('x86_aligned_vector256', memory.ptr).zeroExtend(256)
        if isinstance(dst, ExprId):
            dst, value = ExprId('ZMM0', 512), value.zeroExtend(512)
        next_pc = ExprInt(instr.offset + instr.l, 64)
        return next_pc, {dst: value, lifter.pc: next_pc, lifter.IRDst: next_pc}

    if isinstance(instr, _AArch64DcZva):
        if instr.mode != 'l' or lifter.attrib != 'l' or str(lifter.pc) != 'PC' or instr.l != 4:
            raise UnsupportedInstructionError('DC ZVA requires a matching little-endian AArch64 lifter.')
        # The observed musl path uses permitted 64-byte blocks (DCZID=4).
        # Keep that requirement in the expression, so the emulator must supply
        # its OWN capability. Different sizes/DZP never become an assumed zero.
        address = instr.args[0] & ExprInt((1 << 64) - 64, 64)
        capability = ExprId('DCZID_EL0', 64)
        guard = ExprOp('aarch64_dczva_zero64', capability)
        zero = guard.zeroExtend(512)
        next_pc = ExprInt(instr.offset + 4, 64)
        # A guarded identity is a postcondition, not a system-register write.
        # It preserves the capability obligation if later stores overwrite all
        # zeroed bytes during cutpoint composition.
        return next_pc, {ExprMem(address, 512): zero, capability: capability + guard,
                         lifter.pc: next_pc, lifter.IRDst: next_pc}

    if isinstance(instr, _AArch64DupGeneral):
        if instr.mode != 'l' or lifter.attrib != 'l' or str(lifter.pc) != 'PC' or instr.l != 4:
            raise UnsupportedInstructionError('AArch64 DUP requires its matching little-endian lifter and length.')
        source = instr.args[1]
        element = source if source.size == instr.element_width else source[:instr.element_width]
        value = ExprCompose(*([element] * (instr.vector_width // instr.element_width))).zeroExtend(128)
        next_pc = ExprInt(instr.offset + 4, 64)
        return next_pc, {instr.args[0]: value, lifter.pc: next_pc, lifter.IRDst: next_pc}

    # Lift and execute the instruction through one typed unsupported boundary.
    ircfg = lifter.new_ircfg()
    try:
        loc = lifter.add_instr_to_ircfg(instr, ircfg, None, False)
        if not isinstance(loc, (Expr, LocKey)):
            raise UnsupportedInstructionError(
                f"Lifter returned an invalid location for {instr}: {loc!r}."
            )
        new_pc, modified = execute_location(loc)
    except UnsupportedInstructionError:
        raise
    except NotImplementedError as err:
        raise UnsupportedInstructionError(f"Unable to execute instruction {instr}: {err}") from err

    modified[lifter.pc] = new_pc  # Add PC update to state
    return new_pc, modified
