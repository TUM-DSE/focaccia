"""Specification-derived AArch64 semantics through the packaged Rust oracle.

Miasm expressions remain Focaccia's shared expression representation; this
backend never calls the Miasm instruction lifter. Unsupported oracle results
remain explicit failures, including when the Miasm backend supports the opcode.
"""

from __future__ import annotations

from collections import OrderedDict
import json
import math
import os
import re
import subprocess

from miasm.expression.expression import Expr, ExprCompose, ExprCond, ExprId, ExprInt, ExprMem, ExprOp

from focaccia.snapshot import ReadableProgramState
from focaccia.symbolic import (
    DisassemblyContext,
    Instruction,
    SymbolEvaluationError,
    UnsupportedInstructionError,
    eval_symbol,
)

_REGISTERS = {
    **{f"X{i}": 64 for i in range(31)},
    **{f"V{i}": 128 for i in range(32)},
    "SP": 64,
    "PC": 64,
    "N": 1,
    "Z": 1,
    "C": 1,
    "V": 1,
    "TPIDR": 64,
}


def _object_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate oracle field {key!r}")
        result[key] = value
    return result


def _fields(value: object, expected: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("Unexpected oracle expression fields")
    return value


class _ExpressionDecoder:
    def __init__(self) -> None:
        # The response is already capped at 1 MiB. Extended-register flag
        # semantics legitimately repeat a ~1,100-node carry/overflow cone for
        # N/Z/C/V, so the old 4,096 aggregate budget rejected an audited musl
        # CMP despite shallow depth and bounded wire size.
        self.remaining = 65_536

    def decode(self, node: object, depth: int = 0) -> Expr:
        self.remaining -= 1
        if self.remaining < 0 or depth > 64:
            raise ValueError("Oracle expression exceeds size/depth limit")
        if not isinstance(node, dict):
            raise ValueError("Oracle expression must be an object")
        bits = node.get("bits")
        if type(bits) is not int or not 1 <= bits <= 2048:
            raise ValueError("Unsupported oracle bit width")
        kind = node.get("kind")
        common = {"kind", "bits"}
        if kind == "constant":
            _fields(node, common | {"value"})
            raw = node["value"]
            if not isinstance(raw, str) or re.fullmatch(r"0x[0-9a-f]{1,512}", raw) is None:
                raise ValueError("Malformed oracle bitvector constant")
            value = int(raw, 16)
            if value >= 1 << bits:
                raise ValueError("Oracle constant exceeds its bit width")
            return ExprInt(value, bits)
        if kind == "register":
            _fields(node, common | {"name"})
            name = node["name"]
            if not isinstance(name, str) or name not in _REGISTERS:
                raise ValueError("Unsupported architectural input register")
            register_bits = _REGISTERS[name]
            if bits == register_bits:
                return ExprId(name, bits)
            if name.startswith("V") and register_bits == 128 and bits > 128:
                return ExprId(name, 128).zeroExtend(bits)
            raise ValueError("Unsupported architectural input register width")
        if kind == "binary":
            _fields(node, common | {"op", "left", "right"})
            left = self.decode(node["left"], depth + 1)
            right = self.decode(node["right"], depth + 1)
            op = node["op"]
            if op not in (
                "add",
                "sub",
                "mul",
                "eq",
                "ne",
                "ugt",
                "ult",
                "uge",
                "ule",
                "and",
                "or",
                "xor",
                "shl",
                "lshr",
                "ashr",
            ):
                raise ValueError("Unsupported oracle binary operation")
            expected_bits = 1 if op in ("eq", "ne", "ugt", "ult", "uge", "ule") else left.size
            if left.size != right.size or bits != expected_bits:
                raise ValueError("Oracle binary operation width mismatch")
            if op == "sub":
                return left - right
            if op in ("shl", "lshr", "ashr"):
                names = {"shl": "<<", "lshr": ">>", "ashr": "a>>"}
                return ExprOp(names[op], left, right)
            if op in ("eq", "ne"):
                # XOR is zero exactly on equality; ExprCond tests nonzero.
                unequal = ExprInt(int(op == "ne"), 1)
                equal = ExprInt(int(op == "eq"), 1)
                return ExprCond(left ^ right, unequal, equal)
            if op in ("ugt", "ult", "uge", "ule"):
                if op == "ugt":
                    left, right, comparison = right, left, "<u"
                elif op == "uge":
                    left, right, comparison = right, left, "<=u"
                else:
                    comparison = "<u" if op == "ult" else "<=u"
                return ExprOp(comparison, left, right)
            names = {"add": "+", "mul": "*", "and": "&", "or": "|", "xor": "^"}
            return ExprOp(names[op], left, right)
        if kind == "unary":
            _fields(node, common | {"op", "value"})
            value = self.decode(node["value"], depth + 1)
            if node["op"] != "not" or value.size != bits:
                raise ValueError("Unsupported oracle unary operation")
            return value ^ ExprInt((1 << bits) - 1, bits)
        if kind == "concat":
            _fields(node, common | {"high", "low"})
            high = self.decode(node["high"], depth + 1)
            low = self.decode(node["low"], depth + 1)
            if high.size + low.size != bits:
                raise ValueError("Oracle concatenation width mismatch")
            return ExprCompose(low, high)
        if kind == "slice":
            _fields(node, common | {"value", "start"})
            value = self.decode(node["value"], depth + 1)
            start = node["start"]
            if type(start) is not int or start < 0 or start + bits > value.size:
                raise ValueError("Invalid oracle bit slice")
            return value[start : start + bits]
        if kind == "ite":
            _fields(node, common | {"condition", "then_value", "else_value"})
            condition = self.decode(node["condition"], depth + 1)
            lhs = self.decode(node["then_value"], depth + 1)
            rhs = self.decode(node["else_value"], depth + 1)
            if condition.size != 1 or lhs.size != bits or rhs.size != bits:
                raise ValueError("Oracle conditional width mismatch")
            return ExprCond(condition, lhs, rhs)
        if kind == "memory":
            _fields(node, common | {"address"})
            address = self.decode(node["address"], depth + 1)
            if not 1 <= address.size <= 64 or bits % 8:
                raise ValueError("Oracle memory read width mismatch")
            return ExprMem(address.zeroExtend(64), bits)
        raise ValueError(f"Unsupported oracle expression kind {kind!r}")


def decode_response(text: str, pc: int, code: bytes) -> tuple[Expr, dict[Expr, Expr]]:
    """Validate the versioned response before constructing shared expressions."""
    if len(text) > 1_048_576:
        raise SymbolEvaluationError("TIR response exceeds the size limit")
    try:
        response = json.loads(text, object_pairs_hook=_object_pairs)
        common = {
            "schema",
            "architecture",
            "endianness",
            "pc",
            "instruction",
            "tir_revision",
            "profile",
            "status",
        }
        if not isinstance(response, dict):
            raise ValueError("Oracle response must be an object")
        status = response.get("status")
        if status not in ("ok", "unsupported"):
            raise ValueError("Unknown oracle status")
        _fields(response, common | ({"outputs", "memory_writes"} if status == "ok" else {"reason"}))
        if (
            type(response["schema"]) is not int
            or response["schema"] != 1
            or response["architecture"] != "aarch64"
            or response["endianness"] != "little"
            or response["profile"] != "aarch64-fullspec-el0"
            or response["pc"] != str(pc)
            or response["instruction"] != code.hex()
        ):
            raise ValueError(
                "Oracle response does not match the requested instruction/configuration"
            )
        revision = response["tir_revision"]
        if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
            raise ValueError("Malformed oracle revision")
        if status == "unsupported":
            reason = response["reason"]
            if not isinstance(reason, str) or not reason or len(reason) > 4096:
                raise ValueError("Malformed unsupported-instruction diagnostic")
            raise UnsupportedInstructionError(f"TIR: {reason}")
        outputs = response["outputs"]
        if not isinstance(outputs, dict) or not outputs or len(outputs) > len(_REGISTERS):
            raise ValueError("Malformed architectural outputs")
        decoder = _ExpressionDecoder()
        result = {}
        for name, expression in outputs.items():
            if name not in _REGISTERS:
                raise ValueError(f"Unsupported architectural output {name!r}")
            expr = decoder.decode(expression)
            if expr.size != _REGISTERS[name]:
                raise ValueError(f"Wrong output width for {name}")
            result[ExprId(name, expr.size)] = expr
        writes = response["memory_writes"]
        if not isinstance(writes, list) or len(writes) > 16:
            raise ValueError("Malformed architectural memory writes")
        for write in writes:
            _fields(write, {"address", "value"})
            address = decoder.decode(write["address"])
            value = decoder.decode(write["value"])
            if not 1 <= address.size <= 64 or value.size % 8:
                raise ValueError("Malformed architectural memory write")
            result[ExprMem(address.zeroExtend(64), value.size)] = value
        next_pc = result.get(ExprId("PC", 64))
        if next_pc is None or next_pc.size != 64:
            raise ValueError("Missing or malformed PC transition")
        return next_pc, result
    except (ValueError, KeyError, TypeError, RecursionError) as error:
        raise SymbolEvaluationError(f"Invalid TIR oracle response: {error}") from error


class TirBackend:
    """AArch64 little-endian immediate arithmetic, with explicit unsupported gaps."""

    name = "tir"

    def __init__(
        self, executable: str | None = None, *, timeout: float = 120.0, cache_size: int = 128
    ) -> None:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Oracle timeout must be finite and positive")
        if type(cache_size) is not int or cache_size < 0:
            raise ValueError("Oracle cache size must be nonnegative")
        self.executable = executable or os.environ.get("FOCACCIA_TIR_ORACLE", "focaccia-tir-oracle")
        self.timeout = timeout
        self.cache_size = cache_size
        self._cache: OrderedDict[tuple[int, bytes], tuple[Expr, dict[Expr, Expr]]] = OrderedDict()

    def generate(
        self, instruction: Instruction, state: ReadableProgramState, context: DisassemblyContext
    ) -> tuple[ExprInt | None, dict[Expr, Expr]]:
        arch = instruction.arch
        if (
            arch.archname != "aarch64"
            or arch.endianness != "little"
            or arch.ptr_size != 64
            or state.arch != arch
            or context.arch != arch
        ):
            raise UnsupportedInstructionError(
                "TIR backend requires matching little-endian AArch64 state"
            )
        pc = instruction.addr
        if type(pc) is not int or not 0 <= pc < (1 << 64) - 4 or pc % 4 or instruction.length != 4:
            raise UnsupportedInstructionError(
                "TIR backend requires one aligned four-byte instruction"
            )
        code = state.read_instructions(pc, 4)
        if len(code) != 4:
            raise SymbolEvaluationError("Incomplete instruction bytes for TIR oracle")
        key = (pc, bytes(code))
        if key in self._cache:
            self._cache.move_to_end(key)
            next_pc, cached_outputs = self._cache[key]
            outputs = cached_outputs.copy()
        else:
            # The bridge has a fixed profile. Do not inherit experimental
            # translator settings or an unpinned AST from a development shell.
            env = {
                k: v
                for k, v in os.environ.items()
                if not k.startswith(("TIR_", "TIRAMISU_", "FOCACCIA_TIR_MODULE"))
            }
            try:
                completed = subprocess.run(
                    [self.executable, str(pc), code.hex()],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    env=env,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired, UnicodeError) as error:
                raise SymbolEvaluationError(f"Unable to execute TIR oracle: {error}") from error
            if completed.returncode != 0:
                diagnostic = completed.stderr[-4096:].strip()
                raise SymbolEvaluationError(
                    f"TIR oracle failed ({completed.returncode}): {diagnostic}"
                )
            next_pc, outputs = decode_response(completed.stdout, pc, code)
            if self.cache_size:
                self._cache[key] = (next_pc, outputs.copy())
                while len(self._cache) > self.cache_size:
                    self._cache.popitem(last=False)
        outputs[context.lifter.IRDst] = next_pc
        concrete_next_pc = ExprInt(eval_symbol(next_pc, state), 64)
        return concrete_next_pc, outputs
