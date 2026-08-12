"""Versioned trace persistence with strict JSON and streaming MessagePack readers.

Schema-v3 MessagePack files begin with ``MSGPACK_MAGIC`` and encode each map as
an unsigned 64-bit big-endian length followed by one MessagePack payload.  This
framing makes truncation and trailing data distinguishable while retaining
one-transform-at-a-time decoding.
"""

from __future__ import annotations

import base64
import binascii
import copy
from collections import OrderedDict
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from itertools import chain
from os import PathLike
from struct import Struct
from typing import BinaryIO, Literal, TextIO, cast

import msgpack
import orjson as json
from miasm.expression.expression import Expr
from miasm.expression.parser import str_to_expr

from .arch import Arch, supported_architectures
from .arch.arch import ArchitectureKey
from .snapshot import ProgramState, RegisterAccessError
from .symbolic import (
    GapReason,
    Instruction,
    InstructionRecord,
    MemoryWrite,
    SymbolicTraceItem,
    SymbolicTransform,
    TraceGap,
)
from .trace import MaterializedTrace, TraceEnvironment, TransformStream

SCHEMA_VERSION = 3
SUPPORTED_SCHEMA_VERSIONS = (2, SCHEMA_VERSION)
TraceKind = Literal["states", "transforms"]

MAX_JSON_CHARS = 64 * 1024 * 1024
MAX_MSGPACK_BUFFER_BYTES = 64 * 1024 * 1024
MAX_MSGPACK_FRAME_BYTES = 64 * 1024 * 1024
MSGPACK_MAGIC = b"Focaccia\x00MessagePack\n"
_MSGPACK_FRAME_LENGTH = Struct(">Q")
MAX_TRACE_ITEMS = 100_000_000
MAX_MEMORY_RANGE_BYTES = 64 * 1024 * 1024
MAX_EXPRESSION_CHARS = 1024 * 1024
MAX_INSTRUCTION_TEXT_CHARS = 1024 * 1024
MAX_INSTRUCTION_LENGTH = 64
MAX_INSTRUCTIONS_PER_TRANSFORM = 1_000_000
MAX_GAP_MESSAGE_CHARS = 1024 * 1024
MAX_ADDRESS = (1 << 64) - 1
MAX_RANGE_END = 1 << 64
_STREAM_EXPRESSION_CACHE_SIZE = 65_536
_STREAM_INSTRUCTION_CACHE_SIZE = 16_384


class ParseError(ValueError):
    """Base class for persisted-trace decoding and validation failures."""


class TraceDecodeError(ParseError):
    pass


class MissingFieldError(ParseError):
    pass


class FieldTypeError(ParseError):
    pass


class UnsupportedSchemaVersionError(ParseError):
    pass


class TraceKindError(ParseError):
    pass


class ArchitectureParseError(ParseError):
    pass


class AmbiguousArchitectureError(ArchitectureParseError):
    pass


class TraceCardinalityError(ParseError):
    pass


class TraceLimitError(ParseError):
    pass


class StateParseError(ParseError):
    pass


class TransformParseError(ParseError):
    pass


class ExpressionWidthError(TransformParseError):
    pass


class InstructionParseError(TransformParseError):
    pass


class TruncatedTraceError(ParseError):
    pass


@dataclass(frozen=True)
class _TraceHeader:
    version: int
    kind: TraceKind
    architecture: Arch
    environment: TraceEnvironment
    addresses: tuple[int, ...] | None
    item_count: int


def _required(document: Mapping, key: str, path: str) -> object:
    if key not in document:
        raise MissingFieldError(f"Missing required field {path}.{key}.")
    return document[key]


def _mapping(value: object, path: str) -> Mapping:
    if not isinstance(value, Mapping):
        raise FieldTypeError(f"{path} must be an object.")
    return value


def _list(value: object, path: str) -> list:
    if not isinstance(value, list):
        raise FieldTypeError(f"{path} must be an array.")
    return value


def _string(value: object, path: str, *, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str):
        expected = "a string or null" if allow_none else "a string"
        raise FieldTypeError(f"{path} must be {expected}.")
    return value


def _integer(
    value: object,
    path: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FieldTypeError(f"{path} must be an integer.")
    if minimum is not None and value < minimum:
        raise FieldTypeError(f"{path} must be at least {minimum}.")
    if maximum is not None and value > maximum:
        raise FieldTypeError(f"{path} must be at most {maximum}.")
    return value


def _optional_integer(value: object, path: str) -> int | None:
    if value is None:
        return None
    return _integer(value, path, minimum=0, maximum=MAX_ADDRESS)


def _string_array(value: object, path: str) -> tuple[str, ...]:
    values = _list(value, path)
    result = []
    for index, item in enumerate(values):
        parsed = _string(item, f"{path}[{index}]")
        assert parsed is not None
        result.append(parsed)
    return tuple(result)


def _read_json_document(stream: TextIO) -> Mapping:
    encoded = stream.read(MAX_JSON_CHARS + 1)
    if len(encoded) > MAX_JSON_CHARS:
        raise TraceLimitError(f"JSON trace exceeds the {MAX_JSON_CHARS}-character input limit.")
    try:
        document = json.loads(encoded)
    except json.JSONDecodeError as error:
        raise TraceDecodeError(f"Invalid JSON trace: {error}.") from error
    return _mapping(document, "trace")


def _architecture_from_id(value: object, path: str, *, legacy: bool = False) -> Arch:
    architecture_id = _string(value, path)
    assert architecture_id is not None
    if architecture_id == "aarch64":
        raise AmbiguousArchitectureError(
            "Legacy architecture 'aarch64' does not preserve endianness; "
            "use an explicitly identified aarch64l/aarch64b trace."
        )
    try:
        architecture = supported_architectures[architecture_id]
    except KeyError as error:
        raise ArchitectureParseError(
            f"Unsupported architecture identifier at {path}: {architecture_id}."
        ) from error
    if architecture.serialized_name != architecture_id:
        context = "legacy " if legacy else ""
        raise ArchitectureParseError(
            f"Non-canonical {context}architecture identifier at {path}: {architecture_id}."
        )
    return architecture


def _resolve_legacy_architecture(
    value: object,
    path: str,
    environment_architecture: Arch | None,
) -> Arch:
    architecture_id = _string(value, path)
    assert architecture_id is not None
    if architecture_id == "aarch64":
        if environment_architecture is None or environment_architecture.isa != "aarch64":
            raise AmbiguousArchitectureError(
                "Legacy architecture 'aarch64' does not preserve endianness and "
                "has no explicit environment identity."
            )
        return environment_architecture

    architecture = _architecture_from_id(value, path, legacy=True)
    if environment_architecture is not None and environment_architecture != architecture:
        raise ArchitectureParseError(
            f"Legacy architecture {architecture} conflicts with environment "
            f"architecture {environment_architecture}."
        )
    return architecture


def _architecture_from_key(key: ArchitectureKey) -> Arch:
    matches = {
        architecture for architecture in supported_architectures.values() if architecture.key == key
    }
    if len(matches) != 1:
        raise ArchitectureParseError(f"No unique registered architecture for {key}.")
    return next(iter(matches))


def _parse_environment(
    value: object,
    architecture: Arch,
    *,
    legacy: bool,
) -> TraceEnvironment:
    document = _mapping(value, "trace.environment")
    binary_name = _string(
        _required(document, "binary_name", "trace.environment"),
        "trace.environment.binary_name",
        allow_none=True,
    )
    binary_hash = _string(
        _required(document, "binary_hash", "trace.environment"),
        "trace.environment.binary_hash",
        allow_none=True,
    )
    argv = _string_array(
        _required(document, "argv", "trace.environment"),
        "trace.environment.argv",
    )
    envp = _string_array(
        _required(document, "envp", "trace.environment"),
        "trace.environment.envp",
    )

    if legacy:
        start_address = _optional_integer(
            document.get("start_address"), "trace.environment.start_address"
        )
        stop_address = _optional_integer(
            document.get("stop_address"), "trace.environment.stop_address"
        )
        replay_provenance = _string(
            document.get("replay_provenance"),
            "trace.environment.replay_provenance",
            allow_none=True,
        )
    else:
        start_address = _optional_integer(
            _required(document, "start_address", "trace.environment"),
            "trace.environment.start_address",
        )
        stop_address = _optional_integer(
            _required(document, "stop_address", "trace.environment"),
            "trace.environment.stop_address",
        )
        replay_provenance = _string(
            _required(document, "replay_provenance", "trace.environment"),
            "trace.environment.replay_provenance",
            allow_none=True,
        )

    if start_address is not None and stop_address is not None and start_address > stop_address:
        raise TraceCardinalityError("trace.environment.start_address must not exceed stop_address.")

    architecture_document = document.get("architecture")
    if architecture_document is None:
        if not legacy:
            raise MissingFieldError("Missing required field trace.environment.architecture.")
    else:
        encoded_architecture = _mapping(architecture_document, "trace.environment.architecture")
        isa = _string(
            _required(encoded_architecture, "isa", "trace.environment.architecture"),
            "trace.environment.architecture.isa",
        )
        endianness = _string(
            _required(
                encoded_architecture,
                "endianness",
                "trace.environment.architecture",
            ),
            "trace.environment.architecture.endianness",
        )
        if (isa, endianness) != (architecture.isa, architecture.endianness):
            raise ArchitectureParseError(
                "Trace environment architecture conflicts with the top-level "
                f"architecture {architecture.serialized_name}."
            )

    return TraceEnvironment(
        binary_name,
        argv,
        envp,
        binary_hash=binary_hash,
        start_address=start_address,
        stop_address=stop_address,
        replay_provenance=replay_provenance,
        architecture=architecture.key,
    )


def _parse_addresses(
    value: object,
    item_count: int,
    kind: TraceKind,
) -> tuple[int, ...] | None:
    if value is None:
        if kind == "transforms":
            raise TraceCardinalityError("Transform traces require an address index.")
        return None
    encoded = _list(value, "trace.addresses")
    addresses = tuple(
        _integer(
            item,
            f"trace.addresses[{index}]",
            minimum=0,
            maximum=MAX_ADDRESS,
        )
        for index, item in enumerate(encoded)
    )
    if len(addresses) != item_count:
        raise TraceCardinalityError(
            f"Trace address count does not match item_count: {len(addresses)} != {item_count}."
        )
    return addresses


def _parse_versioned_header(document: Mapping, expected_kind: TraceKind) -> _TraceHeader:
    version = _integer(
        _required(document, "schema_version", "trace"),
        "trace.schema_version",
        minimum=0,
    )
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        supported = ", ".join(str(item) for item in SUPPORTED_SCHEMA_VERSIONS)
        raise UnsupportedSchemaVersionError(
            f"Unsupported trace schema version {version}; supported versions: {supported}."
        )

    kind_value = _string(_required(document, "trace_kind", "trace"), "trace.trace_kind")
    if kind_value not in ("states", "transforms"):
        raise TraceKindError(f"Unsupported trace kind: {kind_value}.")
    if kind_value != expected_kind:
        raise TraceKindError(
            f"Expected a {expected_kind} trace, but document contains {kind_value}."
        )
    kind: TraceKind = kind_value

    item_count = _integer(
        _required(document, "item_count", "trace"),
        "trace.item_count",
        minimum=0,
    )
    if item_count > MAX_TRACE_ITEMS:
        raise TraceLimitError(f"trace.item_count exceeds the {MAX_TRACE_ITEMS}-item limit.")
    architecture = _architecture_from_id(
        _required(document, "architecture", "trace"),
        "trace.architecture",
    )
    environment = _parse_environment(
        _required(document, "environment", "trace"),
        architecture,
        legacy=False,
    )
    addresses = _parse_addresses(_required(document, "addresses", "trace"), item_count, kind)
    return _TraceHeader(version, kind, architecture, environment, addresses, item_count)


def _header_document(
    kind: TraceKind,
    architecture: Arch,
    environment: TraceEnvironment,
    addresses: tuple[int, ...] | None,
    item_count: int,
) -> dict:
    if item_count > MAX_TRACE_ITEMS:
        raise TraceLimitError(f"Trace exceeds the {MAX_TRACE_ITEMS}-item limit.")
    encoded_addresses = list(addresses) if addresses is not None else None
    _parse_addresses(encoded_addresses, item_count, kind)
    encoded_environment = environment.to_json()
    _parse_environment(encoded_environment, architecture, legacy=False)
    return {
        "schema_version": SCHEMA_VERSION,
        "trace_kind": kind,
        "architecture": architecture.serialized_name,
        "environment": encoded_environment,
        "addresses": encoded_addresses,
        "item_count": item_count,
    }


def _trace_architecture(
    trace: MaterializedTrace,
    *,
    item_kind: str,
) -> tuple[Arch, TraceEnvironment]:
    if trace:
        architecture = trace[0].arch
        for index, item in enumerate(trace[1:], start=1):
            if item.arch != architecture:
                raise ArchitectureParseError(
                    f"{item_kind} trace item {index} has architecture {item.arch}, "
                    f"expected {architecture}."
                )
    else:
        if trace.env.architecture is None:
            raise ArchitectureParseError(
                f"An empty {item_kind} trace requires architecture metadata."
            )
        architecture = _architecture_from_key(trace.env.architecture)

    try:
        environment = trace.env.with_architecture(architecture.key)
    except ValueError as error:
        raise ArchitectureParseError(str(error)) from error
    return architecture, environment


def _decode_state(value: object, architecture: Arch, path: str, *, legacy: bool) -> ProgramState:
    document = _mapping(value, path)
    registers = _mapping(_required(document, "registers", path), f"{path}.registers")
    register_validity: Mapping[object, object] | None = None
    if not legacy:
        register_validity = _mapping(
            _required(document, "register_validity", path),
            f"{path}.register_validity",
        )
        if set(register_validity) != set(registers):
            raise StateParseError(
                f"{path}.registers and {path}.register_validity must have the same keys."
            )
    memory = _list(_required(document, "memory", path), f"{path}.memory")
    state = ProgramState(architecture)

    known_masks: dict[str, int] = {}
    known_values: dict[str, int] = {}
    for encoded_name, encoded_value in registers.items():
        if not isinstance(encoded_name, str):
            raise FieldTypeError(f"{path}.registers keys must be strings.")
        normalized = architecture.to_regname(encoded_name)
        if normalized is None:
            raise StateParseError(f"Unknown register {encoded_name} at {path}.registers.")
        if not legacy and normalized != encoded_name:
            raise StateParseError(
                f"Register {encoded_name} at {path}.registers is not canonical ({normalized})."
            )
        accessor = architecture.get_reg_accessor(normalized)
        assert accessor is not None
        register_value = _integer(
            encoded_value,
            f"{path}.registers.{encoded_name}",
            minimum=0,
        )
        if register_value >= 1 << accessor.num_bits:
            raise StateParseError(f"Value {register_value} does not fit in register {normalized}.")

        if architecture.is_constant_register(normalized):
            if not legacy:
                raise StateParseError(
                    f"Version 2 state must not persist constant register {normalized}."
                )
            expected = architecture.get_constant_register_value(normalized)
            if register_value != expected:
                raise StateParseError(
                    f"Constant register {normalized} has impossible value {register_value}."
                )
            continue

        if not legacy:
            if accessor.base_reg != normalized:
                raise StateParseError(
                    f"Version 2 state register {normalized} must use base-register storage."
                )
            assert register_validity is not None
            valid_mask = _integer(
                register_validity[encoded_name],
                f"{path}.register_validity.{encoded_name}",
                minimum=1,
            )
            if valid_mask >= 1 << accessor.num_bits:
                raise StateParseError(f"Validity mask for {normalized} does not fit its width.")
            if register_value & ~valid_mask:
                raise StateParseError(
                    f"Value for {normalized} sets bits outside its validity mask."
                )
            state.write_register_bits(normalized, register_value, valid_mask)
            continue

        shifted = register_value << accessor.start
        previous_mask = known_masks.get(accessor.base_reg, 0)
        previous_value = known_values.get(accessor.base_reg, 0)
        overlap = previous_mask & accessor.mask
        if previous_value & overlap != shifted & overlap:
            raise StateParseError(
                f"Conflicting aliases for register {accessor.base_reg} at {path}.registers."
            )
        known_masks[accessor.base_reg] = previous_mask | accessor.mask
        known_values[accessor.base_reg] = (previous_value & ~accessor.mask) | (
            shifted & accessor.mask
        )
        state.write_register(normalized, register_value)

    ranges: list[tuple[int, int]] = []
    for index, encoded_range in enumerate(memory):
        memory_path = f"{path}.memory[{index}]"
        entry = _mapping(encoded_range, memory_path)
        bounds = _list(_required(entry, "range", memory_path), f"{memory_path}.range")
        if len(bounds) != 2:
            raise StateParseError(f"{memory_path}.range must contain [start, end].")
        start = _integer(
            bounds[0],
            f"{memory_path}.range[0]",
            minimum=0,
            maximum=MAX_ADDRESS,
        )
        end = _integer(
            bounds[1],
            f"{memory_path}.range[1]",
            minimum=0,
            maximum=MAX_RANGE_END,
        )
        if end <= start:
            raise StateParseError(f"{memory_path}.range must be non-empty and increasing.")
        size = end - start
        if size > MAX_MEMORY_RANGE_BYTES:
            raise TraceLimitError(
                f"{memory_path} exceeds the {MAX_MEMORY_RANGE_BYTES}-byte range limit."
            )
        for previous_start, previous_end in ranges:
            if start < previous_end and previous_start < end:
                raise StateParseError(f"{memory_path} overlaps another memory range.")

        encoded_data = _string(_required(entry, "data", memory_path), f"{memory_path}.data")
        assert encoded_data is not None
        try:
            data = base64.b64decode(encoded_data, validate=True)
        except (binascii.Error, ValueError) as error:
            raise StateParseError(f"Invalid base64 data at {memory_path}.data.") from error
        if len(data) != size:
            raise StateParseError(f"{memory_path} declares {size} bytes but contains {len(data)}.")
        ranges.append((start, end))
        state.write_memory(start, data)

    return state


def _encode_state(
    state: ProgramState,
    architecture: Arch,
    path: str,
) -> dict:
    register_bits = state.known_register_bits()
    registers = {name: value for name, (value, _) in register_bits.items()}
    register_validity = {name: valid_mask for name, (_, valid_mask) in register_bits.items()}
    memory = [
        {
            "range": [address, address + len(data)],
            "data": base64.b64encode(data).decode("ascii"),
        }
        for address, data in state.mem.known_ranges()
    ]
    document = {
        "registers": registers,
        "register_validity": register_validity,
        "memory": memory,
    }
    _decode_state(document, architecture, path, legacy=False)
    return document


def _validate_state_addresses(
    states: Sequence[ProgramState], addresses: tuple[int, ...] | None
) -> None:
    if addresses is None:
        return
    for index, (state, address) in enumerate(zip(states, addresses, strict=True)):
        try:
            pc = state.read_pc()
        except RegisterAccessError as error:
            raise StateParseError(
                f"State {index} has an address index but no known program counter."
            ) from error
        if pc != address:
            raise StateParseError(
                f"State {index} PC {hex(pc)} does not match address index {hex(address)}."
            )


class _BoundedCache:
    def __init__(self, maximum: int):
        self.maximum = maximum
        self.values: OrderedDict[object, object] = OrderedDict()

    def get_or_create(self, key: object, factory):
        try:
            value = self.values.pop(key)
        except KeyError:
            value = factory()
            if len(self.values) >= self.maximum:
                self.values.popitem(last=False)
        self.values[key] = value
        return value


@dataclass(slots=True)
class _TransformDecodeCache:
    expressions: _BoundedCache
    instructions: _BoundedCache

    @classmethod
    def bounded(cls) -> _TransformDecodeCache:
        return cls(
            _BoundedCache(_STREAM_EXPRESSION_CACHE_SIZE),
            _BoundedCache(_STREAM_INSTRUCTION_CACHE_SIZE),
        )


def _parse_cached_expression(
    text: str,
    cache: _TransformDecodeCache | None,
) -> Expr:
    value = (
        str_to_expr(text)
        if cache is None
        else cache.expressions.get_or_create(text, lambda: str_to_expr(text))
    )
    if not isinstance(value, Expr):
        raise ValueError(f"Expression parser returned {type(value).__name__}.")
    return value


def _validate_transform_document(
    value: object,
    architecture: Arch,
    path: str,
    *,
    legacy: bool,
    schema_version: int = SCHEMA_VERSION,
    decode_cache: _TransformDecodeCache | None = None,
) -> SymbolicTransform:
    document = _mapping(value, path)
    if not legacy and schema_version >= 3:
        record_kind = _string(
            _required(document, "record_kind", path),
            f"{path}.record_kind",
        )
        if record_kind != "transform":
            raise TransformParseError(
                f"Expected a symbolic transform at {path}, received {record_kind}."
            )
    encoded_architecture_value = _required(document, "arch", path)
    if legacy:
        encoded_architecture = _resolve_legacy_architecture(
            encoded_architecture_value,
            f"{path}.arch",
            architecture,
        )
    else:
        encoded_architecture = _architecture_from_id(
            encoded_architecture_value,
            f"{path}.arch",
        )
    if encoded_architecture != architecture:
        raise ArchitectureParseError(
            f"{path}.arch is {encoded_architecture}, expected {architecture}."
        )

    tid = _integer(
        _required(document, "tid", path),
        f"{path}.tid",
        minimum=0,
        maximum=MAX_ADDRESS,
    )
    start = _integer(
        _required(document, "from_addr", path),
        f"{path}.from_addr",
        minimum=0,
        maximum=MAX_ADDRESS,
    )
    end = _integer(
        _required(document, "to_addr", path),
        f"{path}.to_addr",
        minimum=0,
        maximum=MAX_ADDRESS,
    )

    registers = _mapping(_required(document, "regs", path), f"{path}.regs")
    parsed_registers = {}
    changed_register_masks: dict[str, int] = {}
    for name, expression in registers.items():
        if not isinstance(name, str):
            raise FieldTypeError(f"{path}.regs keys must be strings.")
        normalized = architecture.to_regname(name)
        if normalized is None:
            raise TransformParseError(f"Unknown register {name} at {path}.regs.")
        if not legacy and normalized != name:
            raise TransformParseError(
                f"Register {name} at {path}.regs is not canonical ({normalized})."
            )
        accessor = architecture.get_reg_accessor(normalized)
        assert accessor is not None
        previous_mask = changed_register_masks.get(accessor.base_reg, 0)
        if previous_mask & accessor.mask:
            raise TransformParseError(
                f"Overlapping register destinations at {path}.regs include {name}."
            )
        changed_register_masks[accessor.base_reg] = previous_mask | accessor.mask
        expression_text = _string(expression, f"{path}.regs.{name}")
        assert expression_text is not None
        if len(expression_text) > MAX_EXPRESSION_CHARS:
            raise TraceLimitError(f"Expression at {path}.regs.{name} is too large.")
        try:
            parsed_expression = _parse_cached_expression(expression_text, decode_cache)
        except Exception as error:
            raise TransformParseError(
                f"Unable to parse expression at {path}.regs.{name}: {error}."
            ) from error
        if parsed_expression.size != accessor.num_bits:
            raise ExpressionWidthError(
                f"Expression for {name} at {path}.regs is {parsed_expression.size} bits, "
                f"expected {accessor.num_bits}."
            )
        parsed_registers[normalized] = parsed_expression

    parsed_memory_writes: list[MemoryWrite] = []
    memory_write_count: int
    if not legacy and schema_version >= 3:
        memory_writes = _list(
            _required(document, "memory_writes", path),
            f"{path}.memory_writes",
        )
        memory_write_count = len(memory_writes)
        for index, encoded_write in enumerate(memory_writes):
            write_path = f"{path}.memory_writes[{index}]"
            write = _mapping(encoded_write, write_path)
            address = _string(_required(write, "address", write_path), f"{write_path}.address")
            expression = _string(_required(write, "value", write_path), f"{write_path}.value")
            assert address is not None and expression is not None
            if len(address) > MAX_EXPRESSION_CHARS or len(expression) > MAX_EXPRESSION_CHARS:
                raise TraceLimitError(f"Memory expression at {write_path} is too large.")
            try:
                parsed_memory_writes.append(
                    MemoryWrite(
                        _parse_cached_expression(address, decode_cache),
                        _parse_cached_expression(expression, decode_cache),
                    )
                )
            except Exception as error:
                raise TransformParseError(
                    f"Unable to parse memory expression at {write_path}: {error}."
                ) from error
    else:
        memory = _mapping(_required(document, "mem", path), f"{path}.mem")
        memory_write_count = len(memory)
        for address, expression in memory.items():
            if not isinstance(address, str):
                raise FieldTypeError(f"{path}.mem keys must be strings.")
            expression_text = _string(expression, f"{path}.mem[{address}]")
            assert expression_text is not None
            if len(address) > MAX_EXPRESSION_CHARS or len(expression_text) > MAX_EXPRESSION_CHARS:
                raise TraceLimitError(f"Memory expression at {path}.mem is too large.")
            try:
                parsed_memory_writes.append(
                    MemoryWrite(
                        _parse_cached_expression(address, decode_cache),
                        _parse_cached_expression(expression_text, decode_cache),
                    )
                )
            except Exception as error:
                raise TransformParseError(
                    f"Unable to parse memory expression at {path}.mem: {error}."
                ) from error

    instructions = _list(_required(document, "instructions", path), f"{path}.instructions")
    parsed_instructions: list[Instruction] = []
    if len(instructions) > MAX_INSTRUCTIONS_PER_TRANSFORM:
        raise TraceLimitError(f"{path}.instructions contains too many instructions.")
    for index, encoded_instruction in enumerate(instructions):
        instruction_path = f"{path}.instructions[{index}]"
        instruction = _list(encoded_instruction, instruction_path)
        if len(instruction) != 2:
            raise InstructionParseError(f"{instruction_path} must contain [length, text].")
        instruction_length = _integer(
            instruction[0],
            f"{instruction_path}[0]",
        )
        if not 1 <= instruction_length <= MAX_INSTRUCTION_LENGTH:
            raise InstructionParseError(
                f"Instruction length at {instruction_path} must be between 1 "
                f"and {MAX_INSTRUCTION_LENGTH}."
            )
        text = _string(instruction[1], f"{instruction_path}[1]")
        assert text is not None
        if not text or len(text) > MAX_INSTRUCTION_TEXT_CHARS:
            raise InstructionParseError(f"Invalid instruction text at {instruction_path}.")
        assert text is not None
        key = (architecture.key, instruction_length, text)
        try:
            template = (
                Instruction.from_string(text, architecture, offset=0, length=instruction_length)
                if decode_cache is None
                else decode_cache.instructions.get_or_create(
                    key,
                    lambda: Instruction.from_string(
                        text,
                        architecture,
                        offset=0,
                        length=instruction_length,
                    ),
                )
            )
        except Exception as error:
            raise InstructionParseError(
                f"Unable to parse instruction at {instruction_path}: {error}."
            ) from error
        assert isinstance(template, Instruction)
        decoded_instruction = copy.copy(template)
        decoded_instruction.instr = copy.copy(template.instr)
        parsed_instructions.append(decoded_instruction)

    try:
        transform = SymbolicTransform(tid, {}, [], architecture, start, end)
        transform.changed_regs = parsed_registers
        transform.memory_writes = parsed_memory_writes
        transform.instructions = parsed_instructions
        instruction_address = start
        for instruction in transform.instructions:
            instruction.addr = instruction_address
            instruction_address += instruction.length
    except Exception as error:
        raise TransformParseError(f"Unable to decode {path}: {error}.") from error
    if transform.arch != architecture:
        raise ArchitectureParseError(
            f"Decoded transform architecture {transform.arch} does not match {architecture}."
        )

    for name, expression in transform.changed_regs.items():
        accessor = architecture.get_reg_accessor(name)
        if accessor is None:
            raise TransformParseError(f"Unknown decoded register {name} at {path}.regs.")
        if expression.size != accessor.num_bits:
            raise ExpressionWidthError(
                f"Expression for {name} at {path}.regs is {expression.size} bits, "
                f"expected {accessor.num_bits}."
            )

    if len(transform.memory_writes) != memory_write_count:
        raise TransformParseError(f"Unable to retain every memory write at {path}.")
    for write in transform.memory_writes:
        address = write.address
        expression = write.value
        if address.size != architecture.ptr_size:
            raise ExpressionWidthError(
                f"Memory address at {path}.mem is {address.size} bits, "
                f"expected {architecture.ptr_size}."
            )
        if expression.size <= 0 or expression.size % 8 != 0:
            raise ExpressionWidthError(
                f"Memory value at {path}.mem has non-byte width {expression.size}."
            )

    return transform


def _encode_transform(transform: SymbolicTransform, architecture: Arch, path: str) -> dict:
    document = transform.to_json()
    document.pop("mem", None)
    document["record_kind"] = "transform"
    _validate_transform_document(
        document,
        architecture,
        path,
        legacy=False,
        schema_version=SCHEMA_VERSION,
    )
    return document


_GAP_REASONS: set[str] = {
    "disassembly-error",
    "symbolic-timeout",
    "unsupported-semantics",
    "cross-validation-error",
}


def _validate_gap_document(
    value: object,
    architecture: Arch,
    path: str,
) -> TraceGap:
    document = _mapping(value, path)
    record_kind = _string(
        _required(document, "record_kind", path),
        f"{path}.record_kind",
    )
    if record_kind != "gap":
        raise TransformParseError(f"Expected a trace gap at {path}, received {record_kind}.")
    encoded_architecture = _architecture_from_id(
        _required(document, "arch", path),
        f"{path}.arch",
    )
    if encoded_architecture != architecture:
        raise ArchitectureParseError(
            f"{path}.arch is {encoded_architecture}, expected {architecture}."
        )
    tid = _integer(
        _required(document, "tid", path),
        f"{path}.tid",
        minimum=0,
        maximum=MAX_ADDRESS,
    )
    start = _integer(
        _required(document, "from_addr", path),
        f"{path}.from_addr",
        minimum=0,
        maximum=MAX_ADDRESS,
    )
    end = _integer(
        _required(document, "to_addr", path),
        f"{path}.to_addr",
        minimum=0,
        maximum=MAX_ADDRESS,
    )
    reason_value = _string(_required(document, "reason", path), f"{path}.reason")
    assert reason_value is not None
    if reason_value not in _GAP_REASONS:
        raise TransformParseError(f"Unsupported trace-gap reason {reason_value} at {path}.")
    message = _string(_required(document, "message", path), f"{path}.message")
    assert message is not None
    if not message or len(message) > MAX_GAP_MESSAGE_CHARS:
        raise TransformParseError(f"Invalid trace-gap message at {path}.")
    cause_type = _string(
        _required(document, "cause_type", path),
        f"{path}.cause_type",
        allow_none=True,
    )

    encoded_instruction = _required(document, "instruction", path)
    instruction = None
    if encoded_instruction is not None:
        instruction_path = f"{path}.instruction"
        fields = _list(encoded_instruction, instruction_path)
        if len(fields) != 2:
            raise InstructionParseError(f"{instruction_path} must contain [length, text].")
        length = _integer(fields[0], f"{instruction_path}[0]")
        if not 1 <= length <= MAX_INSTRUCTION_LENGTH:
            raise InstructionParseError(f"Invalid instruction length at {instruction_path}.")
        text = _string(fields[1], f"{instruction_path}[1]")
        assert text is not None
        if not text or len(text) > MAX_INSTRUCTION_TEXT_CHARS:
            raise InstructionParseError(f"Invalid instruction text at {instruction_path}.")
        instruction = InstructionRecord(start, length, text)

    return TraceGap(
        tid,
        architecture,
        start,
        end,
        cast(GapReason, reason_value),
        message,
        instruction=instruction,
        recorded_cause_type=cause_type,
    )


def _encode_gap(gap: TraceGap, architecture: Arch, path: str) -> dict:
    if gap.arch != architecture:
        raise ArchitectureParseError(
            f"Trace gap has architecture {gap.arch}, expected {architecture}."
        )
    encoded_instruction = None
    if gap.instruction is not None:
        if gap.instruction.addr != gap.addr:
            raise InstructionParseError(
                f"Trace-gap instruction address {hex(gap.instruction.addr)} does not "
                f"match gap source {hex(gap.addr)} at {path}."
            )
        try:
            encoded_instruction = [gap.instruction.length, gap.instruction.to_string()]
        except Exception as error:
            raise InstructionParseError(
                f"Unable to serialize trace-gap instruction at {path}: {error}."
            ) from error
    document = {
        "record_kind": "gap",
        "arch": gap.arch.serialized_name,
        "tid": gap.tid,
        "from_addr": gap.range[0],
        "to_addr": gap.range[1],
        "reason": gap.reason,
        "message": gap.message,
        "cause_type": gap.cause_type,
        "instruction": encoded_instruction,
    }
    _validate_gap_document(document, architecture, path)
    return document


def _decode_symbolic_item(
    value: object,
    architecture: Arch,
    path: str,
    schema_version: int,
    decode_cache: _TransformDecodeCache | None = None,
) -> SymbolicTraceItem:
    if schema_version == 2:
        return _validate_transform_document(
            value,
            architecture,
            path,
            legacy=False,
            schema_version=2,
            decode_cache=decode_cache,
        )
    document = _mapping(value, path)
    record_kind = _string(
        _required(document, "record_kind", path),
        f"{path}.record_kind",
    )
    if record_kind == "transform":
        return _validate_transform_document(
            document,
            architecture,
            path,
            legacy=False,
            schema_version=schema_version,
            decode_cache=decode_cache,
        )
    if record_kind == "gap":
        return _validate_gap_document(document, architecture, path)
    raise TransformParseError(f"Unsupported symbolic record kind {record_kind} at {path}.")


def _encode_symbolic_item(
    item: SymbolicTraceItem,
    architecture: Arch,
    path: str,
) -> dict:
    if isinstance(item, TraceGap):
        return _encode_gap(item, architecture, path)
    return _encode_transform(item, architecture, path)


def _validate_transform_addresses(
    transforms: Sequence[SymbolicTraceItem], addresses: tuple[int, ...]
) -> None:
    for index, (transform, address) in enumerate(zip(transforms, addresses, strict=True)):
        if transform.addr != address:
            raise TransformParseError(
                f"Transform {index} starts at {hex(transform.addr)}, "
                f"but address index contains {hex(address)}."
            )


def _parse_versioned_states(document: Mapping) -> MaterializedTrace[ProgramState]:
    header = _parse_versioned_header(document, "states")
    items = _list(_required(document, "items", "trace"), "trace.items")
    if len(items) != header.item_count:
        raise TraceCardinalityError(
            f"trace.items length {len(items)} does not match item_count {header.item_count}."
        )
    states = [
        _decode_state(item, header.architecture, f"trace.items[{index}]", legacy=False)
        for index, item in enumerate(items)
    ]
    _validate_state_addresses(states, header.addresses)
    return MaterializedTrace(states, header.environment, header.addresses)


def _parse_legacy_states(document: Mapping) -> MaterializedTrace[ProgramState]:
    if not document:
        raise AmbiguousArchitectureError(
            "Legacy empty snapshot documents do not identify trace kind or architecture."
        )
    environment_document = _required(document, "env", "legacy trace")
    environment_architecture = _legacy_architecture_from_environment(environment_document)
    architecture = _resolve_legacy_architecture(
        _required(document, "architecture", "legacy trace"),
        "legacy trace.architecture",
        environment_architecture,
    )
    environment = _parse_environment(environment_document, architecture, legacy=True)
    items = _list(_required(document, "snapshots", "legacy trace"), "legacy trace.snapshots")
    if len(items) > MAX_TRACE_ITEMS:
        raise TraceLimitError("Legacy state trace contains too many items.")
    states = [
        _decode_state(
            item,
            architecture,
            f"legacy trace.snapshots[{index}]",
            legacy=True,
        )
        for index, item in enumerate(items)
    ]
    return MaterializedTrace(states, environment)


def parse_snapshots(json_stream: TextIO) -> MaterializedTrace[ProgramState]:
    """Parse a versioned or known unambiguous legacy JSON state trace."""
    document = _read_json_document(json_stream)
    if "schema_version" in document:
        return _parse_versioned_states(document)
    return _parse_legacy_states(document)


def serialize_snapshots(
    snapshots: MaterializedTrace[ProgramState],
    out_stream: TextIO,
) -> None:
    """Serialize a materialized state trace as a versioned JSON document."""
    architecture, environment = _trace_architecture(snapshots, item_kind="state")
    addresses = snapshots.addresses
    if addresses is not None:
        _validate_state_addresses(snapshots, addresses)
    document = _header_document("states", architecture, environment, addresses, len(snapshots))
    document["items"] = [
        _encode_state(state, architecture, f"trace.items[{index}]")
        for index, state in enumerate(snapshots)
    ]
    out_stream.write(json.dumps(document, option=json.OPT_INDENT_2).decode())


def _parse_versioned_transforms(document: Mapping) -> MaterializedTrace[SymbolicTraceItem]:
    header = _parse_versioned_header(document, "transforms")
    assert header.addresses is not None
    items = _list(_required(document, "items", "trace"), "trace.items")
    if len(items) != header.item_count:
        raise TraceCardinalityError(
            f"trace.items length {len(items)} does not match item_count {header.item_count}."
        )
    transforms = [
        _decode_symbolic_item(
            item,
            header.architecture,
            f"trace.items[{index}]",
            header.version,
        )
        for index, item in enumerate(items)
    ]
    _validate_transform_addresses(transforms, header.addresses)
    return MaterializedTrace(transforms, header.environment, header.addresses)


def _parse_legacy_transforms(document: Mapping) -> MaterializedTrace[SymbolicTransform]:
    items = _list(_required(document, "states", "legacy trace"), "legacy trace.states")
    if len(items) > MAX_TRACE_ITEMS:
        raise TraceLimitError("Legacy transform trace contains too many items.")
    environment_document = _required(document, "env", "legacy trace")
    environment_architecture = _legacy_architecture_from_environment(environment_document)
    if items:
        first_item = _mapping(items[0], "legacy trace.states[0]")
        architecture = _resolve_legacy_architecture(
            _required(first_item, "arch", "legacy trace.states[0]"),
            "legacy trace.states[0].arch",
            environment_architecture,
        )
    elif environment_architecture is None:
        raise AmbiguousArchitectureError(
            "Legacy empty transform traces do not identify architecture."
        )
    else:
        architecture = environment_architecture
    environment = _parse_environment(environment_document, architecture, legacy=True)
    transforms = [
        _validate_transform_document(
            item,
            architecture,
            f"legacy trace.states[{index}]",
            legacy=True,
        )
        for index, item in enumerate(items)
    ]
    encoded_addresses = document.get("addrs")
    if encoded_addresses is None:
        addresses = tuple(transform.addr for transform in transforms)
    else:
        addresses = _parse_addresses(encoded_addresses, len(transforms), "transforms")
        assert addresses is not None
    _validate_transform_addresses(transforms, addresses)
    return MaterializedTrace(transforms, environment, addresses)


def parse_transformations(json_stream: TextIO) -> MaterializedTrace[SymbolicTraceItem]:
    """Parse a versioned or known unambiguous legacy symbolic trace."""
    document = _read_json_document(json_stream)
    if "schema_version" in document:
        return _parse_versioned_transforms(document)
    return _parse_legacy_transforms(document)


def _transform_trace_metadata(
    trace: MaterializedTrace[SymbolicTraceItem] | TransformStream[SymbolicTraceItem],
) -> tuple[Arch, TraceEnvironment, tuple[int, ...]]:
    addresses = trace.require_addresses()
    if len(addresses) > MAX_TRACE_ITEMS:
        raise TraceLimitError("Transform trace contains too many items.")

    if isinstance(trace, MaterializedTrace):
        architecture, environment = _trace_architecture(trace, item_kind="transform")
        if len(trace) != len(addresses):
            raise TraceCardinalityError("Transform count does not match address count.")
        _validate_transform_addresses(trace, addresses)
    else:
        if trace.env.architecture is None:
            raise ArchitectureParseError(
                "A transform stream requires architecture metadata before serialization."
            )
        architecture = _architecture_from_key(trace.env.architecture)
        try:
            environment = trace.env.with_architecture(architecture.key)
        except ValueError as error:
            raise ArchitectureParseError(str(error)) from error
    return architecture, environment, addresses


def _serialize_transform_json(
    trace: MaterializedTrace[SymbolicTraceItem] | TransformStream[SymbolicTraceItem],
    out_file: str | PathLike[str],
) -> None:
    architecture, environment, addresses = _transform_trace_metadata(trace)
    items = []
    for index, transform in enumerate(trace):
        if index >= len(addresses):
            raise TraceCardinalityError("Transform stream exceeds its address count.")
        if transform.addr != addresses[index]:
            raise TransformParseError(
                f"Transform {index} does not match address index {hex(addresses[index])}."
            )
        if transform.arch != architecture:
            raise ArchitectureParseError(
                f"Transform {index} has architecture {transform.arch}, expected {architecture}."
            )
        items.append(_encode_symbolic_item(transform, architecture, f"trace.items[{index}]"))
    if len(items) != len(addresses):
        raise TraceCardinalityError(
            f"Transform stream ended after {len(items)} items; expected {len(addresses)}."
        )

    document = _header_document("transforms", architecture, environment, addresses, len(items))
    document["items"] = items
    with open(out_file, "w") as out_stream:
        out_stream.write(json.dumps(document, option=json.OPT_INDENT_2).decode())


def _write_msgpack_frame(stream: BinaryIO, value: object) -> None:
    try:
        payload = msgpack.packb(value, use_bin_type=True)
    except Exception as error:
        raise TraceDecodeError(f"Unable to encode MessagePack frame: {error}.") from error
    if len(payload) > MAX_MSGPACK_FRAME_BYTES:
        raise TraceLimitError(
            f"MessagePack frame exceeds the {MAX_MSGPACK_FRAME_BYTES}-byte limit."
        )
    stream.write(_MSGPACK_FRAME_LENGTH.pack(len(payload)))
    stream.write(payload)


def _serialize_transform_msgpack(
    trace: MaterializedTrace[SymbolicTraceItem] | TransformStream[SymbolicTraceItem],
    out_file: str | PathLike[str],
) -> None:
    architecture, environment, addresses = _transform_trace_metadata(trace)
    header = _header_document("transforms", architecture, environment, addresses, len(addresses))
    with open(out_file, "wb") as out_stream:
        out_stream.write(MSGPACK_MAGIC)
        _write_msgpack_frame(out_stream, header)
        count = 0
        for index, transform in enumerate(trace):
            if index >= len(addresses):
                raise TraceCardinalityError("Transform stream exceeds its address count.")
            if transform.addr != addresses[index]:
                raise TransformParseError(
                    f"Transform {index} does not match address index {hex(addresses[index])}."
                )
            if transform.arch != architecture:
                raise ArchitectureParseError(
                    f"Transform {index} has architecture {transform.arch}, expected {architecture}."
                )
            item = _encode_symbolic_item(
                transform,
                architecture,
                f"trace.items[{index}]",
            )
            _write_msgpack_frame(out_stream, {"item": item})
            count += 1
        if count != len(addresses):
            raise TraceCardinalityError(
                f"Transform stream ended after {count} items; expected {len(addresses)}."
            )


def serialize_transformations(
    trace: MaterializedTrace[SymbolicTraceItem] | TransformStream[SymbolicTraceItem],
    out_file: str | PathLike[str],
    out_type: Literal["msgpack", "json"] = "json",
) -> None:
    """Serialize symbolic records using versioned JSON or streaming MessagePack."""
    if out_type == "json":
        _serialize_transform_json(trace, out_file)
    elif out_type == "msgpack":
        _serialize_transform_msgpack(trace, out_file)
    else:
        raise ValueError(f"Unsupported trace output type: {out_type}.")


class _TransformFrameIterator(Iterator[SymbolicTraceItem]):
    def __init__(
        self,
        frames: Iterator,
        header: _TraceHeader,
        *,
        frame_key: str,
        legacy: bool,
    ):
        assert header.addresses is not None
        self._frames = frames
        self._header = header
        self._frame_key = frame_key
        self._legacy = legacy
        self._decode_cache = _TransformDecodeCache.bounded()
        self._index = 0
        self._finished = False

    def __iter__(self) -> _TransformFrameIterator:
        return self

    def _next_frame(self) -> object:
        try:
            return next(self._frames)
        except StopIteration as error:
            raise TruncatedTraceError(
                f"Transform stream ended after {self._index} items; "
                f"expected {self._header.item_count}."
            ) from error
        except ParseError:
            raise
        except Exception as error:
            raise TraceDecodeError(f"Invalid MessagePack frame: {error}.") from error

    def __next__(self) -> SymbolicTraceItem:
        if self._finished:
            raise StopIteration
        if self._index == self._header.item_count:
            try:
                next(self._frames)
            except StopIteration:
                self._finished = True
                raise
            except ParseError:
                raise
            except Exception as error:
                raise TraceDecodeError(f"Invalid trailing MessagePack frame: {error}.") from error
            raise TraceCardinalityError(
                f"Transform stream contains more than {self._header.item_count} items."
            )

        frame = _mapping(self._next_frame(), f"stream frame {self._index}")
        item = _required(frame, self._frame_key, f"stream frame {self._index}")
        if self._legacy:
            transform: SymbolicTraceItem = _validate_transform_document(
                item,
                self._header.architecture,
                f"trace.items[{self._index}]",
                legacy=True,
                decode_cache=self._decode_cache,
            )
        else:
            transform = _decode_symbolic_item(
                item,
                self._header.architecture,
                f"trace.items[{self._index}]",
                self._header.version,
                self._decode_cache,
            )
        assert self._header.addresses is not None
        expected_address = self._header.addresses[self._index]
        if transform.addr != expected_address:
            raise TransformParseError(
                f"Transform {self._index} starts at {hex(transform.addr)}, "
                f"expected {hex(expected_address)}."
            )
        self._index += 1
        return transform


class _PrefixedBinaryReader:
    def __init__(self, prefix: bytes, source: BinaryIO):
        self._prefix = bytearray(prefix)
        self._source = source

    def read(self, size: int = -1) -> bytes:
        if size == 0:
            return b""
        if size < 0:
            prefix = bytes(self._prefix)
            self._prefix.clear()
            return prefix + self._source.read()

        prefix = bytes(self._prefix[:size])
        del self._prefix[:size]
        if len(prefix) == size:
            return prefix
        return prefix + self._source.read(size - len(prefix))


def _read_exact(stream: BinaryIO, size: int, path: str, *, prefix: bytes = b"") -> bytes:
    data = bytearray(prefix)
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            raise TruncatedTraceError(f"{path} ended after {len(data)} bytes; expected {size}.")
        data.extend(chunk)
    return bytes(data)


def _read_msgpack_frame(
    stream: BinaryIO,
    path: str,
    *,
    allow_eof: bool,
) -> object | None:
    first = stream.read(1)
    if not first:
        if allow_eof:
            return None
        raise TruncatedTraceError(f"{path} is missing.")
    encoded_length = _read_exact(
        stream,
        _MSGPACK_FRAME_LENGTH.size,
        f"{path} length",
        prefix=first,
    )
    (length,) = _MSGPACK_FRAME_LENGTH.unpack(encoded_length)
    if length == 0:
        raise TraceDecodeError(f"{path} has an empty MessagePack payload.")
    if length > MAX_MSGPACK_FRAME_BYTES:
        raise TraceLimitError(f"{path} exceeds the {MAX_MSGPACK_FRAME_BYTES}-byte frame limit.")
    payload = _read_exact(stream, length, f"{path} payload")
    try:
        return msgpack.unpackb(payload, raw=False, strict_map_key=False)
    except Exception as error:
        raise TraceDecodeError(f"Invalid {path}: {error}.") from error


class _LengthPrefixedFrames(Iterator[object]):
    def __init__(self, stream: BinaryIO):
        self._stream = stream
        self._index = 0

    def __iter__(self) -> _LengthPrefixedFrames:
        return self

    def __next__(self) -> object:
        frame = _read_msgpack_frame(
            self._stream,
            f"MessagePack frame {self._index}",
            allow_eof=True,
        )
        if frame is None:
            raise StopIteration
        self._index += 1
        return frame


def _msgpack_unpacker(stream: BinaryIO) -> msgpack.Unpacker:
    return msgpack.Unpacker(
        stream,
        raw=False,
        max_buffer_size=MAX_MSGPACK_BUFFER_BYTES,
        strict_map_key=False,
    )


def _next_msgpack_header(unpacker: msgpack.Unpacker) -> Mapping:
    try:
        return _mapping(next(unpacker), "MessagePack trace header")
    except StopIteration as error:
        raise TruncatedTraceError("MessagePack trace has no header.") from error
    except ParseError:
        raise
    except Exception as error:
        raise TraceDecodeError(f"Invalid MessagePack trace header: {error}.") from error


def _legacy_architecture_from_environment(value: object) -> Arch | None:
    environment = _mapping(value, "legacy trace.env")
    encoded_architecture = environment.get("architecture")
    if encoded_architecture is None:
        return None
    architecture = _mapping(encoded_architecture, "legacy trace.env.architecture")
    isa = _string(
        _required(architecture, "isa", "legacy trace.env.architecture"),
        "legacy trace.env.architecture.isa",
    )
    endianness = _string(
        _required(architecture, "endianness", "legacy trace.env.architecture"),
        "legacy trace.env.architecture.endianness",
    )
    if endianness not in ("little", "big"):
        raise ArchitectureParseError(f"Unsupported legacy endianness: {endianness}.")
    assert isa is not None
    return _architecture_from_key(ArchitectureKey(isa, endianness))


def _stream_versioned_transformations(
    header_document: Mapping,
    frames: Iterator,
) -> TransformStream[SymbolicTraceItem]:
    header = _parse_versioned_header(header_document, "transforms")
    assert header.addresses is not None
    iterator = _TransformFrameIterator(
        frames,
        header,
        frame_key="item",
        legacy=False,
    )
    return TransformStream(iterator, header.environment, header.addresses)


def _stream_legacy_transformations(
    header_document: Mapping,
    unpacker: msgpack.Unpacker,
) -> TransformStream[SymbolicTraceItem]:
    addresses_value = _required(header_document, "addresses", "legacy trace header")
    encoded_addresses = _list(addresses_value, "legacy trace header.addresses")
    if len(encoded_addresses) > MAX_TRACE_ITEMS:
        raise TraceLimitError("Legacy transform stream contains too many items.")
    addresses = tuple(
        _integer(item, f"legacy trace header.addresses[{index}]", minimum=0)
        for index, item in enumerate(encoded_addresses)
    )
    environment_document = _required(header_document, "env", "legacy trace header")
    architecture = _legacy_architecture_from_environment(environment_document)

    frames = unpacker
    if addresses:
        try:
            first_frame = next(frames)
        except StopIteration as error:
            raise TruncatedTraceError(
                f"Legacy transform stream expects {len(addresses)} items but is empty."
            ) from error
        first_mapping = _mapping(first_frame, "legacy stream frame 0")
        first_item = _mapping(
            _required(first_mapping, "state", "legacy stream frame 0"),
            "legacy stream frame 0.state",
        )
        architecture = _resolve_legacy_architecture(
            _required(first_item, "arch", "legacy stream frame 0.state"),
            "legacy stream frame 0.state.arch",
            architecture,
        )
        frames = chain([first_frame], frames)
    elif architecture is None:
        raise AmbiguousArchitectureError(
            "Legacy empty transform streams do not identify architecture."
        )

    assert architecture is not None
    environment = _parse_environment(environment_document, architecture, legacy=True)
    header = _TraceHeader(
        1,
        "transforms",
        architecture,
        environment,
        addresses,
        len(addresses),
    )
    iterator = _TransformFrameIterator(
        iter(frames),
        header,
        frame_key="state",
        legacy=True,
    )
    return TransformStream(iterator, environment, addresses)


def stream_transformation(stream: BinaryIO) -> TransformStream[SymbolicTraceItem]:
    """Read a versioned or known legacy streaming MessagePack symbolic trace."""
    prefix = bytearray()
    while len(prefix) < len(MSGPACK_MAGIC):
        chunk = stream.read(len(MSGPACK_MAGIC) - len(prefix))
        if not chunk:
            break
        prefix.extend(chunk)

    if bytes(prefix) == MSGPACK_MAGIC:
        header_value = _read_msgpack_frame(
            stream,
            "MessagePack trace header",
            allow_eof=False,
        )
        assert header_value is not None
        header = _mapping(header_value, "MessagePack trace header")
        return _stream_versioned_transformations(
            header,
            _LengthPrefixedFrames(stream),
        )

    if prefix and MSGPACK_MAGIC.startswith(prefix):
        raise TruncatedTraceError("MessagePack versioned magic header is truncated.")
    legacy_stream = _PrefixedBinaryReader(bytes(prefix), stream)
    unpacker = _msgpack_unpacker(legacy_stream)
    header = _next_msgpack_header(unpacker)
    if "schema_version" in header:
        raise TraceDecodeError("Versioned MessagePack traces require the Focaccia magic envelope.")
    return _stream_legacy_transformations(header, unpacker)
