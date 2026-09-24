"""Output validation reuses parsing, never cached record validity (offline only)."""

import copy
from unittest.mock import patch

import pytest
from miasm.expression.expression import ExprId, ExprInt

import focaccia.persistence as p
from focaccia.arch import aarch64, x86
from focaccia.symbolic import Instruction, MemoryWrite, SymbolicTransform
from focaccia.trace import MaterializedTrace, TraceEnvironment, TransformStream


def transform(arch=None, start=0x1000, value=42):
    arch = arch or x86.ArchX86()
    name = "RAX" if arch == x86.ArchX86() else "X0"
    item = SymbolicTransform(7, {ExprId(name, 64): ExprInt(value, 64)}, [], arch, start, start + 4)
    item.instructions = [Instruction.from_string("NOP", arch, offset=start, length=4)]
    return item


def trace(items, streaming=False):
    env = TraceEnvironment(None, (), (), architecture=items[0].arch.key)
    addresses = [item.addr for item in items]
    if streaming:
        return TransformStream(iter(items), env, addresses)
    return MaterializedTrace(items, env, addresses)


@pytest.mark.parametrize("format", ["json", "msgpack"])
@pytest.mark.parametrize("streaming", [False, True])
def test_serialization_reuses_parsing_per_call_only(tmp_path, format, streaming):
    items = [transform(start=0x1000 + 4 * i) for i in range(8)]
    original = [item.to_json() for item in items]
    output = tmp_path / "trace"
    with (
        patch.object(p, "str_to_expr", wraps=p.str_to_expr) as expressions,
        patch.object(Instruction, "from_string", wraps=Instruction.from_string) as instructions,
    ):
        for call in range(2):
            p.serialize_transformations(trace(items, streaming), output, format)
            assert expressions.call_count == call + 1
            assert instructions.call_count == call + 1
    assert [item.to_json() for item in items] == original
    with output.open("r" if format == "json" else "rb") as stream:
        parsed = (
            p.parse_transformations(stream) if format == "json" else p.stream_transformation(stream)
        )
        decoded = list(parsed)
        assert all(isinstance(item, SymbolicTransform) for item in decoded)
        assert [
            item.to_json() for item in decoded if isinstance(item, SymbolicTransform)
        ] == original


@pytest.mark.parametrize("format", ["json", "msgpack"])
def test_serialization_cache_eviction_is_bounded(tmp_path, monkeypatch, format):
    monkeypatch.setattr(p, "_STREAM_EXPRESSION_CACHE_SIZE", 2)
    monkeypatch.setattr(p, "_STREAM_INSTRUCTION_CACHE_SIZE", 1)
    items = [transform(value=value) for value in (1, 2, 3, 1)]
    items[1].instructions = [Instruction.from_string("RET", items[1].arch, length=1)]
    caches = []
    bounded = p._TransformDecodeCache.bounded

    def capture():
        cache = bounded()
        caches.append(cache)
        return cache

    monkeypatch.setattr(p._TransformDecodeCache, "bounded", capture)
    with (
        patch.object(p, "str_to_expr", wraps=p.str_to_expr) as expressions,
        patch.object(Instruction, "from_string", wraps=Instruction.from_string) as instructions,
    ):
        p.serialize_transformations(trace(items), tmp_path / "trace", format)
        assert expressions.call_count == 4
        assert instructions.call_count == 3
    assert len(caches) == 1
    assert len(caches[0].expressions.values) == 2
    assert len(caches[0].instructions.values) == 1


@pytest.mark.parametrize("format", ["json", "msgpack"])
@pytest.mark.parametrize(
    "change",
    [
        {"regs": {"EAX": "ExprInt(0x2A, 64)"}},
        {"arch": "aarch64b"},
        {"validation_registers": ["RAX", "RAX"]},
        {"instructions": [[0, "NOP"]]},
        {"instructions": [[4, "not an instruction"]]},
        {"regs": {"RAX": "not an expression"}},
        {"memory_writes": [{"address": "ExprInt(0x2A, 8)", "value": "ExprInt(0x2A, 64)"}]},
        {"memory_writes": [{"address": "ExprInt(0x2A, 64)", "value": "ExprInt(0x1, 1)"}]},
    ],
)
def test_cache_hits_do_not_bypass_output_validation(tmp_path, format, change):
    item = transform()
    valid = item.to_json()
    malformed = copy.deepcopy(valid)
    malformed.update(change)
    # Identical object occurs twice; a cached whole-record success would be unsound.
    with patch.object(SymbolicTransform, "to_json", side_effect=[valid, malformed]):
        with pytest.raises(p.ParseError):
            p.serialize_transformations(trace([item, item]), tmp_path / "trace", format)


@pytest.mark.parametrize(
    "arch", [x86.ArchX86(), aarch64.ArchAArch64("little"), aarch64.ArchAArch64("big")]
)
def test_cache_architecture_version_and_output_mutation_isolation(arch):
    cache = p._TransformDecodeCache.bounded()
    for architecture in (x86.ArchX86(), arch):
        item = transform(architecture)
        expected = p._encode_transform(item, architecture, "uncached")
        document = p._encode_transform(item, architecture, "cached", cache)
        assert document == expected
        document["instructions"][0][1] = "BAD"
        document["regs"].clear()
        assert p._encode_transform(item, architecture, "again", cache) == expected
        old = copy.deepcopy(expected)
        del old["validation_registers"]
        old["mem"] = {}
        p._validate_transform_document(
            old, architecture, "v2", legacy=False, schema_version=2, decode_cache=cache
        )
        with pytest.raises(p.MissingFieldError):
            p._validate_transform_document(
                old, architecture, "current", legacy=False, decode_cache=cache
            )
    assert {key[0] for key in cache.instructions.values if isinstance(key, tuple)} == {
        x86.ArchX86().key,
        arch.key,
    }


def test_repeated_invalid_output_rejects_with_warm_cache():
    item = transform()
    cache = p._TransformDecodeCache.bounded()
    valid = p._encode_transform(item, item.arch, "warm", cache)
    malformed = copy.deepcopy(valid)
    malformed["regs"] = {"EAX": valid["regs"]["RAX"]}
    with patch.object(SymbolicTransform, "to_json", return_value=malformed):
        for index in range(3):
            with pytest.raises(p.ExpressionWidthError):
                p._encode_transform(item, item.arch, f"bad[{index}]", cache)
    assert p._encode_transform(item, item.arch, "valid-again", cache) == valid


def test_cached_output_preserves_ordered_writes_and_unknowns():
    item = transform()
    item.changed_regs["RAX"] = ExprId("unknown_value", 64)
    item._validation_register_names = set()
    item.memory_writes = [MemoryWrite(ExprInt(0x2000, 64), ExprInt(value, 8)) for value in (1, 2)]
    cache = p._TransformDecodeCache.bounded()
    expected = p._encode_transform(item, item.arch, "uncached")
    for _ in range(2):
        assert p._encode_transform(item, item.arch, "cached", cache) == expected
    assert len(expected["memory_writes"]) == 2
    assert expected["validation_registers"] == []
    assert "unknown_value" in expected["regs"]["RAX"]
