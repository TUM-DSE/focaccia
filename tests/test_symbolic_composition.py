import pytest
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import ExprCompose, ExprId, ExprInt, ExprMem, ExprOp

from focaccia.arch import aarch64, x86
from focaccia.miasm_util import MiasmSymbolResolver, eval_expr, expression_depth
from focaccia.snapshot import ProgramState
from focaccia.symbolic import (
    _TransformEvaluator,
    SymbolicCompositionError,
    SymbolicTransform,
    SymbolicTransformComposer,
)


X86 = x86.ArchX86()


def transform(
    arch,
    start: int,
    end: int,
    changes: dict,
    *,
    tid: int = 1,
) -> SymbolicTransform:
    return SymbolicTransform(tid, changes, [], arch, start, end)


def state(arch, **registers: int) -> ProgramState:
    result = ProgramState(arch)
    for name, value in registers.items():
        result.write_register(name, value)
    return result


def zero_extend(expression, width: int):
    if expression.size == width:
        return expression
    return ExprCompose(expression, ExprInt(0, width - expression.size))


def test_deep_expression_composition_evaluation_and_dependencies_are_iterative(
    monkeypatch,
):
    depth = 1_100
    expression = ExprId("RAX", 64)
    for _ in range(depth):
        expression = ExprOp("deep_identity", expression)
    deep = transform(
        X86,
        0x1000,
        0x1001,
        {ExprId("RBX", 64): expression},
    )
    consume = transform(
        X86,
        0x1001,
        0x1002,
        {ExprId("RCX", 64): ExprId("RBX", 64)},
    )
    original_resolver = _TransformEvaluator.resolve_environment_operation

    def resolve_deep_identity(self, operation, arguments):
        if operation == "deep_identity":
            return arguments[0]
        return original_resolver(self, operation, arguments)

    monkeypatch.setattr(
        _TransformEvaluator,
        "resolve_environment_operation",
        resolve_deep_identity,
    )

    composed = deep.composed_with(consume)
    concrete = state(X86, RAX=7, RBX=0, RCX=0)

    assert expression_depth(composed.changed_regs["RBX"]) > 1_000
    assert composed.eval_register_transforms(concrete)["RBX"] == 7
    assert composed.eval_register_transforms(concrete)["RCX"] == 7
    assert composed.get_used_registers() == ["RAX"]


def test_long_composition_does_not_rescan_accumulated_register_dags(monkeypatch):
    import focaccia.symbolic as symbolic

    depth = 1_100
    expression = ExprId("RAX", 64)
    for _ in range(depth):
        expression = ExprOp("deep_identity", expression)
    first = transform(
        X86,
        0x1000,
        0x1001,
        {ExprId("RBX", 64): expression},
    )
    copies = 2_000
    composer = SymbolicTransformComposer(first)
    depth_calls = 0
    original_depth = symbolic.expression_depth

    def counted_depth(value):
        nonlocal depth_calls
        depth_calls += 1
        return original_depth(value)

    monkeypatch.setattr(symbolic, "expression_depth", counted_depth)
    for index in range(copies):
        composer.append(
            transform(
                X86,
                0x1001 + index,
                0x1002 + index,
                {ExprId("RBX", 64): ExprId("RBX", 64)},
            )
        )

    composed = composer.finish()

    assert composed.range == (0x1000, 0x1001 + copies)
    assert expression_depth(composed.changed_regs["RBX"]) > 1_000
    assert depth_calls == 0


def test_unknown_symbolic_destinations_fail_closed_while_irdst_is_internal():
    internal = transform(
        X86,
        0x1000,
        0x1001,
        {ExprId("IRDst", 64): ExprInt(0x1001, 64)},
    )

    assert internal.changed_regs == {}
    with pytest.raises(SymbolicCompositionError, match="Unsupported symbolic destination"):
        transform(
            X86,
            0x1000,
            0x1001,
            {ExprId("UNMODELED", 64): ExprInt(0, 64)},
        )


def test_x86_extended_register_aliases_are_canonical_and_composable():
    for index in range(8, 16):
        for suffix, width in (("D", 32), ("W", 16), ("B", 8)):
            accessor = X86.get_reg_accessor(f"R{index}{suffix}")
            assert accessor is not None
            assert accessor.base_reg == f"R{index}"
            assert accessor.num_bits == width

    first = transform(
        X86,
        0x1000,
        0x1001,
        {ExprId("r8d", 32): ExprInt(0x1234, 32)},
    )
    second = transform(
        X86,
        0x1001,
        0x1002,
        {ExprId("R9D", 32): ExprId("R8D", 32) + ExprInt(1, 32)},
    )
    concrete = state(X86, R8=(1 << 64) - 1, R9=(1 << 64) - 1)

    values = first.composed_with(second).eval_register_transforms(concrete)

    assert values["R8"] == 0x1234
    assert values["R9"] == 0x1235


def test_single_alias_writes_expose_complete_base_register_outputs():
    low_byte = transform(
        X86,
        0x1000,
        0x1001,
        {ExprId("al", 8): ExprInt(0x56, 8)},
    )
    low_word = transform(
        X86,
        0x1000,
        0x1001,
        {ExprId("eax", 32): ExprInt(7, 32)},
    )
    concrete = state(X86, RAX=0x1122334455667788)

    assert low_byte.eval_register_transforms(concrete) == {"RAX": 0x1122334455667756}
    assert low_word.eval_register_transforms(concrete) == {"RAX": 7}
    assert "RAX" in low_byte.get_used_registers()
    assert "RAX" not in low_word.get_used_registers()


def test_register_dependencies_use_canonical_alias_identity_and_zero_extension():
    first = transform(X86, 0x1000, 0x1001, {ExprId("eax", 32): ExprInt(5, 32)})
    second = transform(
        X86,
        0x1001,
        0x1002,
        {ExprId("ebx", 32): ExprId("EAX", 32) + ExprInt(1, 32)},
    )

    composed = first.composed_with(second)
    concrete = state(X86, RAX=0xFFFF_FFFF_FFFF_FFFF, RBX=0)

    assert composed.eval_register_transforms(concrete)["RAX"] == 5
    assert composed.eval_register_transforms(concrete)["RBX"] == 6
    assert first.range == (0x1000, 0x1001)
    assert first.changed_regs == {"EAX": ExprInt(5, 32)}


def test_concat_compatibility_mutates_only_the_receiver():
    first = transform(X86, 0x1000, 0x1001, {ExprId("EAX", 32): ExprInt(5, 32)})
    second = transform(
        X86,
        0x1001,
        0x1002,
        {ExprId("EBX", 32): ExprId("EAX", 32) + ExprInt(1, 32)},
    )
    original_second = second.changed_regs.copy()

    returned = first.concat(second)

    assert returned is first
    assert first.range == (0x1000, 0x1002)
    assert first.eval_register_transforms(state(X86, RAX=0, RBX=0))["RBX"] == 6
    assert second.range == (0x1001, 0x1002)
    assert second.changed_regs == original_second


def test_flag_aliases_compose_through_the_base_register():
    first = transform(
        X86,
        0x1000,
        0x1001,
        {ExprId("iopl_f", 2): ExprInt(3, 2)},
    )
    second = transform(
        X86,
        0x1001,
        0x1002,
        {ExprId("EAX", 32): zero_extend(ExprId("IOPL", 2), 32)},
    )
    concrete = state(X86, RFLAGS=0, RAX=0)

    values = first.composed_with(second).eval_register_transforms(concrete)

    assert values["RFLAGS"] == 3 << 12
    assert values["RAX"] == 3


def test_aarch64_miasm_flag_aliases_share_canonical_cpsr_bits():
    arch = aarch64.ArchAArch64("little")
    first = transform(
        arch,
        0x1000,
        0x1004,
        {ExprId("nf", 1): ExprInt(1, 1)},
    )
    second = transform(
        arch,
        0x1004,
        0x1008,
        {ExprId("W0", 32): zero_extend(ExprId("N", 1), 32)},
    )
    concrete = state(arch, CPSR=0, X0=0)

    values = first.composed_with(second).eval_register_transforms(concrete)

    assert values["CPSR"] == 1 << 31
    assert values["X0"] == 1


def test_aarch64_writes_zero_extend_their_x_register():
    arch = aarch64.ArchAArch64("little")
    first = transform(arch, 0x1000, 0x1004, {ExprId("w0", 32): ExprInt(7, 32)})
    second = transform(
        arch,
        0x1004,
        0x1008,
        {ExprId("W1", 32): ExprId("W0", 32) + ExprInt(1, 32)},
    )
    concrete = state(arch, X0=(1 << 64) - 1, X1=(1 << 64) - 1)

    values = first.composed_with(second).eval_register_transforms(concrete)

    assert values["X0"] == 7
    assert values["X1"] == 8


def test_little_endian_store_is_forwarded_to_a_later_load():
    pointer = ExprId("RSP", 64)
    first = transform(
        X86,
        0x1000,
        0x1001,
        {ExprMem(pointer, 32): ExprInt(0x11223344, 32)},
    )
    second = transform(
        X86,
        0x1001,
        0x1002,
        {
            ExprId("RAX", 64): zero_extend(
                ExprMem(pointer + ExprInt(1, 64), 16),
                64,
            )
        },
    )
    concrete = state(X86, RSP=0x2000, RAX=0)

    values = first.composed_with(second).eval_register_transforms(concrete)

    assert values["RAX"] == 0x2233


def test_partial_store_to_load_forwarding_reads_only_unwritten_bytes():
    pointer = ExprId("RSP", 64)
    first = transform(
        X86,
        0x1000,
        0x1001,
        {ExprMem(pointer + ExprInt(1, 64), 16): ExprInt(0x1122, 16)},
    )
    second = transform(
        X86,
        0x1001,
        0x1002,
        {ExprId("EAX", 32): ExprMem(pointer, 32)},
    )
    concrete = state(X86, RSP=0x2000, RAX=0)
    concrete.write_memory(0x2000, b"\xaa\xbb\xcc\xdd")

    values = first.composed_with(second).eval_register_transforms(concrete)

    assert values["RAX"] == 0xDD1122AA


def test_overlapping_stores_are_ordered_and_last_write_wins():
    pointer = ExprId("RSP", 64)
    first = transform(
        X86,
        0x1000,
        0x1001,
        {ExprMem(pointer, 32): ExprInt(0x11223344, 32)},
    )
    second = transform(
        X86,
        0x1001,
        0x1002,
        {ExprMem(pointer + ExprInt(1, 64), 16): ExprInt(0xAABB, 16)},
    )
    concrete = state(X86, RSP=0x2000)

    memory = first.composed_with(second).eval_memory_transforms(concrete)

    assert memory == {0x2000: b"\x44\xbb\xaa\x11"}


def test_big_endian_store_to_load_and_overlap_use_address_order():
    arch = aarch64.ArchAArch64("big")
    pointer = ExprId("X0", 64)
    first = transform(
        arch,
        0x1000,
        0x1004,
        {ExprMem(pointer, 32): ExprInt(0x11223344, 32)},
    )
    second = transform(
        arch,
        0x1004,
        0x1008,
        {
            ExprId("X1", 64): zero_extend(
                ExprMem(pointer + ExprInt(1, 64), 16),
                64,
            ),
            ExprMem(pointer + ExprInt(1, 64), 16): ExprInt(0xAABB, 16),
        },
    )
    concrete = state(arch, X0=0x2000, X1=0)
    composed = first.composed_with(second)

    assert composed.eval_register_transforms(concrete)["X1"] == 0x2233
    assert composed.eval_memory_transforms(concrete) == {0x2000: b"\x11\xaa\xbb\x44"}


def test_symbolic_memory_aliases_are_forwarded_conditionally():
    first = transform(
        X86,
        0x1000,
        0x1001,
        {ExprMem(ExprId("RAX", 64), 8): ExprInt(0x42, 8)},
    )
    second = transform(
        X86,
        0x1001,
        0x1002,
        {ExprId("BL", 8): ExprMem(ExprId("RCX", 64), 8)},
    )
    composed = first.composed_with(second)

    aliased = state(X86, RAX=0x2000, RCX=0x2000, RBX=0)
    distinct = state(X86, RAX=0x2000, RCX=0x3000, RBX=0)
    distinct.write_memory(0x3000, b"\x99")

    assert composed.eval_register_transforms(aliased)["RBX"] == 0x42
    assert composed.eval_register_transforms(distinct)["RBX"] == 0x99


def test_deferred_memory_reads_remain_compact_over_growing_write_history():
    pointer = ExprId("RSP", 64)
    transforms = [
        transform(
            X86,
            0x1000 + index,
            0x1001 + index,
            {ExprMem(pointer + ExprInt(index, 64), 8): ExprInt(index & 0xFF, 8)},
        )
        for index in range(2_000)
    ]
    transforms.append(
        transform(
            X86,
            0x1000 + len(transforms),
            0x1001 + len(transforms),
            {ExprId("RAX", 64): zero_extend(ExprMem(pointer + ExprInt(1_999, 64), 8), 64)},
        )
    )
    composed = SymbolicTransformComposer(transforms[0])
    for item in transforms[1:]:
        composed.append(item)
    result = composed.finish()
    expression = result.canonical_register_outputs()["RAX"]
    concrete = state(X86, RSP=0x2000, RAX=0)

    assert "focaccia_memory_byte" in repr(expression)
    assert "ExprCond" not in repr(expression)
    assert len(repr(expression)) < 500
    assert result.eval_register_transforms(concrete)["RAX"] == 1_999 & 0xFF


def test_deferred_memory_reads_fail_closed_on_missing_source_bytes():
    pointer = ExprId("RSP", 64)
    first = transform(
        X86,
        0x1000,
        0x1001,
        {ExprId("RAX", 64): zero_extend(ExprMem(pointer, 8), 64)},
    )
    concrete = state(X86, RSP=0x2000, RAX=0)

    with pytest.raises(Exception, match="unknown in sparse memory"):
        first.eval_register_transforms(concrete)


def test_deferred_memory_reads_honor_ordered_write_prefixes():
    pointer = ExprId("RSP", 64)
    first = transform(
        X86,
        0x1000,
        0x1001,
        {ExprMem(pointer, 8): ExprInt(0x11, 8)},
    )
    load = transform(
        X86,
        0x1001,
        0x1002,
        {ExprId("AL", 8): ExprMem(pointer, 8)},
    )
    overwrite = transform(
        X86,
        0x1002,
        0x1003,
        {ExprMem(pointer, 8): ExprInt(0x22, 8)},
    )
    concrete = state(X86, RSP=0x2000, RAX=0)
    concrete.write_memory(0x2000, b"\x00")

    result = first.composed_with(load).composed_with(overwrite)

    assert result.eval_register_transforms(concrete)["RAX"] == 0x11
    assert result.eval_memory_transforms(concrete) == {0x2000: b"\x22"}


def test_deferred_memory_evaluator_rejects_malformed_and_unknown_operations():
    concrete = state(X86, RAX=0)
    evaluator = _TransformEvaluator(concrete, [])

    assert evaluator.resolve_environment_operation("unknown", ()) is None
    assert evaluator.resolve_environment_operation("focaccia_memory_byte", ()) is None
    assert (
        evaluator.resolve_environment_operation(
            "focaccia_memory_byte",
            (ExprId("RAX", 64), ExprInt(0, 64)),
        )
        is None
    )
    unresolved = ExprOp(
        "focaccia_memory_byte",
        ExprId("RAX", 64),
        ExprInt(0, 64),
    )
    with pytest.raises(Exception, match="unknown in sparse memory"):
        evaluator.evaluate(unresolved)


def test_unresolved_custom_operation_and_memory_remain_symbolic():
    concrete = state(X86, RAX=0)

    class UnknownResolver(MiasmSymbolResolver):
        def __init__(self):
            super().__init__(concrete, LocationDB())

        def resolve_register(self, regname):
            del regname
            return None

        def resolve_memory(self, addr, size):
            del addr, size
            return None

    resolver = UnknownResolver()
    operation = ExprOp(
        "focaccia_memory_byte",
        ExprId("RAX", 64),
        ExprInt(0, 64),
    )
    symbolic_address = ExprMem(ExprId("RAX", 64), 8)
    missing_memory = ExprMem(ExprInt(0x2000, 64), 8)

    assert eval_expr(operation, resolver) == operation
    assert eval_expr(symbolic_address, resolver) == symbolic_address
    assert eval_expr(missing_memory, resolver) == missing_memory


def test_symbolic_state_composition_is_associative_for_register_and_memory_dependencies():
    pointer = ExprId("RSP", 64)
    first = transform(
        X86,
        0x1000,
        0x1001,
        {ExprMem(pointer, 16): ExprInt(0x1234, 16)},
    )
    second = transform(
        X86,
        0x1001,
        0x1002,
        {ExprId("EBX", 32): zero_extend(ExprMem(pointer, 16), 32)},
    )
    third = transform(
        X86,
        0x1002,
        0x1003,
        {ExprId("ECX", 32): ExprId("EBX", 32) + ExprInt(1, 32)},
    )
    concrete = state(X86, RSP=0x2000, RBX=0, RCX=0)

    left = first.composed_with(second).composed_with(third)
    right = first.composed_with(second.composed_with(third))

    assert left.eval_register_transforms(concrete) == right.eval_register_transforms(concrete)
    assert left.eval_register_transforms(concrete)["RCX"] == 0x1235
    assert left.eval_memory_transforms(concrete) == right.eval_memory_transforms(concrete)


def test_composition_rejects_discontinuous_architecture_and_thread_inputs():
    linear = transform(X86, 0x1000, 0x1001, {})
    composer = SymbolicTransformComposer(linear)
    invalid = (
        ("discontinuous", transform(X86, 0x1002, 0x1003, {})),
        ("thread", transform(X86, 0x1001, 0x1002, {}, tid=2)),
        (
            "architectures",
            transform(aarch64.ArchAArch64("little"), 0x1001, 0x1002, {}),
        ),
    )

    for message, item in invalid:
        with pytest.raises(SymbolicCompositionError, match=message):
            linear.composed_with(item)
        with pytest.raises(SymbolicCompositionError, match=message):
            composer.append(item)
