from __future__ import annotations

from dataclasses import dataclass

import pytest
from hypothesis import given, settings, strategies as st

from focaccia.arch import aarch64, x86
from focaccia.arch.arch import Arch
from focaccia.snapshot import ProgramState, RegisterAccessError


PROPERTY_SETTINGS = settings(
    max_examples=100,
    derandomize=True,
    database=None,
    deadline=None,
)
ARCHITECTURES = (
    x86.ArchX86(),
    aarch64.ArchAArch64("little"),
    aarch64.ArchAArch64("big"),
)


@dataclass(frozen=True)
class ObservedWrite:
    regname: str
    value: int


@dataclass(frozen=True)
class BitWrite:
    regname: str
    value: int
    valid_mask: int


RegisterOperation = ObservedWrite | BitWrite


@dataclass(frozen=True)
class RegisterSequence:
    arch: Arch
    base_reg: str
    operations: tuple[RegisterOperation, ...]


@st.composite
def mutable_register_values(draw: st.DrawFn) -> tuple[Arch, str, int]:
    arch = draw(st.sampled_from(ARCHITECTURES))
    regname = draw(
        st.sampled_from(
            sorted(name for name in arch.all_regnames if not arch.is_constant_register(name))
        )
    )
    accessor = arch.get_reg_accessor(regname)
    assert accessor is not None
    value = draw(st.integers(min_value=0, max_value=(1 << accessor.num_bits) - 1))
    return arch, regname, value


@st.composite
def register_sequences(draw: st.DrawFn) -> RegisterSequence:
    arch = draw(st.sampled_from(ARCHITECTURES))
    base_reg = draw(st.sampled_from(sorted(arch.regnames)))
    aliases = sorted(
        name
        for name in arch.all_regnames
        if (accessor := arch.get_reg_accessor(name)) is not None
        and accessor.base_reg == base_reg
    )
    operation_count = draw(st.integers(min_value=0, max_value=30))
    operations: list[RegisterOperation] = []
    for _ in range(operation_count):
        regname = draw(st.sampled_from(aliases))
        accessor = arch.get_reg_accessor(regname)
        assert accessor is not None
        value = draw(st.integers(min_value=0, max_value=(1 << accessor.num_bits) - 1))
        if draw(st.booleans()):
            operations.append(ObservedWrite(regname, value))
        else:
            valid_mask = draw(
                st.integers(min_value=0, max_value=(1 << accessor.num_bits) - 1)
            )
            operations.append(BitWrite(regname, value, valid_mask))
    return RegisterSequence(arch, base_reg, tuple(operations))


@st.composite
def proper_low_alias_values(draw: st.DrawFn) -> tuple[Arch, str, int]:
    arch = draw(st.sampled_from(ARCHITECTURES))
    aliases = []
    for name in sorted(arch.all_regnames):
        accessor = arch.get_reg_accessor(name)
        if accessor is None or arch.is_constant_register(name):
            continue
        base = arch.get_reg_accessor(accessor.base_reg)
        assert base is not None
        if accessor.start == 0 and accessor.num_bits < base.num_bits:
            aliases.append(name)
    regname = draw(st.sampled_from(aliases))
    accessor = arch.get_reg_accessor(regname)
    assert accessor is not None
    value = draw(st.integers(min_value=0, max_value=(1 << accessor.num_bits) - 1))
    return arch, regname, value


def aliases_for_base(arch: Arch, base_reg: str) -> list[str]:
    return sorted(
        name
        for name in arch.all_regnames
        if (accessor := arch.get_reg_accessor(name)) is not None
        and accessor.base_reg == base_reg
    )


def assert_register_model(
    state: ProgramState,
    base_reg: str,
    stored: int,
    validity: int,
) -> None:
    arch = state.arch
    base = arch.get_reg_accessor(base_reg)
    assert base is not None
    base_mask = (1 << base.num_bits) - 1
    expected_bits = {} if validity == 0 else {base_reg: (stored & validity, validity)}
    assert state.known_register_bits() == expected_bits

    expected_full_values: dict[str, int] = {}
    expected_partial_values: dict[str, int] = {}
    if validity & base.mask == base.mask:
        expected_full_values[base_reg] = stored & base_mask
        expected_partial_values[base_reg] = stored & base_mask

    for regname in aliases_for_base(arch, base_reg):
        accessor = arch.get_reg_accessor(regname)
        assert accessor is not None
        known = validity & accessor.mask == accessor.mask
        assert state.test_register(regname) is known
        if known:
            expected = (stored & accessor.mask) >> accessor.start
            assert state.read_register(regname) == expected
            if regname != base_reg and validity != base.mask:
                expected_partial_values[regname] = expected
        else:
            with pytest.raises(RegisterAccessError):
                state.read_register(regname)

    assert state.known_register_values() == expected_full_values
    assert state.known_register_values(include_partial=True) == expected_partial_values


@PROPERTY_SETTINGS
@given(case=mutable_register_values())
def test_full_base_observations_select_every_alias_exactly(
    case: tuple[Arch, str, int],
) -> None:
    arch, regname, value = case
    accessor = arch.get_reg_accessor(regname)
    assert accessor is not None
    base = arch.get_reg_accessor(accessor.base_reg)
    assert base is not None
    base_value = value << accessor.start
    state = ProgramState(arch)

    state.write_register(accessor.base_reg, base_value)

    assert state.read_register(regname) == value
    assert state.known_register_bits() == {
        accessor.base_reg: (base_value & base.mask, base.mask)
    }


@PROPERTY_SETTINGS
@given(sequence=register_sequences())
def test_observed_register_bits_match_independent_value_and_validity_model(
    sequence: RegisterSequence,
) -> None:
    state = ProgramState(sequence.arch)
    base = sequence.arch.get_reg_accessor(sequence.base_reg)
    assert base is not None
    base_mask = (1 << base.num_bits) - 1
    stored = 0
    validity = 0

    assert_register_model(state, sequence.base_reg, stored, validity)
    for operation in sequence.operations:
        accessor = sequence.arch.get_reg_accessor(operation.regname)
        assert accessor is not None
        if isinstance(operation, ObservedWrite):
            state.write_register(operation.regname, operation.value)
            stored &= ~accessor.mask & base_mask
            stored |= operation.value << accessor.start & accessor.mask
            validity |= accessor.mask
        else:
            state.write_register_bits(
                operation.regname,
                operation.value,
                operation.valid_mask,
            )
            shifted_validity = operation.valid_mask << accessor.start & accessor.mask
            stored = (stored & ~shifted_validity) | (
                operation.value << accessor.start & shifted_validity
            )
            validity |= shifted_validity
        assert_register_model(state, sequence.base_reg, stored, validity)


@PROPERTY_SETTINGS
@given(case=proper_low_alias_values())
def test_explicit_zero_extension_makes_the_entire_base_known(
    case: tuple[Arch, str, int],
) -> None:
    arch, regname, value = case
    accessor = arch.get_reg_accessor(regname)
    assert accessor is not None
    base = arch.get_reg_accessor(accessor.base_reg)
    assert base is not None
    state = ProgramState(arch)

    state.write_register_zero_extended(regname, value)

    assert state.read_register(accessor.base_reg) == value
    assert state.known_register_bits() == {
        accessor.base_reg: (value, (1 << base.num_bits) - 1)
    }


@PROPERTY_SETTINGS
@given(case=mutable_register_values())
def test_register_names_are_case_insensitive_without_changing_semantics(
    case: tuple[Arch, str, int],
) -> None:
    arch, regname, value = case
    lower = regname.lower()
    upper = regname.upper()
    lower_state = ProgramState(arch)
    upper_state = ProgramState(arch)

    lower_state.write_register(lower, value)
    upper_state.write_register(upper, value)

    assert lower_state.known_register_bits() == upper_state.known_register_bits()
    assert lower_state.read_register(lower) == upper_state.read_register(upper) == value


@PROPERTY_SETTINGS
@given(case=mutable_register_values(), initial=st.integers(min_value=0, max_value=(1 << 512) - 1))
def test_compose_and_decompose_follow_declared_accessor_ranges(
    case: tuple[Arch, str, int],
    initial: int,
) -> None:
    arch, regname, value = case
    accessor = arch.get_reg_accessor(regname)
    assert accessor is not None
    base = arch.get_reg_accessor(accessor.base_reg)
    assert base is not None
    base_mask = (1 << base.num_bits) - 1

    composed = arch.compose_register(
        accessor.base_reg,
        {regname: value},
        initial_value=initial,
    )

    expected = initial & base_mask
    expected = (expected & ~accessor.mask) | (value << accessor.start)
    assert composed == expected
    assert arch.decompose_register(accessor.base_reg, composed, [regname]) == {
        regname: value
    }


@PROPERTY_SETTINGS
@given(
    regname=st.sampled_from(("XZR", "WZR", "RZR", "xzr", "wzr", "rzr")),
    value=st.integers(min_value=0, max_value=(1 << 64) - 1),
    valid_mask=st.integers(min_value=0, max_value=(1 << 32) - 1),
)
def test_aarch64_constant_registers_ignore_all_generated_writes(
    regname: str,
    value: int,
    valid_mask: int,
) -> None:
    arch = aarch64.ArchAArch64("little")
    state = ProgramState(arch)
    accessor = arch.get_reg_accessor(regname)
    assert accessor is not None
    fitting_value = value & ((1 << accessor.num_bits) - 1)
    fitting_validity = valid_mask & ((1 << accessor.num_bits) - 1)

    state.write_register(regname, fitting_value)
    state.write_register_bits(regname, fitting_value, fitting_validity)
    if accessor.start == 0:
        state.write_register_zero_extended(regname, fitting_value)

    assert state.test_register(regname)
    assert state.read_register(regname) == 0
    assert state.known_register_bits() == {}
