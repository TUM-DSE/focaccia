from __future__ import annotations

from dataclasses import dataclass

import pytest
from hypothesis import given, settings, strategies as st

from focaccia.snapshot import MemoryAccessError, SparseMemory


PROPERTY_SETTINGS = settings(
    max_examples=100,
    derandomize=True,
    database=None,
    deadline=None,
)


@dataclass(frozen=True)
class Write:
    address: int
    data: bytes


@dataclass(frozen=True)
class Probe:
    address: int
    size: int


@dataclass(frozen=True)
class DropAll:
    pass


Operation = Write | Probe | DropAll

ADDRESSES = st.integers(min_value=0, max_value=255)
DATA = st.binary(min_size=0, max_size=48)
WRITES = st.builds(Write, address=ADDRESSES, data=DATA)
PROBES = st.builds(
    Probe,
    address=st.integers(min_value=0, max_value=303),
    size=st.integers(min_value=0, max_value=48),
)
OPERATIONS = st.lists(
    st.one_of(WRITES, WRITES, WRITES, PROBES, PROBES, st.just(DropAll())),
    min_size=1,
    max_size=50,
)
PAGE_SIZES = st.integers(min_value=1, max_value=64)


def model_ranges(model: dict[int, int]) -> list[tuple[int, bytes]]:
    ranges: list[tuple[int, bytes]] = []
    start: int | None = None
    previous: int | None = None
    data = bytearray()

    for address in sorted(model):
        if previous is None or address != previous + 1:
            if start is not None:
                ranges.append((start, bytes(data)))
            start = address
            data = bytearray()
        data.append(model[address])
        previous = address

    if start is not None:
        ranges.append((start, bytes(data)))
    return ranges


def assert_matches_model(memory: SparseMemory, model: dict[int, int]) -> None:
    ranges = memory.known_ranges()
    assert ranges == model_ranges(model)

    previous_end: int | None = None
    reconstructed: dict[int, int] = {}
    for start, data in ranges:
        assert data
        if previous_end is not None:
            assert start > previous_end
        for offset, value in enumerate(data):
            reconstructed[start + offset] = value
        previous_end = start + len(data)
    assert reconstructed == model


def apply_operation(memory: SparseMemory, model: dict[int, int], operation: Operation) -> None:
    if isinstance(operation, Write):
        memory.write(operation.address, operation.data)
        for offset, value in enumerate(operation.data):
            model[operation.address + offset] = value
    elif isinstance(operation, DropAll):
        memory.drop_all()
        model.clear()
    else:
        addresses = range(operation.address, operation.address + operation.size)
        expected_known = all(address in model for address in addresses)
        assert memory.test(operation.address, operation.size) is expected_known
        if expected_known:
            assert memory.read(operation.address, operation.size) == bytes(
                model[address] for address in addresses
            )
        else:
            first_unknown = next(address for address in addresses if address not in model)
            with pytest.raises(MemoryAccessError) as raised:
                memory.read(operation.address, operation.size)
            assert raised.value.mem_addr == first_unknown
            assert raised.value.mem_size == 1

    assert_matches_model(memory, model)


@PROPERTY_SETTINGS
@given(page_size=PAGE_SIZES, operations=OPERATIONS)
def test_sparse_memory_operation_sequences_match_independent_byte_model(
    page_size: int,
    operations: list[Operation],
) -> None:
    memory = SparseMemory(page_size=page_size)
    model: dict[int, int] = {}

    for operation in operations:
        apply_operation(memory, model, operation)


@PROPERTY_SETTINGS
@given(
    first_page_size=PAGE_SIZES,
    second_page_size=PAGE_SIZES,
    operations=OPERATIONS,
)
def test_sparse_memory_semantics_do_not_depend_on_page_size(
    first_page_size: int,
    second_page_size: int,
    operations: list[Operation],
) -> None:
    first = SparseMemory(page_size=first_page_size)
    second = SparseMemory(page_size=second_page_size)
    first_model: dict[int, int] = {}
    second_model: dict[int, int] = {}

    for operation in operations:
        apply_operation(first, first_model, operation)
        apply_operation(second, second_model, operation)
        assert first.known_ranges() == second.known_ranges()


@PROPERTY_SETTINGS
@given(page_size=PAGE_SIZES, address=ADDRESSES, data=DATA, split=st.data())
def test_splitting_a_write_is_equivalent_to_the_original_write(
    page_size: int,
    address: int,
    data: bytes,
    split: st.DataObject,
) -> None:
    split_at = split.draw(st.integers(min_value=0, max_value=len(data)))
    combined = SparseMemory(page_size=page_size)
    separated = SparseMemory(page_size=page_size)

    combined.write(address, data)
    separated.write(address, data[:split_at])
    separated.write(address + split_at, data[split_at:])

    assert combined.known_ranges() == separated.known_ranges()
    assert combined.test(address, len(data))
    assert separated.test(address, len(data))
    assert combined.read(address, len(data)) == separated.read(address, len(data)) == data


@PROPERTY_SETTINGS
@given(
    page_size=PAGE_SIZES,
    first_address=ADDRESSES,
    first_data=DATA,
    gap=st.integers(min_value=1, max_value=32),
    second_data=DATA,
)
def test_disjoint_writes_commute(
    page_size: int,
    first_address: int,
    first_data: bytes,
    gap: int,
    second_data: bytes,
) -> None:
    second_address = first_address + len(first_data) + gap
    forward = SparseMemory(page_size=page_size)
    reverse = SparseMemory(page_size=page_size)

    forward.write(first_address, first_data)
    forward.write(second_address, second_data)
    reverse.write(second_address, second_data)
    reverse.write(first_address, first_data)

    assert forward.known_ranges() == reverse.known_ranges()


@PROPERTY_SETTINGS
@given(
    page_size=PAGE_SIZES,
    address=ADDRESSES,
    initial=st.binary(min_size=1, max_size=48),
    overwrite=st.binary(min_size=1, max_size=48),
    offset=st.data(),
)
def test_overlapping_writes_use_the_last_value_for_each_byte(
    page_size: int,
    address: int,
    initial: bytes,
    overwrite: bytes,
    offset: st.DataObject,
) -> None:
    overwrite_offset = offset.draw(st.integers(min_value=0, max_value=len(initial) - 1))
    memory = SparseMemory(page_size=page_size)
    model: dict[int, int] = {}

    apply_operation(memory, model, Write(address, initial))
    apply_operation(memory, model, Write(address + overwrite_offset, overwrite))

    start = min(model)
    end = max(model) + 1
    assert memory.read(start, end - start) == bytes(model[index] for index in range(start, end))


@PROPERTY_SETTINGS
@given(page_size=PAGE_SIZES, address=ADDRESSES, writes=st.lists(WRITES, max_size=20))
def test_zero_length_operations_are_identities(
    page_size: int,
    address: int,
    writes: list[Write],
) -> None:
    memory = SparseMemory(page_size=page_size)
    model: dict[int, int] = {}
    for write in writes:
        apply_operation(memory, model, write)

    before = memory.known_ranges()
    memory.write(address, b"")

    assert memory.known_ranges() == before
    assert memory.test(address, 0)
    assert memory.read(address, 0) == b""
