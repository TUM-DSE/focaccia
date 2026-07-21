import pytest

from focaccia.snapshot import SparseMemory, MemoryAccessError

@pytest.fixture
def mem():
    return SparseMemory()

def test_oob_read(mem):
    for addr in range(mem.page_size):
        with pytest.raises(MemoryAccessError):
            mem.read(addr, 1)
        with pytest.raises(MemoryAccessError): 
            mem.read(addr, 30)
        with pytest.raises(MemoryAccessError): 
            mem.read(addr + 0x10, 30)
        with pytest.raises(MemoryAccessError): 
            mem.read(addr, mem.page_size)
        with pytest.raises(MemoryAccessError): 
            mem.read(addr, mem.page_size - 1)
        with pytest.raises(MemoryAccessError): 
            mem.read(addr, mem.page_size + 1)

def test_basic_read_write(mem):
    data = b'a' * mem.page_size * 2
    mem.write(0x300, data)
    assert mem.read(0x300, len(data)) == data
    assert mem.read(0x300, 1) == b'a'
    assert mem.read(0x400, 1) == b'a'
    assert mem.read(0x299 + mem.page_size * 2, 1) == b'a'
    assert mem.read(0x321, 12) == b'aaaaaaaaaaaa'

    mem.write(0x321, b'Hello World!')
    assert mem.read(0x321, 12) == b'Hello World!'

    with pytest.raises(MemoryAccessError): 
        mem.read(0x300, mem.page_size * 3)


def test_partial_page_write_keeps_other_bytes_unknown(mem):
    mem.write(0x42, b'known')

    assert mem.test(0x42, 5)
    assert mem.read(0x42, 5) == b'known'
    assert not mem.test(0x41)
    assert not mem.test(0x47)
    with pytest.raises(MemoryAccessError):
        mem.read(0x41, 1)
    with pytest.raises(MemoryAccessError):
        mem.read(0x42, 6)


def test_cross_page_mixed_validity(mem):
    start = mem.page_size - 1
    mem.write(start, b'A')
    mem.write(start + 2, b'C')

    assert not mem.test(start, 3)
    with pytest.raises(MemoryAccessError) as raised:
        mem.read(start, 3)
    assert raised.value.mem_addr == start + 1

    mem.write(start + 1, b'B')
    assert mem.test(start, 3)
    assert mem.read(start, 3) == b'ABC'


def test_zero_length_and_negative_sizes(mem):
    assert mem.test(0xdeadbeef, 0)
    assert mem.read(0xdeadbeef, 0) == b''
    mem.write(0x1000, b'')
    assert mem.known_ranges() == []

    with pytest.raises(ValueError):
        mem.test(0, -1)
    with pytest.raises(ValueError):
        mem.read(0, -1)


def test_known_ranges_merge_only_contiguous_bytes(mem):
    mem.write(mem.page_size - 1, b'AB')
    mem.write(mem.page_size + 2, b'D')

    assert mem.known_ranges() == [
        (mem.page_size - 1, b'AB'),
        (mem.page_size + 2, b'D'),
    ]

