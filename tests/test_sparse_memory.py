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

