import unittest

from focaccia.snapshot import SparseMemory, MemoryAccessError

class TestSparseMemory(unittest.TestCase):
    def test_oob_read(self):
        mem = SparseMemory()
        for addr in range(mem.page_size):
            self.assertRaises(MemoryAccessError, mem.read, addr, 1)
            self.assertRaises(MemoryAccessError, mem.read, addr, 30)
            self.assertRaises(MemoryAccessError, mem.read, addr + 0x10, 30)
            self.assertRaises(MemoryAccessError, mem.read, addr, mem.page_size)
            self.assertRaises(MemoryAccessError, mem.read, addr, mem.page_size - 1)
            self.assertRaises(MemoryAccessError, mem.read, addr, mem.page_size + 1)

    def test_basic_read_write(self):
        mem = SparseMemory()

        data = b'a' * mem.page_size * 2
        mem.write(0x300, data)
        self.assertEqual(mem.read(0x300, len(data)), data)
        self.assertEqual(mem.read(0x300, 1), b'a')
        self.assertEqual(mem.read(0x400, 1), b'a')
        self.assertEqual(mem.read(0x299 + mem.page_size * 2, 1), b'a')
        self.assertEqual(mem.read(0x321, 12), b'aaaaaaaaaaaa')

        mem.write(0x321, b'Hello World!')
        self.assertEqual(mem.read(0x321, 12), b'Hello World!')

        self.assertRaises(MemoryAccessError, mem.read, 0x300, mem.page_size * 3)

if __name__ == '__main__':
    unittest.main()
