
from .lldb_target import LLDBConcreteTarget
from .snapshot import ProgramState
from .symbolic import SymbolicTransform, eval_symbol
from .arch import x86

class ReproducerMemoryError(Exception):
    pass
class ReproducerBasicBlockError(Exception):
    pass
class ReproducerRegisterError(Exception):
    pass

class Reproducer():
    def __init__(self, oracle: str, argv: str, snap: ProgramState, sym: SymbolicTransform) -> None:

        target = LLDBConcreteTarget(oracle)

        self.pc = snap.read_register("pc")
        self.bb = target.get_basic_block_inst(self.pc)
        self.sl = target.get_symbol_limit()
        self.snap = snap
        self.sym = sym

    def get_bb(self) -> str:
        try:
            asm = ""
            asm += f'_bb_{hex(self.pc)}:\n'
            for i in self.bb[:-1]:
                asm += f'{i}\n'
            asm += f'ret\n'
            asm += f'\n'

            return asm
        except:
            raise ReproducerBasicBlockError(f'{hex(self.pc)}\n{self.snap}\n{self.sym}\n{self.bb}')

    def get_regs(self) -> str:
        general_regs = ['RIP', 'RAX', 'RBX','RCX','RDX', 'RSI','RDI','RBP','RSP','R8','R9','R10','R11','R12','R13','R14','R15',]
        flag_regs = ['CF', 'PF', 'AF', 'ZF', 'SF', 'TF', 'IF', 'DF', 'OF', 'IOPL', 'NT',]
        eflag_regs = ['RF', 'VM', 'AC', 'VIF', 'VIP', 'ID',]

        try:
            asm = ""
            asm += f'_setup_regs:\n'
            for reg in self.sym.get_used_registers():
                if reg in general_regs:
                    asm += f'mov ${hex(self.snap.read_register(reg))}, %{reg.lower()}\n'

            if 'RFLAGS' in self.sym.get_used_registers():
                asm += f'pushfq ${hex(self.snap.read_register("RFLAGS"))}\n'

            if any(reg in self.sym.get_used_registers() for reg in flag_regs+eflag_regs):
                asm += f'pushfd ${hex(x86.compose_rflags(self.snap.regs))}\n'
            asm += f'ret\n'
            asm += f'\n'

            return asm
        except:
            raise ReproducerRegisterError(f'{hex(self.pc)}\n{self.snap}\n{self.sym}\n{self.bb}')

    def get_mem(self) -> str:
        try:
            asm = ""
            asm += f'_setup_mem:\n'
            for mem in self.sym.get_used_memory_addresses():
                addr = eval_symbol(mem.ptr, self.snap)
                val = self.snap.read_memory(addr, int(mem.size/8))

                if addr < self.sl:
                    asm += f'.org {hex(addr)}\n'
                    for b in val:
                        asm += f'.byte ${hex(b)}\n'
            asm += f'\n'

            return asm
        except:
            raise ReproducerMemoryError(f'{hex(self.pc)}\n{self.snap}\n{self.sym}\n{self.bb}')

    def get_dyn(self) -> str:
        try:
            asm = ""
            asm += f'_setup_dyn:\n'
            for mem in self.sym.get_used_memory_addresses():
                addr = eval_symbol(mem.ptr, self.snap)
                val = self.snap.read_memory(addr, int(mem.size/8))

                if addr >= self.sl:
                    asm += f'mov ${hex(addr)}, %rdi\n'
                    asm += f'call _alloc\n'
                    for b in val:
                        asm += f'mov ${hex(addr)}, %rax\n'
                        asm += f'movb ${hex(b)}, (%rax)\n'
                        addr += 1
            asm += f'ret\n'
            asm += f'\n'

            return asm
        except:
            raise ReproducerMemoryError(f'{hex(self.pc)}\n{self.snap}\n{self.sym}\n{self.bb}')

    def get_start(self) -> str:
        asm = ""
        asm += f'_start:\n'
        asm += f'call _setup_dyn\n'
        asm += f'call _setup_regs\n'
        asm += f'call _bb_{hex(self.pc)}\n'
        asm += f'call _exit\n'
        asm += f'\n'

        return asm

    def get_exit(self) -> str:
        asm = ""
        asm += f'_exit:\n'
        asm += f'movq $0, %rdi\n'
        asm += f'movq $60, %rax\n'
        asm += f'syscall\n'
        asm += f'\n'

        return asm

    def get_alloc(self) -> str:
        asm = ""
        asm += f'_alloc:\n'
        asm += f'movq $4096, %rsi\n'
        asm += f'movq $(PROT_READ | PROT_WRITE), %rdx\n'
        asm += f'movq $(MAP_PRIVATE | MAP_ANONYMOUS), %r10\n'
        asm += f'movq $-1, %r8\n'
        asm += f'movq $0, %r9\n'
        asm += f'movq $syscall_mmap, %rax\n'
        asm += f'syscall\n'
        asm += f'ret\n'
        asm += f'\n'

        return asm

    def get_code(self) -> str:
        asm = ""
        asm += f'.section .text\n'
        asm += f'.global _start\n'
        asm += f'\n'
        asm += f'.org {hex(self.pc)}\n'
        asm += self.get_bb()
        asm += self.get_start()
        asm += self.get_exit()
        asm += self.get_alloc()
        asm += self.get_regs()
        asm += self.get_dyn()

        return asm

    def get_data(self) -> str:
        asm = ""
        asm += f'.section .data\n'
        asm += f'PROT_READ  = 0x1\n'
        asm += f'PROT_WRITE = 0x2\n'
        asm += f'MAP_PRIVATE = 0x2\n'
        asm += f'MAP_ANONYMOUS = 0x20\n'
        asm += f'syscall_mmap = 9\n'
        asm += f'\n'

        asm += self.get_mem()

        return asm

    def asm(self) -> str:
        asm = ""
        asm += self.get_code()
        asm += self.get_data()

        return asm
