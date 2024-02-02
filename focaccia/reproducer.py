
from typing import Iterable

import lldb

from .lldb_target import LLDBConcreteTarget
from .symbolic import SymbolicTransform, collect_symbolic_trace, eval_symbol
from .compare import _find_errors_symbolic
from .parser import parse_arancini, parse_arancini3
from .arch import x86



class Reproducer():
    def __init__(self, oracle: str, argv: list[str], emu: str) -> None:
        
        self.oracle = oracle
        self.argv = argv
        self.emu = emu

        self.nbb = len(self.get_breakpoints())

        #self.log = {"concrete": self.record_concrete(),
        #            "emulator": self.record_emulator(),
        #            "symbolic": self.record_symbolic(),
        #            "combined": [],}
        #self.log["combined"] = self.combine_logs()
        
                
        
        
        




    def bp(self):

        x1 = [i["pc"] for i in self.record_concrete()]
        x2 = self.get_breakpoints()
        x3 = self.record_emulator()
        #x3 = parse_arancini3()


        breakpoint()
        k1 = [i["pc"] for i in self.log["emulator"]]
        k2 = [i["pc"] for i in self.log["concrete"]]
        k3 = [i["pc"] for i in self.log["symbolic"]]
        k4 = self.combine_logs()
        for i in self.combine_logs():
            print(i["sym"].get_used_memory_addresses())
            print(i["sym"].get_used_registers())
            print(i["bb"])

        a1 = [i["esnap"].regs for i in self.combine_logs()]
        a2 = [i["csnap"].regs for i in self.combine_logs()]
        for a1, a2 in zip(a1, a2):
            res1 = [(i, a1[i] == a2[i] or a1[i] == None) for i in a1.keys()]
            res2 = [a1[i] == a2[i] or a1[i] == None for i in a1.keys()]
            # registers are same or none except RSP
            # I assume it is because of different stack addresses
            #breakpoint()

    
    def record_concrete(self) -> list[dict]:
        target = LLDBConcreteTarget(self.oracle, self.argv)

        concrete_log = [{
            "pc": target.read_register("pc"), 
            "snap": target.record_snapshot(),
            "bb": self.get_basic_block(target, target.read_register("pc"))
        }]
        for address in self.get_breakpoints()[1:]:
            target.run_until(address)
            concrete_log.append({
                "pc":   target.read_register("pc"),
                "snap": target.record_snapshot(),
                "bb":   target.get_basic_block(address),
            })

        return concrete_log

    def record_emulator(self) -> list:
        with open(self.emu, "r") as emu_trace:
            emulator_log = parse_arancini3(emu_trace, x86.ArchX86())       
            return emulator_log


    def record_emulator1(self) -> list:
        with open(self.emu, "r") as emu_trace:
            emulator_log = parse_arancini(emu_trace, x86.ArchX86())

            #filtered_emulator_log = [emulator_log[0]]
            #for i in emulator_log[1:]:
            #    if i.read_register("pc") != filtered_emulator_log[-1].read_register("pc"):
            #        filtered_emulator_log.append(i)
                    
            return [{"pc": i.read_register("pc"), "snap": i} for i in emulator_log]







    def compare_logs(self):
        for i in self.combine_logs():
            print(i["sym"].get_used_memory_addresses())
            print(i["sym"].get_used_registers())
            print(i["bb"])
            # use these to find the needed addresses and registers
            # exact values from i["csnap"]
        pass
    
    def combine_logs(self):
        k1 = [i["pc"] for i in self.log["emulator"]]
        k2 = [i["pc"] for i in self.log["concrete"]]
        k3 = [i["pc"] for i in self.log["symbolic"]]
        assert(k1 == k2 == k3)

        combined_log = []
        for i in range(len(self.get_breakpoints())-1):
            entry = {}
            entry["pc"] = self.log["emulator"][i]["pc"]
            entry["bb"] = self.log["concrete"][i]["bb"]
            entry["sym"] = self.log["symbolic"][i]["sym"]
            entry["csnap"] = self.log["concrete"][i]["snap"]
            entry["esnap"] = self.log["emulator"][i]["snap"]

            current_state = self.log["emulator"][i]["snap"]
            next_state = self.log["emulator"][i+1]["snap"]
            transformation = self.log["symbolic"][i]["sym"]
            errors = _find_errors_symbolic(current_state, next_state, transformation)
            entry["err"] = errors

            combined_log.append(entry)
        
        return combined_log
    

    def get_breakpoints(self) -> list[int]:
        return [i["pc"] for i in self.record_emulator()]


    def record_symbolic(self) -> list:
        symbolic_trace = collect_symbolic_trace(self.oracle, self.argv)

        symbolic_log = [symbolic_trace.pop(0)]
        for address in self.get_breakpoints()[1:]:
            while symbolic_trace[0].addr != address:
                symbolic_log[-1].concat(symbolic_trace.pop(0))
            symbolic_log.append(symbolic_trace.pop(0))

        return [{"pc": s.addr, "sym": s} for s in symbolic_log]
    

    
    def run_until(self, target: LLDBConcreteTarget, address: int) -> None:
        bp = target.target.BreakpointCreateByAddress(address) #target.set_breakpoint(address)
        while target.read_register("pc") != address:
            target.run()
        target.target.BreakpointDelete(bp.GetID()) #target.remove_breakpoint(address)

    def get_basic_block(self, target: LLDBConcreteTarget, addr: int) -> [lldb.SBInstruction]:
        block = []
        while not target.target.ReadInstructions(lldb.SBAddress(addr, target.target), 1)[0].is_branch:
            block.append(target.target.ReadInstructions(lldb.SBAddress(addr, target.target), 1)[0])
            addr += target.target.ReadInstructions(lldb.SBAddress(addr, target.target), 1)[0].size
        block.append(target.target.ReadInstructions(lldb.SBAddress(addr, target.target), 1)[0])

        return block




        
        

    #f"{i.GetMnemonic(self.target)} {i.GetOperands(self.target)}"
    
    def reproducer_asm(result, data):
        reproducers = [str]
        general_regs = ['RIP', 'RAX', 'RBX','RCX','RDX', 'RSI','RDI','RBP','RSP','R8','R9','R10','R11','R12','R13','R14','R15',]
        flag_regs = ['CF', 'PF', 'AF', 'ZF', 'SF', 'TF', 'IF', 'DF', 'OF', 'IOPL', 'NT',]
        eflag_regs = ['RF', 'VM', 'AC', 'VIF', 'VIP', 'ID',]

        for res in result:
            asm = f'# Reproducer for the block starting at {hex(res["pc"])}\n'
            asm += f'.section .text\n'
            asm += f'.global _start\n'
            asm += f'\n'

            asm += f'_start:\n'
            asm += f'call _setup_mem\n'
            asm += f'call _setup_regs\n'
            asm += f'call _foo\n'
            asm += f'call _exit\n'
            asm += f'\n'

            # Setup for memory


            # Setup for registers
            asm += f'_setup_regs:\n'
            for reg in res["ref"].get_used_registers():
                if reg in general_regs:
                    asm += f'mov ${hex(res["cur"].regs[reg])}, %{reg.lower()}\n'
            if 'RFLAGS' in res["ref"].get_used_registers():
                asm += f'pushfq {res["cur"].regs["RFLAGS"]}\n'
            if any(reg in res["ref"].get_used_registers() for reg in flag_regs+eflag_regs):
                asm += f'pushfd {x86.compose_rflags(res["cur"].regs)}\n'
            asm += f'ret\n'
            asm += f'\n'

            # The exit stub for LINUX
            asm += f'_exit:\n'
            asm += f'movq $0, %rdi\n'
            asm += f'movq $60, %rax\n'
            asm += f'syscall\n'
            asm += f'\n'

            # The basic block
            asm += f'.org {hex(res["pc"])}\n'
            asm +=f'_foo:\n'
            for instruction in res["bb"]:
                asm += f'{instruction}\n'
            asm += f'\n'

            #print(res["txl"].mem._pages)

            asm += f'_setup_mem:\n'
            for mem in res["ref"].get_used_memory_addresses():
                asm += f'{mem}\n'
                #breakpoint()
            asm += f'ret\n'
            asm += f'\n'

            print(asm)
            reproducers.append(asm)
            #breakpoint()
        return reproducers
    
def compose_rflags(rflags: dict[str, int]) -> int:
    """Compose the RFLAGS register's value into its separate flags.

    Uses flag name abbreviation conventions from
    `https://en.wikipedia.org/wiki/FLAGS_register`.

    Use PUSHFD (for 32 bit) to set the flags
    PUSHF (for 16 bit)
    PUSHFQ for 64 bit
    https://stackoverflow.com/questions/1406783/how-to-read-and-write-x86-flags-registers-directly

    :param rflags: A dictionary mapping Miasm's flag names to their alues.
    :return: The RFLAGS register value.
    """
    return (
        # FLAGS
        (0x0001 if rflags['CF']   else 0) |
                        # 0x0002   reserved
        (0x0004 if rflags['PF']   else 0) |
                        # 0x0008   reserved
        (0x0010 if rflags['AF']   else 0) |
                        # 0x0020   reserved
        (0x0040 if rflags['ZF']   else 0) |
        (0x0080 if rflags['SF']   else 0) |
        (0x0100 if rflags['TF']   else 0) |
        (0x0200 if rflags['IF']   else 0) |
        (0x0400 if rflags['DF']   else 0) |
        (0x0800 if rflags['OF']   else 0) |
        (0x3000 if rflags['IOPL'] else 0) |
        (0x4000 if rflags['NT']   else 0) |

        # EFLAGS
        (0x00010000 if rflags['RF']  else 0) |
        (0x00020000 if rflags['VM']  else 0) |
        (0x00040000 if rflags['AC']  else 0) |
        (0x00080000 if rflags['VIF'] else 0) |
        (0x00100000 if rflags['VIP'] else 0) |
        (0x00200000 if rflags['ID']  else 0)
    )