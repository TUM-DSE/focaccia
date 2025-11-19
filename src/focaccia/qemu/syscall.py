class SyscallInfo:
    def __init__(self, 
                 name: str,
                 patchup_registers: list[str] | None = None,
                 patchup_address_registers: list[str] | None = None):
        """Describes a syscall by its name and outputs.

        :param name: The name of a system call.
        :param patchup_registers: Registers that must be replaced with deterministic values.
        """
        self.name = name
        self.patchup_registers = patchup_registers
        self.patchup_address_registers = patchup_address_registers

