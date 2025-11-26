class SyscallInfo:
    def __init__(self, 
                 name: str,
                 patchup_registers: list[str] | None = None,
                 patchup_address_registers: list[str] | None = None,
                 creates_thread: bool = False,
                 return_from_signal: bool = False,
                 sets_signal_restorer: bool = False):
        """Describes a syscall by its name and outputs.

        :param name: The name of a system call.
        :param patchup_registers: Registers that must be replaced with deterministic values.
        :param patchup_address_registers: Registers that contain addresses to be looked up when
        mapping to native addresses.
        :param creates_thread: True when the system call creates a new thread.
        """
        self.name = name
        self.patchup_registers = patchup_registers
        self.patchup_address_registers = patchup_address_registers
        self.creates_thread = creates_thread
        self.return_from_signal = return_from_signal
        self.sets_signal_restorer = sets_signal_restorer

