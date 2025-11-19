from focaccia.qemu.x86 import emulated_system_calls as x86_emu_syscalls

emulated_system_calls = {
    'x86_64': x86_emu_syscalls,
    'aarch64': { },
    'aarch64l': { },
    'aarch64b': { }
}

