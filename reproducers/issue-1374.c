void main() {
    asm("mov rax, 0xb1aa9da2fe33fe3");
    asm("mov rbx, 0x80000000ffffffff");
    asm("mov rcx, 0xf3fce8829b99a5c6");
    asm("bzhi rax, rbx, rcx");
}

