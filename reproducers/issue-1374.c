void main() {
    asm("mov $0xb1aa9da2fe33fe3, %rcx");
    asm("mov $0x80000000ffffffff, %rbx");
    asm("mov $0xf3fce8829b99a5c6, %rax");
    asm("bzhi %rax, %rbx, %rcx");
}
