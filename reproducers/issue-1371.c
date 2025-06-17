void main() {
    asm("mov rax, 0x65b2e276ad27c67");
    asm("mov rbx, 0x62f34955226b2b5d");
    asm("blsmsk eax, ebx");
}

