void main() {
    asm("mov rax, 0x17b3693f77fb6e9");
    asm("mov rbx, 0x8f635a775ad3b9b4");
    asm("mov rcx, 0xb717b75da9983018");
    asm("bextr eax, ebx, ecx");
}

