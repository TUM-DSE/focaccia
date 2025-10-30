void main() {
    asm("mov $0x17b3693f77fb6e9, %rax");
    asm("mov $0x8f635a775ad3b9b4, %rbx");
    asm("mov $0xb717b75da9983018, %rcx");
    asm("bextr %ecx, %ebx, %eax");
}
