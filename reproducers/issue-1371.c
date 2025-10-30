void main() {
    asm("mov $0x65b2e276ad27c67, %rax");
    asm("mov $0x62f34955226b2b5d, %rbx");
    asm("blsmsk %ebx, %eax");
}
