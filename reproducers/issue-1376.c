void main() {
    asm(".intel_syntax noprefix");
    asm("mov rax, 0xa02e698e741f5a6a");
    asm("mov rbx, 0x20959ddd7a0aef");
    asm("lsl ax, bx");
}
