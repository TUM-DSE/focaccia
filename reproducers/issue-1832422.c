void main() {
    asm(".intel_syntax noprefix");
    asm("cmppd xmm0,xmm0,0xd1");
}
