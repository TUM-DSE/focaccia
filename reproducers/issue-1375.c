void main() {
    asm("mov rax, 0x000000007fffffff; push rax; mov rax, 0x00000000ffffffff; push rax; movdqu XMM1, [rsp];");
    asm("mov rax, 0x2e711de7aa46af1a; push rax; mov rax, 0x7fffffff7fffffff; push rax; movdqu XMM2, [rsp];");
    asm("addsubps xmm1, xmm2");
}
