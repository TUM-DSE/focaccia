void main() {
    asm("push 512; popfq;");
    asm("mov rax, 0xffffffff84fdbf24");
    asm("mov rbx, 0xb197d26043bec15d");
    asm("adox eax, ebx");
}
