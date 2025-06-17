int main() {
  __asm__ (
    "movq $0x1, %r8\n"
    "mov $0xedbf530a, %r9\n"
    "push $0x1\n"
    "popf\n"
    "blsi %r9d, %r8d\n"
    "pushf\n"
    "pop %rax\n"
    "pop %rbp\n"
    "ret\n"
  );

  return 0;
}

