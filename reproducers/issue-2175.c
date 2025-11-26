int main() {
  __asm__ (
    "movq $0x1, %r8\n"
    "mov $0xedbf530a, %r9\n"
    "blsi %r9d, %r8d\n"
  );

  return 0;
}
