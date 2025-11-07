#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>

int main() {
  int mem = 0x12345678;
  int buf = 0;
  getrandom(&buf, sizeof(buf), 0);
  register long rax asm("rax") = 0x1234567812345678;
  register int edi asm("edi") = buf;
  asm("cmpxchg %[edi],%[mem]"
      : [ mem ] "+m"(mem), [ rax ] "+r"(rax)
      : [ edi ] "r"(edi));
  long rax2 = rax;
  printf("rax2 = %lx\n", rax2);
  printf("rand= %d\n", buf);
}

