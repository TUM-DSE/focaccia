#include<stdio.h>
#include<sys/mman.h>
__attribute__((naked,noinline)) void* f(void* dst, void* p) {
  __asm__(
    "\n  pushq   %rbp"
    "\n  movq    %rsp, %rbp"
    "\n  movq    %rdi, %rax"
    "\n  movq    $0x0, (%rdi)"
    "\n  movl    $0x140a, (%rdi)         # imm = 0x140A"
    "\n  movb    $0x4, 0x5(%rdi)"
    "\n  cvtps2pd        (%rsi), %xmm0"
    "\n  movups  %xmm0, 0x8(%rdi)"
    "\n  cvtps2pd        0x8(%rsi), %xmm0"
    "\n  movups  %xmm0, 0x18(%rdi)"
    "\n  popq    %rbp"
    "\n  retq"
  );
}
int main() {
  char dst[1000];
  int page = 4096;
  char* buf = mmap(NULL, page*2, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  // mprotect(buf+page, page, 0);
  
  float* src = (float*)(buf+0x40);
  printf("src: %p\n", src);
  
  void* r = f(dst, src);
  printf("res: %p\n", r);
}
