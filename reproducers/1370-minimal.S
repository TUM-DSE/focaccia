.section .text
.global _start

_bb_0x401040:
blsiq %rax, %rbx
ret

_start:
call _setup_dyn
call _setup_regs
call _bb_0x401040
call _exit

_exit:
movq $0, %rdi
movq $60, %rax
syscall

_alloc:
movq $4096, %rsi
movq $(PROT_READ | PROT_WRITE), %rdx
movq $(MAP_PRIVATE | MAP_ANONYMOUS), %r10
movq $-1, %r8
movq $0, %r9
movq $syscall_mmap, %rax
syscall
ret

_setup_regs:
mov $0x0, %rax
ret

_setup_dyn:
ret

.section .data
PROT_READ  = 0x1
PROT_WRITE = 0x2
MAP_PRIVATE = 0x2
MAP_ANONYMOUS = 0x20
syscall_mmap = 9

_setup_mem:

