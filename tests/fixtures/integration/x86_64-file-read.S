.section .text
.global _start
.type _start, @function
_start:
    mov 16(%rsp), %rsi
    test %rsi, %rsi
    jz .Lusage

    mov $257, %eax
    mov $-100, %edi
    xor %edx, %edx
    xor %r10d, %r10d
.global _focaccia_trace_start
_focaccia_trace_start:
    syscall
    test %rax, %rax
    js .Lfailure
    mov %rax, %r12

    xor %eax, %eax
    mov %r12, %rdi
    lea input_buffer(%rip), %rsi
    mov $64, %edx
    syscall
    test %rax, %rax
    js .Lclose_failure
    mov %rax, %r13

    mov $1, %eax
    mov $1, %edi
    lea input_buffer(%rip), %rsi
    mov %r13, %rdx
    syscall

.Lclose_failure:
    mov $3, %eax
    mov %r12, %rdi
    syscall

    xor %edi, %edi
    mov $60, %eax
.global _focaccia_trace_stop
_focaccia_trace_stop:
    syscall

.Lfailure:
    mov $111, %edi
    mov $60, %eax
    syscall

.Lusage:
    mov $64, %edi
    mov $60, %eax
    syscall
.size _start, .-_start

.section .bss
.balign 16
input_buffer:
    .skip 64

.section .note.GNU-stack,"",@progbits
