/* Register-observation calibration only. No Intel oracle inputs/expectations.
 * Every checkpoint is a real branch target/TB entry, not an insn callback.
 * PUSHFQ captures are architecturally independent of the debugger getter. */
.section .text
.global _start, after_and, after_stc_std, after_cld_xor
.global after_overflow, after_carry, after_auxcarry
_start:
    mov $0x12c0, %eax
    and $0xff, %eax
    jmp after_and

after_and:
    pushfq
    popq captures(%rip)
    stc
    std
    jmp after_stc_std

after_stc_std:
    pushfq
    popq captures+8(%rip)
    cld
    xor %eax, %eax
    jmp after_cld_xor

after_cld_xor:
    pushfq
    popq captures+16(%rip)
    mov $0x7fffffff, %eax
    add $1, %eax
    jmp after_overflow

after_overflow:
    pushfq
    popq captures+24(%rip)
    mov $0xffffffff, %eax
    add $1, %eax
    jmp after_carry

after_carry:
    pushfq
    popq captures+32(%rip)
    mov $0x0f, %eax
    add $1, %eax
    jmp after_auxcarry

after_auxcarry:
    pushfq
    popq captures+40(%rip)
    mov $1, %eax
    mov $1, %edi
    lea captures(%rip), %rsi
    mov $48, %edx
    syscall
    mov $60, %eax
    xor %edi, %edi
    syscall

.section .data
.balign 8
.global captures
captures:
    .zero 48
.section .note.GNU-stack,"",@progbits
