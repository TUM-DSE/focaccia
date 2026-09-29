// Deterministic, freestanding AArch64 fixture. Only the labelled arithmetic
// region is validated; setup, control transfer, and exit are outside its scope.
.section .text,"ax",@progbits
.global _start
.type _start, %function
_start:
    mov x0, #-1
    mov x1, #-1
    movk x1, #0x7fff, lsl #16
    mov x2, #0
    mov x3, #0
    b tir_region_begin
.Lexit:
    mov x0, #0
    mov x8, #93
    svc #0
.size _start, .-_start

.section .validation,"ax",@progbits
.balign 4
.global tir_region_begin
.global tir_region_end
.type tir_region_begin, %function
tir_region_begin:
    add x0, x0, #1
    adds w1, w1, #1
    subs x2, x2, #1
    add x3, x2, #2
    add sp, sp, #16
    sub sp, sp, #16
    subs xzr, x3, #1
tir_region_end:
    b .Lexit
.size tir_region_begin, tir_region_end-tir_region_begin
.section .note.GNU-stack,"",@progbits
