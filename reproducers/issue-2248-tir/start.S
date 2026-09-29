// Freestanding lifecycle wrapper for the canonical issue-2248 witness.
// The validated region is callme through (but excluding) its RET. Setup and
// process exit deliberately remain outside the bounded semantics claim.
.section .text.start,"ax",@progbits
.global _start
.type _start, %function
_start:
    mov x2, #0
    mov x3, #1
    mov x4, #2
    bl callme

    // Both fixed and regression-injected guests must complete normally. The
    // validator, rather than guest control flow, decides whether X0 is correct.
    mov x0, #0
    mov x8, #93
    svc #0
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
