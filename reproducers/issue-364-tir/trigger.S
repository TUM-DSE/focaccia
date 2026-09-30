.text
.global issue364
.type issue364, %function
issue364:
    mov     x1, x0
    mov     w2, #-1
    ldsmaxb w2, w0, [x1]
    ret
.size issue364, .-issue364
.section .note.GNU-stack,"",%progbits
