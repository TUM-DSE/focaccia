.text
.global issue2419
.type issue2419, %function
issue2419:
    mov    x1, x0
    ldapur x0, [x1, #-8]
    ret
.size issue2419, .-issue2419
.section .note.GNU-stack,"",%progbits
