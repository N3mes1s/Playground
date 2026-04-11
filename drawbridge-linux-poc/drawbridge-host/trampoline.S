.text
.global drawbridge_enter_ntum
.type drawbridge_enter_ntum, @function

drawbridge_enter_ntum:
    /* rdi=entry, rsi=stack, rdx=params */
    movq %rdx, %rcx       /* rcx = params */
    /* rdx already = params */
    movq %rsi, %rsp        /* switch to NTUM stack */
    xorq %rbp, %rbp        /* clean frame */
    callq *%rdi            /* call entry (not jmp) */
    hlt                    /* never reached */
