.global drawbridge_enter_ntum
.type drawbridge_enter_ntum, @function

/*
 * drawbridge_enter_ntum(entry, stack, params)
 *
 * SysV args: rdi=entry, rsi=stack, rdx=params
 *
 * Sets up Win64 convention and jumps to entry:
 *   rcx = params (Win64 arg1)
 *   rdx = params (Win64 arg2)
 *   rsp = stack
 *   rbp = 0
 */
drawbridge_enter_ntum:
    /* Set Win64 args */
    movq %rdx, %rcx       /* rcx = params */
    /* rdx already = params */

    /* Switch to NTUM stack */
    movq %rsi, %rsp

    /* Clean frame */
    xorq %rbp, %rbp

    /* Jump to entry - never returns */
    jmpq *%rdi
