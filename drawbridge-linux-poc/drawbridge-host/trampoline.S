.text
.global drawbridge_enter_ntum
.type drawbridge_enter_ntum, @function

/*
 * Enter the NTUM kernel.
 *
 * SysV ABI args:
 *   rdi = entry_point (DllMain at 0x1803a04d0)
 *   rsi = stack_ptr (unused - entry point sets its own stack)
 *   rdx = params (WINDOWS_LIBOS_PARAMETERS*)
 *
 * Windows x64 ABI setup:
 *   rcx = params
 *   rdx = params (same value for both args, like real sqlservr)
 *
 * The entry point at 0x1803a04d0 does:
 *   lea rsp, [rip+0x296b29] → sets stack to 0x180637000
 *   add rsp, [rip+0x72fa2]  → adds 0x4000
 *   sub rsp, 0x28
 *   jmp init_wrapper
 *
 * So we do NOT need to set up the stack.
 */
drawbridge_enter_ntum:
    movq %rdx, %rcx       /* rcx = params (1st Win64 arg) */
    /* rdx already = params (2nd Win64 arg) */
    xorq %rbp, %rbp       /* clean frame pointer */
    jmpq *%rdi             /* jump to entry point */
    /* Entry point sets its own stack, then calls init */
    hlt                    /* never reached */

.section .note.GNU-stack,"",@progbits
