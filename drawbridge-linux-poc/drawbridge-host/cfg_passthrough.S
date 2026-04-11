.text
.global cfg_dispatch_passthrough
.type cfg_dispatch_passthrough, @function

/* CFG dispatch passthrough - only used as fallback if PE's
 * built-in guard_dispatch gets corrupted. Normal path uses
 * the PE's own function at RVA 0x3a86f0 (jmp *%rax). */
cfg_dispatch_passthrough:
    testq %rax, %rax
    jz .Lcfg_null_target
    jmpq *%rax
.Lcfg_null_target:
    xorq %rax, %rax
    ret

.global cfg_check_passthrough
.type cfg_check_passthrough, @function
/* CFG check passthrough - fallback. PE has its own at RVA 0x21ff10 (ret). */
cfg_check_passthrough:
    ret

.section .note.GNU-stack,"",@progbits
