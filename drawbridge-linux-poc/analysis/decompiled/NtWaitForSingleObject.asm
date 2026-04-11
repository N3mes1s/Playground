            ; CALL XREF from sym.sqlpal.dll_ZwWaitForSingleObject @ 0x180253272
            ; CALL XREF from fcn.1802591f0 @ 0x18025930e
/ 137: sym.sqlpal.dll_NtWaitForSingleObject (int64_t arg1, int64_t arg3);
|           ; var int64_t var_20h @ rsp+0x20
|           ; var int64_t var_28h @ rsp+0x28
|           ; var int64_t var_30h @ rsp+0x30
|           ; var int64_t var_50h @ rsp+0x50
|           ; var int64_t var_58h @ rsp+0x58
|           ; var int64_t var_60h @ rsp+0x60
|           ; var int64_t var_68h @ rsp+0x68
|           ; arg int64_t arg1 @ rcx
|           ; arg int64_t arg3 @ r8
|           0x180253120      488bc4         mov rax, rsp
|           0x180253123      48895808       mov qword [rax + 8], rbx
|           0x180253127      48896810       mov qword [rax + 0x10], rbp
|           0x18025312b      48897018       mov qword [rax + 0x18], rsi
|           0x18025312f      57             push rdi
|           0x180253130      4883ec40       sub rsp, 0x40
|           0x180253134      4883602000     and qword [rax + 0x20], 0
|           0x180253139      408aea         mov bpl, dl
|           0x18025313c      488bd1         mov rdx, rcx               ; arg1
|           0x18025313f      498bf0         mov rsi, r8                ; arg3
|           0x180253142      488d4820       lea rcx, [rax + 0x20]
|           0x180253146      e84192ffff     call fcn.18024c38c
|           0x18025314b      488b5c2468     mov rbx, qword [var_68h]
|           0x180253150      8bf8           mov edi, eax
|           0x180253152      85c0           test eax, eax
|       ,=< 0x180253154      782f           js 0x180253185
|       |   0x180253156      4084ed         test bpl, bpl
|       |   0x180253159      c644243000     mov byte [var_30h], 0
|       |   0x18025315e      4889742428     mov qword [var_28h], rsi
|       |   0x180253163      488d4c2468     lea rcx, [var_68h]
|       |   0x180253168      0f95c0         setne al
|       |   0x18025316b      48895c2468     mov qword [var_68h], rbx
|       |   0x180253170      4533c9         xor r9d, r9d
|       |   0x180253173      88442420       mov byte [var_20h], al
|       |   0x180253177      418d5101       lea edx, [r9 + 1]
|       |   0x18025317b      448bc2         mov r8d, edx
|       |   0x18025317e      e849040000     call fcn.1802535cc
|       |   0x180253183      8bf8           mov edi, eax
|       `-> 0x180253185      4885db         test rbx, rbx
|       ,=< 0x180253188      7408           je 0x180253192
|       |   0x18025318a      488bcb         mov rcx, rbx
|       |   0x18025318d      e81a320200     call fcn.1802763ac
|       `-> 0x180253192      488b5c2450     mov rbx, qword [var_50h]
|           0x180253197      8bc7           mov eax, edi
|           0x180253199      488b6c2458     mov rbp, qword [var_58h]
|           0x18025319e      488b742460     mov rsi, qword [var_60h]
|           0x1802531a3      4883c440       add rsp, 0x40
|           0x1802531a7      5f             pop rdi
\           0x1802531a8      c3             ret
