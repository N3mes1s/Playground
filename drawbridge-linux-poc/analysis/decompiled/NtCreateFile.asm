            ; CALL XREF from sym.sqlpal.dll_IoCreateFile @ 0x18023e9fe
            ; CALL XREF from sym.sqlpal.dll_ZwCreateFile @ 0x18025e7a1
/ 122: sym.sqlpal.dll_NtCreateFile (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4, int64_t arg_a8h, int64_t arg_b0h, int64_t arg_b8h, int64_t arg_c0h, int64_t arg_c8h, int64_t arg_d0h);
|           ; var int64_t var_20h @ rsp+0x20
|           ; var int64_t var_28h @ rsp+0x28
|           ; var int64_t var_30h @ rsp+0x30
|           ; var int64_t var_38h @ rsp+0x38
|           ; var int64_t var_48h @ rsp+0x48
|           ; var int64_t var_60h @ rsp+0x60
|           ; arg int64_t arg_a8h @ rsp+0xa8
|           ; arg int64_t arg_b0h @ rsp+0xb0
|           ; arg int64_t arg_b8h @ rsp+0xb8
|           ; arg int64_t arg_c0h @ rsp+0xc0
|           ; arg int64_t arg_c8h @ rsp+0xc8
|           ; arg int64_t arg_d0h @ rsp+0xd0
|           ; arg int64_t arg1 @ rcx
|           ; arg int64_t arg2 @ rdx
|           ; arg int64_t arg3 @ r8
|           ; arg int64_t arg4 @ r9
|           0x18025e460      4c8bdc         mov r11, rsp
|           0x18025e463      53             push rbx
|           0x18025e464      4883ec70       sub rsp, 0x70
|           0x18025e468      498363e800     and qword [r11 - 0x18], 0
|           0x18025e46d      498d43e8       lea rax, [r11 - 0x18]
|           0x18025e471      498943d8       mov qword [r11 - 0x28], rax
|           0x18025e475      8b8424d00000.  mov eax, dword [arg_d0h]
|           0x18025e47c      89442448       mov dword [var_48h], eax
|           0x18025e480      488b8424c800.  mov rax, qword [arg_c8h]
|           0x18025e488      498943c8       mov qword [r11 - 0x38], rax
|           0x18025e48c      8b8424c00000.  mov eax, dword [arg_c0h]
|           0x18025e493      89442438       mov dword [var_38h], eax
|           0x18025e497      8b8424b80000.  mov eax, dword [arg_b8h]
|           0x18025e49e      89442430       mov dword [var_30h], eax
|           0x18025e4a2      8b8424b00000.  mov eax, dword [arg_b0h]
|           0x18025e4a9      89442428       mov dword [var_28h], eax
|           0x18025e4ad      8b8424a80000.  mov eax, dword [arg_a8h]
|           0x18025e4b4      89442420       mov dword [var_20h], eax
|           0x18025e4b8      e877fbffff     call fcn.18025e034
|           0x18025e4bd      488b4c2460     mov rcx, qword [var_60h]
|           0x18025e4c2      8bd8           mov ebx, eax
|           0x18025e4c4      4885c9         test rcx, rcx
|       ,=< 0x18025e4c7      7409           je 0x18025e4d2
|       |   0x18025e4c9      4883c110       add rcx, 0x10              ; 16
|       |   0x18025e4cd      e85abffeff     call fcn.18024a42c
|       `-> 0x18025e4d2      8bc3           mov eax, ebx
|           0x18025e4d4      4883c470       add rsp, 0x70
|           0x18025e4d8      5b             pop rbx
\           0x18025e4d9      c3             ret
