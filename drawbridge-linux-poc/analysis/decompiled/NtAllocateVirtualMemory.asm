            ; CALL XREF from sym.sqlpal.dll_ZwAllocateVirtualMemory @ 0x180265600
/ 110: sym.sqlpal.dll_NtAllocateVirtualMemory (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4, int64_t arg_70h, int64_t arg_78h);
|           ; var int64_t var_20h @ rsp+0x20
|           ; var int64_t var_28h @ rsp+0x28
|           ; var int64_t var_30h @ rsp+0x30
|           ; var int64_t var_8h @ rsp+0x50
|           ; var int64_t var_10h @ rsp+0x58
|           ; arg int64_t arg_70h @ rsp+0x70
|           ; arg int64_t arg_78h @ rsp+0x78
|           ; arg int64_t arg1 @ rcx
|           ; arg int64_t arg2 @ rdx
|           ; arg int64_t arg3 @ r8
|           ; arg int64_t arg4 @ r9
|           0x180265540      48895c2408     mov qword [var_8h], rbx
|           0x180265545      4889742410     mov qword [var_10h], rsi
|           0x18026554a      57             push rdi
|           0x18026554b      4883ec40       sub rsp, 0x40
|           0x18026554f      498bd9         mov rbx, r9                ; arg4
|           0x180265552      488bfa         mov rdi, rdx               ; arg2
|           0x180265555      488bf1         mov rsi, rcx               ; arg1
|           0x180265558      4d85c0         test r8, r8                ; arg3
|       ,=< 0x18026555b      7418           je 0x180265575
|       |   0x18026555d      4c8d05accf1d.  lea r8, str.Unsupported_ZeroBits ; 0x180442510 ; "Unsupported ZeroBits"
|       |   0x180265564      ba88000000     mov edx, 0x88              ; 136
|       |   0x180265569      488d0db8cf1d.  lea rcx, [0x180442528]     ; "NtAllocateVirtualMemory"
|       |   0x180265570      e82b89fdff     call fcn.18023dea0
|       `-> 0x180265575      8b442478       mov eax, dword [arg_78h]
|           0x180265579      4533c9         xor r9d, r9d
|           0x18026557c      c74424305573.  mov dword [var_30h], 0x72657355 ; 'User'
|                                                                      ; [0x72657355:4]=-1
|           0x180265584      4c8bc3         mov r8, rbx
|           0x180265587      89442428       mov dword [var_28h], eax
|           0x18026558b      488bd7         mov rdx, rdi
|           0x18026558e      8b442470       mov eax, dword [arg_70h]
|           0x180265592      488bce         mov rcx, rsi
|           0x180265595      89442420       mov dword [var_20h], eax
|           0x180265599      e8aefdffff     call fcn.18026534c
|           0x18026559e      488b5c2450     mov rbx, qword [var_8h]
|           0x1802655a3      488b742458     mov rsi, qword [var_10h]
|           0x1802655a8      4883c440       add rsp, 0x40
|           0x1802655ac      5f             pop rdi
\           0x1802655ad      c3             ret
