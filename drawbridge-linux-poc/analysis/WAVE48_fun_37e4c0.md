# Wave-48-c: FUN_0x37e4c0 — PE image descriptor state setter

Source: `/tmp/sqlpal_full.txt` lines 436205-436225 (function body).

## Signature

```
void FUN_0x37e4c0(void *desc /*rcx*/, uint32_t new_state /*edx*/);
```

Called from `FUN_0x37cf68` at `/tmp/sqlpal_full.txt:434822` with rcx = newly-allocated PE descriptor, edx=2.

## Full instruction flow

| Line   | Addr      | Insn                                  | Meaning                                       |
|--------|-----------|---------------------------------------|-----------------------------------------------|
| 436205 | 37e4c0    | `mov %rbx,0x8(%rsp)`                  | home RBX                                      |
| 436206 | 37e4c5    | `push %rdi`                           | prologue                                      |
| 436207 | 37e4c6    | `sub $0x30,%rsp`                      | stack frame                                   |
| 436208 | 37e4ca    | `mov 0x74(%rcx),%eax`                 | EAX = desc->state (current)                   |
| 436209 | 37e4cd    | `mov %edx,%ebx`                       | save new_state                                |
| 436210 | 37e4cf    | `inc %eax`                            | EAX = current_state + 1                       |
| 436211 | 37e4d1    | `mov %rcx,%rdi`                       | save desc ptr                                 |
| 436212 | 37e4d4    | `cmp %eax,%edx`                       | new_state == current_state + 1 ?              |
| 436213 | 37e4d6    | `je 0x37e501`                         | if yes, skip assert                           |
| 436214 | 37e4d8    | `call 0x3a0880`                       | `int $0x2c` fastfail (assert preamble)        |
| 436215 | 37e4dd    | `andq $0x0,0x20(%rsp)`                | zero arg slot                                 |
| 436216 | 37e4e3    | `lea 0xf1376(%rip),%r8 # 0x46f860`    | r8 = file-name string (assert helper arg)     |
| 436217 | 37e4ea    | `mov $0x379,%r9d`                     | r9d = 0x379 (= line 889, source line number)  |
| 436218 | 37e4f0    | `lea 0xf5991(%rip),%rdx # 0x473e88`   | rdx = assert message string                   |
| 436219 | 37e4f7    | `mov $0x1,%ecx`                       | ecx = 1 (assert severity)                     |
| 436220 | 37e4fc    | `call 0x218494`                       | assertion reporter                            |
| 436221 | 37e501    | `mov %ebx,0x74(%rdi)`                 | **desc->state = new_state**                   |
| 436222 | 37e504    | `mov 0x40(%rsp),%rbx`                 | restore rbx                                   |
| 436223 | 37e509    | `add $0x30,%rsp`                      | epilogue                                      |
| 436224 | 37e50d    | `pop %rdi`                            |                                               |
| 436225 | 37e50e    | `ret`                                 |                                               |

## Descriptor field writes

- **Only one write**: `desc[+0x74] = new_state` at line 436221.
- **No write to desc[+0x80]**. The state field tracked by this helper lives at **offset 0x74**, not 0x80. (The `cmpl $0x2,0x80(%rax)` mentioned in the context for `FUN_0x37d073` therefore refers to a *different* field, likely set by `FUN_0x380708` or the `FUN_0x37d23c` helper at caller line 434819, not by FUN_0x37e4c0.)
- No cmpxchg/locked ops on the descriptor.
- No linked-list prev/next writes.
- No counter inc/dec.

## Callees

| Addr     | Target     | Role                                                                      |
|----------|------------|---------------------------------------------------------------------------|
| 37e4d8   | 0x3a0880   | `int $0x2c` — Windows fastfail, assert preamble (`/tmp/sqlpal_full.txt:475782`) |
| 37e4fc   | 0x218494   | Assert reporter (`/tmp/sqlpal_full.txt:27951`)                             |

Both are on the assertion path only (`edx != current_state + 1`). In normal operation the function is a plain 1-instruction store.

## Invariant enforced

`new_state == current_state + 1`. Therefore calls must increment the state monotonically by 1. A call with `edx=2` asserts that the descriptor is currently in state 1.

## State-machine codes observed at call sites

Every caller passes a constant immediate for `edx`:

| Caller addr | edx | /tmp/sqlpal_full.txt line | Surrounding context                                            |
|-------------|-----|---------------------------|----------------------------------------------------------------|
| 37a807      | 3   | 432033                    | after FUN_0x37d23c teardown path in FUN_0x37a5xx               |
| 37b26d      | 2   | 432719                    | after list unlink via FUN_0x37d23c                             |
| 37b56f      | 2   | 432925                    | after `lock incl 0x18(rax)` refcount bump, on 0x58(rbp) desc   |
| 37b9cb      | 4   | 433229                    | terminal transition before `(*vtbl[0x30])()`                   |
| 37bfde      | 2   | 433604                    | right after FUN_0x37d23c on freshly linked desc                |
| 37c108      | 3   | 433676                    | optional (guarded by `test rdi,rdi`)                           |
| 37c59f      | 3   | 433971                    | error path (`test eax,eax; jns`)                               |
| 37c5db      | 2   | 433987                    | success path immediately after FUN_0x37d23c                    |
| 37d207      | 2   | 434822                    | **target caller** — FUN_0x37cf68 post-link, pre-FUN_0x380708   |
| 37ea74      | 3   | 436610                    | `lea 0x3(%rbx),%edx` with rbx=0 (`/tmp/sqlpal_full.txt:436592`) |
| 385ada      | 3   | 444514                    | error cleanup after FUN_0x385c28                               |

Observed state codes: **{2, 3, 4}**. State 1 must be the initial value written at descriptor allocation (pre-condition for the first `edx=2` call). The monotonic invariant means:

```
1 (allocated)  -->  2 (linked/REGISTERED)  -->  3 (torn-down/unlinked)  -->  4 (freed/terminal)
```

- `edx=2` calls always appear immediately after a `FUN_0x37d23c` helper invocation (see lines 432716, 433601, 433984, 434819), consistent with "linked into parent list => state 2".
- `edx=3` calls appear on both error cleanup (433971, 444514) and normal teardown (432033, 433676) paths.
- `edx=4` appears once (433229) just before an indirect vtable call at `0x30(rax)` — likely the final destructor/release.

## Answer to mission question

At line 434822, FUN_0x37cf68 calls FUN_0x37e4c0(desc, 2). The function:
1. Asserts `desc->state == 1` (via the `inc eax; cmp eax,edx` check at 436210/436212).
2. Sets `desc[+0x74] = 2`.

That is the entire effect. **Nothing else is touched** — no list pointers, no counters, no atomic ops. The `desc[+0x80] = 2` post-condition seen at FUN_0x37d073 is produced by a **different** helper in the caller's flow (FUN_0x37d23c at 434819 or FUN_0x380708 at 434825), not by FUN_0x37e4c0.
