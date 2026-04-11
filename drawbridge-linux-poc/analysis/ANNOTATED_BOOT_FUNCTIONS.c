/*
 * ANNOTATED DECOMPILED BOOT FUNCTIONS
 *
 * Function names decoded from sqlservr_FULL.c and PE disassembly.
 * This is the REAL sqlservr ELF host code that we need to replicate.
 */

/* ===================================================================
 * FUN_001d9720 = dk_prot_to_linux(windows_prot)
 * Converts Windows PAGE_* flags to Linux PROT_* flags
 * IMPLEMENTED: dk_pal.c - CORRECT
 * =================================================================== */
// return (flags & 3) | ((flags >> 1) & 6);


/* ===================================================================
 * FUN_001fa9c0 = allocate_thread_teb(thread_block, size)
 * Allocates TEB memory for a new thread
 * NEED TO IMPLEMENT in our thread creation
 * =================================================================== */
// if (*(thread_block + 0x88) == 0) {
//     void *teb = malloc(size);          // typically 0x10000 = 64KB
//     *(thread_block + 0x88) = teb;
//     memset(teb, 0xb0, size);           // Fill with sentinel 0xb0
// }


/* ===================================================================
 * FUN_00289740 = set_gs_base(teb_address)
 * Calls arch_prctl(ARCH_SET_GS, teb_address)
 * IMPLEMENTED: ntum_bootstrap.c boot thread - NEED TO FIX
 * =================================================================== */
// int result = arch_prctl(ARCH_SET_GS, teb_address);
// if (result != 0) fatal("Error setting GS base");


/* ===================================================================
 * FUN_002890a0 = init_thread_subsystem()
 * Initializes the thread pool and registers thread entry callback
 * Called from FUN_00204680 (PAL boot) at line 69412
 * NOT IMPLEMENTED - runs inside the PE, but registers host callbacks
 * =================================================================== */
// local_config = { 0xffff00000400, 0, 0, 0xe10 };
// set_thread_attributes(&local_config);     // FUN_00355d60
// register_thread_entry(thread_entry_fn);   // FUN_00279f90(FUN_00252bf0)


/* ===================================================================
 * FUN_00252e60 = dk_thread_create(entry, start, param, flags, p5, out_handle)
 * Creates a new managed thread
 * Allocates 0xAA0 (2720) byte thread control block
 * PARTIALLY IMPLEMENTED: dk_pal.c DK_ThreadCreate
 * =================================================================== */
// 1. thread_block = calloc(1, 0xAA0);
// 2. thread_counter++; thread_block[0x12] = thread_counter;
// 3. Link into global list (DAT_003b21c8)
// 4. thread_block[0x0B] = entry_function
// 5. thread_block[0x0C] = parameter
// 6. thread_block[0x0D] = stack
// 7. Create stack: FUN_001fa5f0(4)
// 8. pthread_create with FUN_00253350 as entry thunk
// 9. Return handle


/* ===================================================================
 * FUN_00253350 = thread_entry_thunk(thread_block)
 * The actual pthread start function
 * Sets up TEB, GS register, exception dispatcher
 * NOT IMPLEMENTED - our threads don't do TEB setup
 * =================================================================== */
// 1. thread_info = get_thread_info();           // FUN_003553f0
// 2. Set stack: FUN_00355400/00355410
// 3. TEB init: thread_block[0x18] = stack_base
//              thread_block[0x10] = stack_top
// 4. Call user routine: thread_block[0x20]
// 5. Set GS base: FUN_001fa9c0 (allocate_thread_teb)
//                 then arch_prctl(ARCH_SET_GS, teb)


/* ===================================================================
 * FUN_0024b4f0 = dk_virtual_memory_allocate(addr, size, type, protect, ...)
 * Allocates virtual memory using mmap
 * IMPLEMENTED: dk_pal.c DK_VirtualMemoryAllocate - UPDATED
 * =================================================================== */
// 1. Validate params (non-zero)
// 2. Page-align address and size
// 3. prot = dk_prot_to_linux(protect)
// 4. If MEM_RESERVE only: mmap(addr, size, prot, MAP_NORESERVE)
// 5. If MEM_COMMIT: mmap(addr, size, prot, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED)
// 6. Optional: mprotect if protection change needed


/* ===================================================================
 * FUN_0024c620 = dk_notification_event_create(initial_state, out_handle)
 * Creates a manual-reset event
 * IMPLEMENTED: dk_pal.c DK_NotificationEventCreate (via eventfd)
 * =================================================================== */
// 1. event_object = FUN_002b67d0(0, initial_state);  // type=0 for notification
// 2. handle = object_to_handle(event_object);
// 3. *out_handle = handle;


/* ===================================================================
 * FUN_0024c730 = dk_sync_event_create(initial_state, out_handle)
 * Creates an auto-reset event
 * IMPLEMENTED: dk_pal.c DK_SynchronizationEventCreate (via eventfd)
 * =================================================================== */
// Same as notification but type=1


/* ===================================================================
 * FUN_00252b10 = allocate_exception_record(info, out_buffer)
 * Allocates 0x280 (640) byte exception record
 * IMPLEMENTED: ntum_signals.c dk_exception_record_t
 * =================================================================== */
// record = calloc(1, 0x280);
// copy exception info from info struct
// *out_buffer = record;


/* ===================================================================
 * FUN_001f1c50 = create_io_completion_port(result, flag, port_ptr)
 * Creates FileIoCompletionPort with io_setup
 * NOT DIRECTLY CALLED BY US - runs inside PE
 * =================================================================== */
// 1. Allocate 0x1c0 bytes
// 2. FUN_001f1fd0(port) - init constructor
// 3. io_setup(0x400, &aio_context) via FUN_00202100
//    If io_setup fails: fatal "Unable to create asynchronous I/O context"


/* ===================================================================
 * FUN_002897e0 = build_exception_record(ucontext, record)
 * Copies CPU register state from Linux ucontext to Windows exception record
 * IMPLEMENTED: ntum_signals.c build_exception_record()
 * =================================================================== */
// record->error_code = ucontext->gregs[REG_EFL]
// record->cs = ucontext->gregs[REG_CSGSFS]
// record->rax = ucontext->gregs[REG_RAX]
// ... all GPRs ...
// record->rip = ucontext->gregs[REG_RIP]
// if (fpregs) copy FPU state, else zero-fill 0x1a0 bytes


/* ===================================================================
 * FUN_002899d0 = signal_handler(sig, siginfo, ucontext, thread_state)
 * Main signal handler - converts signals to Windows exceptions
 * IMPLEMENTED: ntum_signals.c ntum_signal_handler()
 * =================================================================== */
// 1. Read RIP and RSP from ucontext
// 2. Validate addresses (IsValidLibOSAddress)
// 3. Based on signal type, build exception_info
// 4. Allocate exception record via FUN_00252b10
// 5. Build record via FUN_002897e0
// 6. Rewrite RIP → RuntimeCallbackState+0x10 (thread switcher)
//    RCX = exception record
//    RDX = thread state from TCB[0x68]
// 7. Store in thread exception array at TCB[0xa20 + nesting*8]


/* ===================================================================
 * KEY DATA STRUCTURES IN PE .data
 * =================================================================== */
// [0x18063f8c0] = boot_ready_flag (must be 1, overwritten by 0x7001000 resolution)
// [0x18063f8c8] = abi_dispatcher_ptr (overwritten by 0x8001001 resolution)
// [0x18063f5c0] = abi_version (must be 2, checked by second resolver)
// [0x18063f4f0] = feature_flag_f005 (must be 1, checked at 0x2049da)
// [0x1806092c0] = global_teb_ptr (set from PAL_instance+0x80)
// [0x18063b220] = default_thread_block (fallback for thread switcher)


/* ===================================================================
 * THE BOOT FLOW (what ACTUALLY happens)
 * =================================================================== */
// 1. Our host calls PE entry at 0x1803a04d0
// 2. PE sets its own stack: RSP = 0x18063b000
// 3. PE calls cookie init, then real_init
// 4. real_init → FUN_0020ba60 (setup WINDOWS_LIBOS_PARAMETERS)
// 5. real_init → FUN_00204ee0 (create PAL instance, store at DAT_0036f598)
// 6. FUN_00204ee0 → FUN_00204680 (PAL boot):
//    a. ABI resolution: 84 first-pass + 89 second-pass calls to our dispatcher
//    b. Boot sync (int3 spin loop)
//    c. Config calls (6 calls through wrapper)
//    d. Init subsystems: OpenSSL, io_setup, threading
//    e. FUN_00204bb0 (boot thread):
//       - Allocate KTHREAD via FUN_00204baa → FUN_00020f03c
//       - Store TEB[0x1838] = KTHREAD
//       - Enter scheduler (FUN_00204c6c)
//    f. The scheduler reads gs:0x30 and expects [0x6092c0] to match
//    g. FUN_00247910 reads get_current_thread_state() chain
//       gs:0x30 → TEB[0x1838] → KTHREAD[0x70] → +0xF0
//       If any part is NULL, returns 0
//    h. CRASH: rsi=0 from get_current_thread_state()=0
//              rdi = rsi + 0x9d8 = 0x9d8 (invalid pointer)

/* ===================================================================
 * WHAT WE NEED TO FIX
 * ===================================================================
 *
 * The PE's init code creates KTHREAD with [+0x70]=0 (cleared by FUN_00020f03c).
 * KTHREAD[0x70] should be set to a valid scheduler processor block LATER
 * by the kernel init, but it never happens.
 *
 * The kernel init at FUN_00204c6c → 0x26b3a4 should allocate scheduler
 * structures via VirtualMemoryAllocate. But we saw ZERO PAL function calls
 * during boot!
 *
 * HYPOTHESIS: The PE's resolved function pointers are stored as 32-bit values
 * by the first-pass resolution (mov [addr], eax). When the PE reads them as
 * 64-bit (mov rax, [addr]), the upper 32 bits may be non-zero garbage from
 * adjacent .data, causing the function calls to jump to wrong addresses.
 *
 * OR: The function call mechanism in the PE goes through the guard_dispatch
 * (call [0x180a00008] = jmp *rax), and since our function pointers are in
 * ELF space (0x404xxx), they're below 0x180000000 and might fail a range check.
 *
 * NEXT: Check if the second-pass 64-bit pointers are actually being used
 * for runtime calls, or if the 32-bit first-pass values corrupt things.
 */
