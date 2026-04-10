use crate::context::context64::Context64;
use crate::debug::console::Console;
use crate::emu;
use crate::windows::{constants, structures};

pub(super) fn dispatch(api: &str, emu: &mut emu::Emu) -> bool {
    match api {
        "ZwQueueApcThread" => ZwQueueApcThread(emu),
        "NtGetContextThread" => NtGetContextThread(emu),
        "RtlExitUserThread" => RtlExitUserThread(emu),
        "NtGetTickCount" => NtGetTickCount(emu),
        "NtQueryPerformanceCounter" => NtQueryPerformanceCounter(emu),
        "RtlGetVersion" => RtlGetVersion(emu),
        "RtlSetUnhandledExceptionFilter" => RtlSetUnhandledExceptionFilter(emu),
        "NtTerminateThread" => NtTerminateThread(emu),
        "NtSetInformationThread" => NtSetInformationThread(emu),
        "RtlFlsAlloc" => RtlFlsAlloc(emu),
        "RtlFlsFree" => RtlFlsFree(emu),
        "RtlFlsGetValue" => RtlFlsGetValue(emu),
        "RtlFlsSetValue" => RtlFlsSetValue(emu),
        "RtlNtStatusToDosError" => RtlNtStatusToDosError(emu),
        "RestoreLastError" => RestoreLastError(emu),
        "RtlDeleteCriticalSection" | "DeleteCriticalSection" => RtlDeleteCriticalSection(emu),
        "RtlLeaveCriticalSection" => RtlLeaveCriticalSection(emu),
        "NtTerminateProcess" => NtTerminateProcess(emu),
        "RtlCaptureContext" => RtlCaptureContext(emu),
        "RtlLookupFunctionEntry" => RtlLookupFunctionEntry(emu),
        "RtlVirtualUnwind" => RtlVirtualUnwind(emu),
        _ => return false,
    }
    true
}

fn NtGetContextThread(emu: &mut emu::Emu) {
    let handle = emu.regs().rcx;
    let ctx_ptr = emu.regs().rdx;
    let ctx_ptr2 = emu
        .maps
        .read_qword(ctx_ptr)
        .expect("ntdll_NtGetContextThread: error reading context ptr");

    log_red!(emu, "ntdll_NtGetContextThread   ctx:");

    let ctx = Context64::new(&emu.regs());
    ctx.save(ctx_ptr2, &mut emu.maps);

    emu.regs_mut().rax = 0;
}

fn RtlExitUserThread(emu: &mut emu::Emu) {
    log_red!(emu, "ntdll!RtlExitUserThread");
    Console::spawn_console(emu);
    emu.stop();
}

fn ZwQueueApcThread(emu: &mut emu::Emu) {
    let thread_handle = emu.regs().rcx;
    let apc_routine = emu.regs().rdx;
    let apc_ctx = emu.regs().r8;
    let arg1 = emu.regs().r9;
    let arg2 = emu
        .maps
        .read_qword(emu.regs().rsp + 0x20)
        .expect("kernel32!ZwQueueApcThread cannot read arg2");

    log_red!(
        emu,
        "ntdll!ZwQueueApcThread hndl: {} routine: {} ctx: {} arg1: {} arg2: {}",
        thread_handle,
        apc_routine,
        apc_ctx,
        arg1,
        arg2
    );

    emu.regs_mut().rax = constants::STATUS_SUCCESS;
}

fn NtGetTickCount(emu: &mut emu::Emu) {
    log_red!(emu, "ntdll!NtGetTickCount");
    emu.regs_mut().rax = emu.tick as u64;
}

fn NtQueryPerformanceCounter(emu: &mut emu::Emu) {
    let perf_counter_ptr = emu.regs().rcx;
    let perf_freq_ptr = emu.regs().rdx;

    log_red!(emu, "ntdll!NtQueryPerformanceCounter");

    emu.maps.write_dword(perf_counter_ptr, 0);
    emu.regs_mut().rax = constants::STATUS_SUCCESS;
}

fn RtlGetVersion(emu: &mut emu::Emu) {
    let versioninfo_ptr = emu.regs().rcx;

    log_red!(emu, "ntdll!RtlGetVersion");

    let versioninfo = structures::OsVersionInfoExA::new();
    versioninfo.save(versioninfo_ptr, &mut emu.maps);

    emu.regs_mut().rax = 1;
}

fn RtlSetUnhandledExceptionFilter(emu: &mut emu::Emu) {
    let filter = emu.regs().rcx;

    log_red!(
        emu,
        "ntdll!RtlSetUnhandledExceptionFilter filter: 0x{:x}",
        filter
    );

    emu.set_uef(filter);
    emu.regs_mut().rax = 1;
}

fn NtTerminateThread(emu: &mut emu::Emu) {
    let handle = emu.regs().rcx;
    let exit_status = emu.regs().rdx;

    log_red!(emu, "ntdll!NtTerminateThread {:x} {}", handle, exit_status);

    emu.regs_mut().rax = 0;
}

fn NtSetInformationThread(emu: &mut emu::Emu) {
    let thread_handle = emu.regs().rcx;
    let thread_info_class = emu.regs().rdx;
    let thread_info_ptr = emu.regs().r8;
    let thread_info_length = emu.regs().r9;

    log_red!(
        emu,
        "ntdll!NtSetInformationThread handle: 0x{:x} class: {} info_ptr: 0x{:x} length: {}",
        thread_handle,
        thread_info_class,
        thread_info_ptr,
        thread_info_length
    );

    emu.regs_mut().rax = 0x00000000;
}

// Fiber-Local Storage
static mut FLS_COUNTER: u32 = 0;

fn RtlFlsAlloc(emu: &mut emu::Emu) {
    let callback = emu.regs().rcx;
    let fls_index_ptr = emu.regs().rdx;

    let idx = unsafe {
        FLS_COUNTER += 1;
        FLS_COUNTER
    };

    log_red!(emu, "ntdll!RtlFlsAlloc callback:0x{:x} out:0x{:x} -> idx {}", callback, fls_index_ptr, idx);

    // Write the FLS index to the output pointer.
    if fls_index_ptr != 0 {
        let _ = emu.maps.write_dword(fls_index_ptr, idx);
    }
    emu.regs_mut().rax = 0; // STATUS_SUCCESS
}

fn RtlFlsFree(emu: &mut emu::Emu) {
    let fls_index = emu.regs().rcx;
    log_red!(emu, "ntdll!RtlFlsFree idx:{}", fls_index);
    emu.regs_mut().rax = 0;
}

fn RtlFlsGetValue(emu: &mut emu::Emu) {
    let fls_index = emu.regs().rcx;
    log_red!(emu, "ntdll!RtlFlsGetValue idx:{}", fls_index);
    emu.regs_mut().rax = 0;
}

fn RtlFlsSetValue(emu: &mut emu::Emu) {
    let fls_index = emu.regs().rcx;
    let value = emu.regs().rdx;
    log_red!(emu, "ntdll!RtlFlsSetValue idx:{} val:0x{:x}", fls_index, value);
    emu.regs_mut().rax = 0;
}

fn RtlNtStatusToDosError(emu: &mut emu::Emu) {
    let status = emu.regs().rcx;
    log_red!(emu, "ntdll!RtlNtStatusToDosError status:0x{:x}", status);
    // Map STATUS_SUCCESS -> ERROR_SUCCESS, others -> generic error
    emu.regs_mut().rax = if status == 0 { 0 } else { 1 };
}

fn RestoreLastError(emu: &mut emu::Emu) {
    let error = emu.regs().rcx;
    log_red!(emu, "ntdll!RestoreLastError error:{}", error);
    emu.last_error = error as u32;
}

fn RtlDeleteCriticalSection(emu: &mut emu::Emu) {
    let cs = emu.regs().rcx;
    log_red!(emu, "ntdll!RtlDeleteCriticalSection 0x{:x}", cs);
    emu.regs_mut().rax = 0;
}

fn RtlLeaveCriticalSection(emu: &mut emu::Emu) {
    let cs = emu.regs().rcx;
    log_red!(emu, "ntdll!RtlLeaveCriticalSection 0x{:x}", cs);
    emu.regs_mut().rax = 0;
}

fn NtTerminateProcess(emu: &mut emu::Emu) {
    let handle = emu.regs().rcx;
    let exit_code = emu.regs().rdx;
    log_red!(emu, "ntdll!NtTerminateProcess handle:0x{:x} code:{}", handle, exit_code);
    emu.is_running.store(0, std::sync::atomic::Ordering::Relaxed);
    emu.regs_mut().rax = 0;
}

fn RtlCaptureContext(emu: &mut emu::Emu) {
    let ctx_ptr = emu.regs().rcx;
    log_red!(emu, "ntdll!RtlCaptureContext ctx:0x{:x}", ctx_ptr);
    // Write a minimal CONTEXT structure (just enough to not crash).
    if ctx_ptr != 0 {
        // ContextFlags at offset 0x30
        let _ = emu.maps.write_dword(ctx_ptr + 0x30, 0x10001f); // CONTEXT_ALL
        // Rip at offset 0xf8
        let _ = emu.maps.write_qword(ctx_ptr + 0xf8, emu.regs().rip);
        // Rsp at offset 0x98
        let _ = emu.maps.write_qword(ctx_ptr + 0x98, emu.regs().rsp);
    }
}

fn RtlLookupFunctionEntry(emu: &mut emu::Emu) {
    let pc = emu.regs().rcx;
    let image_base = emu.regs().rdx;
    let history_table = emu.regs().r8;
    log_red!(emu, "ntdll!RtlLookupFunctionEntry pc:0x{:x}", pc);
    // Return NULL = no function entry found (used for stack unwinding).
    emu.regs_mut().rax = 0;
}

fn RtlVirtualUnwind(emu: &mut emu::Emu) {
    log_red!(emu, "ntdll!RtlVirtualUnwind");
    emu.regs_mut().rax = 0;
}
