use crate::emu;
use crate::maps::mem64::Permission;
use crate::serialization;
use crate::winapi::winapi64;

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    let api = winapi64::kernel32::guess_api_name(emu, addr);
    let api = api.split("!").last().unwrap_or(&api);
    gateway_by_name(api, emu)
}

pub fn gateway_by_name(api: &str, emu: &mut emu::Emu) -> String {
    match api {
        "_initialize_onexit_table" => _initialize_onexit_table(emu),
        "_register_onexit_function" => _register_onexit_function(emu),
        "_register_thread_local_exe_atexit_callback" => _register_thread_local_exe_atexit_callback(emu),
        "_get_initial_narrow_environment" => _get_initial_narrow_environment(emu),
        "_initialize_narrow_environment" => _initialize_narrow_environment(emu),
        "_configure_narrow_argv" => _configure_narrow_argv(emu),
        "_set_invalid_parameter_handler" => set_invalid_parameter_handler(emu),
        "_invalid_parameter_noinfo_noreturn" => _invalid_parameter_noinfo_noreturn(emu),
        "_set_app_type" => _set_app_type(emu),
        "_set_fmode" => _set_fmode(emu),
        "_set_new_mode" => _set_new_mode(emu),
        "_seh_filter_exe" => _seh_filter_exe(emu),
        "_callnewh" => _callnewh(emu),
        "_configthreadlocale" => _configthreadlocale(emu),
        "___lc_codepage_func" => ___lc_codepage_func(emu),
        "__setusermatherr" => __setusermatherr(emu),
        "terminate" => terminate(emu),
        "malloc" => malloc(emu),
        "calloc" => calloc(emu),
        "free" => free(emu),
        "realloc" => realloc(emu),
        "_crt_atexit" => _crt_atexit(emu),
        "__p___argv" => __p___argv(emu),
        "__p___argc" => __p___argc(emu),
        "__p__environ" => __p__environ(emu),
        "__acrt_iob_func" => __acrt_iob_func(emu),
        "__p__commode" => __p__commode(emu),
        "__p__fmode" => __p__fmode(emu),
        "__stdio_common_vfprintf" => __stdio_common_vfprintf(emu),
        "_get_stream_buffer_pointers" => _get_stream_buffer_pointers(emu),
        // File I/O stubs
        "fread" => fread_stub(emu),
        "fwrite" => fwrite_stub(emu),
        "fclose" => fclose_stub(emu),
        "fflush" => fflush_stub(emu),
        "fgetc" => fgetc_stub(emu),
        "fputc" => fputc_stub(emu),
        "fsetpos" => fsetpos_stub(emu),
        "fgetpos" => fgetpos_stub(emu),
        "_fseeki64" => fseeki64_stub(emu),
        "ungetc" => ungetc_stub(emu),
        "setvbuf" => setvbuf_stub(emu),
        "_lock_file" => lock_file_stub(emu),
        "_unlock_file" => unlock_file_stub(emu),
        // Utility
        "rand" => rand_stub(emu),
        "srand" => srand_stub(emu),
        // String/memory
        "puts" => puts(emu),
        "strlen" => strlen(emu),
        "strncmp" => strncmp(emu),
        "memcpy" => memcpy(emu),
        "memset" => memset(emu),
        "abort" => abort(emu),
        "signal" => signal(emu),
        // VCRuntime stubs
        "__std_type_info_destroy_list" => vcrt_stub(emu, api),
        "_CxxThrowException" => vcrt_stub(emu, api),
        "__CxxFrameHandler4" => vcrt_stub(emu, api),
        "__current_exception" => vcrt_stub(emu, api),
        "__current_exception_context" => vcrt_stub(emu, api),
        "memcmp" => memcmp(emu),
        "_initterm" => _initterm(emu),
        "_initterm_e" => _initterm_e(emu),
        "_cexit" => _cexit(emu),
        "_exit" | "exit" | "_Exit" => exit_stub(emu),
        "__p__acmdln" => __p__acmdln(emu),
        "_get_narrow_winmain_command_line" => _get_narrow_winmain_command_line(emu),
        "_errno" => _errno_stub(emu),
        "strerror" => strerror_stub(emu),
        "strcmp" => strcmp(emu),
        "strcpy" | "strcpy_s" => strcpy(emu),
        "strcat" | "strcat_s" => strcat(emu),
        "sprintf" | "sprintf_s" | "snprintf" | "_snprintf" => sprintf_stub(emu),
        "sscanf" | "sscanf_s" => sscanf_stub(emu),
        "atoi" => atoi(emu),
        "atol" => atoi(emu),
        "strtol" => strtol(emu),
        "toupper" => toupper(emu),
        "tolower" => tolower(emu),
        "isdigit" | "isalpha" | "isalnum" | "isspace" | "isupper" | "islower" => istype_stub(emu, api),
        "wcslen" => wcslen(emu),
        "wcscpy" | "wcscpy_s" => wcscpy(emu),
        _ => {
            if emu.cfg.skip_unimplemented == false {
                if emu.cfg.dump_on_exit && emu.cfg.dump_filename.is_some() {
                    serialization::Serialization::dump_to_file(
                        &emu,
                        emu.cfg.dump_filename.as_ref().unwrap(),
                    );
                }

                unimplemented!("atemmpt to call unimplemented CRT API {}", api);
            }
            log::warn!(
                "calling unimplemented CRT API {} at 0x{:x}",
                api,
                emu.regs().rip
            );
            return api.to_ascii_lowercase();
        }
    }

    String::new()
}

fn _set_app_type(emu: &mut emu::Emu) {
    let app_type = emu.regs().rcx;
    log_red!(emu, "wincrt!_set_app_type app_type: 0x{:x}", app_type);
    emu.regs_mut().rax = 0;
}

fn _initialize_narrow_environment(emu: &mut emu::Emu) {
    log_red!(emu, "wincrt!_initialize_narrow_environment");
    emu.regs_mut().rax = 0;
}

fn _configure_narrow_argv(emu: &mut emu::Emu) {
    let mode = emu.regs().rcx;
    log_red!(emu, "wincrt!_configure_narrow_argv mode: 0x{:x}", mode);
    emu.regs_mut().rax = 0;
}

fn __p__commode(emu: &mut emu::Emu) {
    // int * __p__commode(void)
    let p = emu
        .maps
        .alloc(4)
        .expect("wincrt!__p__commode alloc failed");
    emu.maps
        .create_map(&format!("alloc_{:x}", p), p, 4, Permission::READ_WRITE)
        .expect("wincrt!__p__commode cannot create map");
    let _ = emu.maps.write_dword(p, 0);
    emu.regs_mut().rax = p;
}

fn __p__fmode(emu: &mut emu::Emu) {
    // int * __p__fmode(void)
    let p = emu
        .maps
        .alloc(4)
        .expect("wincrt!__p__fmode alloc failed");
    emu.maps
        .create_map(&format!("alloc_{:x}", p), p, 4, Permission::READ_WRITE)
        .expect("wincrt!__p__fmode cannot create map");
    let _ = emu.maps.write_dword(p, 0);
    emu.regs_mut().rax = p;
}

fn __p__environ(emu: &mut emu::Emu) {
    // char *** __p__environ(void)
    // Return a pointer to a NULL-terminated environment pointer list (empty env).
    let envp = emu
        .maps
        .alloc(8)
        .expect("wincrt!__p__environ alloc failed");
    emu.maps
        .create_map(&format!("alloc_{:x}", envp), envp, 8, Permission::READ_WRITE)
        .expect("wincrt!__p__environ cannot create map");
    let _ = emu.maps.write_qword(envp, 0);
    emu.regs_mut().rax = envp;
}

fn calloc(emu: &mut emu::Emu) {
    let nmemb = emu.regs().rcx;
    let size = emu.regs().rdx;
    let total = nmemb.saturating_mul(size);
    if total == 0 {
        emu.regs_mut().rax = 0;
        return;
    }
    let base = emu.maps.alloc(total).expect("wincrt!calloc out of memory");
    emu.maps
        .create_map(
            &format!("alloc_{:x}", base),
            base,
            total,
            Permission::READ_WRITE,
        )
        .expect("wincrt!calloc cannot create map");
    for i in 0..total {
        let _ = emu.maps.write_byte(base + i, 0);
    }
    log_red!(emu, "wincrt!calloc nmemb:{} size:{} =0x{:x}", nmemb, size, base);
    emu.regs_mut().rax = base;
}

fn free(emu: &mut emu::Emu) {
    let p = emu.regs().rcx;
    log_red!(emu, "wincrt!free 0x{:x}", p);
    emu.regs_mut().rax = 0;
}

fn puts(emu: &mut emu::Emu) {
    let s = emu.regs().rcx;
    let msg = emu.maps.read_string(s);
    log_red!(emu, "wincrt!puts '{}'", msg);
    emu.regs_mut().rax = 0;
}

fn strlen(emu: &mut emu::Emu) {
    let s = emu.regs().rcx;
    let mut n: u64 = 0;
    loop {
        if let Some(b) = emu.maps.read_byte(s + n) {
            if b == 0 {
                break;
            }
            n += 1;
        } else {
            break;
        }
        if n > 0x10_0000 {
            break;
        }
    }
    emu.regs_mut().rax = n;
}

fn strncmp(emu: &mut emu::Emu) {
    let s1 = emu.regs().rcx;
    let s2 = emu.regs().rdx;
    let n = emu.regs().r8;
    let mut i: u64 = 0;
    let mut res: i64 = 0;
    while i < n {
        let b1 = emu.maps.read_byte(s1 + i).unwrap_or(0);
        let b2 = emu.maps.read_byte(s2 + i).unwrap_or(0);
        if b1 != b2 {
            res = (b1 as i64) - (b2 as i64);
            break;
        }
        if b1 == 0 {
            break;
        }
        i += 1;
    }
    emu.regs_mut().rax = res as u64;
}

fn memcpy(emu: &mut emu::Emu) {
    let dst = emu.regs().rcx;
    let src = emu.regs().rdx;
    let n = emu.regs().r8;
    let sz = n.min(usize::MAX as u64) as usize;
    if let Some(bytes) = emu.maps.try_read_bytes(src, sz).map(|b| b.to_vec()) {
        let _ = emu.maps.write_bytes(dst, &bytes);
    }
    emu.regs_mut().rax = dst;
}

fn abort(emu: &mut emu::Emu) {
    log_red!(emu, "wincrt!abort");
    emu.is_running.store(0, std::sync::atomic::Ordering::Relaxed);
    emu.regs_mut().rax = 0;
}

fn signal(emu: &mut emu::Emu) {
    let sig = emu.regs().rcx;
    let handler = emu.regs().rdx;
    log_red!(emu, "wincrt!signal sig:{} handler:0x{:x}", sig, handler);
    emu.regs_mut().rax = 0;
}

fn _initialize_onexit_table(emu: &mut emu::Emu) {
    let table = emu.regs().rcx;

    /*
    http://sandbox.hlt.bme.hu/~gaebor/STLdoc/VS2017/corecrt__startup_8h_source.html
    133 typedef struct _onexit_table_t
    134 {
    135     _PVFV* _first;
    136     _PVFV* _last;
    137     _PVFV* _end;
    138 } _onexit_table_t;
    139
     */

    log_red!(emu, "wincrt!_initialize_onexit_table");

    emu.regs_mut().rax = 0;
}

fn _register_onexit_function(emu: &mut emu::Emu) {
    let table = emu.regs().rcx;
    let callback = emu.regs().rdx;

    /*
    http://sandbox.hlt.bme.hu/~gaebor/STLdoc/VS2017/corecrt__startup_8h_source.html
    133 typedef struct _onexit_table_t
    134 {
    135     _PVFV* _first;
    136     _PVFV* _last;
    137     _PVFV* _end;
    138 } _onexit_table_t;
    139
     */

    log_red!(
        emu,
        "wincrt!_initialize_onexit_function callback: 0x{:x}",
        callback
    );

    emu.regs_mut().rax = 0;
}

/*
extern "C" char** __cdecl _get_initial_narrow_environment()
{
    return common_get_initial_environment<char>();
}
*/
fn _get_initial_narrow_environment(emu: &mut emu::Emu) {
    log_red!(emu, "wincrt!_get_initial_narrow_environment");

    // Return a pointer to a NULL-terminated array of env strings.
    // Allocate: envp[0] = "COMPUTERNAME=DESKTOP-PC\0", envp[1] = NULL
    let env_str = "COMPUTERNAME=DESKTOP-PC\0";
    let str_addr = emu.maps.alloc(env_str.len() as u64).expect("alloc");
    emu.maps.create_map(&format!("alloc_{:x}", str_addr), str_addr, env_str.len() as u64, Permission::READ_WRITE);
    emu.maps.write_string(str_addr, env_str);

    // envp array: [ptr_to_str, NULL]
    let envp_addr = emu.maps.alloc(16).expect("alloc");
    emu.maps.create_map(&format!("alloc_{:x}", envp_addr), envp_addr, 16, Permission::READ_WRITE);
    emu.maps.write_qword(envp_addr, str_addr);
    emu.maps.write_qword(envp_addr + 8, 0);

    emu.regs_mut().rax = envp_addr;
}

// char*** CDECL __p___argv(void) { return &MSVCRT___argv; }
fn __p___argv(emu: &mut emu::Emu) {
    log_red!(emu, "wincrt!__p___argv");

    // argv array: [ptr_to_prog, ptr_to_arg1, NULL]
    let argv_array_addr = emu
        .maps
        .alloc(24) // 3 * sizeof(pointer) on x64
        .expect("wincrt!__p___argv cannot allocate argv array");
    emu.maps.create_map(
        &format!("alloc_{:x}", argv_array_addr),
        argv_array_addr,
        24,
        Permission::READ_WRITE,
    );

    // argv[0] = program name
    let prog_name = "program.exe\0";
    let prog_name_addr = emu
        .maps
        .alloc(prog_name.len() as u64 + 8)
        .expect("wincrt!__p___argv cannot allocate program name");
    emu.maps.create_map(
        &format!("alloc_{:x}", prog_name_addr),
        prog_name_addr,
        prog_name.len() as u64 + 8,
        Permission::READ_WRITE,
    );
    emu.maps.write_string(prog_name_addr, prog_name);

    // argv[1] = fake target argument (for malware that expects argc>=2)
    let arg1 = "C:\\Windows\\System32\\calc.exe\0";
    let arg1_addr = emu
        .maps
        .alloc(arg1.len() as u64 + 8)
        .expect("wincrt!__p___argv cannot allocate arg1");
    emu.maps.create_map(
        &format!("alloc_{:x}", arg1_addr),
        arg1_addr,
        arg1.len() as u64 + 8,
        Permission::READ_WRITE,
    );
    emu.maps.write_string(arg1_addr, arg1);

    // Write argv array
    emu.maps.write_qword(argv_array_addr, prog_name_addr);
    emu.maps.write_qword(argv_array_addr + 8, arg1_addr);
    emu.maps.write_qword(argv_array_addr + 16, 0); // NULL terminator

    // pointer to argv
    let p_argv_addr = emu
        .maps
        .alloc(8)
        .expect("wincrt!__p___argv cannot allocate p_argv");
    emu.maps.create_map(
        &format!("alloc_{:x}", p_argv_addr),
        p_argv_addr,
        8,
        Permission::READ_WRITE,
    );
    emu.maps.write_qword(p_argv_addr, argv_array_addr);

    emu.regs_mut().rax = p_argv_addr;
}

// int* CDECL __p___argc(void) { return &MSVCRT___argc; }
fn __p___argc(emu: &mut emu::Emu) {
    log_red!(emu, "wincrt!__p___argc");

    let argc_addr = emu
        .maps
        .alloc(4)
        .expect("wincrt!__p___argc cannot allocate");
    emu.maps.create_map(
        &format!("alloc_{:x}", argc_addr),
        argc_addr,
        4,
        Permission::READ_WRITE,
    );
    // Return argc=2 so malware that checks for arguments can proceed.
    emu.maps.write_dword(argc_addr, 2);
    emu.regs_mut().rax = argc_addr;
}

/*
FILE * CDECL __acrt_iob_func(int index)
{
    return &__iob_func()[index];
}
*/

fn __acrt_iob_func(emu: &mut emu::Emu) {
    let index = emu.regs().rcx;

    log_red!(emu, "wincrt!__acrt_iob_func index: 0x{:x}", index);

    // Return a fake FILE* for stdin (0), stdout (1), stderr (2).
    // Each FILE struct is 48 bytes (_iobuf on MSVC x64).
    // We allocate a static region for all 3 on first call.
    let iob_base = 0x7FF0_0005_0000u64;
    let file_size = 48u64;
    if emu.maps.get_mem_by_addr(iob_base).is_none() {
        emu.maps.create_map("acrt_iob", iob_base, file_size * 3, Permission::READ_WRITE);
        // stdin:  _file = 0
        emu.maps.write_dword(iob_base + 0x18, 0);
        // stdout: _file = 1
        emu.maps.write_dword(iob_base + file_size + 0x18, 1);
        // stderr: _file = 2
        emu.maps.write_dword(iob_base + file_size * 2 + 0x18, 2);
    }

    let result = iob_base + index * file_size;
    emu.regs_mut().rax = result;
}

/*
_ACRTIMP int __cdecl __stdio_common_vfprintf(unsigned __int64,FILE*,const char*,_locale_t,__ms_va_list);
*/
fn parse_format_specifiers(fmt: &str) -> Vec<&str> {
    let mut specs = Vec::new();
    let mut chars = fmt.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            if let Some(next) = chars.next() {
                if next != '%' {
                    // Skip %% (literal %)
                    specs.push(match next {
                        'd' | 'i' => "int",
                        'x' | 'X' => "hex",
                        'p' => "ptr",
                        's' => "str",
                        // Add other format specifiers as needed
                        _ => "unknown",
                    });
                }
            }
        }
    }
    specs
}

fn __stdio_common_vfprintf(emu: &mut emu::Emu) {
    let options = emu.regs().rcx; // _In_ options
    let file = emu.regs().rdx; // _In_ FILE*
    let format = emu.regs().r8; // _In_ format string ptr
    let locale = emu.regs().r9; // _In_opt_ locale
    let va_list = emu
        .maps
        .read_qword(emu.regs().rsp + 0x20)
        .expect("wincrt!__stdio_common_vfprintf cannot read_qword va_list");

    // Just try to read the format string
    let fmt_str = emu.maps.read_string(format);
    let specs = parse_format_specifiers(&fmt_str);

    log_red!(
        emu,
        "wincrt!__stdio_common_vfprintf options: 0x{:x} file: 0x{:x} format: '{}' locale: 0x{:x} va_list: 0x{:x}",
        options,
        file,
        fmt_str,
        locale,
        va_list
    );

    let mut current_ptr = va_list;
    for spec in specs {
        match spec {
            "int" | "hex" | "ptr" => {
                let arg = emu
                    .maps
                    .read_qword(current_ptr)
                    .expect("wincrt!__stdio_common_vfprintf cannot read_qword arg");
                current_ptr += 8; // Move to next arg
                log::trace!("arg: {:016x}", arg);
            }
            "str" => {
                let str_ptr = emu
                    .maps
                    .read_qword(current_ptr)
                    .expect("wincrt!__stdio_common_vfprintf cannot read_qword str_ptr");
                let string = emu.maps.read_string(str_ptr);
                current_ptr += 8;
                log::trace!("string: {}", string);
            }
            _ => {
                unimplemented!(
                    "wincrt!__stdio_common_vfprintf unknown format character: {}",
                    spec
                );
            }
        }
    }

    // Return success (1) - this is super basic
    emu.regs_mut().rax = 1;
}

fn realloc(emu: &mut emu::Emu) {
    let addr = emu.regs().rcx;
    let size = emu.regs().rdx;

    if addr == 0 {
        if size == 0 {
            emu.maps.dealloc(addr);
            emu.regs_mut().rax = 0;
            return;
        } else {
            let base = emu.maps.alloc(size).expect("msvcrt!malloc out of memory");

            // normally malloc region is permission read write
            emu.maps
                .create_map(
                    &format!("alloc_{:x}", base),
                    base,
                    size,
                    Permission::READ_WRITE,
                )
                .expect("msvcrt!malloc cannot create map");

            log_red!(emu, "msvcrt!realloc 0x{:x} {} =0x{:x}", addr, size, base);

            emu.regs_mut().rax = base;
            return;
        }
    }

    if size == 0 {
        log_red!(emu, "msvcrt!realloc 0x{:x} {} =0x1337", addr, size);

        emu.regs_mut().rax = 0x1337; // weird msvcrt has to return a random unallocated pointer, and the program has to do free() on it
        return;
    }

    let new_addr = emu.maps.alloc(size).expect("msvcrt!realloc out of memory");
    let mem = emu
        .maps
        .get_mem_by_addr_mut(addr)
        .expect("msvcrt!realloc error getting mem");
    let old_permission = mem.permission();
    let prev_size = mem.size();

    emu.maps
        .create_map(
            &format!("alloc_{:x}", new_addr),
            new_addr,
            size,
            old_permission,
        )
        .expect("msvcrt!realloc cannot create map");

    emu.maps.memcpy(new_addr, addr, prev_size);
    emu.maps.dealloc(addr);

    log_red!(
        emu,
        "msvcrt!realloc 0x{:x} {} =0x{:x}",
        addr,
        size,
        new_addr
    );

    emu.regs_mut().rax = new_addr;
}

fn set_invalid_parameter_handler(emu: &mut emu::Emu) {
    log_red!(emu, "wincrt!_set_invalid_parameter_handler");
    emu.regs_mut().rax = 0;
}

fn malloc(emu: &mut emu::Emu) {
    let size = emu.regs().rcx; // In malloc, size is the only parameter

    if size == 0 {
        emu.regs_mut().rax = 0;
        return;
    }

    let base = emu.maps.alloc(size).expect("msvcrt!malloc out of memory");

    emu.maps
        .create_map(
            &format!("alloc_{:x}", base),
            base,
            size,
            Permission::READ_WRITE,
        )
        .expect("msvcrt!malloc cannot create map");

    log_red!(emu, "msvcrt!malloc {} =0x{:x}", size, base);

    emu.regs_mut().rax = base;
}

/*
int _crt_atexit(
    _PVFV const function
)
*/
fn _crt_atexit(emu: &mut emu::Emu) {
    let function = emu.regs().rcx;
    log_red!(emu, "wincrt!_crt_atexit function: 0x{:x}", function);
    emu.regs_mut().rax = 0;
}

fn _register_thread_local_exe_atexit_callback(emu: &mut emu::Emu) {
    let callback = emu.regs().rcx;
    log_red!(emu, "wincrt!_register_thread_local_exe_atexit_callback callback: 0x{:x}", callback);
    emu.regs_mut().rax = 0;
}

fn _invalid_parameter_noinfo_noreturn(emu: &mut emu::Emu) {
    log_red!(emu, "wincrt!_invalid_parameter_noinfo_noreturn");
    // This should terminate, but we'll just return for emulation purposes.
    emu.regs_mut().rax = 0;
}

fn _set_fmode(emu: &mut emu::Emu) {
    let mode = emu.regs().rcx;
    log_red!(emu, "wincrt!_set_fmode mode: 0x{:x}", mode);
    emu.regs_mut().rax = 0;
}

fn _set_new_mode(emu: &mut emu::Emu) {
    let mode = emu.regs().rcx;
    log_red!(emu, "wincrt!_set_new_mode mode: 0x{:x}", mode);
    emu.regs_mut().rax = 0; // return old mode
}

fn _seh_filter_exe(emu: &mut emu::Emu) {
    let exception_pointers = emu.regs().rcx;
    log_red!(emu, "wincrt!_seh_filter_exe ep: 0x{:x}", exception_pointers);
    emu.regs_mut().rax = 1; // EXCEPTION_EXECUTE_HANDLER
}

fn _callnewh(emu: &mut emu::Emu) {
    let size = emu.regs().rcx;
    log_red!(emu, "wincrt!_callnewh size: 0x{:x}", size);
    emu.regs_mut().rax = 0; // no new handler installed
}

fn _configthreadlocale(emu: &mut emu::Emu) {
    let type_ = emu.regs().rcx;
    log_red!(emu, "wincrt!_configthreadlocale type: 0x{:x}", type_);
    emu.regs_mut().rax = 0; // _ENABLE_PER_THREAD_LOCALE
}

fn ___lc_codepage_func(emu: &mut emu::Emu) {
    log_red!(emu, "wincrt!___lc_codepage_func");
    emu.regs_mut().rax = 65001; // UTF-8 codepage
}

fn __setusermatherr(emu: &mut emu::Emu) {
    let handler = emu.regs().rcx;
    log_red!(emu, "wincrt!__setusermatherr handler: 0x{:x}", handler);
    emu.regs_mut().rax = 0;
}

fn terminate(emu: &mut emu::Emu) {
    log_red!(emu, "wincrt!terminate");
    emu.is_running.store(0, std::sync::atomic::Ordering::Relaxed);
    emu.regs_mut().rax = 0;
}

fn _get_stream_buffer_pointers(emu: &mut emu::Emu) {
    let stream = emu.regs().rcx;
    log_red!(emu, "wincrt!_get_stream_buffer_pointers stream: 0x{:x}", stream);
    // Returns 0 (failure) - streams aren't really implemented
    emu.regs_mut().rax = 0;
}

// --- File I/O stubs ---

fn fread_stub(emu: &mut emu::Emu) {
    let buf = emu.regs().rcx;
    let size = emu.regs().rdx;
    let count = emu.regs().r8;
    let stream = emu.regs().r9;
    log_red!(emu, "wincrt!fread buf:0x{:x} size:{} count:{} stream:0x{:x}", buf, size, count, stream);
    emu.regs_mut().rax = 0; // 0 items read (EOF)
}

fn fwrite_stub(emu: &mut emu::Emu) {
    let buf = emu.regs().rcx;
    let size = emu.regs().rdx;
    let count = emu.regs().r8;
    let stream = emu.regs().r9;
    log_red!(emu, "wincrt!fwrite buf:0x{:x} size:{} count:{} stream:0x{:x}", buf, size, count, stream);
    emu.regs_mut().rax = count; // pretend all items written
}

fn fclose_stub(emu: &mut emu::Emu) {
    let stream = emu.regs().rcx;
    log_red!(emu, "wincrt!fclose stream: 0x{:x}", stream);
    emu.regs_mut().rax = 0; // success
}

fn fflush_stub(emu: &mut emu::Emu) {
    let stream = emu.regs().rcx;
    log_red!(emu, "wincrt!fflush stream: 0x{:x}", stream);
    emu.regs_mut().rax = 0; // success
}

fn fgetc_stub(emu: &mut emu::Emu) {
    let stream = emu.regs().rcx;
    log_red!(emu, "wincrt!fgetc stream: 0x{:x}", stream);
    emu.regs_mut().rax = 0xFFFF_FFFF_FFFF_FFFF; // EOF (-1)
}

fn fputc_stub(emu: &mut emu::Emu) {
    let c = emu.regs().rcx;
    let stream = emu.regs().rdx;
    log_red!(emu, "wincrt!fputc c:{} stream: 0x{:x}", c as u8 as char, stream);
    emu.regs_mut().rax = c; // return the character written
}

fn fsetpos_stub(emu: &mut emu::Emu) {
    let stream = emu.regs().rcx;
    let pos = emu.regs().rdx;
    log_red!(emu, "wincrt!fsetpos stream:0x{:x} pos:0x{:x}", stream, pos);
    emu.regs_mut().rax = 0; // success
}

fn fgetpos_stub(emu: &mut emu::Emu) {
    let stream = emu.regs().rcx;
    let pos = emu.regs().rdx;
    log_red!(emu, "wincrt!fgetpos stream:0x{:x} pos:0x{:x}", stream, pos);
    if pos != 0 {
        let _ = emu.maps.write_qword(pos, 0); // position 0
    }
    emu.regs_mut().rax = 0; // success
}

fn fseeki64_stub(emu: &mut emu::Emu) {
    let stream = emu.regs().rcx;
    let offset = emu.regs().rdx as i64;
    let origin = emu.regs().r8;
    log_red!(emu, "wincrt!_fseeki64 stream:0x{:x} offset:{} origin:{}", stream, offset, origin);
    emu.regs_mut().rax = 0; // success
}

fn ungetc_stub(emu: &mut emu::Emu) {
    let c = emu.regs().rcx;
    let stream = emu.regs().rdx;
    log_red!(emu, "wincrt!ungetc c:{} stream:0x{:x}", c, stream);
    emu.regs_mut().rax = c; // return the pushed-back character
}

fn setvbuf_stub(emu: &mut emu::Emu) {
    let stream = emu.regs().rcx;
    let buf = emu.regs().rdx;
    let mode = emu.regs().r8;
    let size = emu.regs().r9;
    log_red!(emu, "wincrt!setvbuf stream:0x{:x} buf:0x{:x} mode:{} size:{}", stream, buf, mode, size);
    emu.regs_mut().rax = 0; // success
}

fn lock_file_stub(emu: &mut emu::Emu) {
    let stream = emu.regs().rcx;
    log_red!(emu, "wincrt!_lock_file stream:0x{:x}", stream);
}

fn unlock_file_stub(emu: &mut emu::Emu) {
    let stream = emu.regs().rcx;
    log_red!(emu, "wincrt!_unlock_file stream:0x{:x}", stream);
}

// --- Utility ---

fn rand_stub(emu: &mut emu::Emu) {
    log_red!(emu, "wincrt!rand");
    emu.regs_mut().rax = 42; // deterministic for reproducibility
}

fn srand_stub(emu: &mut emu::Emu) {
    let seed = emu.regs().rcx;
    log_red!(emu, "wincrt!srand seed: {}", seed);
}

fn memset(emu: &mut emu::Emu) {
    let dst = emu.regs().rcx;
    let val = emu.regs().rdx as u8;
    let n = emu.regs().r8;
    for i in 0..n.min(0x100000) {
        let _ = emu.maps.write_byte(dst + i, val);
    }
    log_red!(emu, "wincrt!memset dst:0x{:x} val:0x{:x} n:{}", dst, val, n);
    emu.regs_mut().rax = dst;
}

fn memcmp(emu: &mut emu::Emu) {
    let s1 = emu.regs().rcx;
    let s2 = emu.regs().rdx;
    let n = emu.regs().r8;
    let mut result: i32 = 0;
    for i in 0..n.min(0x100000) {
        let b1 = emu.maps.read_byte(s1 + i).unwrap_or(0);
        let b2 = emu.maps.read_byte(s2 + i).unwrap_or(0);
        if b1 != b2 {
            result = (b1 as i32) - (b2 as i32);
            break;
        }
    }
    emu.regs_mut().rax = result as u64;
}

fn vcrt_stub(emu: &mut emu::Emu, name: &str) {
    log_red!(emu, "vcruntime!{}", name);
    emu.regs_mut().rax = 0;
}

/// _initterm calls each function pointer in the array [first, last).
/// These are C++ static constructors / CRT init routines.
fn _initterm(emu: &mut emu::Emu) {
    let first = emu.regs().rcx;
    let last = emu.regs().rdx;
    log_red!(emu, "wincrt!_initterm first:0x{:x} last:0x{:x}", first, last);
    // Skip static constructors - they often require deep CRT state.
}

/// _initterm_e is like _initterm but the functions return an error code.
/// Returns 0 on success.
fn _initterm_e(emu: &mut emu::Emu) {
    let first = emu.regs().rcx;
    let last = emu.regs().rdx;
    log_red!(emu, "wincrt!_initterm_e first:0x{:x} last:0x{:x}", first, last);
    // Skip init functions - return success.
    // The individual CRT setup (_set_app_type, _configure_narrow_argv, etc.)
    // will be called by __scrt_common_main_seh directly after _initterm_e.
    emu.regs_mut().rax = 0;
}

fn _cexit(emu: &mut emu::Emu) {
    log_red!(emu, "wincrt!_cexit");
}

fn exit_stub(emu: &mut emu::Emu) {
    let code = emu.regs().rcx;
    log_red!(emu, "wincrt!exit code: {}", code);
    emu.is_running.store(0, std::sync::atomic::Ordering::Relaxed);
}

fn __p__acmdln(emu: &mut emu::Emu) {
    log_red!(emu, "wincrt!__p__acmdln");
    let cmd = "program.exe\0";
    let cmd_addr = emu.maps.alloc(cmd.len() as u64 + 8).expect("alloc failed");
    emu.maps.create_map(&format!("alloc_{:x}", cmd_addr), cmd_addr, cmd.len() as u64 + 8, Permission::READ_WRITE);
    emu.maps.write_string(cmd_addr, cmd);
    let p_addr = emu.maps.alloc(8).expect("alloc failed");
    emu.maps.create_map(&format!("alloc_{:x}", p_addr), p_addr, 8, Permission::READ_WRITE);
    emu.maps.write_qword(p_addr, cmd_addr);
    emu.regs_mut().rax = p_addr;
}

fn _get_narrow_winmain_command_line(emu: &mut emu::Emu) {
    log_red!(emu, "wincrt!_get_narrow_winmain_command_line");
    let cmd = "\0";
    let cmd_addr = emu.maps.alloc(8).expect("alloc failed");
    emu.maps.create_map(&format!("alloc_{:x}", cmd_addr), cmd_addr, 8, Permission::READ_WRITE);
    emu.maps.write_string(cmd_addr, cmd);
    emu.regs_mut().rax = cmd_addr;
}

fn _errno_stub(emu: &mut emu::Emu) {
    log_red!(emu, "wincrt!_errno");
    let p = emu.maps.alloc(4).expect("alloc failed");
    emu.maps.create_map(&format!("alloc_{:x}", p), p, 4, Permission::READ_WRITE);
    let _ = emu.maps.write_dword(p, 0);
    emu.regs_mut().rax = p;
}

fn strerror_stub(emu: &mut emu::Emu) {
    let errnum = emu.regs().rcx;
    log_red!(emu, "wincrt!strerror errnum: {}", errnum);
    let msg = "Unknown error\0";
    let addr = emu.maps.alloc(msg.len() as u64).expect("alloc failed");
    emu.maps.create_map(&format!("alloc_{:x}", addr), addr, msg.len() as u64, Permission::READ_WRITE);
    emu.maps.write_string(addr, msg);
    emu.regs_mut().rax = addr;
}

fn strcmp(emu: &mut emu::Emu) {
    let s1 = emu.regs().rcx;
    let s2 = emu.regs().rdx;
    let str1 = emu.maps.read_string(s1);
    let str2 = emu.maps.read_string(s2);
    let result = str1.cmp(&str2) as i32;
    log_red!(emu, "wincrt!strcmp '{}' vs '{}' = {}", str1, str2, result);
    emu.regs_mut().rax = result as u64;
}

fn strcpy(emu: &mut emu::Emu) {
    let dst = emu.regs().rcx;
    let src = emu.regs().rdx;
    let s = emu.maps.read_string(src);
    emu.maps.write_string(dst, &format!("{}\0", s));
    log_red!(emu, "wincrt!strcpy dst:0x{:x} src:'{}' ", dst, s);
    emu.regs_mut().rax = dst;
}

fn strcat(emu: &mut emu::Emu) {
    let dst = emu.regs().rcx;
    let src = emu.regs().rdx;
    let s1 = emu.maps.read_string(dst);
    let s2 = emu.maps.read_string(src);
    let combined = format!("{}{}\0", s1, s2);
    emu.maps.write_string(dst, &combined);
    log_red!(emu, "wincrt!strcat -> '{}'", combined.trim_end_matches('\0'));
    emu.regs_mut().rax = dst;
}

fn sprintf_stub(emu: &mut emu::Emu) {
    let buf = emu.regs().rcx;
    let fmt = emu.regs().rdx;
    let fmt_str = emu.maps.read_string(fmt);
    log_red!(emu, "wincrt!sprintf buf:0x{:x} fmt:'{}'", buf, fmt_str);
    // Write the format string as-is (without substitution).
    emu.maps.write_string(buf, &format!("{}\0", fmt_str));
    emu.regs_mut().rax = fmt_str.len() as u64;
}

fn sscanf_stub(emu: &mut emu::Emu) {
    let buf = emu.regs().rcx;
    let fmt = emu.regs().rdx;
    let fmt_str = emu.maps.read_string(fmt);
    log_red!(emu, "wincrt!sscanf buf:0x{:x} fmt:'{}'", buf, fmt_str);
    emu.regs_mut().rax = 0; // 0 items matched
}

fn atoi(emu: &mut emu::Emu) {
    let s = emu.regs().rcx;
    let str_val = emu.maps.read_string(s);
    let val: i32 = str_val.trim().parse().unwrap_or(0);
    log_red!(emu, "wincrt!atoi '{}' = {}", str_val, val);
    emu.regs_mut().rax = val as u64;
}

fn strtol(emu: &mut emu::Emu) {
    let s = emu.regs().rcx;
    let str_val = emu.maps.read_string(s);
    let base = emu.regs().r8 as u32;
    let val = i64::from_str_radix(str_val.trim(), if base == 0 { 10 } else { base });
    let result = val.unwrap_or(0);
    log_red!(emu, "wincrt!strtol '{}' base:{} = {}", str_val, base, result);
    emu.regs_mut().rax = result as u64;
}

fn toupper(emu: &mut emu::Emu) {
    let c = emu.regs().rcx as u8;
    emu.regs_mut().rax = (c as char).to_uppercase().next().unwrap_or(c as char) as u64;
}

fn tolower(emu: &mut emu::Emu) {
    let c = emu.regs().rcx as u8;
    emu.regs_mut().rax = (c as char).to_lowercase().next().unwrap_or(c as char) as u64;
}

fn istype_stub(emu: &mut emu::Emu, name: &str) {
    let c = emu.regs().rcx as u8 as char;
    let result = match name {
        "isdigit" => c.is_ascii_digit(),
        "isalpha" => c.is_ascii_alphabetic(),
        "isalnum" => c.is_ascii_alphanumeric(),
        "isspace" => c.is_ascii_whitespace(),
        "isupper" => c.is_ascii_uppercase(),
        "islower" => c.is_ascii_lowercase(),
        _ => false,
    };
    emu.regs_mut().rax = result as u64;
}

fn wcslen(emu: &mut emu::Emu) {
    let s = emu.regs().rcx;
    let mut n: u64 = 0;
    loop {
        let lo = emu.maps.read_byte(s + n * 2).unwrap_or(0);
        let hi = emu.maps.read_byte(s + n * 2 + 1).unwrap_or(0);
        if lo == 0 && hi == 0 { break; }
        n += 1;
        if n > 0x10_0000 { break; }
    }
    emu.regs_mut().rax = n;
}

fn wcscpy(emu: &mut emu::Emu) {
    let dst = emu.regs().rcx;
    let src = emu.regs().rdx;
    let mut i: u64 = 0;
    loop {
        let lo = emu.maps.read_byte(src + i * 2).unwrap_or(0);
        let hi = emu.maps.read_byte(src + i * 2 + 1).unwrap_or(0);
        let _ = emu.maps.write_byte(dst + i * 2, lo);
        let _ = emu.maps.write_byte(dst + i * 2 + 1, hi);
        if lo == 0 && hi == 0 { break; }
        i += 1;
        if i > 0x10_0000 { break; }
    }
    emu.regs_mut().rax = dst;
}
