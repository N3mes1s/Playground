use crate::emu;
use crate::maps::mem64::Permission;
use crate::winapi::helper;
use crate::windows::constants;

pub(super) fn dispatch(api: &str, emu: &mut emu::Emu) -> bool {
    match api {
        "LdrLoadDll" => LdrLoadDll(emu),
        "LdrGetDllHandleEx" => LdrGetDllHandleEx(emu),
        _ => return false,
    }
    true
}

fn LdrLoadDll(emu: &mut emu::Emu) {
    let libname_ptr = emu.regs().r8;
    let libaddr_ptr = emu.regs().r9;

    let libname = emu.maps.read_wide_string(libname_ptr);
    log_red!(emu, "ntdll!LdrLoadDll   lib: {}", libname);

    if libname == "user32.dll" {
        let user32 = emu
            .maps
            .create_map("user32", 0x773b0000, 0x1000, Permission::READ_WRITE)
            .expect("ntdll!LdrLoadDll_gul cannot create map");
        user32.load("maps32/user32.bin");
        let user32_text = emu
            .maps
            .create_map(
                "user32_text",
                0x773b1000,
                0x1000,
                Permission::READ_WRITE_EXECUTE,
            )
            .expect("ntdll!LdrLoadDll_gul cannot create map");
        user32_text.load("maps32/user32_text.bin");

        if !emu.maps.write_qword(libaddr_ptr, 0x773b0000) {
            panic!("ntdll_LdrLoadDll: cannot write in addr param");
        }
    }

    emu.regs_mut().rax = constants::STATUS_SUCCESS;
}

fn LdrGetDllHandleEx(emu: &mut emu::Emu) {
    let flags = emu.regs().rcx;
    let path_ptr = emu.regs().rdx;
    let characteristics = emu.regs().r8;
    let dll_name_ptr = emu.regs().r9;
    let out_hndl = emu
        .maps
        .read_qword(emu.regs().rsp + 0x20)
        .expect("ntdll!LdrGetDllHandleEx error reading out_hdl");

    let dll_name = emu.maps.read_wide_string(dll_name_ptr);

    log_red!(emu, "ntdll!LdrGetDllHandleEx {}", dll_name);

    let result = emu.maps.memcpy(path_ptr, dll_name_ptr, dll_name.len());
    if result == false {
        panic!("LdrGetDllHandleEx failed to copy");
    }

    let handle = helper::handler_create(&dll_name);
    emu.maps.write_qword(out_hndl, handle);

    emu.regs_mut().rax = 1;
}
