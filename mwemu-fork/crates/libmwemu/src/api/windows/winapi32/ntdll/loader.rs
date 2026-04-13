use crate::emu;
use crate::maps::mem64::Permission;
use crate::windows::constants;

pub(super) fn dispatch(api: &str, emu: &mut emu::Emu) -> bool {
    match api {
        "LdrLoadDll" => LdrLoadDll(emu),
        "LdrLoadDll_gul" => LdrLoadDll_gul(emu),
        _ => return false,
    }
    true
}

fn LdrLoadDll(emu: &mut emu::Emu) {
    let libname_ptr = emu
        .maps
        .read_dword(emu.regs().get_esp() + 12)
        .expect("ntdll!LdrLoadDll error reading libname param") as u64;
    let libaddr_ptr = emu
        .maps
        .read_dword(emu.regs().get_esp() + 16)
        .expect("ntdll!LdrLoadDll error reading libaddr param") as u64;

    let libname = emu.maps.read_wide_string(libname_ptr);
    log_red!(emu, "ntdll!LdrLoadDll   lib: {}", libname);

    if libname == "user32.dll" {
        let user32 = emu
            .maps
            .create_map("user32", 0x773b0000, 0x1000, Permission::READ_WRITE)
            .expect("ntdll!LdrLoadDll cannot create map");
        user32.load("maps32/user32.bin");
        let user32_text = emu
            .maps
            .create_map(
                "user32_text",
                0x773b1000,
                0x1000,
                Permission::READ_WRITE_EXECUTE,
            )
            .expect("ntdll!LdrLoadDll cannot create map");
        user32_text.load("maps32/user32_text.bin");

        if !emu.maps.write_dword(libaddr_ptr, 0x773b0000) {
            panic!("ntdll!LdrLoadDll: cannot write in addr param");
        }
    }

    emu.regs_mut().rax = constants::STATUS_SUCCESS as u64;
}

fn LdrLoadDll_gul(emu: &mut emu::Emu) {
    LdrLoadDll(emu);
}
