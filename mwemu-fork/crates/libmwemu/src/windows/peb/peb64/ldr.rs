use crate::emu;
use crate::maps::mem64::Permission;
use crate::windows::peb::peb64::bootstrap::ensure_peb_system_dependent_07;
use crate::windows::structures::LdrDataTableEntry64;
use crate::windows::structures::OrdinalTable;

const NTDLL_LDRP_HASH_TABLE_RVA64: u64 = 0x1d30e0;
const NTDLL_LDRP_HASH_BUCKETS64: u64 = 32;
const LDR_HASH_LINKS_OFFSET64: u64 = 0x7f;
const NTDLL_LDRP_GLOBAL_2680_RVA64: u64 = 0x1d2680;
const NTDLL_LDRP_GLOBAL_26C0_RVA64: u64 = 0x1d26c0;
const NTDLL_LDRP_GLOBAL_26F0_RVA64: u64 = 0x1d26f0;

#[derive(Debug)]
pub struct Flink {
    flink_addr: u64,
    pub mod_base: u64,
    pub mod_name: String,
    pub pe_hdr: u64,
    pub export_table_rva: u64,
    pub export_dir_size: u64,
    pub export_table: u64,
    pub num_of_funcs: u64,
    pub func_name_tbl_rva: u64,
    pub func_name_tbl: u64,
}

impl Flink {
    pub fn new(emu: &mut emu::Emu) -> Flink {
        let Some(peb) = emu.maps.get_map_by_name("peb") else {
            return Flink {
                flink_addr: 0, mod_base: 0, mod_name: String::new(),
                pe_hdr: 0, export_table_rva: 0, export_dir_size: 0,
                export_table: 0, num_of_funcs: 0, func_name_tbl_rva: 0,
                func_name_tbl: 0,
            };
        };
        // peb is already &Mem64 from get_map_by_name
        let peb_base = peb.get_base();
        let ldr = peb.read_qword(peb_base + 0x18);
        let flink = emu.maps.read_qword(ldr + 0x10).unwrap_or(0);

        Flink {
            flink_addr: flink,
            mod_base: 0,
            mod_name: String::new(),
            pe_hdr: 0,
            export_table_rva: 0,
            export_dir_size: 0,
            export_table: 0,
            num_of_funcs: 0,
            func_name_tbl_rva: 0,
            func_name_tbl: 0,
        }
    }

    pub fn print(&self) {
        log::trace!("{:#x?}", self);
    }

    pub fn get_ptr(&self) -> u64 {
        self.flink_addr
    }

    pub fn set_ptr(&mut self, addr: u64) {
        self.flink_addr = addr;
    }

    pub fn load(&mut self, emu: &mut emu::Emu) {
        self.get_mod_base(emu);
        self.get_mod_name(emu);
        self.get_pe_hdr(emu);
        self.get_export_table(emu);
    }

    pub fn get_mod_base(&mut self, emu: &mut emu::Emu) {
        self.mod_base = emu.maps.read_qword(self.flink_addr + 0x30).unwrap_or(0);
        if self.mod_base == 0 && emu.cfg.verbose >= 2 {
            log::trace!("peb64: LDR entry has modbase=0 at 0x{:x}", self.flink_addr);
        }
    }

    pub fn set_mod_base(&mut self, base: u64, emu: &mut emu::Emu) {
        self.mod_base = base;
        emu.maps.write_qword(self.flink_addr + 0x30, base);
    }

    pub fn get_mod_name(&mut self, emu: &mut emu::Emu) {
        let mod_name_ptr = emu.maps.read_qword(self.flink_addr + 0x60).unwrap_or(0);
        self.mod_name = emu.maps.read_wide_string(mod_name_ptr);
    }

    pub fn has_module(&self) -> bool {
        self.mod_base != 0 && self.flink_addr != 0
    }

    pub fn get_pe_hdr(&mut self, emu: &mut emu::Emu) {
        self.pe_hdr = match emu.maps.read_dword(self.mod_base + 0x3c) {
            Some(hdr) => hdr as u64,
            None => 0,
        };
    }

    pub fn get_export_table(&mut self, emu: &mut emu::Emu) {
        if self.pe_hdr == 0 {
            return;
        }

        self.export_table_rva = match emu.maps.read_dword(self.mod_base + self.pe_hdr + 0x88) {
            Some(rva) => rva as u64,
            None => 0,
        };

        self.export_dir_size = emu.maps.read_dword(self.mod_base + self.pe_hdr + 0x8c).unwrap_or(0) as u64;

        if self.export_table_rva == 0 {
            return;
        }

        self.export_table = self.export_table_rva + self.mod_base;
        self.num_of_funcs = emu.maps.read_dword(self.export_table + 0x18).unwrap_or(0) as u64;
        self.func_name_tbl_rva = emu.maps.read_dword(self.export_table + 0x20).unwrap_or(0) as u64;
        self.func_name_tbl = self.func_name_tbl_rva + self.mod_base;
    }

    pub fn get_function_ordinal(&self, emu: &mut emu::Emu, function_id: u64) -> OrdinalTable {
        self.get_function_ordinal_depth(emu, function_id, 0)
    }

    pub fn get_function_ordinal_depth(
        &self,
        emu: &mut emu::Emu,
        function_id: u64,
        forward_depth: u32,
    ) -> OrdinalTable {
        let mut ordinal = OrdinalTable::new();
        let func_name_rva = emu.maps.read_dword(self.func_name_tbl + function_id * 4).unwrap_or(0) as u64;
        ordinal.func_name = emu.maps.read_string(func_name_rva + self.mod_base);
        ordinal.ordinal_tbl_rva = emu.maps.read_dword(self.export_table + 0x24).unwrap_or(0) as u64;
        ordinal.ordinal_tbl = ordinal.ordinal_tbl_rva + self.mod_base;
        ordinal.ordinal = emu.maps.read_word(ordinal.ordinal_tbl + 2 * function_id).unwrap_or(0) as u64;
        ordinal.func_addr_tbl_rva = emu.maps.read_dword(self.export_table + 0x1c).unwrap_or(0) as u64;
        ordinal.func_addr_tbl = ordinal.func_addr_tbl_rva + self.mod_base;
        ordinal.func_rva = emu.maps.read_dword(ordinal.func_addr_tbl + 4 * ordinal.ordinal).unwrap_or(0) as u64;

        if self.export_dir_size > 0
            && ordinal.func_rva >= self.export_table_rva
            && ordinal.func_rva < self.export_table_rva.saturating_add(self.export_dir_size)
        {
            let forwarder = emu.maps.read_string(self.mod_base + ordinal.func_rva);
            let resolved = crate::winapi::winapi64::kernel32::resolve_forwarded_export_string_depth(
                emu,
                &forwarder,
                forward_depth.saturating_add(1),
            );
            if resolved != 0 {
                ordinal.func_va = resolved;
            } else {
                ordinal.func_va = ordinal.func_rva + self.mod_base;
            }
        } else {
            ordinal.func_va = ordinal.func_rva + self.mod_base;
        }

        ordinal
    }

    pub fn get_next_flink(&self, emu: &mut emu::Emu) -> u64 {
        emu.maps.read_qword(self.flink_addr).unwrap_or(0)
    }

    pub fn get_prev_flink(&self, emu: &mut emu::Emu) -> u64 {
        emu.maps.read_qword(self.flink_addr + 8).unwrap_or(0)
    }

    pub fn next(&mut self, emu: &mut emu::Emu) -> bool {
        let next = self.get_next_flink(emu);
        if next == 0 || next == self.flink_addr {
            return false;
        }
        self.flink_addr = next;
        self.load(emu);
        true
    }
}

pub fn get_module_base(libname: &str, emu: &mut emu::Emu) -> Option<u64> {
    // Check if PEB exists before trying to traverse LDR.
    if emu.maps.get_map_by_name("peb").is_none() {
        return None;
    }

    let mut libname2 = libname.to_string().to_lowercase();
    if !libname2.ends_with(".dll") {
        libname2.push_str(".dll");
    }

    let mut flink = Flink::new(emu);
    flink.load(emu);
    let first_flink = flink.get_ptr();
    let mut iters = 0usize;
    loop {
        if libname.to_string().to_lowercase() == flink.mod_name.to_string().to_lowercase()
            || libname2 == flink.mod_name.to_string().to_lowercase()
        {
            return Some(flink.mod_base);
        }
        if !flink.next(emu) {
            break;
        }
        iters += 1;

        if flink.get_ptr() == first_flink || iters > 4096 {
            break;
        }
    }
    None
}

pub fn show_linked_modules(emu: &mut emu::Emu) {
    let mut flink = Flink::new(emu);
    flink.load(emu);
    let first_flink = flink.get_ptr();

    loop {
        let pe1 = emu.maps.read_byte(flink.mod_base + flink.pe_hdr).unwrap_or_default();
        let pe2 = emu
            .maps
            .read_byte(flink.mod_base + flink.pe_hdr + 1)
            .unwrap_or_default();
        log::trace!(
            "0x{:x} {} flink:{:x} blink:{:x} base:{:x} pe_hdr:{:x} {:x}{:x}",
            flink.get_ptr(),
            flink.mod_name,
            flink.get_next_flink(emu),
            flink.get_prev_flink(emu),
            flink.mod_base,
            flink.pe_hdr,
            pe1,
            pe2
        );
        if !flink.next(emu) || flink.get_ptr() == first_flink {
            return;
        }
    }
}

pub fn update_ldr_entry_base(libname: &str, base: u64, emu: &mut emu::Emu) {
    let mut flink = Flink::new(emu);
    flink.load(emu);
    let first = flink.get_ptr();
    loop {
        if flink.mod_name.to_lowercase() == libname.to_lowercase() {
            flink.set_mod_base(base, emu);
            return;
        }
        if !flink.next(emu) || flink.get_ptr() == first {
            break;
        }
    }
}

pub fn dynamic_unlink_module(libname: &str, emu: &mut emu::Emu) {
    let mut prev_flink: u64 = 0;

    let mut flink = Flink::new(emu);
    flink.load(emu);
    let first = flink.get_ptr();
    loop {
        if flink.mod_name == libname {
            break;
        }
        log::trace!("{}", flink.mod_name);
        prev_flink = flink.get_ptr();
        if !flink.next(emu) || flink.get_ptr() == first {
            return;
        }
    }

    flink.next(emu);
    let next_flink: u64 = flink.get_ptr();

    log::trace!("prev_flink: 0x{:x}", prev_flink);
    emu.maps.write_qword(prev_flink, 0);
    log::trace!("next_flink: 0x{:x}", next_flink);
    emu.maps.write_qword(next_flink + 4, prev_flink);

    show_linked_modules(emu);
}

pub fn dynamic_link_module(base: u64, pe_off: u32, libname: &str, emu: &mut emu::Emu) {
    let mut flink = Flink::new(emu);
    flink.load(emu);
    let first_flink = flink.get_ptr();

    let mut iters = 0usize;
    loop {
        let next_addr = flink.get_next_flink(emu);
        if next_addr == first_flink {
            break;
        }
        if !flink.next(emu) {
            break;
        }
        iters += 1;
        if flink.get_next_flink(emu) == first_flink || iters > 4096 {
            break;
        }
    }
    let next_flink: u64 = flink.get_ptr();

    let space_addr = create_ldr_entry(
        emu,
        base,
        pe_off.into(),
        libname,
        first_flink,
        next_flink,
    );

    emu.maps.write_qword(next_flink, space_addr);
    emu.maps.write_qword(next_flink + 0x10, space_addr + 0x10);
    emu.maps.write_qword(next_flink + 0x20, space_addr + 0x20);

    emu.maps.write_qword(first_flink + 8, space_addr);
    emu.maps.write_qword(first_flink + 0x10 + 8, space_addr + 0x10);
    emu.maps.write_qword(first_flink + 0x20 + 8, space_addr + 0x20);
}

pub fn create_ldr_entry(
    emu: &mut emu::Emu,
    base: u64,
    entry_point: u64,
    libname: &str,
    next_flink: u64,
    prev_flink: u64,
) -> u64 {
    let base_addr;
    let sz = LdrDataTableEntry64::size() + 0x40 + (1024 * 2);
    let space_addr = emu
        .maps
        .alloc(sz)
        .expect("cannot alloc few bytes to put the LDR for LoadLibraryA");
    let mut lib = format!("{}.ldr", libname);
    if emu.maps.exists_mapname(&lib) {
        use std::sync::atomic::{AtomicU32, Ordering};
        static LDR_SEQ: AtomicU32 = AtomicU32::new(0);
        lib = format!("{}.ldr.{}", libname, LDR_SEQ.fetch_add(1, Ordering::Relaxed));
    }
    let mut image_sz = 0;
    if base > 0 {
        let pe_hdr = emu.maps.read_dword(base + 0x3c).unwrap() as u64;
        image_sz = emu.maps.read_dword(base + pe_hdr + 0x50).unwrap();
        base_addr = base;
    } else {
        base_addr = space_addr
    }
    let mem = emu
        .maps
        .create_map(lib.as_str(), space_addr, sz, Permission::READ_WRITE)
        .expect("cannot create ldr entry map");
    mem.write_byte(space_addr + sz - 1, 0x61);

    let full_libname = "C:\\Windows\\System32\\".to_string() + libname;

    let mut ldr = LdrDataTableEntry64::new();
    if next_flink != 0 {
        ldr.in_load_order_links.flink = next_flink;
        ldr.in_load_order_links.blink = prev_flink;
        ldr.in_memory_order_links.flink = next_flink + 0x10;
        ldr.in_memory_order_links.blink = prev_flink + 0x10;
        ldr.in_initialization_order_links.flink = next_flink + 0x20;
        ldr.in_initialization_order_links.blink = prev_flink + 0x20;
        ldr.hash_links.flink = next_flink + 0x7f;
        ldr.hash_links.blink = prev_flink + 0x7f;
    } else {
        ldr.in_load_order_links.flink = space_addr;
        ldr.in_load_order_links.blink = space_addr;
        ldr.in_memory_order_links.flink = space_addr + 0x10;
        ldr.in_memory_order_links.blink = space_addr + 0x10;
        ldr.in_initialization_order_links.flink = space_addr + 0x20;
        ldr.in_initialization_order_links.blink = space_addr + 0x20;
        ldr.hash_links.flink = space_addr + 0x7f;
        ldr.hash_links.blink = space_addr + 0x7f;
    }
    ldr.dll_base = base_addr;
    ldr.entry_point = entry_point;
    ldr.size_of_image = image_sz;
    ldr.full_dll_name.length = full_libname.len() as u16 * 2;
    ldr.full_dll_name.maximum_length = full_libname.len() as u16 * 2 + 4;
    ldr.full_dll_name.buffer = space_addr + LdrDataTableEntry64::size();
    ldr.base_dll_name.length = libname.len() as u16 * 2;
    ldr.base_dll_name.maximum_length = libname.len() as u16 * 2 + 2;
    ldr.base_dll_name.buffer =
        space_addr + LdrDataTableEntry64::size() + full_libname.len() as u64 * 2 + 10;
    ldr.flags = 0;
    ldr.load_count = 0;
    ldr.tls_index = 0;
    ldr.hash_links.flink = next_flink;
    ldr.hash_links.blink = prev_flink;
    mem.write_wide_string(
        space_addr + LdrDataTableEntry64::size(),
        &(full_libname.clone() + "\x00\x00"),
    );
    mem.write_wide_string(
        space_addr + LdrDataTableEntry64::size() + full_libname.len() as u64 * 2 + 10,
        &(libname.to_string() + "\x00"),
    );
    ldr.save(space_addr, &mut emu.maps);

    space_addr
}

fn ldr_hash_bucket_index(libname: &str) -> u64 {
    let mut hash: u32 = 0;
    for ch in libname.encode_utf16() {
        let folded = if ch >= b'a' as u16 && ch <= b'z' as u16 { ch - 0x20 } else { ch };
        hash = hash.wrapping_mul(0x1003f).wrapping_add(folded as u32);
    }
    (hash & 0x1f) as u64
}

fn rebuild_ldr_hash_table(emu: &mut emu::Emu, modules: &[ModInfo], entries: &[u64]) {
    let Some(ntdll_map) = emu.maps.get_map_by_name("ntdll.pe") else {
        return;
    };
    let table = ntdll_map.get_base() + NTDLL_LDRP_HASH_TABLE_RVA64;

    for i in 0..NTDLL_LDRP_HASH_BUCKETS64 {
        let head = table + i * 0x10;
        emu.maps.write_qword(head, head);
        emu.maps.write_qword(head + 8, head);
    }

    for (module, entry) in modules.iter().zip(entries.iter()) {
        let bucket = ldr_hash_bucket_index(&module.name);
        let head = table + bucket * 0x10;
        let hash_links = *entry + LDR_HASH_LINKS_OFFSET64;
        let tail = emu.maps.read_qword(head + 8).unwrap_or(head);

        emu.maps.write_qword(hash_links, head);
        emu.maps.write_qword(hash_links + 8, tail);
        emu.maps.write_qword(tail, hash_links);
        emu.maps.write_qword(head + 8, hash_links);
    }
}

fn ensure_ntdll_loader_globals(emu: &mut emu::Emu) {
    let Some(ntdll_map) = emu.maps.get_map_by_name("ntdll.pe") else {
        return;
    };
    let base = ntdll_map.get_base();

    let list_2680 = base + NTDLL_LDRP_GLOBAL_2680_RVA64;
    emu.maps.write_qword(list_2680, list_2680);
    emu.maps.write_qword(list_2680 + 8, list_2680);

    let state_26c0 = base + NTDLL_LDRP_GLOBAL_26C0_RVA64;
    emu.maps.write_qword(state_26c0, u64::MAX);

    let list_26f0 = base + NTDLL_LDRP_GLOBAL_26F0_RVA64;
    emu.maps.write_qword(list_26f0, list_26f0);
    emu.maps.write_qword(list_26f0 + 8, list_26f0);
}

struct ModInfo {
    name: String,
    base: u64,
}

pub fn rebuild_ldr_lists(emu: &mut emu::Emu) {
    ensure_peb_system_dependent_07(emu);
    let peb_addr = emu.maps.get_mem("peb").get_base();
    let ldr_addr = emu.maps.read_qword(peb_addr + 0x18).unwrap_or(0);
    if ldr_addr == 0 {
        return;
    }

    let exe_base = emu.base;
    let exe_name = emu.cfg.exe_name.clone();

    let pe_names: Vec<String> = emu
        .maps
        .name_map
        .keys()
        .filter(|n| n.ends_with(".pe"))
        .cloned()
        .collect();

    let mut modules: Vec<ModInfo> = vec![ModInfo {
        name: exe_name,
        base: exe_base,
    }];

    for map_name in &pe_names {
        let stem = map_name.trim_end_matches(".pe");
        if stem.eq_ignore_ascii_case("ntdll") {
            if let Some(m) = emu.maps.get_map_by_name(map_name) {
                modules.push(ModInfo {
                    name: "ntdll.dll".into(),
                    base: m.get_base(),
                });
            }
        }
    }

    for map_name in &pe_names {
        let stem = map_name.trim_end_matches(".pe");
        if stem.eq_ignore_ascii_case("kernel32") {
            if let Some(m) = emu.maps.get_map_by_name(map_name) {
                modules.push(ModInfo {
                    name: "kernel32.dll".into(),
                    base: m.get_base(),
                });
            }
        }
    }

    for map_name in &pe_names {
        let stem = map_name.trim_end_matches(".pe");
        let sl = stem.to_lowercase();
        if sl == "ntdll" || sl == "kernel32" {
            continue;
        }
        let exe_stem = emu
            .cfg
            .filename
            .split('/')
            .last()
            .unwrap_or("")
            .split('.')
            .next()
            .unwrap_or("");
        if stem.eq_ignore_ascii_case(exe_stem) {
            continue;
        }
        if let Some(m) = emu.maps.get_map_by_name(map_name) {
            modules.push(ModInfo {
                name: format!("{}.dll", stem),
                base: m.get_base(),
            });
        }
    }

    if modules.is_empty() {
        return;
    }

    let mut entries: Vec<u64> = Vec::new();
    for m in &modules {
        let entry_point = if m.base > 0 {
            let pe_hdr = emu.maps.read_dword(m.base + 0x3c).unwrap_or(0) as u64;
            if pe_hdr > 0 {
                let ep_rva = emu.maps.read_dword(m.base + pe_hdr + 0x28).unwrap_or(0) as u64;
                m.base + ep_rva
            } else {
                0
            }
        } else {
            0
        };
        let addr = create_ldr_entry(emu, m.base, entry_point, &m.name, 0, 0);
        entries.push(addr);
    }

    let n = entries.len();
    for i in 0..n {
        let next = entries[(i + 1) % n];
        let prev = entries[(i + n - 1) % n];
        emu.maps.write_qword(entries[i], next);
        emu.maps.write_qword(entries[i] + 8, prev);
        emu.maps.write_qword(entries[i] + 0x10, next + 0x10);
        emu.maps.write_qword(entries[i] + 0x18, prev + 0x10);
        emu.maps.write_qword(entries[i] + 0x20, next + 0x20);
        emu.maps.write_qword(entries[i] + 0x28, prev + 0x20);
    }

    let first = entries[0];
    let last = entries[n - 1];
    emu.maps.write_qword(ldr_addr + 0x10, first);
    emu.maps.write_qword(ldr_addr + 0x18, last);
    emu.maps.write_qword(ldr_addr + 0x20, first + 0x10);
    emu.maps.write_qword(ldr_addr + 0x28, last + 0x10);
    emu.maps.write_qword(ldr_addr + 0x30, first + 0x20);
    emu.maps.write_qword(ldr_addr + 0x38, last + 0x20);
    emu.maps.write_dword(ldr_addr + 4, 1);

    rebuild_ldr_hash_table(emu, &modules, &entries);
    ensure_ntdll_loader_globals(emu);

    if exe_base != 0 {
        emu.maps.write_qword(peb_addr + 0x10, exe_base);
    }

    log::trace!("rebuild_ldr_lists: rebuilt with {} modules", modules.len());
}
