use crate::emu::Emu;
use crate::loaders::elf::elf64::Elf64;
use crate::windows::constants;

impl Emu {
    /// Loads an ELF64 parsing sections etc, powered by elf64.rs
    /// This is called from load_code() if the sample is ELF64
    pub fn load_elf64(&mut self, filename: &str) {
        let mut elf64 = Elf64::parse(filename).unwrap();
        let dyn_link = !elf64.get_dynamic().is_empty();

        if dyn_link {
            log::trace!("dynamic elf64 detected.");
        } else {
            log::trace!("static elf64 detected.");
        }

        elf64.load(
            &mut self.maps,
            "elf64",
            false,
            dyn_link,
            self.cfg.code_base_addr,
        );
        if self.cfg.arch.is_aarch64() {
            self.init_linux64_aarch64();
        } else {
            self.init_linux64(dyn_link);
        }

        // Get .text addr and size
        let mut text_addr: u64 = 0;
        let mut text_sz = 0;
        for i in 0..elf64.elf_shdr.len() {
            let sname = elf64.get_section_name(elf64.elf_shdr[i].sh_name as usize);
            if sname == ".text" {
                text_addr = elf64.elf_shdr[i].sh_addr;
                text_sz = elf64.elf_shdr[i].sh_size;
                break;
            }
        }

        if text_addr == 0 {
            panic!(".text not found on this elf64");
        }

        // entry point logic:

        // 1. Configured entry point
        if self.cfg.entry_point != constants::CFG_DEFAULT_BASE {
            log::trace!("forcing entry point to 0x{:x}", self.cfg.entry_point);
            self.set_pc(self.cfg.entry_point);

        // 2. Entry point pointing inside .text
        } else if elf64.elf_hdr.e_entry >= text_addr && elf64.elf_hdr.e_entry < text_addr + text_sz
        {
            log::trace!(
                "Entry point pointing to .text 0x{:x}",
                elf64.elf_hdr.e_entry
            );
            self.set_pc(elf64.elf_hdr.e_entry);

        // 3. Entry point points above .text, relative entry point
        } else if elf64.elf_hdr.e_entry < text_addr {
            self.set_pc(elf64.elf_hdr.e_entry + elf64.base);
            log::trace!(
                "relative entry point: 0x{:x}  fixed: 0x{:x}",
                elf64.elf_hdr.e_entry,
                self.pc()
            );

        // 4. Entry point points below .text, weird case.
        } else {
            panic!(
                "Entry points is pointing below .text 0x{:x}",
                elf64.elf_hdr.e_entry
            );
        }

        /*
        if dyn_link {
            //let mut ld = Elf64::parse("/lib64/ld-linux-x86-64.so.2").unwrap();
            //ld.load(&mut self.maps, "ld-linux", true, dyn_link, constants::CFG_DEFAULT_BASE);
            //log::trace!("--- emulating ld-linux _start ---");

            self.regs_mut().rip = elf64.elf_hdr.e_entry;

            //TODO: emulate the linker
            //self.regs_mut().rip = ld.elf_hdr.e_entry + elf64::LD_BASE;
            //self.run(None);
        } else {
            self.regs_mut().rip = elf64.elf_hdr.e_entry;
        }*/

        /*
        for lib in elf64.get_dynamic() {
            log::trace!("dynamic library {}", lib);
            let libspath = "/usr/lib/x86_64-linux-gnu/";
            let libpath = format!("{}{}", libspath, lib);
            let mut elflib = Elf64::parse(&libpath).unwrap();
            elflib.load(&mut self.maps, &lib, true);

            if lib.contains("libc") {
                elflib.craft_libc_got(&mut self.maps, "elf64");
            }

            /*
            match elflib.init {
                Some(addr) => {
                    self.call64(addr, &[]);
                }
                None => {}
            }*/
        }*/

        self.elf64 = Some(elf64);
    }
}
