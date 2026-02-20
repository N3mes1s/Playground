//! # Page Table Management
//!
//! Identity-maps the first 4 GiB and creates higher-half mappings for the kernel.
//! Uses 2 MiB huge pages for simplicity and performance.

/// Page table entry flags.
pub mod flags {
    pub const PRESENT: u64 = 1 << 0;
    pub const WRITABLE: u64 = 1 << 1;
    pub const HUGE_PAGE: u64 = 1 << 7;
    pub const NO_EXECUTE: u64 = 1 << 63;
}

/// 512-entry page table (4 KiB aligned).
#[repr(C, align(4096))]
pub struct PageTable {
    entries: [u64; 512],
}

impl PageTable {
    pub const fn empty() -> Self {
        PageTable {
            entries: [0; 512],
        }
    }

    pub fn set(&mut self, index: usize, addr: u64, flags: u64) {
        self.entries[index] = addr | flags;
    }

    pub fn get(&self, index: usize) -> u64 {
        self.entries[index]
    }

    pub fn clear(&mut self) {
        for entry in self.entries.iter_mut() {
            *entry = 0;
        }
    }
}

// Static page tables for initial mapping
static mut PML4: PageTable = PageTable::empty();
static mut PDPT_LOW: PageTable = PageTable::empty();
static mut PDPT_HIGH: PageTable = PageTable::empty();
static mut PD_TABLES: [PageTable; 4] = [
    PageTable::empty(),
    PageTable::empty(),
    PageTable::empty(),
    PageTable::empty(),
];

/// Set up initial page tables:
/// - Identity map first 4 GiB (for boot and device access)
/// - Higher-half map at 0xFFFFFF80_00000000 for kernel code
pub fn init() {
    unsafe {
        // Clear all tables
        PML4.clear();
        PDPT_LOW.clear();
        PDPT_HIGH.clear();
        for pd in PD_TABLES.iter_mut() {
            pd.clear();
        }

        // Fill page directory tables with 2 MiB huge pages
        // Maps 4 GiB total (4 PDs × 512 entries × 2 MiB)
        for (pd_idx, pd) in PD_TABLES.iter_mut().enumerate() {
            for i in 0..512 {
                let phys_addr = ((pd_idx * 512) + i) as u64 * 0x200000; // 2 MiB pages
                pd.set(i, phys_addr, flags::PRESENT | flags::WRITABLE | flags::HUGE_PAGE);
            }
        }

        // Low PDPT: point to our PD tables (identity mapping)
        for i in 0..4 {
            let pd_addr = &PD_TABLES[i] as *const PageTable as u64;
            PDPT_LOW.set(i, pd_addr, flags::PRESENT | flags::WRITABLE);
        }

        // High PDPT: same physical pages, mapped at higher-half
        for i in 0..4 {
            let pd_addr = &PD_TABLES[i] as *const PageTable as u64;
            PDPT_HIGH.set(i, pd_addr, flags::PRESENT | flags::WRITABLE);
        }

        // PML4 entry 0: identity map via low PDPT
        let pdpt_low_addr = &PDPT_LOW as *const PageTable as u64;
        PML4.set(0, pdpt_low_addr, flags::PRESENT | flags::WRITABLE);

        // PML4 entry 510: higher-half kernel mapping
        // 0xFFFFFF80_00000000 >> 39 = 511, but we use 510 for the kernel region
        let pdpt_high_addr = &PDPT_HIGH as *const PageTable as u64;
        PML4.set(510, pdpt_high_addr, flags::PRESENT | flags::WRITABLE);

        // Load PML4 into CR3
        let pml4_addr = &PML4 as *const PageTable as u64;
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) pml4_addr,
            options(nostack)
        );
    }
}
