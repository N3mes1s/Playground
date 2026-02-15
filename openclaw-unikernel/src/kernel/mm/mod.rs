//! # Memory Management
//!
//! Provides the kernel heap allocator and physical frame management.
//! Uses a linked-list free-list allocator that supports both allocation and
//! deallocation, suitable for a long-running unikernel.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Heap region bounds — set by linker script.
extern "C" {
    static __heap_start: u8;
    static __heap_end: u8;
}

/// Minimum allocation block size (must fit a FreeBlock header).
const MIN_BLOCK_SIZE: usize = 32;

/// Free block header stored at the start of each free region.
#[repr(C)]
struct FreeBlock {
    size: usize,          // Total size of this free block (including header)
    next: *mut FreeBlock,  // Pointer to next free block (or null)
}

/// Linked-list allocator with bump fallback.
///
/// Strategy:
/// 1. Check the free list for a block that fits (first-fit)
/// 2. If no suitable free block, bump-allocate from the end
struct UnikernelAllocator {
    /// Offset into the heap for bump allocation
    bump_next: AtomicUsize,
    /// Head of the free list (0 = empty list)
    free_head: AtomicUsize,
}

impl UnikernelAllocator {
    const fn new() -> Self {
        UnikernelAllocator {
            bump_next: AtomicUsize::new(0),
            free_head: AtomicUsize::new(0),
        }
    }

    /// Round up size to include header and meet minimum block size.
    fn block_size(layout: &Layout) -> usize {
        let size = layout.size().max(core::mem::size_of::<FreeBlock>());
        // Align to 16 bytes for all blocks
        (size + 15) & !15
    }
}

unsafe impl GlobalAlloc for UnikernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let needed = Self::block_size(&layout);
        let align = layout.align().max(16); // Minimum 16-byte alignment

        // Strategy 1: Search free list for a suitable block (first-fit)
        // Use a simple lock-free approach: try to claim the head
        loop {
            let head_addr = self.free_head.load(Ordering::Acquire);
            if head_addr == 0 {
                break; // Free list is empty
            }

            let head = head_addr as *mut FreeBlock;
            let block_sz = unsafe { (*head).size };
            let next = unsafe { (*head).next } as usize;

            if block_sz >= needed {
                // Try to remove this block from the free list
                match self.free_head.compare_exchange(
                    head_addr,
                    next,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // Check alignment
                        let addr = head_addr;
                        if addr & (align - 1) == 0 {
                            return addr as *mut u8;
                        }
                        // Alignment doesn't match — put it back and fall through to bump
                        self.dealloc(head_addr as *mut u8, Layout::from_size_align_unchecked(block_sz, 1));
                        break;
                    }
                    Err(_) => continue, // CAS failed, retry
                }
            } else {
                // This block is too small; we'd need to traverse the list,
                // but for simplicity, fall through to bump allocation.
                // A more sophisticated allocator would walk the full list.
                break;
            }
        }

        // Strategy 2: Bump allocate
        loop {
            let current = self.bump_next.load(Ordering::Relaxed);
            let heap_start = unsafe { &__heap_start as *const u8 as usize };
            let heap_end = unsafe { &__heap_end as *const u8 as usize };

            let addr = heap_start + current;
            let aligned = (addr + align - 1) & !(align - 1);
            let offset = aligned - heap_start;
            let new_next = offset + needed;

            if heap_start + new_next > heap_end {
                return ptr::null_mut(); // Out of memory
            }

            match self.bump_next.compare_exchange(
                current,
                new_next,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => return aligned as *mut u8,
                Err(_) => continue,
            }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let size = Self::block_size(&layout);
        if size < core::mem::size_of::<FreeBlock>() {
            return; // Too small to track
        }

        let block = ptr as *mut FreeBlock;

        // Add to the head of the free list
        loop {
            let current_head = self.free_head.load(Ordering::Relaxed);
            unsafe {
                (*block).size = size;
                (*block).next = current_head as *mut FreeBlock;
            }
            match self.free_head.compare_exchange(
                current_head,
                ptr as usize,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(_) => continue,
            }
        }
    }
}

#[global_allocator]
static ALLOCATOR: UnikernelAllocator = UnikernelAllocator::new();

/// Initialize the heap. Called once at boot.
pub fn init_heap() {
    let heap_start = unsafe { &__heap_start as *const u8 as usize };
    let heap_end = unsafe { &__heap_end as *const u8 as usize };
    let heap_size = heap_end - heap_start;

    // Zero the heap region
    unsafe {
        ptr::write_bytes(heap_start as *mut u8, 0, heap_size);
    }
}

/// Returns heap usage statistics.
pub fn heap_stats() -> HeapStats {
    let heap_start = unsafe { &__heap_start as *const u8 as usize };
    let heap_end = unsafe { &__heap_end as *const u8 as usize };
    let used = ALLOCATOR.bump_next.load(Ordering::Relaxed);
    let total = heap_end - heap_start;

    HeapStats {
        total_bytes: total,
        used_bytes: used,
        free_bytes: total - used,
    }
}

pub struct HeapStats {
    pub total_bytes: usize,
    pub used_bytes: usize,
    pub free_bytes: usize,
}
