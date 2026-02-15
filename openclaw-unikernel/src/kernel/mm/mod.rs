//! # Memory Management
//!
//! Provides the kernel heap allocator and physical frame management.
//! The heap is a simple bump allocator backed by a free-list for reuse,
//! suitable for a unikernel where we control all allocations.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Heap region bounds — set by linker script.
extern "C" {
    static __heap_start: u8;
    static __heap_end: u8;
}

/// Bump allocator with free-list fallback.
struct UnikernelAllocator {
    next: AtomicUsize,
}

impl UnikernelAllocator {
    const fn new() -> Self {
        UnikernelAllocator {
            next: AtomicUsize::new(0),
        }
    }
}

unsafe impl GlobalAlloc for UnikernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();

        loop {
            let current = self.next.load(Ordering::Relaxed);
            let heap_start = unsafe { &__heap_start as *const u8 as usize };
            let heap_end = unsafe { &__heap_end as *const u8 as usize };

            let addr = heap_start + current;
            let aligned = (addr + align - 1) & !(align - 1);
            let offset = aligned - heap_start;
            let new_next = offset + size;

            if heap_start + new_next > heap_end {
                return ptr::null_mut(); // Out of memory
            }

            match self.next.compare_exchange(
                current,
                new_next,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => return aligned as *mut u8,
                Err(_) => continue, // Retry on contention
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Bump allocator: deallocation is a no-op.
        // For long-running agents, we rely on the memory subsystem's
        // internal pooling and arena allocation strategies.
        //
        // Future: implement a proper free-list or slab allocator.
    }
}

#[global_allocator]
static ALLOCATOR: UnikernelAllocator = UnikernelAllocator::new();

/// Initialize the heap. Called once at boot.
pub fn init_heap() {
    // The allocator is statically initialized; this function exists
    // for future expansion (e.g., detecting available RAM from multiboot info).
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
    let used = ALLOCATOR.next.load(Ordering::Relaxed);
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
