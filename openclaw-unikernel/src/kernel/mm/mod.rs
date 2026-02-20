//! # Memory Management
//!
//! Provides the kernel heap allocator and physical frame management.
//! Uses a linked-list free-list allocator with:
//! - Full free-list traversal (first-fit, not just head)
//! - Block splitting (return excess to free list)
//! - Block coalescing on dealloc (merge adjacent free regions)
//! - Accurate heap statistics (tracks free list bytes)
//!
//! Designed for long-running unikernel operation (1000+ autonomous cycles
//! without OOM). Previous version only checked the head of the free list,
//! causing the bump pointer to grow monotonically even when freed memory
//! was available.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

// Heap region bounds — set by linker script.
extern "C" {
    static __heap_start: u8;
    static __heap_end: u8;
}

/// Minimum allocation block size (must fit a FreeBlock header + alignment padding).
const MIN_BLOCK_SIZE: usize = 32;

/// Minimum remainder size worth splitting off. If the leftover after serving
/// an allocation is smaller than this, just give the whole block.
const MIN_SPLIT_SIZE: usize = 64;

/// Free block header stored at the start of each free region.
/// The free list is sorted by address to enable O(1) coalescing on dealloc.
#[repr(C)]
struct FreeBlock {
    size: usize,           // Total size of this free block (including header)
    next: *mut FreeBlock,  // Pointer to next free block (or null)
}

/// Linked-list allocator with coalescing and bump fallback.
///
/// Strategy:
/// 1. Walk the entire free list for a first-fit block with proper alignment
/// 2. Split oversized blocks, returning the remainder to the free list
/// 3. If no suitable free block, bump-allocate from the end
///
/// On dealloc:
/// 1. Insert the freed block into the list sorted by address
/// 2. Coalesce with left neighbor if adjacent
/// 3. Coalesce with right neighbor if adjacent
struct UnikernelAllocator {
    /// Offset into the heap for bump allocation
    bump_next: AtomicUsize,
    /// Head of the free list (0 = empty list), address-sorted
    free_head: AtomicUsize,
    /// Total bytes currently in the free list (for accurate heap stats)
    free_list_bytes: AtomicUsize,
}

impl UnikernelAllocator {
    const fn new() -> Self {
        UnikernelAllocator {
            bump_next: AtomicUsize::new(0),
            free_head: AtomicUsize::new(0),
            free_list_bytes: AtomicUsize::new(0),
        }
    }

    /// Round up size to meet minimum block size and 16-byte alignment.
    fn block_size(layout: &Layout) -> usize {
        let size = layout.size().max(core::mem::size_of::<FreeBlock>());
        // Align to 16 bytes for all blocks
        (size + 15) & !15
    }

    /// Calculate the aligned address within a block, and whether it fits.
    /// Returns (aligned_addr, front_padding) or None if block is too small.
    fn align_within_block(block_addr: usize, block_size: usize, needed: usize, align: usize) -> Option<(usize, usize)> {
        let aligned = (block_addr + align - 1) & !(align - 1);
        let padding = aligned - block_addr;
        if padding + needed <= block_size {
            Some((aligned, padding))
        } else {
            None
        }
    }
}

unsafe impl GlobalAlloc for UnikernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let needed = Self::block_size(&layout);
        let align = layout.align().max(16); // Minimum 16-byte alignment

        // Strategy 1: Walk the ENTIRE free list for a first-fit block.
        // We use a simple spinlock-like approach: disable interrupts aren't
        // needed in a cooperative unikernel (single core, no preemption).
        //
        // Walk with prev pointer so we can unlink from the middle of the list.
        let head_addr = self.free_head.load(Ordering::Acquire);
        if head_addr != 0 {
            let mut prev_ptr: *mut *mut FreeBlock = self.free_head.as_ptr() as *mut *mut FreeBlock;
            let mut current = head_addr as *mut FreeBlock;

            while !current.is_null() {
                let block_addr = current as usize;
                let block_sz = (*current).size;
                let next = (*current).next;

                // Check if this block can serve the allocation (with alignment)
                if let Some((aligned, padding)) = Self::align_within_block(block_addr, block_sz, needed, align) {
                    // This block works! Unlink it from the list.
                    *prev_ptr = next;
                    self.free_list_bytes.fetch_sub(block_sz, Ordering::Relaxed);

                    // If alignment caused front padding >= MIN_SPLIT_SIZE,
                    // return the front padding as a separate free block
                    if padding >= MIN_SPLIT_SIZE {
                        let front_block = block_addr as *mut FreeBlock;
                        (*front_block).size = padding;
                        self.insert_free_block(front_block);
                    }

                    // If the remaining space after the allocation is large enough,
                    // split it off and return to the free list
                    let used_end = aligned + needed;
                    let block_end = block_addr + block_sz;
                    let remainder = block_end - used_end;

                    if remainder >= MIN_SPLIT_SIZE {
                        let split_block = used_end as *mut FreeBlock;
                        (*split_block).size = remainder;
                        self.insert_free_block(split_block);
                    }

                    return aligned as *mut u8;
                }

                // This block doesn't fit — advance to next
                prev_ptr = &mut (*current).next;
                current = next;
            }
        }

        // Strategy 2: Bump allocate (no suitable free block found)
        loop {
            let current = self.bump_next.load(Ordering::Relaxed);
            let heap_start = &__heap_start as *const u8 as usize;
            let heap_end = &__heap_end as *const u8 as usize;

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
        (*block).size = size;
        (*block).next = ptr::null_mut();

        // Insert into the free list sorted by address, then coalesce neighbors
        self.insert_free_block_coalescing(block);
    }
}

impl UnikernelAllocator {
    /// Insert a free block into the list sorted by address (no coalescing).
    /// Used for split blocks that don't need coalescing checks.
    unsafe fn insert_free_block(&self, block: *mut FreeBlock) {
        let block_addr = block as usize;
        let block_size = (*block).size;

        // Find insertion point (sorted by address)
        let mut prev_ptr: *mut *mut FreeBlock = self.free_head.as_ptr() as *mut *mut FreeBlock;
        let mut current = self.free_head.load(Ordering::Acquire) as *mut FreeBlock;

        while !current.is_null() && (current as usize) < block_addr {
            prev_ptr = &mut (*current).next;
            current = (*current).next;
        }

        // Insert between prev and current
        (*block).next = current;
        *prev_ptr = block;
        self.free_list_bytes.fetch_add(block_size, Ordering::Relaxed);
    }

    /// Insert a free block into the list sorted by address WITH coalescing.
    /// Merges with left and right neighbors if they are physically adjacent.
    unsafe fn insert_free_block_coalescing(&self, block: *mut FreeBlock) {
        let block_addr = block as usize;
        let mut block_size = (*block).size;

        // Find insertion point and track the left neighbor
        let mut prev_ptr: *mut *mut FreeBlock = self.free_head.as_ptr() as *mut *mut FreeBlock;
        let mut current = self.free_head.load(Ordering::Acquire) as *mut FreeBlock;
        let mut left_neighbor: *mut FreeBlock = ptr::null_mut();
        let mut _left_prev_ptr: *mut *mut FreeBlock = ptr::null_mut();

        while !current.is_null() && (current as usize) < block_addr {
            left_neighbor = current;
            _left_prev_ptr = prev_ptr;
            prev_ptr = &mut (*current).next;
            current = (*current).next;
        }

        // `current` is the right neighbor (or null)
        // `left_neighbor` is the left neighbor (or null)
        // `prev_ptr` points to where we should insert

        let right_neighbor = current;

        // Try to coalesce with RIGHT neighbor
        let block_end = block_addr + block_size;
        if !right_neighbor.is_null() && block_end == right_neighbor as usize {
            // Merge: absorb right neighbor into this block
            let right_size = (*right_neighbor).size;
            block_size += right_size;
            // Remove right neighbor from list
            *prev_ptr = (*right_neighbor).next;
            self.free_list_bytes.fetch_sub(right_size, Ordering::Relaxed);
            // Update current to the next after the absorbed neighbor
            // (prev_ptr now points to what was right_neighbor.next)
        }

        // Try to coalesce with LEFT neighbor
        if !left_neighbor.is_null() {
            let left_end = left_neighbor as usize + (*left_neighbor).size;
            if left_end == block_addr {
                // Merge: grow left neighbor to absorb this block
                let old_left_size = (*left_neighbor).size;
                (*left_neighbor).size = old_left_size + block_size;
                self.free_list_bytes.fetch_add(block_size, Ordering::Relaxed);
                // Left neighbor is already in the list, just grew
                return;
            }
        }

        // No left coalescing — insert the block at the correct position
        (*block).size = block_size;
        (*block).next = *prev_ptr; // whatever prev_ptr now points to
        *prev_ptr = block;
        self.free_list_bytes.fetch_add(block_size, Ordering::Relaxed);
    }
}

// Expose the AtomicUsize internal pointer for free-list manipulation.
// This is safe because we're single-core cooperative scheduling.
trait AtomicPtr {
    fn as_ptr(&self) -> *mut usize;
}

impl AtomicPtr for AtomicUsize {
    fn as_ptr(&self) -> *mut usize {
        self as *const AtomicUsize as *mut usize
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
/// Now accounts for free list bytes to give accurate "actually in use" numbers.
pub fn heap_stats() -> HeapStats {
    let heap_start = unsafe { &__heap_start as *const u8 as usize };
    let heap_end = unsafe { &__heap_end as *const u8 as usize };
    let bump = ALLOCATOR.bump_next.load(Ordering::Relaxed);
    let free_list = ALLOCATOR.free_list_bytes.load(Ordering::Relaxed);
    let total = heap_end - heap_start;

    // bump = total bytes claimed from the bump allocator
    // free_list = bytes returned to the free list (reusable)
    // actual_used = bump - free_list
    let actual_used = bump.saturating_sub(free_list);

    HeapStats {
        total_bytes: total,
        used_bytes: actual_used,
        free_bytes: total - actual_used,
        bump_bytes: bump,
        free_list_bytes: free_list,
    }
}

pub struct HeapStats {
    pub total_bytes: usize,
    pub used_bytes: usize,
    pub free_bytes: usize,
    /// Raw bump pointer offset (total ever allocated from bump region)
    pub bump_bytes: usize,
    /// Total bytes currently in the free list (reusable)
    pub free_list_bytes: usize,
}
