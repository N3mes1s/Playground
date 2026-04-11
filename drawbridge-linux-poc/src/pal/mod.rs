//! PAL (Platform Abstraction Layer) - Linux implementation
//!
//! This is the real PAL: ~50 operations that abstract the host OS.
//! Modeled directly after Gramine's PAL API but implemented as a
//! Rust-native layer for our Drawbridge runner.
//!
//! Each PAL call maps to one or a few Linux syscalls.
//! This is the ONLY layer that talks to the host kernel.

use anyhow::{bail, Result};
use nix::sys::mman::{self, MapFlags, ProtFlags};
use std::num::NonZeroUsize;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr::NonNull;

/// PAL handle - wraps a Linux resource (fd, thread, event, etc.)
#[derive(Debug)]
pub enum PalHandle {
    File(OwnedFd),
    Console(RawFd), // stdout/stderr - not owned
    Thread(std::thread::JoinHandle<i32>),
    Event { fd: OwnedFd },
    Memory { addr: *mut u8, size: usize },
    Invalid,
}

/// PAL memory protection flags
#[derive(Debug, Clone, Copy)]
pub struct PalProt(u32);

impl PalProt {
    pub const NONE: PalProt = PalProt(0);
    pub const READ: PalProt = PalProt(1);
    pub const WRITE: PalProt = PalProt(2);
    pub const EXEC: PalProt = PalProt(4);
    pub const READ_WRITE: PalProt = PalProt(3);
    pub const READ_EXEC: PalProt = PalProt(5);
    pub const READ_WRITE_EXEC: PalProt = PalProt(7);

    fn to_mmap_prot(self) -> ProtFlags {
        let mut flags = ProtFlags::empty();
        if self.0 & 1 != 0 {
            flags |= ProtFlags::PROT_READ;
        }
        if self.0 & 2 != 0 {
            flags |= ProtFlags::PROT_WRITE;
        }
        if self.0 & 4 != 0 {
            flags |= ProtFlags::PROT_EXEC;
        }
        if flags.is_empty() {
            flags = ProtFlags::PROT_NONE;
        }
        flags
    }
}

/// Initialize the PAL subsystem
pub fn pal_init() -> Result<()> {
    Ok(())
}

// ============================================================
// Memory Management
// ============================================================

/// Allocate virtual memory (maps to mmap)
pub fn pal_virtual_memory_alloc(
    addr: Option<*mut u8>,
    size: usize,
    prot: PalProt,
) -> Result<*mut u8> {
    let prot_flags = prot.to_mmap_prot();
    let mut map_flags = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS;

    let addr_hint = match addr {
        Some(a) if !a.is_null() => {
            map_flags |= MapFlags::MAP_FIXED;
            NonZeroUsize::new(a as usize)
        }
        _ => None,
    };

    let size_nz = NonZeroUsize::new(size).ok_or_else(|| anyhow::anyhow!("zero size"))?;
    let result = unsafe { mman::mmap_anonymous(addr_hint, size_nz, prot_flags, map_flags) };

    match result {
        Ok(ptr) => Ok(ptr.as_ptr() as *mut u8),
        Err(e) => bail!("PAL mmap failed: {}", e),
    }
}

/// Free virtual memory (maps to munmap)
pub fn pal_virtual_memory_free(addr: *mut u8, size: usize) -> Result<()> {
    let ptr: NonNull<std::ffi::c_void> =
        NonNull::new(addr as *mut std::ffi::c_void).ok_or_else(|| anyhow::anyhow!("null pointer"))?;
    unsafe { mman::munmap(ptr, size) }.map_err(|e| anyhow::anyhow!("PAL munmap failed: {}", e))
}

/// Change memory protection (maps to mprotect)
pub fn pal_virtual_memory_protect(addr: *mut u8, size: usize, prot: PalProt) -> Result<()> {
    let ptr: NonNull<std::ffi::c_void> =
        NonNull::new(addr as *mut std::ffi::c_void).ok_or_else(|| anyhow::anyhow!("null pointer"))?;
    unsafe { mman::mprotect(ptr, size, prot.to_mmap_prot()) }
        .map_err(|e| anyhow::anyhow!("PAL mprotect failed: {}", e))
}

// ============================================================
// I/O Streams
// ============================================================

/// Open a file stream (maps to open)
pub fn pal_stream_open(path: &str, read: bool, write: bool, create: bool) -> Result<PalHandle> {
    use nix::fcntl::OFlag;
    use nix::sys::stat::Mode;

    let mut flags = OFlag::empty();
    if read && write {
        flags |= OFlag::O_RDWR;
    } else if write {
        flags |= OFlag::O_WRONLY;
    } else {
        flags |= OFlag::O_RDONLY;
    }
    if create {
        flags |= OFlag::O_CREAT;
    }

    // Use nix::fcntl::open with a &str path (NixPath is implemented for str)
    let fd = nix::fcntl::open(path, flags, Mode::from_bits_truncate(0o644))
        .map_err(|e| anyhow::anyhow!("PAL open({}) failed: {}", path, e))?;

    Ok(PalHandle::File(unsafe { OwnedFd::from_raw_fd(fd) }))
}

/// Read from a stream
pub fn pal_stream_read(handle: &PalHandle, buf: &mut [u8]) -> Result<usize> {
    let raw_fd = match handle {
        PalHandle::File(fd) => fd.as_raw_fd(),
        PalHandle::Console(fd) => *fd,
        _ => bail!("Cannot read from this handle type"),
    };
    let n = unsafe { libc::read(raw_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        bail!("PAL read failed: {}", std::io::Error::last_os_error());
    }
    Ok(n as usize)
}

/// Write to a stream
pub fn pal_stream_write(handle: &PalHandle, buf: &[u8]) -> Result<usize> {
    let raw_fd = match handle {
        PalHandle::File(fd) => fd.as_raw_fd(),
        PalHandle::Console(fd) => *fd,
        _ => bail!("Cannot write to this handle type"),
    };
    let n = unsafe { libc::write(raw_fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
    if n < 0 {
        bail!("PAL write failed: {}", std::io::Error::last_os_error());
    }
    Ok(n as usize)
}

/// Close a stream
pub fn pal_stream_close(handle: PalHandle) -> Result<()> {
    match handle {
        PalHandle::File(fd) => drop(fd),
        PalHandle::Console(_) => {}
        _ => {}
    }
    Ok(())
}

/// Get stdout handle
pub fn pal_console_stdout() -> PalHandle {
    PalHandle::Console(1)
}

/// Get stderr handle
pub fn pal_console_stderr() -> PalHandle {
    PalHandle::Console(2)
}

// ============================================================
// Threading
// ============================================================

/// Create a new thread
pub fn pal_thread_create<F>(f: F) -> Result<PalHandle>
where
    F: FnOnce() -> i32 + Send + 'static,
{
    let handle = std::thread::spawn(f);
    Ok(PalHandle::Thread(handle))
}

/// Exit current thread
pub fn pal_thread_exit(code: i32) -> ! {
    std::process::exit(code);
}

/// Get current thread ID
pub fn pal_thread_id() -> u64 {
    nix::unistd::gettid().as_raw() as u64
}

// ============================================================
// Process
// ============================================================

/// Exit process
pub fn pal_process_exit(code: i32) -> ! {
    std::process::exit(code);
}

/// Get process ID
pub fn pal_process_id() -> u64 {
    std::process::id() as u64
}

// ============================================================
// Synchronization
// ============================================================

/// Create an eventfd-based event
pub fn pal_event_create(initial_signaled: bool) -> Result<PalHandle> {
    let initval = if initial_signaled { 1u32 } else { 0u32 };
    let fd = nix::sys::eventfd::eventfd(initval, nix::sys::eventfd::EfdFlags::EFD_NONBLOCK)
        .map_err(|e| anyhow::anyhow!("PAL eventfd failed: {}", e))?;
    Ok(PalHandle::Event { fd })
}

// ============================================================
// Time
// ============================================================

/// Get system time in microseconds since epoch
pub fn pal_time_query() -> u64 {
    let ts = nix::time::clock_gettime(nix::time::ClockId::CLOCK_REALTIME).unwrap();
    (ts.tv_sec() as u64) * 1_000_000 + (ts.tv_nsec() as u64) / 1000
}

/// Get monotonic time in microseconds
pub fn pal_time_monotonic() -> u64 {
    let ts = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC).unwrap();
    (ts.tv_sec() as u64) * 1_000_000 + (ts.tv_nsec() as u64) / 1000
}

// ============================================================
// System Info
// ============================================================

/// Get CPU count
pub fn pal_cpu_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Get total memory
pub fn pal_memory_total() -> u64 {
    let info = nix::sys::sysinfo::sysinfo().unwrap();
    info.ram_total()
}

// ============================================================
// Entropy
// ============================================================

/// Fill buffer with random bytes (maps to getrandom syscall via libc)
pub fn pal_random_read(buf: &mut [u8]) -> Result<()> {
    let ret =
        unsafe { libc::getrandom(buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    if ret < 0 {
        bail!("PAL getrandom failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

// ============================================================
// PAL Status Report
// ============================================================

/// Report PAL capabilities and host info
pub fn pal_report() -> PalReport {
    PalReport {
        host_os: "Linux".to_string(),
        kernel_version: get_kernel_version(),
        cpu_count: pal_cpu_count(),
        total_memory: pal_memory_total(),
        page_size: unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize },
        operations_implemented: vec![
            "PalVirtualMemoryAlloc (mmap)",
            "PalVirtualMemoryFree (munmap)",
            "PalVirtualMemoryProtect (mprotect)",
            "PalStreamOpen (open)",
            "PalStreamRead (read)",
            "PalStreamWrite (write)",
            "PalStreamClose (close)",
            "PalThreadCreate (pthread_create)",
            "PalThreadExit (exit)",
            "PalThreadId (gettid)",
            "PalProcessExit (exit_group)",
            "PalProcessId (getpid)",
            "PalEventCreate (eventfd)",
            "PalTimeQuery (clock_gettime REALTIME)",
            "PalTimeMonotonic (clock_gettime MONOTONIC)",
            "PalCpuCount (sysconf)",
            "PalMemoryTotal (sysinfo)",
            "PalRandomRead (getrandom)",
            "PalConsoleWrite (write fd=1)",
            "PalConsoleError (write fd=2)",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    }
}

#[derive(Debug, serde::Serialize)]
pub struct PalReport {
    pub host_os: String,
    pub kernel_version: String,
    pub cpu_count: usize,
    pub total_memory: u64,
    pub page_size: usize,
    pub operations_implemented: Vec<String>,
}

fn get_kernel_version() -> String {
    std::fs::read_to_string("/proc/version")
        .unwrap_or_else(|_| "unknown".to_string())
        .split_whitespace()
        .nth(2)
        .unwrap_or("unknown")
        .to_string()
}
