//! # Virtio-Net PCI Driver
//!
//! Probes the PCI bus for a virtio-net device, initializes it, and sets up
//! the RX/TX virtqueues using the legacy (0.9.5) register layout.

use core::arch::asm;

// ── PCI I/O ──────────────────────────────────────────────────────────────

unsafe fn outl(port: u16, val: u32) {
    asm!("out dx, eax", in("dx") port, in("eax") val, options(nomem, nostack, preserves_flags));
}
unsafe fn inl(port: u16) -> u32 {
    let v: u32;
    asm!("in eax, dx", in("dx") port, out("eax") v, options(nomem, nostack, preserves_flags));
    v
}
unsafe fn outw(port: u16, val: u16) {
    asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack, preserves_flags));
}
unsafe fn inw(port: u16) -> u16 {
    let v: u16;
    asm!("in ax, dx", in("dx") port, out("ax") v, options(nomem, nostack, preserves_flags));
    v
}
unsafe fn outb(port: u16, val: u8) {
    asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
}
unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags));
    v
}

fn pci_read32(bus: u8, dev: u8, func: u8, off: u8) -> u32 {
    let addr = 0x8000_0000u32
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((off as u32) & 0xFC);
    unsafe {
        outl(0xCF8, addr);
        inl(0xCFC)
    }
}

fn pci_write32(bus: u8, dev: u8, func: u8, off: u8, val: u32) {
    let addr = 0x8000_0000u32
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((off as u32) & 0xFC);
    unsafe {
        outl(0xCF8, addr);
        outl(0xCFC, val);
    }
}

// ── Virtio Legacy Register Offsets (from BAR0 I/O base) ─────────────────

const VIRTIO_DEV_FEATURES: u16 = 0x00;   // 32-bit read
const VIRTIO_GUEST_FEATURES: u16 = 0x04; // 32-bit write
const VIRTIO_QUEUE_PFN: u16 = 0x08;      // 32-bit write (page frame number)
const VIRTIO_QUEUE_SIZE: u16 = 0x0C;     // 16-bit read
const VIRTIO_QUEUE_SEL: u16 = 0x0E;      // 16-bit write
const VIRTIO_QUEUE_NOTIFY: u16 = 0x10;   // 16-bit write
const VIRTIO_DEV_STATUS: u16 = 0x12;     // 8-bit read/write
const VIRTIO_ISR: u16 = 0x13;            // 8-bit read
const VIRTIO_NET_MAC: u16 = 0x14;        // 6 bytes, device-specific

const STATUS_ACK: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FAILED: u8 = 128;

const VIRTQ_DESC_F_WRITE: u16 = 2;

const VIRTIO_NET_HDR_SIZE: usize = 10;
const BUF_SIZE: usize = 2048;

// ── Queue layout for 256-entry queue ─────────────────────────────────────
// Desc table:     256 * 16 = 4096
// Avail ring:     2 + 2 + 256*2 + 2 = 518
// Align to 4096 → 8192
// Used ring:      2 + 2 + 256*8 + 2 = 2054
// Align to 4096 → 4096
// Total per queue: 12288 = 3 pages

const QUEUE_SIZE: usize = 256;
const QUEUE_STRUCT_SIZE: usize = 12288;
const AVAIL_OFFSET: usize = QUEUE_SIZE * 16;   // 4096
const USED_OFFSET: usize = 8192;

extern "C" {
    static __net_buffer_start: u8;
}

/// Saved I/O base for queue notifications
static mut IO_BASE: u16 = 0;

/// Read and clear the ISR status register.
/// Returns the ISR value (bit 0 = used buffer notification, bit 1 = config change).
pub fn read_isr() -> u8 {
    unsafe {
        if IO_BASE == 0 {
            return 0;
        }
        inb(IO_BASE + VIRTIO_ISR)
    }
}

/// Initialize the virtio-net device.
/// Returns true if a device was found and initialized.
pub fn init() -> bool {
    // Scan PCI bus 0 for virtio-net (vendor 0x1AF4, device 0x1000 or 0x1041)
    let mut found = false;
    let mut bus = 0u8;
    let mut dev = 0u8;

    'scan: for d in 0..32u8 {
        let id = pci_read32(0, d, 0, 0x00);
        let vendor = (id & 0xFFFF) as u16;
        let device = ((id >> 16) & 0xFFFF) as u16;

        if vendor == 0x1AF4 && (device == 0x1000 || device == 0x1041) {
            bus = 0;
            dev = d;
            found = true;
            break 'scan;
        }
    }

    if !found {
        crate::kernel::console::puts("[virtio] no virtio-net device found\n");
        return false;
    }

    crate::kprintln!("[virtio] found virtio-net at PCI 0:{}.0", dev);

    // Read BAR0 (I/O port base)
    let bar0 = pci_read32(bus, dev, 0, 0x10);
    let io_base = (bar0 & 0xFFFC) as u16;
    crate::kprintln!("[virtio] I/O base: 0x{:04X}", io_base);

    // Enable PCI bus mastering
    let cmd = pci_read32(bus, dev, 0, 0x04);
    pci_write32(bus, dev, 0, 0x04, cmd | 0x04);

    unsafe { IO_BASE = io_base; }

    // ── Device initialization (legacy virtio 0.9.5) ──

    unsafe {
        // 1. Reset
        outb(io_base + VIRTIO_DEV_STATUS, 0);

        // 2. Acknowledge
        outb(io_base + VIRTIO_DEV_STATUS, STATUS_ACK);

        // 3. Driver
        outb(io_base + VIRTIO_DEV_STATUS, STATUS_ACK | STATUS_DRIVER);

        // 4. Read features, negotiate (accept none for simplicity)
        let _features = inl(io_base + VIRTIO_DEV_FEATURES);
        outl(io_base + VIRTIO_GUEST_FEATURES, 0);

        // Get net buffer base address
        let net_buf_base = &__net_buffer_start as *const u8 as usize;
        crate::kprintln!("[virtio] net buffer base: 0x{:08X}", net_buf_base);

        // ── Set up RX queue (queue 0) ──
        let rx_queue_base = net_buf_base;
        let rx_bufs_base = net_buf_base + QUEUE_STRUCT_SIZE * 2; // after both queue structs

        outw(io_base + VIRTIO_QUEUE_SEL, 0);
        let rx_size = inw(io_base + VIRTIO_QUEUE_SIZE) as usize;
        crate::kprintln!("[virtio] RX queue size: {}", rx_size);

        if rx_size == 0 || rx_size > QUEUE_SIZE {
            outb(io_base + VIRTIO_DEV_STATUS, STATUS_FAILED);
            return false;
        }

        // Zero the queue structure
        core::ptr::write_bytes(rx_queue_base as *mut u8, 0, QUEUE_STRUCT_SIZE);

        // Populate RX descriptors: each points to a 2K buffer, flagged WRITE
        let actual_rx_size = core::cmp::min(rx_size, QUEUE_SIZE);
        for i in 0..actual_rx_size {
            let desc_addr = rx_queue_base + i * 16;
            let buf_addr = rx_bufs_base + i * BUF_SIZE;
            // addr (u64)
            core::ptr::write_volatile(desc_addr as *mut u64, buf_addr as u64);
            // len (u32)
            core::ptr::write_volatile((desc_addr + 8) as *mut u32, BUF_SIZE as u32);
            // flags (u16) = WRITE (device writes to this buffer)
            core::ptr::write_volatile((desc_addr + 12) as *mut u16, VIRTQ_DESC_F_WRITE);
            // next (u16) = 0 (single descriptor, not chained)
            core::ptr::write_volatile((desc_addr + 14) as *mut u16, 0);

            // Add to available ring
            let avail_ring_entry = rx_queue_base + AVAIL_OFFSET + 4 + i * 2;
            core::ptr::write_volatile(avail_ring_entry as *mut u16, i as u16);
        }

        // Set available ring idx (all buffers available)
        core::ptr::write_volatile(
            (rx_queue_base + AVAIL_OFFSET) as *mut u16, 0  // flags
        );
        core::ptr::write_volatile(
            (rx_queue_base + AVAIL_OFFSET + 2) as *mut u16, actual_rx_size as u16  // idx
        );

        // Tell device the queue PFN
        outl(io_base + VIRTIO_QUEUE_PFN, (rx_queue_base >> 12) as u32);

        // ── Set up TX queue (queue 1) ──
        let tx_queue_base = net_buf_base + QUEUE_STRUCT_SIZE;
        let tx_bufs_base = rx_bufs_base + QUEUE_SIZE * BUF_SIZE;

        outw(io_base + VIRTIO_QUEUE_SEL, 1);
        let tx_size = inw(io_base + VIRTIO_QUEUE_SIZE) as usize;
        crate::kprintln!("[virtio] TX queue size: {}", tx_size);

        if tx_size == 0 || tx_size > QUEUE_SIZE {
            outb(io_base + VIRTIO_DEV_STATUS, STATUS_FAILED);
            return false;
        }

        // Zero the queue structure
        core::ptr::write_bytes(tx_queue_base as *mut u8, 0, QUEUE_STRUCT_SIZE);

        // TX descriptors: set up buffer addresses only (data filled on send)
        let actual_tx_size = core::cmp::min(tx_size, QUEUE_SIZE);
        for i in 0..actual_tx_size {
            let desc_addr = tx_queue_base + i * 16;
            let buf_addr = tx_bufs_base + i * BUF_SIZE;
            // addr (u64) — point to buffer
            core::ptr::write_volatile(desc_addr as *mut u64, buf_addr as u64);
            // len, flags, next will be set per-send
        }

        // Available ring starts empty
        core::ptr::write_volatile(
            (tx_queue_base + AVAIL_OFFSET) as *mut u16, 0  // flags
        );
        core::ptr::write_volatile(
            (tx_queue_base + AVAIL_OFFSET + 2) as *mut u16, 0  // idx = 0 (nothing available yet)
        );

        // Tell device the queue PFN
        outl(io_base + VIRTIO_QUEUE_PFN, (tx_queue_base >> 12) as u32);

        // ── Wire up the TCP module's NIC interface ──
        super::tcp::init_nic_rx_virtio(
            rx_queue_base,
            rx_bufs_base,
            actual_rx_size,
        );
        super::tcp::init_nic_tx_virtio(
            tx_queue_base,
            tx_bufs_base,
            actual_tx_size,
            io_base,
        );

        // 5. Driver OK — device is live
        outb(io_base + VIRTIO_DEV_STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK);

        // Read MAC address from device config
        let mut mac = [0u8; 6];
        for i in 0..6 {
            mac[i] = inb(io_base + VIRTIO_NET_MAC + i as u16);
        }
        crate::kprintln!(
            "[virtio] MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );

        // Update net config with actual MAC
        if let Some(ref mut cfg) = super::NET_CONFIG {
            cfg.mac_addr = mac;
        }
    }

    crate::kernel::console::puts("[virtio] device initialized, queues active\n");

    // Send a gratuitous ARP to announce our presence to SLIRP
    send_gratuitous_arp();

    true
}

/// Send a gratuitous ARP (ARP request for our own IP) to announce our MAC
/// to the QEMU SLIRP stack. Also send an ARP request for the gateway.
fn send_gratuitous_arp() {
    let cfg = super::config();
    let our_mac = cfg.mac_addr;
    let our_ip = cfg.ip_addr;
    let gw_ip = cfg.gateway;

    // ARP request: "Who has <gateway>? Tell <our IP>"
    let mut arp = alloc::vec::Vec::with_capacity(28);
    arp.extend_from_slice(&[0x00, 0x01]); // HW type: Ethernet
    arp.extend_from_slice(&[0x08, 0x00]); // Proto: IPv4
    arp.extend_from_slice(&[6, 4]);       // HW/Proto sizes
    arp.extend_from_slice(&[0x00, 0x01]); // Op: Request
    arp.extend_from_slice(&our_mac);       // Sender MAC
    arp.extend_from_slice(&our_ip);        // Sender IP
    arp.extend_from_slice(&[0x00; 6]);     // Target MAC (unknown)
    arp.extend_from_slice(&gw_ip);         // Target IP (gateway)

    let frame = super::EthFrame {
        dst_mac: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], // Broadcast
        src_mac: our_mac,
        ether_type: 0x0806,
        payload: arp,
    };

    super::tcp::send_raw_frame(&frame.serialize());
    crate::kprintln!("[virtio] sent ARP request for gateway {}.{}.{}.{}",
        gw_ip[0], gw_ip[1], gw_ip[2], gw_ip[3]);
}
