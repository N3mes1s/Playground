//! # Network Stack
//!
//! A minimal TCP/IP stack built from scratch for the unikernel.
//! Provides everything needed for HTTPS communication with LLM APIs:
//!
//! - Ethernet frame handling (virtio-net driver)
//! - ARP resolution
//! - IPv4 with basic routing
//! - TCP with connection management
//! - TLS 1.3 (simplified implementation)
//! - HTTP/1.1 client
//! - DNS resolver

pub mod tcp;
pub mod tls;
pub mod http;
pub mod dns;
pub mod virtio;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

static NET_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Network configuration.
#[derive(Debug, Clone)]
pub struct NetConfig {
    pub ip_addr: [u8; 4],
    pub gateway: [u8; 4],
    pub netmask: [u8; 4],
    pub dns_server: [u8; 4],
    pub mac_addr: [u8; 6],
}

impl Default for NetConfig {
    fn default() -> Self {
        NetConfig {
            ip_addr: [10, 0, 2, 15],       // QEMU default
            gateway: [10, 0, 2, 2],         // QEMU default
            netmask: [255, 255, 255, 0],
            dns_server: [8, 8, 8, 8],       // Google DNS
            mac_addr: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
        }
    }
}

static mut NET_CONFIG: Option<NetConfig> = None;

/// Initialize the network stack.
pub fn init() {
    unsafe {
        NET_CONFIG = Some(NetConfig::default());
    }

    // Initialize subsystems
    tcp::init();
    dns::init();

    // Probe PCI and initialize virtio-net device
    if virtio::init() {
        crate::kernel::console::puts("[net] virtio-net NIC active\n");
    } else {
        crate::kernel::console::puts("[net] WARNING: no NIC found, networking will not work\n");
    }

    NET_INITIALIZED.store(true, Ordering::SeqCst);
}

/// Get the network configuration.
pub fn config() -> &'static NetConfig {
    unsafe { NET_CONFIG.as_ref().expect("network not initialized") }
}

/// Check if the network stack is ready.
pub fn is_ready() -> bool {
    NET_INITIALIZED.load(Ordering::Relaxed)
}

/// Poll the network for incoming frames.
/// Should be called frequently from the main loop.
pub fn poll() {
    if NET_INITIALIZED.load(Ordering::Relaxed) {
        tcp::process_incoming();
    }
}

// ── Ethernet Frame ─────────────────────────────────────────────────────────

/// Ethernet frame types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Arp = 0x0806,
}

/// Minimal Ethernet frame.
pub struct EthFrame {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
    pub payload: Vec<u8>,
}

impl EthFrame {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(14 + self.payload.len());
        buf.extend_from_slice(&self.dst_mac);
        buf.extend_from_slice(&self.src_mac);
        buf.push((self.ether_type >> 8) as u8);
        buf.push(self.ether_type as u8);
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 14 {
            return None;
        }
        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        dst_mac.copy_from_slice(&data[0..6]);
        src_mac.copy_from_slice(&data[6..12]);
        let ether_type = ((data[12] as u16) << 8) | (data[13] as u16);

        Some(EthFrame {
            dst_mac,
            src_mac,
            ether_type,
            payload: data[14..].to_vec(),
        })
    }
}

// ── IPv4 Packet ────────────────────────────────────────────────────────────

/// IPv4 protocol numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum IpProtocol {
    Tcp = 6,
    Udp = 17,
}

pub struct Ipv4Packet {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub protocol: u8,
    pub ttl: u8,
    pub payload: Vec<u8>,
}

impl Ipv4Packet {
    pub fn new(dst_ip: [u8; 4], protocol: u8, payload: Vec<u8>) -> Self {
        let cfg = config();
        Ipv4Packet {
            src_ip: cfg.ip_addr,
            dst_ip,
            protocol,
            ttl: 64,
            payload,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let total_len = 20 + self.payload.len();
        let mut buf = Vec::with_capacity(total_len);

        // Version (4) + IHL (5) = 0x45
        buf.push(0x45);
        // DSCP + ECN
        buf.push(0x00);
        // Total length
        buf.push((total_len >> 8) as u8);
        buf.push(total_len as u8);
        // Identification
        buf.push(0x00);
        buf.push(0x00);
        // Flags + Fragment offset (Don't Fragment)
        buf.push(0x40);
        buf.push(0x00);
        // TTL
        buf.push(self.ttl);
        // Protocol
        buf.push(self.protocol);
        // Checksum (placeholder, filled below)
        buf.push(0x00);
        buf.push(0x00);
        // Source IP
        buf.extend_from_slice(&self.src_ip);
        // Destination IP
        buf.extend_from_slice(&self.dst_ip);

        // Calculate header checksum
        let checksum = ip_checksum(&buf[..20]);
        buf[10] = (checksum >> 8) as u8;
        buf[11] = checksum as u8;

        // Payload
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }
        let ihl = (data[0] & 0x0F) as usize * 4;
        if data.len() < ihl {
            return None;
        }

        let mut src_ip = [0u8; 4];
        let mut dst_ip = [0u8; 4];
        src_ip.copy_from_slice(&data[12..16]);
        dst_ip.copy_from_slice(&data[16..20]);

        Some(Ipv4Packet {
            src_ip,
            dst_ip,
            protocol: data[9],
            ttl: data[8],
            payload: data[ihl..].to_vec(),
        })
    }
}

/// Compute IPv4 header checksum.
fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i < data.len() - 1 {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}
