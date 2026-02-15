//! # TCP Implementation
//!
//! A minimal TCP stack for the unikernel. Supports:
//! - Active open (client connections — what we need for LLM APIs)
//! - Passive open (server — for the gateway)
//! - ARP response (required for QEMU SLIRP networking)
//! - TCP checksum (pseudo-header based)

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

/// TCP connection states (RFC 793).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    TimeWait,
}

/// TCP flags.
pub mod flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
}

/// A TCP connection control block.
pub struct TcpConnection {
    pub id: usize,
    pub state: TcpState,
    pub local_port: u16,
    pub remote_port: u16,
    pub remote_ip: [u8; 4],
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub snd_wnd: u16,
    pub rcv_nxt: u32,
    pub rcv_wnd: u16,
    pub send_buf: Vec<u8>,
    pub recv_buf: Vec<u8>,
    pub retransmit_count: u8,
    pub last_activity: u64,
}

impl TcpConnection {
    pub fn new(id: usize, remote_ip: [u8; 4], remote_port: u16) -> Self {
        let isn = (crate::kernel::rdtsc() & 0xFFFFFFFF) as u32;
        TcpConnection {
            id,
            state: TcpState::Closed,
            local_port: allocate_ephemeral_port(),
            remote_port,
            remote_ip,
            snd_una: isn,
            snd_nxt: isn,
            snd_wnd: 65535,
            rcv_nxt: 0,
            rcv_wnd: 65535,
            send_buf: Vec::new(),
            recv_buf: Vec::new(),
            retransmit_count: 0,
            last_activity: crate::kernel::rdtsc(),
        }
    }
}

static NEXT_CONN_ID: AtomicUsize = AtomicUsize::new(1);
static NEXT_PORT: AtomicUsize = AtomicUsize::new(49152);

static mut CONNECTIONS: Option<BTreeMap<usize, TcpConnection>> = None;

fn allocate_ephemeral_port() -> u16 {
    let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
    if port > 65535 {
        NEXT_PORT.store(49152, Ordering::Relaxed);
    }
    port as u16
}

/// Initialize the TCP subsystem.
pub fn init() {
    unsafe {
        CONNECTIONS = Some(BTreeMap::new());
    }
}

/// Open a new TCP connection (active open).
pub fn connect(remote_ip: [u8; 4], remote_port: u16) -> Result<usize, &'static str> {
    let id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
    let mut conn = TcpConnection::new(id, remote_ip, remote_port);

    crate::kprintln!("[tcp] connect to {}.{}.{}.{}:{} (conn {})",
        remote_ip[0], remote_ip[1], remote_ip[2], remote_ip[3], remote_port, id);

    let syn = build_segment(&conn, flags::SYN, &[]);
    transmit_segment(&conn, &syn);
    conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
    conn.state = TcpState::SynSent;

    unsafe {
        if let Some(ref mut conns) = CONNECTIONS {
            conns.insert(id, conn);
        }
    }

    let start = crate::kernel::rdtsc();
    let timeout_ticks = 10_000_000_000u64;

    loop {
        crate::kernel::sched::yield_now();
        process_incoming();

        let state = unsafe {
            CONNECTIONS
                .as_ref()
                .and_then(|c| c.get(&id))
                .map(|c| c.state)
        };

        match state {
            Some(TcpState::Established) => return Ok(id),
            Some(TcpState::Closed) => return Err("connection refused"),
            _ => {}
        }

        if crate::kernel::rdtsc() - start > timeout_ticks {
            unsafe {
                if let Some(ref mut conns) = CONNECTIONS {
                    conns.remove(&id);
                }
            }
            return Err("connection timed out");
        }
    }
}

/// Listen on a port (passive open).
pub fn listen(port: u16) -> Result<usize, &'static str> {
    let id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
    let mut conn = TcpConnection::new(id, [0; 4], 0);
    conn.local_port = port;
    conn.state = TcpState::Listen;

    unsafe {
        if let Some(ref mut conns) = CONNECTIONS {
            conns.insert(id, conn);
        }
    }

    Ok(id)
}

/// Send data on a connection.
pub fn send(conn_id: usize, data: &[u8]) -> isize {
    unsafe {
        if let Some(ref mut conns) = CONNECTIONS {
            if let Some(conn) = conns.get_mut(&conn_id) {
                if conn.state != TcpState::Established {
                    return -1;
                }

                conn.send_buf.extend_from_slice(data);

                let mss = 1460;
                while !conn.send_buf.is_empty() {
                    let end = core::cmp::min(conn.send_buf.len(), mss);
                    let chunk: Vec<u8> = conn.send_buf.drain(..end).collect();
                    let segment = build_segment(conn, flags::PSH | flags::ACK, &chunk);
                    transmit_segment(conn, &segment);
                    conn.snd_nxt = conn.snd_nxt.wrapping_add(chunk.len() as u32);
                }

                return data.len() as isize;
            }
        }
    }
    -1
}

/// Receive data from a connection.
pub fn recv(conn_id: usize, buf: &mut [u8]) -> isize {
    unsafe {
        if let Some(ref mut conns) = CONNECTIONS {
            if let Some(conn) = conns.get_mut(&conn_id) {
                if conn.recv_buf.is_empty() {
                    if conn.state != TcpState::Established {
                        return 0;
                    }
                    return -1;
                }

                let len = core::cmp::min(buf.len(), conn.recv_buf.len());
                buf[..len].copy_from_slice(&conn.recv_buf[..len]);
                conn.recv_buf.drain(..len);
                return len as isize;
            }
        }
    }
    -1
}

/// Close a TCP connection.
pub fn close(conn_id: usize) {
    unsafe {
        if let Some(ref mut conns) = CONNECTIONS {
            if let Some(conn) = conns.get_mut(&conn_id) {
                if conn.state == TcpState::Established {
                    let fin = build_segment(conn, flags::FIN | flags::ACK, &[]);
                    transmit_segment(conn, &fin);
                    conn.state = TcpState::FinWait1;
                }
            }
        }
    }
}

/// Accept a pending connection on a listening socket.
pub fn accept(listener_id: usize) -> Option<usize> {
    process_incoming();

    unsafe {
        if let Some(ref conns) = CONNECTIONS {
            let listener = conns.get(&listener_id)?;
            if listener.state != TcpState::Listen {
                return None;
            }
            let listen_port = listener.local_port;

            for (id, conn) in conns.iter() {
                if *id != listener_id
                    && conn.local_port == listen_port
                    && conn.state == TcpState::Established
                {
                    return Some(*id);
                }
            }
        }
    }
    None
}

// ── Virtio-net NIC state ────────────────────────────────────────────────

const VIRTIO_NET_HDR_SIZE: usize = 10;
const BUF_SIZE: usize = 2048;
const QUEUE_SIZE: usize = 256;
const AVAIL_OFFSET: usize = QUEUE_SIZE * 16;
const USED_OFFSET: usize = 8192;

// RX state
static mut RX_QUEUE_BASE: usize = 0;
static mut RX_BUFS_BASE: usize = 0;
static mut RX_QUEUE_SIZE: usize = 0;
static mut RX_LAST_USED: u16 = 0;

// TX state
static mut TX_QUEUE_BASE: usize = 0;
static mut TX_BUFS_BASE: usize = 0;
static mut TX_QUEUE_SIZE: usize = 0;
static mut TX_AVAIL_IDX: u16 = 0;
static mut TX_IO_BASE: u16 = 0;

// Learned gateway MAC (from ARP replies)
pub static mut GATEWAY_MAC: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
pub static mut GATEWAY_MAC_LEARNED: bool = false;

// Debug counter

/// Called by virtio.rs after queue setup.
pub fn init_nic_rx_virtio(queue_base: usize, bufs_base: usize, size: usize) {
    unsafe {
        RX_QUEUE_BASE = queue_base;
        RX_BUFS_BASE = bufs_base;
        RX_QUEUE_SIZE = size;
        RX_LAST_USED = 0;
    }
}

pub fn init_nic_tx_virtio(queue_base: usize, bufs_base: usize, size: usize, io_base: u16) {
    unsafe {
        TX_QUEUE_BASE = queue_base;
        TX_BUFS_BASE = bufs_base;
        TX_QUEUE_SIZE = size;
        TX_AVAIL_IDX = 0;
        TX_IO_BASE = io_base;
    }
}

// Keep old stubs for backward compat
pub fn init_nic_rx(_: usize) {}
pub fn init_nic_tx(_: usize, _: usize) {}

/// Read a raw Ethernet frame from the virtio-net RX queue.
pub fn read_nic_frame() -> Option<Vec<u8>> {
    unsafe {
        if RX_QUEUE_BASE == 0 {
            return None;
        }

        // Read and clear ISR to acknowledge any pending notifications
        let _isr = super::virtio::read_isr();

        let used_idx = core::ptr::read_volatile(
            (RX_QUEUE_BASE + USED_OFFSET + 2) as *const u16,
        );

        if used_idx == RX_LAST_USED {
            return None;
        }

        let used_entry = RX_QUEUE_BASE + USED_OFFSET + 4
            + ((RX_LAST_USED as usize) % RX_QUEUE_SIZE) * 8;
        let desc_id = core::ptr::read_volatile(used_entry as *const u32) as usize;
        let total_len = core::ptr::read_volatile((used_entry + 4) as *const u32) as usize;

        if desc_id >= RX_QUEUE_SIZE || total_len <= VIRTIO_NET_HDR_SIZE || total_len > BUF_SIZE {
            RX_LAST_USED = RX_LAST_USED.wrapping_add(1);
            re_enqueue_rx(desc_id);
            return None;
        }

        let buf_addr = RX_BUFS_BASE + desc_id * BUF_SIZE;
        let frame_len = total_len - VIRTIO_NET_HDR_SIZE;
        let frame_start = buf_addr + VIRTIO_NET_HDR_SIZE;

        let mut frame = Vec::with_capacity(frame_len);
        for i in 0..frame_len {
            frame.push(core::ptr::read_volatile((frame_start + i) as *const u8));
        }

        RX_LAST_USED = RX_LAST_USED.wrapping_add(1);
        re_enqueue_rx(desc_id);

        Some(frame)
    }
}

unsafe fn re_enqueue_rx(desc_id: usize) {
    let avail_idx = core::ptr::read_volatile(
        (RX_QUEUE_BASE + AVAIL_OFFSET + 2) as *const u16,
    );
    let ring_slot = (avail_idx as usize) % RX_QUEUE_SIZE;
    core::ptr::write_volatile(
        (RX_QUEUE_BASE + AVAIL_OFFSET + 4 + ring_slot * 2) as *mut u16,
        desc_id as u16,
    );
    core::ptr::write_volatile(
        (RX_QUEUE_BASE + AVAIL_OFFSET + 2) as *mut u16,
        avail_idx.wrapping_add(1),
    );
    // Notify device (queue 0 = receiveq)
    if TX_IO_BASE != 0 {
        core::arch::asm!(
            "out dx, ax",
            in("dx") TX_IO_BASE + 0x10u16,
            in("ax") 0u16,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Send a raw Ethernet frame via the virtio-net TX queue.
pub fn send_raw_frame(frame: &[u8]) {
    unsafe {
        if TX_QUEUE_BASE == 0 || frame.is_empty() {
            return;
        }

        let desc_idx = (TX_AVAIL_IDX as usize) % TX_QUEUE_SIZE;
        let buf_addr = TX_BUFS_BASE + desc_idx * BUF_SIZE;
        let total_len = VIRTIO_NET_HDR_SIZE + frame.len();

        if total_len > BUF_SIZE {
            return;
        }

        // Virtio-net header (10 bytes of zeros)
        for i in 0..VIRTIO_NET_HDR_SIZE {
            core::ptr::write_volatile((buf_addr + i) as *mut u8, 0);
        }
        // Ethernet frame data
        for i in 0..frame.len() {
            core::ptr::write_volatile(
                (buf_addr + VIRTIO_NET_HDR_SIZE + i) as *mut u8,
                frame[i],
            );
        }

        // Update descriptor length
        let desc_addr = TX_QUEUE_BASE + desc_idx * 16;
        core::ptr::write_volatile((desc_addr + 8) as *mut u32, total_len as u32);
        core::ptr::write_volatile((desc_addr + 12) as *mut u16, 0); // flags = read
        core::ptr::write_volatile((desc_addr + 14) as *mut u16, 0); // no chain

        // Add to available ring
        let avail_idx = TX_AVAIL_IDX;
        let ring_slot = (avail_idx as usize) % TX_QUEUE_SIZE;
        core::ptr::write_volatile(
            (TX_QUEUE_BASE + AVAIL_OFFSET + 4 + ring_slot * 2) as *mut u16,
            desc_idx as u16,
        );
        TX_AVAIL_IDX = avail_idx.wrapping_add(1);
        core::ptr::write_volatile(
            (TX_QUEUE_BASE + AVAIL_OFFSET + 2) as *mut u16,
            TX_AVAIL_IDX,
        );

        // Notify device (queue 1 = transmitq)
        if TX_IO_BASE != 0 {
            core::arch::asm!(
                "out dx, ax",
                in("dx") TX_IO_BASE + 0x10u16,
                in("ax") 1u16,
                options(nomem, nostack, preserves_flags)
            );
        }
    }
}

// ── Packet Processing ───────────────────────────────────────────────────

/// Process incoming network frames: ARP + TCP.
/// Drains all available frames from the RX queue.
pub fn process_incoming() {
    // Process up to 32 frames per call to avoid starving the caller
    for _ in 0..32 {
        let raw_frame = match read_nic_frame() {
            Some(frame) => frame,
            None => return,
        };

        let eth = match super::EthFrame::parse(&raw_frame) {
            Some(f) => f,
            None => continue,
        };

        match eth.ether_type {
            0x0806 => handle_arp(&eth.payload),
            0x0800 => handle_ipv4(&eth),
            _ => {}
        }
    }
}

fn handle_arp(data: &[u8]) {
    if data.len() < 28 {
        return;
    }

    let operation = ((data[6] as u16) << 8) | data[7] as u16;
    let sender_ip = [data[14], data[15], data[16], data[17]];
    let gw_ip = super::config().gateway;

    // Learn gateway MAC from any ARP packet from the gateway IP
    if sender_ip == gw_ip {
        unsafe {
            GATEWAY_MAC.copy_from_slice(&data[8..14]);
            if !GATEWAY_MAC_LEARNED {
                GATEWAY_MAC_LEARNED = true;
                crate::kprintln!("[net] learned gateway MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    GATEWAY_MAC[0], GATEWAY_MAC[1], GATEWAY_MAC[2],
                    GATEWAY_MAC[3], GATEWAY_MAC[4], GATEWAY_MAC[5]);
            }
        }
    }

    if operation == 1 {
        // ARP Request - respond if it's for our IP
        let target_ip = [data[24], data[25], data[26], data[27]];
        let our_ip = super::config().ip_addr;
        if target_ip != our_ip {
            return;
        }

        crate::kprintln!("[net] ARP request for our IP, sending reply");

        let cfg = super::config();
        let mut reply = Vec::with_capacity(28);
        reply.extend_from_slice(&[0x00, 0x01]); // HW type: Ethernet
        reply.extend_from_slice(&[0x08, 0x00]); // Proto: IPv4
        reply.extend_from_slice(&[6, 4]);       // HW/Proto sizes
        reply.extend_from_slice(&[0x00, 0x02]); // Op: Reply
        reply.extend_from_slice(&cfg.mac_addr);
        reply.extend_from_slice(&cfg.ip_addr);
        reply.extend_from_slice(&data[8..14]);  // Target MAC (sender of request)
        reply.extend_from_slice(&data[14..18]); // Target IP (sender of request)

        let mut dst_mac = [0u8; 6];
        dst_mac.copy_from_slice(&data[8..14]);

        let frame = super::EthFrame {
            dst_mac,
            src_mac: cfg.mac_addr,
            ether_type: 0x0806,
            payload: reply,
        };

        send_raw_frame(&frame.serialize());
    } else if operation == 2 {
        // ARP Reply - we already learned the MAC above
        crate::kprintln!("[net] ARP reply from {}.{}.{}.{}",
            sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]);
    }
}

fn handle_ipv4(eth: &super::EthFrame) {
    let ip = match super::Ipv4Packet::parse(&eth.payload) {
        Some(p) if p.protocol == super::IpProtocol::Tcp as u8 => p,
        _ => return,
    };

    let tcp_data = &ip.payload;
    if tcp_data.len() < 20 {
        return;
    }

    let src_port = ((tcp_data[0] as u16) << 8) | (tcp_data[1] as u16);
    let dst_port = ((tcp_data[2] as u16) << 8) | (tcp_data[3] as u16);
    let seq_num = u32::from_be_bytes([tcp_data[4], tcp_data[5], tcp_data[6], tcp_data[7]]);
    let ack_num = u32::from_be_bytes([tcp_data[8], tcp_data[9], tcp_data[10], tcp_data[11]]);
    let data_offset = ((tcp_data[12] >> 4) as usize) * 4;
    let tcp_flags = tcp_data[13];
    let window = ((tcp_data[14] as u16) << 8) | (tcp_data[15] as u16);
    let payload = if data_offset < tcp_data.len() {
        &tcp_data[data_offset..]
    } else {
        &[]
    };

    unsafe {
        if let Some(ref mut conns) = CONNECTIONS {
            let matched_id = conns
                .iter()
                .find(|(_, c)| {
                    c.local_port == dst_port
                        && c.remote_port == src_port
                        && c.remote_ip == ip.src_ip
                })
                .map(|(id, _)| *id);

            if let Some(id) = matched_id {
                if let Some(conn) = conns.get_mut(&id) {
                    process_segment(conn, tcp_flags, seq_num, ack_num, window, payload);
                }
            } else if tcp_flags & flags::SYN != 0 {
                let has_listener = conns
                    .values()
                    .any(|c| c.state == TcpState::Listen && c.local_port == dst_port);

                if has_listener {
                    let new_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
                    let mut new_conn = TcpConnection::new(new_id, ip.src_ip, src_port);
                    new_conn.local_port = dst_port;
                    new_conn.rcv_nxt = seq_num.wrapping_add(1);
                    new_conn.state = TcpState::SynReceived;

                    let syn_ack = build_segment(&new_conn, flags::SYN | flags::ACK, &[]);
                    transmit_segment(&new_conn, &syn_ack);
                    new_conn.snd_nxt = new_conn.snd_nxt.wrapping_add(1);

                    conns.insert(new_id, new_conn);
                }
            }
        }
    }
}

fn process_segment(
    conn: &mut TcpConnection,
    tcp_flags: u8,
    seq_num: u32,
    ack_num: u32,
    window: u16,
    payload: &[u8],
) {
    conn.last_activity = crate::kernel::rdtsc();

    match conn.state {
        TcpState::SynSent => {
            if tcp_flags & flags::SYN != 0 && tcp_flags & flags::ACK != 0 {
                conn.rcv_nxt = seq_num.wrapping_add(1);
                conn.snd_una = ack_num;
                conn.snd_wnd = window;
                conn.state = TcpState::Established;
                let ack = build_segment(conn, flags::ACK, &[]);
                transmit_segment(conn, &ack);
            } else if tcp_flags & flags::RST != 0 {
                conn.state = TcpState::Closed;
            }
        }
        TcpState::SynReceived => {
            if tcp_flags & flags::ACK != 0 {
                conn.snd_una = ack_num;
                conn.snd_wnd = window;
                conn.state = TcpState::Established;
            }
        }
        TcpState::Established => {
            if tcp_flags & flags::RST != 0 {
                conn.state = TcpState::Closed;
                return;
            }
            conn.snd_una = ack_num;
            conn.snd_wnd = window;

            if !payload.is_empty() {
                conn.recv_buf.extend_from_slice(payload);
                conn.rcv_nxt = seq_num.wrapping_add(payload.len() as u32);
                let ack = build_segment(conn, flags::ACK, &[]);
                transmit_segment(conn, &ack);
            }
            if tcp_flags & flags::FIN != 0 {
                conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
                conn.state = TcpState::CloseWait;
                let ack = build_segment(conn, flags::ACK, &[]);
                transmit_segment(conn, &ack);
            }
        }
        TcpState::FinWait1 => {
            if tcp_flags & flags::ACK != 0 && tcp_flags & flags::FIN != 0 {
                conn.rcv_nxt = seq_num.wrapping_add(1);
                let ack = build_segment(conn, flags::ACK, &[]);
                transmit_segment(conn, &ack);
                conn.state = TcpState::TimeWait;
            } else if tcp_flags & flags::ACK != 0 {
                conn.state = TcpState::FinWait2;
            } else if tcp_flags & flags::FIN != 0 {
                conn.rcv_nxt = seq_num.wrapping_add(1);
                let ack = build_segment(conn, flags::ACK, &[]);
                transmit_segment(conn, &ack);
                conn.state = TcpState::TimeWait;
            }
        }
        TcpState::FinWait2 => {
            if tcp_flags & flags::FIN != 0 {
                conn.rcv_nxt = seq_num.wrapping_add(1);
                let ack = build_segment(conn, flags::ACK, &[]);
                transmit_segment(conn, &ack);
                conn.state = TcpState::TimeWait;
            }
        }
        TcpState::LastAck => {
            if tcp_flags & flags::ACK != 0 {
                conn.state = TcpState::Closed;
            }
        }
        _ => {}
    }
}

// ── Segment building and transmission ───────────────────────────────────

fn build_segment(conn: &TcpConnection, tcp_flags: u8, payload: &[u8]) -> Vec<u8> {
    let cfg = super::config();
    let mut segment = Vec::with_capacity(20 + payload.len());

    segment.push((conn.local_port >> 8) as u8);
    segment.push(conn.local_port as u8);
    segment.push((conn.remote_port >> 8) as u8);
    segment.push(conn.remote_port as u8);
    segment.push((conn.snd_nxt >> 24) as u8);
    segment.push((conn.snd_nxt >> 16) as u8);
    segment.push((conn.snd_nxt >> 8) as u8);
    segment.push(conn.snd_nxt as u8);
    segment.push((conn.rcv_nxt >> 24) as u8);
    segment.push((conn.rcv_nxt >> 16) as u8);
    segment.push((conn.rcv_nxt >> 8) as u8);
    segment.push(conn.rcv_nxt as u8);
    segment.push(0x50); // data offset = 5 words
    segment.push(tcp_flags);
    segment.push((conn.rcv_wnd >> 8) as u8);
    segment.push(conn.rcv_wnd as u8);
    segment.push(0x00); // checksum placeholder
    segment.push(0x00);
    segment.push(0x00); // urgent pointer
    segment.push(0x00);
    segment.extend_from_slice(payload);

    // Compute TCP checksum with pseudo-header
    let tcp_len = segment.len() as u16;
    let checksum = tcp_checksum(&cfg.ip_addr, &conn.remote_ip, &segment, tcp_len);
    segment[16] = (checksum >> 8) as u8;
    segment[17] = checksum as u8;

    segment
}

fn tcp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], segment: &[u8], tcp_len: u16) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header
    sum += ((src_ip[0] as u32) << 8) | (src_ip[1] as u32);
    sum += ((src_ip[2] as u32) << 8) | (src_ip[3] as u32);
    sum += ((dst_ip[0] as u32) << 8) | (dst_ip[1] as u32);
    sum += ((dst_ip[2] as u32) << 8) | (dst_ip[3] as u32);
    sum += 6u32; // Protocol = TCP
    sum += tcp_len as u32;

    // TCP header + data
    let mut i = 0;
    while i + 1 < segment.len() {
        sum += ((segment[i] as u32) << 8) | (segment[i + 1] as u32);
        i += 2;
    }
    if i < segment.len() {
        sum += (segment[i] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

fn transmit_segment(conn: &TcpConnection, segment: &[u8]) {
    let cfg = super::config();

    let ip_packet = super::Ipv4Packet::new(
        conn.remote_ip,
        super::IpProtocol::Tcp as u8,
        segment.to_vec(),
    );

    // Use learned gateway MAC, or broadcast if not yet learned
    let dst_mac = unsafe {
        if GATEWAY_MAC_LEARNED {
            GATEWAY_MAC
        } else {
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        }
    };

    let frame = super::EthFrame {
        dst_mac,
        src_mac: cfg.mac_addr,
        ether_type: super::EtherType::Ipv4 as u16,
        payload: ip_packet.serialize(),
    };

    send_raw_frame(&frame.serialize());
}
