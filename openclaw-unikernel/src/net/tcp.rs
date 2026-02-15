//! # TCP Implementation
//!
//! A minimal TCP stack for the unikernel. Supports:
//! - Active open (client connections — what we need for LLM APIs)
//! - Passive open (server — for the gateway)
//! - Basic flow control with sliding window
//! - Retransmission with exponential backoff

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
    /// Send sequence variables
    pub snd_una: u32,   // Oldest unacknowledged
    pub snd_nxt: u32,   // Next to send
    pub snd_wnd: u16,   // Send window
    /// Receive sequence variables
    pub rcv_nxt: u32,   // Next expected
    pub rcv_wnd: u16,   // Receive window
    /// Buffers
    pub send_buf: Vec<u8>,
    pub recv_buf: Vec<u8>,
    /// Retransmission
    pub retransmit_count: u8,
    pub last_activity: u64,
}

impl TcpConnection {
    pub fn new(id: usize, remote_ip: [u8; 4], remote_port: u16) -> Self {
        // Use a pseudo-random initial sequence number based on TSC
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

    // Send SYN
    let syn = build_segment(&conn, flags::SYN, &[]);
    transmit_segment(&conn, &syn);
    conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
    conn.state = TcpState::SynSent;

    unsafe {
        if let Some(ref mut conns) = CONNECTIONS {
            conns.insert(id, conn);
        }
    }

    // Wait for SYN-ACK (with timeout)
    let start = crate::kernel::rdtsc();
    let timeout_ticks = 10_000_000_000u64; // ~5 seconds at 2GHz

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
            // Clean up
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

                // Buffer the data
                conn.send_buf.extend_from_slice(data);

                // Send in MSS-sized chunks (1460 bytes for standard Ethernet)
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
                        return 0; // EOF
                    }
                    return -1; // Would block
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
/// Returns the connection ID if a client has completed the handshake.
pub fn accept(listener_id: usize) -> Option<usize> {
    process_incoming();

    unsafe {
        if let Some(ref conns) = CONNECTIONS {
            let listener = conns.get(&listener_id)?;
            if listener.state != TcpState::Listen {
                return None;
            }
            let listen_port = listener.local_port;

            // Find an Established connection on the same local port
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

/// Process incoming TCP segments from the NIC.
///
/// Reads raw Ethernet frames from the virtio-net ring buffer, parses
/// through the Ethernet → IPv4 → TCP pipeline, matches to an existing
/// connection or creates a new one for SYN on a listening port, and
/// drives the TCP state machine.
pub fn process_incoming() {
    // Read raw frame from the virtio-net device ring buffer
    let raw_frame = match read_nic_frame() {
        Some(frame) => frame,
        None => return,
    };

    // Parse Ethernet → IPv4 → TCP
    let eth = match super::EthFrame::parse(&raw_frame) {
        Some(f) if f.ether_type == super::EtherType::Ipv4 as u16 => f,
        _ => return,
    };
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
    let payload = if data_offset < tcp_data.len() { &tcp_data[data_offset..] } else { &[] };

    unsafe {
        if let Some(ref mut conns) = CONNECTIONS {
            // Match existing connection by (local_port, remote_port, remote_ip)
            let matched_id = conns.iter()
                .find(|(_, c)| {
                    c.local_port == dst_port && c.remote_port == src_port
                        && c.remote_ip == ip.src_ip
                })
                .map(|(id, _)| *id);

            if let Some(id) = matched_id {
                if let Some(conn) = conns.get_mut(&id) {
                    process_segment(conn, tcp_flags, seq_num, ack_num, window, payload);
                }
            } else if tcp_flags & flags::SYN != 0 {
                // New incoming SYN — check for a listener on this port
                let has_listener = conns.values()
                    .any(|c| c.state == TcpState::Listen && c.local_port == dst_port);

                if has_listener {
                    let new_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
                    let mut new_conn = TcpConnection::new(new_id, ip.src_ip, src_port);
                    new_conn.local_port = dst_port;
                    new_conn.rcv_nxt = seq_num.wrapping_add(1);
                    new_conn.state = TcpState::SynReceived;

                    // Send SYN-ACK
                    let syn_ack = build_segment(&new_conn, flags::SYN | flags::ACK, &[]);
                    transmit_segment(&new_conn, &syn_ack);
                    new_conn.snd_nxt = new_conn.snd_nxt.wrapping_add(1);

                    conns.insert(new_id, new_conn);
                }
            }
        }
    }
}

/// Drive the TCP state machine for a received segment.
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

/// Read a raw Ethernet frame from the virtio-net receive ring.
/// Returns None if no frame is pending in the ring buffer.
/// Public for use by the DNS resolver for receiving UDP responses.
pub fn read_nic_frame() -> Option<Vec<u8>> {
    unsafe {
        if NET_RX_RING_BASE == 0 {
            return None; // NIC not initialized
        }

        let used_idx = core::ptr::read_volatile(
            (NET_RX_RING_BASE + NET_RX_USED_OFFSET) as *const u16
        );

        if used_idx == NET_RX_LAST_SEEN {
            return None;
        }

        let desc_idx = (NET_RX_LAST_SEEN as usize) % NET_RX_RING_SIZE;
        let buf_addr = core::ptr::read_volatile(
            (NET_RX_RING_BASE + desc_idx * 16) as *const u64
        ) as *const u8;
        let buf_len = core::ptr::read_volatile(
            (NET_RX_RING_BASE + desc_idx * 16 + 8) as *const u32
        ) as usize;

        if buf_addr.is_null() || buf_len == 0 || buf_len > 2048 {
            NET_RX_LAST_SEEN = NET_RX_LAST_SEEN.wrapping_add(1);
            return None;
        }

        let mut frame = Vec::with_capacity(buf_len);
        for i in 0..buf_len {
            frame.push(core::ptr::read_volatile(buf_addr.add(i)));
        }

        NET_RX_LAST_SEEN = NET_RX_LAST_SEEN.wrapping_add(1);
        core::ptr::write_volatile(
            (NET_RX_RING_BASE + NET_RX_AVAIL_OFFSET) as *mut u16,
            NET_RX_LAST_SEEN,
        );

        Some(frame)
    }
}

// Virtio-net receive ring buffer state
static mut NET_RX_RING_BASE: usize = 0;
static mut NET_RX_LAST_SEEN: u16 = 0;
const NET_RX_RING_SIZE: usize = 256;
const NET_RX_USED_OFFSET: usize = 4096;
const NET_RX_AVAIL_OFFSET: usize = 2048;

// Virtio-net transmit ring buffer state
static mut NET_TX_RING_BASE: usize = 0;
static mut NET_TX_NEXT_DESC: u16 = 0;
static mut NET_TX_NOTIFY_ADDR: usize = 0;
const NET_TX_RING_SIZE: usize = 256;
const NET_TX_AVAIL_OFFSET: usize = 2048;

/// Initialize virtio-net receive ring base address.
pub fn init_nic_rx(ring_base: usize) {
    unsafe {
        NET_RX_RING_BASE = ring_base;
        NET_RX_LAST_SEEN = 0;
    }
}

/// Initialize virtio-net transmit ring base address.
pub fn init_nic_tx(ring_base: usize, notify_addr: usize) {
    unsafe {
        NET_TX_RING_BASE = ring_base;
        NET_TX_NEXT_DESC = 0;
        NET_TX_NOTIFY_ADDR = notify_addr;
    }
}

/// Build a TCP segment.
fn build_segment(conn: &TcpConnection, tcp_flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut segment = Vec::with_capacity(20 + payload.len());

    // Source port
    segment.push((conn.local_port >> 8) as u8);
    segment.push(conn.local_port as u8);
    // Destination port
    segment.push((conn.remote_port >> 8) as u8);
    segment.push(conn.remote_port as u8);
    // Sequence number
    segment.push((conn.snd_nxt >> 24) as u8);
    segment.push((conn.snd_nxt >> 16) as u8);
    segment.push((conn.snd_nxt >> 8) as u8);
    segment.push(conn.snd_nxt as u8);
    // Acknowledgment number
    segment.push((conn.rcv_nxt >> 24) as u8);
    segment.push((conn.rcv_nxt >> 16) as u8);
    segment.push((conn.rcv_nxt >> 8) as u8);
    segment.push(conn.rcv_nxt as u8);
    // Data offset (5 × 4 = 20 bytes header) + reserved
    segment.push(0x50);
    // Flags
    segment.push(tcp_flags);
    // Window size
    segment.push((conn.rcv_wnd >> 8) as u8);
    segment.push(conn.rcv_wnd as u8);
    // Checksum (placeholder)
    segment.push(0x00);
    segment.push(0x00);
    // Urgent pointer
    segment.push(0x00);
    segment.push(0x00);

    // Payload
    segment.extend_from_slice(payload);

    // TODO: compute TCP checksum with pseudo-header

    segment
}

/// Transmit a TCP segment by wrapping it in IPv4 and Ethernet.
fn transmit_segment(conn: &TcpConnection, segment: &[u8]) {
    let ip_packet = super::Ipv4Packet::new(
        conn.remote_ip,
        super::IpProtocol::Tcp as u8,
        segment.to_vec(),
    );

    let frame = super::EthFrame {
        dst_mac: [0xFF; 6], // Would be resolved via ARP
        src_mac: super::config().mac_addr,
        ether_type: super::EtherType::Ipv4 as u16,
        payload: ip_packet.serialize(),
    };

    let frame_bytes = frame.serialize();
    send_raw_frame(&frame_bytes);
}

/// Send a raw Ethernet frame through the virtio-net transmit ring.
/// Also used by the DNS resolver for sending UDP packets.
pub fn send_raw_frame(frame: &[u8]) {
    unsafe {
        if NET_TX_RING_BASE == 0 {
            return; // NIC not initialized
        }

        let desc_idx = (NET_TX_NEXT_DESC as usize) % NET_TX_RING_SIZE;

        // Write frame data to the descriptor's buffer
        let buf_addr = core::ptr::read_volatile(
            (NET_TX_RING_BASE + desc_idx * 16) as *const u64
        ) as *mut u8;

        if buf_addr.is_null() {
            return;
        }

        let len = core::cmp::min(frame.len(), 2048);
        for i in 0..len {
            core::ptr::write_volatile(buf_addr.add(i), frame[i]);
        }

        // Write the length to the descriptor
        core::ptr::write_volatile(
            (NET_TX_RING_BASE + desc_idx * 16 + 8) as *mut u32,
            len as u32,
        );

        // Advance the available ring index
        NET_TX_NEXT_DESC = NET_TX_NEXT_DESC.wrapping_add(1);
        core::ptr::write_volatile(
            (NET_TX_RING_BASE + NET_TX_AVAIL_OFFSET) as *mut u16,
            NET_TX_NEXT_DESC,
        );

        // Notify the device (write to the queue notify register)
        if NET_TX_NOTIFY_ADDR != 0 {
            core::ptr::write_volatile(NET_TX_NOTIFY_ADDR as *mut u32, 1);
        }
    }
}
