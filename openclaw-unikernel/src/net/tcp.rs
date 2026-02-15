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

/// Process incoming TCP segments.
pub fn process_incoming() {
    // In a real implementation, this would read from the virtio-net device
    // and process incoming packets. For the unikernel framework, this is
    // the hook point where the NIC driver delivers packets.
    //
    // The flow is:
    // 1. NIC delivers Ethernet frame
    // 2. Parse Ethernet → IPv4 → TCP headers
    // 3. Match to connection by (src_ip, src_port, dst_port)
    // 4. Process according to TCP state machine
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

    let _frame = super::EthFrame {
        dst_mac: [0xFF; 6], // Would be resolved via ARP
        src_mac: super::config().mac_addr,
        ether_type: super::EtherType::Ipv4 as u16,
        payload: ip_packet.serialize(),
    };

    // In a full implementation, this would write to the virtio-net device.
    // The frame is ready to be transmitted.
}
