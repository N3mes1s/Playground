//! # DNS Resolver
//!
//! Minimal DNS client for resolving hostnames to IP addresses.
//! Sends raw UDP packets via the NIC for DNS queries, with a
//! built-in cache for common LLM API hosts as fallback.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// DNS cache — maps hostnames to IPv4 addresses.
static mut DNS_CACHE: Option<BTreeMap<String, [u8; 4]>> = None;

/// Initialize the DNS resolver with well-known LLM API hosts.
pub fn init() {
    unsafe {
        let mut cache = BTreeMap::new();

        // Pre-seed with common LLM API endpoints
        // These are fallback IPs; real resolution happens via UDP queries
        cache.insert(String::from("api.openai.com"), [104, 18, 7, 192]);
        cache.insert(String::from("api.anthropic.com"), [104, 18, 37, 228]);
        cache.insert(String::from("openrouter.ai"), [104, 18, 28, 140]);
        cache.insert(String::from("api.groq.com"), [104, 18, 3, 47]);
        cache.insert(String::from("generativelanguage.googleapis.com"), [142, 250, 80, 42]);
        cache.insert(String::from("api.mistral.ai"), [104, 18, 6, 171]);
        cache.insert(String::from("api.together.xyz"), [76, 76, 21, 21]);
        cache.insert(String::from("api.fireworks.ai"), [104, 18, 12, 88]);
        cache.insert(String::from("api.deepseek.com"), [47, 236, 18, 163]);
        cache.insert(String::from("api.cohere.ai"), [104, 18, 32, 7]);
        cache.insert(String::from("api.x.ai"), [104, 18, 14, 35]);
        cache.insert(String::from("api.perplexity.ai"), [104, 18, 33, 45]);

        // Discord/Telegram/Slack API endpoints
        cache.insert(String::from("discord.com"), [162, 159, 135, 232]);
        cache.insert(String::from("api.telegram.org"), [149, 154, 167, 220]);
        cache.insert(String::from("slack.com"), [34, 226, 36, 144]);

        // WhatsApp / Facebook / GitHub
        cache.insert(String::from("graph.facebook.com"), [157, 240, 1, 35]);
        cache.insert(String::from("api.github.com"), [140, 82, 121, 4]);
        cache.insert(String::from("raw.githubusercontent.com"), [185, 199, 108, 133]);

        // Matrix / Email
        cache.insert(String::from("matrix.org"), [104, 18, 37, 53]);

        DNS_CACHE = Some(cache);
    }
}

/// Resolve a hostname to an IPv4 address.
pub fn resolve(hostname: &str) -> Result<[u8; 4], &'static str> {
    // Check cache first
    unsafe {
        if let Some(ref cache) = DNS_CACHE {
            if let Some(ip) = cache.get(hostname) {
                return Ok(*ip);
            }
        }
    }

    // Check if hostname is already an IP address
    if let Some(ip) = parse_ip(hostname) {
        return Ok(ip);
    }

    // Perform DNS query via UDP
    match dns_query(hostname) {
        Ok(ip) => {
            // Cache the result for future lookups
            cache_insert(hostname, ip);
            Ok(ip)
        }
        Err(e) => Err(e),
    }
}

/// Cache a DNS resolution result.
pub fn cache_insert(hostname: &str, ip: [u8; 4]) {
    unsafe {
        if let Some(ref mut cache) = DNS_CACHE {
            cache.insert(String::from(hostname), ip);
        }
    }
}

/// Parse a dotted-decimal IPv4 address.
fn parse_ip(s: &str) -> Option<[u8; 4]> {
    let mut parts = s.split('.');
    let mut ip = [0u8; 4];
    for octet in ip.iter_mut() {
        let part = parts.next()?;
        *octet = parse_u8(part)?;
    }
    if parts.next().is_some() {
        return None; // Too many octets
    }
    Some(ip)
}

fn parse_u8(s: &str) -> Option<u8> {
    let mut result: u16 = 0;
    if s.is_empty() {
        return None;
    }
    for c in s.chars() {
        if !c.is_ascii_digit() {
            return None;
        }
        result = result * 10 + (c as u16 - b'0' as u16);
        if result > 255 {
            return None;
        }
    }
    Some(result as u8)
}

/// Perform a DNS query over UDP by constructing a raw Ethernet→IPv4→UDP packet.
fn dns_query(hostname: &str) -> Result<[u8; 4], &'static str> {
    let net_cfg = crate::net::config();
    let dns_server = net_cfg.dns_server;

    // Build DNS query payload
    let dns_payload = build_dns_query(hostname);
    let txid = ((dns_payload[0] as u16) << 8) | (dns_payload[1] as u16);

    // Build UDP header (8 bytes) + DNS payload
    let src_port: u16 = 49152 + (crate::kernel::rdtsc() as u16 % 16384);
    let dst_port: u16 = 53;
    let udp_len = (8 + dns_payload.len()) as u16;
    let mut udp_packet = Vec::with_capacity(udp_len as usize);
    udp_packet.push((src_port >> 8) as u8);
    udp_packet.push(src_port as u8);
    udp_packet.push((dst_port >> 8) as u8);
    udp_packet.push(dst_port as u8);
    udp_packet.push((udp_len >> 8) as u8);
    udp_packet.push(udp_len as u8);
    udp_packet.push(0x00); udp_packet.push(0x00); // Checksum (0 = disabled for UDP over IPv4)
    udp_packet.extend_from_slice(&dns_payload);

    // Build IPv4 packet (protocol = UDP = 17)
    let ip_packet = super::Ipv4Packet::new(dns_server, super::IpProtocol::Udp as u8, udp_packet);
    let ip_bytes = ip_packet.serialize();

    // Build Ethernet frame (destination = gateway MAC for routed traffic)
    // Use the learned gateway MAC, fall back to broadcast
    let dst_mac = unsafe {
        if super::tcp::GATEWAY_MAC_LEARNED {
            super::tcp::GATEWAY_MAC
        } else {
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        }
    };
    let frame = super::EthFrame {
        dst_mac,
        src_mac: net_cfg.mac_addr,
        ether_type: super::EtherType::Ipv4 as u16,
        payload: ip_bytes,
    };

    // Send the raw frame via the NIC
    let frame_bytes = frame.serialize();
    super::tcp::send_raw_frame(&frame_bytes);

    // Wait for DNS response with timeout
    let timeout_ticks = 4_000_000_000u64; // ~2 seconds at 2 GHz
    let start = crate::kernel::rdtsc();

    while crate::kernel::rdtsc().saturating_sub(start) < timeout_ticks {
        // Try to read a response frame from the NIC
        if let Some(resp_frame) = super::tcp::read_nic_frame() {
            // Parse Ethernet → IPv4 → UDP → DNS
            if let Some(eth) = super::EthFrame::parse(&resp_frame) {
                if eth.ether_type != super::EtherType::Ipv4 as u16 {
                    continue;
                }
                if let Some(ip) = super::Ipv4Packet::parse(&eth.payload) {
                    if ip.protocol != super::IpProtocol::Udp as u8 {
                        continue;
                    }
                    if ip.src_ip != dns_server {
                        continue;
                    }
                    // Parse UDP header
                    if ip.payload.len() < 8 {
                        continue;
                    }
                    let resp_src_port = ((ip.payload[0] as u16) << 8) | (ip.payload[1] as u16);
                    if resp_src_port != 53 {
                        continue;
                    }
                    let dns_response = &ip.payload[8..];
                    if dns_response.len() < 12 {
                        continue;
                    }
                    // Verify transaction ID
                    let resp_txid = ((dns_response[0] as u16) << 8) | (dns_response[1] as u16);
                    if resp_txid != txid {
                        continue;
                    }
                    // Parse the DNS response for A records
                    return parse_dns_response(dns_response);
                }
            }
        }
        crate::kernel::sched::yield_now();
    }

    Err("DNS query timed out")
}

/// Build a DNS query packet for an A record.
fn build_dns_query(hostname: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(512);

    // Transaction ID
    let txid = (crate::kernel::rdtsc() & 0xFFFF) as u16;
    packet.push((txid >> 8) as u8);
    packet.push(txid as u8);

    // Flags: standard query, recursion desired
    packet.push(0x01); packet.push(0x00);

    // Questions: 1
    packet.push(0x00); packet.push(0x01);
    // Answer RRs: 0
    packet.push(0x00); packet.push(0x00);
    // Authority RRs: 0
    packet.push(0x00); packet.push(0x00);
    // Additional RRs: 0
    packet.push(0x00); packet.push(0x00);

    // Question: hostname as DNS name
    for label in hostname.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00); // Root label

    // Type: A (1)
    packet.push(0x00); packet.push(0x01);
    // Class: IN (1)
    packet.push(0x00); packet.push(0x01);

    packet
}

/// Parse a DNS response and extract the first A record.
fn parse_dns_response(data: &[u8]) -> Result<[u8; 4], &'static str> {
    if data.len() < 12 {
        return Err("DNS response too short");
    }

    // Check response flags
    let flags = ((data[2] as u16) << 8) | (data[3] as u16);
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err("DNS server returned error");
    }

    let answer_count = ((data[6] as u16) << 8) | (data[7] as u16);
    if answer_count == 0 {
        return Err("DNS response has no answers");
    }

    // Skip the question section
    let mut offset = 12;
    // Skip the query name
    offset = skip_dns_name(data, offset)?;
    offset += 4; // Skip QTYPE (2) + QCLASS (2)

    // Parse answer records
    for _ in 0..answer_count {
        if offset >= data.len() {
            break;
        }
        // Skip the name (may be compressed with pointer)
        offset = skip_dns_name(data, offset)?;

        if offset + 10 > data.len() {
            break;
        }

        let rtype = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
        let rdlength = ((data[offset + 8] as u16) << 8) | (data[offset + 9] as u16);
        offset += 10; // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)

        // A record (type 1) with 4-byte IPv4 address
        if rtype == 1 && rdlength == 4 && offset + 4 <= data.len() {
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&data[offset..offset + 4]);
            return Ok(ip);
        }

        offset += rdlength as usize;
    }

    Err("no A record found in DNS response")
}

/// Skip a DNS name (handles pointer compression).
fn skip_dns_name(data: &[u8], mut offset: usize) -> Result<usize, &'static str> {
    let mut jumps = 0;
    let max_jumps = 10;

    loop {
        if offset >= data.len() {
            return Err("DNS name extends past packet");
        }

        let len = data[offset] as usize;

        if len == 0 {
            offset += 1;
            break;
        }

        // Pointer compression: top 2 bits are 11
        if len & 0xC0 == 0xC0 {
            offset += 2; // Skip the 2-byte pointer
            break;
        }

        offset += 1 + len;
        jumps += 1;
        if jumps > max_jumps {
            return Err("DNS name too long");
        }
    }

    Ok(offset)
}
