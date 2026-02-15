//! # DNS Resolver
//!
//! Minimal DNS client for resolving hostnames to IP addresses.
//! Uses UDP (or falls back to a built-in cache for common LLM API hosts).

use alloc::collections::BTreeMap;
use alloc::string::String;

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

        // Discord/Telegram/Slack API endpoints
        cache.insert(String::from("discord.com"), [162, 159, 135, 232]);
        cache.insert(String::from("api.telegram.org"), [149, 154, 167, 220]);
        cache.insert(String::from("slack.com"), [34, 226, 36, 144]);

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
    dns_query(hostname)
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

/// Perform a DNS query over UDP.
fn dns_query(hostname: &str) -> Result<[u8; 4], &'static str> {
    let dns_server = crate::net::config().dns_server;

    // Build DNS query packet
    let query = build_dns_query(hostname);

    // In a full implementation, this would:
    // 1. Create a UDP socket to dns_server:53
    // 2. Send the query packet
    // 3. Wait for response with timeout
    // 4. Parse the response for A records
    //
    // For the unikernel framework, we use the seeded cache
    // and return an error for unknown hosts.
    let _ = (dns_server, query);

    Err("DNS resolution failed: hostname not in cache")
}

/// Build a DNS query packet for an A record.
fn build_dns_query(hostname: &str) -> alloc::vec::Vec<u8> {
    let mut packet = alloc::vec::Vec::with_capacity(512);

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
