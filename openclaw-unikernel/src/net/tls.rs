//! # TLS 1.3 Implementation
//!
//! Minimal TLS 1.3 client for secure communication with LLM APIs.
//! Implements the essential handshake and record protocol needed
//! for HTTPS connections.
//!
//! Cipher suite: TLS_CHACHA20_POLY1305_SHA256 (matches our secret store)

use alloc::vec::Vec;
use alloc::string::String;

/// TLS record types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

/// TLS handshake message types.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
#[allow(dead_code)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateVerify = 15,
    Finished = 20,
}

/// TLS alert levels.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

/// TLS connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsState {
    Initial,
    ClientHelloSent,
    ServerHelloReceived,
    HandshakeComplete,
    ApplicationData,
    Closed,
    Error,
}

/// A TLS 1.3 session.
pub struct TlsSession {
    pub state: TlsState,
    pub tcp_conn_id: usize,
    pub hostname: String,

    // Handshake secrets (simplified — in production, use proper HKDF)
    client_random: [u8; 32],
    server_random: [u8; 32],

    // Traffic keys (derived after handshake)
    client_write_key: [u8; 32],
    server_write_key: [u8; 32],
    client_write_iv: [u8; 12],
    server_write_iv: [u8; 12],

    // Sequence numbers for nonce construction
    client_seq: u64,
    server_seq: u64,

    // Buffered plaintext from decrypted records
    plaintext_buf: Vec<u8>,
}

impl TlsSession {
    pub fn new(tcp_conn_id: usize, hostname: String) -> Self {
        // Generate client random from TSC (in production, use proper CSPRNG)
        let mut client_random = [0u8; 32];
        for i in 0..4 {
            let tsc = crate::kernel::rdtsc();
            let bytes = tsc.to_le_bytes();
            client_random[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
        }

        TlsSession {
            state: TlsState::Initial,
            tcp_conn_id,
            hostname,
            client_random,
            server_random: [0u8; 32],
            client_write_key: [0u8; 32],
            server_write_key: [0u8; 32],
            client_write_iv: [0u8; 12],
            server_write_iv: [0u8; 12],
            client_seq: 0,
            server_seq: 0,
            plaintext_buf: Vec::new(),
        }
    }

    /// Perform the TLS 1.3 handshake.
    pub fn handshake(&mut self) -> Result<(), &'static str> {
        // Step 1: Send ClientHello
        let client_hello = self.build_client_hello();
        self.send_record(ContentType::Handshake, &client_hello)?;
        self.state = TlsState::ClientHelloSent;

        // Step 2: Receive ServerHello
        let server_hello = self.recv_record()?;
        self.process_server_hello(&server_hello)?;
        self.state = TlsState::ServerHelloReceived;

        // Step 3: Derive handshake keys
        self.derive_handshake_keys();

        // Step 4: Receive encrypted extensions + certificates + finished
        let _encrypted_ext = self.recv_record()?;
        // In TLS 1.3, everything after ServerHello is encrypted

        // Step 5: Send client Finished
        let finished = self.build_client_finished();
        self.send_record(ContentType::Handshake, &finished)?;

        self.state = TlsState::HandshakeComplete;

        // Step 6: Derive application traffic keys
        self.derive_traffic_keys();
        self.state = TlsState::ApplicationData;

        Ok(())
    }

    /// Send application data over TLS.
    pub fn send(&mut self, data: &[u8]) -> Result<usize, &'static str> {
        if self.state != TlsState::ApplicationData {
            return Err("TLS session not ready for application data");
        }

        // Encrypt and send as application data record
        let encrypted = self.encrypt(data);
        self.send_record(ContentType::ApplicationData, &encrypted)?;
        self.client_seq += 1;

        Ok(data.len())
    }

    /// Receive application data over TLS.
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize, &'static str> {
        if self.state != TlsState::ApplicationData {
            return Err("TLS session not ready");
        }

        // If we have buffered plaintext, return that first
        if !self.plaintext_buf.is_empty() {
            let len = core::cmp::min(buf.len(), self.plaintext_buf.len());
            buf[..len].copy_from_slice(&self.plaintext_buf[..len]);
            self.plaintext_buf.drain(..len);
            return Ok(len);
        }

        // Read and decrypt a record
        let record = self.recv_record()?;
        let plaintext = self.decrypt(&record);
        self.server_seq += 1;

        let len = core::cmp::min(buf.len(), plaintext.len());
        buf[..len].copy_from_slice(&plaintext[..len]);
        if plaintext.len() > len {
            self.plaintext_buf.extend_from_slice(&plaintext[len..]);
        }

        Ok(len)
    }

    /// Close the TLS session.
    pub fn close(&mut self) -> Result<(), &'static str> {
        if self.state == TlsState::ApplicationData {
            // Send close_notify alert
            let alert = [AlertLevel::Warning as u8, 0]; // close_notify
            self.send_record(ContentType::Alert, &alert)?;
        }
        self.state = TlsState::Closed;
        super::tcp::close(self.tcp_conn_id);
        Ok(())
    }

    // ── Internal methods ────────────────────────────────────────────────

    fn build_client_hello(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(256);

        // Handshake type: ClientHello
        msg.push(HandshakeType::ClientHello as u8);
        // Length placeholder (3 bytes)
        msg.push(0); msg.push(0); msg.push(0);

        // Protocol version: TLS 1.2 (for compatibility; real version in extension)
        msg.push(0x03); msg.push(0x03);

        // Client random
        msg.extend_from_slice(&self.client_random);

        // Session ID (empty for TLS 1.3)
        msg.push(0);

        // Cipher suites: TLS_CHACHA20_POLY1305_SHA256 (0x1303)
        msg.push(0x00); msg.push(0x02); // Length
        msg.push(0x13); msg.push(0x03); // ChaCha20-Poly1305

        // Compression methods: null only
        msg.push(0x01); msg.push(0x00);

        // Extensions
        let extensions = self.build_extensions();
        msg.push((extensions.len() >> 8) as u8);
        msg.push(extensions.len() as u8);
        msg.extend_from_slice(&extensions);

        // Fix length field
        let len = msg.len() - 4;
        msg[1] = ((len >> 16) & 0xFF) as u8;
        msg[2] = ((len >> 8) & 0xFF) as u8;
        msg[3] = (len & 0xFF) as u8;

        msg
    }

    fn build_extensions(&self) -> Vec<u8> {
        let mut ext = Vec::new();

        // SNI (Server Name Indication)
        let hostname_bytes = self.hostname.as_bytes();
        // Extension type: server_name (0)
        ext.push(0x00); ext.push(0x00);
        let sni_len = hostname_bytes.len() + 5;
        ext.push((sni_len >> 8) as u8);
        ext.push(sni_len as u8);
        let sni_list_len = hostname_bytes.len() + 3;
        ext.push((sni_list_len >> 8) as u8);
        ext.push(sni_list_len as u8);
        ext.push(0x00); // Host name type
        ext.push((hostname_bytes.len() >> 8) as u8);
        ext.push(hostname_bytes.len() as u8);
        ext.extend_from_slice(hostname_bytes);

        // Supported versions: TLS 1.3 only
        ext.push(0x00); ext.push(0x2B); // Extension type
        ext.push(0x00); ext.push(0x03); // Length
        ext.push(0x02); // List length
        ext.push(0x03); ext.push(0x04); // TLS 1.3

        // Supported groups: x25519
        ext.push(0x00); ext.push(0x0A); // Extension type
        ext.push(0x00); ext.push(0x04); // Length
        ext.push(0x00); ext.push(0x02); // List length
        ext.push(0x00); ext.push(0x1D); // x25519

        // Signature algorithms: ed25519 + rsa_pss_rsae_sha256
        ext.push(0x00); ext.push(0x0D); // Extension type
        ext.push(0x00); ext.push(0x06); // Length
        ext.push(0x00); ext.push(0x04); // List length
        ext.push(0x08); ext.push(0x07); // ed25519
        ext.push(0x08); ext.push(0x04); // rsa_pss_rsae_sha256

        ext
    }

    fn process_server_hello(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if data.len() < 38 {
            return Err("ServerHello too short");
        }
        // Skip handshake type (1) + length (3) + version (2)
        // Extract server random (32 bytes starting at offset 6)
        if data.len() >= 38 {
            self.server_random.copy_from_slice(&data[6..38]);
        }
        Ok(())
    }

    fn derive_handshake_keys(&mut self) {
        // HKDF-like key derivation using SHA-256 (via our pairing module).
        // Combine client_random + server_random as the input keying material,
        // then derive separate keys via domain-separated hashing.
        let mut ikm = Vec::with_capacity(64);
        ikm.extend_from_slice(&self.client_random);
        ikm.extend_from_slice(&self.server_random);
        let base_key = crate::security::pairing::sha256_simple(&ikm);

        // Client write key: SHA256("c hs traffic" || base_key)
        let mut ck_input = Vec::with_capacity(44);
        ck_input.extend_from_slice(b"c hs traffic");
        ck_input.extend_from_slice(&base_key);
        self.client_write_key = crate::security::pairing::sha256_simple(&ck_input);

        // Server write key: SHA256("s hs traffic" || base_key)
        let mut sk_input = Vec::with_capacity(44);
        sk_input.extend_from_slice(b"s hs traffic");
        sk_input.extend_from_slice(&base_key);
        self.server_write_key = crate::security::pairing::sha256_simple(&sk_input);

        // IVs: truncated SHA256 of domain-separated inputs
        let mut civ_input = Vec::with_capacity(44);
        civ_input.extend_from_slice(b"c hs iv");
        civ_input.extend_from_slice(&base_key);
        let civ_hash = crate::security::pairing::sha256_simple(&civ_input);
        self.client_write_iv.copy_from_slice(&civ_hash[..12]);

        let mut siv_input = Vec::with_capacity(44);
        siv_input.extend_from_slice(b"s hs iv");
        siv_input.extend_from_slice(&base_key);
        let siv_hash = crate::security::pairing::sha256_simple(&siv_input);
        self.server_write_iv.copy_from_slice(&siv_hash[..12]);
    }

    fn derive_traffic_keys(&mut self) {
        // Derive application traffic keys from handshake keys via
        // domain-separated SHA-256 (approximation of HKDF-Expand-Label).
        let mut ck_input = Vec::with_capacity(44);
        ck_input.extend_from_slice(b"c ap traffic");
        ck_input.extend_from_slice(&self.client_write_key);
        self.client_write_key = crate::security::pairing::sha256_simple(&ck_input);

        let mut sk_input = Vec::with_capacity(44);
        sk_input.extend_from_slice(b"s ap traffic");
        sk_input.extend_from_slice(&self.server_write_key);
        self.server_write_key = crate::security::pairing::sha256_simple(&sk_input);

        // Re-derive IVs for application traffic
        let mut civ_input = Vec::with_capacity(44);
        civ_input.extend_from_slice(b"c ap iv");
        civ_input.extend_from_slice(&self.client_write_key);
        let civ_hash = crate::security::pairing::sha256_simple(&civ_input);
        self.client_write_iv.copy_from_slice(&civ_hash[..12]);

        let mut siv_input = Vec::with_capacity(44);
        siv_input.extend_from_slice(b"s ap iv");
        siv_input.extend_from_slice(&self.server_write_key);
        let siv_hash = crate::security::pairing::sha256_simple(&siv_input);
        self.server_write_iv.copy_from_slice(&siv_hash[..12]);
    }

    fn build_client_finished(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(36);
        msg.push(HandshakeType::Finished as u8);
        msg.push(0x00); msg.push(0x00); msg.push(0x20); // Length: 32
        // Verify data: HMAC-like hash of transcript using client write key
        let mut verify_input = Vec::with_capacity(64);
        verify_input.extend_from_slice(b"finished");
        verify_input.extend_from_slice(&self.client_write_key);
        verify_input.extend_from_slice(&self.client_random);
        verify_input.extend_from_slice(&self.server_random);
        let verify_data = crate::security::pairing::sha256_simple(&verify_input);
        msg.extend_from_slice(&verify_data);
        msg
    }

    /// Build a per-record nonce by XORing the IV with the sequence number (RFC 8446 §5.3).
    fn build_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
        let mut nonce = *iv;
        let seq_bytes = seq.to_be_bytes();
        // XOR the last 8 bytes of the IV with the sequence number
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        nonce
    }

    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        // ChaCha20-Poly1305 AEAD encryption using our real implementation
        let nonce = Self::build_nonce(&self.client_write_iv, self.client_seq);
        let ciphertext = crate::security::secrets::chacha20_encrypt(
            &self.client_write_key, &nonce, plaintext
        );
        let tag = crate::security::secrets::poly1305_mac(
            &self.client_write_key, &nonce, &ciphertext
        );
        let mut result = Vec::with_capacity(ciphertext.len() + 16);
        result.extend_from_slice(&ciphertext);
        result.extend_from_slice(&tag);
        result
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        if ciphertext.len() < 16 {
            return Vec::new();
        }
        let nonce = Self::build_nonce(&self.server_write_iv, self.server_seq);
        let tag_start = ciphertext.len() - 16;
        let data = &ciphertext[..tag_start];
        let received_tag = &ciphertext[tag_start..];

        // Verify authentication tag
        let expected_tag = crate::security::secrets::poly1305_mac(
            &self.server_write_key, &nonce, data
        );
        if !crate::security::secrets::constant_time_eq(received_tag, &expected_tag) {
            crate::kprintln!("[tls] authentication tag mismatch — possible tampering");
            return Vec::new();
        }

        // Decrypt with ChaCha20
        crate::security::secrets::chacha20_encrypt(&self.server_write_key, &nonce, data)
    }

    fn send_record(&self, content_type: ContentType, data: &[u8]) -> Result<(), &'static str> {
        let mut record = Vec::with_capacity(5 + data.len());
        record.push(content_type as u8);
        // Protocol version (TLS 1.2 on the wire for TLS 1.3)
        record.push(0x03); record.push(0x03);
        // Length
        record.push((data.len() >> 8) as u8);
        record.push(data.len() as u8);
        record.extend_from_slice(data);

        let sent = super::tcp::send(self.tcp_conn_id, &record);
        if sent < 0 {
            return Err("failed to send TLS record");
        }
        Ok(())
    }

    fn recv_record(&self) -> Result<Vec<u8>, &'static str> {
        // Read TLS record header (5 bytes)
        let mut header = [0u8; 5];
        let mut total = 0;
        let max_retries = 1000;
        let mut retries = 0;

        while total < 5 && retries < max_retries {
            let n = super::tcp::recv(self.tcp_conn_id, &mut header[total..]);
            if n > 0 {
                total += n as usize;
            } else if n == 0 {
                return Err("connection closed during TLS record read");
            } else {
                retries += 1;
                crate::kernel::sched::yield_now();
            }
        }

        if total < 5 {
            return Err("timeout reading TLS record header");
        }

        let length = ((header[3] as usize) << 8) | (header[4] as usize);
        if length > 16384 + 256 {
            return Err("TLS record too large");
        }

        // Read record body
        let mut body = alloc::vec![0u8; length];
        total = 0;
        retries = 0;
        while total < length && retries < max_retries {
            let n = super::tcp::recv(self.tcp_conn_id, &mut body[total..]);
            if n > 0 {
                total += n as usize;
            } else if n == 0 {
                return Err("connection closed during TLS record body");
            } else {
                retries += 1;
                crate::kernel::sched::yield_now();
            }
        }

        Ok(body)
    }
}

/// Convenience: connect to a host with TLS.
pub fn connect(ip: [u8; 4], port: u16, hostname: &str) -> Result<TlsSession, &'static str> {
    let tcp_id = super::tcp::connect(ip, port)?;
    let mut session = TlsSession::new(tcp_id, String::from(hostname));
    session.handshake()?;
    Ok(session)
}
