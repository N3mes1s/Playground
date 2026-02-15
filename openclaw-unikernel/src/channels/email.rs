//! # Email Channel
//!
//! Sends and receives messages via SMTP (outbound) and IMAP (inbound).
//! Implements minimal protocol handling directly on our TCP+TLS stack.

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use super::*;

/// Email channel configuration.
pub struct EmailChannel {
    config: ChannelConfig,
    running: bool,
    smtp_host: String,
    smtp_port: u16,
    imap_host: String,
    imap_port: u16,
    username: String,
    password: String,
    from_address: String,
    pending_messages: Vec<ChannelMessage>,
    last_uid: u32,
}

impl EmailChannel {
    pub fn new(config: ChannelConfig) -> Self {
        let get_extra = |key: &str, default: &str| -> String {
            config.extra.iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| String::from(default))
        };

        EmailChannel {
            smtp_host: get_extra("smtp_host", "smtp.gmail.com"),
            smtp_port: crate::util::parse_usize(&get_extra("smtp_port", "465")).unwrap_or(465) as u16,
            imap_host: get_extra("imap_host", "imap.gmail.com"),
            imap_port: crate::util::parse_usize(&get_extra("imap_port", "993")).unwrap_or(993) as u16,
            username: get_extra("username", ""),
            password: get_extra("password", ""),
            from_address: get_extra("from", ""),
            config,
            running: false,
            pending_messages: Vec::new(),
            last_uid: 0,
        }
    }

    /// Check for new emails via IMAP.
    fn check_imap(&mut self) {
        // Resolve IMAP host
        let ip = match crate::net::dns::resolve(&self.imap_host) {
            Ok(ip) => ip,
            Err(_) => return,
        };

        // Connect with TLS
        let mut tls = match crate::net::tls::connect(ip, self.imap_port, &self.imap_host) {
            Ok(s) => s,
            Err(_) => return,
        };

        // Read greeting
        let mut buf = [0u8; 4096];
        let _ = tls.recv(&mut buf);

        // Login
        let login_cmd = format!(
            "A001 LOGIN {} {}\r\n",
            self.username, self.password
        );
        let _ = tls.send(login_cmd.as_bytes());
        let _ = tls.recv(&mut buf);

        // Select INBOX
        let _ = tls.send(b"A002 SELECT INBOX\r\n");
        let _ = tls.recv(&mut buf);

        // Search for unseen messages
        let search_cmd = if self.last_uid > 0 {
            format!("A003 UID SEARCH UID {}:* UNSEEN\r\n", self.last_uid + 1)
        } else {
            String::from("A003 UID SEARCH UNSEEN\r\n")
        };
        let _ = tls.send(search_cmd.as_bytes());

        let n = tls.recv(&mut buf).unwrap_or(0);
        if n > 0 {
            let response = core::str::from_utf8(&buf[..n]).unwrap_or("");

            // Parse UIDs from "* SEARCH uid1 uid2 ..."
            if let Some(search_line) = response.lines().find(|l| l.starts_with("* SEARCH")) {
                let uids: Vec<u32> = search_line
                    .split_whitespace()
                    .skip(2) // skip "* SEARCH"
                    .filter_map(|s| crate::util::parse_u64(s).map(|v| v as u32))
                    .collect();

                // Fetch each message
                for uid in uids {
                    let fetch_cmd = format!(
                        "A004 UID FETCH {} (BODY[HEADER.FIELDS (FROM SUBJECT)] BODY[TEXT])\r\n",
                        uid
                    );
                    let _ = tls.send(fetch_cmd.as_bytes());

                    let mut msg_buf = [0u8; 16384];
                    let n = tls.recv(&mut msg_buf).unwrap_or(0);
                    if n > 0 {
                        let msg_text = core::str::from_utf8(&msg_buf[..n]).unwrap_or("");
                        self.parse_email_message(uid, msg_text);
                    }

                    self.last_uid = core::cmp::max(self.last_uid, uid);
                }
            }
        }

        // Logout
        let _ = tls.send(b"A005 LOGOUT\r\n");
        let _ = tls.close();
    }

    fn parse_email_message(&mut self, uid: u32, raw: &str) {
        // Extract From header
        let from = raw.lines()
            .find(|l| crate::util::starts_with_ci(l, "from:"))
            .map(|l| String::from(l[5..].trim()))
            .unwrap_or_else(|| String::from("unknown"));

        // Extract Subject
        let subject = raw.lines()
            .find(|l| crate::util::starts_with_ci(l, "subject:"))
            .map(|l| String::from(l[8..].trim()))
            .unwrap_or_default();

        // Extract body (everything after the blank line separating headers from body)
        let body = if let Some(pos) = raw.find("\r\n\r\n") {
            String::from(raw[pos + 4..].trim())
        } else if let Some(pos) = raw.find("\n\n") {
            String::from(raw[pos + 2..].trim())
        } else {
            String::new()
        };

        // Check allowlist
        if !self.config.allowed_users.is_empty() {
            let from_lower = crate::util::ascii_lowercase(&from);
            let allowed = self.config.allowed_users.iter()
                .any(|u| from_lower.contains(&crate::util::ascii_lowercase(u)));
            if !allowed {
                return;
            }
        }

        let content = if subject.is_empty() {
            body
        } else {
            format!("[{}] {}", subject, body)
        };

        self.pending_messages.push(ChannelMessage {
            id: format!("email-{}", uid),
            channel: String::from("email"),
            sender: from,
            content,
            timestamp: crate::kernel::rdtsc(),
            metadata: MessageMetadata::default(),
        });
    }

    /// Send an email via SMTP with STARTTLS.
    fn send_smtp(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        let ip = crate::net::dns::resolve(&self.smtp_host)
            .map_err(|e| String::from(e))?;

        let mut tls = crate::net::tls::connect(ip, self.smtp_port, &self.smtp_host)
            .map_err(|e| String::from(e))?;

        let mut buf = [0u8; 1024];

        // Read greeting
        let _ = tls.recv(&mut buf);

        // EHLO
        let ehlo = format!("EHLO openclaw.local\r\n");
        tls.send(ehlo.as_bytes()).map_err(|e| String::from(e))?;
        let _ = tls.recv(&mut buf);

        // AUTH LOGIN
        let auth = format!("AUTH LOGIN\r\n");
        tls.send(auth.as_bytes()).map_err(|e| String::from(e))?;
        let _ = tls.recv(&mut buf);

        // Send base64-encoded username
        let user_b64 = crate::util::base64_encode(self.username.as_bytes());
        let user_cmd = format!("{}\r\n", user_b64);
        tls.send(user_cmd.as_bytes()).map_err(|e| String::from(e))?;
        let _ = tls.recv(&mut buf);

        // Send base64-encoded password
        let pass_b64 = crate::util::base64_encode(self.password.as_bytes());
        let pass_cmd = format!("{}\r\n", pass_b64);
        tls.send(pass_cmd.as_bytes()).map_err(|e| String::from(e))?;
        let _ = tls.recv(&mut buf);

        // MAIL FROM
        let mail_from = format!("MAIL FROM:<{}>\r\n", self.from_address);
        tls.send(mail_from.as_bytes()).map_err(|e| String::from(e))?;
        let _ = tls.recv(&mut buf);

        // RCPT TO
        let rcpt_to = format!("RCPT TO:<{}>\r\n", to);
        tls.send(rcpt_to.as_bytes()).map_err(|e| String::from(e))?;
        let _ = tls.recv(&mut buf);

        // DATA
        tls.send(b"DATA\r\n").map_err(|e| String::from(e))?;
        let _ = tls.recv(&mut buf);

        // Message content
        let message = format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{}\r\n.\r\n",
            self.from_address, to, subject, body
        );
        tls.send(message.as_bytes()).map_err(|e| String::from(e))?;
        let _ = tls.recv(&mut buf);

        // QUIT
        tls.send(b"QUIT\r\n").map_err(|e| String::from(e))?;
        let _ = tls.close();

        Ok(())
    }
}

impl Channel for EmailChannel {
    fn name(&self) -> &str { "email" }

    fn start(&mut self) -> Result<(), String> {
        if self.username.is_empty() || self.password.is_empty() {
            return Err(String::from("email credentials not configured"));
        }
        self.running = true;
        Ok(())
    }

    fn poll_messages(&mut self) -> Vec<ChannelMessage> {
        if !self.running {
            return Vec::new();
        }
        // Only check IMAP periodically (not every tick)
        // The daemon controls the polling frequency
        self.check_imap();
        core::mem::take(&mut self.pending_messages)
    }

    fn send_message(&self, to: &str, content: &str) -> Result<(), String> {
        self.send_smtp(to, "OpenClaw Agent", content)
    }

    fn health_check(&self) -> Result<(), String> {
        if self.running && !self.username.is_empty() {
            Ok(())
        } else {
            Err(String::from("email channel not configured"))
        }
    }

    fn stop(&mut self) -> Result<(), String> {
        self.running = false;
        Ok(())
    }
}
