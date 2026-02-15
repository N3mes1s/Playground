//! # HTTP/1.1 Client
//!
//! Minimal HTTP client built on top of our TCP+TLS stack.
//! Designed for JSON API communication with LLM providers.

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use super::tls::TlsSession;

/// HTTP methods.
#[derive(Debug, Clone, Copy)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Patch,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Patch => "PATCH",
        }
    }
}

/// An HTTP request.
pub struct Request {
    pub method: Method,
    pub path: String,
    pub host: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

impl Request {
    pub fn new(method: Method, host: &str, path: &str) -> Self {
        Request {
            method,
            path: String::from(path),
            host: String::from(host),
            headers: Vec::new(),
            body: None,
        }
    }

    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.push((String::from(key), String::from(value)));
        self
    }

    pub fn json_body(mut self, json: &str) -> Self {
        self.body = Some(json.as_bytes().to_vec());
        self.headers.push((
            String::from("Content-Type"),
            String::from("application/json"),
        ));
        self
    }

    pub fn bearer_auth(self, token: &str) -> Self {
        self.header("Authorization", &format!("Bearer {}", token))
    }

    /// Serialize to HTTP/1.1 wire format.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1024);

        // Request line
        buf.extend_from_slice(self.method.as_str().as_bytes());
        buf.push(b' ');
        buf.extend_from_slice(self.path.as_bytes());
        buf.extend_from_slice(b" HTTP/1.1\r\n");

        // Host header
        buf.extend_from_slice(b"Host: ");
        buf.extend_from_slice(self.host.as_bytes());
        buf.extend_from_slice(b"\r\n");

        // Content-Length if body present
        if let Some(ref body) = self.body {
            buf.extend_from_slice(b"Content-Length: ");
            let len_str = format!("{}", body.len());
            buf.extend_from_slice(len_str.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }

        // Custom headers
        for (key, value) in &self.headers {
            buf.extend_from_slice(key.as_bytes());
            buf.extend_from_slice(b": ");
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }

        // Connection: keep-alive
        buf.extend_from_slice(b"Connection: keep-alive\r\n");
        buf.extend_from_slice(b"User-Agent: OpenClaw-Unikernel/0.1.0\r\n");

        // End of headers
        buf.extend_from_slice(b"\r\n");

        // Body
        if let Some(ref body) = self.body {
            buf.extend_from_slice(body);
        }

        buf
    }
}

/// An HTTP response.
pub struct Response {
    pub status_code: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// Parse an HTTP response from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        let text = core::str::from_utf8(data).map_err(|_| "invalid UTF-8 in response")?;

        // Find header/body boundary
        let header_end = text.find("\r\n\r\n").ok_or("no header/body boundary")?;
        let header_text = &text[..header_end];
        let body_start = header_end + 4;

        // Parse status line
        let mut lines = header_text.split("\r\n");
        let status_line = lines.next().ok_or("missing status line")?;
        let mut parts = status_line.splitn(3, ' ');
        let _version = parts.next().ok_or("missing HTTP version")?;
        let status_str = parts.next().ok_or("missing status code")?;
        let status_code: u16 = parse_u16(status_str).ok_or("invalid status code")?;
        let status_text = String::from(parts.next().unwrap_or(""));

        // Parse headers
        let mut headers = Vec::new();
        for line in lines {
            if let Some(colon) = line.find(':') {
                let key = String::from(line[..colon].trim());
                let value = String::from(line[colon + 1..].trim());
                headers.push((key, value));
            }
        }

        // Extract body
        let body = if body_start < data.len() {
            data[body_start..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Response {
            status_code,
            status_text,
            headers,
            body,
        })
    }

    /// Get a header value by name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        let name_lower = crate::util::ascii_lowercase(name);
        for (key, value) in &self.headers {
            if crate::util::ascii_lowercase(key) == name_lower {
                return Some(value.as_str());
            }
        }
        None
    }

    /// Get body as UTF-8 string.
    pub fn body_str(&self) -> Result<&str, &'static str> {
        core::str::from_utf8(&self.body).map_err(|_| "response body is not valid UTF-8")
    }

    /// Check if the response indicates success (2xx).
    pub fn is_success(&self) -> bool {
        self.status_code >= 200 && self.status_code < 300
    }
}

/// Simple u16 parser (no_std).
fn parse_u16(s: &str) -> Option<u16> {
    let mut result: u16 = 0;
    for c in s.chars() {
        if !c.is_ascii_digit() {
            return None;
        }
        result = result.checked_mul(10)?;
        result = result.checked_add((c as u16) - (b'0' as u16))?;
    }
    Some(result)
}

/// Perform an HTTPS request.
pub fn request(req: &Request) -> Result<Response, &'static str> {
    // Resolve hostname to IP
    let ip = super::dns::resolve(&req.host)?;

    // Establish TLS connection
    let mut tls = super::tls::connect(ip, 443, &req.host)?;

    // Send HTTP request
    let raw_request = req.serialize();
    tls.send(&raw_request)?;

    // Read response (up to 1 MiB)
    let mut response_buf = Vec::with_capacity(65536);
    let mut read_buf = [0u8; 4096];
    let mut headers_done = false;
    let mut content_length: Option<usize> = None;
    let mut body_received = 0usize;

    loop {
        match tls.recv(&mut read_buf) {
            Ok(0) => break,
            Ok(n) => {
                response_buf.extend_from_slice(&read_buf[..n]);

                // Check if we've received all headers
                if !headers_done {
                    if let Ok(text) = core::str::from_utf8(&response_buf) {
                        if let Some(header_end) = text.find("\r\n\r\n") {
                            headers_done = true;
                            // Extract Content-Length
                            let header_text = &text[..header_end];
                            for line in header_text.split("\r\n") {
                                if crate::util::starts_with_ci(line, "content-length:") {
                                    if let Some(val) = line.split(':').nth(1) {
                                        content_length = parse_u16(val.trim()).map(|v| v as usize);
                                    }
                                }
                            }
                            body_received = response_buf.len() - header_end - 4;
                        }
                    }
                } else {
                    body_received += n;
                }

                // Check if we've received the full body
                if headers_done {
                    if let Some(cl) = content_length {
                        if body_received >= cl {
                            break;
                        }
                    }
                }

                // Safety limit
                if response_buf.len() > 1_048_576 {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    tls.close()?;

    Response::parse(&response_buf)
}

/// Convenience: POST JSON to an HTTPS endpoint.
pub fn post_json(
    host: &str,
    path: &str,
    json: &str,
    auth_token: Option<&str>,
) -> Result<Response, &'static str> {
    let mut req = Request::new(Method::Post, host, path)
        .json_body(json)
        .header("Accept", "application/json");

    if let Some(token) = auth_token {
        req = req.bearer_auth(token);
    }

    request(&req)
}

/// Convenience: GET from an HTTPS endpoint.
pub fn get(
    host: &str,
    path: &str,
    auth_token: Option<&str>,
) -> Result<Response, &'static str> {
    let mut req = Request::new(Method::Get, host, path)
        .header("Accept", "application/json");

    if let Some(token) = auth_token {
        req = req.bearer_auth(token);
    }

    request(&req)
}
