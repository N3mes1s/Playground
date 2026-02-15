//! # HTTP Gateway
//!
//! A minimal HTTP server built on our TCP stack.
//! Provides the REST API for external interaction:
//!
//! - GET  /health         — Public health metrics
//! - GET  /doctor         — Full diagnostic report
//! - POST /pair           — Pairing code exchange for bearer token
//! - POST /webhook        — Authenticated message processing
//! - GET  /whatsapp       — Meta webhook verification
//! - POST /whatsapp       — WhatsApp message ingestion
//! - GET  /export         — Export agent state (authenticated)
//! - POST /import         — Import agent state (authenticated)
//! - GET  /identity       — Get AIEOS identity JSON

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;

/// Start the HTTP gateway on the given port.
pub fn start(port: u16) {
    crate::kprintln!("[gateway] starting on port {}", port);

    // Spawn a listener task in the cooperative scheduler
    crate::kernel::sched::spawn("gateway", alloc::boxed::Box::new(move || {
        // Listen for TCP connections on the port
        match crate::net::tcp::listen(port) {
            Ok(listener_id) => {
                process_connections(listener_id);
            }
            Err(e) => {
                crate::kprintln!("[gateway] listen error: {}", e);
            }
        }
        false // Never completes
    }));
}

/// Accept and process incoming HTTP connections.
fn process_connections(listener_id: usize) {
    loop {
        // Try to accept a pending connection from the listener
        let conn_id = match crate::net::tcp::accept(listener_id) {
            Some(id) => id,
            None => {
                // No pending connection — yield and retry
                crate::kernel::sched::yield_now();
                continue;
            }
        };

        // Read the raw HTTP request from the TCP connection
        let mut request_buf = [0u8; 8192];
        let mut total_read = 0;
        let mut retries = 0;
        let max_retries = 500;

        while total_read < request_buf.len() && retries < max_retries {
            let n = crate::net::tcp::recv(conn_id, &mut request_buf[total_read..]);
            if n > 0 {
                total_read += n as usize;
                // Check if we've received the end of HTTP headers
                if contains_header_end(&request_buf[..total_read]) {
                    // Check Content-Length to see if we need more body data
                    let header_str = core::str::from_utf8(&request_buf[..total_read]).unwrap_or("");
                    let header_end = find_header_end(header_str).unwrap_or(total_read);
                    let content_length = extract_content_length(header_str);
                    let body_received = total_read.saturating_sub(header_end);
                    if body_received >= content_length {
                        break;
                    }
                }
            } else if n == 0 {
                break; // Connection closed
            } else {
                retries += 1;
                crate::kernel::sched::yield_now();
            }
        }

        if total_read == 0 {
            crate::net::tcp::close(conn_id);
            continue;
        }

        // Parse the HTTP request
        let raw = core::str::from_utf8(&request_buf[..total_read]).unwrap_or("");
        let (method, path, body, auth) = parse_http_request(raw);

        // Route to handler
        let response = handle_request(&method, &path, &body, auth.as_deref());

        // Build HTTP response
        let status_text = match response.status {
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "OK",
        };

        let response_str = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response.status, status_text,
            response.body.len(),
            response.body
        );

        // Send response back over TCP
        crate::net::tcp::send(conn_id, response_str.as_bytes());
        crate::net::tcp::close(conn_id);
    }
}

/// Check if the buffer contains the HTTP header terminator (\r\n\r\n).
fn contains_header_end(buf: &[u8]) -> bool {
    buf.windows(4).any(|w| w == b"\r\n\r\n")
}

/// Find the byte offset of the header/body boundary.
fn find_header_end(s: &str) -> Option<usize> {
    s.find("\r\n\r\n").map(|pos| pos + 4)
}

/// Extract Content-Length header value.
fn extract_content_length(headers: &str) -> usize {
    for line in headers.lines() {
        if crate::util::starts_with_ci(line, "content-length:") {
            let rest = &line["content-length:".len()..];
            if let Some(len) = crate::util::parse_usize(rest) {
                return len;
            }
        }
    }
    0
}

/// Parse an HTTP request into (method, path, body, auth_header).
fn parse_http_request(raw: &str) -> (String, String, String, Option<String>) {
    let mut lines = raw.lines();

    // Request line: "GET /path HTTP/1.1"
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = String::from(parts.next().unwrap_or("GET"));
    let path = String::from(parts.next().unwrap_or("/"));

    // Parse headers
    let mut auth = None;
    let mut in_headers = true;
    let mut body_lines = Vec::new();

    for line in lines {
        if in_headers {
            if line.is_empty() || line == "\r" {
                in_headers = false;
                continue;
            }
            if crate::util::starts_with_ci(line, "authorization:") {
                auth = Some(String::from(line[14..].trim()));
            }
        } else {
            body_lines.push(line);
        }
    }

    let body = body_lines.join("\n");
    (method, path, body, auth)
}

/// Handle an HTTP request and return the response.
fn handle_request(method: &str, path: &str, body: &str, auth: Option<&str>) -> HttpResponse {
    match (method, path) {
        ("GET", "/health") => handle_health(),
        ("GET", "/doctor") => handle_doctor(auth),
        ("POST", "/pair") => handle_pair(body),
        ("POST", "/webhook") => handle_webhook(body, auth),
        ("GET", "/whatsapp") => handle_whatsapp_verify(body),
        ("POST", "/whatsapp") => handle_whatsapp_message(body),
        ("GET", "/export") => handle_export(auth),
        ("POST", "/import") => handle_import(body, auth),
        ("GET", "/identity") => handle_identity(),
        _ => HttpResponse {
            status: 404,
            body: String::from("{\"error\":\"not found\"}"),
        },
    }
}

struct HttpResponse {
    status: u16,
    body: String,
}

fn handle_health() -> HttpResponse {
    let heap = crate::kernel::mm::heap_stats();
    let mem_count = crate::memory::global().lock().entry_count();
    let metrics = crate::observability::snapshot();

    HttpResponse {
        status: 200,
        body: format!(
            "{{\"status\":\"ok\",\"heap_used\":{},\"heap_total\":{},\"memories\":{},\"tasks\":{},\"requests\":{},\"errors\":{}}}",
            heap.used_bytes,
            heap.total_bytes,
            mem_count,
            crate::kernel::sched::task_count(),
            metrics.total_requests,
            metrics.total_errors
        ),
    }
}

fn handle_pair(body: &str) -> HttpResponse {
    let code = crate::providers::extract_json_string(body, "code")
        .unwrap_or_default();

    match crate::security::attempt_pairing(&code) {
        Ok(token) => HttpResponse {
            status: 200,
            body: format!("{{\"token\":\"{}\"}}", token),
        },
        Err(e) => HttpResponse {
            status: 401,
            body: format!("{{\"error\":\"{}\"}}", e),
        },
    }
}

fn handle_webhook(body: &str, auth: Option<&str>) -> HttpResponse {
    // Validate bearer token
    let token = auth.and_then(|a| a.strip_prefix("Bearer "));
    match token {
        Some(t) if crate::security::validate_token(t) => {}
        _ => {
            return HttpResponse {
                status: 401,
                body: String::from("{\"error\":\"unauthorized\"}"),
            };
        }
    }

    let message = crate::providers::extract_json_string(body, "message")
        .unwrap_or_default();

    if message.is_empty() {
        return HttpResponse {
            status: 400,
            body: String::from("{\"error\":\"message is required\"}"),
        };
    }

    // Inject the message into the webhook channel's pending queue
    crate::channels::inject_webhook_message(&message, "webhook-api");

    HttpResponse {
        status: 202,
        body: String::from("{\"status\":\"accepted\"}"),
    }
}

fn handle_whatsapp_verify(query: &str) -> HttpResponse {
    // Meta webhook verification: echo back hub.challenge
    let challenge = crate::providers::extract_json_string(query, "hub.challenge")
        .unwrap_or_default();

    HttpResponse {
        status: 200,
        body: challenge,
    }
}

fn handle_whatsapp_message(body: &str) -> HttpResponse {
    // Inject as a webhook message for the WhatsApp channel to process
    crate::channels::inject_webhook_message(body, "whatsapp-webhook");
    HttpResponse {
        status: 200,
        body: String::from("{\"status\":\"ok\"}"),
    }
}

fn handle_doctor(auth: Option<&str>) -> HttpResponse {
    let token = auth.and_then(|a| a.strip_prefix("Bearer "));
    match token {
        Some(t) if crate::security::validate_token(t) => {}
        _ => {
            return HttpResponse {
                status: 401,
                body: String::from("{\"error\":\"unauthorized\"}"),
            };
        }
    }

    let report = crate::doctor::run_diagnostics();
    HttpResponse {
        status: 200,
        body: report.to_json(),
    }
}

fn handle_export(auth: Option<&str>) -> HttpResponse {
    let token = auth.and_then(|a| a.strip_prefix("Bearer "));
    match token {
        Some(t) if crate::security::validate_token(t) => {}
        _ => {
            return HttpResponse {
                status: 401,
                body: String::from("{\"error\":\"unauthorized\"}"),
            };
        }
    }

    let bundle = crate::migration::export(&crate::migration::ExportOptions::default());
    HttpResponse {
        status: 200,
        body: bundle.json,
    }
}

fn handle_import(body: &str, auth: Option<&str>) -> HttpResponse {
    let token = auth.and_then(|a| a.strip_prefix("Bearer "));
    match token {
        Some(t) if crate::security::validate_token(t) => {}
        _ => {
            return HttpResponse {
                status: 401,
                body: String::from("{\"error\":\"unauthorized\"}"),
            };
        }
    }

    match crate::migration::import(body) {
        Ok(result) => HttpResponse {
            status: 200,
            body: format!(
                "{{\"memories_imported\":{},\"files_imported\":{},\"config_updated\":{},\"warnings\":{}}}",
                result.memories_imported,
                result.files_imported,
                result.config_updated,
                result.warnings.len()
            ),
        },
        Err(e) => HttpResponse {
            status: 400,
            body: format!("{{\"error\":\"{}\"}}", e),
        },
    }
}

fn handle_identity() -> HttpResponse {
    match crate::identity::AieosIdentity::load() {
        Some(id) => HttpResponse {
            status: 200,
            body: id.to_json(),
        },
        None => {
            let cfg = crate::config::get();
            let id = crate::identity::AieosIdentity::from_config(&cfg.identity);
            HttpResponse {
                status: 200,
                body: id.to_json(),
            }
        }
    }
}
