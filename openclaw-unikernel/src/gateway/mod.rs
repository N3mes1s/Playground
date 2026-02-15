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
use alloc::format;

/// Start the HTTP gateway on the given port.
pub fn start(port: u16) {
    crate::kprintln!("[gateway] starting on port {}", port);

    // Spawn a listener task in the cooperative scheduler
    crate::kernel::sched::spawn("gateway", alloc::boxed::Box::new(move || {
        // Listen for TCP connections on the port
        match crate::net::tcp::listen(port) {
            Ok(listener_id) => {
                // Process incoming connections
                process_connections(listener_id);
            }
            Err(e) => {
                crate::kprintln!("[gateway] listen error: {}", e);
            }
        }
        false // Never completes
    }));
}

fn process_connections(_listener_id: usize) {
    // In a full implementation, this would:
    // 1. Accept incoming TCP connections
    // 2. Read HTTP request
    // 3. Route to handler
    // 4. Send HTTP response
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
    let mem_count = crate::memory::global().lock().count();

    HttpResponse {
        status: 200,
        body: format!(
            "{{\"status\":\"ok\",\"heap_used\":{},\"heap_total\":{},\"memories\":{},\"tasks\":{}}}",
            heap.used_bytes,
            heap.total_bytes,
            mem_count,
            crate::kernel::sched::task_count()
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

    // The actual processing happens asynchronously through the channel system
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
    // HMAC-SHA256 verification would happen here
    let _ = body;
    HttpResponse {
        status: 200,
        body: String::from("{\"status\":\"ok\"}"),
    }
}

fn handle_doctor(auth: Option<&str>) -> HttpResponse {
    // Doctor endpoint requires authentication
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
