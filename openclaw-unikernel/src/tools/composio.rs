//! # Composio Integration
//!
//! Provides access to 1000+ app actions through the Composio API.
//! Supports OAuth connection management and action execution for
//! services like GitHub, Jira, Notion, Google Sheets, Slack, etc.

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use super::{Tool, ToolResult};

/// Composio tool — proxies tool calls to the Composio API.
pub struct ComposioTool {
    api_key: String,
    enabled: bool,
}

impl ComposioTool {
    pub fn new(api_key: &str) -> Self {
        ComposioTool {
            api_key: String::from(api_key),
            enabled: !api_key.is_empty(),
        }
    }

    /// List available Composio actions.
    pub fn list_actions(&self) -> Result<Vec<ComposioAction>, String> {
        if !self.enabled {
            return Err(String::from("composio not configured (no API key)"));
        }

        let response = crate::net::http::get(
            "backend.composio.dev",
            "/api/v1/actions?limit=50",
            Some(&self.api_key),
        ).map_err(|e| String::from(e))?;

        if !response.is_success() {
            return Err(format!("composio API error {}", response.status_code));
        }

        let body = response.body_str().map_err(|e| String::from(e))?;
        parse_actions_list(body)
    }

    /// Execute a Composio action.
    pub fn execute_action(&self, action_name: &str, params: &str) -> Result<String, String> {
        if !self.enabled {
            return Err(String::from("composio not configured"));
        }

        let body = format!(
            "{{\"actionName\":\"{}\",\"input\":{}}}",
            action_name,
            if params.is_empty() { "{}" } else { params }
        );

        let response = crate::net::http::post_json(
            "backend.composio.dev",
            "/api/v1/actions/execute",
            &body,
            Some(&self.api_key),
        ).map_err(|e| String::from(e))?;

        if !response.is_success() {
            return Err(format!(
                "composio action '{}' failed: HTTP {}",
                action_name, response.status_code
            ));
        }

        let result = response.body_str().map_err(|e| String::from(e))?;
        Ok(String::from(result))
    }

    /// Check connection status for an app.
    pub fn check_connection(&self, app_name: &str) -> Result<bool, String> {
        if !self.enabled {
            return Err(String::from("composio not configured"));
        }

        let path = format!("/api/v1/connectedAccounts?appName={}", app_name);
        let response = crate::net::http::get(
            "backend.composio.dev",
            &path,
            Some(&self.api_key),
        ).map_err(|e| String::from(e))?;

        Ok(response.is_success())
    }

    /// Initiate OAuth connection for an app.
    pub fn connect_app(&self, app_name: &str) -> Result<String, String> {
        if !self.enabled {
            return Err(String::from("composio not configured"));
        }

        let body = format!("{{\"appName\":\"{}\"}}", app_name);
        let response = crate::net::http::post_json(
            "backend.composio.dev",
            "/api/v1/connectedAccounts",
            &body,
            Some(&self.api_key),
        ).map_err(|e| String::from(e))?;

        if response.is_success() {
            let body = response.body_str().map_err(|e| String::from(e))?;
            let redirect_url = crate::providers::extract_json_string(body, "redirectUrl")
                .unwrap_or_else(|| String::from("(check composio dashboard)"));
            Ok(redirect_url)
        } else {
            Err(format!("failed to initiate connection: HTTP {}", response.status_code))
        }
    }
}

/// A Composio action descriptor.
#[derive(Debug, Clone)]
pub struct ComposioAction {
    pub name: String,
    pub display_name: String,
    pub app_name: String,
    pub description: String,
}

fn parse_actions_list(json: &str) -> Result<Vec<ComposioAction>, String> {
    let mut actions = Vec::new();
    let mut search_from = 0;

    while let Some(pos) = json[search_from..].find("\"appName\"") {
        let abs_pos = search_from + pos;
        let context_start = if abs_pos > 300 { abs_pos - 300 } else { 0 };
        let context_end = core::cmp::min(json.len(), abs_pos + 500);
        let context = &json[context_start..context_end];

        let name = crate::providers::extract_json_string(context, "name")
            .unwrap_or_default();
        let display_name = crate::providers::extract_json_string(context, "displayName")
            .unwrap_or_else(|| name.clone());
        let app_name = crate::providers::extract_json_string(context, "appName")
            .unwrap_or_default();
        let description = crate::providers::extract_json_string(context, "description")
            .unwrap_or_default();

        if !name.is_empty() {
            actions.push(ComposioAction {
                name,
                display_name,
                app_name,
                description,
            });
        }

        search_from = abs_pos + 10;
    }

    Ok(actions)
}

impl Tool for ComposioTool {
    fn name(&self) -> &str { "composio" }

    fn description(&self) -> &str {
        "Execute actions on 1000+ apps via Composio. Supports GitHub, Jira, Notion, \
         Google Sheets, Slack, Gmail, Trello, Linear, and many more. \
         Specify the action name and parameters as JSON."
    }

    fn parameters_schema(&self) -> &str {
        r#"{"type":"object","properties":{"action":{"type":"string","description":"Composio action name (e.g., 'GITHUB_CREATE_ISSUE', 'SLACK_SEND_MESSAGE')"},"params":{"type":"string","description":"JSON parameters for the action"},"list_actions":{"type":"boolean","description":"Set to true to list available actions"}},"required":["action"]}"#
    }

    fn execute(&self, arguments: &str) -> ToolResult {
        if !self.enabled {
            return ToolResult::err("composio not configured: set composio API key in config");
        }

        let list = crate::providers::extract_json_string(arguments, "list_actions")
            .map(|v| v == "true")
            .unwrap_or(false);

        if list {
            match self.list_actions() {
                Ok(actions) => {
                    let mut output = format!("Available Composio actions ({}):\n", actions.len());
                    for action in actions.iter().take(20) {
                        output.push_str(&format!(
                            "  - {} ({}): {}\n",
                            action.name, action.app_name, action.description
                        ));
                    }
                    if actions.len() > 20 {
                        output.push_str(&format!("  ... and {} more\n", actions.len() - 20));
                    }
                    return ToolResult::ok(&output);
                }
                Err(e) => return ToolResult::err(&e),
            }
        }

        let action = crate::providers::extract_json_string(arguments, "action")
            .unwrap_or_default();
        let params = crate::providers::extract_json_string(arguments, "params")
            .unwrap_or_else(|| String::from("{}"));

        if action.is_empty() {
            return ToolResult::err("action name is required");
        }

        match self.execute_action(&action, &params) {
            Ok(result) => ToolResult::ok(&result),
            Err(e) => ToolResult::err(&e),
        }
    }
}
