// SPDX-FileCopyrightText: 2025 David Mulder <dmulder@suse.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Device Authorization Grant (DAG) detection module.
//!
//! This module detects DAG authentication messages from any OIDC provider
//! by parsing the standard Himmelblau message format.

use regex::Regex;

lazy_static! {
    /// Regex to detect DAG messages and extract URL.
    /// Matches the Himmelblau format: "Using a browser on another device, visit:\n{url}"
    static ref DAG_MESSAGE_RE: Regex = Regex::new(
        r"(?i)Using a browser on another device, visit:\s*\n?\s*(https?://[^\s]+)"
    ).expect("Failed to compile DAG message regex");

    /// Regex to extract the device code from DAG messages.
    /// Matches: "And enter the code:\n{code}"
    static ref DAG_CODE_RE: Regex = Regex::new(
        r"(?i)And enter the code:\s*\n?\s*([A-Z0-9]{4,15})"
    ).expect("Failed to compile DAG code regex");

    /// Fallback regex for generic URL detection in messages.
    /// Used when the standard format isn't matched but a URL is present.
    static ref URL_RE: Regex = Regex::new(
        r"(https?://[^\s]+)"
    ).expect("Failed to compile URL regex");

    /// Fallback regex for device codes - alphanumeric, typically 7-12 chars.
    static ref CODE_RE: Regex = Regex::new(
        r"\b([A-Z0-9]{7,12})\b"
    ).expect("Failed to compile code regex");
}

/// Information extracted from a DAG authentication message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagInfo {
    /// The verification URL where the user should authenticate.
    pub url: String,
    /// The device code to enter at the verification URL.
    /// May be None if we couldn't parse it from the message.
    pub code: Option<String>,
}

/// Parse a PAM info message to detect and extract DAG authentication details.
///
/// Returns `Some(DagInfo)` if the message appears to be a DAG authentication
/// prompt, `None` otherwise.
///
/// # Examples
///
/// ```
/// use himmelblau_greeter::dag::parse_dag_message;
///
/// let msg = "Using a browser on another device, visit:\n\
///            https://microsoft.com/devicelogin\n\
///            And enter the code:\n\
///            BXT8AJLW";
///
/// let info = parse_dag_message(msg).unwrap();
/// assert_eq!(info.url, "https://microsoft.com/devicelogin");
/// assert_eq!(info.code, Some("BXT8AJLW".to_string()));
/// ```
pub fn parse_dag_message(message: &str) -> Option<DagInfo> {
    // Try the standard Himmelblau format first
    if let Some(caps) = DAG_MESSAGE_RE.captures(message) {
        let url = caps.get(1)?.as_str().to_string();
        let code = DAG_CODE_RE
            .captures(message)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        return Some(DagInfo { url, code });
    }

    // Fallback: Check for any URL with device-login-like patterns in the path
    // This helps catch variations in message formatting from different IdPs
    if let Some(caps) = URL_RE.captures(message) {
        let url = caps.get(1)?.as_str();

        // Only treat as DAG if URL looks like a device login endpoint
        let url_lower = url.to_lowercase();
        if url_lower.contains("device")
            || url_lower.contains("activate")
            || url_lower.contains("code")
        {
            let code = CODE_RE
                .captures(message)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string());

            return Some(DagInfo {
                url: url.to_string(),
                code,
            });
        }
    }

    None
}

/// Check if a message is likely a DAG authentication prompt.
///
/// This is a quick check that doesn't extract the full details.
pub fn is_dag_message(message: &str) -> bool {
    DAG_MESSAGE_RE.is_match(message)
        || (message.to_lowercase().contains("device")
            && URL_RE.is_match(message)
            && CODE_RE.is_match(message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_standard_dag_message() {
        let msg = "Using a browser on another device, visit:\n\
                   https://microsoft.com/devicelogin\n\
                   And enter the code:\n\
                   BXT8AJLW";

        let info = parse_dag_message(msg).unwrap();
        assert_eq!(info.url, "https://microsoft.com/devicelogin");
        assert_eq!(info.code, Some("BXT8AJLW".to_string()));
    }

    #[test]
    fn test_parse_dag_message_with_www() {
        let msg = "Using a browser on another device, visit:\n\
                   https://www.microsoft.com/link\n\
                   And enter the code:\n\
                   ABC123XYZ";

        let info = parse_dag_message(msg).unwrap();
        assert_eq!(info.url, "https://www.microsoft.com/link");
        assert_eq!(info.code, Some("ABC123XYZ".to_string()));
    }

    #[test]
    fn test_parse_dag_message_generic_oidc() {
        let msg = "Using a browser on another device, visit:\n\
                   https://login.example.org/device\n\
                   And enter the code:\n\
                   TESTCODE1";

        let info = parse_dag_message(msg).unwrap();
        assert_eq!(info.url, "https://login.example.org/device");
        assert_eq!(info.code, Some("TESTCODE1".to_string()));
    }

    #[test]
    fn test_parse_dag_message_no_code() {
        let msg = "Using a browser on another device, visit:\n\
                   https://example.com/devicelogin";

        let info = parse_dag_message(msg).unwrap();
        assert_eq!(info.url, "https://example.com/devicelogin");
        assert_eq!(info.code, None);
    }

    #[test]
    fn test_non_dag_message() {
        let msg = "Please enter your password:";
        assert!(parse_dag_message(msg).is_none());
    }

    #[test]
    fn test_non_dag_url_message() {
        // A message with a URL but not a DAG flow
        let msg = "For more info, visit https://example.com/help";
        assert!(parse_dag_message(msg).is_none());
    }

    #[test]
    fn test_is_dag_message() {
        assert!(is_dag_message(
            "Using a browser on another device, visit:\nhttps://example.com/device"
        ));
        assert!(!is_dag_message("Enter your password:"));
    }

    #[test]
    fn test_dag_message_inline_format() {
        // Some systems might format it slightly differently
        let msg =
            "Using a browser on another device, visit: https://idp.example.com/device/activate And enter the code: ABCD1234";

        let info = parse_dag_message(msg).unwrap();
        assert_eq!(info.url, "https://idp.example.com/device/activate");
        assert_eq!(info.code, Some("ABCD1234".to_string()));
    }
}
