/*! Auto Attack Mode - Orchestrates multiple attack types sequentially */

use std::path::PathBuf;
use std::time::Duration;

/// Types of attacks that can be executed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackType {
    /// WPS Pixie Dust attack (fast, WPA2 only)
    WpsPixieDust,
    /// WPS PIN bruteforce (slow, not used in auto sequence)
    WpsPinBruteforce,
    /// WPA3-Transition downgrade attack
    Wpa3TransitionDowngrade,
    /// WPA3 SAE handshake capture
    Wpa3SaeCapture,
    /// PMKID capture attack (fast, passive)
    PmkidCapture,
    /// Standard 4-way handshake capture
    HandshakeCapture,
    /// Evil Twin phishing attack (slowest, highest success)
    EvilTwin,
}

impl AttackType {
    /// Get human-readable name for display
    pub fn display_name(&self) -> &str {
        match self {
            Self::WpsPixieDust => "WPS Pixie Dust",
            Self::WpsPinBruteforce => "WPS PIN Bruteforce",
            Self::Wpa3TransitionDowngrade => "WPA3 Transition Downgrade",
            Self::Wpa3SaeCapture => "WPA3 SAE Capture",
            Self::PmkidCapture => "PMKID Capture",
            Self::HandshakeCapture => "Handshake Capture",
            Self::EvilTwin => "Evil Twin",
        }
    }
}

/// Status of an individual attack
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackStatus {
    /// Attack is queued but not started
    Pending,
    /// Attack is currently running
    Running,
    /// Attack succeeded
    Success,
    /// Attack failed or timed out
    Failed,
    /// Attack was skipped (e.g., due to earlier success)
    Skipped,
    /// Attack was stopped by user
    Stopped,
}

/// State of a single attack in the sequence
#[derive(Debug, Clone)]
pub struct AttackState {
    pub attack_type: AttackType,
    pub status: AttackStatus,
    pub elapsed_time: Duration,
    pub timeout: Duration,
    pub progress_message: String,
}

impl AttackState {
    /// Create a new pending attack state
    pub fn new(attack_type: AttackType, timeout: Duration) -> Self {
        Self {
            attack_type,
            status: AttackStatus::Pending,
            elapsed_time: Duration::ZERO,
            timeout,
            progress_message: "Waiting...".to_string(),
        }
    }
}

/// Configuration for auto attack sequence
#[derive(Debug, Clone)]
pub struct AutoAttackConfig {
    pub network_ssid: String,
    pub network_bssid: String,
    pub network_channel: u32,
    pub network_security: String,
    pub interface: String,
    pub output_dir: PathBuf,
}

/// Progress updates during auto attack execution
#[derive(Debug, Clone)]
pub enum AutoAttackProgress {
    /// Auto attack sequence started
    Started { total_attacks: u8 },
    /// Individual attack started
    AttackStarted {
        attack_type: AttackType,
        index: u8,
        total: u8,
    },
    /// Progress update from current attack
    AttackProgress {
        attack_type: AttackType,
        message: String,
    },
    /// Attack succeeded with result
    AttackSuccess {
        attack_type: AttackType,
        result: AutoAttackResult,
    },
    /// Attack failed
    AttackFailed {
        attack_type: AttackType,
        reason: String,
    },
    /// All attacks completed
    AllCompleted {
        successful_attack: Option<AttackType>,
    },
    /// Sequence was stopped by user
    Stopped,
    /// Error occurred
    Error(String),
}

/// Result from a successful attack
#[derive(Debug, Clone)]
pub enum AutoAttackResult {
    /// WPS attack found credentials
    WpsCredentials { pin: String, password: String },
    /// Handshake or PMKID captured
    HandshakeCaptured {
        capture_file: PathBuf,
        hash_file: PathBuf,
    },
    /// Evil Twin captured password
    EvilTwinPassword { password: String },
}

/// Final result after all attacks complete
#[derive(Debug, Clone)]
pub enum AutoAttackFinalResult {
    /// At least one attack succeeded
    Success {
        attack_type: AttackType,
        result: AutoAttackResult,
    },
    /// All attacks failed
    AllFailed,
    /// Stopped by user before completion
    Stopped,
    /// Error occurred
    Error(String),
}

/// Determine which attacks to run based on network security type
///
/// # Arguments
/// * `security` - Network security type string (e.g., "WPA2", "WPA3-Transition")
///
/// # Returns
/// Ordered list of attacks to attempt
pub fn determine_attack_sequence(security: &str) -> Vec<AttackType> {
    let security_upper = security.to_uppercase();

    if security_upper.contains("WPA3") {
        if security_upper.contains("TRANSITION") || security_upper.contains("WPA2") {
            // WPA3-Transition: Try downgrade first, then standard attacks
            vec![
                AttackType::Wpa3TransitionDowngrade,
                AttackType::PmkidCapture,
                AttackType::HandshakeCapture,
                AttackType::EvilTwin,
            ]
        } else {
            // WPA3-Only: Limited attack surface
            vec![AttackType::Wpa3SaeCapture, AttackType::EvilTwin]
        }
    } else if security_upper.contains("WPA2") {
        // WPA2: Full attack suite including WPS
        vec![
            AttackType::WpsPixieDust,
            AttackType::PmkidCapture,
            AttackType::HandshakeCapture,
            AttackType::EvilTwin,
        ]
    } else if security_upper.contains("WPA") {
        // WPA (original): No WPS support
        vec![
            AttackType::PmkidCapture,
            AttackType::HandshakeCapture,
            AttackType::EvilTwin,
        ]
    } else {
        // Unknown or open network
        vec![]
    }
}

/// Get timeout duration for a specific attack type
///
/// # Arguments
/// * `attack_type` - Type of attack
///
/// # Returns
/// Recommended timeout duration
pub fn get_attack_timeout(attack_type: &AttackType) -> Duration {
    match attack_type {
        AttackType::WpsPixieDust => Duration::from_secs(60),
        AttackType::WpsPinBruteforce => Duration::from_secs(3600), // 1 hour (not used)
        AttackType::PmkidCapture => Duration::from_secs(60),
        AttackType::HandshakeCapture => Duration::from_secs(300), // 5 minutes
        AttackType::Wpa3TransitionDowngrade => Duration::from_secs(30),
        AttackType::Wpa3SaeCapture => Duration::from_secs(60),
        AttackType::EvilTwin => Duration::from_secs(600), // 10 minutes
    }
}

/// Check if required tools are available for an attack type
///
/// # Arguments
/// * `attack_type` - Type of attack to check
///
/// # Returns
/// Result with error message if tool is missing
pub fn check_attack_dependencies(attack_type: &AttackType) -> Result<(), String> {
    match attack_type {
        AttackType::WpsPixieDust => {
            // Check for reaver and pixiewps
            if !command_exists("reaver") {
                return Err("reaver not found. Install with: brew install reaver (macOS) or apt install reaver (Linux)".to_string());
            }
            if !command_exists("pixiewps") {
                return Err("pixiewps not found. Install with: brew install pixiewps (macOS) or apt install pixiewps (Linux)".to_string());
            }
            Ok(())
        }
        AttackType::PmkidCapture
        | AttackType::Wpa3TransitionDowngrade
        | AttackType::Wpa3SaeCapture => {
            // Check for hcxdumptool and hcxpcapngtool
            if !command_exists("hcxdumptool") {
                return Err("hcxdumptool not found. Install with: brew install hcxdumptool (macOS) or apt install hcxdumptool (Linux)".to_string());
            }
            if !command_exists("hcxpcapngtool") {
                return Err("hcxpcapngtool not found. Install with: brew install hcxtools (macOS) or apt install hcxtools (Linux)".to_string());
            }
            Ok(())
        }
        AttackType::EvilTwin => {
            // Check for hostapd and dnsmasq
            if !command_exists("hostapd") {
                return Err("hostapd not found. Install with: brew install hostapd (macOS) or apt install hostapd (Linux)".to_string());
            }
            if !command_exists("dnsmasq") {
                return Err("dnsmasq not found. Install with: brew install dnsmasq (macOS) or apt install dnsmasq (Linux)".to_string());
            }
            Ok(())
        }
        AttackType::HandshakeCapture | AttackType::WpsPinBruteforce => {
            // No special tools needed beyond pcap
            Ok(())
        }
    }
}

/// Check if a command exists in PATH
fn command_exists(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_attack_sequence_wpa2() {
        let attacks = determine_attack_sequence("WPA2");
        assert_eq!(attacks.len(), 4);
        assert_eq!(attacks[0], AttackType::WpsPixieDust);
        assert_eq!(attacks[1], AttackType::PmkidCapture);
        assert_eq!(attacks[2], AttackType::HandshakeCapture);
        assert_eq!(attacks[3], AttackType::EvilTwin);
    }

    #[test]
    fn test_determine_attack_sequence_wpa2_psk() {
        let attacks = determine_attack_sequence("WPA2-PSK");
        assert_eq!(attacks.len(), 4);
        assert_eq!(attacks[0], AttackType::WpsPixieDust);
    }

    #[test]
    fn test_determine_attack_sequence_wpa3_transition() {
        let attacks = determine_attack_sequence("WPA3-Transition");
        assert_eq!(attacks.len(), 4);
        assert_eq!(attacks[0], AttackType::Wpa3TransitionDowngrade);
        assert_eq!(attacks[1], AttackType::PmkidCapture);
        assert_eq!(attacks[2], AttackType::HandshakeCapture);
        assert_eq!(attacks[3], AttackType::EvilTwin);
        assert!(!attacks.contains(&AttackType::WpsPixieDust));
    }

    #[test]
    fn test_determine_attack_sequence_wpa3_wpa2() {
        let attacks = determine_attack_sequence("WPA3/WPA2");
        assert_eq!(attacks[0], AttackType::Wpa3TransitionDowngrade);
    }

    #[test]
    fn test_determine_attack_sequence_wpa3_only() {
        let attacks = determine_attack_sequence("WPA3");
        assert_eq!(attacks.len(), 2);
        assert_eq!(attacks[0], AttackType::Wpa3SaeCapture);
        assert_eq!(attacks[1], AttackType::EvilTwin);
    }

    #[test]
    fn test_determine_attack_sequence_wpa3_sae() {
        let attacks = determine_attack_sequence("WPA3-SAE");
        assert_eq!(attacks.len(), 2);
        assert_eq!(attacks[0], AttackType::Wpa3SaeCapture);
    }

    #[test]
    fn test_determine_attack_sequence_wpa() {
        let attacks = determine_attack_sequence("WPA");
        assert_eq!(attacks.len(), 3);
        assert_eq!(attacks[0], AttackType::PmkidCapture);
        assert_eq!(attacks[1], AttackType::HandshakeCapture);
        assert_eq!(attacks[2], AttackType::EvilTwin);
        assert!(!attacks.contains(&AttackType::WpsPixieDust));
    }

    #[test]
    fn test_determine_attack_sequence_wpa_psk() {
        let attacks = determine_attack_sequence("WPA-PSK");
        assert_eq!(attacks.len(), 3);
        assert!(!attacks.contains(&AttackType::WpsPixieDust));
    }

    #[test]
    fn test_determine_attack_sequence_case_insensitive() {
        let attacks1 = determine_attack_sequence("wpa2");
        let attacks2 = determine_attack_sequence("WPA2");
        let attacks3 = determine_attack_sequence("Wpa2");
        assert_eq!(attacks1, attacks2);
        assert_eq!(attacks2, attacks3);
    }

    #[test]
    fn test_determine_attack_sequence_open_network() {
        let attacks = determine_attack_sequence("Open");
        assert_eq!(attacks.len(), 0);
    }

    #[test]
    fn test_determine_attack_sequence_wep() {
        let attacks = determine_attack_sequence("WEP");
        assert_eq!(attacks.len(), 0);
    }

    #[test]
    fn test_attack_timeout_values() {
        assert_eq!(
            get_attack_timeout(&AttackType::WpsPixieDust),
            Duration::from_secs(60)
        );
        assert_eq!(
            get_attack_timeout(&AttackType::PmkidCapture),
            Duration::from_secs(60)
        );
        assert_eq!(
            get_attack_timeout(&AttackType::HandshakeCapture),
            Duration::from_secs(300)
        );
        assert_eq!(
            get_attack_timeout(&AttackType::Wpa3TransitionDowngrade),
            Duration::from_secs(30)
        );
        assert_eq!(
            get_attack_timeout(&AttackType::Wpa3SaeCapture),
            Duration::from_secs(60)
        );
        assert_eq!(
            get_attack_timeout(&AttackType::EvilTwin),
            Duration::from_secs(600)
        );
    }

    #[test]
    fn test_attack_state_new() {
        let state = AttackState::new(AttackType::WpsPixieDust, Duration::from_secs(60));
        assert_eq!(state.attack_type, AttackType::WpsPixieDust);
        assert_eq!(state.status, AttackStatus::Pending);
        assert_eq!(state.elapsed_time, Duration::ZERO);
        assert_eq!(state.timeout, Duration::from_secs(60));
        assert_eq!(state.progress_message, "Waiting...");
    }

    #[test]
    fn test_attack_type_display_names() {
        assert_eq!(AttackType::WpsPixieDust.display_name(), "WPS Pixie Dust");
        assert_eq!(
            AttackType::Wpa3TransitionDowngrade.display_name(),
            "WPA3 Transition Downgrade"
        );
        assert_eq!(
            AttackType::HandshakeCapture.display_name(),
            "Handshake Capture"
        );
    }
}
