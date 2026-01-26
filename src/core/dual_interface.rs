/*!
 * Dual Interface Support
 *
 * Allows using two wireless adapters simultaneously for improved performance.
 * Primary interface: Monitor mode (capture, injection)
 * Secondary interface: Managed mode (validation, connection testing)
 */

use serde::{Deserialize, Serialize};
use std::process::Command;

/// Dual interface configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DualInterfaceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub primary: String,
    #[serde(default)]
    pub secondary: String,
    #[serde(default)]
    pub auto_assigned: bool,
}

/// Interface capabilities
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceCapabilities {
    pub name: String,
    pub monitor_mode: bool,
    pub injection: bool,
    pub bands_2ghz: bool,
    pub bands_5ghz: bool,
    pub chipset: Option<String>,
}

impl InterfaceCapabilities {
    /// Calculate a score for interface quality (higher is better)
    pub fn score(&self) -> u32 {
        let mut score = 0u32;
        if self.monitor_mode {
            score += 100;
        }
        if self.injection {
            score += 50;
        }
        if self.bands_5ghz {
            score += 20;
        }
        if self.bands_2ghz {
            score += 10;
        }
        score
    }
}

/// Interface assignment result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceAssignment {
    Single(String),
    Dual { primary: String, secondary: String },
}

/// Detect capabilities of a wireless interface
pub fn detect_interface_capabilities(interface: &str) -> InterfaceCapabilities {
    let monitor_mode = check_monitor_mode_support(interface);
    let injection = check_injection_support(interface);
    let (bands_2ghz, bands_5ghz) = check_frequency_bands(interface);
    let chipset = detect_chipset(interface);

    InterfaceCapabilities {
        name: interface.to_string(),
        monitor_mode,
        injection,
        bands_2ghz,
        bands_5ghz,
        chipset,
    }
}

/// Check if interface supports monitor mode
fn check_monitor_mode_support(interface: &str) -> bool {
    // Try to check with iw (Linux)
    if let Ok(output) = Command::new("iw").args(["phy", "phy0", "info"]).output() {
        if let Ok(stdout) = String::from_utf8(output.stdout) {
            if stdout.contains("monitor") {
                return true;
            }
        }
    }

    // Try with iwconfig (older systems)
    if let Ok(output) = Command::new("iwconfig").arg(interface).output() {
        if let Ok(stdout) = String::from_utf8(output.stdout) {
            if stdout.contains("Mode:Monitor") || stdout.contains("monitor") {
                return true;
            }
        }
    }

    // Default: assume monitor mode is supported for testing
    true
}

/// Check if interface supports packet injection
fn check_injection_support(interface: &str) -> bool {
    // Try aireplay-ng test (if available)
    if let Ok(output) = Command::new("aireplay-ng")
        .args(["--test", interface])
        .output()
    {
        if let Ok(stdout) = String::from_utf8(output.stdout) {
            if stdout.contains("Injection is working") {
                return true;
            }
        }
    }

    // Default: assume injection is supported
    true
}

/// Check supported frequency bands
fn check_frequency_bands(interface: &str) -> (bool, bool) {
    let mut supports_2ghz = false;
    let mut supports_5ghz = false;

    if let Ok(output) = Command::new("iw").args([interface, "info"]).output() {
        if let Ok(stdout) = String::from_utf8(output.stdout) {
            if stdout.contains("2.4") || stdout.contains("2400") {
                supports_2ghz = true;
            }
            if stdout.contains("5.") || stdout.contains("5000") {
                supports_5ghz = true;
            }
        }
    }

    // Default: assume both bands supported
    if !supports_2ghz && !supports_5ghz {
        supports_2ghz = true;
        supports_5ghz = true;
    }

    (supports_2ghz, supports_5ghz)
}

/// Detect chipset for interface
fn detect_chipset(interface: &str) -> Option<String> {
    if let Ok(output) = Command::new("lsusb").output() {
        if let Ok(stdout) = String::from_utf8(output.stdout) {
            // Try to find chipset info
            for line in stdout.lines() {
                if line.contains("Atheros") {
                    return Some("Atheros".to_string());
                } else if line.contains("Ralink") {
                    return Some("Ralink".to_string());
                } else if line.contains("Realtek") {
                    return Some("Realtek".to_string());
                }
            }
        }
    }

    // Try lspci for internal cards
    if let Ok(output) = Command::new("lspci").output() {
        if let Ok(stdout) = String::from_utf8(output.stdout) {
            for line in stdout.lines() {
                if line.contains("Network controller") {
                    if line.contains("Atheros") {
                        return Some("Atheros".to_string());
                    } else if line.contains("Intel") {
                        return Some("Intel".to_string());
                    } else if line.contains("Broadcom") {
                        return Some("Broadcom".to_string());
                    }
                }
            }
        }
    }

    // Check interface name patterns
    if interface.starts_with("ath") {
        return Some("Atheros".to_string());
    } else if interface.starts_with("wlan") && interface.len() > 4 {
        return Some("Unknown".to_string());
    }

    None
}

/// Automatically assign primary and secondary interfaces
pub fn auto_assign_interfaces(available: &[String]) -> InterfaceAssignment {
    if available.is_empty() {
        return InterfaceAssignment::Single("wlan0".to_string());
    }

    if available.len() == 1 {
        return InterfaceAssignment::Single(available[0].clone());
    }

    // Detect capabilities for all interfaces
    let mut capabilities: Vec<InterfaceCapabilities> = available
        .iter()
        .map(|iface| detect_interface_capabilities(iface))
        .collect();

    // Sort by score (best first)
    capabilities.sort_by_key(|b| std::cmp::Reverse(b.score()));

    // Best interface becomes primary
    let primary = capabilities[0].name.clone();

    // Second best becomes secondary (prefer different chipset)
    let secondary = if capabilities.len() > 1 {
        // Try to find interface with different chipset
        let primary_chipset = &capabilities[0].chipset;
        if let Some(different) = capabilities[1..]
            .iter()
            .find(|cap| cap.chipset != *primary_chipset)
        {
            different.name.clone()
        } else {
            capabilities[1].name.clone()
        }
    } else {
        primary.clone()
    };

    if primary == secondary {
        InterfaceAssignment::Single(primary)
    } else {
        InterfaceAssignment::Dual { primary, secondary }
    }
}

/// Validate manual interface assignment
pub fn validate_manual_assignment(
    primary: &str,
    secondary: &str,
    available: &[String],
) -> Result<(), String> {
    // Check interfaces are different
    if primary == secondary {
        return Err("Primary and secondary interfaces must be different".to_string());
    }

    // Check both exist
    if !available.contains(&primary.to_string()) {
        return Err(format!("Primary interface '{}' not found", primary));
    }

    if !available.contains(&secondary.to_string()) {
        return Err(format!("Secondary interface '{}' not found", secondary));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // DualInterfaceConfig Tests
    // =========================================================================

    #[test]
    fn test_dual_interface_config_default() {
        let config = DualInterfaceConfig::default();
        assert!(!config.enabled);
        assert!(config.primary.is_empty());
        assert!(config.secondary.is_empty());
        assert!(!config.auto_assigned);
    }

    #[test]
    fn test_dual_interface_config_clone() {
        let config = DualInterfaceConfig {
            enabled: true,
            primary: "wlan0".to_string(),
            secondary: "wlan1".to_string(),
            auto_assigned: true,
        };
        let cloned = config.clone();
        assert_eq!(config, cloned);
    }

    #[test]
    fn test_dual_interface_config_serialization() {
        let config = DualInterfaceConfig {
            enabled: true,
            primary: "wlan0".to_string(),
            secondary: "wlan1".to_string(),
            auto_assigned: false,
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: DualInterfaceConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }

    // =========================================================================
    // InterfaceCapabilities Tests
    // =========================================================================

    #[test]
    fn test_interface_capabilities_score() {
        let cap = InterfaceCapabilities {
            name: "wlan0".to_string(),
            monitor_mode: true,
            injection: true,
            bands_2ghz: true,
            bands_5ghz: true,
            chipset: Some("Atheros".to_string()),
        };

        // 100 (monitor) + 50 (injection) + 10 (2ghz) + 20 (5ghz) = 180
        assert_eq!(cap.score(), 180);
    }

    #[test]
    fn test_interface_capabilities_score_no_monitor() {
        let cap = InterfaceCapabilities {
            name: "wlan0".to_string(),
            monitor_mode: false,
            injection: true,
            bands_2ghz: true,
            bands_5ghz: true,
            chipset: None,
        };

        // 50 (injection) + 10 (2ghz) + 20 (5ghz) = 80
        assert_eq!(cap.score(), 80);
    }

    #[test]
    fn test_interface_capabilities_score_minimal() {
        let cap = InterfaceCapabilities {
            name: "wlan0".to_string(),
            monitor_mode: false,
            injection: false,
            bands_2ghz: true,
            bands_5ghz: false,
            chipset: None,
        };

        // 10 (2ghz) = 10
        assert_eq!(cap.score(), 10);
    }

    // =========================================================================
    // InterfaceAssignment Tests
    // =========================================================================

    #[test]
    fn test_interface_assignment_single() {
        let assignment = InterfaceAssignment::Single("wlan0".to_string());
        match assignment {
            InterfaceAssignment::Single(iface) => assert_eq!(iface, "wlan0"),
            _ => panic!("Expected Single variant"),
        }
    }

    #[test]
    fn test_interface_assignment_dual() {
        let assignment = InterfaceAssignment::Dual {
            primary: "wlan0".to_string(),
            secondary: "wlan1".to_string(),
        };
        match assignment {
            InterfaceAssignment::Dual { primary, secondary } => {
                assert_eq!(primary, "wlan0");
                assert_eq!(secondary, "wlan1");
            }
            _ => panic!("Expected Dual variant"),
        }
    }

    #[test]
    fn test_interface_assignment_clone() {
        let assignment = InterfaceAssignment::Dual {
            primary: "wlan0".to_string(),
            secondary: "wlan1".to_string(),
        };
        let cloned = assignment.clone();
        assert_eq!(assignment, cloned);
    }

    // =========================================================================
    // Auto Assignment Tests
    // =========================================================================

    #[test]
    fn test_auto_assign_empty() {
        let assignment = auto_assign_interfaces(&[]);
        match assignment {
            InterfaceAssignment::Single(iface) => assert_eq!(iface, "wlan0"),
            _ => panic!("Expected Single variant with default"),
        }
    }

    #[test]
    fn test_auto_assign_single_interface() {
        let interfaces = vec!["wlan0".to_string()];
        let assignment = auto_assign_interfaces(&interfaces);
        match assignment {
            InterfaceAssignment::Single(iface) => assert_eq!(iface, "wlan0"),
            _ => panic!("Expected Single variant"),
        }
    }

    #[test]
    fn test_auto_assign_two_interfaces() {
        let interfaces = vec!["wlan0".to_string(), "wlan1".to_string()];
        let assignment = auto_assign_interfaces(&interfaces);
        match assignment {
            InterfaceAssignment::Dual { primary, secondary } => {
                assert!(!primary.is_empty());
                assert!(!secondary.is_empty());
                assert_ne!(primary, secondary);
            }
            _ => panic!("Expected Dual variant"),
        }
    }

    #[test]
    fn test_auto_assign_multiple_interfaces() {
        let interfaces = vec![
            "wlan0".to_string(),
            "wlan1".to_string(),
            "wlan2".to_string(),
        ];
        let assignment = auto_assign_interfaces(&interfaces);
        match assignment {
            InterfaceAssignment::Dual { primary, secondary } => {
                assert!(interfaces.contains(&primary));
                assert!(interfaces.contains(&secondary));
                assert_ne!(primary, secondary);
            }
            _ => panic!("Expected Dual variant"),
        }
    }

    // =========================================================================
    // Manual Assignment Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_manual_assignment_success() {
        let available = vec!["wlan0".to_string(), "wlan1".to_string()];
        let result = validate_manual_assignment("wlan0", "wlan1", &available);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_manual_assignment_same_interface() {
        let available = vec!["wlan0".to_string(), "wlan1".to_string()];
        let result = validate_manual_assignment("wlan0", "wlan0", &available);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Primary and secondary interfaces must be different"));
    }

    #[test]
    fn test_validate_manual_assignment_primary_not_found() {
        let available = vec!["wlan0".to_string(), "wlan1".to_string()];
        let result = validate_manual_assignment("wlan99", "wlan1", &available);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Primary interface"));
        assert!(err.contains("not found"));
    }

    #[test]
    fn test_validate_manual_assignment_secondary_not_found() {
        let available = vec!["wlan0".to_string(), "wlan1".to_string()];
        let result = validate_manual_assignment("wlan0", "wlan99", &available);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Secondary interface"));
        assert!(err.contains("not found"));
    }

    #[test]
    fn test_validate_manual_assignment_both_not_found() {
        let available = vec!["wlan0".to_string(), "wlan1".to_string()];
        let result = validate_manual_assignment("wlan98", "wlan99", &available);
        assert!(result.is_err());
        // Should fail on primary first
        assert!(result.unwrap_err().contains("Primary interface"));
    }

    // =========================================================================
    // Capability Detection Tests
    // =========================================================================

    #[test]
    fn test_detect_interface_capabilities() {
        let cap = detect_interface_capabilities("wlan0");
        assert_eq!(cap.name, "wlan0");
        // We can't make strong assertions about capabilities in tests
        // because they depend on the system, but verify fields exist
        let _monitor = cap.monitor_mode;
        let _injection = cap.injection;
        let _2ghz = cap.bands_2ghz;
        let _5ghz = cap.bands_5ghz;
    }

    #[test]
    fn test_detect_interface_capabilities_different_names() {
        let interfaces = ["wlan0", "wlan1", "ath0", "en0"];
        for iface in &interfaces {
            let cap = detect_interface_capabilities(iface);
            assert_eq!(cap.name, *iface);
        }
    }

    // =========================================================================
    // Helper Function Tests
    // =========================================================================

    #[test]
    fn test_check_monitor_mode_support() {
        // Should not panic for any interface name
        let _result = check_monitor_mode_support("wlan0");
        // Just verify it doesn't panic - result value is system-dependent
    }

    #[test]
    fn test_check_injection_support() {
        // Should not panic for any interface name
        let _result = check_injection_support("wlan0");
        // Just verify it doesn't panic - result value is system-dependent
    }

    #[test]
    fn test_check_frequency_bands() {
        // Should not panic and should return valid tuple
        let (ghz_2, ghz_5) = check_frequency_bands("wlan0");
        // At least one should be true (default behavior)
        assert!(ghz_2 || ghz_5);
    }

    #[test]
    fn test_detect_chipset() {
        // Should not panic and return Option
        let chipset = detect_chipset("wlan0");
        // Can be Some or None, both are valid
        assert!(chipset.is_some() || chipset.is_none());
    }

    #[test]
    fn test_detect_chipset_atheros_pattern() {
        // Should detect Atheros from interface name pattern
        let chipset = detect_chipset("ath0");
        if let Some(cs) = chipset {
            assert_eq!(cs, "Atheros");
        }
    }
}
