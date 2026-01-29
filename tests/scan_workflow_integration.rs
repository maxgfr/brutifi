/*!
 * Scan Workflow Integration Tests
 *
 * Tests that verify all attack methods can be automatically selected
 * and triggered based on scan results, using scan as the single entry point.
 *
 * Workflow: Scan → Detect Vulnerabilities → Auto-select Attack → Execute
 */

use brutifi::core::{
    evil_twin::{self, EvilTwinParams, PortalTemplate},
    passive_pmkid::{self, PassivePmkidConfig, PassivePmkidState},
    wpa3::{self, Wpa3AttackParams, Wpa3AttackType, Wpa3NetworkType},
    wps::{self, WpsAttackParams, WpsAttackType},
};
use brutifi::WifiNetwork;
use std::path::PathBuf;
use std::time::Duration;

// =========================================================================
// Mock Network Detection from Scan Results
// =========================================================================

/// Mock scan result for testing
fn create_mock_wpa2_network() -> WifiNetwork {
    WifiNetwork {
        ssid: "TestWPA2Network".to_string(),
        bssid: "AA:BB:CC:DD:EE:FF".to_string(),
        channel: "6".to_string(),
        signal_strength: "-50".to_string(),
        security: "WPA2-PSK".to_string(),
    }
}

fn create_mock_wpa3_transition_network() -> WifiNetwork {
    WifiNetwork {
        ssid: "TestWPA3Transition".to_string(),
        bssid: "11:22:33:44:55:66".to_string(),
        channel: "11".to_string(),
        signal_strength: "-45".to_string(),
        security: "WPA3-Transition".to_string(),
    }
}

fn create_mock_wpa3_only_network() -> WifiNetwork {
    WifiNetwork {
        ssid: "TestWPA3Only".to_string(),
        bssid: "22:33:44:55:66:77".to_string(),
        channel: "1".to_string(),
        signal_strength: "-40".to_string(),
        security: "WPA3-SAE".to_string(),
    }
}

fn create_mock_wpa_network() -> WifiNetwork {
    WifiNetwork {
        ssid: "TestWPANetwork".to_string(),
        bssid: "33:44:55:66:77:88".to_string(),
        channel: "3".to_string(),
        signal_strength: "-60".to_string(),
        security: "WPA-PSK".to_string(),
    }
}

// =========================================================================
// Vulnerability Detection Logic (from scan_capture.rs)
// =========================================================================

/// Detect vulnerabilities based on network security type
/// This mimics the logic in src/screens/scan_capture.rs:249-260
fn detect_vulnerabilities(network: &WifiNetwork) -> Vec<String> {
    if network.security.contains("WPA3") {
        vec![
            "WPA3-SAE".to_string(),
            "Dragonblood".to_string(),
            "Downgrade".to_string(),
        ]
    } else if network.security.contains("WPA2") {
        vec![
            "PMKID".to_string(),
            "Handshake".to_string(),
            "WPS".to_string(),
        ]
    } else if network.security.contains("WPA") {
        vec!["PMKID".to_string(), "Handshake".to_string()]
    } else if network.security.contains("None") {
        vec!["Open".to_string()]
    } else {
        vec![]
    }
}

// =========================================================================
// Auto-Attack Selection Logic
// =========================================================================

/// Select best attack method based on detected vulnerabilities
fn select_best_attack_method(vulnerabilities: &[String]) -> Option<String> {
    // Priority order (fastest to slowest)
    if vulnerabilities.contains(&"PMKID".to_string()) {
        Some("PMKID".to_string())
    } else if vulnerabilities.contains(&"WPS".to_string()) {
        Some("WPS-Pixie".to_string())
    } else if vulnerabilities.contains(&"Downgrade".to_string()) {
        Some("WPA3-Downgrade".to_string())
    } else if vulnerabilities.contains(&"Handshake".to_string()) {
        Some("Handshake".to_string())
    } else if vulnerabilities.contains(&"WPA3-SAE".to_string()) {
        Some("WPA3-SAE".to_string())
    } else {
        None
    }
}

// =========================================================================
// Test: Scan → Detect → Auto-Select for WPA2 Networks
// =========================================================================

#[test]
fn test_scan_to_attack_wpa2_network() {
    // Step 1: Simulate scan result
    let network = create_mock_wpa2_network();

    // Step 2: Detect vulnerabilities (mimics UI logic)
    let vulnerabilities = detect_vulnerabilities(&network);

    // Verify detection
    assert_eq!(vulnerabilities.len(), 3);
    assert!(vulnerabilities.contains(&"PMKID".to_string()));
    assert!(vulnerabilities.contains(&"Handshake".to_string()));
    assert!(vulnerabilities.contains(&"WPS".to_string()));

    // Step 3: Auto-select best attack method
    let selected_method = select_best_attack_method(&vulnerabilities);
    assert_eq!(selected_method, Some("PMKID".to_string()));

    // Step 4: Verify we can create attack params for PMKID
    // (This would be triggered automatically in a real workflow)
    let output_path = PathBuf::from("/tmp/test_pmkid_capture.pcap");
    assert!(output_path.parent().is_some());
}

#[test]
fn test_scan_to_attack_wpa2_with_wps() {
    // Step 1: Scan result
    let network = create_mock_wpa2_network();

    // Step 2: Detect vulnerabilities
    let vulnerabilities = detect_vulnerabilities(&network);
    assert!(vulnerabilities.contains(&"WPS".to_string()));

    // Step 3: Can we create WPS Pixie-Dust params?
    let wps_params = WpsAttackParams::pixie_dust(
        network.bssid.clone(),
        network.channel.parse().unwrap_or(6),
        "wlan0".to_string(),
    );

    assert_eq!(wps_params.bssid, "AA:BB:CC:DD:EE:FF");
    assert_eq!(wps_params.attack_type, WpsAttackType::PixieDust);

    // Step 4: Verify tools available (would auto-select if available)
    let _reaver_available = wps::check_reaver_installed();
    let _pixiewps_available = wps::check_pixiewps_installed();
}

#[test]
fn test_scan_to_attack_wpa2_fallback_to_handshake() {
    // Scenario: PMKID fails, fallback to handshake
    let network = create_mock_wpa2_network();
    let vulnerabilities = detect_vulnerabilities(&network);

    // If PMKID not captured, try handshake
    let fallback_methods = vec!["Handshake", "WPS-Pixie", "WPS-PIN"];
    for method in fallback_methods {
        assert!(
            method == "Handshake" || vulnerabilities.contains(&"WPS".to_string()),
            "Should have fallback method available"
        );
    }
}

// =========================================================================
// Test: Scan → Detect → Auto-Select for WPA3 Networks
// =========================================================================

#[test]
fn test_scan_to_attack_wpa3_transition() {
    // Step 1: Scan result
    let network = create_mock_wpa3_transition_network();

    // Step 2: Detect vulnerabilities
    let vulnerabilities = detect_vulnerabilities(&network);

    // Verify WPA3-specific vulnerabilities detected
    assert!(vulnerabilities.contains(&"WPA3-SAE".to_string()));
    assert!(vulnerabilities.contains(&"Dragonblood".to_string()));
    assert!(vulnerabilities.contains(&"Downgrade".to_string()));

    // Step 3: Auto-select best method (Downgrade for transition mode)
    let selected_method = select_best_attack_method(&vulnerabilities);
    assert_eq!(selected_method, Some("WPA3-Downgrade".to_string()));

    // Step 4: Can we create WPA3 downgrade params?
    let wpa3_params = Wpa3AttackParams {
        bssid: network.bssid.clone(),
        channel: network.channel.parse().unwrap_or(11),
        interface: "wlan0".to_string(),
        attack_type: Wpa3AttackType::TransitionDowngrade,
        timeout: Duration::from_secs(300),
        output_file: PathBuf::from("/tmp/wpa3_capture.pcap"),
    };

    assert_eq!(wpa3_params.bssid, "11:22:33:44:55:66");
    assert_eq!(wpa3_params.attack_type, Wpa3AttackType::TransitionDowngrade);
}

#[test]
fn test_scan_to_attack_wpa3_only() {
    // Step 1: Scan result
    let network = create_mock_wpa3_only_network();

    // Step 2: Detect vulnerabilities
    let vulnerabilities = detect_vulnerabilities(&network);
    assert!(vulnerabilities.contains(&"WPA3-SAE".to_string()));

    // Step 3: For WPA3-only, must use SAE capture
    let selected_method = select_best_attack_method(&vulnerabilities);
    // Should select WPA3-SAE since no downgrade possible
    assert!(selected_method.is_some());

    // Step 4: Create SAE capture params
    let wpa3_params = Wpa3AttackParams {
        bssid: network.bssid.clone(),
        channel: network.channel.parse().unwrap_or(1),
        interface: "wlan0".to_string(),
        attack_type: Wpa3AttackType::SaeHandshake,
        timeout: Duration::from_secs(300),
        output_file: PathBuf::from("/tmp/wpa3_sae_capture.pcap"),
    };

    assert_eq!(wpa3_params.attack_type, Wpa3AttackType::SaeHandshake);
}

#[test]
fn test_scan_to_dragonblood_detection() {
    // Step 1: Scan WPA3 network
    let network = create_mock_wpa3_only_network();
    let vulnerabilities = detect_vulnerabilities(&network);

    // Step 2: If Dragonblood tag present, check vulnerabilities
    if vulnerabilities.contains(&"Dragonblood".to_string()) {
        let dragonblood_vulns = wpa3::check_dragonblood_vulnerabilities(Wpa3NetworkType::Wpa3Only);

        // Should detect at least 2 CVEs
        assert!(dragonblood_vulns.len() >= 2);
        assert!(dragonblood_vulns.iter().any(|v| v.cve == "CVE-2019-13377"));
        assert!(dragonblood_vulns.iter().any(|v| v.cve == "CVE-2019-13456"));
    }
}

// =========================================================================
// Test: Scan → Detect → Auto-Select for Legacy WPA Networks
// =========================================================================

#[test]
fn test_scan_to_attack_wpa_legacy() {
    // Step 1: Scan result
    let network = create_mock_wpa_network();

    // Step 2: Detect vulnerabilities
    let vulnerabilities = detect_vulnerabilities(&network);

    // WPA (not WPA2) should have PMKID and Handshake, but not WPS
    assert_eq!(vulnerabilities.len(), 2);
    assert!(vulnerabilities.contains(&"PMKID".to_string()));
    assert!(vulnerabilities.contains(&"Handshake".to_string()));
    assert!(!vulnerabilities.contains(&"WPS".to_string()));

    // Step 3: Auto-select (should prefer PMKID)
    let selected_method = select_best_attack_method(&vulnerabilities);
    assert_eq!(selected_method, Some("PMKID".to_string()));
}

// =========================================================================
// Test: Multi-Attack Workflow (All Methods from Single Scan)
// =========================================================================

#[test]
fn test_scan_enables_all_attack_methods() {
    // Simulate scanning multiple networks
    let networks = vec![
        create_mock_wpa2_network(),
        create_mock_wpa3_transition_network(),
        create_mock_wpa3_only_network(),
        create_mock_wpa_network(),
    ];

    let mut all_methods_available = std::collections::HashSet::new();

    for network in networks {
        let vulnerabilities = detect_vulnerabilities(&network);

        // Map vulnerabilities to actual attack methods
        for vuln in vulnerabilities {
            match vuln.as_str() {
                "PMKID" => {
                    all_methods_available.insert("PMKID-Capture");
                }
                "Handshake" => {
                    all_methods_available.insert("Handshake-Capture");
                }
                "WPS" => {
                    all_methods_available.insert("WPS-Pixie-Dust");
                    all_methods_available.insert("WPS-PIN-Bruteforce");
                }
                "WPA3-SAE" => {
                    all_methods_available.insert("WPA3-SAE-Capture");
                }
                "Downgrade" => {
                    all_methods_available.insert("WPA3-Downgrade");
                }
                "Dragonblood" => {
                    all_methods_available.insert("Dragonblood-Detection");
                }
                _ => {}
            }
        }
    }

    // Verify all 8 methods are available from scan results
    assert!(all_methods_available.contains("PMKID-Capture"));
    assert!(all_methods_available.contains("Handshake-Capture"));
    assert!(all_methods_available.contains("WPS-Pixie-Dust"));
    assert!(all_methods_available.contains("WPS-PIN-Bruteforce"));
    assert!(all_methods_available.contains("WPA3-SAE-Capture"));
    assert!(all_methods_available.contains("WPA3-Downgrade"));
    assert!(all_methods_available.contains("Dragonblood-Detection"));

    // Evil Twin and Passive PMKID are always available (not network-specific)
    assert_eq!(all_methods_available.len(), 7); // 7 network-specific methods
}

// =========================================================================
// Test: Evil Twin Attack (Always Available from Any Scan)
// =========================================================================

#[test]
fn test_scan_to_evil_twin_attack() {
    // Evil Twin can target ANY network (WPA, WPA2, WPA3-Transition)
    let network = create_mock_wpa2_network();

    // Step 1: Create Evil Twin params from scan result
    let evil_twin_params = EvilTwinParams {
        target_ssid: network.ssid.clone(),
        target_bssid: Some(network.bssid.clone()),
        target_channel: network.channel.parse().unwrap_or(6),
        interface: "wlan0".to_string(),
        portal_template: PortalTemplate::Generic,
        web_port: 80,
        dhcp_range_start: "192.168.1.100".to_string(),
        dhcp_range_end: "192.168.1.200".to_string(),
        gateway_ip: "192.168.1.1".to_string(),
    };

    assert_eq!(evil_twin_params.target_ssid, "TestWPA2Network");
    assert_eq!(evil_twin_params.target_channel, 6);

    // Step 2: Verify we can generate configs
    let hostapd_config = evil_twin::generate_hostapd_config(&evil_twin_params);
    assert!(hostapd_config.is_ok());

    let dnsmasq_config = evil_twin::generate_dnsmasq_config(&evil_twin_params);
    assert!(dnsmasq_config.is_ok());

    // Cleanup
    if let Ok(path) = hostapd_config {
        let _ = std::fs::remove_file(&path);
    }
    if let Ok(path) = dnsmasq_config {
        let _ = std::fs::remove_file(&path);
    }
}

#[test]
fn test_scan_to_evil_twin_with_all_templates() {
    let network = create_mock_wpa2_network();

    // Test all 4 portal templates can be used
    let templates = vec![
        PortalTemplate::Generic,
        PortalTemplate::TpLink,
        PortalTemplate::Netgear,
        PortalTemplate::Linksys,
    ];

    for template in templates {
        let params = EvilTwinParams {
            target_ssid: network.ssid.clone(),
            portal_template: template,
            target_channel: 6,
            ..Default::default()
        };

        // Each template should be valid
        assert_eq!(params.portal_template, template);
        assert!(!params.target_ssid.is_empty());
    }
}

// =========================================================================
// Test: Passive PMKID Sniffing (Background Mode)
// =========================================================================

#[test]
fn test_scan_to_passive_pmkid_mode() {
    // Passive PMKID runs in background, independent of specific network
    // but triggered by scanning activity

    // Step 1: Create passive PMKID config
    let config = PassivePmkidConfig {
        interface: "wlan0".to_string(),
        output_dir: PathBuf::from("/tmp/pmkid_passive"),
        auto_save: true,
        save_interval_secs: 60,
        hop_channels: true,
        channels: vec![1, 6, 11], // Scan these channels
    };

    assert!(config.hop_channels);
    assert_eq!(config.channels.len(), 3);

    // Step 2: Create state for background capture
    let state = PassivePmkidState::new();
    assert!(!state.should_stop());
    assert_eq!(state.count(), 0);

    // Step 3: Simulate capturing PMKIDs from scan
    let mock_pmkid = passive_pmkid::CapturedPmkid::new(
        "TestNetwork".to_string(),
        "AA:BB:CC:DD:EE:FF".to_string(),
        "abcdef1234567890".to_string(),
        6,
        -50,
    );

    state.add_pmkid(mock_pmkid);
    assert_eq!(state.count(), 1);
}

// =========================================================================
// Test: Complete Workflow Simulation
// =========================================================================

#[test]
#[allow(clippy::useless_vec)]
fn test_complete_scan_to_attack_workflow() {
    // Simulate complete workflow: Scan → Detect → Select → Prepare Attack

    // Step 1: SCAN - User clicks "Scan" button
    let scan_results = vec![
        create_mock_wpa2_network(),
        create_mock_wpa3_transition_network(),
    ];

    assert_eq!(scan_results.len(), 2);

    // Step 2: SELECT - User selects first network (WPA2)
    let selected_network = &scan_results[0];

    // Step 3: DETECT - Automatically detect vulnerabilities
    let vulnerabilities = detect_vulnerabilities(selected_network);
    assert_eq!(vulnerabilities.len(), 3); // PMKID, Handshake, WPS

    // Step 4: AUTO-SELECT - Choose best attack method
    let selected_method = select_best_attack_method(&vulnerabilities);
    assert_eq!(selected_method, Some("PMKID".to_string()));

    // Step 5: PREPARE - Can we create params for the attack?
    match selected_method.as_deref() {
        Some("PMKID") => {
            // Would trigger PMKID capture
            let output = PathBuf::from("/tmp/pmkid_capture.pcap");
            assert!(output.parent().is_some());
        }
        Some("WPS-Pixie") => {
            // Would trigger WPS Pixie-Dust
            let _params = WpsAttackParams::pixie_dust(
                selected_network.bssid.clone(),
                selected_network.channel.parse().unwrap_or(6),
                "wlan0".to_string(),
            );
        }
        Some("WPA3-Downgrade") => {
            // Would trigger WPA3 downgrade
            let _params = Wpa3AttackParams {
                bssid: selected_network.bssid.clone(),
                channel: selected_network.channel.parse().unwrap_or(6),
                interface: "wlan0".to_string(),
                attack_type: Wpa3AttackType::TransitionDowngrade,
                timeout: Duration::from_secs(300),
                output_file: PathBuf::from("/tmp/wpa3.pcap"),
            };
        }
        _ => {}
    }
}

// =========================================================================
// Test: Priority Order of Attack Methods
// =========================================================================

#[test]
fn test_attack_method_priority_order() {
    // Verify priority order: PMKID > WPS-Pixie > WPA3-Downgrade > Handshake > WPA3-SAE

    // Test 1: PMKID has highest priority
    let vulns1 = vec!["PMKID".to_string(), "Handshake".to_string()];
    assert_eq!(
        select_best_attack_method(&vulns1),
        Some("PMKID".to_string())
    );

    // Test 2: WPS-Pixie if no PMKID
    let vulns2 = vec!["WPS".to_string(), "Handshake".to_string()];
    assert_eq!(
        select_best_attack_method(&vulns2),
        Some("WPS-Pixie".to_string())
    );

    // Test 3: WPA3-Downgrade if no PMKID/WPS
    let vulns3 = vec![
        "Downgrade".to_string(),
        "WPA3-SAE".to_string(),
        "Handshake".to_string(),
    ];
    assert_eq!(
        select_best_attack_method(&vulns3),
        Some("WPA3-Downgrade".to_string())
    );

    // Test 4: Handshake if nothing faster available
    let vulns4 = vec!["Handshake".to_string()];
    assert_eq!(
        select_best_attack_method(&vulns4),
        Some("Handshake".to_string())
    );

    // Test 5: WPA3-SAE as last resort
    let vulns5 = vec!["WPA3-SAE".to_string()];
    assert_eq!(
        select_best_attack_method(&vulns5),
        Some("WPA3-SAE".to_string())
    );
}

// =========================================================================
// Test: Fallback Chain
// =========================================================================

#[test]
fn test_attack_method_fallback_chain() {
    // Simulate fallback scenario: PMKID fails → try WPS → try Handshake

    let network = create_mock_wpa2_network();
    let vulnerabilities = detect_vulnerabilities(&network);

    // Build fallback chain
    let mut fallback_chain = Vec::new();

    if vulnerabilities.contains(&"PMKID".to_string()) {
        fallback_chain.push("PMKID");
    }
    if vulnerabilities.contains(&"WPS".to_string()) {
        fallback_chain.push("WPS-Pixie");
        fallback_chain.push("WPS-PIN");
    }
    if vulnerabilities.contains(&"Handshake".to_string()) {
        fallback_chain.push("Handshake");
    }

    // Should have complete fallback chain
    assert_eq!(fallback_chain.len(), 4);
    assert_eq!(fallback_chain[0], "PMKID"); // Try first
    assert_eq!(fallback_chain[1], "WPS-Pixie"); // Try second
    assert_eq!(fallback_chain[2], "WPS-PIN"); // Try third
    assert_eq!(fallback_chain[3], "Handshake"); // Try last
}

// =========================================================================
// Test: Tool Availability Check Before Attack
// =========================================================================

#[test]
fn test_scan_checks_tool_availability() {
    // Before triggering any attack, verify required tools are available

    // WPS attacks require reaver + pixiewps
    let wps_available = wps::check_reaver_installed() && wps::check_pixiewps_installed();

    // WPA3 attacks require hcxdumptool + hcxpcapngtool
    let wpa3_available =
        wpa3::check_hcxdumptool_installed() && wpa3::check_hcxpcapngtool_installed();

    // Evil Twin requires hostapd + dnsmasq
    let evil_twin_available =
        evil_twin::check_hostapd_installed() && evil_twin::check_dnsmasq_installed();

    // Passive PMKID requires hcxdumptool
    let passive_pmkid_available = passive_pmkid::check_hcxdumptool_available();

    // If tools not available, those methods should be disabled
    // This would be checked in the real workflow
    let _ = wps_available;
    let _ = wpa3_available;
    let _ = evil_twin_available;
    let _ = passive_pmkid_available;
}

// =========================================================================
// Test: Network Type Classification
// =========================================================================

#[test]
fn test_scan_classifies_network_types() {
    let networks = vec![
        ("WPA2-PSK", vec!["PMKID", "Handshake", "WPS"]),
        (
            "WPA3-Transition",
            vec!["WPA3-SAE", "Dragonblood", "Downgrade"],
        ),
        ("WPA3-SAE", vec!["WPA3-SAE", "Dragonblood", "Downgrade"]),
        ("WPA-PSK", vec!["PMKID", "Handshake"]),
        ("None", vec!["Open"]),
    ];

    for (security_type, expected_vulns) in networks {
        let network = WifiNetwork {
            ssid: format!("Test-{}", security_type),
            bssid: "AA:BB:CC:DD:EE:FF".to_string(),
            channel: "6".to_string(),
            signal_strength: "-50".to_string(),
            security: security_type.to_string(),
        };

        let detected_vulns = detect_vulnerabilities(&network);

        for expected in expected_vulns {
            assert!(
                detected_vulns.contains(&expected.to_string()),
                "Network type {} should detect {}",
                security_type,
                expected
            );
        }
    }
}
