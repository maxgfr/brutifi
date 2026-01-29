/*!
 * Integration tests for all security attack methods
 *
 * Tests that verify all 8 attack methods are properly integrated
 * and can be invoked programmatically.
 */

use brutifi::core::{
    evil_twin::{self, EvilTwinParams, PortalTemplate},
    passive_pmkid::{self, PassivePmkidConfig, PassivePmkidState},
    wpa3::{self, Wpa3AttackParams, Wpa3AttackType, Wpa3NetworkType},
    wps::{self, WpsAttackParams, WpsAttackType},
};
use std::path::PathBuf;
use std::time::Duration;

// =========================================================================
// WPS Attack Integration Tests
// =========================================================================

#[test]
fn test_wps_pixie_dust_params_creation() {
    let params =
        WpsAttackParams::pixie_dust("AA:BB:CC:DD:EE:FF".to_string(), 6, "wlan0".to_string());

    assert_eq!(params.bssid, "AA:BB:CC:DD:EE:FF");
    assert_eq!(params.channel, 6);
    assert_eq!(params.interface, "wlan0");
    assert_eq!(params.attack_type, WpsAttackType::PixieDust);
    assert_eq!(params.timeout, Duration::from_secs(60));
}

#[test]
fn test_wps_pin_bruteforce_params_creation() {
    let params =
        WpsAttackParams::pin_bruteforce("11:22:33:44:55:66".to_string(), 11, "wlan1".to_string());

    assert_eq!(params.bssid, "11:22:33:44:55:66");
    assert_eq!(params.channel, 11);
    assert_eq!(params.interface, "wlan1");
    assert_eq!(params.attack_type, WpsAttackType::PinBruteForce);
    assert_eq!(params.timeout, Duration::from_secs(3600));
}

#[test]
fn test_wps_checksum_algorithm() {
    // Test that checksum algorithm works correctly
    let test_cases = vec![
        (1234567, wps::calculate_wps_checksum(1234567)),
        (0, wps::calculate_wps_checksum(0)),
        (9999999, wps::calculate_wps_checksum(9999999)),
    ];

    // All checksums should be single digits (0-9)
    for (pin, checksum) in test_cases {
        assert!(
            checksum < 10,
            "Checksum for PIN {} should be < 10, got {}",
            pin,
            checksum
        );
    }
}

#[test]
fn test_wps_tools_detection() {
    // Test that tool detection functions don't panic
    let reaver_installed = wps::check_reaver_installed();
    let pixiewps_installed = wps::check_pixiewps_installed();

    // Try to get versions if tools are installed
    if reaver_installed {
        let version = wps::get_reaver_version();
        assert!(version.is_ok());
    }

    if pixiewps_installed {
        let version = wps::get_pixiewps_version();
        assert!(version.is_ok());
    }
}

// =========================================================================
// WPA3 Attack Integration Tests
// =========================================================================

#[test]
fn test_wpa3_attack_params_creation() {
    let params = Wpa3AttackParams {
        bssid: "AA:BB:CC:DD:EE:FF".to_string(),
        channel: 6,
        interface: "wlan0".to_string(),
        attack_type: Wpa3AttackType::TransitionDowngrade,
        timeout: Duration::from_secs(300),
        output_file: PathBuf::from("/tmp/wpa3_capture.pcap"),
    };

    assert_eq!(params.bssid, "AA:BB:CC:DD:EE:FF");
    assert_eq!(params.channel, 6);
    assert_eq!(params.attack_type, Wpa3AttackType::TransitionDowngrade);
}

#[test]
fn test_wpa3_network_type_detection() {
    // Test WPA3 transition mode detection (both SAE and PSK)
    let rsn_ie_transition = vec![
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

    let network_type = wpa3::detect_wpa3_type(&rsn_ie_transition);
    assert_eq!(network_type, Some(Wpa3NetworkType::Wpa3Transition));

    // Test WPA3-only detection (SAE only)
    let rsn_ie_sae_only = vec![
        0x30, 0x18, // Element ID + Length
        0x01, 0x00, // Version
        0x00, 0x0F, 0xAC, 0x04, // Group cipher
        0x01, 0x00, // Pairwise count
        0x00, 0x0F, 0xAC, 0x04, // Pairwise cipher
        0x01, 0x00, // AKM count
        0x00, 0x0F, 0xAC, 0x08, // SAE only
        0xC0, 0x00, // Capabilities (MFPC + MFPR)
    ];

    let network_type_sae = wpa3::detect_wpa3_type(&rsn_ie_sae_only);
    assert_eq!(network_type_sae, Some(Wpa3NetworkType::Wpa3Only));
}

#[test]
fn test_wpa3_dragonblood_detection() {
    let vulns = wpa3::check_dragonblood_vulnerabilities(Wpa3NetworkType::Wpa3Only);

    // Should detect at least CVE-2019-13377 and CVE-2019-13456
    assert!(vulns.len() >= 2);
    assert!(vulns.iter().any(|v| v.cve == "CVE-2019-13377"));
    assert!(vulns.iter().any(|v| v.cve == "CVE-2019-13456"));

    for vuln in &vulns {
        assert!(!vuln.cve.is_empty());
        assert!(!vuln.description.is_empty());
        assert!(!vuln.severity.is_empty());
    }
}

#[test]
fn test_wpa3_tools_detection() {
    let hcxdumptool_installed = wpa3::check_hcxdumptool_installed();
    let hcxpcapngtool_installed = wpa3::check_hcxpcapngtool_installed();

    // Try to get versions if tools are installed
    if hcxdumptool_installed {
        let _version = wpa3::get_hcxdumptool_version();
    }

    if hcxpcapngtool_installed {
        let _version = wpa3::get_hcxpcapngtool_version();
    }
}

// =========================================================================
// Evil Twin Attack Integration Tests
// =========================================================================

#[test]
fn test_evil_twin_params_creation() {
    let params = EvilTwinParams {
        target_ssid: "TestNetwork".to_string(),
        target_bssid: Some("AA:BB:CC:DD:EE:FF".to_string()),
        target_channel: 6,
        interface: "wlan0".to_string(),
        portal_template: PortalTemplate::TpLink,
        web_port: 80,
        dhcp_range_start: "192.168.1.100".to_string(),
        dhcp_range_end: "192.168.1.200".to_string(),
        gateway_ip: "192.168.1.1".to_string(),
    };

    assert_eq!(params.target_ssid, "TestNetwork");
    assert_eq!(params.target_bssid, Some("AA:BB:CC:DD:EE:FF".to_string()));
    assert_eq!(params.target_channel, 6);
    assert_eq!(params.portal_template, PortalTemplate::TpLink);
}

#[test]
fn test_evil_twin_all_portal_templates() {
    let templates = vec![
        PortalTemplate::Generic,
        PortalTemplate::TpLink,
        PortalTemplate::Netgear,
        PortalTemplate::Linksys,
    ];

    for template in templates {
        let params = EvilTwinParams {
            target_ssid: "TestNet".to_string(),
            portal_template: template,
            ..Default::default()
        };

        assert_eq!(params.portal_template, template);

        // Test that template name is not empty
        let template_str = template.to_string();
        assert!(!template_str.is_empty());
    }
}

#[test]
fn test_evil_twin_config_generation() {
    let params = EvilTwinParams {
        target_ssid: "ConfigTest".to_string(),
        target_channel: 11,
        interface: "wlan0".to_string(),
        ..Default::default()
    };

    // Test hostapd config generation
    let hostapd_config = evil_twin::generate_hostapd_config(&params);
    assert!(hostapd_config.is_ok());
    let hostapd_path = hostapd_config.unwrap();
    assert!(hostapd_path.exists());

    // Read and verify content
    let content = std::fs::read_to_string(&hostapd_path).unwrap();
    assert!(content.contains("interface=wlan0"));
    assert!(content.contains("ssid=ConfigTest"));
    assert!(content.contains("channel=11"));

    // Test dnsmasq config generation
    let dnsmasq_config = evil_twin::generate_dnsmasq_config(&params);
    assert!(dnsmasq_config.is_ok());
    let dnsmasq_path = dnsmasq_config.unwrap();
    assert!(dnsmasq_path.exists());

    let dnsmasq_content = std::fs::read_to_string(&dnsmasq_path).unwrap();
    assert!(dnsmasq_content.contains("interface=wlan0"));
    assert!(dnsmasq_content.contains("dhcp-range"));

    // Cleanup
    let _ = std::fs::remove_file(&hostapd_path);
    let _ = std::fs::remove_file(&dnsmasq_path);
}

#[test]
fn test_evil_twin_tools_detection() {
    let hostapd_installed = evil_twin::check_hostapd_installed();
    let dnsmasq_installed = evil_twin::check_dnsmasq_installed();

    // Try to get versions if tools are installed
    if hostapd_installed {
        let _version = evil_twin::get_hostapd_version();
    }

    if dnsmasq_installed {
        let _version = evil_twin::get_dnsmasq_version();
    }
}

// =========================================================================
// Passive PMKID Integration Tests
// =========================================================================

#[test]
fn test_passive_pmkid_config_creation() {
    let config = PassivePmkidConfig {
        interface: "wlan0".to_string(),
        output_dir: PathBuf::from("/tmp/pmkid_test"),
        auto_save: true,
        save_interval_secs: 30,
        hop_channels: true,
        channels: vec![1, 6, 11],
    };

    assert_eq!(config.interface, "wlan0");
    assert_eq!(config.save_interval_secs, 30);
    assert!(config.hop_channels);
    assert_eq!(config.channels.len(), 3);
}

#[test]
fn test_passive_pmkid_state_management() {
    let state = PassivePmkidState::new();

    // Test initial state
    assert_eq!(state.count(), 0);
    assert!(!state.should_stop());

    // Test adding PMKIDs
    let pmkid1 = passive_pmkid::CapturedPmkid::new(
        "Network1".to_string(),
        "AA:BB:CC:DD:EE:FF".to_string(),
        "pmkid1".to_string(),
        6,
        -50,
    );

    state.add_pmkid(pmkid1);
    assert_eq!(state.count(), 1);

    // Test duplicate BSSID (should replace)
    let pmkid2 = passive_pmkid::CapturedPmkid::new(
        "Network1".to_string(),
        "AA:BB:CC:DD:EE:FF".to_string(), // Same BSSID
        "pmkid2".to_string(),
        6,
        -55,
    );

    state.add_pmkid(pmkid2);
    assert_eq!(state.count(), 1); // Should still be 1 (replaced)

    // Test stop flag
    state.stop();
    assert!(state.should_stop());
}

#[test]
fn test_passive_pmkid_save_load() {
    let temp_path = PathBuf::from("/tmp/test_passive_pmkid.json");

    let pmkids = vec![
        passive_pmkid::CapturedPmkid::new(
            "Net1".to_string(),
            "AA:BB:CC:DD:EE:FF".to_string(),
            "pmkid1".to_string(),
            1,
            -50,
        ),
        passive_pmkid::CapturedPmkid::new(
            "Net2".to_string(),
            "11:22:33:44:55:66".to_string(),
            "pmkid2".to_string(),
            6,
            -60,
        ),
    ];

    // Save
    let save_result = passive_pmkid::save_captured_pmkids(&pmkids, &temp_path);
    assert!(save_result.is_ok());

    // Load
    let load_result = passive_pmkid::load_captured_pmkids(&temp_path);
    assert!(load_result.is_ok());

    let loaded = load_result.unwrap();
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded[0].ssid, "Net1");
    assert_eq!(loaded[1].ssid, "Net2");

    // Cleanup
    let _ = std::fs::remove_file(&temp_path);
}

#[test]
fn test_passive_pmkid_tool_detection() {
    // Just verify the function doesn't panic
    let _hcxdumptool_available = passive_pmkid::check_hcxdumptool_available();
}

// =========================================================================
// Cross-Module Integration Tests
// =========================================================================

#[test]
fn test_all_attack_types_enum() {
    // Verify all attack type enums are properly defined and comparable
    let wps_pixie = WpsAttackType::PixieDust;
    let wps_pin = WpsAttackType::PinBruteForce;
    assert_ne!(wps_pixie, wps_pin);

    let wpa3_downgrade = Wpa3AttackType::TransitionDowngrade;
    let wpa3_sae = Wpa3AttackType::SaeHandshake;
    let wpa3_dragonblood = Wpa3AttackType::DragonbloodScan;
    assert_ne!(wpa3_downgrade, wpa3_sae);
    assert_ne!(wpa3_sae, wpa3_dragonblood);

    let portal_generic = PortalTemplate::Generic;
    let portal_tplink = PortalTemplate::TpLink;
    assert_ne!(portal_generic, portal_tplink);
}

#[test]
fn test_all_result_types_serialization() {
    // Test that all result types can be serialized/deserialized
    use serde_json;

    // WPA3
    let wpa3_result = wpa3::Wpa3Result::Captured {
        capture_file: PathBuf::from("/tmp/capture.pcap"),
        hash_file: PathBuf::from("/tmp/hash.22000"),
    };
    let wpa3_json = serde_json::to_string(&wpa3_result).unwrap();
    assert!(wpa3_json.contains("capture.pcap"));

    // Evil Twin
    let evil_twin_result = evil_twin::EvilTwinResult::PasswordFound {
        password: "found123".to_string(),
    };
    let evil_twin_json = serde_json::to_string(&evil_twin_result).unwrap();
    assert!(evil_twin_json.contains("found123"));

    // Passive PMKID
    let passive_result = passive_pmkid::PassivePmkidResult::Stopped { total_captured: 10 };
    let passive_json = serde_json::to_string(&passive_result).unwrap();
    assert!(passive_json.contains("10"));
}

#[test]
fn test_all_progress_types_cloneable() {
    // Verify all progress types are cloneable
    let wps_progress = wps::WpsProgress::Started;
    let wps_clone = wps_progress.clone();
    assert!(matches!(wps_clone, wps::WpsProgress::Started));

    let wpa3_progress = wpa3::Wpa3Progress::Started;
    let wpa3_clone = wpa3_progress.clone();
    assert!(matches!(wpa3_clone, wpa3::Wpa3Progress::Started));

    let evil_twin_progress = evil_twin::EvilTwinProgress::Started;
    let evil_twin_clone = evil_twin_progress.clone();
    assert!(matches!(
        evil_twin_clone,
        evil_twin::EvilTwinProgress::Started
    ));

    let passive_progress = passive_pmkid::PassivePmkidProgress::Started;
    let passive_clone = passive_progress.clone();
    assert!(matches!(
        passive_clone,
        passive_pmkid::PassivePmkidProgress::Started
    ));
}

#[test]
fn test_all_modules_exported() {
    // Verify all modules are properly exported from lib.rs
    // This will fail at compile time if any module is missing
    use brutifi::core::{
        captive_portal, dual_interface, evil_twin, hashcat, network, passive_pmkid, session, wpa3,
        wps,
    };

    // Just ensure they're accessible (test that public APIs exist)
    let _ = wps::check_reaver_installed;
    let _ = wpa3::check_hcxdumptool_installed;
    let _ = evil_twin::check_hostapd_installed;
    let _ = passive_pmkid::check_hcxdumptool_available;
    let _ = hashcat::is_hashcat_installed;
    let _ = network::scan_networks;
    let _ = captive_portal::load_template;
    let _ = session::SessionManager::new;

    // Test that dual_interface module exports structs
    let capabilities = dual_interface::InterfaceCapabilities {
        name: "test".to_string(),
        monitor_mode: false,
        injection: false,
        bands_2ghz: true,
        bands_5ghz: false,
        chipset: None,
    };
    assert_eq!(capabilities.name, "test");
    assert_eq!(capabilities.score(), 10); // 2.4GHz band only = 10 points
}

// =========================================================================
// Performance and Resource Tests
// =========================================================================

#[test]
fn test_state_objects_memory_efficiency() {
    use std::mem::size_of;

    // Verify state objects are reasonably sized
    // (These are just sanity checks, not strict requirements)

    let passive_state_size = size_of::<PassivePmkidState>();
    assert!(
        passive_state_size < 1000,
        "PassivePmkidState too large: {} bytes",
        passive_state_size
    );

    // evil_twin::EvilTwinState uses Arc<Mutex<...>> so it's small
    let evil_twin_state_size = size_of::<evil_twin::EvilTwinState>();
    assert!(
        evil_twin_state_size < 500,
        "EvilTwinState too large: {} bytes",
        evil_twin_state_size
    );
}

#[test]
fn test_concurrent_state_access() {
    use std::sync::Arc;
    use std::thread;

    // Test that states can be safely accessed from multiple threads
    let passive_state = Arc::new(PassivePmkidState::new());
    let mut handles = vec![];

    for i in 0..10 {
        let state_clone = passive_state.clone();
        let handle = thread::spawn(move || {
            let pmkid = passive_pmkid::CapturedPmkid::new(
                format!("Network{}", i),
                format!("AA:BB:CC:DD:EE:{:02X}", i),
                format!("pmkid{}", i),
                1,
                -60,
            );
            state_clone.add_pmkid(pmkid);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    assert_eq!(passive_state.count(), 10);
}

#[test]
fn test_config_serialization_roundtrip() {
    // Test that all config types can be serialized and deserialized
    use serde_json;

    let passive_config = PassivePmkidConfig::default();
    let json = serde_json::to_string(&passive_config).unwrap();
    let deserialized: PassivePmkidConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(passive_config.interface, deserialized.interface);
    assert_eq!(
        passive_config.save_interval_secs,
        deserialized.save_interval_secs
    );
}
