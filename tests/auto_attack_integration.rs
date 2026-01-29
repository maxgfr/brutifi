/*!
 * Auto Attack Integration Tests
 *
 * Tests the full auto attack workflow including attack selection,
 * execution, and result handling.
 */

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use brutifi::{
    determine_attack_sequence, get_attack_timeout, AutoAttackConfig, AutoAttackFinalResult,
    AutoAttackProgress, AutoAttackResult, AutoAttackType,
};

#[test]
fn test_determine_attack_sequence_wpa2() {
    let attacks = determine_attack_sequence("WPA2");
    assert_eq!(attacks.len(), 4);
    assert_eq!(attacks[0], AutoAttackType::WpsPixieDust);
    assert_eq!(attacks[1], AutoAttackType::PmkidCapture);
    assert_eq!(attacks[2], AutoAttackType::HandshakeCapture);
    assert_eq!(attacks[3], AutoAttackType::EvilTwin);
}

#[test]
fn test_determine_attack_sequence_wpa3_transition() {
    let attacks = determine_attack_sequence("WPA3-Transition");
    assert_eq!(attacks.len(), 4);
    assert_eq!(attacks[0], AutoAttackType::Wpa3TransitionDowngrade);
    assert_eq!(attacks[1], AutoAttackType::PmkidCapture);
    assert_eq!(attacks[2], AutoAttackType::HandshakeCapture);
    assert_eq!(attacks[3], AutoAttackType::EvilTwin);
}

#[test]
fn test_determine_attack_sequence_wpa3_only() {
    let attacks = determine_attack_sequence("WPA3");
    assert_eq!(attacks.len(), 2);
    assert_eq!(attacks[0], AutoAttackType::Wpa3SaeCapture);
    assert_eq!(attacks[1], AutoAttackType::EvilTwin);
}

#[test]
fn test_determine_attack_sequence_wpa() {
    let attacks = determine_attack_sequence("WPA");
    assert_eq!(attacks.len(), 3);
    assert_eq!(attacks[0], AutoAttackType::PmkidCapture);
    assert_eq!(attacks[1], AutoAttackType::HandshakeCapture);
    assert_eq!(attacks[2], AutoAttackType::EvilTwin);
}

#[test]
fn test_attack_timeouts() {
    assert_eq!(
        get_attack_timeout(&AutoAttackType::WpsPixieDust),
        Duration::from_secs(60)
    );
    assert_eq!(
        get_attack_timeout(&AutoAttackType::PmkidCapture),
        Duration::from_secs(60)
    );
    assert_eq!(
        get_attack_timeout(&AutoAttackType::HandshakeCapture),
        Duration::from_secs(300)
    );
    assert_eq!(
        get_attack_timeout(&AutoAttackType::Wpa3TransitionDowngrade),
        Duration::from_secs(30)
    );
    assert_eq!(
        get_attack_timeout(&AutoAttackType::Wpa3SaeCapture),
        Duration::from_secs(60)
    );
    assert_eq!(
        get_attack_timeout(&AutoAttackType::EvilTwin),
        Duration::from_secs(600)
    );
}

#[test]
fn test_attack_type_display_names() {
    assert_eq!(AutoAttackType::WpsPixieDust.display_name(), "WPS Pixie Dust");
    assert_eq!(
        AutoAttackType::Wpa3TransitionDowngrade.display_name(),
        "WPA3 Transition Downgrade"
    );
    assert_eq!(
        AutoAttackType::HandshakeCapture.display_name(),
        "Handshake Capture"
    );
    assert_eq!(AutoAttackType::PmkidCapture.display_name(), "PMKID Capture");
    assert_eq!(
        AutoAttackType::Wpa3SaeCapture.display_name(),
        "WPA3 SAE Capture"
    );
    assert_eq!(AutoAttackType::EvilTwin.display_name(), "Evil Twin");
}

#[test]
fn test_auto_attack_config_creation() {
    let config = AutoAttackConfig {
        network_ssid: "TestNetwork".to_string(),
        network_bssid: "00:11:22:33:44:55".to_string(),
        network_channel: 6,
        network_security: "WPA2".to_string(),
        interface: "en0".to_string(),
        output_dir: std::path::PathBuf::from("/tmp"),
    };

    assert_eq!(config.network_ssid, "TestNetwork");
    assert_eq!(config.network_bssid, "00:11:22:33:44:55");
    assert_eq!(config.network_channel, 6);
    assert_eq!(config.network_security, "WPA2");
}

#[test]
fn test_attack_sequence_case_insensitive() {
    let wpa2_lower = determine_attack_sequence("wpa2");
    let wpa2_upper = determine_attack_sequence("WPA2");
    let wpa2_mixed = determine_attack_sequence("Wpa2");

    assert_eq!(wpa2_lower.len(), wpa2_upper.len());
    assert_eq!(wpa2_upper.len(), wpa2_mixed.len());

    for (a, b) in wpa2_lower.iter().zip(wpa2_upper.iter()) {
        assert_eq!(a, b);
    }
}

#[test]
fn test_empty_attack_sequence_for_open_network() {
    let attacks = determine_attack_sequence("Open");
    assert_eq!(attacks.len(), 0);
}

#[test]
fn test_empty_attack_sequence_for_wep() {
    let attacks = determine_attack_sequence("WEP");
    assert_eq!(attacks.len(), 0);
}

#[test]
fn test_attack_sequence_wpa2_psk() {
    let attacks = determine_attack_sequence("WPA2-PSK");
    assert!(attacks.len() > 0);
    assert_eq!(attacks[0], AutoAttackType::WpsPixieDust);
}

#[test]
fn test_attack_sequence_wpa3_mixed() {
    let attacks = determine_attack_sequence("WPA3/WPA2");
    assert!(attacks.len() > 0);
    // Should treat as transition mode
    assert_eq!(attacks[0], AutoAttackType::Wpa3TransitionDowngrade);
}

#[tokio::test]
async fn test_auto_attack_progress_messages() {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    // Send various progress messages
    let _ = tx.send(AutoAttackProgress::Started { total_attacks: 4 });
    let _ = tx.send(AutoAttackProgress::AttackStarted {
        attack_type: AutoAttackType::WpsPixieDust,
        index: 1,
        total: 4,
    });
    let _ = tx.send(AutoAttackProgress::AttackProgress {
        attack_type: AutoAttackType::WpsPixieDust,
        message: "Testing...".to_string(),
    });

    // Verify messages can be received
    assert!(matches!(
        rx.recv().await,
        Some(AutoAttackProgress::Started { .. })
    ));
    assert!(matches!(
        rx.recv().await,
        Some(AutoAttackProgress::AttackStarted { .. })
    ));
    assert!(matches!(
        rx.recv().await,
        Some(AutoAttackProgress::AttackProgress { .. })
    ));
}

#[test]
fn test_auto_attack_result_variants() {
    // Test WPS credentials result
    let wps_result = AutoAttackResult::WpsCredentials {
        pin: "12345678".to_string(),
        password: "password123".to_string(),
    };

    if let AutoAttackResult::WpsCredentials { password, .. } = wps_result {
        assert_eq!(password, "password123");
    } else {
        panic!("Expected WpsCredentials variant");
    }

    // Test handshake captured result
    let handshake_result = AutoAttackResult::HandshakeCaptured {
        capture_file: std::path::PathBuf::from("/tmp/capture.pcap"),
        hash_file: std::path::PathBuf::from("/tmp/hash.22000"),
    };

    if let AutoAttackResult::HandshakeCaptured { hash_file, .. } = handshake_result {
        assert_eq!(hash_file, std::path::PathBuf::from("/tmp/hash.22000"));
    } else {
        panic!("Expected HandshakeCaptured variant");
    }

    // Test Evil Twin result
    let evil_twin_result = AutoAttackResult::EvilTwinPassword {
        password: "captured_password".to_string(),
    };

    if let AutoAttackResult::EvilTwinPassword { password } = evil_twin_result {
        assert_eq!(password, "captured_password");
    } else {
        panic!("Expected EvilTwinPassword variant");
    }
}

#[test]
fn test_auto_attack_final_result_variants() {
    // Test success variant
    let success = AutoAttackFinalResult::Success {
        attack_type: AutoAttackType::WpsPixieDust,
        result: AutoAttackResult::WpsCredentials {
            pin: "12345678".to_string(),
            password: "password123".to_string(),
        },
    };

    if let AutoAttackFinalResult::Success { attack_type, .. } = success {
        assert_eq!(attack_type, AutoAttackType::WpsPixieDust);
    } else {
        panic!("Expected Success variant");
    }

    // Test AllFailed variant
    let all_failed = AutoAttackFinalResult::AllFailed;
    assert!(matches!(all_failed, AutoAttackFinalResult::AllFailed));

    // Test Stopped variant
    let stopped = AutoAttackFinalResult::Stopped;
    assert!(matches!(stopped, AutoAttackFinalResult::Stopped));

    // Test Error variant
    let error = AutoAttackFinalResult::Error("Test error".to_string());
    if let AutoAttackFinalResult::Error(msg) = error {
        assert_eq!(msg, "Test error");
    } else {
        panic!("Expected Error variant");
    }
}
