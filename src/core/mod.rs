// Core library modules
pub mod bruteforce;
pub mod captive_portal;
pub mod crypto;
pub mod dual_interface;
pub mod evil_twin;
pub mod handshake;
pub mod hashcat;
pub mod network;
pub mod passive_pmkid;
pub mod password_gen;
pub mod security;
pub mod session;
pub mod wpa3;
pub mod wps;

// Re-exports
pub use bruteforce::OfflineBruteForcer;
pub use crypto::{calculate_mic, calculate_pmk, calculate_ptk, verify_password};
pub use dual_interface::{
    auto_assign_interfaces, detect_interface_capabilities, validate_manual_assignment,
    DualInterfaceConfig, InterfaceAssignment, InterfaceCapabilities,
};
pub use evil_twin::{
    check_dnsmasq_installed, check_hostapd_installed, configure_interface, generate_dnsmasq_config,
    generate_hostapd_config, get_dnsmasq_version, get_hostapd_version, run_evil_twin_attack,
    start_dnsmasq, start_hostapd, validate_password_against_ap, CapturedCredential, EvilTwinParams,
    EvilTwinProgress, EvilTwinResult, EvilTwinState, PortalTemplate,
};
pub use handshake::{extract_eapol_from_packet, parse_cap_file, EapolPacket, Handshake};
pub use hashcat::{
    are_external_tools_available, convert_to_hashcat_format, crack_with_hashcat, HashcatParams,
    HashcatProgress, HashcatResult,
};
pub use network::{
    capture_traffic, compact_duplicate_networks, disconnect_wifi, scan_networks,
    wifi_connected_ssid, CaptureOptions, WifiNetwork,
};
pub use passive_pmkid::{
    check_hcxdumptool_available, load_captured_pmkids, run_passive_pmkid_capture,
    save_captured_pmkids, CapturedPmkid, PassivePmkidConfig, PassivePmkidProgress,
    PassivePmkidResult, PassivePmkidState,
};
pub use session::{
    AttackType, SessionConfig, SessionData, SessionManager, SessionMetadata, SessionProgress,
    SessionStatus,
};
pub use wpa3::{
    check_dragonblood_vulnerabilities, check_hcxdumptool_installed, check_hcxpcapngtool_installed,
    detect_wpa3_type, get_hcxdumptool_version, get_hcxpcapngtool_version, run_sae_capture,
    run_transition_downgrade_attack, DragonbloodVulnerability, Wpa3AttackParams, Wpa3AttackType,
    Wpa3NetworkType, Wpa3Progress, Wpa3Result,
};
pub use wps::{
    calculate_wps_checksum, check_pixiewps_installed, check_reaver_installed,
    generate_valid_wps_pins, get_pixiewps_version, get_reaver_version, run_pin_bruteforce_attack,
    run_pixie_dust_attack, WpsAttackParams, WpsAttackType, WpsProgress, WpsResult,
};
