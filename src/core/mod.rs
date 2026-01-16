// Core library modules
pub mod bruteforce;
pub mod crypto;
pub mod handshake;
pub mod network;
pub mod password_gen;
pub mod security;

// Re-exports
pub use bruteforce::OfflineBruteForcer;
pub use crypto::{calculate_mic, calculate_pmk, calculate_ptk, verify_password};
pub use handshake::{extract_eapol_from_packet, parse_cap_file, EapolPacket, Handshake};
pub use network::{capture_traffic, scan_networks, CaptureOptions, WifiNetwork};
