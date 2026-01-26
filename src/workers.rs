/*!
 * Background workers for async operations
 *
 * These workers handle long-running tasks in background threads
 * and communicate progress back to the GUI via channels.
 */

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use brutifi::{scan_networks, WifiNetwork};

/// Scan result from background worker
#[derive(Debug, Clone)]
pub enum ScanResult {
    Success(Vec<WifiNetwork>),
    Error(String),
}

/// Capture progress from background worker
#[derive(Debug, Clone)]
pub enum CaptureProgress {
    Started,
    Log(String),
    HandshakeComplete { ssid: String },
    Error(String),
    Finished { output_file: String, packets: u64 },
}

/// Crack progress from background worker
#[derive(Debug, Clone)]
pub enum CrackProgress {
    Started { total: u64 },
    Progress { current: u64, total: u64, rate: f64 },
    Log(String),
    Found(String),
    NotFound,
    Error(String),
}

/// Capture state for controlling the capture process
pub struct CaptureState {
    pub running: Arc<AtomicBool>,
    pub packets_count: Arc<AtomicU64>,
}

impl CaptureState {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(true)),
            packets_count: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Crack state for controlling the crack process
pub struct CrackState {
    pub running: Arc<AtomicBool>,
    pub attempts: Arc<AtomicU64>,
}

impl CrackState {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(true)),
            attempts: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// WPS attack state for controlling the attack process
pub struct WpsState {
    pub running: Arc<AtomicBool>,
}

impl WpsState {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// WPA3 attack state for controlling the attack process
pub struct Wpa3State {
    pub running: Arc<AtomicBool>,
}

impl Wpa3State {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

// Re-export EvilTwinState from brutifi core
pub use brutifi::EvilTwinState;

/// Wordlist crack worker data
pub struct WordlistCrackParams {
    pub handshake_path: PathBuf,
    pub ssid: Option<String>,
    pub wordlist_path: PathBuf,
    pub threads: usize,
}

/// Numeric crack worker data
pub struct NumericCrackParams {
    pub handshake_path: PathBuf,
    pub ssid: Option<String>,
    pub min_digits: usize,
    pub max_digits: usize,
    pub threads: usize,
}

/// Scan networks in background
pub fn scan_networks_async(interface: String) -> ScanResult {
    match scan_networks(&interface) {
        Ok(networks) => {
            if networks.is_empty() {
                ScanResult::Error("No networks found".to_string())
            } else {
                // Compact duplicate networks (same SSID, different channels)
                let compacted_networks = brutifi::compact_duplicate_networks(networks);
                ScanResult::Success(compacted_networks)
            }
        }
        Err(e) => ScanResult::Error(e.to_string()),
    }
}

/// Capture parameters
pub struct CaptureParams {
    pub interface: String,
    pub channel: Option<u32>,
    pub ssid: Option<String>,
    pub output_file: String,
}

/// Run capture in background with progress updates
pub async fn capture_async(
    params: CaptureParams,
    state: Arc<CaptureState>,
    progress_tx: tokio::sync::mpsc::UnboundedSender<CaptureProgress>,
) -> CaptureProgress {
    use brutifi::CaptureOptions;

    let _ = progress_tx.send(CaptureProgress::Started);
    let _ = progress_tx.send(CaptureProgress::Log(
        "Starting packet capture...".to_string(),
    ));

    // Clone output_file before moving params
    let output_file = params.output_file.clone();
    let interface = params.interface.clone();
    let ssid = params.ssid.clone();

    if std::path::Path::new(&output_file).exists() {
        if let Err(e) = std::fs::remove_file(&output_file) {
            let _ = progress_tx.send(CaptureProgress::Log(format!(
                "⚠️  Failed to remove existing capture file: {}",
                e
            )));
        } else {
            let _ = progress_tx.send(CaptureProgress::Log(format!(
                "🗑️  Removed existing capture file: {}",
                output_file
            )));
        }
    }

    // Pre-flight checks
    let _ = progress_tx.send(CaptureProgress::Log(format!(
        "Checking interface {}...",
        interface
    )));

    // Verify interface exists
    let interface_check = interface.clone();
    let check_result = tokio::task::spawn_blocking(move || {
        use pcap::Device;
        let devices = Device::list().unwrap_or_default();
        devices.iter().any(|d| d.name == interface_check)
    })
    .await;

    match check_result {
        Ok(true) => {
            let _ = progress_tx.send(CaptureProgress::Log(format!(
                "Interface {} found",
                interface
            )));
        }
        Ok(false) => {
            let error_msg = format!(
                "Interface '{}' not found. Available interfaces: run 'ifconfig' to list them. On macOS, WiFi is usually 'en0'.",
                interface
            );
            let _ = progress_tx.send(CaptureProgress::Error(error_msg.clone()));
            return CaptureProgress::Error(error_msg);
        }
        Err(e) => {
            let error_msg = format!("Failed to check interfaces: {}", e);
            let _ = progress_tx.send(CaptureProgress::Error(error_msg.clone()));
            return CaptureProgress::Error(error_msg);
        }
    }

    let _ = progress_tx.send(CaptureProgress::Log(
        "Attempting to enable monitor mode...".to_string(),
    ));

    // Log channel information
    if let Some(ch) = params.channel {
        let _ = progress_tx.send(CaptureProgress::Log(format!(
            "Channel {} will be used for capture",
            ch
        )));
    } else {
        let _ = progress_tx.send(CaptureProgress::Log(
            "No specific channel set - will scan all channels".to_string(),
        ));
    }

    // Run capture in blocking thread
    let running_clone = state.running.clone();
    let result = tokio::task::spawn_blocking(move || {
        // Build capture options inside the blocking thread
        let options = CaptureOptions {
            interface: &interface,
            channel: params.channel,
            ssid: ssid.as_deref(),
            bssid: None,
            output_file: &params.output_file,
            duration: None,  // Run until stopped
            no_deauth: true, // macOS doesn't support packet injection
            running: Some(running_clone), // Pass the state for stopping
        };

        // Try to capture, with better error messages
        match brutifi::capture_traffic(options) {
            Ok(captured_ssid) => Ok(captured_ssid),
            Err(e) => {
                let error_str = e.to_string();
                // Provide more helpful error messages
                if error_str.contains("permission denied") || error_str.contains("Operation not permitted") {
                    Err(anyhow::anyhow!(
                        "Permission denied. Make sure to run with sudo: sudo ./target/release/brutifi"
                    ))
                } else if error_str.contains("monitor mode") || error_str.contains("rfmon") {
                    Err(anyhow::anyhow!(
                        "Monitor mode not supported on this interface. On macOS, you may need to disconnect from WiFi first (Option+Click WiFi icon > Disconnect)."
                    ))
                } else if error_str.contains("device") || error_str.contains("interface") {
                    Err(anyhow::anyhow!(
                        "Failed to open interface. Try: 1) Run with sudo, 2) Disconnect from WiFi, 3) Check if en0 is the correct interface."
                    ))
                } else {
                    Err(e)
                }
            }
        }
    })
    .await;

    match result {
        Ok(Ok(captured_ssid)) => {
            let _ = progress_tx.send(CaptureProgress::Log(
                "Capture completed successfully".to_string(),
            ));

            // If we captured a handshake, send HandshakeComplete
            if let Some(ssid) = captured_ssid {
                let _ = progress_tx.send(CaptureProgress::HandshakeComplete { ssid: ssid.clone() });
                let _ = progress_tx.send(CaptureProgress::Log(format!(
                    "✅ Handshake captured for '{}'",
                    ssid
                )));
            }

            CaptureProgress::Finished {
                output_file,
                packets: state.packets_count.load(Ordering::Relaxed),
            }
        }
        Ok(Err(e)) => {
            let error_msg = e.to_string();
            let _ = progress_tx.send(CaptureProgress::Log(format!(
                "Capture error: {}",
                error_msg
            )));
            CaptureProgress::Error(error_msg)
        }
        Err(e) => {
            let error_msg = format!("Task failed: {}", e);
            let _ = progress_tx.send(CaptureProgress::Log(error_msg.clone()));
            CaptureProgress::Error(error_msg)
        }
    }
}

/// Hashcat crack worker parameters
pub struct HashcatCrackParams {
    pub handshake_path: PathBuf,
    pub wordlist_path: Option<PathBuf>,
    pub min_digits: Option<usize>,
    pub max_digits: Option<usize>,
    pub is_numeric: bool,
}

/// Run hashcat crack in background with progress updates
pub async fn crack_hashcat_async(
    params: HashcatCrackParams,
    state: Arc<CrackState>,
    progress_tx: tokio::sync::mpsc::UnboundedSender<CrackProgress>,
) -> CrackProgress {
    use brutifi::{convert_to_hashcat_format, HashcatParams, HashcatResult};

    let _ = progress_tx.send(CrackProgress::Log(
        "Starting hashcat workflow...".to_string(),
    ));

    if !params.handshake_path.exists() {
        let msg = format!(
            "Handshake file not found: {}",
            params.handshake_path.display()
        );
        let _ = progress_tx.send(CrackProgress::Error(msg.clone()));
        return CrackProgress::Error(msg);
    }

    if !params.is_numeric {
        if let Some(ref wordlist_path) = params.wordlist_path {
            if !wordlist_path.exists() {
                let msg = format!("Wordlist file not found: {}", wordlist_path.display());
                let _ = progress_tx.send(CrackProgress::Error(msg.clone()));
                return CrackProgress::Error(msg);
            }
        }
    }

    // Step 1: Convert PCAP to hashcat format
    let _ = progress_tx.send(CrackProgress::Log(
        "Converting capture file to hashcat format (.22000)...".to_string(),
    ));

    let pcap_path = params.handshake_path.clone();
    let convert_result =
        tokio::task::spawn_blocking(move || convert_to_hashcat_format(&pcap_path)).await;

    let hash_file = match convert_result {
        Ok(Ok(path)) => {
            let _ = progress_tx.send(CrackProgress::Log(format!(
                "Converted to: {}",
                path.display()
            )));
            path
        }
        Ok(Err(e)) => {
            return CrackProgress::Error(format!("Failed to convert capture: {}", e));
        }
        Err(e) => {
            return CrackProgress::Error(format!("Task failed: {}", e));
        }
    };

    // Step 2: Build hashcat params
    let hashcat_params = if params.is_numeric {
        let min = params.min_digits.unwrap_or(8);
        let max = params.max_digits.unwrap_or(8);
        let _ = progress_tx.send(CrackProgress::Log(format!(
            "Starting numeric brute-force attack ({}-{} digits)...",
            min, max
        )));
        HashcatParams::numeric(hash_file.clone(), min, max)
    } else if let Some(wordlist) = params.wordlist_path {
        let _ = progress_tx.send(CrackProgress::Log(format!(
            "Starting wordlist attack with {}...",
            wordlist.display()
        )));
        HashcatParams::wordlist(hash_file.clone(), wordlist)
    } else {
        return CrackProgress::Error("No attack method specified".to_string());
    };

    // Estimate total for numeric
    let total = if params.is_numeric {
        let min = params.min_digits.unwrap_or(8);
        let max = params.max_digits.unwrap_or(8);
        let mut t: u64 = 0;
        for len in min..=max {
            t += 10u64.pow(len as u32);
        }
        t
    } else {
        // Unknown for wordlist
        0
    };

    let _ = progress_tx.send(CrackProgress::Started { total });
    let _ = progress_tx.send(CrackProgress::Log(format!(
        "Hashcat is running (hash file: {}, device type: -D {})",
        hash_file.display(),
        hashcat_params.device_types
    )));

    // Step 3: Run hashcat
    let running = state.running.clone();
    let progress_tx_clone = progress_tx.clone();

    let total_attempts = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(total));
    let total_attempts_clone = total_attempts.clone();

    let result = tokio::task::spawn_blocking(move || {
        brutifi::core::hashcat::run_hashcat(
            &hashcat_params,
            |progress| {
                // Update total attempts when hashcat reports keyspace
                if progress.total_attempts > 0 {
                    total_attempts_clone.store(progress.total_attempts, Ordering::Relaxed);
                }

                let total_attempts_val = total_attempts_clone.load(Ordering::Relaxed);
                let current_attempts = if progress.current_attempts > 0 {
                    progress.current_attempts
                } else if total_attempts_val > 0 && progress.progress_percent > 0.0 {
                    (progress.progress_percent * total_attempts_val as f64) as u64
                } else {
                    0
                };

                // Send progress updates
                let _ = progress_tx_clone.send(CrackProgress::Progress {
                    current: current_attempts,
                    total: total_attempts_val,
                    rate: progress.rate_per_sec,
                });

                let _ = progress_tx_clone.send(CrackProgress::Log(format!(
                    "Hashcat: {} - {}",
                    progress.status, progress.speed
                )));
            },
            &running,
        )
    })
    .await;

    match result {
        Ok(HashcatResult::Found(password)) => {
            let _ = progress_tx.send(CrackProgress::Log(format!(
                "✅ Password found: {}",
                password
            )));
            CrackProgress::Found(password)
        }
        Ok(HashcatResult::NotFound) => {
            let _ = progress_tx.send(CrackProgress::Log(
                "Password not found in search space".to_string(),
            ));
            CrackProgress::NotFound
        }
        Ok(HashcatResult::Stopped) => {
            let _ = progress_tx.send(CrackProgress::Log("Hashcat stopped by user".to_string()));
            CrackProgress::Error("Stopped by user".to_string())
        }
        Ok(HashcatResult::Error(e)) => {
            let _ = progress_tx.send(CrackProgress::Log(format!("Hashcat error: {}", e)));
            CrackProgress::Error(e)
        }
        Err(e) => CrackProgress::Error(format!("Task failed: {}", e)),
    }
}

/// Run WPS attack in background with progress updates
pub async fn wps_attack_async(
    params: brutifi::WpsAttackParams,
    state: Arc<WpsState>,
    progress_tx: tokio::sync::mpsc::UnboundedSender<brutifi::WpsProgress>,
) -> brutifi::WpsResult {
    use brutifi::{run_pin_bruteforce_attack, run_pixie_dust_attack, WpsAttackType};

    let _ = progress_tx.send(brutifi::WpsProgress::Started);

    // Log attack configuration
    let attack_name = match params.attack_type {
        WpsAttackType::PixieDust => "Pixie-Dust",
        WpsAttackType::PinBruteForce => "PIN Brute-Force",
    };

    let _ = progress_tx.send(brutifi::WpsProgress::Log(format!(
        "Starting WPS {} attack on {}",
        attack_name, params.bssid
    )));

    // Run attack in blocking thread
    let running = state.running.clone();
    let progress_tx_clone = progress_tx.clone();

    let result = tokio::task::spawn_blocking(move || match params.attack_type {
        WpsAttackType::PixieDust => run_pixie_dust_attack(&params, &progress_tx_clone, &running),
        WpsAttackType::PinBruteForce => {
            run_pin_bruteforce_attack(&params, &progress_tx_clone, &running)
        }
    })
    .await;

    match result {
        Ok(wps_result) => {
            // Forward the result and send appropriate log messages
            match &wps_result {
                brutifi::WpsResult::Found { pin, password } => {
                    let _ = progress_tx.send(brutifi::WpsProgress::Log(format!(
                        "✅ WPS PIN found: {}",
                        pin
                    )));
                    let _ = progress_tx.send(brutifi::WpsProgress::Log(format!(
                        "✅ WiFi Password: {}",
                        password
                    )));
                }
                brutifi::WpsResult::NotFound => {
                    let _ = progress_tx.send(brutifi::WpsProgress::Log(
                        "Attack completed - no PIN found".to_string(),
                    ));
                }
                brutifi::WpsResult::Stopped => {
                    let _ = progress_tx.send(brutifi::WpsProgress::Log(
                        "Attack stopped by user".to_string(),
                    ));
                }
                brutifi::WpsResult::Error(e) => {
                    let _ =
                        progress_tx.send(brutifi::WpsProgress::Log(format!("Attack error: {}", e)));
                }
            }
            wps_result
        }
        Err(e) => {
            let error_msg = format!("WPS task failed: {}", e);
            let _ = progress_tx.send(brutifi::WpsProgress::Error(error_msg.clone()));
            brutifi::WpsResult::Error(error_msg)
        }
    }
}

/// Run WPA3 attack in background with progress updates
pub async fn wpa3_attack_async(
    params: brutifi::Wpa3AttackParams,
    state: Arc<Wpa3State>,
    progress_tx: tokio::sync::mpsc::UnboundedSender<brutifi::Wpa3Progress>,
) -> brutifi::Wpa3Result {
    use brutifi::{run_sae_capture, run_transition_downgrade_attack, Wpa3AttackType};

    let _ = progress_tx.send(brutifi::Wpa3Progress::Started);

    // Log attack configuration
    let attack_name = match params.attack_type {
        Wpa3AttackType::TransitionDowngrade => "Transition Mode Downgrade",
        Wpa3AttackType::SaeHandshake => "SAE Handshake Capture",
        Wpa3AttackType::DragonbloodScan => "Dragonblood Vulnerability Scan",
    };

    let _ = progress_tx.send(brutifi::Wpa3Progress::Log(format!(
        "Starting WPA3 {} attack on {}",
        attack_name, params.bssid
    )));

    // Run attack in blocking thread
    let running = state.running.clone();
    let progress_tx_clone = progress_tx.clone();

    let result = tokio::task::spawn_blocking(move || match params.attack_type {
        Wpa3AttackType::TransitionDowngrade => {
            run_transition_downgrade_attack(&params, &progress_tx_clone, &running)
        }
        Wpa3AttackType::SaeHandshake => run_sae_capture(&params, &progress_tx_clone, &running),
        Wpa3AttackType::DragonbloodScan => {
            // Dragonblood scan is instant, just return vulnerabilities
            let _ = progress_tx_clone.send(brutifi::Wpa3Progress::Log(
                "Scanning for Dragonblood vulnerabilities...".to_string(),
            ));

            // For now, just indicate that WPA3 networks are potentially vulnerable
            // In a real implementation, we would analyze the network's responses
            let _ = progress_tx_clone.send(brutifi::Wpa3Progress::Log(
                "Note: All WPA3 implementations may be vulnerable to timing attacks".to_string(),
            ));

            brutifi::Wpa3Result::Error("Dragonblood scan not yet fully implemented".to_string())
        }
    })
    .await;

    match result {
        Ok(wpa3_result) => {
            // Forward the result and send appropriate log messages
            match &wpa3_result {
                brutifi::Wpa3Result::Captured {
                    capture_file,
                    hash_file,
                } => {
                    let _ = progress_tx.send(brutifi::Wpa3Progress::Log(format!(
                        "✅ Capture file: {}",
                        capture_file.display()
                    )));
                    let _ = progress_tx.send(brutifi::Wpa3Progress::Log(format!(
                        "✅ Hash file: {}",
                        hash_file.display()
                    )));
                }
                brutifi::Wpa3Result::NotFound => {
                    let _ = progress_tx.send(brutifi::Wpa3Progress::Log(
                        "No handshakes captured".to_string(),
                    ));
                }
                brutifi::Wpa3Result::Stopped => {
                    let _ = progress_tx.send(brutifi::Wpa3Progress::Log(
                        "Attack stopped by user".to_string(),
                    ));
                }
                brutifi::Wpa3Result::Error(e) => {
                    let _ = progress_tx
                        .send(brutifi::Wpa3Progress::Log(format!("Attack error: {}", e)));
                }
            }
            wpa3_result
        }
        Err(e) => {
            let error_msg = format!("WPA3 task failed: {}", e);
            let _ = progress_tx.send(brutifi::Wpa3Progress::Error(error_msg.clone()));
            brutifi::Wpa3Result::Error(error_msg)
        }
    }
}

/// Run Evil Twin attack in background with progress updates
pub async fn evil_twin_attack_async(
    params: brutifi::EvilTwinParams,
    state: Arc<EvilTwinState>,
    progress_tx: tokio::sync::mpsc::UnboundedSender<brutifi::EvilTwinProgress>,
) -> brutifi::EvilTwinResult {
    use brutifi::run_evil_twin_attack;

    let _ = progress_tx.send(brutifi::EvilTwinProgress::Started);

    let _ = progress_tx.send(brutifi::EvilTwinProgress::Log(format!(
        "Starting Evil Twin attack on {} (channel {})",
        params.target_ssid, params.target_channel
    )));

    // Run attack in blocking thread
    let state_clone = state.clone();
    let progress_tx_clone = progress_tx.clone();

    let result = tokio::task::spawn_blocking(move || {
        run_evil_twin_attack(&params, state_clone, &progress_tx_clone)
    })
    .await;

    match result {
        Ok(evil_twin_result) => {
            // Forward the result and send appropriate log messages
            match &evil_twin_result {
                brutifi::EvilTwinResult::Running => {
                    let _ = progress_tx.send(brutifi::EvilTwinProgress::Log(
                        "Attack is running...".to_string(),
                    ));
                }
                brutifi::EvilTwinResult::PasswordFound { password } => {
                    let _ = progress_tx.send(brutifi::EvilTwinProgress::Log(format!(
                        "✅ Valid password found: {}",
                        password
                    )));
                }
                brutifi::EvilTwinResult::Stopped => {
                    let _ = progress_tx.send(brutifi::EvilTwinProgress::Log(
                        "Attack stopped by user".to_string(),
                    ));
                }
                brutifi::EvilTwinResult::Error(e) => {
                    let _ = progress_tx.send(brutifi::EvilTwinProgress::Log(format!(
                        "Attack error: {}",
                        e
                    )));
                }
            }
            evil_twin_result
        }
        Err(e) => {
            let error_msg = format!("Evil Twin task failed: {}", e);
            let _ = progress_tx.send(brutifi::EvilTwinProgress::Error(error_msg.clone()));
            brutifi::EvilTwinResult::Error(error_msg)
        }
    }
}
