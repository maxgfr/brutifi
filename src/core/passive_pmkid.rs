/*!
 * Passive PMKID Sniffing
 *
 * Continuous, untargeted PMKID capture from all nearby networks.
 * Runs in background and auto-saves captured PMKIDs.
 */

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Captured PMKID entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapturedPmkid {
    pub ssid: String,
    pub bssid: String,
    pub pmkid: String,
    pub timestamp: u64,
    pub channel: u32,
    pub signal_strength: i32,
}

impl CapturedPmkid {
    /// Create new captured PMKID
    pub fn new(
        ssid: String,
        bssid: String,
        pmkid: String,
        channel: u32,
        signal_strength: i32,
    ) -> Self {
        Self {
            ssid,
            bssid,
            pmkid,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            channel,
            signal_strength,
        }
    }
}

/// Passive PMKID sniffing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassivePmkidConfig {
    pub interface: String,
    pub output_dir: PathBuf,
    pub auto_save: bool,
    pub save_interval_secs: u64,
    pub hop_channels: bool,
    pub channels: Vec<u32>,
}

impl Default for PassivePmkidConfig {
    fn default() -> Self {
        Self {
            interface: "wlan0".to_string(),
            output_dir: PathBuf::from("/tmp/pmkid_captures"),
            auto_save: true,
            save_interval_secs: 60,
            hop_channels: true,
            channels: vec![1, 6, 11], // Common 2.4GHz channels
        }
    }
}

/// Passive PMKID progress events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PassivePmkidProgress {
    Started,
    PmkidCaptured {
        ssid: String,
        bssid: String,
        channel: u32,
    },
    ChannelChanged {
        channel: u32,
    },
    AutoSaved {
        count: usize,
        path: String,
    },
    Statistics {
        total_captured: usize,
        unique_networks: usize,
        runtime_secs: u64,
    },
    Error(String),
    Stopped,
}

/// Passive PMKID result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PassivePmkidResult {
    Running,
    Stopped { total_captured: usize },
    Error(String),
}

/// Passive PMKID capture state
pub struct PassivePmkidState {
    stop_flag: Arc<AtomicBool>,
    captured: Arc<Mutex<HashMap<String, CapturedPmkid>>>, // key: BSSID
    start_time: Arc<Mutex<Option<SystemTime>>>,
}

impl PassivePmkidState {
    pub fn new() -> Self {
        Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
            captured: Arc::new(Mutex::new(HashMap::new())),
            start_time: Arc::new(Mutex::new(None)),
        }
    }

    /// Signal to stop capture
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }

    /// Check if should stop
    pub fn should_stop(&self) -> bool {
        self.stop_flag.load(Ordering::Relaxed)
    }

    /// Add captured PMKID
    pub fn add_pmkid(&self, pmkid: CapturedPmkid) {
        if let Ok(mut captured) = self.captured.lock() {
            captured.insert(pmkid.bssid.clone(), pmkid);
        }
    }

    /// Get all captured PMKIDs
    pub fn get_captured(&self) -> Vec<CapturedPmkid> {
        if let Ok(captured) = self.captured.lock() {
            captured.values().cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Get count of captured PMKIDs
    pub fn count(&self) -> usize {
        if let Ok(captured) = self.captured.lock() {
            captured.len()
        } else {
            0
        }
    }

    /// Set start time
    pub fn set_start_time(&self, time: SystemTime) {
        if let Ok(mut start_time) = self.start_time.lock() {
            *start_time = Some(time);
        }
    }

    /// Get runtime in seconds
    pub fn runtime_secs(&self) -> u64 {
        if let Ok(start_time) = self.start_time.lock() {
            if let Some(start) = *start_time {
                SystemTime::now()
                    .duration_since(start)
                    .unwrap_or_default()
                    .as_secs()
            } else {
                0
            }
        } else {
            0
        }
    }
}

impl Default for PassivePmkidState {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if hcxdumptool is available (required for passive PMKID capture)
pub fn check_hcxdumptool_available() -> bool {
    std::process::Command::new("hcxdumptool")
        .arg("--version")
        .output()
        .is_ok()
}

/// Run passive PMKID capture
pub fn run_passive_pmkid_capture(
    config: &PassivePmkidConfig,
    state: Arc<PassivePmkidState>,
    progress_tx: &tokio::sync::mpsc::UnboundedSender<PassivePmkidProgress>,
) -> PassivePmkidResult {
    state.set_start_time(SystemTime::now());

    let _ = progress_tx.send(PassivePmkidProgress::Started);

    // Check if hcxdumptool is available
    if !check_hcxdumptool_available() {
        let err = "hcxdumptool not found. Install with: apt install hcxdumptool".to_string();
        let _ = progress_tx.send(PassivePmkidProgress::Error(err.clone()));
        return PassivePmkidResult::Error(err);
    }

    // Create output directory if it doesn't exist
    if config.auto_save {
        if let Err(e) = std::fs::create_dir_all(&config.output_dir) {
            let err = format!("Failed to create output directory: {}", e);
            let _ = progress_tx.send(PassivePmkidProgress::Error(err.clone()));
            return PassivePmkidResult::Error(err);
        }
    }

    // TODO: Implement actual passive PMKID capture with hcxdumptool
    // This is a placeholder that would need actual implementation
    let _ = progress_tx.send(PassivePmkidProgress::Error(
        "Passive PMKID capture not yet fully implemented".to_string(),
    ));

    PassivePmkidResult::Stopped {
        total_captured: state.count(),
    }
}

/// Save captured PMKIDs to file
pub fn save_captured_pmkids(pmkids: &[CapturedPmkid], output_path: &PathBuf) -> Result<(), String> {
    // Save as JSON
    let json = serde_json::to_string_pretty(pmkids)
        .map_err(|e| format!("Failed to serialize PMKIDs: {}", e))?;

    std::fs::write(output_path, json).map_err(|e| format!("Failed to write file: {}", e))?;

    Ok(())
}

/// Load captured PMKIDs from file
pub fn load_captured_pmkids(input_path: &PathBuf) -> Result<Vec<CapturedPmkid>, String> {
    let json =
        std::fs::read_to_string(input_path).map_err(|e| format!("Failed to read file: {}", e))?;

    let pmkids: Vec<CapturedPmkid> =
        serde_json::from_str(&json).map_err(|e| format!("Failed to parse PMKIDs: {}", e))?;

    Ok(pmkids)
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // CapturedPmkid Tests
    // =========================================================================

    #[test]
    fn test_captured_pmkid_creation() {
        let pmkid = CapturedPmkid::new(
            "TestNetwork".to_string(),
            "AA:BB:CC:DD:EE:FF".to_string(),
            "abcdef1234567890".to_string(),
            6,
            -50,
        );

        assert_eq!(pmkid.ssid, "TestNetwork");
        assert_eq!(pmkid.bssid, "AA:BB:CC:DD:EE:FF");
        assert_eq!(pmkid.pmkid, "abcdef1234567890");
        assert_eq!(pmkid.channel, 6);
        assert_eq!(pmkid.signal_strength, -50);
        assert!(pmkid.timestamp > 0);
    }

    #[test]
    fn test_captured_pmkid_clone() {
        let pmkid = CapturedPmkid::new(
            "Test".to_string(),
            "AA:BB:CC:DD:EE:FF".to_string(),
            "abcd".to_string(),
            1,
            -60,
        );

        let cloned = pmkid.clone();
        assert_eq!(pmkid, cloned);
    }

    #[test]
    fn test_captured_pmkid_serialization() {
        let pmkid = CapturedPmkid::new(
            "Test".to_string(),
            "AA:BB:CC:DD:EE:FF".to_string(),
            "abcd".to_string(),
            1,
            -60,
        );

        let json = serde_json::to_string(&pmkid).unwrap();
        let deserialized: CapturedPmkid = serde_json::from_str(&json).unwrap();
        assert_eq!(pmkid, deserialized);
    }

    // =========================================================================
    // PassivePmkidConfig Tests
    // =========================================================================

    #[test]
    fn test_passive_pmkid_config_default() {
        let config = PassivePmkidConfig::default();
        assert_eq!(config.interface, "wlan0");
        assert!(config.auto_save);
        assert_eq!(config.save_interval_secs, 60);
        assert!(config.hop_channels);
        assert_eq!(config.channels, vec![1, 6, 11]);
    }

    #[test]
    fn test_passive_pmkid_config_serialization() {
        let config = PassivePmkidConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: PassivePmkidConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.interface, deserialized.interface);
    }

    // =========================================================================
    // PassivePmkidState Tests
    // =========================================================================

    #[test]
    fn test_passive_pmkid_state_new() {
        let state = PassivePmkidState::new();
        assert!(!state.should_stop());
        assert_eq!(state.count(), 0);
    }

    #[test]
    fn test_passive_pmkid_state_stop() {
        let state = PassivePmkidState::new();
        assert!(!state.should_stop());
        state.stop();
        assert!(state.should_stop());
    }

    #[test]
    fn test_passive_pmkid_state_add_pmkid() {
        let state = PassivePmkidState::new();
        let pmkid = CapturedPmkid::new(
            "Test".to_string(),
            "AA:BB:CC:DD:EE:FF".to_string(),
            "abcd".to_string(),
            1,
            -60,
        );

        state.add_pmkid(pmkid.clone());
        assert_eq!(state.count(), 1);

        let captured = state.get_captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0], pmkid);
    }

    #[test]
    fn test_passive_pmkid_state_multiple_pmkids() {
        let state = PassivePmkidState::new();

        for i in 0..5 {
            let pmkid = CapturedPmkid::new(
                format!("Network{}", i),
                format!("AA:BB:CC:DD:EE:{:02X}", i),
                format!("pmkid{}", i),
                1,
                -60,
            );
            state.add_pmkid(pmkid);
        }

        assert_eq!(state.count(), 5);
    }

    #[test]
    fn test_passive_pmkid_state_duplicate_bssid() {
        let state = PassivePmkidState::new();

        let pmkid1 = CapturedPmkid::new(
            "Network1".to_string(),
            "AA:BB:CC:DD:EE:FF".to_string(),
            "pmkid1".to_string(),
            1,
            -60,
        );

        let pmkid2 = CapturedPmkid::new(
            "Network1".to_string(),
            "AA:BB:CC:DD:EE:FF".to_string(), // Same BSSID
            "pmkid2".to_string(),            // Different PMKID
            1,
            -65,
        );

        state.add_pmkid(pmkid1);
        state.add_pmkid(pmkid2.clone());

        // Should replace first with second (same BSSID)
        assert_eq!(state.count(), 1);
        let captured = state.get_captured();
        assert_eq!(captured[0].pmkid, "pmkid2");
    }

    #[test]
    fn test_passive_pmkid_state_runtime() {
        let state = PassivePmkidState::new();
        state.set_start_time(SystemTime::now());
        std::thread::sleep(std::time::Duration::from_millis(100));
        let runtime = state.runtime_secs();
        // Should be 0 or 1 second (very short sleep)
        assert!(runtime <= 1);
    }

    // =========================================================================
    // Progress Events Tests
    // =========================================================================

    #[test]
    fn test_passive_pmkid_progress_serialization() {
        let progress = PassivePmkidProgress::PmkidCaptured {
            ssid: "Test".to_string(),
            bssid: "AA:BB:CC:DD:EE:FF".to_string(),
            channel: 6,
        };

        let json = serde_json::to_string(&progress).unwrap();
        assert!(json.contains("Test"));
        assert!(json.contains("AA:BB:CC:DD:EE:FF"));
    }

    #[test]
    fn test_passive_pmkid_result_serialization() {
        let result = PassivePmkidResult::Stopped { total_captured: 10 };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("10"));
    }

    // =========================================================================
    // File Operations Tests
    // =========================================================================

    #[test]
    fn test_save_and_load_pmkids() {
        let temp_path = PathBuf::from("/tmp/test_pmkids.json");

        let pmkids = vec![
            CapturedPmkid::new(
                "Network1".to_string(),
                "AA:BB:CC:DD:EE:FF".to_string(),
                "pmkid1".to_string(),
                1,
                -50,
            ),
            CapturedPmkid::new(
                "Network2".to_string(),
                "11:22:33:44:55:66".to_string(),
                "pmkid2".to_string(),
                6,
                -60,
            ),
        ];

        // Save
        let result = save_captured_pmkids(&pmkids, &temp_path);
        assert!(result.is_ok());

        // Load
        let loaded = load_captured_pmkids(&temp_path);
        assert!(loaded.is_ok());
        let loaded_pmkids = loaded.unwrap();
        assert_eq!(loaded_pmkids.len(), 2);
        assert_eq!(loaded_pmkids[0].ssid, "Network1");
        assert_eq!(loaded_pmkids[1].ssid, "Network2");

        // Cleanup
        let _ = std::fs::remove_file(&temp_path);
    }

    #[test]
    fn test_load_nonexistent_file() {
        let path = PathBuf::from("/tmp/nonexistent_pmkids.json");
        let result = load_captured_pmkids(&path);
        assert!(result.is_err());
    }

    // =========================================================================
    // Tool Detection Tests
    // =========================================================================

    #[test]
    fn test_check_hcxdumptool_available() {
        // Should not panic
        let _available = check_hcxdumptool_available();
        // Result depends on system, so we just verify it doesn't crash
    }
}
