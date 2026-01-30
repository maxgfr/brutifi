/*!
 * Session Resume
 *
 * Save and restore attack sessions to handle interruptions (Ctrl+C, crashes, power loss).
 */

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Session metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub id: String,
    pub created_at: u64,
    pub last_updated: u64,
    pub attack_type: AttackType,
    pub status: SessionStatus,
    pub description: String,
}

/// Attack type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackType {
    WpaHandshake,
    Pmkid,
    Wpa3Sae,
    WpsPixieDust,
    WpsPinBruteforce,
    EvilTwin,
    PassivePmkid,
}

/// Session status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    Running,
    Paused,
    Completed,
    Failed,
}

/// Session data - stores attack state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub metadata: SessionMetadata,
    pub config: SessionConfig,
    pub progress: SessionProgress,
}

/// Session configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub interface: String,
    pub target_ssid: Option<String>,
    pub target_bssid: Option<String>,
    pub target_channel: Option<u32>,
    pub attack_params: HashMap<String, String>,
}

/// Session progress
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionProgress {
    pub completed_targets: Vec<String>,
    pub failed_targets: Vec<String>,
    pub current_target: Option<String>,
    pub attempts: u64,
    pub start_time: u64,
    pub elapsed_secs: u64,
}

impl SessionData {
    /// Create new session
    pub fn new(attack_type: AttackType, description: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let id = format!("session_{}", now);

        Self {
            metadata: SessionMetadata {
                id,
                created_at: now,
                last_updated: now,
                attack_type,
                status: SessionStatus::Running,
                description,
            },
            config: SessionConfig {
                interface: String::new(),
                target_ssid: None,
                target_bssid: None,
                target_channel: None,
                attack_params: HashMap::new(),
            },
            progress: SessionProgress {
                completed_targets: Vec::new(),
                failed_targets: Vec::new(),
                current_target: None,
                attempts: 0,
                start_time: now,
                elapsed_secs: 0,
            },
        }
    }

    /// Update last modified time
    pub fn touch(&mut self) {
        self.metadata.last_updated = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Mark session as completed
    pub fn complete(&mut self) {
        self.metadata.status = SessionStatus::Completed;
        self.touch();
    }

    /// Mark session as failed
    pub fn fail(&mut self) {
        self.metadata.status = SessionStatus::Failed;
        self.touch();
    }

    /// Add completed target
    pub fn add_completed(&mut self, target: String) {
        self.progress.completed_targets.push(target);
        self.touch();
    }

    /// Add failed target
    pub fn add_failed(&mut self, target: String) {
        self.progress.failed_targets.push(target);
        self.touch();
    }
}

/// Session manager
pub struct SessionManager {
    sessions_dir: PathBuf,
}

impl SessionManager {
    /// Create new session manager
    pub fn new(sessions_dir: PathBuf) -> Self {
        Self { sessions_dir }
    }

    /// Get default sessions directory
    pub fn default_sessions_dir() -> Result<PathBuf, String> {
        let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
        Ok(PathBuf::from(home).join(".brutifi/sessions"))
    }

    /// Initialize sessions directory
    pub fn init(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.sessions_dir)
            .map_err(|e| format!("Failed to create sessions directory: {}", e))
    }

    /// Save session
    pub fn save(&self, session: &SessionData) -> Result<(), String> {
        self.init()?;

        let file_path = self
            .sessions_dir
            .join(format!("{}.json", session.metadata.id));
        let json = serde_json::to_string_pretty(session)
            .map_err(|e| format!("Failed to serialize session: {}", e))?;

        std::fs::write(&file_path, json)
            .map_err(|e| format!("Failed to write session file: {}", e))?;

        Ok(())
    }

    /// Load session by ID
    pub fn load(&self, session_id: &str) -> Result<SessionData, String> {
        let file_path = self.sessions_dir.join(format!("{}.json", session_id));

        if !file_path.exists() {
            return Err(format!("Session {} not found", session_id));
        }

        let json = std::fs::read_to_string(&file_path)
            .map_err(|e| format!("Failed to read session file: {}", e))?;

        let session: SessionData =
            serde_json::from_str(&json).map_err(|e| format!("Failed to parse session: {}", e))?;

        Ok(session)
    }

    /// List all sessions
    pub fn list(&self) -> Result<Vec<SessionMetadata>, String> {
        if !self.sessions_dir.exists() {
            return Ok(Vec::new());
        }

        let entries = std::fs::read_dir(&self.sessions_dir)
            .map_err(|e| format!("Failed to read sessions directory: {}", e))?;

        let mut sessions = Vec::new();

        for entry in entries.flatten() {
            if let Ok(path) = entry.path().canonicalize() {
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    if let Ok(json) = std::fs::read_to_string(&path) {
                        if let Ok(session) = serde_json::from_str::<SessionData>(&json) {
                            sessions.push(session.metadata);
                        }
                    }
                }
            }
        }

        // Sort by last_updated (newest first)
        sessions.sort_by(|a, b| b.last_updated.cmp(&a.last_updated));

        Ok(sessions)
    }

    /// Delete session
    pub fn delete(&self, session_id: &str) -> Result<(), String> {
        let file_path = self.sessions_dir.join(format!("{}.json", session_id));

        if !file_path.exists() {
            return Err(format!("Session {} not found", session_id));
        }

        std::fs::remove_file(&file_path).map_err(|e| format!("Failed to delete session: {}", e))?;

        Ok(())
    }

    /// Clean old sessions (older than given days)
    pub fn clean_old(&self, days: u64) -> Result<usize, String> {
        let sessions = self.list()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let cutoff = now - (days * 24 * 60 * 60);

        let mut count = 0;
        for session in sessions {
            if session.last_updated < cutoff {
                self.delete(&session.id)?;
                count += 1;
            }
        }

        Ok(count)
    }

    /// Get most recent session
    pub fn get_latest(&self) -> Result<Option<SessionData>, String> {
        let sessions = self.list()?;
        if sessions.is_empty() {
            return Ok(None);
        }

        let latest = &sessions[0];
        self.load(&latest.id).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // SessionData Tests
    // =========================================================================

    #[test]
    fn test_session_data_new() {
        let session = SessionData::new(AttackType::WpaHandshake, "Test session".to_string());

        assert_eq!(session.metadata.attack_type, AttackType::WpaHandshake);
        assert_eq!(session.metadata.status, SessionStatus::Running);
        assert_eq!(session.metadata.description, "Test session");
        assert!(session.metadata.id.starts_with("session_"));
        assert!(session.metadata.created_at > 0);
    }

    #[test]
    fn test_session_data_touch() {
        let mut session = SessionData::new(AttackType::Pmkid, "Test".to_string());
        let original_time = session.metadata.last_updated;

        std::thread::sleep(std::time::Duration::from_millis(10));
        session.touch();

        assert!(session.metadata.last_updated >= original_time);
    }

    #[test]
    fn test_session_data_complete() {
        let mut session = SessionData::new(AttackType::WpsPixieDust, "Test".to_string());
        session.complete();

        assert_eq!(session.metadata.status, SessionStatus::Completed);
    }

    #[test]
    fn test_session_data_fail() {
        let mut session = SessionData::new(AttackType::EvilTwin, "Test".to_string());
        session.fail();

        assert_eq!(session.metadata.status, SessionStatus::Failed);
    }

    #[test]
    fn test_session_data_add_completed() {
        let mut session = SessionData::new(AttackType::WpaHandshake, "Test".to_string());
        session.add_completed("Network1".to_string());
        session.add_completed("Network2".to_string());

        assert_eq!(session.progress.completed_targets.len(), 2);
        assert_eq!(session.progress.completed_targets[0], "Network1");
        assert_eq!(session.progress.completed_targets[1], "Network2");
    }

    #[test]
    fn test_session_data_add_failed() {
        let mut session = SessionData::new(AttackType::Wpa3Sae, "Test".to_string());
        session.add_failed("Network1".to_string());

        assert_eq!(session.progress.failed_targets.len(), 1);
        assert_eq!(session.progress.failed_targets[0], "Network1");
    }

    #[test]
    fn test_session_data_serialization() {
        let session = SessionData::new(AttackType::PassivePmkid, "Test".to_string());

        let json = serde_json::to_string(&session).unwrap();
        let deserialized: SessionData = serde_json::from_str(&json).unwrap();

        assert_eq!(session.metadata.id, deserialized.metadata.id);
        assert_eq!(
            session.metadata.attack_type,
            deserialized.metadata.attack_type
        );
    }

    // =========================================================================
    // SessionManager Tests
    // =========================================================================

    #[test]
    fn test_session_manager_new() {
        let temp_dir = PathBuf::from("/tmp/test_sessions");
        let manager = SessionManager::new(temp_dir.clone());

        assert_eq!(manager.sessions_dir, temp_dir);
    }

    #[test]
    fn test_session_manager_init() {
        let temp_dir = PathBuf::from("/tmp/test_sessions_init");
        let manager = SessionManager::new(temp_dir.clone());

        let result = manager.init();
        assert!(result.is_ok());
        assert!(temp_dir.exists());

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_session_manager_save_and_load() {
        let temp_dir = PathBuf::from("/tmp/test_sessions_save_load");
        let manager = SessionManager::new(temp_dir.clone());

        let session = SessionData::new(AttackType::WpaHandshake, "Test save/load".to_string());
        let session_id = session.metadata.id.clone();

        // Save
        let result = manager.save(&session);
        assert!(result.is_ok());

        // Load
        let loaded = manager.load(&session_id);
        assert!(loaded.is_ok());
        let loaded_session = loaded.unwrap();
        assert_eq!(loaded_session.metadata.id, session_id);
        assert_eq!(loaded_session.metadata.description, "Test save/load");

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_session_manager_load_nonexistent() {
        let temp_dir = PathBuf::from("/tmp/test_sessions_nonexistent");
        let manager = SessionManager::new(temp_dir.clone());

        let result = manager.load("nonexistent_session");
        assert!(result.is_err());

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_session_manager_list() {
        let temp_dir = PathBuf::from("/tmp/test_sessions_list_v2");
        let _ = std::fs::remove_dir_all(&temp_dir); // Clean first
        let manager = SessionManager::new(temp_dir.clone());

        // Save multiple sessions with unique IDs
        for i in 0..3 {
            let mut session = SessionData::new(AttackType::WpaHandshake, format!("Session {}", i));
            // Generate unique ID to avoid collisions
            session.metadata.id = format!("session_test_{}", i);
            // Set different timestamps to ensure ordering
            session.metadata.last_updated = session.metadata.created_at + i;
            let _ = manager.save(&session);
        }

        // List
        let result = manager.list();
        assert!(result.is_ok());
        let sessions = result.unwrap();
        assert_eq!(sessions.len(), 3);

        // Should be sorted by last_updated (newest first)
        assert!(sessions[0].last_updated >= sessions[1].last_updated);
        assert!(sessions[1].last_updated >= sessions[2].last_updated);

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_session_manager_delete() {
        let temp_dir = PathBuf::from("/tmp/test_sessions_delete");
        let manager = SessionManager::new(temp_dir.clone());

        let session = SessionData::new(AttackType::Pmkid, "Test delete".to_string());
        let session_id = session.metadata.id.clone();

        // Save
        let _ = manager.save(&session);

        // Verify it exists
        let load_result = manager.load(&session_id);
        assert!(load_result.is_ok());

        // Delete
        let delete_result = manager.delete(&session_id);
        assert!(delete_result.is_ok());

        // Verify it's gone
        let load_result2 = manager.load(&session_id);
        assert!(load_result2.is_err());

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_session_manager_clean_old() {
        let temp_dir = PathBuf::from("/tmp/test_sessions_clean_v2");
        let _ = std::fs::remove_dir_all(&temp_dir); // Clean first
        let manager = SessionManager::new(temp_dir.clone());

        // Create an old session (simulate by modifying timestamp)
        let mut old_session = SessionData::new(AttackType::WpaHandshake, "Old".to_string());
        old_session.metadata.id = "session_test_old".to_string();
        old_session.metadata.last_updated = 1000000; // Very old timestamp
        let _ = manager.save(&old_session);

        // Create a new session
        let mut new_session = SessionData::new(AttackType::Pmkid, "New".to_string());
        new_session.metadata.id = "session_test_new".to_string();
        let _ = manager.save(&new_session);

        // Clean sessions older than 7 days
        let result = manager.clean_old(7);
        assert!(result.is_ok());
        let count = result.unwrap();
        assert_eq!(count, 1); // Only old session should be deleted

        // Verify
        let sessions = manager.list().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].description, "New");

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_session_manager_get_latest() {
        let temp_dir = PathBuf::from("/tmp/test_sessions_latest");
        let manager = SessionManager::new(temp_dir.clone());

        // Empty directory
        let result = manager.get_latest();
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Save sessions
        let session1 = SessionData::new(AttackType::WpaHandshake, "First".to_string());
        let _ = manager.save(&session1);
        std::thread::sleep(std::time::Duration::from_millis(10));

        let session2 = SessionData::new(AttackType::Pmkid, "Second".to_string());
        let _ = manager.save(&session2);

        // Get latest
        let result = manager.get_latest();
        assert!(result.is_ok());
        let latest = result.unwrap();
        assert!(latest.is_some());
        let latest_session = latest.unwrap();
        assert_eq!(latest_session.metadata.description, "Second");

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    // =========================================================================
    // AttackType Tests
    // =========================================================================

    #[test]
    fn test_attack_type_serialization() {
        let attack_type = AttackType::WpaHandshake;
        let json = serde_json::to_string(&attack_type).unwrap();
        let deserialized: AttackType = serde_json::from_str(&json).unwrap();
        assert_eq!(attack_type, deserialized);
    }

    // =========================================================================
    // SessionStatus Tests
    // =========================================================================

    #[test]
    fn test_session_status_serialization() {
        let status = SessionStatus::Completed;
        let json = serde_json::to_string(&status).unwrap();
        let deserialized: SessionStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, deserialized);
    }
}
