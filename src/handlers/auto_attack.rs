/*!
 * Auto Attack handlers
 *
 * Handles automated attack sequence orchestration.
 */

use iced::Task;
use std::sync::Arc;

use crate::app::{BruteforceApp, Screen};
use crate::messages::Message;
use crate::workers::AutoAttackState;
use brutifi::{
    get_attack_timeout, AttackState, AttackStatus, AutoAttackConfig, AutoAttackProgress,
    AutoAttackResult, AutoAttackType,
};

impl BruteforceApp {
    /// Start automated attack sequence
    pub fn handle_start_auto_attack(&mut self) -> Task<Message> {
        // Ensure we have a selected network
        let target_network = match &self.scan_capture_screen.target_network {
            Some(network) => network.clone(),
            None => {
                self.scan_capture_screen.error_message =
                    Some("No network selected for auto attack".to_string());
                return Task::none();
            }
        };

        // Get interface
        let interface = self.scan_capture_screen.selected_interface.clone();
        if interface.is_empty() {
            self.scan_capture_screen.error_message =
                Some("No interface selected for auto attack".to_string());
            return Task::none();
        }

        // Parse channel
        let channel = target_network.channel.parse::<u32>().unwrap_or(6); // Default to channel 6 if parsing fails

        // Create config
        let config = AutoAttackConfig {
            network_ssid: target_network.ssid.clone(),
            network_bssid: target_network.bssid.clone(),
            network_channel: channel,
            network_security: target_network.security.clone(),
            interface: interface.clone(),
            output_dir: std::path::PathBuf::from("/tmp"),
        };

        // Determine attack sequence
        let attack_sequence = brutifi::determine_attack_sequence(&config.network_security);
        if attack_sequence.is_empty() {
            self.scan_capture_screen.error_message = Some(format!(
                "No attacks available for security type: {}",
                config.network_security
            ));
            return Task::none();
        }

        // Check dependencies for all attacks
        let mut missing_tools = Vec::new();
        for attack_type in &attack_sequence {
            if let Err(error) = brutifi::check_attack_dependencies(attack_type) {
                missing_tools.push(format!("• {}: {}", attack_type.display_name(), error));
            }
        }

        if !missing_tools.is_empty() {
            self.scan_capture_screen.error_message = Some(format!(
                "Missing required tools:\n\n{}",
                missing_tools.join("\n")
            ));
            return Task::none();
        }

        // Initialize attack states for UI
        self.scan_capture_screen.auto_attack_attacks = attack_sequence
            .iter()
            .map(|attack_type| AttackState::new(*attack_type, get_attack_timeout(attack_type)))
            .collect();

        // Create channels
        let (progress_tx, progress_rx) =
            tokio::sync::mpsc::unbounded_channel::<AutoAttackProgress>();

        // Create state
        let state = Arc::new(AutoAttackState::new());

        // Store state and channel
        self.auto_attack_state = Some(state.clone());
        self.auto_attack_progress_rx = Some(progress_rx);

        // Open modal
        self.scan_capture_screen.auto_attack_modal_open = true;
        self.scan_capture_screen.auto_attack_running = true;

        // Spawn worker
        Task::perform(
            async move { crate::workers::auto_attack_async(config, state, progress_tx).await },
            |_result| Message::Tick, // Result will be handled via progress channel
        )
    }

    /// Stop automated attack sequence
    pub fn handle_stop_auto_attack(&mut self) -> Task<Message> {
        // Stop the worker if running
        if let Some(state) = &self.auto_attack_state {
            state.stop();
        }

        // Update UI
        self.scan_capture_screen.auto_attack_running = false;

        // Mark all pending/running attacks as stopped
        for attack in &mut self.scan_capture_screen.auto_attack_attacks {
            if attack.status == AttackStatus::Pending || attack.status == AttackStatus::Running {
                attack.status = AttackStatus::Stopped;
                attack.progress_message = "Stopped by user".to_string();
            }
        }

        Task::none()
    }

    /// Handle auto attack progress updates
    pub fn handle_auto_attack_progress(&mut self, progress: AutoAttackProgress) -> Task<Message> {
        match progress {
            AutoAttackProgress::Started { total_attacks } => {
                self.scan_capture_screen.auto_attack_modal_open = true;
                self.scan_capture_screen.auto_attack_running = true;
                self.add_capture_log(format!(
                    "🎯 Starting auto attack sequence ({} attacks)",
                    total_attacks
                ));
            }

            AutoAttackProgress::AttackStarted {
                attack_type,
                index,
                total,
            } => {
                // Update attack state to Running
                if let Some(attack) = self
                    .scan_capture_screen
                    .auto_attack_attacks
                    .iter_mut()
                    .find(|a| a.attack_type == attack_type)
                {
                    attack.status = AttackStatus::Running;
                    attack.progress_message = format!("Starting ({}/{})", index, total);
                    attack.elapsed_time = std::time::Duration::ZERO;
                }

                self.add_capture_log(format!(
                    "🔄 Starting {} ({}/{})",
                    attack_type.display_name(),
                    index,
                    total
                ));

                // Start a timer to update elapsed time every second
                return Task::perform(
                    async move {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        attack_type
                    },
                    Message::UpdateAttackElapsedTime,
                );
            }

            AutoAttackProgress::AttackProgress {
                attack_type,
                message,
            } => {
                // Update progress message for the current attack
                if let Some(attack) = self
                    .scan_capture_screen
                    .auto_attack_attacks
                    .iter_mut()
                    .find(|a| a.attack_type == attack_type)
                {
                    attack.progress_message = message.clone();
                }

                self.add_capture_log(format!("  {}", message));
            }

            AutoAttackProgress::AttackSuccess {
                attack_type,
                result,
            } => {
                // Mark attack as successful
                if let Some(attack) = self
                    .scan_capture_screen
                    .auto_attack_attacks
                    .iter_mut()
                    .find(|a| a.attack_type == attack_type)
                {
                    attack.status = AttackStatus::Success;
                    attack.progress_message = "Success!".to_string();
                }

                self.add_capture_log(format!("✅ {} succeeded!", attack_type.display_name()));

                // Handle different result types
                return self.handle_auto_attack_success(attack_type, result);
            }

            AutoAttackProgress::AttackFailed {
                attack_type,
                reason,
            } => {
                // Mark attack as failed
                if let Some(attack) = self
                    .scan_capture_screen
                    .auto_attack_attacks
                    .iter_mut()
                    .find(|a| a.attack_type == attack_type)
                {
                    attack.status = AttackStatus::Failed;
                    attack.progress_message = reason.clone();
                }

                self.add_capture_log(format!(
                    "❌ {} failed: {}",
                    attack_type.display_name(),
                    reason
                ));
            }

            AutoAttackProgress::AllCompleted { successful_attack } => {
                self.scan_capture_screen.auto_attack_running = false;

                if successful_attack.is_some() {
                    self.add_capture_log(
                        "🎉 Auto attack sequence completed successfully!".to_string(),
                    );
                } else {
                    self.add_capture_log("⚠️  All attacks failed".to_string());
                    self.scan_capture_screen.error_message = Some(
                        "All auto attacks failed. Try manual capture or check your setup."
                            .to_string(),
                    );
                }

                // Clean up state
                self.auto_attack_state = None;
            }

            AutoAttackProgress::Stopped => {
                self.scan_capture_screen.auto_attack_running = false;
                self.add_capture_log("⏹️  Auto attack sequence stopped by user".to_string());

                // Clean up state
                self.auto_attack_state = None;
            }

            AutoAttackProgress::Error(error) => {
                self.scan_capture_screen.auto_attack_running = false;
                self.scan_capture_screen.error_message = Some(error.clone());
                self.add_capture_log(format!("❌ Auto attack error: {}", error));

                // Clean up state
                self.auto_attack_state = None;
            }
        }

        Task::none()
    }

    /// Handle successful attack result
    fn handle_auto_attack_success(
        &mut self,
        attack_type: AutoAttackType,
        result: AutoAttackResult,
    ) -> Task<Message> {
        match result {
            AutoAttackResult::WpsCredentials { pin, password } => {
                // WPS found password - show in crack screen
                self.crack_screen.found_password = Some(password.clone());
                self.crack_screen.ssid = self
                    .scan_capture_screen
                    .target_network
                    .as_ref()
                    .map(|n| n.ssid.clone())
                    .unwrap_or_default();

                self.add_capture_log(format!(
                    "🔑 WPS credentials found! PIN: {}, Password: {}",
                    pin, password
                ));

                // Close modal and navigate to crack screen
                self.scan_capture_screen.auto_attack_modal_open = false;
                self.screen = Screen::Crack;

                Task::none()
            }

            AutoAttackResult::HandshakeCaptured {
                capture_file,
                hash_file,
            } => {
                // Handshake/PMKID captured - navigate to crack screen
                self.crack_screen.handshake_path = hash_file.to_string_lossy().to_string();
                self.crack_screen.ssid = self
                    .scan_capture_screen
                    .target_network
                    .as_ref()
                    .map(|n| n.ssid.clone())
                    .unwrap_or_default();

                self.add_capture_log(format!(
                    "🎯 Handshake captured by {}! File: {}",
                    attack_type.display_name(),
                    capture_file.display()
                ));

                // Close modal and navigate to crack screen
                self.scan_capture_screen.auto_attack_modal_open = false;
                self.screen = Screen::Crack;

                Task::none()
            }

            AutoAttackResult::EvilTwinPassword { password } => {
                // Evil Twin captured password - show in crack screen
                self.crack_screen.found_password = Some(password.clone());
                self.crack_screen.ssid = self
                    .scan_capture_screen
                    .target_network
                    .as_ref()
                    .map(|n| n.ssid.clone())
                    .unwrap_or_default();

                self.add_capture_log(format!("🔑 Evil Twin captured password: {}", password));

                // Close modal and navigate to crack screen
                self.scan_capture_screen.auto_attack_modal_open = false;
                self.screen = Screen::Crack;

                Task::none()
            }
        }
    }

    /// Update elapsed time for currently running attack
    pub fn handle_update_attack_elapsed_time(
        &mut self,
        attack_type: AutoAttackType,
    ) -> Task<Message> {
        // Find the running attack and increment elapsed time
        if let Some(attack) = self
            .scan_capture_screen
            .auto_attack_attacks
            .iter_mut()
            .find(|a| a.attack_type == attack_type && a.status == AttackStatus::Running)
        {
            attack.elapsed_time += std::time::Duration::from_secs(1);

            // Schedule next update if still running
            return Task::perform(
                async move {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    attack_type
                },
                Message::UpdateAttackElapsedTime,
            );
        }

        Task::none()
    }
}
