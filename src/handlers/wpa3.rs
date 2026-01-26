/*!
 * WPA3 attack handlers
 *
 * Handles WPA3 attack-related messages and state transitions.
 */

use iced::Task;

use crate::app::BruteforceApp;
use crate::messages::Message;
use crate::screens::Wpa3AttackMethod;

impl BruteforceApp {
    /// Handle WPA3 attack method change
    pub fn handle_wpa3_method_changed(&mut self, method: Wpa3AttackMethod) -> Task<Message> {
        if let Some(ref mut wpa3_screen) = self.wpa3_screen {
            wpa3_screen.attack_method = method;
            wpa3_screen.reset();
        }
        Task::none()
    }

    /// Handle WPA3 BSSID input change
    pub fn handle_wpa3_bssid_changed(&mut self, bssid: String) -> Task<Message> {
        if let Some(ref mut wpa3_screen) = self.wpa3_screen {
            wpa3_screen.bssid = bssid;
        }
        Task::none()
    }

    /// Handle WPA3 channel input change
    pub fn handle_wpa3_channel_changed(&mut self, channel: String) -> Task<Message> {
        if let Some(ref mut wpa3_screen) = self.wpa3_screen {
            wpa3_screen.channel = channel;
        }
        Task::none()
    }

    /// Handle WPA3 interface input change
    pub fn handle_wpa3_interface_changed(&mut self, interface: String) -> Task<Message> {
        if let Some(ref mut wpa3_screen) = self.wpa3_screen {
            wpa3_screen.interface = interface;
        }
        Task::none()
    }

    /// Handle start WPA3 attack
    pub fn handle_start_wpa3_attack(&mut self) -> Task<Message> {
        if let Some(ref mut wpa3_screen) = self.wpa3_screen {
            // Parse channel
            let channel: u32 = match wpa3_screen.channel.parse() {
                Ok(ch) => ch,
                Err(_) => {
                    wpa3_screen.error_message = Some("Invalid channel number".to_string());
                    return Task::none();
                }
            };

            // Create output file path with timestamp
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let output_file =
                std::path::PathBuf::from(format!("/tmp/wpa3_capture_{}.pcapng", timestamp));

            // Create attack parameters
            let params = brutifi::Wpa3AttackParams {
                bssid: wpa3_screen.bssid.clone(),
                channel,
                interface: wpa3_screen.interface.clone(),
                attack_type: wpa3_screen.attack_method.into(),
                timeout: std::time::Duration::from_secs(300), // 5 minutes
                output_file,
            };

            // Create progress channel
            let (progress_tx, progress_rx) =
                tokio::sync::mpsc::unbounded_channel::<brutifi::Wpa3Progress>();

            // Create state
            let state = std::sync::Arc::new(crate::workers::Wpa3State::new());
            self.wpa3_state = Some(state.clone());
            self.wpa3_progress_rx = Some(progress_rx);

            // Update UI state
            wpa3_screen.is_attacking = true;
            wpa3_screen.error_message = None;
            wpa3_screen.attack_finished = false;
            wpa3_screen.capture_file = None;
            wpa3_screen.hash_file = None;
            wpa3_screen.status_message = "Starting attack...".to_string();

            // Spawn worker
            return Task::perform(
                crate::workers::wpa3_attack_async(params, state, progress_tx),
                |_| Message::Tick,
            );
        }

        Task::none()
    }

    /// Handle stop WPA3 attack
    pub fn handle_stop_wpa3_attack(&mut self) -> Task<Message> {
        if let Some(ref state) = self.wpa3_state {
            state.stop();
        }

        if let Some(ref mut wpa3_screen) = self.wpa3_screen {
            wpa3_screen.is_attacking = false;
            wpa3_screen.status_message = "Attack stopped by user".to_string();
        }

        self.wpa3_state = None;
        self.wpa3_progress_rx = None;

        Task::none()
    }

    /// Handle WPA3 attack progress updates
    pub fn handle_wpa3_progress(&mut self, progress: brutifi::Wpa3Progress) -> Task<Message> {
        if let Some(ref mut wpa3_screen) = self.wpa3_screen {
            match progress {
                brutifi::Wpa3Progress::Started => {
                    wpa3_screen.status_message = "Attack started".to_string();
                    wpa3_screen.add_log("🚀 Attack started".to_string());
                }
                brutifi::Wpa3Progress::Step {
                    current,
                    total,
                    description,
                } => {
                    wpa3_screen.current_step = current;
                    wpa3_screen.total_steps = total;
                    wpa3_screen.step_description = description.clone();
                    wpa3_screen.status_message =
                        format!("Step {}/{}: {}", current, total, description);
                }
                brutifi::Wpa3Progress::Captured {
                    capture_file,
                    hash_file,
                } => {
                    wpa3_screen.capture_file = Some(capture_file.clone());
                    wpa3_screen.hash_file = Some(hash_file.clone());
                    wpa3_screen.is_attacking = false;
                    wpa3_screen.attack_finished = true;
                    wpa3_screen.status_message = "Capture successful!".to_string();
                    wpa3_screen.add_log(format!("✅ Captured: {}", capture_file.display()));
                    wpa3_screen.add_log(format!("✅ Hash file: {}", hash_file.display()));

                    // Clean up
                    self.wpa3_state = None;
                    self.wpa3_progress_rx = None;
                }
                brutifi::Wpa3Progress::NotFound => {
                    wpa3_screen.is_attacking = false;
                    wpa3_screen.attack_finished = true;
                    wpa3_screen.status_message = "No handshakes captured".to_string();
                    wpa3_screen.add_log("❌ No handshakes found".to_string());

                    // Clean up
                    self.wpa3_state = None;
                    self.wpa3_progress_rx = None;
                }
                brutifi::Wpa3Progress::Error(msg) => {
                    wpa3_screen.error_message = Some(msg.clone());
                    wpa3_screen.is_attacking = false;
                    wpa3_screen.status_message = format!("Error: {}", msg);
                    wpa3_screen.add_log(format!("❌ Error: {}", msg));

                    // Clean up
                    self.wpa3_state = None;
                    self.wpa3_progress_rx = None;
                }
                brutifi::Wpa3Progress::Log(msg) => {
                    wpa3_screen.add_log(msg);
                }
            }
        }

        Task::none()
    }

    /// Handle navigation to WPA3 screen
    pub fn handle_go_to_wpa3(&mut self) -> Task<Message> {
        // Initialize WPA3 screen if not already done
        if self.wpa3_screen.is_none() {
            self.wpa3_screen = Some(crate::screens::Wpa3Screen::default());
        }

        // Stop any ongoing attacks
        if let Some(ref mut wpa3_screen) = self.wpa3_screen {
            if wpa3_screen.is_attacking {
                if let Some(ref state) = self.wpa3_state {
                    state.stop();
                }
                wpa3_screen.is_attacking = false;
                self.wpa3_state = None;
                self.wpa3_progress_rx = None;
            }
        }

        // Update screen
        self.screen = crate::app::Screen::Wpa3;

        Task::none()
    }
}
