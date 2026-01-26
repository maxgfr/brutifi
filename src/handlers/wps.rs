/*!
 * WPS attack handlers
 *
 * Handles WPS attack-related messages and state transitions.
 */

use iced::Task;

use crate::app::BruteforceApp;
use crate::messages::Message;
use crate::screens::WpsAttackMethod;

impl BruteforceApp {
    /// Handle WPS attack method change
    pub fn handle_wps_method_changed(&mut self, method: WpsAttackMethod) -> Task<Message> {
        if let Some(ref mut wps_screen) = self.wps_screen {
            wps_screen.attack_method = method;
            wps_screen.reset();
        }
        Task::none()
    }

    /// Handle WPS BSSID input change
    pub fn handle_wps_bssid_changed(&mut self, bssid: String) -> Task<Message> {
        if let Some(ref mut wps_screen) = self.wps_screen {
            wps_screen.bssid = bssid;
        }
        Task::none()
    }

    /// Handle WPS channel input change
    pub fn handle_wps_channel_changed(&mut self, channel: String) -> Task<Message> {
        if let Some(ref mut wps_screen) = self.wps_screen {
            wps_screen.channel = channel;
        }
        Task::none()
    }

    /// Handle WPS interface input change
    pub fn handle_wps_interface_changed(&mut self, interface: String) -> Task<Message> {
        if let Some(ref mut wps_screen) = self.wps_screen {
            wps_screen.interface = interface;
        }
        Task::none()
    }

    /// Handle WPS custom PIN input change
    pub fn handle_wps_custom_pin_changed(&mut self, pin: String) -> Task<Message> {
        if let Some(ref mut wps_screen) = self.wps_screen {
            wps_screen.custom_pin = pin;
        }
        Task::none()
    }

    /// Handle start WPS attack
    pub fn handle_start_wps_attack(&mut self) -> Task<Message> {
        if let Some(ref mut wps_screen) = self.wps_screen {
            // Parse channel
            let channel: u32 = match wps_screen.channel.parse() {
                Ok(ch) => ch,
                Err(_) => {
                    wps_screen.error_message = Some("Invalid channel number".to_string());
                    return Task::none();
                }
            };

            // Create attack parameters
            let params = brutifi::WpsAttackParams {
                bssid: wps_screen.bssid.clone(),
                channel,
                attack_type: wps_screen.attack_method.into(),
                timeout: std::time::Duration::from_secs(300), // 5 minutes
                interface: wps_screen.interface.clone(),
                custom_pin: if wps_screen.custom_pin.is_empty() {
                    None
                } else {
                    Some(wps_screen.custom_pin.clone())
                },
            };

            // Create progress channel
            let (progress_tx, progress_rx) =
                tokio::sync::mpsc::unbounded_channel::<brutifi::WpsProgress>();

            // Create state
            let state = std::sync::Arc::new(crate::workers::WpsState::new());
            self.wps_state = Some(state.clone());
            self.wps_progress_rx = Some(progress_rx);

            // Update UI state
            wps_screen.is_attacking = true;
            wps_screen.error_message = None;
            wps_screen.attack_finished = false;
            wps_screen.found_pin = None;
            wps_screen.found_password = None;
            wps_screen.status_message = "Starting attack...".to_string();

            // Spawn worker
            return Task::perform(
                crate::workers::wps_attack_async(params, state, progress_tx),
                |_| Message::Tick,
            );
        }

        Task::none()
    }

    /// Handle stop WPS attack
    pub fn handle_stop_wps_attack(&mut self) -> Task<Message> {
        if let Some(ref state) = self.wps_state {
            state.stop();
        }

        if let Some(ref mut wps_screen) = self.wps_screen {
            wps_screen.is_attacking = false;
            wps_screen.status_message = "Attack stopped by user".to_string();
        }

        self.wps_state = None;
        self.wps_progress_rx = None;

        Task::none()
    }

    /// Handle WPS attack progress updates
    pub fn handle_wps_progress(&mut self, progress: brutifi::WpsProgress) -> Task<Message> {
        if let Some(ref mut wps_screen) = self.wps_screen {
            match progress {
                brutifi::WpsProgress::Started => {
                    wps_screen.status_message = "Attack started".to_string();
                    wps_screen.add_log("🚀 Attack started".to_string());
                }
                brutifi::WpsProgress::Step {
                    current,
                    total,
                    description,
                } => {
                    wps_screen.current_step = current;
                    wps_screen.total_steps = total;
                    wps_screen.step_description = description.clone();
                    wps_screen.status_message =
                        format!("Step {}/{}: {}", current, total, description);
                }
                brutifi::WpsProgress::Found { pin, password } => {
                    wps_screen.found_pin = Some(pin.clone());
                    wps_screen.found_password = Some(password.clone());
                    wps_screen.is_attacking = false;
                    wps_screen.attack_finished = true;
                    wps_screen.status_message = "Attack successful!".to_string();
                    wps_screen.add_log(format!("✅ PIN found: {}", pin));
                    wps_screen.add_log(format!("✅ Password: {}", password));

                    // Clean up
                    self.wps_state = None;
                    self.wps_progress_rx = None;
                }
                brutifi::WpsProgress::NotFound => {
                    wps_screen.is_attacking = false;
                    wps_screen.attack_finished = true;
                    wps_screen.status_message = "Attack completed - no PIN found".to_string();
                    wps_screen.add_log("❌ No PIN found".to_string());

                    // Clean up
                    self.wps_state = None;
                    self.wps_progress_rx = None;
                }
                brutifi::WpsProgress::Error(msg) => {
                    wps_screen.error_message = Some(msg.clone());
                    wps_screen.is_attacking = false;
                    wps_screen.status_message = format!("Error: {}", msg);
                    wps_screen.add_log(format!("❌ Error: {}", msg));

                    // Clean up
                    self.wps_state = None;
                    self.wps_progress_rx = None;
                }
                brutifi::WpsProgress::Log(msg) => {
                    wps_screen.add_log(msg);
                }
            }
        }

        Task::none()
    }

    /// Handle navigation to WPS screen
    pub fn handle_go_to_wps(&mut self) -> Task<Message> {
        // Initialize WPS screen if not already done
        if self.wps_screen.is_none() {
            self.wps_screen = Some(crate::screens::WpsScreen::default());
        }

        // Stop any ongoing attacks
        if let Some(ref mut wps_screen) = self.wps_screen {
            if wps_screen.is_attacking {
                if let Some(ref state) = self.wps_state {
                    state.stop();
                }
                wps_screen.is_attacking = false;
                self.wps_state = None;
                self.wps_progress_rx = None;
            }
        }

        // Update screen
        self.screen = crate::app::Screen::Wps;

        Task::none()
    }
}
