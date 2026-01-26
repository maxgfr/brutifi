/*!
 * Evil Twin attack handlers
 *
 * Handles Evil Twin attack-related messages and state transitions.
 */

use iced::Task;

use crate::app::BruteforceApp;
use crate::messages::Message;
use crate::screens::EvilTwinPortalTemplate;

impl BruteforceApp {
    /// Handle Evil Twin portal template change
    pub fn handle_evil_twin_template_changed(
        &mut self,
        template: EvilTwinPortalTemplate,
    ) -> Task<Message> {
        if let Some(ref mut evil_twin_screen) = self.evil_twin_screen {
            evil_twin_screen.portal_template = template;
            evil_twin_screen.reset();
        }
        Task::none()
    }

    /// Handle Evil Twin SSID input change
    pub fn handle_evil_twin_ssid_changed(&mut self, ssid: String) -> Task<Message> {
        if let Some(ref mut evil_twin_screen) = self.evil_twin_screen {
            evil_twin_screen.target_ssid = ssid;
        }
        Task::none()
    }

    /// Handle Evil Twin BSSID input change
    pub fn handle_evil_twin_bssid_changed(&mut self, bssid: String) -> Task<Message> {
        if let Some(ref mut evil_twin_screen) = self.evil_twin_screen {
            evil_twin_screen.target_bssid = bssid;
        }
        Task::none()
    }

    /// Handle Evil Twin channel input change
    pub fn handle_evil_twin_channel_changed(&mut self, channel: String) -> Task<Message> {
        if let Some(ref mut evil_twin_screen) = self.evil_twin_screen {
            evil_twin_screen.target_channel = channel;
        }
        Task::none()
    }

    /// Handle Evil Twin interface input change
    pub fn handle_evil_twin_interface_changed(&mut self, interface: String) -> Task<Message> {
        if let Some(ref mut evil_twin_screen) = self.evil_twin_screen {
            evil_twin_screen.interface = interface;
        }
        Task::none()
    }

    /// Handle start Evil Twin attack
    pub fn handle_start_evil_twin_attack(&mut self) -> Task<Message> {
        if let Some(ref mut evil_twin_screen) = self.evil_twin_screen {
            // Parse channel
            let channel: u32 = match evil_twin_screen.target_channel.parse() {
                Ok(ch) => ch,
                Err(_) => {
                    evil_twin_screen.error_message = Some("Invalid channel number".to_string());
                    return Task::none();
                }
            };

            // Create attack parameters
            let params = brutifi::EvilTwinParams {
                target_ssid: evil_twin_screen.target_ssid.clone(),
                target_bssid: if evil_twin_screen.target_bssid.is_empty() {
                    None
                } else {
                    Some(evil_twin_screen.target_bssid.clone())
                },
                target_channel: channel,
                interface: evil_twin_screen.interface.clone(),
                portal_template: evil_twin_screen.portal_template.into(),
                ..Default::default()
            };

            // Create progress channel
            let (progress_tx, progress_rx) =
                tokio::sync::mpsc::unbounded_channel::<brutifi::EvilTwinProgress>();

            // Create state
            let state = std::sync::Arc::new(crate::workers::EvilTwinState::new());
            self.evil_twin_state = Some(state.clone());
            self.evil_twin_progress_rx = Some(progress_rx);

            // Update UI state
            evil_twin_screen.is_attacking = true;
            evil_twin_screen.error_message = None;
            evil_twin_screen.attack_finished = false;
            evil_twin_screen.found_password = None;
            evil_twin_screen.status_message = "Starting Evil Twin attack...".to_string();

            // Spawn worker
            return Task::perform(
                crate::workers::evil_twin_attack_async(params, state, progress_tx),
                |_| Message::Tick,
            );
        }

        Task::none()
    }

    /// Handle stop Evil Twin attack
    pub fn handle_stop_evil_twin_attack(&mut self) -> Task<Message> {
        if let Some(ref state) = self.evil_twin_state {
            state.stop();
        }

        if let Some(ref mut evil_twin_screen) = self.evil_twin_screen {
            evil_twin_screen.is_attacking = false;
            evil_twin_screen.status_message = "Attack stopped by user".to_string();
        }

        self.evil_twin_state = None;
        self.evil_twin_progress_rx = None;

        Task::none()
    }

    /// Handle Evil Twin attack progress updates
    pub fn handle_evil_twin_progress(
        &mut self,
        progress: brutifi::EvilTwinProgress,
    ) -> Task<Message> {
        if let Some(ref mut evil_twin_screen) = self.evil_twin_screen {
            match progress {
                brutifi::EvilTwinProgress::Started => {
                    evil_twin_screen.status_message = "Attack started".to_string();
                    evil_twin_screen.add_log("🚀 Evil Twin attack started".to_string());
                }
                brutifi::EvilTwinProgress::Step {
                    current,
                    total,
                    description,
                } => {
                    evil_twin_screen.current_step = current;
                    evil_twin_screen.total_steps = total;
                    evil_twin_screen.step_description = description.clone();
                    evil_twin_screen.status_message =
                        format!("Step {}/{}: {}", current, total, description);
                }
                brutifi::EvilTwinProgress::ClientConnected { mac, ip } => {
                    evil_twin_screen
                        .clients_connected
                        .push((mac.clone(), ip.clone()));
                    evil_twin_screen.add_log(format!("📱 Client connected: {} ({})", mac, ip));
                }
                brutifi::EvilTwinProgress::CredentialAttempt { password } => {
                    evil_twin_screen.add_log(format!("🔑 Credential attempt: {}", password));
                }
                brutifi::EvilTwinProgress::PasswordFound { password } => {
                    evil_twin_screen.found_password = Some(password.clone());
                    evil_twin_screen.is_attacking = false;
                    evil_twin_screen.attack_finished = true;
                    evil_twin_screen.status_message = "Password found!".to_string();
                    evil_twin_screen.add_log(format!("✅ Valid password: {}", password));

                    // Clean up
                    self.evil_twin_state = None;
                    self.evil_twin_progress_rx = None;
                }
                brutifi::EvilTwinProgress::ValidationFailed { password } => {
                    evil_twin_screen.add_log(format!("❌ Invalid password: {}", password));
                }
                brutifi::EvilTwinProgress::Error(msg) => {
                    evil_twin_screen.error_message = Some(msg.clone());
                    evil_twin_screen.is_attacking = false;
                    evil_twin_screen.status_message = format!("Error: {}", msg);
                    evil_twin_screen.add_log(format!("❌ Error: {}", msg));

                    // Clean up
                    self.evil_twin_state = None;
                    self.evil_twin_progress_rx = None;
                }
                brutifi::EvilTwinProgress::Log(msg) => {
                    evil_twin_screen.add_log(msg);
                }
            }
        }

        Task::none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screens::EvilTwinScreen;

    // =========================================================================
    // Helper Functions
    // =========================================================================

    fn create_test_app_with_evil_twin_screen() -> BruteforceApp {
        let mut app = BruteforceApp::new(true).0;
        app.evil_twin_screen = Some(EvilTwinScreen::default());
        app
    }

    // =========================================================================
    // Input Change Handler Tests
    // =========================================================================

    #[test]
    fn test_evil_twin_ssid_changed() {
        let mut app = create_test_app_with_evil_twin_screen();

        let _ = app.handle_evil_twin_ssid_changed("TestNetwork".to_string());

        assert_eq!(
            app.evil_twin_screen.as_ref().unwrap().target_ssid,
            "TestNetwork"
        );
    }

    #[test]
    fn test_evil_twin_ssid_changed_empty() {
        let mut app = create_test_app_with_evil_twin_screen();
        app.evil_twin_screen.as_mut().unwrap().target_ssid = "OldSSID".to_string();

        let _ = app.handle_evil_twin_ssid_changed(String::new());

        assert!(app
            .evil_twin_screen
            .as_ref()
            .unwrap()
            .target_ssid
            .is_empty());
    }

    #[test]
    fn test_evil_twin_ssid_changed_special_characters() {
        let mut app = create_test_app_with_evil_twin_screen();

        let _ = app.handle_evil_twin_ssid_changed("Test Network!@#$%".to_string());

        assert_eq!(
            app.evil_twin_screen.as_ref().unwrap().target_ssid,
            "Test Network!@#$%"
        );
    }

    #[test]
    fn test_evil_twin_ssid_changed_long() {
        let mut app = create_test_app_with_evil_twin_screen();
        let long_ssid = "A".repeat(32);

        let _ = app.handle_evil_twin_ssid_changed(long_ssid.clone());

        assert_eq!(
            app.evil_twin_screen.as_ref().unwrap().target_ssid,
            long_ssid
        );
    }

    #[test]
    fn test_evil_twin_bssid_changed() {
        let mut app = create_test_app_with_evil_twin_screen();

        let _ = app.handle_evil_twin_bssid_changed("AA:BB:CC:DD:EE:FF".to_string());

        assert_eq!(
            app.evil_twin_screen.as_ref().unwrap().target_bssid,
            "AA:BB:CC:DD:EE:FF"
        );
    }

    #[test]
    fn test_evil_twin_bssid_changed_empty() {
        let mut app = create_test_app_with_evil_twin_screen();
        app.evil_twin_screen.as_mut().unwrap().target_bssid = "AA:BB:CC:DD:EE:FF".to_string();

        let _ = app.handle_evil_twin_bssid_changed(String::new());

        assert!(app
            .evil_twin_screen
            .as_ref()
            .unwrap()
            .target_bssid
            .is_empty());
    }

    #[test]
    fn test_evil_twin_channel_changed() {
        let mut app = create_test_app_with_evil_twin_screen();

        let _ = app.handle_evil_twin_channel_changed("11".to_string());

        assert_eq!(app.evil_twin_screen.as_ref().unwrap().target_channel, "11");
    }

    #[test]
    fn test_evil_twin_channel_changed_all_valid() {
        for channel in ["1", "6", "11", "13", "14"] {
            let mut app = create_test_app_with_evil_twin_screen();

            let _ = app.handle_evil_twin_channel_changed(channel.to_string());

            assert_eq!(
                app.evil_twin_screen.as_ref().unwrap().target_channel,
                channel
            );
        }
    }

    #[test]
    fn test_evil_twin_interface_changed() {
        let mut app = create_test_app_with_evil_twin_screen();

        let _ = app.handle_evil_twin_interface_changed("wlan0".to_string());

        assert_eq!(app.evil_twin_screen.as_ref().unwrap().interface, "wlan0");
    }

    #[test]
    fn test_evil_twin_interface_changed_empty() {
        let mut app = create_test_app_with_evil_twin_screen();

        let _ = app.handle_evil_twin_interface_changed(String::new());

        assert!(app.evil_twin_screen.as_ref().unwrap().interface.is_empty());
    }

    // =========================================================================
    // Template Change Handler Tests
    // =========================================================================

    #[test]
    fn test_evil_twin_template_changed() {
        let mut app = create_test_app_with_evil_twin_screen();

        let _ = app.handle_evil_twin_template_changed(EvilTwinPortalTemplate::TpLink);

        assert_eq!(
            app.evil_twin_screen.as_ref().unwrap().portal_template,
            EvilTwinPortalTemplate::TpLink
        );
    }

    #[test]
    fn test_evil_twin_template_changed_all_templates() {
        let templates = [
            EvilTwinPortalTemplate::Generic,
            EvilTwinPortalTemplate::TpLink,
            EvilTwinPortalTemplate::Netgear,
            EvilTwinPortalTemplate::Linksys,
        ];

        for template in templates {
            let mut app = create_test_app_with_evil_twin_screen();

            let _ = app.handle_evil_twin_template_changed(template);

            assert_eq!(
                app.evil_twin_screen.as_ref().unwrap().portal_template,
                template
            );
        }
    }

    #[test]
    fn test_evil_twin_template_changed_resets_state() {
        let mut app = create_test_app_with_evil_twin_screen();

        // Set some state
        app.evil_twin_screen.as_mut().unwrap().is_attacking = true;
        app.evil_twin_screen
            .as_mut()
            .unwrap()
            .add_log("Test log".to_string());

        let _ = app.handle_evil_twin_template_changed(EvilTwinPortalTemplate::Netgear);

        // State should be reset when template changes
        assert!(!app.evil_twin_screen.as_ref().unwrap().is_attacking);
        assert!(app
            .evil_twin_screen
            .as_ref()
            .unwrap()
            .log_messages
            .is_empty());
    }

    // =========================================================================
    // Stop Attack Handler Tests
    // =========================================================================

    #[test]
    fn test_evil_twin_stop_attack() {
        let mut app = create_test_app_with_evil_twin_screen();
        app.evil_twin_screen.as_mut().unwrap().is_attacking = true;

        let _ = app.handle_stop_evil_twin_attack();

        assert!(!app.evil_twin_screen.as_ref().unwrap().is_attacking);
        assert!(app
            .evil_twin_screen
            .as_ref()
            .unwrap()
            .status_message
            .contains("stopped"));
    }

    #[test]
    fn test_evil_twin_stop_attack_clears_state() {
        let mut app = create_test_app_with_evil_twin_screen();
        app.evil_twin_screen.as_mut().unwrap().is_attacking = true;

        let state = std::sync::Arc::new(crate::workers::EvilTwinState::new());
        app.evil_twin_state = Some(state);

        let _ = app.handle_stop_evil_twin_attack();

        assert!(app.evil_twin_state.is_none());
        assert!(app.evil_twin_progress_rx.is_none());
    }

    // =========================================================================
    // Progress Handler Tests
    // =========================================================================

    #[test]
    fn test_evil_twin_progress_started() {
        let mut app = create_test_app_with_evil_twin_screen();

        let _ = app.handle_evil_twin_progress(brutifi::EvilTwinProgress::Started);

        assert!(app
            .evil_twin_screen
            .as_ref()
            .unwrap()
            .status_message
            .contains("started"));
    }

    #[test]
    fn test_evil_twin_progress_step() {
        let mut app = create_test_app_with_evil_twin_screen();

        let _ = app.handle_evil_twin_progress(brutifi::EvilTwinProgress::Step {
            current: 3,
            total: 6,
            description: "Testing step".to_string(),
        });

        let screen = app.evil_twin_screen.as_ref().unwrap();
        assert_eq!(screen.current_step, 3);
        assert_eq!(screen.total_steps, 6);
        assert_eq!(screen.step_description, "Testing step");
    }

    #[test]
    fn test_evil_twin_progress_client_connected() {
        let mut app = create_test_app_with_evil_twin_screen();

        let _ = app.handle_evil_twin_progress(brutifi::EvilTwinProgress::ClientConnected {
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            ip: "192.168.1.100".to_string(),
        });

        let screen = app.evil_twin_screen.as_ref().unwrap();
        assert_eq!(screen.clients_connected.len(), 1);
        assert_eq!(screen.clients_connected[0].0, "AA:BB:CC:DD:EE:FF");
        assert_eq!(screen.clients_connected[0].1, "192.168.1.100");
    }

    #[test]
    fn test_evil_twin_progress_credential_attempt() {
        let mut app = create_test_app_with_evil_twin_screen();

        let _ = app.handle_evil_twin_progress(brutifi::EvilTwinProgress::CredentialAttempt {
            password: "test_pass".to_string(),
        });

        let screen = app.evil_twin_screen.as_ref().unwrap();
        assert!(!screen.log_messages.is_empty());
        assert!(screen.log_messages.last().unwrap().contains("test_pass"));
    }

    #[test]
    fn test_evil_twin_progress_password_found() {
        let mut app = create_test_app_with_evil_twin_screen();
        app.evil_twin_screen.as_mut().unwrap().is_attacking = true;

        let _ = app.handle_evil_twin_progress(brutifi::EvilTwinProgress::PasswordFound {
            password: "found_password".to_string(),
        });

        let screen = app.evil_twin_screen.as_ref().unwrap();
        assert!(!screen.is_attacking);
        assert!(screen.attack_finished);
        assert_eq!(screen.found_password, Some("found_password".to_string()));
    }

    #[test]
    fn test_evil_twin_progress_validation_failed() {
        let mut app = create_test_app_with_evil_twin_screen();

        let _ = app.handle_evil_twin_progress(brutifi::EvilTwinProgress::ValidationFailed {
            password: "wrong_pass".to_string(),
        });

        let screen = app.evil_twin_screen.as_ref().unwrap();
        assert!(!screen.log_messages.is_empty());
        assert!(screen.log_messages.last().unwrap().contains("wrong_pass"));
    }

    #[test]
    fn test_evil_twin_progress_error() {
        let mut app = create_test_app_with_evil_twin_screen();
        app.evil_twin_screen.as_mut().unwrap().is_attacking = true;

        let _ = app.handle_evil_twin_progress(brutifi::EvilTwinProgress::Error(
            "Test error message".to_string(),
        ));

        let screen = app.evil_twin_screen.as_ref().unwrap();
        assert!(!screen.is_attacking);
        assert_eq!(screen.error_message, Some("Test error message".to_string()));
    }

    #[test]
    fn test_evil_twin_progress_log() {
        let mut app = create_test_app_with_evil_twin_screen();

        let _ = app.handle_evil_twin_progress(brutifi::EvilTwinProgress::Log(
            "Test log message".to_string(),
        ));

        let screen = app.evil_twin_screen.as_ref().unwrap();
        assert!(!screen.log_messages.is_empty());
        assert_eq!(screen.log_messages.last().unwrap(), "Test log message");
    }

    // =========================================================================
    // No Screen Tests
    // =========================================================================

    #[test]
    fn test_evil_twin_handlers_without_screen() {
        let mut app = BruteforceApp::new(true).0;
        assert!(app.evil_twin_screen.is_none());

        // All handlers should not panic when screen is None
        let _ = app.handle_evil_twin_ssid_changed("Test".to_string());
        let _ = app.handle_evil_twin_bssid_changed("AA:BB:CC:DD:EE:FF".to_string());
        let _ = app.handle_evil_twin_channel_changed("6".to_string());
        let _ = app.handle_evil_twin_interface_changed("wlan0".to_string());
        let _ = app.handle_evil_twin_template_changed(EvilTwinPortalTemplate::TpLink);
        let _ = app.handle_stop_evil_twin_attack();
        let _ = app.handle_evil_twin_progress(brutifi::EvilTwinProgress::Started);

        // Screen should still be None
        assert!(app.evil_twin_screen.is_none());
    }

    // =========================================================================
    // Start Attack Handler Tests (Invalid Input)
    // =========================================================================

    #[test]
    fn test_start_evil_twin_attack_invalid_channel() {
        let mut app = create_test_app_with_evil_twin_screen();
        app.evil_twin_screen.as_mut().unwrap().target_ssid = "TestNet".to_string();
        app.evil_twin_screen.as_mut().unwrap().target_channel = "invalid".to_string();

        let _ = app.handle_start_evil_twin_attack();

        // Should set error message for invalid channel
        let screen = app.evil_twin_screen.as_ref().unwrap();
        assert!(screen.error_message.is_some());
        assert!(screen
            .error_message
            .as_ref()
            .unwrap()
            .contains("Invalid channel"));
    }

    #[test]
    fn test_start_evil_twin_attack_empty_channel() {
        let mut app = create_test_app_with_evil_twin_screen();
        app.evil_twin_screen.as_mut().unwrap().target_ssid = "TestNet".to_string();
        app.evil_twin_screen.as_mut().unwrap().target_channel = String::new();

        let _ = app.handle_start_evil_twin_attack();

        let screen = app.evil_twin_screen.as_ref().unwrap();
        assert!(screen.error_message.is_some());
    }

    // =========================================================================
    // Multiple Client Connection Tests
    // =========================================================================

    #[test]
    fn test_evil_twin_multiple_clients_connected() {
        let mut app = create_test_app_with_evil_twin_screen();

        for i in 0..5 {
            let _ = app.handle_evil_twin_progress(brutifi::EvilTwinProgress::ClientConnected {
                mac: format!("AA:BB:CC:DD:EE:{:02X}", i),
                ip: format!("192.168.1.{}", 100 + i),
            });
        }

        let screen = app.evil_twin_screen.as_ref().unwrap();
        assert_eq!(screen.clients_connected.len(), 5);
    }
}
