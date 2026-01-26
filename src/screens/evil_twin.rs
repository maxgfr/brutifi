/*!
 * Evil Twin Attack Screen
 *
 * Handles Evil Twin rogue AP attacks with captive portal.
 */

use iced::widget::{button, column, container, pick_list, row, scrollable, text, text_input};
use iced::{Element, Length};

use crate::messages::Message;
use crate::theme::{self, colors};
use brutifi::{CapturedCredential, EvilTwinResult, PortalTemplate};
use serde::{Deserialize, Serialize};

/// Portal template selection for UI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum EvilTwinPortalTemplate {
    #[default]
    Generic,
    TpLink,
    Netgear,
    Linksys,
}

impl std::fmt::Display for EvilTwinPortalTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvilTwinPortalTemplate::Generic => write!(f, "Generic (Recommended)"),
            EvilTwinPortalTemplate::TpLink => write!(f, "TP-Link"),
            EvilTwinPortalTemplate::Netgear => write!(f, "NETGEAR"),
            EvilTwinPortalTemplate::Linksys => write!(f, "Linksys"),
        }
    }
}

impl From<EvilTwinPortalTemplate> for PortalTemplate {
    fn from(template: EvilTwinPortalTemplate) -> Self {
        match template {
            EvilTwinPortalTemplate::Generic => PortalTemplate::Generic,
            EvilTwinPortalTemplate::TpLink => PortalTemplate::TpLink,
            EvilTwinPortalTemplate::Netgear => PortalTemplate::Netgear,
            EvilTwinPortalTemplate::Linksys => PortalTemplate::Linksys,
        }
    }
}

/// Evil Twin attack screen state
#[derive(Debug)]
#[allow(dead_code)]
pub struct EvilTwinScreen {
    pub target_ssid: String,
    pub target_bssid: String,
    pub target_channel: String,
    pub interface: String,
    pub portal_template: EvilTwinPortalTemplate,
    pub is_attacking: bool,
    pub current_step: u8,
    pub total_steps: u8,
    pub step_description: String,
    pub clients_connected: Vec<(String, String)>, // (MAC, IP)
    pub captured_credentials: Vec<CapturedCredential>,
    pub found_password: Option<String>,
    pub attack_finished: bool,
    pub error_message: Option<String>,
    pub status_message: String,
    pub log_messages: Vec<String>,
    pub hostapd_available: bool,
    pub dnsmasq_available: bool,
}

impl Default for EvilTwinScreen {
    fn default() -> Self {
        // Check external tools availability
        let hostapd_available = brutifi::check_hostapd_installed();
        let dnsmasq_available = brutifi::check_dnsmasq_installed();

        Self {
            target_ssid: String::new(),
            target_bssid: String::new(),
            target_channel: "6".to_string(),
            interface: "en0".to_string(),
            portal_template: EvilTwinPortalTemplate::Generic,
            is_attacking: false,
            current_step: 0,
            total_steps: 6,
            step_description: String::new(),
            clients_connected: Vec::new(),
            captured_credentials: Vec::new(),
            found_password: None,
            attack_finished: false,
            error_message: None,
            status_message: "Ready to start Evil Twin attack".to_string(),
            log_messages: Vec::new(),
            hostapd_available,
            dnsmasq_available,
        }
    }
}

impl EvilTwinScreen {
    #[allow(dead_code)]
    pub fn view(&self, is_root: bool) -> Element<'_, Message> {
        let title = text("Evil Twin Attack").size(28).color(colors::TEXT);

        let subtitle = text("Create rogue AP with captive portal to capture WiFi credentials")
            .size(14)
            .color(colors::TEXT_DIM);

        // Root requirement warning
        let root_warning = if !is_root {
            Some(
                container(
                    column![
                        text("⚠️  Root privileges required for Evil Twin attacks")
                            .size(13)
                            .color(colors::WARNING),
                        text("Run with sudo: sudo ./target/release/brutifi")
                            .size(11)
                            .color(colors::TEXT_DIM),
                    ]
                    .spacing(6),
                )
                .padding(10)
                .style(theme::card_style),
            )
        } else {
            None
        };

        // Tools availability warning
        let tools_warning = if !self.hostapd_available || !self.dnsmasq_available {
            let missing = match (self.hostapd_available, self.dnsmasq_available) {
                (false, false) => "hostapd and dnsmasq not found",
                (false, true) => "hostapd not found",
                (true, false) => "dnsmasq not found",
                _ => "",
            };
            Some(
                container(
                    column![
                        text(format!("⚠️  {}", missing))
                            .size(13)
                            .color(colors::WARNING),
                        text("Install with: brew install hostapd dnsmasq")
                            .size(11)
                            .color(colors::TEXT_DIM),
                    ]
                    .spacing(6),
                )
                .padding(10)
                .style(theme::card_style),
            )
        } else {
            None
        };

        // Portal template selection
        let template_picker = column![
            text("Captive Portal Template").size(13).color(colors::TEXT),
            pick_list(
                vec![
                    EvilTwinPortalTemplate::Generic,
                    EvilTwinPortalTemplate::TpLink,
                    EvilTwinPortalTemplate::Netgear,
                    EvilTwinPortalTemplate::Linksys,
                ],
                Some(self.portal_template),
                Message::EvilTwinTemplateChanged,
            )
            .padding(10)
            .width(Length::Fill),
        ]
        .spacing(6);

        // Template description
        let template_info: Element<Message> = match self.portal_template {
            EvilTwinPortalTemplate::Generic => container(
                column![
                    text("🌐 Generic Portal").size(13).color(colors::SUCCESS),
                    text("Modern gradient design with responsive layout")
                        .size(11)
                        .color(colors::TEXT_DIM),
                    text("Works for any network - recommended for most scenarios")
                        .size(11)
                        .color(colors::TEXT_DIM),
                ]
                .spacing(4)
                .padding(10),
            )
            .style(theme::card_style)
            .into(),
            EvilTwinPortalTemplate::TpLink => container(
                column![
                    text("🔵 TP-Link Portal").size(13).color(colors::TEXT),
                    text("Authentic TP-Link router styling with blue theme")
                        .size(11)
                        .color(colors::TEXT_DIM),
                    text("Best for TP-Link branded networks")
                        .size(11)
                        .color(colors::TEXT_DIM),
                ]
                .spacing(4)
                .padding(10),
            )
            .style(theme::card_style)
            .into(),
            EvilTwinPortalTemplate::Netgear => container(
                column![
                    text("🟦 NETGEAR Portal").size(13).color(colors::TEXT),
                    text("Professional NETGEAR branding and layout")
                        .size(11)
                        .color(colors::TEXT_DIM),
                    text("Best for NETGEAR branded networks")
                        .size(11)
                        .color(colors::TEXT_DIM),
                ]
                .spacing(4)
                .padding(10),
            )
            .style(theme::card_style)
            .into(),
            EvilTwinPortalTemplate::Linksys => container(
                column![
                    text("⬛ Linksys Portal").size(13).color(colors::TEXT),
                    text("Clean Linksys Smart Wi-Fi design")
                        .size(11)
                        .color(colors::TEXT_DIM),
                    text("Best for Linksys branded networks")
                        .size(11)
                        .color(colors::TEXT_DIM),
                ]
                .spacing(4)
                .padding(10),
            )
            .style(theme::card_style)
            .into(),
        };

        // Target configuration
        let ssid_input = column![
            text("Target SSID *").size(13).color(colors::TEXT),
            text_input("Network name to impersonate", &self.target_ssid)
                .on_input(Message::EvilTwinSsidChanged)
                .padding(10)
                .size(14)
                .width(Length::Fill),
        ]
        .spacing(6);

        let bssid_input = column![
            text("Target BSSID (Optional)").size(13).color(colors::TEXT),
            text_input("AA:BB:CC:DD:EE:FF", &self.target_bssid)
                .on_input(Message::EvilTwinBssidChanged)
                .padding(10)
                .size(14)
                .width(Length::Fill),
        ]
        .spacing(6);

        let channel_input = column![
            text("Channel *").size(13).color(colors::TEXT),
            text_input("1-11", &self.target_channel)
                .on_input(Message::EvilTwinChannelChanged)
                .padding(10)
                .size(14)
                .width(Length::Fill),
        ]
        .spacing(6);

        let interface_input = column![
            text("Interface").size(13).color(colors::TEXT),
            text_input("en0", &self.interface)
                .on_input(Message::EvilTwinInterfaceChanged)
                .padding(10)
                .size(14)
                .width(Length::Fill),
            text("Default: en0 (macOS WiFi)")
                .size(11)
                .color(colors::TEXT_DIM),
        ]
        .spacing(6);

        // Progress section
        let progress_section: Element<Message> = if self.is_attacking {
            let step_text = if self.total_steps > 0 {
                format!(
                    "Step {}/{}: {}",
                    self.current_step, self.total_steps, self.step_description
                )
            } else {
                self.step_description.clone()
            };

            let clients_text = if !self.clients_connected.is_empty() {
                format!("Clients connected: {}", self.clients_connected.len())
            } else {
                "Waiting for clients...".to_string()
            };

            let credentials_text = if !self.captured_credentials.is_empty() {
                format!("Credentials captured: {}", self.captured_credentials.len())
            } else {
                "No credentials captured yet".to_string()
            };

            container(
                column![
                    text("Attack Progress").size(14).color(colors::TEXT),
                    text(step_text).size(12).color(colors::TEXT_DIM),
                    text(&self.status_message).size(12).color(colors::TEXT_DIM),
                    text(clients_text).size(11).color(colors::SUCCESS),
                    text(credentials_text).size(11).color(colors::WARNING),
                ]
                .spacing(8)
                .padding(10),
            )
            .style(theme::card_style)
            .into()
        } else if let Some(ref password) = self.found_password {
            container(
                column![
                    text("✅ Password Found!").size(16).color(colors::SUCCESS),
                    text(format!("WiFi Password: {}", password))
                        .size(14)
                        .color(colors::TEXT),
                    text("Password validated against real AP")
                        .size(12)
                        .color(colors::TEXT_DIM),
                ]
                .spacing(8)
                .padding(10),
            )
            .style(theme::card_style)
            .into()
        } else if self.attack_finished {
            container(
                column![
                    text("⚠️ Attack Completed").size(14).color(colors::WARNING),
                    text("No password validated - check captured credentials manually")
                        .size(12)
                        .color(colors::TEXT_DIM),
                ]
                .spacing(8)
                .padding(10),
            )
            .style(theme::card_style)
            .into()
        } else if let Some(ref error) = self.error_message {
            container(
                column![
                    text("❌ Error").size(14).color(colors::DANGER),
                    text(error).size(12).color(colors::TEXT_DIM),
                ]
                .spacing(8)
                .padding(10),
            )
            .style(theme::card_style)
            .into()
        } else {
            container(text("")).into()
        };

        // Captured credentials section
        let credentials_section: Element<Message> = if !self.captured_credentials.is_empty() {
            let cred_items = self.captured_credentials.iter().enumerate().fold(
                column![].spacing(6),
                |col, (idx, cred)| {
                    let status_icon = if cred.validated { "✅" } else { "⏳" };
                    col.push(
                        container(
                            column![
                                text(format!("{}. {} {}", idx + 1, status_icon, cred.password))
                                    .size(12)
                                    .color(if cred.validated {
                                        colors::SUCCESS
                                    } else {
                                        colors::TEXT
                                    }),
                                text(format!("Client: {} ({})", cred.client_mac, cred.client_ip))
                                    .size(10)
                                    .color(colors::TEXT_DIM),
                            ]
                            .spacing(4),
                        )
                        .padding(8)
                        .style(theme::card_style),
                    )
                },
            );

            container(
                column![
                    text("Captured Credentials").size(13).color(colors::TEXT),
                    scrollable(cred_items).height(Length::Fixed(150.0)),
                ]
                .spacing(8),
            )
            .into()
        } else {
            container(text("")).into()
        };

        // Log section
        let log_section: Element<Message> = if !self.log_messages.is_empty() {
            let log_items: Element<Message> = scrollable(
                self.log_messages
                    .iter()
                    .rev()
                    .fold(column![].spacing(4), |col, msg| {
                        col.push(text(msg).size(11).color(colors::TEXT_DIM))
                    }),
            )
            .height(Length::Fixed(150.0))
            .into();

            container(
                column![
                    text("Attack Log").size(13).color(colors::TEXT),
                    container(log_items).padding(10).style(theme::card_style),
                ]
                .spacing(8),
            )
            .into()
        } else {
            container(text("")).into()
        };

        // Action buttons
        let can_start = !self.target_ssid.is_empty()
            && !self.target_channel.is_empty()
            && !self.is_attacking
            && self.hostapd_available
            && self.dnsmasq_available
            && is_root;

        let start_button = button(
            text(if self.is_attacking {
                "Attack Running..."
            } else {
                "Start Attack"
            })
            .size(14),
        )
        .padding([12, 24])
        .style(if can_start {
            theme::primary_button_style
        } else {
            theme::secondary_button_style
        });

        let start_button = if can_start {
            start_button.on_press(Message::StartEvilTwinAttack)
        } else {
            start_button
        };

        let stop_button = button(text("Stop").size(14))
            .padding([12, 24])
            .style(theme::danger_button_style);

        let stop_button = if self.is_attacking {
            stop_button.on_press(Message::StopEvilTwinAttack)
        } else {
            stop_button
        };

        let action_buttons = row![start_button, stop_button].spacing(12);

        // Build the final layout
        let mut content = column![title, subtitle].spacing(20);

        if let Some(warning) = root_warning {
            content = content.push(warning);
        }

        if let Some(warning) = tools_warning {
            content = content.push(warning);
        }

        content = content
            .push(template_picker)
            .push(template_info)
            .push(ssid_input)
            .push(bssid_input)
            .push(
                row![channel_input, interface_input]
                    .spacing(12)
                    .width(Length::Fill),
            )
            .push(progress_section)
            .push(action_buttons)
            .push(credentials_section)
            .push(log_section);

        container(scrollable(content.spacing(20).padding(20)))
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    /// Add a log message
    pub fn add_log(&mut self, message: String) {
        self.log_messages.push(message);
        // Keep only last 100 messages
        if self.log_messages.len() > 100 {
            self.log_messages.remove(0);
        }
    }

    /// Update from Evil Twin result
    #[allow(dead_code)]
    pub fn update_from_result(&mut self, result: &EvilTwinResult) {
        self.is_attacking = false;
        self.attack_finished = true;

        match result {
            EvilTwinResult::PasswordFound { password } => {
                self.found_password = Some(password.clone());
                self.status_message = "Password found and validated!".to_string();
            }
            EvilTwinResult::Running => {
                self.is_attacking = true;
                self.attack_finished = false;
                self.status_message = "Attack running...".to_string();
            }
            EvilTwinResult::Stopped => {
                self.status_message = "Attack stopped by user".to_string();
                self.attack_finished = false;
            }
            EvilTwinResult::Error(e) => {
                self.error_message = Some(e.clone());
                self.status_message = format!("Attack failed: {}", e);
            }
        }
    }

    /// Reset attack state
    pub fn reset(&mut self) {
        self.is_attacking = false;
        self.current_step = 0;
        self.total_steps = 6;
        self.step_description = String::new();
        self.clients_connected.clear();
        self.captured_credentials.clear();
        self.found_password = None;
        self.attack_finished = false;
        self.error_message = None;
        self.status_message = "Ready to start Evil Twin attack".to_string();
        self.log_messages.clear();
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    // =========================================================================
    // EvilTwinPortalTemplate Tests
    // =========================================================================

    #[test]
    fn test_evil_twin_portal_template_display() {
        assert_eq!(
            EvilTwinPortalTemplate::Generic.to_string(),
            "Generic (Recommended)"
        );
        assert_eq!(EvilTwinPortalTemplate::TpLink.to_string(), "TP-Link");
        assert_eq!(EvilTwinPortalTemplate::Netgear.to_string(), "NETGEAR");
        assert_eq!(EvilTwinPortalTemplate::Linksys.to_string(), "Linksys");
    }

    #[test]
    fn test_evil_twin_portal_template_conversion() {
        let generic: PortalTemplate = EvilTwinPortalTemplate::Generic.into();
        assert!(matches!(generic, PortalTemplate::Generic));

        let tplink: PortalTemplate = EvilTwinPortalTemplate::TpLink.into();
        assert!(matches!(tplink, PortalTemplate::TpLink));
    }

    #[test]
    fn test_evil_twin_portal_template_all_conversions() {
        let netgear: PortalTemplate = EvilTwinPortalTemplate::Netgear.into();
        assert!(matches!(netgear, PortalTemplate::Netgear));

        let linksys: PortalTemplate = EvilTwinPortalTemplate::Linksys.into();
        assert!(matches!(linksys, PortalTemplate::Linksys));
    }

    #[test]
    fn test_evil_twin_portal_template_equality() {
        assert_eq!(
            EvilTwinPortalTemplate::Generic,
            EvilTwinPortalTemplate::Generic
        );
        assert_ne!(
            EvilTwinPortalTemplate::Generic,
            EvilTwinPortalTemplate::TpLink
        );
        assert_ne!(
            EvilTwinPortalTemplate::TpLink,
            EvilTwinPortalTemplate::Netgear
        );
    }

    #[test]
    fn test_evil_twin_portal_template_default() {
        let default = EvilTwinPortalTemplate::default();
        assert_eq!(default, EvilTwinPortalTemplate::Generic);
    }

    #[test]
    fn test_evil_twin_portal_template_debug() {
        let template = EvilTwinPortalTemplate::TpLink;
        let debug_str = format!("{:?}", template);
        assert!(debug_str.contains("TpLink"));
    }

    #[test]
    fn test_evil_twin_portal_template_clone() {
        let original = EvilTwinPortalTemplate::Netgear;
        let cloned = original;
        assert_eq!(original, cloned);
    }

    // =========================================================================
    // EvilTwinScreen Default Tests
    // =========================================================================

    #[test]
    fn test_evil_twin_screen_default() {
        let screen = EvilTwinScreen::default();
        assert_eq!(screen.target_channel, "6");
        assert_eq!(screen.interface, "en0");
        assert!(!screen.is_attacking);
        assert_eq!(screen.total_steps, 6);
        assert!(screen.log_messages.is_empty());
    }

    #[test]
    fn test_evil_twin_screen_default_portal_template() {
        let screen = EvilTwinScreen::default();
        assert_eq!(screen.portal_template, EvilTwinPortalTemplate::Generic);
    }

    #[test]
    fn test_evil_twin_screen_default_empty_target() {
        let screen = EvilTwinScreen::default();
        assert!(screen.target_ssid.is_empty());
        assert!(screen.target_bssid.is_empty());
    }

    #[test]
    fn test_evil_twin_screen_default_no_password() {
        let screen = EvilTwinScreen::default();
        assert!(screen.found_password.is_none());
    }

    #[test]
    fn test_evil_twin_screen_default_no_error() {
        let screen = EvilTwinScreen::default();
        assert!(screen.error_message.is_none());
    }

    #[test]
    fn test_evil_twin_screen_default_status_message() {
        let screen = EvilTwinScreen::default();
        assert_eq!(screen.status_message, "Ready to start Evil Twin attack");
    }

    #[test]
    fn test_evil_twin_screen_default_empty_credentials() {
        let screen = EvilTwinScreen::default();
        assert!(screen.captured_credentials.is_empty());
    }

    #[test]
    fn test_evil_twin_screen_default_empty_clients() {
        let screen = EvilTwinScreen::default();
        assert!(screen.clients_connected.is_empty());
    }

    // =========================================================================
    // Add Log Tests
    // =========================================================================

    #[test]
    fn test_evil_twin_screen_add_log() {
        let mut screen = EvilTwinScreen::default();
        screen.add_log("Test message 1".to_string());
        screen.add_log("Test message 2".to_string());

        assert_eq!(screen.log_messages.len(), 2);
        assert_eq!(screen.log_messages[0], "Test message 1");
        assert_eq!(screen.log_messages[1], "Test message 2");
    }

    #[test]
    fn test_evil_twin_screen_add_log_limit() {
        let mut screen = EvilTwinScreen::default();

        // Add 150 messages
        for i in 0..150 {
            screen.add_log(format!("Message {}", i));
        }

        // Should keep only last 100
        assert_eq!(screen.log_messages.len(), 100);
        assert_eq!(screen.log_messages[0], "Message 50");
        assert_eq!(screen.log_messages[99], "Message 149");
    }

    #[test]
    fn test_evil_twin_screen_add_log_exactly_100() {
        let mut screen = EvilTwinScreen::default();

        for i in 0..100 {
            screen.add_log(format!("Message {}", i));
        }

        assert_eq!(screen.log_messages.len(), 100);
        assert_eq!(screen.log_messages[0], "Message 0");
    }

    #[test]
    fn test_evil_twin_screen_add_log_101() {
        let mut screen = EvilTwinScreen::default();

        for i in 0..101 {
            screen.add_log(format!("Message {}", i));
        }

        assert_eq!(screen.log_messages.len(), 100);
        assert_eq!(screen.log_messages[0], "Message 1");
        assert_eq!(screen.log_messages[99], "Message 100");
    }

    #[test]
    fn test_evil_twin_screen_add_log_empty_string() {
        let mut screen = EvilTwinScreen::default();
        screen.add_log(String::new());

        assert_eq!(screen.log_messages.len(), 1);
        assert!(screen.log_messages[0].is_empty());
    }

    #[test]
    fn test_evil_twin_screen_add_log_special_characters() {
        let mut screen = EvilTwinScreen::default();
        let special_msg = "Log: !@#$%^&*() <html>";
        screen.add_log(special_msg.to_string());

        assert_eq!(screen.log_messages[0], special_msg);
    }

    // =========================================================================
    // Reset Tests
    // =========================================================================

    #[test]
    fn test_evil_twin_screen_reset() {
        let mut screen = EvilTwinScreen::default();

        screen.is_attacking = true;
        screen.current_step = 3;
        screen.add_log("Test log".to_string());
        screen.error_message = Some("Error".to_string());

        screen.reset();

        assert!(!screen.is_attacking);
        assert_eq!(screen.current_step, 0);
        assert!(screen.log_messages.is_empty());
        assert!(screen.error_message.is_none());
        assert_eq!(screen.status_message, "Ready to start Evil Twin attack");
    }

    #[test]
    fn test_evil_twin_screen_reset_clears_password() {
        let mut screen = EvilTwinScreen::default();
        screen.found_password = Some("secret123".to_string());

        screen.reset();

        assert!(screen.found_password.is_none());
    }

    #[test]
    fn test_evil_twin_screen_reset_clears_credentials() {
        let mut screen = EvilTwinScreen::default();
        screen.captured_credentials.push(CapturedCredential {
            ssid: "Test".to_string(),
            password: "pass".to_string(),
            client_mac: "AA:BB:CC:DD:EE:FF".to_string(),
            client_ip: "192.168.1.100".to_string(),
            timestamp: 1000,
            validated: false,
        });

        screen.reset();

        assert!(screen.captured_credentials.is_empty());
    }

    #[test]
    fn test_evil_twin_screen_reset_clears_clients() {
        let mut screen = EvilTwinScreen::default();
        screen
            .clients_connected
            .push(("AA:BB:CC:DD:EE:FF".to_string(), "192.168.1.100".to_string()));

        screen.reset();

        assert!(screen.clients_connected.is_empty());
    }

    #[test]
    fn test_evil_twin_screen_reset_resets_steps() {
        let mut screen = EvilTwinScreen::default();
        screen.current_step = 5;
        screen.step_description = "Testing step".to_string();

        screen.reset();

        assert_eq!(screen.current_step, 0);
        assert!(screen.step_description.is_empty());
        assert_eq!(screen.total_steps, 6);
    }

    #[test]
    fn test_evil_twin_screen_reset_attack_finished() {
        let mut screen = EvilTwinScreen::default();
        screen.attack_finished = true;

        screen.reset();

        assert!(!screen.attack_finished);
    }

    #[test]
    fn test_evil_twin_screen_reset_preserves_target_config() {
        let mut screen = EvilTwinScreen::default();
        screen.target_ssid = "TestNetwork".to_string();
        screen.target_bssid = "AA:BB:CC:DD:EE:FF".to_string();
        screen.target_channel = "11".to_string();
        screen.interface = "wlan0".to_string();

        screen.reset();

        // Target configuration should be preserved
        assert_eq!(screen.target_ssid, "TestNetwork");
        assert_eq!(screen.target_bssid, "AA:BB:CC:DD:EE:FF");
        assert_eq!(screen.target_channel, "11");
        assert_eq!(screen.interface, "wlan0");
    }

    // =========================================================================
    // Update From Result Tests
    // =========================================================================

    #[test]
    fn test_update_from_result_password_found() {
        let mut screen = EvilTwinScreen::default();
        screen.is_attacking = true;

        let result = EvilTwinResult::PasswordFound {
            password: "secret123".to_string(),
        };
        screen.update_from_result(&result);

        assert!(!screen.is_attacking);
        assert!(screen.attack_finished);
        assert_eq!(screen.found_password, Some("secret123".to_string()));
        assert!(screen.status_message.contains("found"));
    }

    #[test]
    fn test_update_from_result_running() {
        let mut screen = EvilTwinScreen::default();

        let result = EvilTwinResult::Running;
        screen.update_from_result(&result);

        assert!(screen.is_attacking);
        assert!(!screen.attack_finished);
        assert!(screen.status_message.contains("running"));
    }

    #[test]
    fn test_update_from_result_stopped() {
        let mut screen = EvilTwinScreen::default();
        screen.is_attacking = true;

        let result = EvilTwinResult::Stopped;
        screen.update_from_result(&result);

        assert!(!screen.is_attacking);
        assert!(!screen.attack_finished);
        assert!(screen.status_message.contains("stopped"));
    }

    #[test]
    fn test_update_from_result_error() {
        let mut screen = EvilTwinScreen::default();
        screen.is_attacking = true;

        let result = EvilTwinResult::Error("Connection failed".to_string());
        screen.update_from_result(&result);

        assert!(!screen.is_attacking);
        assert!(screen.attack_finished);
        assert_eq!(screen.error_message, Some("Connection failed".to_string()));
        assert!(screen.status_message.contains("failed"));
    }

    // =========================================================================
    // State Modification Tests
    // =========================================================================

    #[test]
    fn test_evil_twin_screen_modify_ssid() {
        let mut screen = EvilTwinScreen::default();
        screen.target_ssid = "NewNetwork".to_string();
        assert_eq!(screen.target_ssid, "NewNetwork");
    }

    #[test]
    fn test_evil_twin_screen_modify_channel() {
        let mut screen = EvilTwinScreen::default();
        screen.target_channel = "11".to_string();
        assert_eq!(screen.target_channel, "11");
    }

    #[test]
    fn test_evil_twin_screen_modify_interface() {
        let mut screen = EvilTwinScreen::default();
        screen.interface = "wlan0".to_string();
        assert_eq!(screen.interface, "wlan0");
    }

    #[test]
    fn test_evil_twin_screen_add_client() {
        let mut screen = EvilTwinScreen::default();
        screen
            .clients_connected
            .push(("AA:BB:CC:DD:EE:FF".to_string(), "192.168.1.100".to_string()));

        assert_eq!(screen.clients_connected.len(), 1);
        assert_eq!(screen.clients_connected[0].0, "AA:BB:CC:DD:EE:FF");
        assert_eq!(screen.clients_connected[0].1, "192.168.1.100");
    }

    #[test]
    fn test_evil_twin_screen_add_captured_credential() {
        let mut screen = EvilTwinScreen::default();
        screen.captured_credentials.push(CapturedCredential {
            ssid: "TestNet".to_string(),
            password: "pass123".to_string(),
            client_mac: "AA:BB:CC:DD:EE:FF".to_string(),
            client_ip: "192.168.1.100".to_string(),
            timestamp: 1700000000,
            validated: true,
        });

        assert_eq!(screen.captured_credentials.len(), 1);
        assert!(screen.captured_credentials[0].validated);
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn test_evil_twin_screen_multiple_resets() {
        let mut screen = EvilTwinScreen::default();

        for _ in 0..5 {
            screen.is_attacking = true;
            screen.add_log("Test".to_string());
            screen.reset();
        }

        assert!(!screen.is_attacking);
        assert!(screen.log_messages.is_empty());
    }

    #[test]
    fn test_evil_twin_screen_long_ssid() {
        let mut screen = EvilTwinScreen::default();
        screen.target_ssid = "A".repeat(32); // Max WiFi SSID length
        assert_eq!(screen.target_ssid.len(), 32);
    }

    #[test]
    fn test_evil_twin_screen_channel_string_parsing() {
        let mut screen = EvilTwinScreen::default();

        // Valid channels
        for ch in ["1", "6", "11", "13", "14"] {
            screen.target_channel = ch.to_string();
            assert_eq!(screen.target_channel, ch);
        }
    }

    #[test]
    fn test_evil_twin_screen_invalid_channel_stored() {
        let mut screen = EvilTwinScreen::default();
        // Invalid channel should still be stored (validation happens elsewhere)
        screen.target_channel = "invalid".to_string();
        assert_eq!(screen.target_channel, "invalid");
    }
}
