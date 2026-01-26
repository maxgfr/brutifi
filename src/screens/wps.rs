/*!
 * WPS Attack Screen
 *
 * Handles WPS (WiFi Protected Setup) attacks.
 * Supports Pixie-Dust and PIN brute-force attacks.
 */

use iced::widget::{button, column, container, pick_list, row, scrollable, text, text_input};
use iced::{Element, Length};

use crate::messages::Message;
use crate::theme::{self, colors};
use brutifi::{WpsAttackType, WpsResult};
use serde::{Deserialize, Serialize};

/// WPS attack type selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum WpsAttackMethod {
    #[default]
    PixieDust,
    PinBruteForce,
}

impl std::fmt::Display for WpsAttackMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WpsAttackMethod::PixieDust => write!(f, "Pixie-Dust (Recommended)"),
            WpsAttackMethod::PinBruteForce => write!(f, "PIN Brute-Force"),
        }
    }
}

impl From<WpsAttackMethod> for WpsAttackType {
    fn from(method: WpsAttackMethod) -> Self {
        match method {
            WpsAttackMethod::PixieDust => WpsAttackType::PixieDust,
            WpsAttackMethod::PinBruteForce => WpsAttackType::PinBruteForce,
        }
    }
}

/// WPS attack screen state
#[derive(Debug)]
pub struct WpsScreen {
    pub bssid: String,
    pub channel: String,
    pub interface: String,
    pub attack_method: WpsAttackMethod,
    pub custom_pin: String,
    pub is_attacking: bool,
    pub current_step: u8,
    pub total_steps: u8,
    pub step_description: String,
    pub found_pin: Option<String>,
    pub found_password: Option<String>,
    pub attack_finished: bool,
    pub error_message: Option<String>,
    pub status_message: String,
    pub log_messages: Vec<String>,
    pub reaver_available: bool,
    pub pixiewps_available: bool,
}

impl Default for WpsScreen {
    fn default() -> Self {
        // Check external tools availability
        let reaver_available = brutifi::check_reaver_installed();
        let pixiewps_available = brutifi::check_pixiewps_installed();

        Self {
            bssid: String::new(),
            channel: "1".to_string(),
            interface: "en0".to_string(),
            attack_method: WpsAttackMethod::PixieDust,
            custom_pin: String::new(),
            is_attacking: false,
            current_step: 0,
            total_steps: 8,
            step_description: String::new(),
            found_pin: None,
            found_password: None,
            attack_finished: false,
            error_message: None,
            status_message: "Ready to start WPS attack".to_string(),
            log_messages: Vec::new(),
            reaver_available,
            pixiewps_available,
        }
    }
}

impl WpsScreen {
    pub fn view(&self, is_root: bool) -> Element<'_, Message> {
        let title = text("WPS Attack").size(28).color(colors::TEXT);

        let subtitle = text("Exploit WPS vulnerabilities to recover WiFi password")
            .size(14)
            .color(colors::TEXT_DIM);

        // Root requirement warning
        let root_warning = if !is_root {
            Some(
                container(
                    column![
                        text("⚠️  Root privileges required for WPS attacks")
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
        let tools_warning = if !self.reaver_available || !self.pixiewps_available {
            let missing = match (self.reaver_available, self.pixiewps_available) {
                (false, false) => "reaver and pixiewps not found",
                (false, true) => "reaver not found",
                (true, false) => "pixiewps not found",
                _ => "",
            };
            Some(
                container(
                    column![
                        text(format!("⚠️  {}", missing))
                            .size(13)
                            .color(colors::WARNING),
                        text("Install with: brew install reaver pixiewps")
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

        // Attack method selection
        let method_picker = column![
            text("Attack Method").size(13).color(colors::TEXT),
            pick_list(
                vec![WpsAttackMethod::PixieDust, WpsAttackMethod::PinBruteForce],
                Some(self.attack_method),
                Message::WpsMethodChanged,
            )
            .padding(10)
            .width(Length::Fill),
        ]
        .spacing(6);

        // Method description
        let method_info: Element<Message> = match self.attack_method {
            WpsAttackMethod::PixieDust => container(
                column![
                    text("⚡ Pixie-Dust Attack").size(13).color(colors::SUCCESS),
                    text("Exploits weak random number generation in WPS")
                        .size(11)
                        .color(colors::TEXT_DIM),
                    text("Fast: <10 seconds on vulnerable routers")
                        .size(11)
                        .color(colors::TEXT_DIM),
                    text("Success rate: ~30% of WPS-enabled routers")
                        .size(11)
                        .color(colors::TEXT_DIM),
                ]
                .spacing(4)
                .padding(10),
            )
            .style(theme::card_style)
            .into(),
            WpsAttackMethod::PinBruteForce => container(
                column![
                    text("🔢 PIN Brute-Force").size(13).color(colors::WARNING),
                    text("Tries all valid WPS PINs (~11,000 combinations)")
                        .size(11)
                        .color(colors::TEXT_DIM),
                    text("Slow: Hours to days (often blocked by AP)")
                        .size(11)
                        .color(colors::TEXT_DIM),
                    text("⚠️ Many routers implement lockout protection")
                        .size(11)
                        .color(colors::WARNING),
                ]
                .spacing(4)
                .padding(10),
            )
            .style(theme::card_style)
            .into(),
        };

        // Target configuration
        let bssid_input = column![
            text("Target BSSID *").size(13).color(colors::TEXT),
            text_input("AA:BB:CC:DD:EE:FF", &self.bssid)
                .on_input(Message::WpsBssidChanged)
                .padding(10)
                .size(14)
                .width(Length::Fill),
        ]
        .spacing(6);

        let channel_input = column![
            text("Channel *").size(13).color(colors::TEXT),
            text_input("1-11", &self.channel)
                .on_input(Message::WpsChannelChanged)
                .padding(10)
                .size(14)
                .width(Length::Fill),
        ]
        .spacing(6);

        let interface_input = column![
            text("Interface").size(13).color(colors::TEXT),
            text_input("en0", &self.interface)
                .on_input(Message::WpsInterfaceChanged)
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

            container(
                column![
                    text("Attack Progress").size(14).color(colors::TEXT),
                    text(step_text).size(12).color(colors::TEXT_DIM),
                    text(&self.status_message).size(12).color(colors::TEXT_DIM),
                ]
                .spacing(8)
                .padding(10),
            )
            .style(theme::card_style)
            .into()
        } else if let Some(ref pin) = self.found_pin {
            container(
                column![
                    text("✅ Attack Successful!")
                        .size(16)
                        .color(colors::SUCCESS),
                    text(format!("WPS PIN: {}", pin))
                        .size(14)
                        .color(colors::TEXT),
                    if let Some(ref password) = self.found_password {
                        text(format!("WiFi Password: {}", password))
                            .size(14)
                            .color(colors::TEXT)
                    } else {
                        text("").size(1)
                    },
                ]
                .spacing(8)
                .padding(10),
            )
            .style(theme::card_style)
            .into()
        } else if self.attack_finished {
            container(
                column![
                    text("❌ Attack Failed").size(14).color(colors::DANGER),
                    text("No WPS PIN found - router may not be vulnerable")
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
            container(text("").size(1)).into()
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
            .height(Length::Fixed(200.0))
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
            container(text("").size(1)).into()
        };

        // Action buttons
        let can_start = !self.bssid.is_empty()
            && !self.channel.is_empty()
            && !self.is_attacking
            && self.reaver_available
            && (self.attack_method == WpsAttackMethod::PixieDust || self.pixiewps_available)
            && is_root;

        let start_button = button(
            text(if self.is_attacking {
                "Attacking..."
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
            start_button.on_press(Message::StartWpsAttack)
        } else {
            start_button
        };

        let stop_button = button(text("Stop").size(14))
            .padding([12, 24])
            .style(theme::danger_button_style);

        let stop_button = if self.is_attacking {
            stop_button.on_press(Message::StopWpsAttack)
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
            .push(method_picker)
            .push(method_info)
            .push(bssid_input)
            .push(
                row![channel_input, interface_input]
                    .spacing(12)
                    .width(Length::Fill),
            )
            .push(progress_section)
            .push(action_buttons)
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

    /// Update from WPS result
    pub fn update_from_result(&mut self, result: &WpsResult) {
        self.is_attacking = false;
        self.attack_finished = true;

        match result {
            WpsResult::Found { pin, password } => {
                self.found_pin = Some(pin.clone());
                self.found_password = Some(password.clone());
                self.status_message = "Attack successful!".to_string();
            }
            WpsResult::NotFound => {
                self.status_message = "Attack completed - no PIN found".to_string();
            }
            WpsResult::Stopped => {
                self.status_message = "Attack stopped by user".to_string();
                self.attack_finished = false;
            }
            WpsResult::Error(e) => {
                self.error_message = Some(e.clone());
                self.status_message = format!("Attack failed: {}", e);
            }
        }
    }

    /// Reset attack state
    pub fn reset(&mut self) {
        self.is_attacking = false;
        self.current_step = 0;
        self.total_steps = 8;
        self.step_description = String::new();
        self.found_pin = None;
        self.found_password = None;
        self.attack_finished = false;
        self.error_message = None;
        self.status_message = "Ready to start WPS attack".to_string();
        self.log_messages.clear();
    }
}
