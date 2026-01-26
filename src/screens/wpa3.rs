/*!
 * WPA3 Attack Screen
 *
 * Handles WPA3-SAE attacks including transition mode downgrade,
 * SAE handshake capture, and Dragonblood vulnerability detection.
 */

use iced::widget::{button, column, container, pick_list, row, scrollable, text, text_input};
use iced::{Element, Length};

use crate::messages::Message;
use crate::theme::{self, colors};
use brutifi::{DragonbloodVulnerability, Wpa3AttackType, Wpa3NetworkType, Wpa3Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// WPA3 attack method selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Wpa3AttackMethod {
    #[default]
    TransitionDowngrade,
    SaeHandshake,
    DragonbloodScan,
}

impl std::fmt::Display for Wpa3AttackMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Wpa3AttackMethod::TransitionDowngrade => {
                write!(f, "Transition Mode Downgrade (Recommended)")
            }
            Wpa3AttackMethod::SaeHandshake => write!(f, "SAE Handshake Capture"),
            Wpa3AttackMethod::DragonbloodScan => write!(f, "Dragonblood Vulnerability Scan"),
        }
    }
}

impl From<Wpa3AttackMethod> for Wpa3AttackType {
    fn from(method: Wpa3AttackMethod) -> Self {
        match method {
            Wpa3AttackMethod::TransitionDowngrade => Wpa3AttackType::TransitionDowngrade,
            Wpa3AttackMethod::SaeHandshake => Wpa3AttackType::SaeHandshake,
            Wpa3AttackMethod::DragonbloodScan => Wpa3AttackType::DragonbloodScan,
        }
    }
}

/// WPA3 attack screen state
#[derive(Debug)]
#[allow(dead_code)]
pub struct Wpa3Screen {
    pub bssid: String,
    pub channel: String,
    pub interface: String,
    pub attack_method: Wpa3AttackMethod,
    pub network_type: Option<Wpa3NetworkType>,
    pub is_attacking: bool,
    pub current_step: u8,
    pub total_steps: u8,
    pub step_description: String,
    pub capture_file: Option<PathBuf>,
    pub hash_file: Option<PathBuf>,
    pub attack_finished: bool,
    pub error_message: Option<String>,
    pub status_message: String,
    pub log_messages: Vec<String>,
    pub vulnerabilities: Vec<DragonbloodVulnerability>,
    pub hcxdumptool_available: bool,
    pub hcxpcapngtool_available: bool,
}

impl Default for Wpa3Screen {
    fn default() -> Self {
        // Check external tools availability
        let hcxdumptool_available = brutifi::check_hcxdumptool_installed();
        let hcxpcapngtool_available = brutifi::check_hcxpcapngtool_installed();

        Self {
            bssid: String::new(),
            channel: "1".to_string(),
            interface: "en0".to_string(),
            attack_method: Wpa3AttackMethod::TransitionDowngrade,
            network_type: None,
            is_attacking: false,
            current_step: 0,
            total_steps: 6,
            step_description: String::new(),
            capture_file: None,
            hash_file: None,
            attack_finished: false,
            error_message: None,
            status_message: "Ready to start WPA3 attack".to_string(),
            log_messages: Vec::new(),
            vulnerabilities: Vec::new(),
            hcxdumptool_available,
            hcxpcapngtool_available,
        }
    }
}

impl Wpa3Screen {
    #[allow(dead_code)]
    pub fn view(&self, is_root: bool) -> Element<'_, Message> {
        let title = text("WPA3-SAE Attack").size(28).color(colors::TEXT);

        let subtitle = text("Attack WPA3 networks using transition mode downgrade or SAE capture")
            .size(14)
            .color(colors::TEXT_DIM);

        // Root requirement warning
        let root_warning = if !is_root {
            Some(
                container(
                    column![
                        text("⚠️  Root privileges required for WPA3 attacks")
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
        let tools_warning = if !self.hcxdumptool_available || !self.hcxpcapngtool_available {
            let missing = match (self.hcxdumptool_available, self.hcxpcapngtool_available) {
                (false, false) => "hcxdumptool and hcxpcapngtool not found",
                (false, true) => "hcxdumptool not found",
                (true, false) => "hcxpcapngtool not found",
                _ => "",
            };
            Some(
                container(
                    column![
                        text(format!("⚠️  {}", missing))
                            .size(13)
                            .color(colors::WARNING),
                        text("Install with: brew install hcxdumptool hcxtools")
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

        // Network type display
        let network_type_display: Element<Message> = if let Some(ref net_type) = self.network_type {
            let (type_str, type_color, description) = match net_type {
                Wpa3NetworkType::Wpa3Only => (
                    "WPA3-Only (SAE)",
                    colors::SUCCESS,
                    "Pure WPA3 network - requires SAE handshake capture",
                ),
                Wpa3NetworkType::Wpa3Transition => (
                    "WPA3-Transition",
                    colors::WARNING,
                    "WPA2/WPA3 mixed mode - vulnerable to downgrade attack",
                ),
                Wpa3NetworkType::PmfRequired => (
                    "PMF Required",
                    colors::SUCCESS,
                    "Protected Management Frames required",
                ),
                Wpa3NetworkType::PmfOptional => (
                    "PMF Optional",
                    colors::TEXT_DIM,
                    "Protected Management Frames supported but not required",
                ),
            };

            container(
                column![
                    text(format!("Network Type: {}", type_str))
                        .size(13)
                        .color(type_color),
                    text(description).size(11).color(colors::TEXT_DIM),
                ]
                .spacing(4)
                .padding(10),
            )
            .style(theme::card_style)
            .into()
        } else {
            container(text("")).into()
        };

        // Attack method selection
        let method_picker = column![
            text("Attack Method").size(13).color(colors::TEXT),
            pick_list(
                vec![
                    Wpa3AttackMethod::TransitionDowngrade,
                    Wpa3AttackMethod::SaeHandshake,
                    Wpa3AttackMethod::DragonbloodScan,
                ],
                Some(self.attack_method),
                Message::Wpa3MethodChanged,
            )
            .padding(10)
            .width(Length::Fill),
        ]
        .spacing(6);

        // Method description
        let method_info: Element<Message> = match self.attack_method {
            Wpa3AttackMethod::TransitionDowngrade => container(
                column![
                    text("⚡ Transition Mode Downgrade")
                        .size(13)
                        .color(colors::SUCCESS),
                    text("Forces WPA3-Transition networks to use WPA2")
                        .size(11)
                        .color(colors::TEXT_DIM),
                    text("Success rate: 80-90% on transition mode networks")
                        .size(11)
                        .color(colors::TEXT_DIM),
                    text("Then captures WPA2 handshake for offline cracking")
                        .size(11)
                        .color(colors::TEXT_DIM),
                ]
                .spacing(4)
                .padding(10),
            )
            .style(theme::card_style)
            .into(),
            Wpa3AttackMethod::SaeHandshake => container(
                column![
                    text("🔒 SAE Handshake Capture")
                        .size(13)
                        .color(colors::WARNING),
                    text("Captures SAE handshake from WPA3-only networks")
                        .size(11)
                        .color(colors::TEXT_DIM),
                    text("Requires client connection during capture")
                        .size(11)
                        .color(colors::TEXT_DIM),
                    text("Can be cracked offline with hashcat mode 22000")
                        .size(11)
                        .color(colors::TEXT_DIM),
                ]
                .spacing(4)
                .padding(10),
            )
            .style(theme::card_style)
            .into(),
            Wpa3AttackMethod::DragonbloodScan => container(
                column![
                    text("🐉 Dragonblood Vulnerability Scan")
                        .size(13)
                        .color(colors::DANGER),
                    text("Scans for known WPA3 vulnerabilities")
                        .size(11)
                        .color(colors::TEXT_DIM),
                    text("CVE-2019-13377: SAE timing side-channel")
                        .size(11)
                        .color(colors::TEXT_DIM),
                    text("CVE-2019-13456: Cache-based side-channel")
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
        let bssid_input = column![
            text("Target BSSID *").size(13).color(colors::TEXT),
            text_input("AA:BB:CC:DD:EE:FF", &self.bssid)
                .on_input(Message::Wpa3BssidChanged)
                .padding(10)
                .size(14)
                .width(Length::Fill),
        ]
        .spacing(6);

        let channel_input = column![
            text("Channel *").size(13).color(colors::TEXT),
            text_input("1-11", &self.channel)
                .on_input(Message::Wpa3ChannelChanged)
                .padding(10)
                .size(14)
                .width(Length::Fill),
        ]
        .spacing(6);

        let interface_input = column![
            text("Interface").size(13).color(colors::TEXT),
            text_input("en0", &self.interface)
                .on_input(Message::Wpa3InterfaceChanged)
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
        } else if self.capture_file.is_some() && self.hash_file.is_some() {
            let capture_path = self.capture_file.as_ref().unwrap().display().to_string();
            let hash_path = self.hash_file.as_ref().unwrap().display().to_string();

            container(
                column![
                    text("✅ Capture Successful!")
                        .size(16)
                        .color(colors::SUCCESS),
                    text(format!("Capture: {}", capture_path))
                        .size(12)
                        .color(colors::TEXT),
                    text(format!("Hash: {}", hash_path))
                        .size(12)
                        .color(colors::TEXT),
                    text("Ready to crack - use Crack tab")
                        .size(11)
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
                    text("❌ Capture Failed").size(14).color(colors::DANGER),
                    text("No handshakes captured - try again with client connection")
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

        // Vulnerabilities section
        let vulnerabilities_section: Element<Message> = if !self.vulnerabilities.is_empty() {
            let vuln_items = self
                .vulnerabilities
                .iter()
                .fold(column![].spacing(6), |col, vuln| {
                    col.push(
                        container(
                            column![
                                text(format!("{} - {}", vuln.cve, vuln.severity))
                                    .size(12)
                                    .color(colors::DANGER),
                                text(&vuln.description).size(11).color(colors::TEXT_DIM),
                            ]
                            .spacing(4),
                        )
                        .padding(8)
                        .style(theme::card_style),
                    )
                });

            container(
                column![
                    text("🐉 Dragonblood Vulnerabilities")
                        .size(13)
                        .color(colors::TEXT),
                    vuln_items,
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
            container(text("")).into()
        };

        // Action buttons
        let can_start = !self.bssid.is_empty()
            && !self.channel.is_empty()
            && !self.is_attacking
            && self.hcxdumptool_available
            && self.hcxpcapngtool_available
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
            start_button.on_press(Message::StartWpa3Attack)
        } else {
            start_button
        };

        let stop_button = button(text("Stop").size(14))
            .padding([12, 24])
            .style(theme::danger_button_style);

        let stop_button = if self.is_attacking {
            stop_button.on_press(Message::StopWpa3Attack)
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
            .push(network_type_display)
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
            .push(vulnerabilities_section)
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

    /// Update from WPA3 result
    #[allow(dead_code)]
    pub fn update_from_result(&mut self, result: &Wpa3Result) {
        self.is_attacking = false;
        self.attack_finished = true;

        match result {
            Wpa3Result::Captured {
                capture_file,
                hash_file,
            } => {
                self.capture_file = Some(capture_file.clone());
                self.hash_file = Some(hash_file.clone());
                self.status_message = "Capture successful!".to_string();
            }
            Wpa3Result::NotFound => {
                self.status_message = "No handshakes captured".to_string();
            }
            Wpa3Result::Stopped => {
                self.status_message = "Attack stopped by user".to_string();
                self.attack_finished = false;
            }
            Wpa3Result::Error(e) => {
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
        self.capture_file = None;
        self.hash_file = None;
        self.attack_finished = false;
        self.error_message = None;
        self.status_message = "Ready to start WPA3 attack".to_string();
        self.log_messages.clear();
        self.vulnerabilities.clear();
    }
}
