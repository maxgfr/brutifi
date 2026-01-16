/*!
 * Capture Screen
 *
 * Handles WPA/WPA2 handshake capture.
 * Shows real-time progress and EAPOL message detection.
 */

use iced::widget::{button, column, container, horizontal_space, pick_list, row, text};
use iced::{Element, Length};

use crate::app::Message;
use crate::theme::{self, colors};
use bruteforce_wifi::WifiNetwork;

/// EAPOL message tracking
#[derive(Debug, Clone, Default)]
pub struct HandshakeProgress {
    pub m1_received: bool,
    pub m2_received: bool,
    pub m3_received: bool,
    pub m4_received: bool,
    pub last_ap_mac: String,
    pub last_client_mac: String,
}

impl HandshakeProgress {
    pub fn is_complete(&self) -> bool {
        self.m1_received && self.m2_received
    }
}

/// Capture screen state
#[derive(Debug, Clone)]
pub struct CaptureScreen {
    pub target_network: Option<WifiNetwork>,
    pub available_networks: Vec<WifiNetwork>,
    #[allow(dead_code)]
    pub interface: String,
    pub output_file: String,
    pub is_capturing: bool,
    pub packets_captured: u64,
    pub handshake_progress: HandshakeProgress,
    pub handshake_complete: bool,
    pub error_message: Option<String>,
    #[allow(dead_code)]
    pub log_messages: Vec<String>,
}

impl Default for CaptureScreen {
    fn default() -> Self {
        Self {
            target_network: None,
            available_networks: Vec::new(),
            interface: "en0".to_string(),
            output_file: "capture.cap".to_string(),
            is_capturing: false,
            packets_captured: 0,
            handshake_progress: HandshakeProgress::default(),
            handshake_complete: false,
            error_message: None,
            log_messages: Vec::new(),
        }
    }
}

impl CaptureScreen {
    pub fn view(&self) -> Element<'_, Message> {
        let title = text("Capture Handshake").size(28).color(colors::TEXT);

        // Network selector and info
        let network_selector = if self.available_networks.is_empty() {
            container(
                column![
                    text("No networks available")
                        .size(14)
                        .color(colors::TEXT_DIM),
                    text("Please go back to Scan screen and scan for networks first")
                        .size(12)
                        .color(colors::WARNING),
                ]
                .spacing(4)
                .padding(15),
            )
            .style(theme::card_style)
        } else {
            let picker = column![
                text("Select Target Network").size(13).color(colors::TEXT),
                pick_list(
                    &self.available_networks[..],
                    self.target_network.as_ref(),
                    Message::SelectCaptureNetwork,
                )
                .placeholder("Choose a network...")
                .padding(10),
            ]
            .spacing(6);

            let network_details = self.target_network.as_ref().map(|network| {
                column![row![
                    text("BSSID: ").size(12).color(colors::TEXT_DIM),
                    text(&network.bssid).size(12).color(colors::TEXT),
                    text(" | Channel: ").size(12).color(colors::TEXT_DIM),
                    text(&network.channel).size(12).color(colors::TEXT),
                    text(" | Security: ").size(12).color(colors::TEXT_DIM),
                    text(&network.security).size(12).color(colors::PRIMARY),
                ],]
                .spacing(6)
            });

            let mut content = column![picker].spacing(10);
            if let Some(details) = network_details {
                content = content.push(details);
            }

            container(content.padding(15)).style(theme::card_style)
        };

        // macOS Warning
        let macos_warning = container(
            column![
                text("macOS Capture Instructions")
                    .size(14)
                    .color(colors::WARNING),
                text("Apple Silicon does NOT support packet injection (deauth attacks).")
                    .size(12)
                    .color(colors::TEXT_DIM),
                text("").size(4),
                text("To capture a handshake:").size(12).color(colors::TEXT),
                text("  1. Start capture (app will listen on all channels)")
                    .size(11)
                    .color(colors::TEXT_DIM),
                text("  2. On another device (phone/laptop), disconnect from WiFi")
                    .size(11)
                    .color(colors::TEXT_DIM),
                text("  3. Reconnect to the target network")
                    .size(11)
                    .color(colors::TEXT_DIM),
                text("  4. The app will capture the handshake automatically")
                    .size(11)
                    .color(colors::TEXT_DIM),
                text("").size(4),
                text("💡 Tip: Works even without BSSID if you know the channel")
                    .size(11)
                    .color(colors::SUCCESS),
            ]
            .spacing(2)
            .padding(12),
        )
        .style(|_| container::Style {
            background: Some(iced::Background::Color(iced::Color::from_rgba(
                0.95, 0.77, 0.06, 0.1,
            ))),
            border: iced::Border {
                color: colors::WARNING,
                width: 1.0,
                radius: 6.0.into(),
            },
            ..Default::default()
        });

        // Handshake progress
        let handshake_status = {
            let hp = &self.handshake_progress;

            let m1_color = if hp.m1_received {
                colors::SUCCESS
            } else {
                colors::TEXT_DIM
            };
            let m2_color = if hp.m2_received {
                colors::SUCCESS
            } else {
                colors::TEXT_DIM
            };
            let m3_color = if hp.m3_received {
                colors::SUCCESS
            } else {
                colors::TEXT_DIM
            };
            let m4_color = if hp.m4_received {
                colors::SUCCESS
            } else {
                colors::TEXT_DIM
            };

            container(
                column![
                    text("4-Way Handshake Progress")
                        .size(14)
                        .color(colors::TEXT),
                    row![
                        container(
                            column![
                                text("M1").size(13).color(m1_color),
                                text(if hp.m1_received {
                                    "ANonce"
                                } else {
                                    "Waiting..."
                                })
                                .size(10)
                                .color(m1_color),
                            ]
                            .align_x(iced::Alignment::Center)
                        )
                        .padding(10)
                        .style(|_| container::Style {
                            background: Some(iced::Background::Color(if hp.m1_received {
                                iced::Color::from_rgba(0.18, 0.80, 0.44, 0.2)
                            } else {
                                colors::SURFACE
                            })),
                            border: iced::Border {
                                color: if hp.m1_received {
                                    colors::SUCCESS
                                } else {
                                    colors::BORDER
                                },
                                width: 1.0,
                                radius: 6.0.into(),
                            },
                            ..Default::default()
                        }),
                        text("→").size(18).color(colors::TEXT_DIM),
                        container(
                            column![
                                text("M2").size(13).color(m2_color),
                                text(if hp.m2_received {
                                    "SNonce+MIC"
                                } else {
                                    "Waiting..."
                                })
                                .size(10)
                                .color(m2_color),
                            ]
                            .align_x(iced::Alignment::Center)
                        )
                        .padding(10)
                        .style(|_| container::Style {
                            background: Some(iced::Background::Color(if hp.m2_received {
                                iced::Color::from_rgba(0.18, 0.80, 0.44, 0.2)
                            } else {
                                colors::SURFACE
                            })),
                            border: iced::Border {
                                color: if hp.m2_received {
                                    colors::SUCCESS
                                } else {
                                    colors::BORDER
                                },
                                width: 1.0,
                                radius: 6.0.into(),
                            },
                            ..Default::default()
                        }),
                        text("→").size(18).color(colors::TEXT_DIM),
                        container(
                            column![
                                text("M3").size(13).color(m3_color),
                                text(if hp.m3_received { "GTK" } else { "Optional" })
                                    .size(10)
                                    .color(m3_color),
                            ]
                            .align_x(iced::Alignment::Center)
                        )
                        .padding(10)
                        .style(|_| container::Style {
                            background: Some(iced::Background::Color(if hp.m3_received {
                                iced::Color::from_rgba(0.18, 0.80, 0.44, 0.2)
                            } else {
                                colors::SURFACE
                            })),
                            border: iced::Border {
                                color: if hp.m3_received {
                                    colors::SUCCESS
                                } else {
                                    colors::BORDER
                                },
                                width: 1.0,
                                radius: 6.0.into(),
                            },
                            ..Default::default()
                        }),
                        text("→").size(18).color(colors::TEXT_DIM),
                        container(
                            column![
                                text("M4").size(13).color(m4_color),
                                text(if hp.m4_received {
                                    "Complete"
                                } else {
                                    "Optional"
                                })
                                .size(10)
                                .color(m4_color),
                            ]
                            .align_x(iced::Alignment::Center)
                        )
                        .padding(10)
                        .style(|_| container::Style {
                            background: Some(iced::Background::Color(if hp.m4_received {
                                iced::Color::from_rgba(0.18, 0.80, 0.44, 0.2)
                            } else {
                                colors::SURFACE
                            })),
                            border: iced::Border {
                                color: if hp.m4_received {
                                    colors::SUCCESS
                                } else {
                                    colors::BORDER
                                },
                                width: 1.0,
                                radius: 6.0.into(),
                            },
                            ..Default::default()
                        }),
                    ]
                    .spacing(10)
                    .align_y(iced::Alignment::Center),
                    if self.handshake_complete {
                        text("Handshake captured successfully!")
                            .size(14)
                            .color(colors::SUCCESS)
                    } else if hp.is_complete() {
                        text("M1+M2 received - Handshake ready for cracking!")
                            .size(14)
                            .color(colors::SUCCESS)
                    } else {
                        text("Waiting for handshake... Reconnect a device to trigger it.")
                            .size(13)
                            .color(colors::TEXT_DIM)
                    }
                ]
                .spacing(12)
                .padding(15),
            )
            .style(theme::card_style)
        };

        // Capture status
        let status_text = if self.is_capturing {
            text(format!("⟳ Capturing... {} packets", self.packets_captured))
                .size(14)
                .color(colors::SUCCESS)
        } else if self.handshake_complete {
            text("Capture complete!").size(14).color(colors::SUCCESS)
        } else {
            text("Ready to capture").size(14).color(colors::TEXT_DIM)
        };

        // Error display
        let error_display = self.error_message.as_ref().map(|msg| {
            container(
                text(format!("Error: {}", msg))
                    .size(13)
                    .color(colors::DANGER),
            )
            .padding(10)
            .style(|_| container::Style {
                background: Some(iced::Background::Color(iced::Color::from_rgba(
                    0.86, 0.21, 0.27, 0.15,
                ))),
                border: iced::Border {
                    color: colors::DANGER,
                    width: 1.0,
                    radius: 6.0.into(),
                },
                ..Default::default()
            })
        });

        // Control buttons
        let capture_btn = if self.is_capturing {
            button(
                row![text("⟳").size(18), text("Stop Capture").size(14),]
                    .spacing(8)
                    .align_y(iced::Alignment::Center),
            )
            .padding([12, 24])
            .style(theme::danger_button_style)
            .on_press(Message::StopCapture)
        } else {
            button(text("Start Capture").size(14))
                .padding([12, 24])
                .style(theme::primary_button_style)
                .on_press(Message::StartCapture)
        };

        let back_btn = button(text("Back to Scan").size(14))
            .padding([10, 20])
            .style(theme::secondary_button_style)
            .on_press(Message::GoToScan);

        let continue_btn = if self.handshake_complete || self.handshake_progress.is_complete() {
            Some(
                button(text("Continue to Crack").size(14))
                    .padding([12, 24])
                    .style(theme::primary_button_style)
                    .on_press(Message::GoToCrack),
            )
        } else {
            None
        };

        // Build layout
        let mut content = column![
            title,
            network_selector,
            macos_warning,
            handshake_status,
            row![status_text, horizontal_space(),],
        ]
        .spacing(15);

        if let Some(error) = error_display {
            content = content.push(error);
        }

        content = content.push(
            row![back_btn, horizontal_space(), capture_btn,]
                .push_maybe(continue_btn.map(|btn| row![text("  "), btn,]))
                .spacing(10),
        );

        container(content.padding(20))
            .width(Length::Fill)
            .height(Length::Fill)
            .style(|_| container::Style {
                background: Some(iced::Background::Color(colors::BACKGROUND)),
                ..Default::default()
            })
            .into()
    }
}
