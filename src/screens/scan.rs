/*!
 * Scan Screen
 *
 * Handles WiFi network scanning and network selection.
 * Shows Location Services permission warning if needed.
 */

use iced::widget::{button, column, container, horizontal_space, row, scrollable, text, Column};
use iced::{Element, Length};

use crate::app::Message;
use crate::theme::{self, colors};
use bruteforce_wifi::WifiNetwork;

/// Scan screen state
#[derive(Debug, Clone, Default)]
pub struct ScanScreen {
    pub networks: Vec<WifiNetwork>,
    pub selected_network: Option<usize>,
    pub is_scanning: bool,
    pub error_message: Option<String>,
    pub location_services_warning: bool,
}

impl ScanScreen {
    pub fn view(&self) -> Element<'_, Message> {
        let title = text("WiFi Network Scanner").size(28).color(colors::TEXT);

        let subtitle = text("Select a network to capture its handshake")
            .size(14)
            .color(colors::TEXT_DIM);

        // Location Services Warning
        let location_warning = if self.location_services_warning {
            Some(
                container(
                    column![
                        text("Location Services Required")
                            .size(16)
                            .color(colors::WARNING),
                        text("macOS requires Location Services permission to access WiFi BSSIDs.")
                            .size(13)
                            .color(colors::TEXT_DIM),
                        text("").size(6),
                        text("To fix this:").size(13).color(colors::TEXT),
                        text("1. Open System Settings > Privacy & Security > Location Services")
                            .size(12)
                            .color(colors::TEXT_DIM),
                        text("2. Enable location access for the app")
                            .size(12)
                            .color(colors::TEXT_DIM),
                        text("3. Restart the application")
                            .size(12)
                            .color(colors::TEXT_DIM),
                    ]
                    .spacing(4)
                    .padding(15),
                )
                .style(|_| container::Style {
                    background: Some(iced::Background::Color(iced::Color::from_rgba(
                        0.95, 0.77, 0.06, 0.15,
                    ))),
                    border: iced::Border {
                        color: colors::WARNING,
                        width: 1.0,
                        radius: 8.0.into(),
                    },
                    ..Default::default()
                }),
            )
        } else {
            None
        };

        // Error message
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

        // Scan button
        let scan_btn = if self.is_scanning {
            button(
                row![text("⟳").size(18), text("Scanning...").size(14),]
                    .spacing(8)
                    .align_y(iced::Alignment::Center),
            )
            .padding([10, 20])
            .style(theme::secondary_button_style)
            .on_press(Message::StopScan)
        } else {
            button(text("Scan Networks").size(14))
                .padding([10, 20])
                .style(theme::primary_button_style)
                .on_press(Message::StartScan)
        };

        // Deauth button (always show warning on macOS)
        let deauth_btn = if self.selected_network.is_some() {
            Some(
                button(text("Send Deauth").size(14))
                    .padding([10, 20])
                    .style(theme::secondary_button_style)
                    .on_press(Message::DeauthNetwork),
            )
        } else {
            None
        };

        // Network list
        let network_list: Element<Message> = if self.networks.is_empty() {
            if self.is_scanning {
                container(text("Scanning for networks...").color(colors::TEXT_DIM))
                    .center_x(Length::Fill)
                    .center_y(Length::Fill)
                    .into()
            } else {
                container(
                    column![
                        text("No networks found").size(16).color(colors::TEXT_DIM),
                        text("Click 'Scan Networks' to discover nearby WiFi networks")
                            .size(13)
                            .color(colors::TEXT_DIM),
                    ]
                    .spacing(8)
                    .align_x(iced::Alignment::Center),
                )
                .center_x(Length::Fill)
                .center_y(Length::Fill)
                .into()
            }
        } else {
            let items: Vec<Element<Message>> = self
                .networks
                .iter()
                .enumerate()
                .map(|(idx, network)| {
                    let is_selected = self.selected_network == Some(idx);

                    let security_color = if network.security.contains("WPA3") {
                        colors::DANGER
                    } else if network.security.contains("WPA") {
                        colors::PRIMARY
                    } else if network.security.contains("None") {
                        colors::SUCCESS
                    } else {
                        colors::TEXT_DIM
                    };

                    let signal_icon = if let Ok(rssi) = network.signal_strength.parse::<i32>() {
                        if rssi > -50 {
                            "Strong"
                        } else if rssi > -70 {
                            "Medium"
                        } else {
                            "Weak"
                        }
                    } else {
                        "?"
                    };

                    let bssid_display = if network.bssid.is_empty() {
                        "BSSID hidden".to_string()
                    } else {
                        network.bssid.clone()
                    };

                    // Check if this network has multiple channels (grouped SSIDs)
                    let has_multiple_channels = network.channel.contains(',');
                    let channel_display = if has_multiple_channels {
                        format!("Channels: {}", network.channel)
                    } else {
                        format!("Ch {}", network.channel)
                    };

                    let item_style = if is_selected {
                        theme::network_item_selected_style
                    } else {
                        theme::network_item_style
                    };

                    button(
                        container(
                            row![
                                column![
                                    row![
                                        text(network.ssid.clone()).size(15).color(if is_selected {
                                            colors::SUCCESS
                                        } else {
                                            colors::TEXT
                                        }),
                                        if has_multiple_channels {
                                            text(" (Multi-band)").size(11).color(colors::PRIMARY)
                                        } else {
                                            text("")
                                        }
                                    ]
                                    .spacing(6)
                                    .align_y(iced::Alignment::Center),
                                    row![
                                        text(bssid_display).size(11).color(colors::TEXT_DIM),
                                        text(" | ").size(11).color(colors::TEXT_DIM),
                                        text(channel_display).size(11).color(
                                            if has_multiple_channels {
                                                colors::PRIMARY
                                            } else {
                                                colors::TEXT_DIM
                                            }
                                        ),
                                    ]
                                ]
                                .spacing(4),
                                horizontal_space(),
                                column![
                                    text(network.security.clone())
                                        .size(12)
                                        .color(security_color),
                                    text(format!("{} ({})", signal_icon, network.signal_strength))
                                        .size(11)
                                        .color(colors::TEXT_DIM),
                                ]
                                .align_x(iced::Alignment::End)
                            ]
                            .align_y(iced::Alignment::Center)
                            .padding(12),
                        )
                        .style(item_style),
                    )
                    .padding(0)
                    .style(|_, _| button::Style {
                        background: None,
                        ..Default::default()
                    })
                    .on_press(Message::SelectNetwork(idx))
                    .into()
                })
                .collect();

            scrollable(Column::with_children(items).spacing(8).width(Length::Fill))
                .height(Length::Fill)
                .into()
        };

        // Continue button
        let continue_btn = if let Some(idx) = self.selected_network {
            let network = &self.networks[idx];
            if !network.bssid.is_empty() {
                Some(
                    button(text("Continue to Capture").size(14))
                        .padding([12, 24])
                        .style(theme::primary_button_style)
                        .on_press(Message::GoToCapture),
                )
            } else {
                Some(
                    button(text("BSSID required - Enable Location Services").size(14))
                        .padding([12, 24])
                        .style(theme::secondary_button_style),
                )
            }
        } else {
            None
        };

        // Build layout
        let mut content = column![title, subtitle,].spacing(8);

        if let Some(warning) = location_warning {
            content = content.push(warning);
        }

        if let Some(error) = error_display {
            content = content.push(error);
        }

        let mut btn_row = row![scan_btn,].spacing(10);

        if let Some(deauth) = deauth_btn {
            btn_row = btn_row.push(deauth);
        }

        btn_row = btn_row.push(horizontal_space());

        if !self.networks.is_empty() {
            btn_row = btn_row.push(
                text(format!("{} networks found", self.networks.len()))
                    .size(13)
                    .color(colors::TEXT_DIM),
            );
        }

        content = content.push(btn_row.align_y(iced::Alignment::Center));

        content = content.push(
            container(network_list)
                .height(Length::Fill)
                .width(Length::Fill)
                .style(theme::card_style)
                .padding(10),
        );

        if let Some(btn) = continue_btn {
            content = content.push(row![horizontal_space(), btn,]);
        }

        container(content.spacing(15).padding(20))
            .width(Length::Fill)
            .height(Length::Fill)
            .style(|_| container::Style {
                background: Some(iced::Background::Color(colors::BACKGROUND)),
                ..Default::default()
            })
            .into()
    }
}
