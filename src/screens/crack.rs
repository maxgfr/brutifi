/*!
 * Crack Screen
 *
 * Handles WPA/WPA2 password cracking.
 * Supports both numeric and wordlist attacks.
 */

use iced::widget::{
    button, checkbox, column, container, horizontal_space, pick_list, row, text, text_input,
};
use iced::{Element, Length};

use crate::app::Message;
use crate::theme::{self, colors};

/// Crack method selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CrackMethod {
    #[default]
    Numeric,
    Wordlist,
}

impl std::fmt::Display for CrackMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CrackMethod::Numeric => write!(f, "Numeric (digits only)"),
            CrackMethod::Wordlist => write!(f, "Wordlist"),
        }
    }
}

/// Crack screen state
#[derive(Debug, Clone)]
pub struct CrackScreen {
    pub handshake_path: String,
    pub use_captured_file: bool,
    pub ssid: String,
    pub method: CrackMethod,
    pub min_digits: String,
    pub max_digits: String,
    pub wordlist_path: String,
    pub threads: usize,
    pub is_cracking: bool,
    pub progress: f32,
    pub current_attempts: u64,
    pub total_attempts: u64,
    pub rate: f64,
    pub found_password: Option<String>,
    pub password_not_found: bool,
    pub error_message: Option<String>,
    pub status_message: String,
    pub log_messages: Vec<String>,
}

impl Default for CrackScreen {
    fn default() -> Self {
        Self {
            handshake_path: "capture.cap".to_string(),
            use_captured_file: true,
            ssid: String::new(),
            method: CrackMethod::Numeric,
            min_digits: "8".to_string(),
            max_digits: "8".to_string(),
            wordlist_path: String::new(),
            threads: num_cpus::get(),
            is_cracking: false,
            progress: 0.0,
            current_attempts: 0,
            total_attempts: 0,
            rate: 0.0,
            found_password: None,
            password_not_found: false,
            error_message: None,
            status_message: "Ready to crack".to_string(),
            log_messages: Vec::new(),
        }
    }
}

impl CrackScreen {
    pub fn view(&self) -> Element<'_, Message> {
        let title = text("Crack Password").size(28).color(colors::TEXT);

        let subtitle = text("Bruteforce WPA/WPA2 password from captured handshake")
            .size(14)
            .color(colors::TEXT_DIM);

        // Handshake file input
        let mut handshake_input = column![
            text("Handshake File").size(13).color(colors::TEXT),
            checkbox(
                "Use captured file from Capture screen",
                self.use_captured_file
            )
            .on_toggle(Message::UseCapturedFileToggled)
            .size(14),
        ]
        .spacing(6);

        // Only show file browse when NOT using captured file
        if !self.use_captured_file {
            handshake_input = handshake_input.push(
                row![
                    text_input("Browse for .cap file", &self.handshake_path)
                        .on_input(Message::HandshakePathChanged)
                        .padding(10)
                        .size(14)
                        .width(Length::Fill),
                    button(text("Browse").size(13))
                        .padding([10, 15])
                        .style(theme::secondary_button_style)
                        .on_press(Message::BrowseHandshake),
                ]
                .spacing(10),
            );
        }

        // Method selection
        let method_picker = column![
            text("Attack Method").size(13).color(colors::TEXT),
            pick_list(
                vec![CrackMethod::Numeric, CrackMethod::Wordlist],
                Some(self.method),
                Message::MethodChanged,
            )
            .padding(10)
            .width(Length::Fill),
        ]
        .spacing(6);

        // Method-specific options
        let method_options: Element<Message> = match self.method {
            CrackMethod::Numeric => container(
                column![
                    text("Numeric Attack Options").size(14).color(colors::TEXT),
                    text("Tests all numeric combinations (e.g., 00000000 to 99999999)")
                        .size(12)
                        .color(colors::TEXT_DIM),
                    row![
                        column![
                            text("Min Digits").size(12).color(colors::TEXT_DIM),
                            text_input("8", &self.min_digits)
                                .on_input(Message::MinDigitsChanged)
                                .padding(10)
                                .size(14)
                                .width(Length::Fixed(100.0)),
                        ]
                        .spacing(4),
                        column![
                            text("Max Digits").size(12).color(colors::TEXT_DIM),
                            text_input("8", &self.max_digits)
                                .on_input(Message::MaxDigitsChanged)
                                .padding(10)
                                .size(14)
                                .width(Length::Fixed(100.0)),
                        ]
                        .spacing(4),
                        horizontal_space(),
                        column![
                            text("Combinations").size(12).color(colors::TEXT_DIM),
                            text(self.calculate_combinations())
                                .size(14)
                                .color(colors::SECONDARY),
                        ]
                        .spacing(4),
                    ]
                    .spacing(20)
                    .align_y(iced::Alignment::End),
                ]
                .spacing(10)
                .padding(15),
            )
            .style(theme::card_style)
            .into(),
            CrackMethod::Wordlist => container(
                column![
                    text("Wordlist Attack Options").size(14).color(colors::TEXT),
                    text("Tests passwords from a wordlist file (e.g., rockyou.txt)")
                        .size(12)
                        .color(colors::TEXT_DIM),
                    row![
                        text_input("Select a wordlist file...", &self.wordlist_path)
                            .on_input(Message::WordlistPathChanged)
                            .padding(10)
                            .size(14)
                            .width(Length::Fill),
                        button(text("Browse").size(13))
                            .padding([10, 15])
                            .style(theme::secondary_button_style)
                            .on_press(Message::BrowseWordlist),
                    ]
                    .spacing(10),
                ]
                .spacing(10)
                .padding(15),
            )
            .style(theme::card_style)
            .into(),
        };

        // Threads configuration
        let threads_config = column![text(format!(
            "Threads: {} (optimized for your CPU)",
            self.threads
        ))
        .size(13)
        .color(colors::TEXT_DIM),];

        // Progress display
        let progress_display =
            if self.is_cracking || self.found_password.is_some() || self.current_attempts > 0 {
                let progress_bar = container(
                    container(text(""))
                        .width(Length::FillPortion((self.progress * 100.0) as u16))
                        .height(Length::Fixed(8.0))
                        .style(|_| container::Style {
                            background: Some(iced::Background::Color(colors::PRIMARY)),
                            border: iced::Border {
                                radius: 4.0.into(),
                                ..Default::default()
                            },
                            ..Default::default()
                        }),
                )
                .width(Length::Fill)
                .height(Length::Fixed(8.0))
                .style(|_| container::Style {
                    background: Some(iced::Background::Color(colors::SURFACE)),
                    border: iced::Border {
                        radius: 4.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                });

                Some(
                    container(
                        column![
                            row![
                                text(&self.status_message).size(13).color(colors::TEXT),
                                horizontal_space(),
                                text(format!("{:.1}%", self.progress * 100.0))
                                    .size(13)
                                    .color(colors::TEXT_DIM),
                            ],
                            progress_bar,
                            row![
                                text(format!(
                                    "{} / {} attempts",
                                    format_number(self.current_attempts),
                                    format_number(self.total_attempts)
                                ))
                                .size(12)
                                .color(colors::TEXT_DIM),
                                horizontal_space(),
                                text(format!("{:.0} passwords/sec", self.rate))
                                    .size(12)
                                    .color(colors::SECONDARY),
                            ],
                        ]
                        .spacing(8)
                        .padding(15),
                    )
                    .style(theme::card_style),
                )
            } else {
                None
            };

        // Result display
        let result_display = if let Some(ref password) = self.found_password {
            Some(
                container(
                    column![
                        text("Password Found!").size(18).color(colors::SUCCESS),
                        container(
                            row![
                                text(password).size(24).color(colors::TEXT),
                                horizontal_space(),
                                button(text("Copy").size(13))
                                    .padding([8, 15])
                                    .style(theme::secondary_button_style)
                                    .on_press(Message::CopyPassword),
                            ]
                            .align_y(iced::Alignment::Center)
                            .padding(15)
                        )
                        .style(|_| container::Style {
                            background: Some(iced::Background::Color(iced::Color::from_rgba(
                                0.18, 0.80, 0.44, 0.2
                            ))),
                            border: iced::Border {
                                color: colors::SUCCESS,
                                width: 2.0,
                                radius: 6.0.into(),
                            },
                            ..Default::default()
                        }),
                    ]
                    .spacing(10)
                    .padding(15),
                )
                .style(theme::card_style),
            )
        } else if self.password_not_found {
            Some(
                container(
                    column![
                        text("Password Not Found").size(18).color(colors::DANGER),
                        container(
                            text("The password was not found in the tested combinations")
                                .size(14)
                                .color(colors::TEXT)
                        )
                        .padding(15)
                        .style(|_| container::Style {
                            background: Some(iced::Background::Color(iced::Color::from_rgba(
                                0.86, 0.21, 0.27, 0.2
                            ))),
                            border: iced::Border {
                                color: colors::DANGER,
                                width: 2.0,
                                radius: 6.0.into(),
                            },
                            ..Default::default()
                        }),
                    ]
                    .spacing(10)
                    .padding(15),
                )
                .style(theme::card_style),
            )
        } else {
            None
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
        let crack_btn = if self.is_cracking {
            button(
                row![text("⟳").size(18), text("Stop Cracking").size(14),]
                    .spacing(8)
                    .align_y(iced::Alignment::Center),
            )
            .padding([12, 24])
            .style(theme::danger_button_style)
            .on_press(Message::StopCrack)
        } else {
            let can_start = match self.method {
                CrackMethod::Numeric => !self.handshake_path.is_empty(),
                CrackMethod::Wordlist => {
                    !self.handshake_path.is_empty() && !self.wordlist_path.is_empty()
                }
            };

            if can_start {
                button(text("Start Cracking").size(14))
                    .padding([12, 24])
                    .style(theme::primary_button_style)
                    .on_press(Message::StartCrack)
            } else {
                button(text("Start Cracking").size(14))
                    .padding([12, 24])
                    .style(theme::secondary_button_style)
            }
        };

        let back_btn = button(text("Back to Capture").size(14))
            .padding([10, 20])
            .style(theme::secondary_button_style)
            .on_press(Message::GoToCapture);

        // Logs display
        let logs_display = if !self.log_messages.is_empty() {
            let logs: Vec<Element<Message>> = self
                .log_messages
                .iter()
                .map(|msg| {
                    text(format!("• {}", msg))
                        .size(11)
                        .color(colors::TEXT_DIM)
                        .into()
                })
                .collect();

            Some(
                container(
                    column![
                        text("Logs").size(13).color(colors::TEXT),
                        iced::widget::scrollable(
                            iced::widget::Column::with_children(logs)
                                .spacing(2)
                                .width(Length::Fill)
                        )
                        .height(Length::Fixed(150.0))
                    ]
                    .spacing(8)
                    .padding(15),
                )
                .style(theme::card_style),
            )
        } else {
            None
        };

        // Build layout
        let mut content = column![
            title,
            subtitle,
            handshake_input,
            method_picker,
            method_options,
            threads_config,
        ]
        .spacing(15);

        if let Some(progress) = progress_display {
            content = content.push(progress);
        }

        if let Some(logs) = logs_display {
            content = content.push(logs);
        }

        if let Some(result) = result_display {
            content = content.push(result);
        }

        if let Some(error) = error_display {
            content = content.push(error);
        }

        content = content.push(row![back_btn, horizontal_space(), crack_btn,].spacing(10));

        container(iced::widget::scrollable(content.padding(20)))
            .width(Length::Fill)
            .height(Length::Fill)
            .style(|_| container::Style {
                background: Some(iced::Background::Color(colors::BACKGROUND)),
                ..Default::default()
            })
            .into()
    }

    fn calculate_combinations(&self) -> String {
        let min: usize = self.min_digits.parse().unwrap_or(8);
        let max: usize = self.max_digits.parse().unwrap_or(8);

        let mut total: u64 = 0;
        for len in min..=max {
            total += 10u64.pow(len as u32);
        }

        format_number(total)
    }
}

/// Format a number with thousand separators
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.insert(0, ',');
        }
        result.insert(0, c);
    }
    result
}
