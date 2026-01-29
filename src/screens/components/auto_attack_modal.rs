/*!
 * Auto Attack Modal Component
 *
 * Displays progress of automated attack sequence in a modal overlay.
 */

use iced::widget::{
    button, column, container, horizontal_rule, horizontal_space, row, text, Column,
};
use iced::{Element, Length};

use crate::messages::Message;
use crate::theme::{self, colors};
use brutifi::{AttackState, AttackStatus};

/// Render the auto attack modal overlay
pub fn view_modal<'a>(attacks: &'a [AttackState], is_running: bool) -> Element<'a, Message> {
    // Create the modal content
    let modal_content = container(
        column![
            // Header
            row![
                text("Automated Attack Sequence").size(20),
                horizontal_space(),
                if is_running {
                    button(text("Cancel"))
                        .on_press(Message::StopAutoAttack)
                        .style(theme::danger_button_style)
                } else {
                    button(text("Close"))
                        .on_press(Message::CloseAutoAttackModal)
                        .style(theme::secondary_button_style)
                }
            ]
            .spacing(10)
            .padding(5),
            horizontal_rule(1),
            // Attack list
            Column::with_children(
                attacks
                    .iter()
                    .map(|attack| view_attack_row(attack))
                    .collect::<Vec<_>>()
            )
            .spacing(8)
            .padding([10, 0])
        ]
        .spacing(15)
        .padding(25),
    )
    .width(Length::Fixed(600.0))
    .style(theme::card_style);

    // Wrap in semi-transparent overlay
    container(modal_content)
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .style(|_theme: &iced::Theme| container::Style {
            background: Some(iced::Background::Color(iced::Color::from_rgba(
                0.0, 0.0, 0.0, 0.7,
            ))),
            ..Default::default()
        })
        .into()
}

/// Render a single attack row
fn view_attack_row<'a>(attack: &'a AttackState) -> Element<'a, Message> {
    let (status_icon, status_color) = match attack.status {
        AttackStatus::Pending => ("⏳", colors::TEXT_DIM),
        AttackStatus::Running => ("🔄", colors::SECONDARY),
        AttackStatus::Success => ("✅", colors::SUCCESS),
        AttackStatus::Failed => ("❌", colors::DANGER),
        AttackStatus::Skipped => ("⏭️", colors::TEXT_DIM),
        AttackStatus::Stopped => ("⏹️", colors::TEXT_DIM),
    };

    // Format time display based on status
    let time_display = if attack.status == AttackStatus::Running {
        format!(
            "{}s / {}s",
            attack.elapsed_time.as_secs(),
            attack.timeout.as_secs()
        )
    } else {
        format!("{}s", attack.timeout.as_secs())
    };

    container(
        row![
            text(status_icon).size(20),
            column![
                text(attack.attack_type.display_name()).size(15),
                text(&attack.progress_message)
                    .size(12)
                    .color(colors::TEXT_DIM),
            ]
            .spacing(2),
            horizontal_space(),
            text(time_display).size(12).color(colors::TEXT_DIM),
        ]
        .spacing(12)
        .padding(10)
        .align_y(iced::alignment::Vertical::Center),
    )
    .width(Length::Fill)
    .style(move |_theme: &iced::Theme| container::Style {
        border: iced::Border {
            color: status_color,
            width: 1.0,
            radius: 4.0.into(),
        },
        background: Some(iced::Background::Color(iced::Color::from_rgba(
            0.0, 0.0, 0.0, 0.2,
        ))),
        ..Default::default()
    })
    .into()
}
