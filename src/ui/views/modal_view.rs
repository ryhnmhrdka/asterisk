use crate::types::AiProvider;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
    Frame,
};

pub struct ModalView;

impl ModalView {
    pub fn render_key_modal(
        f: &mut Frame,
        area: Rect,
        provider: AiProvider,
        input_key: &str,
        error_msg: Option<&str>,
    ) {
        let modal_width = 68.min(area.width.saturating_sub(4));
        let modal_height = 13.min(area.height.saturating_sub(2));

        let x = (area.width.saturating_sub(modal_width)) / 2;
        let y = (area.height.saturating_sub(modal_height)) / 2;
        let modal_rect = Rect::new(x, y, modal_width, modal_height);

        // 1. Clear underlying widgets and render dark background
        f.render_widget(Clear, modal_rect);
        let bg_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Rgb(220, 220, 220)))
            .title(Span::styled(
                " ⚠️  AUTHENTICATION REQUIRED ",
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ))
            .style(Style::default().bg(Color::Rgb(16, 16, 18)));
        f.render_widget(bg_block, modal_rect);

        // Inner layout
        let inner_chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(1), // Provider notice
                Constraint::Length(1), // Explanation
                Constraint::Length(1), // Spacer
                Constraint::Length(3), // Input box
                Constraint::Length(1), // Error or status
                Constraint::Min(1),    // Spacer
                Constraint::Length(1), // Action hotkeys footer
            ])
            .split(modal_rect);

        // Provider notice
        let notice = Line::from(vec![
            Span::styled("No API key configured for: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                provider.name(),
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ),
        ]);
        f.render_widget(Paragraph::new(notice), inner_chunks[0]);

        // Explanation
        let expl = Line::from(Span::styled(
            "An API key is required to execute autonomous AI defense workflows.",
            Style::default().fg(Color::Gray),
        ));
        f.render_widget(Paragraph::new(expl), inner_chunks[1]);

        // Key Input Box
        let input_box = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::Rgb(80, 80, 90)))
            .style(Style::default().bg(Color::Rgb(24, 24, 28)));

        let input_display = if input_key.is_empty() {
            Line::from(vec![
                Span::styled("> ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    "paste or enter API key here...",
                    Style::default().fg(Color::DarkGray),
                ),
            ])
        } else {
            Line::from(vec![
                Span::styled("> ", Style::default().fg(Color::White)),
                Span::styled(
                    input_key,
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                ),
                Span::styled("█", Style::default().fg(Color::White)),
            ])
        };
        f.render_widget(Paragraph::new(input_display).block(input_box), inner_chunks[3]);

        // Error message if any
        if let Some(err) = error_msg {
            let err_line = Line::from(vec![
                Span::styled("✖ ", Style::default().fg(Color::Red)),
                Span::styled(err, Style::default().fg(Color::Red)),
            ]);
            f.render_widget(Paragraph::new(err_line), inner_chunks[4]);
        }

        // Footer Hotkeys
        let footer = Line::from(vec![
            Span::styled("[Enter]", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled(" Save & Authenticate  │  ", Style::default().fg(Color::DarkGray)),
            Span::styled("[Tab]", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled(" Switch Provider  │  ", Style::default().fg(Color::DarkGray)),
            Span::styled("[Esc]", Style::default().fg(Color::White)),
            Span::styled(" Cancel", Style::default().fg(Color::DarkGray)),
        ]);
        f.render_widget(Paragraph::new(footer), inner_chunks[6]);
    }
}

