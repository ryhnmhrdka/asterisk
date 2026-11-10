#![allow(dead_code)]

use crate::types::AiProvider;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Wrap},
    Frame,
};

pub struct WelcomeClickTargets {
    pub prompt_box: Rect,
}

pub struct WelcomeView;

impl WelcomeView {
    pub fn render(
        f: &mut Frame,
        area: Rect,
        input_text: &str,
        target_path: &str,
        active_provider: AiProvider,
    ) -> WelcomeClickTargets {
        // Pure sleek deep black background
        let bg_block = Block::default().style(Style::default().bg(Color::Rgb(10, 10, 10)));
        f.render_widget(bg_block, area);

        // Vertical split: Top spacer, ASCII title, spacing, prompt box, helper hint, bottom spacer, footer bar
        let v_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(area.height.saturating_sub(18) / 2), // Top margin
                Constraint::Length(5),                                 // ASCII Title
                Constraint::Length(2),                                 // Gap
                Constraint::Length(5),                                 // Expandable Centered Prompt Box
                Constraint::Length(2),                                 // Helper Hint below box
                Constraint::Min(2),                                    // Fill space
                Constraint::Length(1),                                 // Bottom status bar
            ])
            .split(area);

        // 1. ASCII Art Title (from ascoo)
        let ascii_lines = [
            "██▀██ ██▀██ ▀▀██▀▀ ██▀██ ██▀██ ▀██▀ ██▀██ ██ ██",
            "██▄██ ██▄▄▄   ██   ██▄   ██▄█▀  ██  ██▄▄▄ ██▄█▀",
            "██ ██ ▄▄ ██   ██   ██ ▄▄ ██ ██  ██  ▄▄ ██ ██ ██",
            "▀▀ ▀▀ ▀▀▀▀▀   ▀▀   ▀▀▀▀▀ ▀▀ ▀▀ ▀▀▀▀ ▀▀▀▀▀ ▀▀ ▀▀",
        ];

        let title_spans: Vec<Line> = ascii_lines
            .iter()
            .map(|l| {
                Line::from(Span::styled(
                    *l,
                    Style::default().fg(Color::Rgb(240, 240, 240)).add_modifier(Modifier::BOLD),
                ))
            })
            .collect();

        f.render_widget(Paragraph::new(title_spans).alignment(Alignment::Center), v_chunks[1]);

        // 2. Centered Prompt Box (No border left, no model badges, wraps downwards)
        let box_width = 76.min(area.width.saturating_sub(6));
        let h_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length((area.width.saturating_sub(box_width)) / 2),
                Constraint::Length(box_width),
                Constraint::Min(1),
            ])
            .split(v_chunks[3]);

        let prompt_box_rect = h_chunks[1];

        // Background of prompt box (#1a1a1c, rounded padding feel)
        f.render_widget(Clear, prompt_box_rect);
        let box_bg = Block::default().style(Style::default().bg(Color::Rgb(24, 24, 27)));
        f.render_widget(box_bg, prompt_box_rect);

        // Render input text or placeholder
        if input_text.is_empty() {
            // Placeholder: NO cursor, NO white box
            let placeholder_line = Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    "Ask anything... \"Audit repository or binary for security vulnerabilities\"",
                    Style::default().fg(Color::Rgb(110, 110, 115)).bg(Color::Rgb(24, 24, 27)),
                ),
            ]);
            let p = Paragraph::new(vec![Line::raw(""), placeholder_line])
                .wrap(Wrap { trim: true });
            f.render_widget(p, prompt_box_rect);
        } else {
            // User has typed: wrap text downwards, cursor at the very end
            let inner_width = (box_width.saturating_sub(4)) as usize;
            let mut lines: Vec<Line> = Vec::new();
            lines.push(Line::raw(""));

            let wrapped_chunks = wrap_text(input_text, inner_width);
            let total_wrapped = wrapped_chunks.len();

            for (idx, line_str) in wrapped_chunks.into_iter().enumerate() {
                if idx == total_wrapped - 1 {
                    // Last line has the cursor indicator
                    lines.push(Line::from(vec![
                        Span::raw("  "),
                        Span::styled(
                            line_str,
                            Style::default().fg(Color::White).bg(Color::Rgb(24, 24, 27)).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled("█", Style::default().fg(Color::White).bg(Color::Rgb(24, 24, 27))),
                    ]));
                } else {
                    lines.push(Line::from(vec![
                        Span::raw("  "),
                        Span::styled(
                            line_str,
                            Style::default().fg(Color::White).bg(Color::Rgb(24, 24, 27)).add_modifier(Modifier::BOLD),
                        ),
                    ]));
                }
            }

            // Scroll if lines exceed available height
            let visible_lines = prompt_box_rect.height as usize;
            let scroll_offset = if lines.len() > visible_lines {
                (lines.len() - visible_lines) as u16
            } else {
                0
            };

            let p = Paragraph::new(lines).scroll((scroll_offset, 0));
            f.render_widget(p, prompt_box_rect);
        }

        // 3. Helper Hint right below the box
        let hint_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length((area.width.saturating_sub(box_width)) / 2),
                Constraint::Length(box_width),
                Constraint::Min(1),
            ])
            .split(v_chunks[4]);

        let hint_line = Line::from(vec![
            Span::styled("tab", Style::default().fg(Color::Rgb(180, 180, 185)).add_modifier(Modifier::BOLD)),
            Span::styled(" provider: ", Style::default().fg(Color::Rgb(100, 100, 105))),
            Span::styled(active_provider.name(), Style::default().fg(Color::Rgb(140, 190, 255))),
            Span::styled("   ctrl+p", Style::default().fg(Color::Rgb(180, 180, 185)).add_modifier(Modifier::BOLD)),
            Span::styled(" commands   ", Style::default().fg(Color::Rgb(100, 100, 105))),
            Span::styled("enter", Style::default().fg(Color::Rgb(180, 180, 185)).add_modifier(Modifier::BOLD)),
            Span::styled(" execute", Style::default().fg(Color::Rgb(100, 100, 105))),
        ]);
        f.render_widget(Paragraph::new(hint_line).alignment(Alignment::Right), hint_chunks[1]);

        // 4. Bottom status bar
        let bottom_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(area.width.saturating_sub(25)),
                Constraint::Length(25),
            ])
            .split(v_chunks[6]);

        let dir_display = if target_path.is_empty() {
            "."
        } else {
            target_path
        };

        f.render_widget(
            Paragraph::new(Span::styled(
                format!(" target: {dir_display}"),
                Style::default().fg(Color::Rgb(100, 100, 105)),
            )),
            bottom_chunks[0],
        );

        f.render_widget(
            Paragraph::new(Span::styled(
                "v0.1.0 │ production ",
                Style::default().fg(Color::Rgb(100, 100, 105)),
            ))
            .alignment(Alignment::Right),
            bottom_chunks[1],
        );

        WelcomeClickTargets {
            prompt_box: prompt_box_rect,
        }
    }
}

fn wrap_text(text: &str, max_width: usize) -> Vec<String> {
    if max_width == 0 {
        return vec![text.to_string()];
    }
    let mut lines = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= max_width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current);
            current = word.to_string();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}
