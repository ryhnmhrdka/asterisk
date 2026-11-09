use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
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
    ) -> WelcomeClickTargets {
        // Fill entire screen with deep sleek dark background
        let bg_block = Block::default().style(Style::default().bg(Color::Rgb(10, 10, 10)));
        f.render_widget(bg_block, area);

        // Vertical split: Top spacer, ASCII title, spacing, prompt box, helper hint, bottom spacer, footer bar
        let v_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(area.height.saturating_sub(20) / 2), // Top margin
                Constraint::Length(5),                                 // ASCII Title
                Constraint::Length(2),                                 // Gap
                Constraint::Length(4),                                 // Centered Prompt Box
                Constraint::Length(2),                                 // Helper Hint below box
                Constraint::Min(2),                                    // Bottom fill
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

        // 2. Centered Prompt Box
        let box_width = 72.min(area.width.saturating_sub(6));
        let h_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length((area.width.saturating_sub(box_width)) / 2),
                Constraint::Length(box_width),
                Constraint::Min(1),
            ])
            .split(v_chunks[3]);

        let prompt_box_rect = h_chunks[1];

        // Clear and draw background for prompt box (#1c1c1e / Rgb(28, 28, 30))
        f.render_widget(Clear, prompt_box_rect);
        let box_bg = Block::default().style(Style::default().bg(Color::Rgb(26, 26, 28)));
        f.render_widget(box_bg, prompt_box_rect);

        // Content inside prompt box
        let prompt_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // Top padding / Input line
                Constraint::Length(1), // Gap
                Constraint::Length(1), // Mode & Model badges
                Constraint::Min(0),
            ])
            .split(prompt_box_rect);

        // Input Line with accent indicator bar on the left
        let mut input_spans = vec![
            Span::styled("▎ ", Style::default().fg(Color::Rgb(75, 145, 245)).bg(Color::Rgb(26, 26, 28))),
        ];

        if input_text.is_empty() {
            input_spans.push(Span::styled(
                "Ask anything... \"What is the tech stack of this project?\"",
                Style::default().fg(Color::Rgb(120, 120, 125)).bg(Color::Rgb(26, 26, 28)),
            ));
            input_spans.push(Span::styled("█", Style::default().fg(Color::Rgb(220, 220, 220)).bg(Color::Rgb(26, 26, 28))));
        } else {
            input_spans.push(Span::styled(
                input_text,
                Style::default().fg(Color::White).bg(Color::Rgb(26, 26, 28)).add_modifier(Modifier::BOLD),
            ));
            input_spans.push(Span::styled("█", Style::default().fg(Color::Rgb(220, 220, 220)).bg(Color::Rgb(26, 26, 28))));
        }

        f.render_widget(Paragraph::new(Line::from(input_spans)), prompt_chunks[0]);

        // Badges Line (Build, Claude-4.5-Opus, Evolink)
        let badge_spans = vec![
            Span::styled("▎ ", Style::default().fg(Color::Rgb(75, 145, 245)).bg(Color::Rgb(26, 26, 28))),
            Span::styled("Build  ", Style::default().fg(Color::Rgb(85, 155, 255)).bg(Color::Rgb(26, 26, 28))),
            Span::styled("Claude-4.5-Opus  ", Style::default().fg(Color::White).bg(Color::Rgb(26, 26, 28)).add_modifier(Modifier::BOLD)),
            Span::styled("Evolink", Style::default().fg(Color::Rgb(110, 110, 115)).bg(Color::Rgb(26, 26, 28))),
        ];
        f.render_widget(Paragraph::new(Line::from(badge_spans)), prompt_chunks[2]);

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
            Span::styled("tab", Style::default().fg(Color::Rgb(200, 200, 200)).add_modifier(Modifier::BOLD)),
            Span::styled(" switch agent   ", Style::default().fg(Color::Rgb(100, 100, 105))),
            Span::styled("ctrl+p", Style::default().fg(Color::Rgb(200, 200, 200)).add_modifier(Modifier::BOLD)),
            Span::styled(" commands   ", Style::default().fg(Color::Rgb(100, 100, 105))),
            Span::styled("enter", Style::default().fg(Color::Rgb(200, 200, 200)).add_modifier(Modifier::BOLD)),
            Span::styled(" execute", Style::default().fg(Color::Rgb(100, 100, 105))),
        ]);
        f.render_widget(Paragraph::new(hint_line).alignment(Alignment::Right), hint_chunks[1]);

        // 4. Bottom status bar (Directory on Left, Version on Right)
        let bottom_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(area.width.saturating_sub(15)),
                Constraint::Length(15),
            ])
            .split(v_chunks[6]);

        let dir_display = if target_path.is_empty() {
            "constellation"
        } else {
            target_path
        };

        f.render_widget(
            Paragraph::new(Span::styled(
                format!(" {dir_display}"),
                Style::default().fg(Color::Rgb(95, 95, 100)),
            )),
            bottom_chunks[0],
        );

        f.render_widget(
            Paragraph::new(Span::styled(
                "1.0.152 ",
                Style::default().fg(Color::Rgb(95, 95, 100)),
            ))
            .alignment(Alignment::Right),
            bottom_chunks[1],
        );

        WelcomeClickTargets {
            prompt_box: prompt_box_rect,
        }
    }
}
