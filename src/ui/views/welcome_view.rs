use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

pub struct WelcomeView;

impl WelcomeView {
    pub fn render(f: &mut Frame, area: Rect, input_text: &str, default_path: &str) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(25),
                Constraint::Length(8),
                Constraint::Length(3),
                Constraint::Length(2),
                Constraint::Min(2),
            ])
            .split(area);

        // Minimalist monochrome ASCII logo
        let logo_lines = vec![
            Line::from(Span::styled(" _             _   _ _                                ", Style::default().fg(Color::White))),
            Line::from(Span::styled("| |____ _ _ __| |_(_) |____ _ __ _  _ _ __  ___ _ _   ", Style::default().fg(Color::White))),
            Line::from(Span::styled("| / / _` | '_ \\  _| | / / _` / _` || '_ \\/ -_) '_|  ", Style::default().fg(Color::White))),
            Line::from(Span::styled("|_\\_\\__,_| .__/\\__|_|_\\_\\__,_\\__,_(_) .__/\\___|_|    ", Style::default().fg(Color::White))),
            Line::from(Span::styled("         |_|                        |_|               ", Style::default().fg(Color::White))),
            Line::from(Span::styled("autonomous pre-production code defense harness", Style::default().fg(Color::DarkGray))),
        ];
        f.render_widget(Paragraph::new(logo_lines).centered(), chunks[1]);

        // Input prompt block
        let display_prompt = if input_text.is_empty() {
            vec![
                Span::styled("target directory: ", Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{default_path} "), Style::default().fg(Color::Gray)),
                Span::styled("█", Style::default().fg(Color::White)),
            ]
        } else {
            vec![
                Span::styled("target directory: ", Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{input_text} "), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                Span::styled("█", Style::default().fg(Color::White)),
            ]
        };

        f.render_widget(Paragraph::new(Line::from(display_prompt)).centered(), chunks[2]);

        // Hints
        let hint_line = Line::from(vec![
            Span::styled("press ", Style::default().fg(Color::DarkGray)),
            Span::styled("[enter]", Style::default().fg(Color::White)),
            Span::styled(" to start scanning  │  type target path  │  ", Style::default().fg(Color::DarkGray)),
            Span::styled("[q]", Style::default().fg(Color::White)),
            Span::styled(" to exit", Style::default().fg(Color::DarkGray)),
        ]);
        f.render_widget(Paragraph::new(hint_line).centered(), chunks[3]);
    }
}
