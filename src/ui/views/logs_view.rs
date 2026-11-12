use crate::types::DynamicLogEntry;
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

pub struct LogsView;

impl LogsView {
    pub fn render(f: &mut Frame, area: Rect, logs: &[DynamicLogEntry], scroll_offset: usize) {
        let block = Block::default()
            .borders(Borders::NONE);

        let mut lines = Vec::new();
        for entry in logs.iter().skip(scroll_offset) {
            let level_badge = match entry.level.as_str() {
                "EXEC" => "exec",
                "FINDING" => "finding",
                "ALERT" => "alert",
                "SUCCESS" => "done",
                "IMPROVISE" => "adapt",
                "WARN" => "warn",
                _ => "info",
            };

            let agent_badge = format!("[{}]", entry.agent_name.to_lowercase());
            let time_str = entry.timestamp.format("%H:%M:%S").to_string();

            let mut spans = vec![
                Span::raw("  "),
                Span::styled(format!("{time_str}  "), Style::default().fg(Color::Rgb(110, 112, 120))),
                Span::styled(format!("{agent_badge:<16} "), Style::default().fg(Color::White)),
                Span::styled(format!("{level_badge:<8} "), Style::default().fg(Color::Rgb(130, 132, 142))),
            ];

            if entry.is_improvisation {
                spans.push(Span::styled(&entry.message, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)));
            } else {
                spans.push(Span::styled(&entry.message, Style::default().fg(Color::Rgb(180, 182, 192))));
            }

            lines.push(Line::from(spans));
        }

        if lines.is_empty() {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled("awaiting execution dispatch. press [space] to run audit harness.", Style::default().fg(Color::Rgb(120, 122, 130))),
            ]));
        }

        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(block), area);
    }
}
