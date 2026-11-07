use crate::types::HardeningPatch;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame,
};

pub struct PatchView;

impl PatchView {
    pub fn render(
        f: &mut Frame,
        area: Rect,
        patches: &[HardeningPatch],
        selected_index: usize,
        action_msg: &Option<String>,
    ) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(28),
                Constraint::Percentage(72),
            ])
            .split(area);

        // Left Panel: Patch List
        let mut list_lines = Vec::new();
        for (i, patch) in patches.iter().enumerate() {
            let is_sel = i == selected_index;
            let status_badge = if patch.applied {
                Span::styled("[applied]", Style::default().fg(Color::DarkGray))
            } else {
                Span::styled("[pending]", Style::default().fg(Color::White).add_modifier(Modifier::BOLD))
            };

            let prefix = if is_sel { "> " } else { "  " };
            let line_style = if is_sel {
                Style::default().bg(Color::Rgb(35, 35, 35)).fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };

            list_lines.push(Line::from(vec![
                Span::styled(format!("{}{}. ", prefix, i + 1), Style::default().fg(Color::DarkGray)),
                status_badge,
                Span::raw(" "),
                Span::styled(&patch.id, line_style),
            ]));

            list_lines.push(Line::from(vec![
                Span::raw("     "),
                Span::styled(
                    patch.target_file.file_name().map(|n| n.to_string_lossy()).unwrap_or_default(),
                    Style::default().fg(Color::DarkGray),
                ),
            ]));
            list_lines.push(Line::raw(""));
        }

        if patches.is_empty() {
            list_lines.push(Line::from(Span::styled("no hardening patches pending.", Style::default().fg(Color::DarkGray))));
        }

        let list_block = Block::default()
            .borders(Borders::RIGHT)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::DarkGray));

        f.render_widget(Paragraph::new(list_lines).block(list_block), chunks[0]);

        // Right Panel: Diff Viewer + Unit Test Viewer
        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),
                Constraint::Percentage(52),
                Constraint::Percentage(48),
            ])
            .split(chunks[1]);

        // Action Status Bar
        let status_text = if let Some(msg) = action_msg {
            Line::from(vec![
                Span::styled("status: ", Style::default().fg(Color::DarkGray)),
                Span::styled(msg, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            ])
        } else {
            Line::from(vec![
                Span::styled("actions: ", Style::default().fg(Color::DarkGray)),
                Span::styled("[a] apply to disk  │  [r] rollback  │  [↑/↓] select patch", Style::default().fg(Color::Gray)),
            ])
        };

        f.render_widget(Paragraph::new(status_text), right_chunks[0]);

        // Diff Viewer
        let diff_block = Block::default()
            .borders(Borders::TOP)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::DarkGray));

        let diff_lines = if let Some(patch) = patches.get(selected_index) {
            let mut lines = Vec::new();
            lines.push(Line::from(vec![
                Span::styled("diff: ", Style::default().fg(Color::DarkGray)),
                Span::styled(patch.target_file.display().to_string(), Style::default().fg(Color::White)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("fix:  ", Style::default().fg(Color::DarkGray)),
                Span::styled(&patch.explanation, Style::default().fg(Color::Gray)),
            ]));
            lines.push(Line::raw(""));

            for line in patch.unified_diff.lines() {
                if line.starts_with('+') && !line.starts_with("+++") {
                    lines.push(Line::from(Span::styled(line, Style::default().fg(Color::White).add_modifier(Modifier::BOLD))));
                } else if line.starts_with('-') && !line.starts_with("---") {
                    lines.push(Line::from(Span::styled(line, Style::default().fg(Color::DarkGray))));
                } else if line.starts_with("---") || line.starts_with("+++") {
                    lines.push(Line::from(Span::styled(line, Style::default().fg(Color::Gray))));
                } else {
                    lines.push(Line::from(Span::styled(line, Style::default().fg(Color::DarkGray))));
                }
            }
            lines
        } else {
            vec![Line::from(Span::styled("select a patch from the left panel.", Style::default().fg(Color::DarkGray)))]
        };

        f.render_widget(Paragraph::new(diff_lines).block(diff_block), right_chunks[1]);

        // Automated Unit Test Code Block
        let test_block = Block::default()
            .borders(Borders::TOP)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::DarkGray));

        let test_lines = if let Some(patch) = patches.get(selected_index) {
            let mut lines = Vec::new();
            lines.push(Line::from(Span::styled("// automated security verification unit test", Style::default().fg(Color::DarkGray))));
            for l in patch.unit_test_code.lines() {
                lines.push(Line::from(Span::styled(l, Style::default().fg(Color::Gray))));
            }
            lines
        } else {
            vec![Line::from(Span::styled("no test harness available.", Style::default().fg(Color::DarkGray)))]
        };

        f.render_widget(Paragraph::new(test_lines).block(test_block), right_chunks[2]);
    }
}
