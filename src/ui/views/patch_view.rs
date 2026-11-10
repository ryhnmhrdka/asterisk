use crate::types::HardeningPatch;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame,
};

pub struct PatchClickTargets {
    pub list_area: Rect,
    pub btn_apply: Option<Rect>,
    pub btn_rollback: Option<Rect>,
}

pub struct PatchView;

impl PatchView {
    pub fn render(
        f: &mut Frame,
        area: Rect,
        patches: &[HardeningPatch],
        selected_index: usize,
        action_msg: &Option<String>,
    ) -> PatchClickTargets {
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
                Span::styled("● applied", Style::default().fg(Color::Rgb(100, 200, 130)))
            } else {
                Span::styled("● pending", Style::default().fg(Color::Rgb(230, 140, 60)).add_modifier(Modifier::BOLD))
            };

            let prefix = if is_sel { "▸ " } else { "  " };
            let line_style = if is_sel {
                Style::default().bg(Color::Rgb(28, 30, 40)).fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Rgb(180, 185, 195))
            };

            list_lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(format!("{}{}. ", prefix, i + 1), Style::default().fg(Color::Rgb(120, 125, 140))),
                status_badge,
                Span::raw(" "),
                Span::styled(&patch.id, line_style),
            ]));

            list_lines.push(Line::from(vec![
                Span::raw("        "),
                Span::styled(
                    patch.target_file.file_name().map(|n| n.to_string_lossy()).unwrap_or_default(),
                    Style::default().fg(Color::Rgb(120, 125, 140)),
                ),
            ]));
            list_lines.push(Line::raw(""));
        }

        if patches.is_empty() {
            list_lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled("no hardening patches pending.", Style::default().fg(Color::Rgb(120, 125, 140))),
            ]));
        }

        let list_block = Block::default()
            .borders(Borders::RIGHT)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::Rgb(28, 29, 36)))
            .style(Style::default().bg(Color::Rgb(16, 17, 22)));

        f.render_widget(Paragraph::new(list_lines).block(list_block), chunks[0]);

        // Right Panel: Action Buttons + Diff Viewer + Unit Test Viewer
        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Percentage(52),
                Constraint::Percentage(48),
            ])
            .split(chunks[1]);

        // Top Action Bar with Clickable Buttons
        let action_bar_area = right_chunks[0];
        let mut btn_apply = None;
        let mut btn_rollback = None;

        if patches.is_empty() {
            let empty_text = Line::from(vec![
                Span::raw("  "),
                Span::styled("no hardening patches pending  •  codebase is clean or no patches synthesized", Style::default().fg(Color::Rgb(120, 125, 140))),
            ]);
            f.render_widget(Paragraph::new(empty_text).block(Block::default().style(Style::default().bg(Color::Rgb(14, 15, 19)))), action_bar_area);
        } else {
            let action_split = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Length(2),  // Left margin
                    Constraint::Length(20), // Apply button
                    Constraint::Length(1),  // Spacer
                    Constraint::Length(16), // Rollback button
                    Constraint::Length(2),  // Spacer
                    Constraint::Min(10),    // Status text
                ])
                .split(action_bar_area);

            let apply_rect = action_split[1];
            let rollback_rect = action_split[3];
            let msg_rect = action_split[5];

            let apply_block = Block::default()
                .borders(Borders::NONE)
                .style(Style::default().bg(Color::Rgb(240, 240, 245)));
            let apply_text = Line::from(Span::styled(" ✓ Apply to Disk ", Style::default().fg(Color::Black).bg(Color::Rgb(240, 240, 245)).add_modifier(Modifier::BOLD)));
            f.render_widget(Paragraph::new(apply_text).centered().block(apply_block), apply_rect);

            let roll_block = Block::default()
                .borders(Borders::NONE)
                .style(Style::default().bg(Color::Rgb(28, 30, 38)));
            let roll_text = Line::from(Span::styled(" ↩ Rollback ", Style::default().fg(Color::Rgb(170, 175, 190)).bg(Color::Rgb(28, 30, 38))));
            f.render_widget(Paragraph::new(roll_text).centered().block(roll_block), rollback_rect);

            let status_text = if let Some(msg) = action_msg {
                Line::from(vec![
                    Span::styled("status: ", Style::default().fg(Color::Rgb(120, 125, 140))),
                    Span::styled(msg, Style::default().fg(Color::White)),
                ])
            } else {
                Line::from(vec![
                    Span::styled("click buttons or press [a] / [r]", Style::default().fg(Color::Rgb(120, 125, 140))),
                ])
            };
            f.render_widget(Paragraph::new(status_text).block(Block::default().style(Style::default().bg(Color::Rgb(14, 15, 19)))), msg_rect);

            btn_apply = Some(apply_rect);
            btn_rollback = Some(rollback_rect);
        }

        // Diff Viewer
        let diff_block = Block::default()
            .borders(Borders::TOP)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::Rgb(28, 29, 36)))
            .style(Style::default().bg(Color::Rgb(14, 15, 19)));

        let diff_lines = if let Some(patch) = patches.get(selected_index) {
            let mut lines = Vec::new();
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(" file: ", Style::default().fg(Color::Rgb(140, 145, 160)).bg(Color::Rgb(24, 25, 32))),
                Span::raw("  "),
                Span::styled(patch.target_file.display().to_string(), Style::default().fg(Color::White)),
            ]));
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(" diff: ", Style::default().fg(Color::Rgb(140, 145, 160)).bg(Color::Rgb(24, 25, 32))),
                Span::raw("  "),
                Span::styled(&patch.explanation, Style::default().fg(Color::Rgb(170, 175, 190))),
            ]));
            lines.push(Line::raw(""));

            for line in patch.unified_diff.lines() {
                let prefix_span = Span::raw("  ");
                if line.starts_with('+') && !line.starts_with("+++") {
                    lines.push(Line::from(vec![prefix_span, Span::styled(line, Style::default().fg(Color::Rgb(120, 220, 140)).add_modifier(Modifier::BOLD))]));
                } else if line.starts_with('-') && !line.starts_with("---") {
                    lines.push(Line::from(vec![prefix_span, Span::styled(line, Style::default().fg(Color::Rgb(230, 100, 100)))]));
                } else if line.starts_with("---") || line.starts_with("+++") {
                    lines.push(Line::from(vec![prefix_span, Span::styled(line, Style::default().fg(Color::Rgb(120, 125, 140)))]));
                } else {
                    lines.push(Line::from(vec![prefix_span, Span::styled(line, Style::default().fg(Color::Rgb(150, 155, 170)))]));
                }
            }
            lines
        } else {
            vec![Line::from(vec![
                Span::raw("  "),
                Span::styled("no remediation patches available • workspace clean or run defense audit.", Style::default().fg(Color::Rgb(120, 125, 140))),
            ])]
        };

        f.render_widget(Paragraph::new(diff_lines).block(diff_block), right_chunks[1]);

        // Automated Unit Test Code Block
        let test_block = Block::default()
            .borders(Borders::TOP)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::Rgb(28, 29, 36)))
            .style(Style::default().bg(Color::Rgb(12, 13, 16)));

        let test_lines = if let Some(patch) = patches.get(selected_index) {
            let mut lines = Vec::new();
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled("// automated security verification unit test", Style::default().fg(Color::Rgb(100, 105, 120))),
            ]));
            for l in patch.unit_test_code.lines() {
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(l, Style::default().fg(Color::Rgb(180, 185, 200))),
                ]));
            }
            lines
        } else {
            vec![Line::from(vec![
                Span::raw("  "),
                Span::styled("no remediation test harness • workspace clean or run defense audit.", Style::default().fg(Color::Rgb(120, 125, 140))),
            ])]
        };

        f.render_widget(Paragraph::new(test_lines).block(test_block), right_chunks[2]);

        PatchClickTargets {
            list_area: chunks[0],
            btn_apply,
            btn_rollback,
        }
    }
}
