use crate::ui::theme::th;
use crate::types::DynamicLogEntry;
use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Paragraph, Wrap},
    Frame,
};

pub struct LogsView;

impl LogsView {
    pub fn render(f: &mut Frame, area: Rect, logs: &[DynamicLogEntry], scroll_offset: usize) {
        if logs.is_empty() {
            let empty_block = Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(th().element))
                .style(Style::default().bg(th().surface));
            let inner = empty_block.inner(area);
            f.render_widget(empty_block, area);

            let empty_card = vec![
                Line::raw(""),
                Line::from(vec![
                    Span::styled("   📋 Execution Event Log Idle", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                    Span::raw("   "),
                    Span::styled(" ● IDLE ", Style::default().fg(th().text_muted).bg(th().element)),
                ]),
                Line::raw(""),
                Line::from(vec![
                    Span::styled("   Real-time multi-agent orchestrator dispatches and tool traces will stream here.", Style::default().fg(th().fg)),
                ]),
                Line::from(vec![
                    Span::styled("   Logs provide granular verification timelines for all subagents and AST flows.", Style::default().fg(th().text_sub)),
                ]),
                Line::raw(""),
                Line::from(vec![
                    Span::styled("   Next steps:", Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(vec![
                    Span::styled("   • Run ", Style::default().fg(th().text_sub)),
                    Span::styled("/scan", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                    Span::styled(" or press ", Style::default().fg(th().text_sub)),
                    Span::styled("[Space]", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                    Span::styled(" to launch multi-agent triage execution.", Style::default().fg(th().text_sub)),
                ]),
            ];
            f.render_widget(Paragraph::new(empty_card), inner);
            return;
        }

        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(th().border))
            .title(Line::from(vec![
                Span::styled(" 📋 Execution Event Stream ", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                Span::styled(format!("({} events) ", logs.len()), Style::default().fg(th().text_muted)),
            ]))
            .title_bottom(Line::from(vec![
                Span::styled(" [PgUp/PgDn] ", Style::default().fg(th().text_sub).add_modifier(Modifier::BOLD)),
                Span::styled("Scroll  •  ", Style::default().fg(th().text_dim)),
                Span::styled("[Space] ", Style::default().fg(th().text_sub).add_modifier(Modifier::BOLD)),
                Span::styled("Run Audit  •  ", Style::default().fg(th().text_dim)),
                Span::styled("[Esc] ", Style::default().fg(th().text_sub).add_modifier(Modifier::BOLD)),
                Span::styled("Exit ", Style::default().fg(th().text_dim)),
            ]))
            .style(Style::default().bg(th().surface));

        let inner = block.inner(area);
        f.render_widget(block, area);

        let mut lines = Vec::new();
        for entry in logs.iter().skip(scroll_offset) {
            let (level_badge, level_style) = match entry.level.as_str() {
                "EXEC" => ("⚡ EXEC", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                "FINDING" | "ALERT" => ("✕ VULN", Style::default().fg(th().destructive).add_modifier(Modifier::BOLD)),
                "SUCCESS" => ("✓ DONE", Style::default().fg(th().success).add_modifier(Modifier::BOLD)),
                "IMPROVISE" => ("⌥ ADAPT", Style::default().fg(th().warning).add_modifier(Modifier::BOLD)),
                "WARN" => ("⚠ WARN", Style::default().fg(th().warning)),
                _ => ("ℹ INFO", Style::default().fg(th().text_muted)),
            };

            let time_str = entry.timestamp.format("%H:%M:%S").to_string();

            let mut spans = vec![
                Span::raw(" "),
                Span::styled(format!("{time_str} "), Style::default().fg(th().text_dim)),
                Span::styled(format!(" {:<8} ", level_badge), level_style),
                Span::styled(format!(" {:<14} ", entry.agent_name.to_lowercase()), Style::default().fg(th().fg).bg(th().element)),
                Span::raw(" "),
            ];

            if entry.is_improvisation {
                spans.push(Span::styled(&entry.message, Style::default().fg(th().fg).add_modifier(Modifier::BOLD)));
            } else {
                spans.push(Span::styled(&entry.message, Style::default().fg(th().text_sub)));
            }

            lines.push(Line::from(spans));
        }

        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }
}
