use crate::types::{Severity, VulnerabilityFinding};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

pub struct MatrixView;

impl MatrixView {
    pub fn render(
        f: &mut Frame,
        area: Rect,
        findings: &[VulnerabilityFinding],
        selected_index: usize,
    ) -> Rect {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(8),
                Constraint::Length(7),
            ])
            .split(area);

        // 1. Findings Table
        let rows = findings.iter().enumerate().map(|(i, item)| {
            let is_selected = i == selected_index;
            let (sev_str, is_bold) = match item.severity {
                Severity::Critical => ("crit", true),
                Severity::High => ("high", true),
                Severity::Medium => ("med", false),
                Severity::Low => ("low", false),
                Severity::Info => ("info", false),
            };

            let patch_badge = if item.patched {
                Span::styled("patched", Style::default().fg(Color::DarkGray))
            } else {
                Span::styled("unpatched", Style::default().fg(Color::White).add_modifier(Modifier::BOLD))
            };

            let row_style = if is_selected {
                Style::default().bg(Color::Rgb(35, 35, 35)).fg(Color::White)
            } else {
                Style::default().fg(Color::Gray)
            };

            let prefix = if is_selected { "> " } else { "  " };

            Row::new(vec![
                Cell::from(format!("{}{}", prefix, item.id)).style(if is_selected { Style::default().fg(Color::White).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::DarkGray) }),
                Cell::from(sev_str).style(if is_bold { Style::default().fg(Color::White).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::DarkGray) }),
                Cell::from(item.cwe.clone()).style(Style::default().fg(Color::Gray)),
                Cell::from(format!("{}:{}", item.file_path.display(), item.line_number)).style(Style::default().fg(Color::White)),
                Cell::from(item.title.clone()),
                Cell::from(patch_badge),
            ]).style(row_style)
        });

        let header = Row::new(vec![
            Cell::from("  id").style(Style::default().fg(Color::DarkGray)),
            Cell::from("severity").style(Style::default().fg(Color::DarkGray)),
            Cell::from("cwe").style(Style::default().fg(Color::DarkGray)),
            Cell::from("location").style(Style::default().fg(Color::DarkGray)),
            Cell::from("summary").style(Style::default().fg(Color::DarkGray)),
            Cell::from("status").style(Style::default().fg(Color::DarkGray)),
        ])
        .height(1);

        let widths = [
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(28),
            Constraint::Min(30),
            Constraint::Length(12),
        ];

        let table_block = Block::default().borders(Borders::NONE);

        let table = Table::new(rows, widths)
            .header(header)
            .block(table_block);

        f.render_widget(table, chunks[0]);

        // 2. Selected Vulnerability Detail Panel
        let detail_block = Block::default()
            .borders(Borders::TOP)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::DarkGray));

        let detail_content = if let Some(selected) = findings.get(selected_index) {
            vec![
                Line::from(vec![
                    Span::styled("description: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&selected.description, Style::default().fg(Color::White)),
                ]),
                Line::from(vec![
                    Span::styled("code:        ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&selected.snippet, Style::default().fg(Color::White)),
                ]),
                Line::from(vec![
                    Span::styled("remediation: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&selected.recommendation, Style::default().fg(Color::Gray)),
                ]),
                Line::from(vec![
                    Span::styled("click:       ", Style::default().fg(Color::DarkGray)),
                    Span::styled("click any row to inspect  │  switch to tab 3 to review diff  │  [a] apply patch", Style::default().fg(Color::DarkGray)),
                ]),
            ]
        } else {
            vec![Line::from(Span::styled("no vulnerability selected.", Style::default().fg(Color::DarkGray)))]
        };

        f.render_widget(Paragraph::new(detail_content).block(detail_block), chunks[1]);

        chunks[0]
    }
}
