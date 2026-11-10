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
            let (sev_str, sev_color) = match item.severity {
                Severity::Critical => ("CRIT", Color::Rgb(240, 90, 90)),
                Severity::High => ("HIGH", Color::Rgb(230, 140, 60)),
                Severity::Medium => ("MED", Color::Rgb(220, 190, 70)),
                Severity::Low => ("LOW", Color::Rgb(100, 170, 240)),
                Severity::Info => ("INFO", Color::Rgb(140, 150, 170)),
            };

            let patch_badge = if item.patched {
                Span::styled("● patched", Style::default().fg(Color::Rgb(100, 200, 130)))
            } else {
                Span::styled("● open", Style::default().fg(Color::Rgb(235, 95, 95)).add_modifier(Modifier::BOLD))
            };

            let row_style = if is_selected {
                Style::default().bg(Color::Rgb(28, 30, 38)).fg(Color::White)
            } else {
                Style::default().fg(Color::Rgb(180, 185, 195))
            };

            let prefix = if is_selected { "▸ " } else { "  " };

            Row::new(vec![
                Cell::from(format!("{}{}", prefix, item.id)).style(if is_selected { Style::default().fg(Color::White).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Rgb(130, 135, 150)) }),
                Cell::from(sev_str).style(Style::default().fg(sev_color).add_modifier(Modifier::BOLD)),
                Cell::from(item.cwe.clone()).style(Style::default().fg(Color::Rgb(150, 155, 170))),
                Cell::from(format!("{}:{}", item.file_path.display(), item.line_number)).style(Style::default().fg(Color::Rgb(210, 215, 225))),
                Cell::from(item.title.clone()),
                Cell::from(patch_badge),
            ]).style(row_style)
        });

        let header = Row::new(vec![
            Cell::from("  FINDING ID").style(Style::default().fg(Color::Rgb(140, 145, 160)).add_modifier(Modifier::BOLD)),
            Cell::from("SEVERITY").style(Style::default().fg(Color::Rgb(140, 145, 160)).add_modifier(Modifier::BOLD)),
            Cell::from("CWE").style(Style::default().fg(Color::Rgb(140, 145, 160)).add_modifier(Modifier::BOLD)),
            Cell::from("LOCATION").style(Style::default().fg(Color::Rgb(140, 145, 160)).add_modifier(Modifier::BOLD)),
            Cell::from("SUMMARY").style(Style::default().fg(Color::Rgb(140, 145, 160)).add_modifier(Modifier::BOLD)),
            Cell::from("STATUS").style(Style::default().fg(Color::Rgb(140, 145, 160)).add_modifier(Modifier::BOLD)),
        ])
        .height(1)
        .style(Style::default().bg(Color::Rgb(20, 21, 27)));

        let widths = [
            Constraint::Length(14),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(28),
            Constraint::Min(30),
            Constraint::Length(12),
        ];

        let table_block = Block::default()
            .borders(Borders::NONE)
            .style(Style::default().bg(Color::Rgb(14, 15, 19)));

        let table = Table::new(rows, widths)
            .header(header)
            .block(table_block);

        f.render_widget(table, chunks[0]);

        // 2. Selected Vulnerability Detail Panel
        let detail_block = Block::default()
            .borders(Borders::TOP)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::Rgb(28, 29, 36)))
            .style(Style::default().bg(Color::Rgb(16, 17, 22)));

        let detail_content = if let Some(selected) = findings.get(selected_index) {
            vec![
                Line::from(vec![
                    Span::styled(" description  ", Style::default().fg(Color::Rgb(140, 145, 160)).bg(Color::Rgb(24, 25, 32))),
                    Span::raw(" "),
                    Span::styled(&selected.description, Style::default().fg(Color::White)),
                ]),
                Line::from(vec![
                    Span::styled(" code         ", Style::default().fg(Color::Rgb(140, 145, 160)).bg(Color::Rgb(24, 25, 32))),
                    Span::raw(" "),
                    Span::styled(&selected.snippet, Style::default().fg(Color::Rgb(215, 220, 230))),
                ]),
                Line::from(vec![
                    Span::styled(" remediation  ", Style::default().fg(Color::Rgb(140, 145, 160)).bg(Color::Rgb(24, 25, 32))),
                    Span::raw(" "),
                    Span::styled(&selected.recommendation, Style::default().fg(Color::Rgb(170, 175, 190))),
                ]),
                Line::from(vec![
                    Span::styled(" shortcuts    ", Style::default().fg(Color::Rgb(120, 125, 140)).bg(Color::Rgb(20, 21, 27))),
                    Span::raw(" "),
                    Span::styled("click row to inspect  •  tab [3] review diff  •  [a] apply patch", Style::default().fg(Color::Rgb(120, 125, 140))),
                ]),
            ]
        } else {
            vec![Line::from(Span::styled(" no vulnerabilities identified  •  workspace clean or press [space] to run defense audit.", Style::default().fg(Color::Rgb(120, 125, 140))))]
        };

        f.render_widget(Paragraph::new(detail_content).block(detail_block), chunks[1]);

        chunks[0]
    }
}
