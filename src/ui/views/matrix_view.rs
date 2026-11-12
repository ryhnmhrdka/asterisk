use crate::types::{Severity, VulnerabilityFinding};
use crate::ui::fit::{ellipsize, ellipsize_start};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table, Wrap},
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
                Constraint::Length(9),
            ])
            .split(area);

        // 1. Findings Table (cells are ellipsized to their exact column width)
        let fixed_cols: usize = 13 + 9 + 9 + 13 + 24 + 11 + 6;
        let summary_w = (area.width as usize).saturating_sub(fixed_cols).max(24);
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

            let (reach_label, reach_color) = match item.reachability.as_str() {
                "REACHABLE" => ("REACHABLE", Color::Rgb(240, 100, 100)),
                "UNREACHABLE" => ("UNREACHABLE", Color::Rgb(120, 190, 140)),
                _ => ("POTENTIAL", Color::Rgb(220, 185, 90)),
            };

            let row_style = if is_selected {
                Style::default().bg(Color::Rgb(28, 30, 38)).fg(Color::White)
            } else {
                Style::default().fg(Color::Rgb(180, 185, 195))
            };

            let prefix = if is_selected { "▸ " } else { "  " };

            Row::new(vec![
                Cell::from(ellipsize(&format!("{}{}", prefix, item.id), 13)).style(if is_selected { Style::default().fg(Color::White).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Rgb(130, 135, 150)) }),
                Cell::from(sev_str).style(Style::default().fg(sev_color).add_modifier(Modifier::BOLD)),
                Cell::from(ellipsize(&item.cwe, 9)).style(Style::default().fg(Color::Rgb(150, 155, 170))),
                Cell::from(reach_label).style(Style::default().fg(reach_color).add_modifier(Modifier::BOLD)),
                Cell::from(ellipsize_start(&format!("{}:{}", item.file_path.display(), item.line_number), 24)).style(Style::default().fg(Color::Rgb(210, 215, 225))),
                Cell::from(ellipsize(&item.title, summary_w)),
                Cell::from(patch_badge),
            ]).style(row_style)
        });

        let header = Row::new(vec![
            Cell::from("  FINDING ID").style(Style::default().fg(Color::Rgb(140, 145, 160)).add_modifier(Modifier::BOLD)),
            Cell::from("SEVERITY").style(Style::default().fg(Color::Rgb(140, 145, 160)).add_modifier(Modifier::BOLD)),
            Cell::from("CWE").style(Style::default().fg(Color::Rgb(140, 145, 160)).add_modifier(Modifier::BOLD)),
            Cell::from("REACHABILITY").style(Style::default().fg(Color::Rgb(140, 145, 160)).add_modifier(Modifier::BOLD)),
            Cell::from("LOCATION").style(Style::default().fg(Color::Rgb(140, 145, 160)).add_modifier(Modifier::BOLD)),
            Cell::from("SUMMARY").style(Style::default().fg(Color::Rgb(140, 145, 160)).add_modifier(Modifier::BOLD)),
            Cell::from("STATUS").style(Style::default().fg(Color::Rgb(140, 145, 160)).add_modifier(Modifier::BOLD)),
        ])
        .height(1)
        .style(Style::default().bg(Color::Rgb(20, 21, 27)));

        let widths = [
            Constraint::Length(13),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(13),
            Constraint::Length(24),
            Constraint::Min(24),
            Constraint::Length(11),
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
            let call_chain = if selected.call_path.is_empty() {
                String::new()
            } else {
                format!("  •  path: {}", selected.call_path.join(" ➔ "))
            };
            let reasoning = if selected.triage_reasoning.is_empty() {
                "Static signature & AST taint evaluation.".to_string()
            } else {
                selected.triage_reasoning.clone()
            };
            vec![
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled(" description ", Style::default().fg(Color::Rgb(140, 145, 160)).bg(Color::Rgb(24, 25, 32))),
                    Span::raw("  "),
                    Span::styled(&selected.description, Style::default().fg(Color::White)),
                ]),
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled(" triage      ", Style::default().fg(Color::Rgb(140, 145, 160)).bg(Color::Rgb(24, 25, 32))),
                    Span::raw("  "),
                    Span::styled(
                        format!("[{} | {}] ", selected.triage_verdict, selected.reachability),
                        Style::default().fg(Color::Rgb(140, 200, 255)).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(reasoning, Style::default().fg(Color::Rgb(195, 200, 215))),
                    Span::styled(call_chain, Style::default().fg(Color::Rgb(150, 155, 170))),
                ]),
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled(" code        ", Style::default().fg(Color::Rgb(140, 145, 160)).bg(Color::Rgb(24, 25, 32))),
                    Span::raw("  "),
                    Span::styled(&selected.snippet, Style::default().fg(Color::Rgb(215, 220, 230))),
                ]),
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled(" remediation ", Style::default().fg(Color::Rgb(140, 145, 160)).bg(Color::Rgb(24, 25, 32))),
                    Span::raw("  "),
                    Span::styled(&selected.recommendation, Style::default().fg(Color::Rgb(170, 175, 190))),
                ]),
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled(" shortcuts   ", Style::default().fg(Color::Rgb(120, 125, 140)).bg(Color::Rgb(20, 21, 27))),
                    Span::raw("  "),
                    Span::styled("click row: inspect  •  [Alt+3] review diff  •  [Ctrl+A] or [/patch]: apply", Style::default().fg(Color::Rgb(120, 125, 140))),
                ]),
            ]
        } else {
            vec![Line::from(vec![
                Span::raw("  "),
                Span::styled("no vulnerabilities identified  •  workspace clean or press [space] to run defense audit.", Style::default().fg(Color::Rgb(120, 125, 140))),
            ])]
        };

        f.render_widget(Paragraph::new(detail_content).wrap(Wrap { trim: false }).block(detail_block), chunks[1]);

        chunks[0]
    }
}
