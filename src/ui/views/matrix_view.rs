use crate::ui::theme::th;
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
                Constraint::Percentage(45), // Findings Table
                Constraint::Percentage(55), // Finding Inspector
            ])
            .split(area);

        // 1. Findings Table (cells are ellipsized to their exact column width)
        let fixed_cols: usize = 13 + 9 + 9 + 13 + 24 + 11 + 6;
        let summary_w = (area.width as usize).saturating_sub(fixed_cols).max(24);
        let rows = findings.iter().enumerate().map(|(i, item)| {
            let is_selected = i == selected_index;
            let (sev_str, sev_color) = match item.severity {
                Severity::Critical => ("CRIT", th().destructive),
                Severity::High => ("HIGH", th().warning),
                Severity::Medium => ("MED", th().warning),
                Severity::Low => ("LOW", th().primary),
                Severity::Info => ("INFO", th().primary),
            };

            let patch_badge = if item.patched {
                Span::styled("● patched", Style::default().fg(th().success))
            } else {
                Span::styled("● open", Style::default().fg(th().destructive).add_modifier(Modifier::BOLD))
            };

            let (reach_label, reach_color) = match item.reachability.as_str() {
                "REACHABLE" => ("REACHABLE", th().destructive),
                "UNREACHABLE" => ("UNREACHABLE", th().success),
                _ => ("POTENTIAL", th().warning),
            };

            let row_style = if is_selected {
                Style::default().bg(th().element).fg(th().fg)
            } else {
                Style::default().fg(th().text_sub)
            };

            let prefix = if is_selected { "▸ " } else { "  " };

            Row::new(vec![
                Cell::from(ellipsize(&format!("{}{}", prefix, item.id), 13)).style(if is_selected { Style::default().fg(th().fg).add_modifier(Modifier::BOLD) } else { Style::default().fg(th().text_muted) }),
                Cell::from(sev_str).style(Style::default().fg(sev_color).add_modifier(Modifier::BOLD)),
                Cell::from(ellipsize(&item.cwe, 9)).style(Style::default().fg(th().text_sub)),
                Cell::from(reach_label).style(Style::default().fg(reach_color).add_modifier(Modifier::BOLD)),
                Cell::from(ellipsize_start(&format!("{}:{}", item.file_path.display(), item.line_number), 24)).style(Style::default().fg(th().text)),
                Cell::from(ellipsize(&item.title, summary_w)),
                Cell::from(patch_badge),
            ]).style(row_style)
        });

        let header = Row::new(vec![
            Cell::from("  FINDING ID").style(Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
            Cell::from("SEVERITY").style(Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
            Cell::from("CWE").style(Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
            Cell::from("REACHABILITY").style(Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
            Cell::from("LOCATION").style(Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
            Cell::from("SUMMARY").style(Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
            Cell::from("STATUS").style(Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
        ])
        .height(1)
        .style(Style::default().bg(th().surface));

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
            .style(Style::default().bg(th().bg));

        let table = Table::new(rows, widths)
            .header(header)
            .block(table_block);

        f.render_widget(table, chunks[0]);

        // 2. Selected Vulnerability Detail Panel (IDE-Style Formatted Inspector)
        let detail_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(th().border))
            .title_top(Line::from(vec![
                Span::styled(" finding inspector ", Style::default().fg(th().fg).add_modifier(Modifier::BOLD)),
                if let Some(sel) = findings.get(selected_index) {
                    let max_t_w = (chunks[1].width as usize).saturating_sub(38).min(45);
                    Span::styled(
                        format!("{} · {} ", sel.id, ellipsize(&sel.title, max_t_w)),
                        Style::default().fg(th().text_muted),
                    )
                } else {
                    Span::raw("")
                },
            ]))
            .title_bottom(Line::from(vec![
                Span::styled(" [Alt+3] ", Style::default().fg(th().text_sub).add_modifier(Modifier::BOLD)),
                Span::styled("diff  ", Style::default().fg(th().text_dim)),
                Span::styled("[/patch] ", Style::default().fg(th().text_sub).add_modifier(Modifier::BOLD)),
                Span::styled("apply fix  ", Style::default().fg(th().text_dim)),
                Span::styled("[↑↓/jk] ", Style::default().fg(th().text_sub).add_modifier(Modifier::BOLD)),
                Span::styled("navigate ", Style::default().fg(th().text_dim)),
            ]))
            .style(Style::default().bg(th().surface));

        let inner_detail = detail_block.inner(chunks[1]);
        f.render_widget(detail_block, chunks[1]);

        if let Some(selected) = findings.get(selected_index) {
            let inspector_rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(5), // Top Card: IDE / Text Editor Code View
                    Constraint::Min(4),    // Bottom Card: Impact, Triage Verdict & Remediation
                ])
                .split(inner_detail);

            // 1. TOP CARD: IDE Code Viewer with Red Highlight on the Vulnerable Line
            let file_loc = format!("{}:{}", selected.file_path.display(), selected.line_number);
            let code_card_block = Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(th().border))
                .title_top(Line::from(vec![
                    Span::styled(" source location ", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                    Span::styled(format!(" {} ", file_loc), Style::default().fg(th().fg).add_modifier(Modifier::BOLD)),
                ]))
                .style(Style::default().bg(th().bg));
            let inner_code = code_card_block.inner(inspector_rows[0]);
            f.render_widget(code_card_block, inspector_rows[0]);

            let snippet_trimmed = selected.snippet.trim();
            let mut code_lines = Vec::new();

            // Try reading context lines from disk if file is accessible
            let (prev_line, next_line) = if let Ok(content) = std::fs::read_to_string(&selected.file_path) {
                let lines_vec: Vec<&str> = content.lines().collect();
                let idx = selected.line_number.saturating_sub(1);
                let prev = if idx > 0 { lines_vec.get(idx - 1).map(|s| s.trim().to_string()) } else { None };
                let next = lines_vec.get(idx + 1).map(|s| s.trim().to_string());
                (prev, next)
            } else {
                (None, None)
            };

            let gutter_w = 6;
            let code_max_w = (inner_code.width as usize).saturating_sub(gutter_w + 4).max(20);

            // Context line before (if present)
            if let Some(prev) = prev_line {
                if !prev.is_empty() && selected.line_number > 1 {
                    code_lines.push(Line::from(vec![
                        Span::styled(format!(" {:>4} │ ", selected.line_number - 1), Style::default().fg(th().text_dim)),
                        Span::styled(ellipsize(&prev, code_max_w), Style::default().fg(th().text_sub)),
                    ]));
                }
            }

            // Faulty / Vulnerable Code Line (Highlighted with solid red background)
            code_lines.push(Line::from(vec![
                Span::styled(format!(" {:>4} │ ", selected.line_number), Style::default().fg(th().destructive).add_modifier(Modifier::BOLD)),
                Span::styled(
                    format!(" {} ", ellipsize(if snippet_trimmed.is_empty() { "(empty snippet)" } else { snippet_trimmed }, code_max_w)),
                    Style::default().fg(Color::Rgb(255, 255, 255)).bg(th().destructive).add_modifier(Modifier::BOLD),
                ),
            ]));

            // Context line after (if present)
            if let Some(next) = next_line {
                if !next.is_empty() {
                    code_lines.push(Line::from(vec![
                        Span::styled(format!(" {:>4} │ ", selected.line_number + 1), Style::default().fg(th().text_dim)),
                        Span::styled(ellipsize(&next, code_max_w), Style::default().fg(th().text_sub)),
                    ]));
                }
            }

            f.render_widget(Paragraph::new(code_lines).wrap(Wrap { trim: false }), inner_code);

            // 2. BOTTOM CARD: Impact, Triage Verdict & Remediation
            let bottom_cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(50),
                    Constraint::Length(1), // Divider
                    Constraint::Percentage(50),
                ])
                .split(inspector_rows[1]);

            let (reach_fg, reach_bg) = match selected.reachability.as_str() {
                "REACHABLE" => (th().destructive, th().destructive_bg),
                "UNREACHABLE" => (th().success, th().element),
                _ => (th().warning, th().warning_bg),
            };

            let call_chain = if selected.call_path.is_empty() {
                "direct taint execution".to_string()
            } else {
                selected.call_path.join(" ➔ ")
            };
            let reasoning = if selected.triage_reasoning.is_empty() {
                "Deterministic AST syntax & reachability analysis.".to_string()
            } else {
                selected.triage_reasoning.clone()
            };

            let l_col_w = (bottom_cols[0].width as usize).saturating_sub(4);
            let left_content = vec![
                Line::from(vec![
                    Span::styled(" IMPACT & CONTEXT ", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                    Span::styled(format!(" [CWE: {}] ", selected.cwe), Style::default().fg(th().text_dim)),
                ]),
                Line::from(vec![
                    Span::styled("   summary    ", Style::default().fg(th().text_dim)),
                    Span::styled(ellipsize(&selected.description, l_col_w * 2), Style::default().fg(th().text)),
                ]),
                Line::raw(""),
                Line::from(vec![
                    Span::styled(" TRIAGE VERDICT   ", Style::default().fg(th().fg).add_modifier(Modifier::BOLD)),
                    Span::styled(
                        format!(" {} · {} ", selected.triage_verdict, selected.reachability),
                        Style::default().fg(reach_fg).bg(reach_bg).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("   reasoning  ", Style::default().fg(th().text_dim)),
                    Span::styled(ellipsize(&reasoning, l_col_w.saturating_sub(15)), Style::default().fg(th().text_sub)),
                ]),
                Line::from(vec![
                    Span::styled("   callpath   ", Style::default().fg(th().text_dim)),
                    Span::styled(ellipsize(&call_chain, l_col_w.saturating_sub(15)), Style::default().fg(th().text_muted)),
                ]),
            ];
            f.render_widget(Paragraph::new(left_content).wrap(Wrap { trim: false }), bottom_cols[0]);

            let divider_lines = vec![Line::from(Span::styled("│", Style::default().fg(th().border))); bottom_cols[1].height as usize];
            f.render_widget(Paragraph::new(divider_lines), bottom_cols[1]);

            let r_col_w = (bottom_cols[2].width as usize).saturating_sub(4);
            let right_content = vec![
                Line::from(vec![
                    Span::styled(" REMEDIATION & FIX ", Style::default().fg(th().success).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(vec![
                    Span::styled("   action     ", Style::default().fg(th().text_dim)),
                    Span::styled("✓ ", Style::default().fg(th().success).add_modifier(Modifier::BOLD)),
                    Span::styled(ellipsize(&selected.recommendation, r_col_w * 2), Style::default().fg(th().text)),
                ]),
                Line::raw(""),
                Line::from(vec![
                    Span::styled(" QUICK ACTIONS ", Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(vec![
                    Span::styled("   press ", Style::default().fg(th().text_dim)),
                    Span::styled("[/patch]", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                    Span::styled(" or switch to tab [3] to apply verified fix.", Style::default().fg(th().text_sub)),
                ]),
            ];
            f.render_widget(Paragraph::new(right_content).wrap(Wrap { trim: false }), bottom_cols[2]);
        } else {
            let empty_text = vec![Line::from(vec![
                Span::raw("  "),
                Span::styled("no vulnerabilities identified in current scope • workspace clean or press [space] to run defense audit.", Style::default().fg(th().text_muted)),
            ])];
            f.render_widget(Paragraph::new(empty_text), inner_detail);
        }

        chunks[0]
    }
}
