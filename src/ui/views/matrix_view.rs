use crate::ui::theme::th;
use crate::types::{Severity, VulnerabilityFinding};
use crate::ui::fit::{ellipsize, ellipsize_start};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
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
                Constraint::Min(6),
                Constraint::Length(12),
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

        // 2. Selected Vulnerability Detail Panel (Sleek Minimalist Inspector)
        let detail_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(th().border))
            .title_top(Line::from(vec![
                Span::styled(" [finding inspector] ", Style::default().fg(th().fg).add_modifier(Modifier::BOLD)),
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
            let call_chain = if selected.call_path.is_empty() {
                "direct execution".to_string()
            } else {
                selected.call_path.join(" ➔ ")
            };
            let reasoning = if selected.triage_reasoning.is_empty() {
                "Deterministic AST syntax & reachability analysis.".to_string()
            } else {
                selected.triage_reasoning.clone()
            };

            let (reach_fg, reach_bg) = match selected.reachability.as_str() {
                "REACHABLE" => (th().destructive, th().destructive_bg),
                "UNREACHABLE" => (th().success, th().element),
                _ => (th().warning, th().warning_bg),
            };

            if inner_detail.width >= 90 {
                // Dual Column Minimalist Grid
                let detail_cols = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([
                        Constraint::Percentage(50),
                        Constraint::Length(1), // Subtle vertical rule
                        Constraint::Percentage(50),
                    ])
                    .split(inner_detail);

                let l_col_w = (detail_cols[0].width as usize).saturating_sub(4);
                let l_val_w = l_col_w.saturating_sub(15).max(18);

                let desc_clean = ellipsize(&selected.description, l_col_w * 2);
                let reason_clean = ellipsize(&reasoning, l_val_w);
                let path_clean = ellipsize(&call_chain, l_val_w);

                // Left Column: Threat Context & Triage Verdict
                let left_content = vec![
                    Line::from(vec![
                        Span::styled(" ◆ ", Style::default().fg(th().primary)),
                        Span::styled("IMPACT & CONTEXT", Style::default().fg(th().fg).add_modifier(Modifier::BOLD)),
                    ]),
                    Line::from(vec![
                        Span::styled("   summary    ", Style::default().fg(th().text_dim)),
                        Span::styled(desc_clean, Style::default().fg(th().text)),
                    ]),
                    Line::raw(""),
                    Line::from(vec![
                        Span::styled(" ◆ ", Style::default().fg(th().primary)),
                        Span::styled("TRIAGE VERDICT", Style::default().fg(th().fg).add_modifier(Modifier::BOLD)),
                        Span::raw("  "),
                        Span::styled(
                            format!(" {} · {} ", selected.triage_verdict, selected.reachability),
                            Style::default().fg(reach_fg).bg(reach_bg).add_modifier(Modifier::BOLD),
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled("   reasoning  ", Style::default().fg(th().text_dim)),
                        Span::styled(reason_clean, Style::default().fg(th().text_sub)),
                    ]),
                    Line::from(vec![
                        Span::styled("   callpath   ", Style::default().fg(th().text_dim)),
                        Span::styled(path_clean, Style::default().fg(th().text_muted)),
                    ]),
                ];
                f.render_widget(Paragraph::new(left_content).wrap(Wrap { trim: false }), detail_cols[0]);

                // Subtle Vertical Divider
                let divider_lines = vec![Line::from(Span::styled("│", Style::default().fg(th().border))); inner_detail.height as usize];
                f.render_widget(Paragraph::new(divider_lines), detail_cols[1]);

                // Right Column: Source Location & Remediation
                let r_col_w = (detail_cols[2].width as usize).saturating_sub(4);
                let r_val_w = r_col_w.saturating_sub(15).max(18);

                let snippet_raw = selected.snippet.trim();
                let loc_clean = ellipsize_start(&format!("{}:{}", selected.file_path.display(), selected.line_number), r_val_w);
                let snip_clean = if snippet_raw.is_empty() {
                    "(source line omitted)".to_string()
                } else {
                    ellipsize(snippet_raw, r_val_w)
                };
                let rec_clean = ellipsize(&selected.recommendation, r_col_w * 2);

                let right_content = vec![
                    Line::from(vec![
                        Span::styled(" ◆ ", Style::default().fg(th().text_muted)),
                        Span::styled("SOURCE LOCATION", Style::default().fg(th().fg).add_modifier(Modifier::BOLD)),
                        Span::raw("  "),
                        Span::styled(format!(" L{} ", selected.line_number), Style::default().fg(th().text_sub).bg(th().element)),
                    ]),
                    Line::from(vec![
                        Span::styled("   file       ", Style::default().fg(th().text_dim)),
                        Span::styled(loc_clean, Style::default().fg(th().text_sub)),
                    ]),
                    Line::from(vec![
                        Span::styled("   code       ", Style::default().fg(th().text_dim)),
                        Span::styled(format!(" {} ", snip_clean), Style::default().fg(th().fg).bg(th().element)),
                    ]),
                    Line::raw(""),
                    Line::from(vec![
                        Span::styled(" ◆ ", Style::default().fg(th().success)),
                        Span::styled("REMEDIATION", Style::default().fg(th().fg).add_modifier(Modifier::BOLD)),
                    ]),
                    Line::from(vec![
                        Span::styled("   action     ", Style::default().fg(th().text_dim)),
                        Span::styled("✓ ", Style::default().fg(th().success)),
                        Span::styled(rec_clean, Style::default().fg(th().text)),
                    ]),
                ];
                f.render_widget(Paragraph::new(right_content).wrap(Wrap { trim: false }), detail_cols[2]);
            } else {
                // Stacked Minimalist Layout for Narrow Viewports
                let max_w = (inner_detail.width as usize).saturating_sub(16).max(15);
                let stacked_content = vec![
                    Line::from(vec![
                        Span::styled("  summary   ", Style::default().fg(th().text_dim)),
                        Span::styled(ellipsize(&selected.description, max_w), Style::default().fg(th().text)),
                    ]),
                    Line::from(vec![
                        Span::styled("  verdict   ", Style::default().fg(th().text_dim)),
                        Span::styled(
                            format!(" {} · {} ", selected.triage_verdict, selected.reachability),
                            Style::default().fg(reach_fg).bg(reach_bg).add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(" "),
                        Span::styled(ellipsize(&reasoning, max_w.saturating_sub(22).max(12)), Style::default().fg(th().text_sub)),
                    ]),
                    Line::from(vec![
                        Span::styled("  location  ", Style::default().fg(th().text_dim)),
                        Span::styled(ellipsize_start(&format!("{}:{}", selected.file_path.display(), selected.line_number), max_w.saturating_sub(24).max(12)), Style::default().fg(th().text_sub)),
                        Span::raw(" "),
                        Span::styled(format!(" {} ", ellipsize(selected.snippet.trim(), 20)), Style::default().fg(th().fg).bg(th().element)),
                    ]),
                    Line::from(vec![
                        Span::styled("  remedy    ", Style::default().fg(th().text_dim)),
                        Span::styled("✓ ", Style::default().fg(th().success)),
                        Span::styled(ellipsize(&selected.recommendation, max_w.saturating_sub(2)), Style::default().fg(th().text)),
                    ]),
                ];
                f.render_widget(Paragraph::new(stacked_content).wrap(Wrap { trim: false }), inner_detail);
            }
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
