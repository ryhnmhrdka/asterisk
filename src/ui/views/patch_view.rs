use crate::ui::theme::th;
use crate::types::HardeningPatch;
use crate::ui::fit::ellipsize;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Paragraph, Wrap},
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
                Constraint::Length(((area.width as usize * 36 / 100).clamp(26, 40) as u16).min(area.width / 2)),
                Constraint::Min(10),
            ])
            .split(area);

        // Left Panel: Patch List
        let list_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(th().border))
            .title(Line::from(vec![
                Span::styled(" [remediation patches] ", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                Span::styled(format!("({} total) ", patches.len()), Style::default().fg(th().text_muted)),
            ]))
            .style(Style::default().bg(th().surface));

        let inner_list = list_block.inner(chunks[0]);
        let list_w = inner_list.width as usize;

        let mut list_lines = Vec::new();
        for (i, patch) in patches.iter().enumerate() {
            let is_sel = i == selected_index;
            let status_badge = if patch.applied {
                Span::styled("● applied", Style::default().fg(th().success).add_modifier(Modifier::BOLD))
            } else {
                Span::styled("● pending", Style::default().fg(th().warning).add_modifier(Modifier::BOLD))
            };

            let prefix = if is_sel { "▸ " } else { "  " };
            let title_style = if is_sel {
                Style::default().fg(th().fg).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(th().text)
            };

            list_lines.push(Line::from(vec![
                Span::raw(" "),
                Span::styled(format!("{}{}. ", prefix, i + 1), Style::default().fg(th().text_muted)),
                Span::styled(ellipsize(&patch.id, list_w.saturating_sub(18).max(8)), title_style),
                Span::raw("  "),
                status_badge,
            ]));

            let fname = patch.target_file.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            list_lines.push(Line::from(vec![
                Span::raw("     "),
                Span::styled("target: ", Style::default().fg(th().text_dim)),
                Span::styled(ellipsize(&fname, list_w.saturating_sub(15)), Style::default().fg(th().text_sub)),
            ]));

            let test_badge = if patch.unit_test_passed {
                Span::styled("✓ test passed", Style::default().fg(th().success))
            } else {
                Span::styled("… test pending", Style::default().fg(th().text_muted))
            };
            let gate_badge = if patch.safe_outputs_passed {
                Span::styled("✓ gate verified", Style::default().fg(th().primary))
            } else {
                Span::styled("! gate review", Style::default().fg(th().warning))
            };

            list_lines.push(Line::from(vec![
                Span::raw("     "),
                test_badge,
                Span::styled("  •  ", Style::default().fg(th().border)),
                gate_badge,
            ]));
            list_lines.push(Line::raw(""));
        }

        if patches.is_empty() {
            list_lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled("no hardening patches pending • codebase is clean or run defense audit.", Style::default().fg(th().text_muted)),
            ]));
        }

        f.render_widget(list_block, chunks[0]);
        f.render_widget(Paragraph::new(list_lines).wrap(Wrap { trim: false }), inner_list);

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
                Span::styled("no hardening patches pending • workspace clean or run defense audit via [space].", Style::default().fg(th().text_muted)),
            ]);
            let empty_block = Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(th().border))
                .style(Style::default().bg(th().bg));
            f.render_widget(Paragraph::new(empty_text).block(empty_block), action_bar_area);
        } else {
            let bar_block = Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(th().border))
                .title(Line::from(vec![
                    Span::styled(" [patch actions] ", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                ]))
                .style(Style::default().bg(th().surface));
            let inner_action = bar_block.inner(action_bar_area);
            f.render_widget(bar_block, action_bar_area);

            let apply_lbl = " [a] Apply to Disk ";
            let roll_lbl = " [r] Rollback ";
            let apply_w = (apply_lbl.len() as u16).max(18);
            let roll_w = (roll_lbl.len() as u16).max(14);

            let action_split = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Length(1),       // Left margin
                    Constraint::Length(apply_w), // Apply button
                    Constraint::Length(1),       // Spacer
                    Constraint::Length(roll_w),  // Rollback button
                    Constraint::Length(2),       // Spacer
                    Constraint::Min(0),          // Status/Target info
                ])
                .split(inner_action);

            let apply_rect = action_split[1];
            let rollback_rect = action_split[3];
            let msg_rect = action_split[5];

            let apply_text = Line::from(Span::styled(apply_lbl, Style::default().fg(th().on_accent).bg(th().success).add_modifier(Modifier::BOLD)));
            f.render_widget(Paragraph::new(apply_text).centered(), apply_rect);

            let roll_text = Line::from(Span::styled(roll_lbl, Style::default().fg(th().fg).bg(th().element_hi).add_modifier(Modifier::BOLD)));
            f.render_widget(Paragraph::new(roll_text).centered(), rollback_rect);

            let status_text = if let Some(msg) = action_msg {
                Line::from(vec![
                    Span::styled("status: ", Style::default().fg(th().text_muted)),
                    Span::styled(msg, Style::default().fg(th().fg).add_modifier(Modifier::BOLD)),
                ])
            } else if let Some(selected_patch) = patches.get(selected_index) {
                Line::from(vec![
                    Span::styled("target: ", Style::default().fg(th().text_muted)),
                    Span::styled(selected_patch.target_file.display().to_string(), Style::default().fg(th().primary)),
                    Span::styled("  •  hotkey: [a] apply  •  [r] rollback", Style::default().fg(th().text_muted)),
                ])
            } else {
                Line::from(vec![
                    Span::styled("click buttons or press [a] / [r]", Style::default().fg(th().text_muted)),
                ])
            };
            f.render_widget(Paragraph::new(status_text), msg_rect);

            btn_apply = Some(apply_rect);
            btn_rollback = Some(rollback_rect);
        }

        // Diff Viewer
        let diff_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(th().border))
            .title(Line::from(vec![
                Span::styled(" Code Diff ", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                if let Some(patch) = patches.get(selected_index) {
                    Span::styled(format!(" {} ", patch.target_file.display()), Style::default().fg(th().fg))
                } else {
                    Span::raw("")
                },
            ]))
            .style(Style::default().bg(th().bg));

        let diff_lines = if let Some(patch) = patches.get(selected_index) {
            let mut lines = Vec::new();
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled("Remediation: ", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                Span::styled(&patch.explanation, Style::default().fg(th().text)),
            ]));
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled("Status:      ", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                Span::styled(
                    if patch.unit_test_passed { "✓ Unit Test Passed" } else { "… Unit Test Pending" },
                    Style::default().fg(if patch.unit_test_passed { th().success } else { th().text_sub }),
                ),
                Span::raw("  •  "),
                Span::styled(
                    if patch.safe_outputs_passed { "✓ Safety Gates Verified" } else { "! Safety Gates Unverified" },
                    Style::default().fg(if patch.safe_outputs_passed { th().primary } else { th().warning }),
                ),
            ]));
            lines.push(Line::raw(""));

            for line in patch.unified_diff.lines() {
                let prefix_span = Span::raw("  ");
                if line.starts_with('+') && !line.starts_with("+++") {
                    lines.push(Line::from(vec![prefix_span, Span::styled(line, Style::default().fg(th().success).add_modifier(Modifier::BOLD))]));
                } else if line.starts_with('-') && !line.starts_with("---") {
                    lines.push(Line::from(vec![prefix_span, Span::styled(line, Style::default().fg(th().destructive))]));
                } else if line.starts_with("---") || line.starts_with("+++") {
                    lines.push(Line::from(vec![prefix_span, Span::styled(line, Style::default().fg(th().text_muted))]));
                } else if line.starts_with("@@") {
                    lines.push(Line::from(vec![prefix_span, Span::styled(line, Style::default().fg(th().primary))]));
                } else {
                    lines.push(Line::from(vec![prefix_span, Span::styled(line, Style::default().fg(th().text_sub))]));
                }
            }
            lines
        } else {
            vec![Line::from(vec![
                Span::raw("  "),
                Span::styled("no remediation patches available • workspace clean or run defense audit.", Style::default().fg(th().text_muted)),
            ])]
        };

        let inner_diff = diff_block.inner(right_chunks[1]);
        f.render_widget(diff_block, right_chunks[1]);
        f.render_widget(Paragraph::new(diff_lines).wrap(Wrap { trim: false }), inner_diff);

        // Automated Unit Test Code Block
        let test_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(th().border))
            .title(Line::from(vec![
                Span::styled(" Verification Unit Test ", Style::default().fg(th().success).add_modifier(Modifier::BOLD)),
                if let Some(patch) = patches.get(selected_index) {
                    Span::styled(format!(" {} ", patch.target_file.display()), Style::default().fg(th().text_muted))
                } else {
                    Span::raw("")
                },
            ]))
            .style(Style::default().bg(th().bg_alt));

        let test_lines = if let Some(patch) = patches.get(selected_index) {
            let mut lines = Vec::new();
            for l in patch.unit_test_code.lines() {
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(l, Style::default().fg(th().text)),
                ]));
            }
            lines
        } else {
            vec![Line::from(vec![
                Span::raw("  "),
                Span::styled("no remediation test harness • workspace clean or run defense audit.", Style::default().fg(th().text_muted)),
            ])]
        };

        let inner_test = test_block.inner(right_chunks[2]);
        f.render_widget(test_block, right_chunks[2]);
        f.render_widget(Paragraph::new(test_lines).wrap(Wrap { trim: false }), inner_test);

        PatchClickTargets {
            list_area: chunks[0],
            btn_apply,
            btn_rollback,
        }
    }
}
