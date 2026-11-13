use crate::ui::theme::th;
use crate::types::InteractiveSkill;
use crate::ui::fit::ellipsize;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Cell, Paragraph, Row, Table, Wrap},
    Frame,
};

pub struct SkillsView;

impl SkillsView {
    pub fn render(
        f: &mut Frame,
        area: Rect,
        skills: &[InteractiveSkill],
        search_query: &str,
        is_search_active: bool,
        selected_index: usize,
    ) -> Rect {
        // Layout: Search bar (3), Table (Min 8), Detail Spec & Agent Decs (8)
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(8),
                Constraint::Length(8),
            ])
            .split(area);

        let search_area = chunks[0];
        let table_area = chunks[1];
        let detail_area = chunks[2];

        // 1. Search Bar
        let search_border_color = if is_search_active {
            th().primary
        } else if !search_query.is_empty() {
            th().primary
        } else {
            th().border
        };

        // Filter skills based on query
        let q = search_query.trim().to_lowercase();
        let filtered_skills: Vec<&InteractiveSkill> = if q.is_empty() {
            skills.iter().collect()
        } else {
            skills
                .iter()
                .filter(|s| {
                    s.name.to_lowercase().contains(&q)
                        || s.id.to_lowercase().contains(&q)
                        || s.category.to_lowercase().contains(&q)
                        || s.description.to_lowercase().contains(&q)
                })
                .collect()
        };

        let count_badge = format!(" [ {} / {} skills ] ", filtered_skills.len(), skills.len());
        let search_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(search_border_color))
            .style(Style::default().bg(th().surface))
            .title(Line::from(vec![
                Span::styled(
                    " [search skills] ",
                    Style::default()
                        .fg(if is_search_active {
                            th().primary
                        } else {
                            th().text_muted
                        })
                        .add_modifier(Modifier::BOLD),
                ),
            ]))
            .title_bottom(Line::from(vec![
                Span::styled(
                    if is_search_active {
                        " [typing mode :: press Esc to exit / Enter to confirm] "
                    } else {
                        " [press '/' to search :: Esc to clear] "
                    },
                    Style::default().fg(th().border_hi),
                ),
            ]));

        let search_line = if search_query.is_empty() {
            if is_search_active {
                Line::from(vec![
                    Span::styled(" [?] search: ", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                    Span::styled("█", Style::default().fg(th().primary)),
                    Span::styled(" Type skill name, id, category, or capability...", Style::default().fg(th().border_hi)),
                ])
            } else {
                Line::from(vec![
                    Span::styled(" [?] search: ", Style::default().fg(th().text_muted)),
                    Span::styled("Type '/' to filter skills by name, ID, or capability... ", Style::default().fg(th().border_hi)),
                    Span::styled(count_badge, Style::default().fg(th().text_dim)),
                ])
            }
        } else {
            Line::from(vec![
                Span::styled(" [?] search: ", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                Span::styled(search_query, Style::default().fg(th().fg).add_modifier(Modifier::BOLD)),
                if is_search_active {
                    Span::styled("█", Style::default().fg(th().primary))
                } else {
                    Span::raw("")
                },
                Span::styled(format!("  {}", count_badge), Style::default().fg(th().primary)),
            ])
        };

        f.render_widget(Paragraph::new(search_line).block(search_block), search_area);

        // 2. Skills Table
        let table_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(th().border))
            .style(Style::default().bg(th().bg))
            .title(Line::from(vec![
                Span::styled(
                    " [autonomous agent capabilities & skills] ",
                    Style::default().fg(th().primary).add_modifier(Modifier::BOLD),
                ),
            ]))
            .title_bottom(Line::from(vec![
                Span::styled(
                    " [↑/↓ / j/k] Navigate  •  [/] Filter  •  [Enter] Toggle Active  •  [Esc] Clear ",
                    Style::default().fg(th().border_hi),
                ),
            ]));

        if filtered_skills.is_empty() {
            let empty_text = vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled(" [!] ", Style::default().fg(th().warning)),
                    Span::styled(
                        format!("No skills found matching filter \"{}\"", search_query),
                        Style::default().fg(th().fg).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "Press [Esc] to clear your filter and display all installed skills.",
                    Style::default().fg(th().text_muted),
                )),
            ];
            let empty_p = Paragraph::new(empty_text)
                .alignment(ratatui::layout::Alignment::Center)
                .block(table_block);
            f.render_widget(empty_p, table_area);
        } else {
            let clamped_selected = selected_index.min(filtered_skills.len().saturating_sub(1));

            let header = Row::new(vec![
                Cell::from("  STATUS").style(Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
                Cell::from("ID").style(Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
                Cell::from("CAPABILITY NAME").style(Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
                Cell::from("CATEGORY").style(Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
                Cell::from("INVOCATIONS").style(Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
            ])
            .height(1)
            .style(Style::default().bg(th().surface));

            let rows = filtered_skills.iter().enumerate().map(|(idx, skill)| {
                let is_selected = idx == clamped_selected;
                let status_cell = if skill.active {
                    Span::styled(
                        if is_selected { "▸ ● active" } else { "  ● active" },
                        Style::default().fg(th().success).add_modifier(Modifier::BOLD),
                    )
                } else {
                    Span::styled(
                        if is_selected { "▸ ○ disabled" } else { "  ○ disabled" },
                        Style::default().fg(th().text_muted),
                    )
                };

                let row_style = if is_selected {
                    Style::default().bg(th().element_hi).fg(th().fg)
                } else {
                    Style::default().fg(th().text_sub)
                };

                let cat_color = match skill.category.to_lowercase().as_str() {
                    c if c.contains("synthesized") => th().secondary,
                    c if c.contains("custom") => th().warning,
                    _ => th().primary,
                };

                Row::new(vec![
                    Cell::from(status_cell),
                    Cell::from(Span::styled(&skill.id, Style::default().fg(th().text_sub))),
                    Cell::from(Span::styled(
                        &skill.name,
                        if is_selected {
                            Style::default().fg(th().fg).add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(th().text)
                        },
                    )),
                    Cell::from(Span::styled(&skill.category, Style::default().fg(cat_color))),
                    Cell::from(Span::styled(
                        format!("{} calls", skill.invocations),
                        Style::default().fg(if skill.invocations > 0 {
                            th().info
                        } else {
                            th().text_dim
                        }),
                    )),
                ])
                .style(row_style)
            });

            let widths = [
                Constraint::Length(14),
                Constraint::Length(18),
                Constraint::Min(24),
                Constraint::Length(18),
                Constraint::Length(14),
            ];

            let table = Table::new(rows, widths)
                .header(header)
                .block(table_block);

            f.render_widget(table, table_area);
        }

        // 3. Balanced Dual-Column: Skill Specification (Left) & Agent Description (Right)
        let detail_cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(50),
                Constraint::Percentage(50),
            ])
            .split(detail_area);

        let maybe_skill = filtered_skills.get(selected_index.min(filtered_skills.len().saturating_sub(1)));

        // 3A. Left Column: Skill Specification
        let active_badge = if let Some(s) = maybe_skill {
            if s.active {
                Span::styled(" [ACTIVE] ", Style::default().fg(th().success).add_modifier(Modifier::BOLD))
            } else {
                Span::styled(" [DISABLED] ", Style::default().fg(th().text_muted))
            }
        } else {
            Span::raw("")
        };

        let spec_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(th().border))
            .style(Style::default().bg(th().surface))
            .title(Line::from(vec![
                Span::styled(
                    " [skill specification] ",
                    Style::default().fg(th().primary).add_modifier(Modifier::BOLD),
                ),
                active_badge,
            ]));

        let spec_content = if let Some(s) = maybe_skill {
            let cat_color = match s.category.to_lowercase().as_str() {
                c if c.contains("synthesized") => th().secondary,
                c if c.contains("custom") => th().warning,
                _ => th().primary,
            };

            let max_w = (detail_cols[0].width as usize).saturating_sub(16).max(15);
            let name_display = ellipsize(&s.name, max_w);
            let id_display = ellipsize(&s.id, max_w);
            let cat_display = ellipsize(&s.category, max_w);

            vec![
                Line::from(vec![
                    Span::styled("  Name:       ", Style::default().fg(th().text_muted)),
                    Span::styled(name_display, Style::default().fg(th().fg).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(vec![
                    Span::styled("  ID:         ", Style::default().fg(th().text_muted)),
                    Span::styled(id_display, Style::default().fg(th().primary)),
                ]),
                Line::from(vec![
                    Span::styled("  Category:   ", Style::default().fg(th().text_muted)),
                    Span::styled(cat_display, Style::default().fg(cat_color)),
                ]),
                Line::from(vec![
                    Span::styled("  Telemetry:  ", Style::default().fg(th().text_muted)),
                    Span::styled(format!("{} calls", s.invocations), Style::default().fg(if s.invocations > 0 { th().info } else { th().text })),
                ]),
            ]
        } else {
            vec![
                Line::from(""),
                Line::from(Span::styled("  No skill selected or available.", Style::default().fg(th().text_muted))),
            ]
        };

        f.render_widget(
            Paragraph::new(spec_content)
                .wrap(Wrap { trim: false })
                .block(spec_block),
            detail_cols[0],
        );

        // 3B. Right Column: Agent Description
        let desc_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(th().border))
            .style(Style::default().bg(th().surface))
            .title(Line::from(vec![
                Span::styled(
                    " [agent description & capabilities] ",
                    Style::default().fg(th().primary).add_modifier(Modifier::BOLD),
                ),
            ]))
            .title_bottom(Line::from(vec![
                Span::styled(
                    " progressive disclosure active ",
                    Style::default().fg(th().border_hi),
                ),
            ]));

        let desc_content = if let Some(s) = maybe_skill {
            let desc = if s.description.trim().is_empty() {
                "No agent description provided for this capability."
            } else {
                s.description.as_str()
            };

            vec![
                Line::from(vec![
                    Span::styled("  Overview:   ", Style::default().fg(th().text_muted)),
                    Span::styled("Automated reasoning subagent workflow", Style::default().fg(th().text_sub)),
                ]),
                Line::from(vec![
                    Span::styled("  Directives: ", Style::default().fg(th().text_muted)),
                    Span::styled(desc, Style::default().fg(th().text)),
                ]),
            ]
        } else {
            vec![
                Line::from(""),
                Line::from(Span::styled("  No agent description available.", Style::default().fg(th().text_muted))),
            ]
        };

        f.render_widget(
            Paragraph::new(desc_content)
                .wrap(Wrap { trim: true })
                .block(desc_block),
            detail_cols[1],
        );

        search_area
    }
}
