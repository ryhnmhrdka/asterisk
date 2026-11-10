use crate::types::{get_matching_commands, AgentStatus, ChatMessage, SproutedNodeInfo};
use crate::ui::markdown::parse_markdown;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap},
    Frame,
};
use std::collections::HashSet;

pub struct SidebarClickTargets {
    pub btn_confirm: Option<Rect>,
    pub btn_cancel: Option<Rect>,
    pub btn_pause: Option<Rect>,
    pub btn_apply: Option<Rect>,
    pub btn_send: Option<Rect>,
    pub subagent_rows: Vec<(String, Rect)>,
    pub user_msg_expand: Vec<(usize, Rect)>,
    pub suggestion_rows: Vec<(&'static str, &'static str, Rect)>,
}

pub struct SidebarView;

impl SidebarView {
    pub fn render(
        f: &mut Frame,
        area: Rect,
        chat_messages: &[ChatMessage],
        chat_scroll: usize,
        nodes_info: &std::collections::HashMap<String, SproutedNodeInfo>,
        selected_node: Option<&SproutedNodeInfo>,
        prompt_input: &str,
        selected_suggestion: usize,
        awaiting_confirmation: bool,
        expanded_messages: &HashSet<usize>,
        has_patches: bool,
    ) -> SidebarClickTargets {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4),                                               // 1. Review Modules Tray
                Constraint::Min(8),                                                  // 2. Chatbot Message Stream
                Constraint::Length(if awaiting_confirmation { 3 } else { 0 }),       // 3. Confirmation Buttons
                Constraint::Length(4),                                               // 4. Module Inspector Box
                Constraint::Length(3),                                               // 5. Input Prompt Row (with bottom margin)
            ])
            .split(area);

        let mut targets = SidebarClickTargets {
            btn_confirm: None,
            btn_cancel: None,
            btn_pause: None,
            btn_apply: None,
            btn_send: None,
            subagent_rows: Vec::new(),
            user_msg_expand: Vec::new(),
            suggestion_rows: Vec::new(),
        };

        // Deep obsidian filled sidebar with single quiet right border
        let sidebar_bg = Block::default()
            .borders(Borders::RIGHT)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::Rgb(28, 29, 36)))
            .style(Style::default().bg(Color::Rgb(16, 17, 21)));
        f.render_widget(sidebar_bg, area);

        // 1. Review Modules Tray (Clean filled banner, NO bottom border)
        let tray_block = Block::default()
            .style(Style::default().bg(Color::Rgb(20, 21, 26)));

        let mut tray_lines = Vec::new();
        tray_lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(" MODULES ", Style::default().fg(Color::Rgb(180, 182, 192)).bg(Color::Rgb(28, 29, 36)).add_modifier(Modifier::BOLD)),
            Span::styled("  click row to inspect", Style::default().fg(Color::Rgb(110, 112, 120))),
        ]));

        let mut key_subagents: Vec<(String, String, String)> = nodes_info
            .values()
            .filter(|n| n.tier == "subagent" && (n.status == AgentStatus::Running || n.is_paused || n.status == AgentStatus::Failed))
            .map(|n| {
                let clean_label = n.label.lines().next().unwrap_or("module").to_string();
                let clean_target = n.target_path.clone().unwrap_or_else(|| "-".to_string());
                (n.id.clone(), clean_label, clean_target)
            })
            .collect();

        key_subagents.sort_by(|a, b| a.0.cmp(&b.0));

        let tray_area = chunks[0];
        let mut row_y = tray_area.y + 1;

        if key_subagents.is_empty() {
            tray_lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled("workspace idle", Style::default().fg(Color::Rgb(120, 122, 130))),
                Span::styled("  •  press [space] or /scan to audit", Style::default().fg(Color::Rgb(90, 92, 100))),
            ]));
        } else {
            let tray_items: Vec<(&str, &str, &str)> = key_subagents
                .iter()
                .take(3)
                .map(|(id, label, target)| (id.as_str(), label.as_str(), target.as_str()))
                .collect();

            for (id, name, target) in tray_items {
                let info = nodes_info.get(id);
                let (status_icon, status_color) = match info.map(|n| (n.status, n.is_paused)) {
                    Some((_, true)) => ("⏸", Color::DarkGray),
                    Some((AgentStatus::Running, false)) => ("⠋", Color::White),
                    Some((AgentStatus::Failed, false)) => ("✖", Color::Red),
                    _ => ("✔", Color::Gray),
                };

                let row_rect = Rect::new(tray_area.x, row_y, tray_area.width, 1);
                targets.subagent_rows.push((id.to_string(), row_rect));

                tray_lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(format!("{status_icon} "), Style::default().fg(status_color)),
                    Span::styled(format!("{name:<16} "), Style::default().fg(Color::White)),
                    Span::styled(format!("{target}"), Style::default().fg(Color::Rgb(120, 122, 130))),
                ]));
                row_y += 1;
            }
        }

        f.render_widget(Paragraph::new(tray_lines).block(tray_block), tray_area);

        // 2. Chat Message Stream (Clean filled surface, NO borders)
        let chat_block = Block::default()
            .style(Style::default().bg(Color::Rgb(16, 17, 21)));

        let max_text_width = (chunks[1].width.saturating_sub(4)) as usize;
        let mut all_chat_lines: Vec<(Line, Option<usize>)> = Vec::new();

        for (actual_idx, msg) in chat_messages.iter().enumerate() {
            match msg {
                ChatMessage::User(text) => {
                    let user_style = Style::default().bg(Color::Rgb(26, 28, 34));

                    all_chat_lines.push((
                        Line::from(vec![
                            Span::styled("  You:", user_style.fg(Color::Rgb(150, 185, 255)).add_modifier(Modifier::BOLD)),
                        ]),
                        None,
                    ));

                    let wrapped = wrap_multiline(text, max_text_width);
                    let is_expanded = expanded_messages.contains(&actual_idx);

                    if wrapped.len() <= 3 || is_expanded {
                        for l in &wrapped {
                            all_chat_lines.push((
                                Line::from(vec![
                                    Span::styled(format!("  {l}"), user_style.fg(Color::White)),
                                ]),
                                None,
                            ));
                        }
                        if is_expanded && wrapped.len() > 3 {
                            all_chat_lines.push((
                                Line::from(vec![
                                    Span::styled("  ▲ [collapse]", user_style.fg(Color::Rgb(110, 160, 255)).add_modifier(Modifier::BOLD)),
                                ]),
                                Some(actual_idx),
                            ));
                        }
                    } else {
                        for l in &wrapped[..2] {
                            all_chat_lines.push((
                                Line::from(vec![
                                    Span::styled(format!("  {l}"), user_style.fg(Color::White)),
                                ]),
                                None,
                            ));
                        }
                        let last_line = format!("  {} ... [click to expand]", &wrapped[2]);
                        all_chat_lines.push((
                            Line::from(vec![
                                Span::styled(last_line, user_style.fg(Color::Rgb(120, 175, 255)).add_modifier(Modifier::BOLD)),
                            ]),
                            Some(actual_idx),
                        ));
                    }
                }
                ChatMessage::Thinking { agent, thought } => {
                    all_chat_lines.push((
                        Line::from(vec![
                            Span::styled("  ⠋ ", Style::default().fg(Color::Rgb(120, 122, 132))),
                            Span::styled(format!("[{agent}]: "), Style::default().fg(Color::Rgb(130, 132, 142))),
                            Span::styled(thought, Style::default().fg(Color::Rgb(160, 162, 172)).add_modifier(Modifier::ITALIC)),
                        ]),
                        None,
                    ));
                }
                ChatMessage::ToolCall { tool, input, .. } => {
                    all_chat_lines.push((
                        Line::from(vec![
                            Span::styled("  ❯ task: ", Style::default().fg(Color::Rgb(120, 122, 132))),
                            Span::styled(format!("{tool} "), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                            Span::styled(format!("({input})"), Style::default().fg(Color::Rgb(130, 132, 142))),
                        ]),
                        None,
                    ));
                }
                ChatMessage::ToolResult { output, elapsed_ms, .. } => {
                    let ms_str = elapsed_ms.map(|ms| format!(" ({ms}ms)")).unwrap_or_default();
                    all_chat_lines.push((
                        Line::from(vec![
                            Span::styled("    ✔ result: ", Style::default().fg(Color::Rgb(120, 195, 130))),
                            Span::styled(output, Style::default().fg(Color::Rgb(210, 212, 220))),
                            Span::styled(ms_str, Style::default().fg(Color::Rgb(110, 112, 120))),
                        ]),
                        None,
                    ));
                }
                ChatMessage::Agent { sender, text } => {
                    all_chat_lines.push((
                        Line::from(vec![
                            Span::styled(format!("  ● {sender}:"), Style::default().fg(Color::Rgb(100, 165, 255)).add_modifier(Modifier::BOLD)),
                        ]),
                        None,
                    ));

                    let parsed = parse_markdown(text);
                    for pl in parsed {
                        let mut spans = vec![Span::raw("    ")];
                        spans.extend(pl.spans);
                        all_chat_lines.push((Line::from(spans), None));
                    }
                }
                ChatMessage::System(text) => {
                    all_chat_lines.push((
                        Line::from(vec![
                            Span::styled("  ● system: ", Style::default().fg(Color::Rgb(110, 112, 122))),
                            Span::styled(text, Style::default().fg(Color::Rgb(200, 202, 210))),
                        ]),
                        None,
                    ));
                }
            }
            all_chat_lines.push((Line::raw(""), None));
        }

        let visible_height = chunks[1].height as usize;
        let total_lines = all_chat_lines.len();
        let max_scroll = total_lines.saturating_sub(visible_height);
        let effective_scroll = chat_scroll.min(max_scroll);

        let start_line = max_scroll.saturating_sub(effective_scroll);
        let end_line = (start_line + visible_height).min(total_lines);

        let mut visible_lines = Vec::new();
        if total_lines > 0 && start_line < total_lines {
            for (idx, (line, expand_msg_idx)) in all_chat_lines[start_line..end_line].iter().enumerate() {
                visible_lines.push(line.clone());
                if let Some(msg_idx) = expand_msg_idx {
                    let click_y = chunks[1].y + idx as u16;
                    targets.user_msg_expand.push((*msg_idx, Rect::new(chunks[1].x, click_y, chunks[1].width, 1)));
                }
            }
        }

        f.render_widget(
            Paragraph::new(visible_lines)
                .wrap(Wrap { trim: false })
                .block(chat_block),
            chunks[1],
        );

        // 3. Clickable Confirmation Buttons
        if awaiting_confirmation {
            let confirm_area = chunks[2];
            let btn_split = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(50),
                    Constraint::Percentage(50),
                ])
                .split(confirm_area);

            let btn_conf_rect = btn_split[0];
            let btn_canc_rect = btn_split[1];

            let conf_block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::White));
            let conf_text = Line::from(Span::styled(" [ ✓ Execute Review ] ", Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD)));
            f.render_widget(Paragraph::new(conf_text).centered().block(conf_block), btn_conf_rect);

            let canc_block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(80, 80, 85)));
            let canc_text = Line::from(Span::styled(" [ ✗ Cancel ] ", Style::default().fg(Color::Rgb(150, 150, 155))));
            f.render_widget(Paragraph::new(canc_text).centered().block(canc_block), btn_canc_rect);

            targets.btn_confirm = Some(btn_conf_rect);
            targets.btn_cancel = Some(btn_canc_rect);
        }

        // 4. Module Inspector Box (Sleek filled surface, NO borders)
        let node_block = Block::default()
            .style(Style::default().bg(Color::Rgb(22, 23, 29)));

        let node_area = chunks[3];
        let (node_lines, pause_rect, apply_rect) = if let Some(node) = selected_node {
            let status_str = if node.is_paused { "paused" } else { node.status.as_str() };
            let p_rect = Rect::new(node_area.x + 2, node_area.y + 2, 14.min(node_area.width.saturating_sub(4)), 1);
            let a_rect = Rect::new(node_area.x + 18, node_area.y + 2, 18.min(node_area.width.saturating_sub(20)), 1);

            let mut action_spans = Vec::new();
            action_spans.push(Span::raw("  "));
            let mut opt_pause = None;
            let mut opt_apply = None;

            if node.status == AgentStatus::Running || node.is_paused {
                action_spans.push(Span::styled(
                    if node.is_paused { " [ ▶ Resume ] " } else { " [ ⏸ Pause ] " },
                    Style::default().fg(Color::White).bg(Color::Rgb(38, 40, 50)),
                ));
                action_spans.push(Span::raw("  "));
                opt_pause = Some(p_rect);
            }

            if has_patches {
                action_spans.push(Span::styled(
                    " [ ✓ Apply Patch ] ",
                    Style::default().fg(Color::White).bg(Color::Rgb(38, 40, 50)),
                ));
                opt_apply = Some(a_rect);
            }

            if opt_pause.is_none() && opt_apply.is_none() {
                action_spans.push(Span::styled("no pending actions", Style::default().fg(Color::Rgb(110, 112, 120))));
            }

            let lines = vec![
                Line::from(vec![
                    Span::styled("  module: ", Style::default().fg(Color::Rgb(110, 112, 120))),
                    Span::styled(&node.id, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                    Span::styled(format!("  [{status_str}]"), Style::default().fg(if node.is_paused { Color::Rgb(140, 142, 150) } else { Color::White })),
                ]),
                Line::from(vec![
                    Span::styled("  target: ", Style::default().fg(Color::Rgb(110, 112, 120))),
                    Span::styled(node.target_path.as_deref().unwrap_or("-"), Style::default().fg(Color::White)),
                ]),
                Line::from(action_spans),
            ];
            (lines, opt_pause, opt_apply)
        } else {
            let lines = vec![
                Line::from(vec![
                    Span::styled("  ● ", Style::default().fg(Color::Rgb(100, 102, 112))),
                    Span::styled("click any module on graph to inspect", Style::default().fg(Color::Rgb(120, 122, 130))),
                ]),
                Line::from(Span::styled("    or use arrow keys to navigate flow", Style::default().fg(Color::Rgb(90, 92, 100)))),
            ];
            (lines, None, None)
        };

        f.render_widget(Paragraph::new(node_lines).block(node_block), node_area);
        targets.btn_pause = pause_rect;
        targets.btn_apply = apply_rect;

        // 5. Interactive Chatbot Input Bar with Clickable [ Send ↵ ] Button
        let prompt_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // 1. Input Box & Send button
                Constraint::Length(1), // 2. Clean hotkey hint line
                Constraint::Length(1), // 3. Bottom breathing margin
            ])
            .split(chunks[4]);

        let input_split = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Min(10),
                Constraint::Length(1), // Quiet spacer
                Constraint::Length(10), // Send button
            ])
            .split(prompt_chunks[0]);

        let input_rect = input_split[0];
        let send_rect = input_split[2];

        let prompt_block = Block::default()
            .style(Style::default().bg(Color::Rgb(24, 25, 31)));

        let prompt_display = if prompt_input.is_empty() {
            if awaiting_confirmation {
                vec![
                    Span::styled(" > ", Style::default().fg(Color::Rgb(255, 200, 100)).add_modifier(Modifier::BOLD)),
                    Span::styled("click [Execute] or type 'y'... ", Style::default().fg(Color::Rgb(110, 112, 120))),
                ]
            } else {
                vec![
                    Span::styled(" > ", Style::default().fg(Color::Rgb(160, 200, 255)).add_modifier(Modifier::BOLD)),
                    Span::styled("type instructions or slash commands... ", Style::default().fg(Color::Rgb(100, 102, 112))),
                ]
            }
        } else {
            vec![
                Span::styled(" > ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                Span::styled(prompt_input, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                Span::styled("█", Style::default().fg(Color::White)),
            ]
        };

        f.render_widget(Paragraph::new(Line::from(prompt_display)).block(prompt_block), input_rect);

        // [ Send ↵ ] Button (Sleek filled pill, NO borders)
        let send_block = Block::default()
            .style(Style::default().bg(Color::White));
        let send_text = Line::from(Span::styled(" Send ↵ ", Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD)));
        f.render_widget(Paragraph::new(send_text).centered().block(send_block), send_rect);

        targets.btn_send = Some(send_rect);

        // Subtitle hint row beneath input box (so it has comfortable bottom breathing space)
        let hint_line = Line::from(vec![
            Span::raw("  "),
            Span::styled("type ", Style::default().fg(Color::Rgb(85, 87, 95))),
            Span::styled("/", Style::default().fg(Color::Rgb(140, 180, 255))),
            Span::styled(" for commands  •  ", Style::default().fg(Color::Rgb(85, 87, 95))),
            Span::styled("[Tab]", Style::default().fg(Color::Rgb(140, 142, 150))),
            Span::styled(" complete  •  ", Style::default().fg(Color::Rgb(85, 87, 95))),
            Span::styled("[↵]", Style::default().fg(Color::Rgb(140, 142, 150))),
            Span::styled(" send", Style::default().fg(Color::Rgb(85, 87, 95))),
        ]);
        f.render_widget(Paragraph::new(hint_line), prompt_chunks[1]);

        // 6. Command Autocomplete Suggestions Popup
        let suggestions = get_matching_commands(prompt_input);
        if !suggestions.is_empty() {
            let visible_count = suggestions.len().min(6);
            let popup_height = (visible_count + 2) as u16;
            let popup_width = input_rect.width + send_rect.width + 1;
            let popup_y = input_rect.y.saturating_sub(popup_height);
            let popup_rect = Rect::new(input_rect.x, popup_y, popup_width, popup_height);

            f.render_widget(Clear, popup_rect);

            let popup_block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Rgb(60, 62, 72)))
                .style(Style::default().bg(Color::Rgb(16, 17, 22)))
                .title(Span::styled("  commands [↑/↓ select, Tab complete]  ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)));

            let start_idx = if selected_suggestion >= visible_count {
                selected_suggestion + 1 - visible_count
            } else {
                0
            };

            let mut suggestion_lines = Vec::new();
            let mut row_y = popup_y + 1;

            for (idx, cmd) in suggestions.iter().enumerate().skip(start_idx).take(visible_count) {
                let is_selected = idx == selected_suggestion;
                let item_rect = Rect::new(popup_rect.x + 1, row_y, popup_rect.width.saturating_sub(2), 1);
                targets.suggestion_rows.push((cmd.name, cmd.args, item_rect));
                row_y += 1;

                if is_selected {
                    suggestion_lines.push(Line::from(vec![
                        Span::styled(" ▸ ", Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD)),
                        Span::styled(format!("{:<10} ", cmd.name), Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD)),
                        Span::styled(format!("{:<14} ", cmd.args), Style::default().fg(Color::Rgb(60, 62, 70)).bg(Color::White)),
                        Span::styled(cmd.description.to_string(), Style::default().fg(Color::Black).bg(Color::White)),
                    ]));
                } else {
                    suggestion_lines.push(Line::from(vec![
                        Span::styled("   ", Style::default().fg(Color::Rgb(110, 112, 120))),
                        Span::styled(format!("{:<10} ", cmd.name), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                        Span::styled(format!("{:<14} ", cmd.args), Style::default().fg(Color::Rgb(130, 132, 142))),
                        Span::styled(cmd.description.to_string(), Style::default().fg(Color::Rgb(150, 152, 160))),
                    ]));
                }
            }

            f.render_widget(Paragraph::new(suggestion_lines).block(popup_block), popup_rect);
        }

        targets
    }
}

fn wrap_multiline(text: &str, max_width: usize) -> Vec<String> {
    if max_width == 0 {
        return vec![text.to_string()];
    }
    let mut result = Vec::new();
    for paragraph in text.lines() {
        let mut current = String::new();
        for word in paragraph.split_whitespace() {
            if word.len() > max_width {
                if !current.is_empty() {
                    result.push(current);
                    current = String::new();
                }
                let mut rem = word;
                while rem.len() > max_width {
                    result.push(rem[..max_width].to_string());
                    rem = &rem[max_width..];
                }
                if !rem.is_empty() {
                    current = rem.to_string();
                }
            } else if current.is_empty() {
                current.push_str(word);
            } else if current.len() + 1 + word.len() <= max_width {
                current.push(' ');
                current.push_str(word);
            } else {
                result.push(current);
                current = word.to_string();
            }
        }
        if !current.is_empty() {
            result.push(current);
        }
    }
    if result.is_empty() {
        result.push(String::new());
    }
    result
}
