use crate::types::{get_matching_commands, AgentStatus, ChatMessage, SproutedNodeInfo};
use crate::ui::fit::{ellipsize, hint_line};
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
        _nodes_info: &std::collections::HashMap<String, SproutedNodeInfo>,
        selected_node: Option<&SproutedNodeInfo>,
        prompt_input: &str,
        selected_suggestion: usize,
        awaiting_confirmation: bool,
        expanded_messages: &HashSet<usize>,
        has_patches: bool,
    ) -> SidebarClickTargets {
        let est_input_width = area.width;
        let wrap_width = (est_input_width.saturating_sub(6) as usize).max(10);

        let display_lines = if prompt_input.is_empty() {
            if awaiting_confirmation {
                vec![
                    Line::from(vec![
                        Span::styled(" > ", Style::default().fg(Color::Rgb(255, 200, 100)).add_modifier(Modifier::BOLD)),
                        Span::styled("click [Execute] or type 'y'... ", Style::default().fg(Color::Rgb(110, 112, 120))),
                    ]),
                    Line::raw(""),
                ]
            } else {
                vec![
                    Line::from(vec![
                        Span::styled(" > ", Style::default().fg(Color::Rgb(160, 200, 255)).add_modifier(Modifier::BOLD)),
                        Span::styled("type instructions or slash commands... ", Style::default().fg(Color::Rgb(100, 102, 112))),
                    ]),
                    Line::raw(""),
                ]
            }
        } else {
            let wrapped = wrap_multiline(prompt_input, wrap_width);
            let total_wrapped = wrapped.len();
            let mut lines = Vec::new();
            for (i, line_text) in wrapped.iter().enumerate() {
                let is_last = i == total_wrapped - 1;
                let prefix = if i == 0 { " > " } else { "   " };
                let mut spans = vec![
                    Span::styled(prefix, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                    Span::styled(line_text.clone(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                ];
                if is_last {
                    spans.push(Span::styled("█", Style::default().fg(Color::White)));
                }
                lines.push(Line::from(spans));
            }
            lines.push(Line::raw(""));
            lines
        };

        let num_lines = display_lines.len();
        let max_box_height = 6;
        let input_box_height = (num_lines as u16).clamp(3, max_box_height);
        let prompt_section_height = input_box_height + 1; // +1 for subtitle hint line

        let has_inspector = selected_node.is_some();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(8),                                                  // 0. Chatbot Message Stream (TOP)
                Constraint::Length(if has_inspector { 4 } else { 0 }),               // 1. Module Inspector Box (only when selected)
                Constraint::Length(if awaiting_confirmation { 3 } else { 0 }),       // 2. Confirmation Buttons
                Constraint::Length(prompt_section_height),                           // 3. Input Prompt at BOTTOM
            ])
            .split(area);

        let mut targets = SidebarClickTargets {
            btn_confirm: None,
            btn_cancel: None,
            btn_pause: None,
            btn_apply: None,
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

        // 1. Chat Message Stream (Clean filled surface, NO borders)
        let chat_block = Block::default()
            .style(Style::default().bg(Color::Rgb(16, 17, 21)));

        let max_text_width = (chunks[0].width.saturating_sub(4)) as usize;
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
                    let wrapped = wrap_multiline(thought, max_text_width.saturating_sub(agent.len() + 8).max(10));
                    for (i, l) in wrapped.into_iter().enumerate() {
                        if i == 0 {
                            all_chat_lines.push((
                                Line::from(vec![
                                    Span::styled("  ⠋ ", Style::default().fg(Color::Rgb(120, 122, 132))),
                                    Span::styled(format!("[{agent}]: "), Style::default().fg(Color::Rgb(130, 132, 142))),
                                    Span::styled(l, Style::default().fg(Color::Rgb(160, 162, 172)).add_modifier(Modifier::ITALIC)),
                                ]),
                                None,
                            ));
                        } else {
                            all_chat_lines.push((
                                Line::from(vec![
                                    Span::raw("    "),
                                    Span::styled(l, Style::default().fg(Color::Rgb(160, 162, 172)).add_modifier(Modifier::ITALIC)),
                                ]),
                                None,
                            ));
                        }
                    }
                }
                ChatMessage::ToolCall { tool, input, .. } => {
                    let wrapped = wrap_multiline(input, max_text_width.saturating_sub(tool.len() + 12).max(10));
                    for (i, l) in wrapped.into_iter().enumerate() {
                        if i == 0 {
                            all_chat_lines.push((
                                Line::from(vec![
                                    Span::styled("  ❯ task: ", Style::default().fg(Color::Rgb(120, 122, 132))),
                                    Span::styled(format!("{tool} "), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                                    Span::styled(format!("({l})"), Style::default().fg(Color::Rgb(130, 132, 142))),
                                ]),
                                None,
                            ));
                        } else {
                            all_chat_lines.push((
                                Line::from(vec![
                                    Span::raw("    "),
                                    Span::styled(l, Style::default().fg(Color::Rgb(130, 132, 142))),
                                ]),
                                None,
                            ));
                        }
                    }
                }
                ChatMessage::ToolResult { output, elapsed_ms, .. } => {
                    let ms_str = elapsed_ms.map(|ms| format!(" ({ms}ms)")).unwrap_or_default();
                    let wrapped = wrap_multiline(output, max_text_width.saturating_sub(16).max(10));
                    for (i, l) in wrapped.into_iter().enumerate() {
                        if i == 0 {
                            all_chat_lines.push((
                                Line::from(vec![
                                    Span::styled("    ✔ result: ", Style::default().fg(Color::Rgb(120, 195, 130))),
                                    Span::styled(l, Style::default().fg(Color::Rgb(210, 212, 220))),
                                    Span::styled(ms_str.clone(), Style::default().fg(Color::Rgb(110, 112, 120))),
                                ]),
                                None,
                            ));
                        } else {
                            all_chat_lines.push((
                                Line::from(vec![
                                    Span::raw("      "),
                                    Span::styled(l, Style::default().fg(Color::Rgb(210, 212, 220))),
                                ]),
                                None,
                            ));
                        }
                    }
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
                        let line_text: String = pl.spans.iter().map(|s| s.content.as_ref()).collect();
                        if line_text.chars().count() > max_text_width.saturating_sub(4).max(10) {
                            let wrapped = wrap_multiline(&line_text, max_text_width.saturating_sub(4).max(10));
                            for wl in wrapped {
                                all_chat_lines.push((
                                    Line::from(vec![
                                        Span::raw("    "),
                                        Span::styled(wl, Style::default().fg(Color::Rgb(210, 212, 220))),
                                    ]),
                                    None,
                                ));
                            }
                        } else {
                            let mut spans = vec![Span::raw("    ")];
                            spans.extend(pl.spans);
                            all_chat_lines.push((Line::from(spans), None));
                        }
                    }
                }
                ChatMessage::System(text) => {
                    let wrapped = wrap_multiline(text, max_text_width.saturating_sub(14).max(10));
                    for (i, l) in wrapped.into_iter().enumerate() {
                        if i == 0 {
                            all_chat_lines.push((
                                Line::from(vec![
                                    Span::styled("  ● system: ", Style::default().fg(Color::Rgb(110, 112, 122))),
                                    Span::styled(l, Style::default().fg(Color::Rgb(200, 202, 210))),
                                ]),
                                None,
                            ));
                        } else {
                            all_chat_lines.push((
                                Line::from(vec![
                                    Span::raw("    "),
                                    Span::styled(l, Style::default().fg(Color::Rgb(200, 202, 210))),
                                ]),
                                None,
                            ));
                        }
                    }
                }
            }
            all_chat_lines.push((Line::raw(""), None));
        }

        let visible_height = chunks[0].height as usize;
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
                    let click_y = chunks[0].y + idx as u16;
                    targets.user_msg_expand.push((*msg_idx, Rect::new(chunks[0].x, click_y, chunks[0].width, 1)));
                }
            }
        }

        f.render_widget(
            Paragraph::new(visible_lines)
                .wrap(Wrap { trim: false })
                .block(chat_block),
            chunks[0],
        );

        // 2. Module Inspector Box (Sleek filled surface, only shown when a node is selected)
        if let Some(node) = selected_node {
            let node_block = Block::default()
                .style(Style::default().bg(Color::Rgb(22, 23, 29)));
            let node_area = chunks[1];
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
                    Span::styled(ellipsize(&node.id, (node_area.width as usize).saturating_sub(28).max(8)), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                    Span::styled(format!("  [{status_str}]"), Style::default().fg(if node.is_paused { Color::Rgb(140, 142, 150) } else { Color::White })),
                ]),
                Line::from(vec![
                    Span::styled("  target: ", Style::default().fg(Color::Rgb(110, 112, 120))),
                    Span::styled(crate::ui::fit::ellipsize_start(node.target_path.as_deref().unwrap_or("-"), (node_area.width as usize).saturating_sub(12).max(8)), Style::default().fg(Color::White)),
                ]),
                Line::from(action_spans),
            ];

            f.render_widget(Paragraph::new(lines).block(node_block), node_area);
            targets.btn_pause = opt_pause;
            targets.btn_apply = opt_apply;
        }

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
            let inner_bw = btn_conf_rect.width.saturating_sub(2) as usize;
            let conf_label = [" [ ✓ Execute Review ] ", " [✓ Execute] ", " ✓ Run ", " ✓ "]
                .iter()
                .find(|l| l.chars().count() <= inner_bw)
                .copied()
                .unwrap_or(" ✓ ");
            let conf_text = Line::from(Span::styled(conf_label, Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD)));
            f.render_widget(Paragraph::new(conf_text).centered().block(conf_block), btn_conf_rect);

            let canc_block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(80, 80, 85)));
            let inner_cw = btn_canc_rect.width.saturating_sub(2) as usize;
            let canc_label = [" [ ✗ Cancel ] ", " [✗ Cancel] ", " ✗ Esc ", " ✗ "]
                .iter()
                .find(|l| l.chars().count() <= inner_cw)
                .copied()
                .unwrap_or(" ✗ ");
            let canc_text = Line::from(Span::styled(canc_label, Style::default().fg(Color::Rgb(150, 150, 155))));
            f.render_widget(Paragraph::new(canc_text).centered().block(canc_block), btn_canc_rect);

            targets.btn_confirm = Some(btn_conf_rect);
            targets.btn_cancel = Some(btn_canc_rect);
        }

        // 4. Interactive Chatbot Input Bar AT BOTTOM (Full width, Enter to send)
        let prompt_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(input_box_height), // 1. Input Box
                Constraint::Length(1),                // 2. Clean hotkey hint line
            ])
            .split(chunks[3]);

        let input_rect = prompt_chunks[0];

        let prompt_block = Block::default()
            .style(Style::default().bg(Color::Rgb(24, 25, 31)));

        let scroll_y = (num_lines as u16).saturating_sub(input_box_height);
        let prompt_paragraph = Paragraph::new(display_lines)
            .scroll((scroll_y, 0))
            .block(prompt_block);
        f.render_widget(prompt_paragraph, input_rect);

        // Subtitle hint row beneath input box
        let hint_line = hint_line(
            &[("/", "commands"), ("[Tab]", "complete"), ("[↵]", "send")],
            prompt_chunks[1].width as usize,
            Style::default().fg(Color::Rgb(140, 180, 255)),
            Style::default().fg(Color::Rgb(85, 87, 95)),
            "  •  ",
        );
        f.render_widget(Paragraph::new(hint_line), prompt_chunks[1]);

        // 5. Command Autocomplete Suggestions Popup (Floats above prompt at bottom)
        let suggestions = get_matching_commands(prompt_input);
        if !suggestions.is_empty() {
            let visible_count = suggestions.len().min(6);
            let popup_height = (visible_count + 2) as u16;
            let popup_width = input_rect.width;
            let popup_y = input_rect.y.saturating_sub(popup_height);
            let popup_rect = Rect::new(input_rect.x, popup_y, popup_width, popup_height);

            f.render_widget(Clear, popup_rect);

            let popup_block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Rgb(60, 62, 72)))
                .style(Style::default().bg(Color::Rgb(16, 17, 22)))
                .title(Span::styled(format!("  {}  ", ellipsize("commands [↑/↓ select, Tab complete]", (popup_rect.width as usize).saturating_sub(8))), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)));

            let start_idx = if selected_suggestion >= visible_count {
                selected_suggestion + 1 - visible_count
            } else {
                0
            };

            let mut suggestion_lines = Vec::new();
            let mut row_y = popup_y + 1;

            // Adaptive columns: name fits its longest entry; args shrink/hide before the
            // description gets squeezed; description is ellipsized to the exact remainder.
            let inner_w = popup_rect.width.saturating_sub(2) as usize;
            let name_w = suggestions.iter().map(|c| c.name.chars().count()).max().unwrap_or(8) + 1;
            let max_args = suggestions.iter().map(|c| c.args.chars().count()).max().unwrap_or(0);
            let mut args_w = if max_args == 0 { 0 } else { max_args + 1 };
            while args_w > 0 && inner_w < 3 + name_w + args_w + 24 {
                args_w = if args_w > 8 { args_w - 4 } else { 0 };
            }
            let desc_w = inner_w.saturating_sub(3 + name_w + args_w);

            for (idx, cmd) in suggestions.iter().enumerate().skip(start_idx).take(visible_count) {
                let is_selected = idx == selected_suggestion;
                let item_rect = Rect::new(popup_rect.x + 1, row_y, popup_rect.width.saturating_sub(2), 1);
                targets.suggestion_rows.push((cmd.name, cmd.args, item_rect));
                row_y += 1;

                let name_txt = format!("{:<w$}", ellipsize(cmd.name, name_w.saturating_sub(1)), w = name_w);
                let args_txt = if args_w > 0 {
                    format!("{:<w$}", ellipsize(cmd.args, args_w.saturating_sub(1)), w = args_w)
                } else {
                    String::new()
                };
                let desc_txt = ellipsize(cmd.description, desc_w);

                if is_selected {
                    suggestion_lines.push(Line::from(vec![
                        Span::styled(" ▸ ", Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD)),
                        Span::styled(name_txt, Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD)),
                        Span::styled(args_txt, Style::default().fg(Color::Rgb(60, 62, 70)).bg(Color::White)),
                        Span::styled(desc_txt, Style::default().fg(Color::Black).bg(Color::White)),
                    ]));
                } else {
                    suggestion_lines.push(Line::from(vec![
                        Span::styled("   ", Style::default().fg(Color::Rgb(110, 112, 120))),
                        Span::styled(name_txt, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                        Span::styled(args_txt, Style::default().fg(Color::Rgb(130, 132, 142))),
                        Span::styled(desc_txt, Style::default().fg(Color::Rgb(150, 152, 160))),
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
