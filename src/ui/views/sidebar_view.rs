use crate::ui::theme::th;
use crate::types::{get_matching_commands, AgentStatus, ChatMessage, SproutedNodeInfo};
use crate::ui::fit::{ellipsize, hint_line};
use crate::ui::markdown::parse_markdown;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
    Frame,
};
use std::collections::HashSet;

pub struct SidebarClickTargets {
    pub btn_confirm: Option<Rect>,
    pub btn_cancel: Option<Rect>,
    pub btn_pause: Option<Rect>,
    pub btn_apply: Option<Rect>,
    pub btn_delete_node: Option<Rect>,
    pub btn_move_left: Option<Rect>,
    pub btn_move_right: Option<Rect>,
    pub btn_move_up: Option<Rect>,
    pub btn_move_down: Option<Rect>,
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
        is_focused: bool,
        is_chat_querying: bool,
        querying_model: &str,
    ) -> SidebarClickTargets {
        let est_input_width = area.width;
        let wrap_width = (est_input_width.saturating_sub(6) as usize).max(10);

        let display_lines = if prompt_input.is_empty() {
            if awaiting_confirmation {
                vec![
                    Line::from(vec![
                        Span::styled(" ❯ ", Style::default().fg(th().warning).add_modifier(Modifier::BOLD)),
                        Span::styled("type 'y' to confirm or [Enter]... ", Style::default().fg(th().text_dim)),
                    ]),
                ]
            } else {
                vec![
                    Line::from(vec![
                        Span::styled(" ❯ ", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                        Span::styled("ask a question or type /scan... ", Style::default().fg(th().text_dim)),
                    ]),
                ]
            }
        } else {
            let wrapped = wrap_multiline(prompt_input, wrap_width);
            let total_wrapped = wrapped.len();
            let mut lines = Vec::new();
            for (i, line_text) in wrapped.iter().enumerate() {
                let is_last = i == total_wrapped - 1;
                let prefix = if i == 0 { " ❯ " } else { "   " };
                let mut spans = vec![
                    Span::styled(prefix, Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                    Span::styled(line_text.clone(), Style::default().fg(th().fg).add_modifier(Modifier::BOLD)),
                ];
                if is_last {
                    spans.push(Span::styled("█", Style::default().fg(th().primary)));
                }
                lines.push(Line::from(spans));
            }
            lines
        };

        let num_lines = display_lines.len();
        let max_box_height = 6;
        let input_box_height = ((num_lines + 2) as u16).clamp(3, max_box_height);
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
            btn_delete_node: None,
            btn_move_left: None,
            btn_move_right: None,
            btn_move_up: None,
            btn_move_down: None,
            subagent_rows: Vec::new(),
            user_msg_expand: Vec::new(),
            suggestion_rows: Vec::new(),
        };

        // Deep obsidian filled sidebar with responsive focus border
        let sidebar_border_style = if is_focused {
            Style::default().fg(th().ring)
        } else {
            Style::default().fg(th().element)
        };
        let sidebar_bg = Block::default()
            .borders(Borders::RIGHT)
            .border_type(BorderType::Plain)
            .border_style(sidebar_border_style)
            .style(Style::default().bg(th().surface));
        f.render_widget(sidebar_bg, area);

        // 1. Chat Message Stream (Clean filled surface, NO borders)
        let chat_block = Block::default()
            .style(Style::default().bg(th().surface));

        let max_text_width = (chunks[0].width.saturating_sub(4)) as usize;
        let mut all_chat_lines: Vec<(Line, Option<usize>)> = Vec::new();

        if chat_messages.is_empty() {
            all_chat_lines.push((Line::raw(""), None));
            all_chat_lines.push((
                Line::from(vec![
                    Span::styled("  ✻ Asterisk Defense Assistant", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                ]),
                None,
            ));
            all_chat_lines.push((
                Line::from(vec![
                    Span::styled("    Autonomous pre-production security & triage", Style::default().fg(th().text_muted)),
                ]),
                None,
            ));
            all_chat_lines.push((Line::raw(""), None));
            all_chat_lines.push((
                Line::from(vec![
                    Span::styled("    Quick commands:", Style::default().fg(th().text_dim).add_modifier(Modifier::BOLD)),
                ]),
                None,
            ));
            all_chat_lines.push((
                Line::from(vec![
                    Span::styled("    /scan      ", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                    Span::styled("Run SAST & secret audit", Style::default().fg(th().text_sub)),
                ]),
                None,
            ));
            all_chat_lines.push((
                Line::from(vec![
                    Span::styled("    /provider  ", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                    Span::styled("Configure AI models & keys", Style::default().fg(th().text_sub)),
                ]),
                None,
            ));
            all_chat_lines.push((
                Line::from(vec![
                    Span::styled("    /help      ", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                    Span::styled("Display command reference", Style::default().fg(th().text_sub)),
                ]),
                None,
            ));
            all_chat_lines.push((
                Line::from(vec![
                    Span::styled("    ?          ", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                    Span::styled("Open keyboard cheat sheet", Style::default().fg(th().text_sub)),
                ]),
                None,
            ));
            all_chat_lines.push((Line::raw(""), None));
        }

        for (actual_idx, msg) in chat_messages.iter().enumerate() {
            match msg {
                ChatMessage::User(text) => {
                    all_chat_lines.push((
                        Line::from(vec![
                            Span::styled("  ▸ You:", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                        ]),
                        None,
                    ));

                    let wrapped = wrap_text_with_indent(text, "    ", max_text_width);
                    let is_expanded = expanded_messages.contains(&actual_idx);

                    if wrapped.len() <= 3 || is_expanded {
                        for l in &wrapped {
                            all_chat_lines.push((
                                Line::from(vec![
                                    Span::styled(l.clone(), Style::default().fg(th().fg)),
                                ]),
                                None,
                            ));
                        }
                        if is_expanded && wrapped.len() > 3 {
                            all_chat_lines.push((
                                Line::from(vec![
                                    Span::styled("    ▲ [collapse]", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                                ]),
                                Some(actual_idx),
                            ));
                        }
                    } else {
                        for l in &wrapped[..2] {
                            all_chat_lines.push((
                                Line::from(vec![
                                    Span::styled(l.clone(), Style::default().fg(th().fg)),
                                ]),
                                None,
                            ));
                        }
                        let last_line = format!("    {} ... [click to expand]", wrapped[2].trim_start());
                        all_chat_lines.push((
                            Line::from(vec![
                                Span::styled(last_line, Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                            ]),
                            Some(actual_idx),
                        ));
                    }
                }
                ChatMessage::Thinking { agent, thought } => {
                    all_chat_lines.push((
                        Line::from(vec![
                            Span::styled("  💭 ", Style::default().fg(th().text_muted)),
                            Span::styled(format!("{agent} thinking:"), Style::default().fg(th().text_dim).add_modifier(Modifier::BOLD)),
                        ]),
                        None,
                    ));
                    let wrapped = wrap_text_with_indent(thought, "     ", max_text_width);
                    for l in wrapped {
                        all_chat_lines.push((
                            Line::from(vec![
                                Span::styled(l, Style::default().fg(th().text_sub).add_modifier(Modifier::ITALIC)),
                            ]),
                            None,
                        ));
                    }
                }
                ChatMessage::ToolCall { tool, input, .. } => {
                    all_chat_lines.push((
                        Line::from(vec![
                            Span::styled("  ⚡ task: ", Style::default().fg(th().primary)),
                            Span::styled(tool.to_string(), Style::default().fg(th().fg).add_modifier(Modifier::BOLD)),
                        ]),
                        None,
                    ));
                    let wrapped = wrap_text_with_indent(input, "     ", max_text_width);
                    for l in wrapped {
                        all_chat_lines.push((
                            Line::from(vec![
                                Span::styled(l, Style::default().fg(th().text_muted)),
                            ]),
                            None,
                        ));
                    }
                }
                ChatMessage::ToolResult { output, elapsed_ms, .. } => {
                    let ms_str = elapsed_ms.map(|ms| format!(" ({ms}ms)")).unwrap_or_default();
                    all_chat_lines.push((
                        Line::from(vec![
                            Span::styled("  ✓ result", Style::default().fg(th().success).add_modifier(Modifier::BOLD)),
                            Span::styled(ms_str, Style::default().fg(th().text_dim)),
                            Span::styled(":", Style::default().fg(th().text_dim)),
                        ]),
                        None,
                    ));
                    let wrapped = wrap_text_with_indent(output, "     ", max_text_width);
                    for l in wrapped {
                        all_chat_lines.push((
                            Line::from(vec![
                                Span::styled(l, Style::default().fg(th().text)),
                            ]),
                            None,
                        ));
                    }
                }
                ChatMessage::Agent { sender, text } => {
                    let (icon, role_name, color) = match sender.to_lowercase().as_str() {
                        "sast-analyzer" | "sast" => ("⚡", "SAST Analyzer", th().warning),
                        "secret-scanner" | "secret" => ("🔑", "Secret Hunter", th().warning),
                        "reachability-engine" | "reachability" => ("🎯", "Reachability Verifier", th().info),
                        "patch-verifier" | "verifier" => ("🛡", "Patch Verifier", th().success),
                        "orchestrator" => ("✻", "Defense Orchestrator", th().primary),
                        _ => ("●", sender.as_str(), th().primary),
                    };

                    all_chat_lines.push((
                        Line::from(vec![
                            Span::styled(format!("  {icon} "), Style::default().fg(color)),
                            Span::styled(format!("{role_name}:"), Style::default().fg(color).add_modifier(Modifier::BOLD)),
                        ]),
                        None,
                    ));

                    let parsed = parse_markdown(text);
                    for pl in parsed {
                        let wrapped = wrap_spans_to_lines(pl.spans, "  ", max_text_width);
                        for wl in wrapped {
                            all_chat_lines.push((wl, None));
                        }
                    }
                }
                ChatMessage::System(text) => {
                    all_chat_lines.push((
                        Line::from(vec![
                            Span::styled("  ● system:", Style::default().fg(th().text_dim).add_modifier(Modifier::BOLD)),
                        ]),
                        None,
                    ));
                    let wrapped = wrap_text_with_indent(text, "    ", max_text_width);
                    for l in wrapped {
                        all_chat_lines.push((
                            Line::from(vec![
                                Span::styled(l, Style::default().fg(th().text)),
                            ]),
                            None,
                        ));
                    }
                }
            }
            all_chat_lines.push((Line::raw(""), None));
        }

        if is_chat_querying {
            let spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let frame_idx = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                / 80) as usize
                % spinner_frames.len();
            let spinner = spinner_frames[frame_idx];

            all_chat_lines.push((
                Line::from(vec![
                    Span::styled(format!("  {} ", spinner), Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                    Span::styled(format!("Asterisk is thinking ({querying_model})..."), Style::default().fg(th().text_muted).add_modifier(Modifier::ITALIC)),
                ]),
                None,
            ));
            all_chat_lines.push((Line::raw(""), None));
        }

        let visible_height = chunks[0].height as usize;
        let total_visual_lines = all_chat_lines.len();
        let max_scroll = total_visual_lines.saturating_sub(visible_height);
        let effective_scroll = chat_scroll.min(max_scroll);
        let scroll_top = max_scroll.saturating_sub(effective_scroll) as u16;

        let lines_to_render: Vec<Line> = all_chat_lines.into_iter().map(|(l, _)| l).collect();
        f.render_widget(
            Paragraph::new(lines_to_render)
                .scroll((scroll_top, 0))
                .block(chat_block),
            chunks[0],
        );

        // 2. Module Inspector Box (Sleek filled surface, only shown when a node is selected)
        if let Some(node) = selected_node {
            let node_block = Block::default()
                .style(Style::default().bg(th().element));
            let node_area = chunks[1];
            let status_str = if node.is_paused { "paused" } else { node.status.as_str() };
            let p_rect = Rect::new(node_area.x + 2, node_area.y + 2, 14.min(node_area.width.saturating_sub(4)), 1);
            let a_rect = Rect::new(node_area.x + 18, node_area.y + 2, 18.min(node_area.width.saturating_sub(20)), 1);

            let mut action_spans = Vec::new();
            action_spans.push(Span::raw("  "));
            let mut opt_pause = None;
            let mut opt_apply = None;
            let mut opt_del = None;
            let mut opt_left = None;
            let mut opt_right = None;
            let mut opt_up = None;
            let mut opt_down = None;

            if awaiting_confirmation && node.id != "orch" && node.id != "defense_gate" {
                let d_rect = Rect::new(node_area.x + 2, node_area.y + 2, 8.min(node_area.width.saturating_sub(4)), 1);
                let l_rect = Rect::new(node_area.x + 11, node_area.y + 2, 6.min(node_area.width.saturating_sub(13)), 1);
                let r_rect = Rect::new(node_area.x + 18, node_area.y + 2, 6.min(node_area.width.saturating_sub(20)), 1);
                let u_rect = Rect::new(node_area.x + 25, node_area.y + 2, 5.min(node_area.width.saturating_sub(27)), 1);
                let dn_rect = Rect::new(node_area.x + 31, node_area.y + 2, 5.min(node_area.width.saturating_sub(33)), 1);

                action_spans.push(Span::styled(
                    " [✕Del] ",
                    Style::default().fg(th().destructive).bg(th().element_hi).add_modifier(Modifier::BOLD),
                ));
                action_spans.push(Span::raw(" "));
                action_spans.push(Span::styled(
                    " [◀] ",
                    Style::default().fg(th().fg).bg(th().element_hi),
                ));
                action_spans.push(Span::raw(" "));
                action_spans.push(Span::styled(
                    " [▶] ",
                    Style::default().fg(th().fg).bg(th().element_hi),
                ));
                action_spans.push(Span::raw(" "));
                action_spans.push(Span::styled(
                    " [▲] ",
                    Style::default().fg(th().fg).bg(th().element_hi),
                ));
                action_spans.push(Span::raw(" "));
                action_spans.push(Span::styled(
                    " [▼] ",
                    Style::default().fg(th().fg).bg(th().element_hi),
                ));

                opt_del = Some(d_rect);
                opt_left = Some(l_rect);
                opt_right = Some(r_rect);
                opt_up = Some(u_rect);
                opt_down = Some(dn_rect);
            } else if node.status == AgentStatus::Running || node.is_paused {
                action_spans.push(Span::styled(
                    if node.is_paused { " [ ▶ Resume ] " } else { " [ ⏸ Pause ] " },
                    Style::default().fg(th().fg).bg(th().element_hi),
                ));
                action_spans.push(Span::raw("  "));
                opt_pause = Some(p_rect);
            }

            if has_patches {
                action_spans.push(Span::styled(
                    " [ ✓ Apply Patch ] ",
                    Style::default().fg(th().fg).bg(th().element_hi),
                ));
                opt_apply = Some(a_rect);
            }

            if opt_pause.is_none() && opt_apply.is_none() && opt_del.is_none() {
                action_spans.push(Span::styled("no pending actions", Style::default().fg(th().text_dim)));
            }

            let lines = vec![
                Line::from(vec![
                    Span::styled("  module: ", Style::default().fg(th().text_dim)),
                    Span::styled(ellipsize(&node.id, (node_area.width as usize).saturating_sub(28).max(8)), Style::default().fg(th().fg).add_modifier(Modifier::BOLD)),
                    Span::styled(format!("  [{status_str}]"), Style::default().fg(if node.is_paused { th().text_muted } else { th().fg })),
                ]),
                Line::from(vec![
                    Span::styled("  target: ", Style::default().fg(th().text_dim)),
                    Span::styled(crate::ui::fit::ellipsize_start(node.target_path.as_deref().unwrap_or("-"), (node_area.width as usize).saturating_sub(12).max(8)), Style::default().fg(th().fg)),
                ]),
                Line::from(action_spans),
            ];

            f.render_widget(Paragraph::new(lines).block(node_block), node_area);
            targets.btn_pause = opt_pause;
            targets.btn_apply = opt_apply;
            targets.btn_delete_node = opt_del;
            targets.btn_move_left = opt_left;
            targets.btn_move_right = opt_right;
            targets.btn_move_up = opt_up;
            targets.btn_move_down = opt_down;
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
                .border_style(Style::default().fg(th().fg));
            let inner_bw = btn_conf_rect.width.saturating_sub(2) as usize;
            let conf_label = [" [ ✓ Execute Review ] ", " [✓ Execute] ", " ✓ Run ", " ✓ "]
                .iter()
                .find(|l| l.chars().count() <= inner_bw)
                .copied()
                .unwrap_or(" ✓ ");
            let conf_text = Line::from(Span::styled(conf_label, Style::default().fg(th().on_accent).bg(th().fg).add_modifier(Modifier::BOLD)));
            f.render_widget(Paragraph::new(conf_text).centered().block(conf_block), btn_conf_rect);

            let canc_block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(th().border_hi));
            let inner_cw = btn_canc_rect.width.saturating_sub(2) as usize;
            let canc_label = [" [ ✗ Cancel ] ", " [✗ Cancel] ", " ✗ Esc ", " ✗ "]
                .iter()
                .find(|l| l.chars().count() <= inner_cw)
                .copied()
                .unwrap_or(" ✗ ");
            let canc_text = Line::from(Span::styled(canc_label, Style::default().fg(th().text_muted)));
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

        let prompt_border_color = if is_focused {
            th().ring
        } else {
            th().element_hi
        };
        let prompt_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(prompt_border_color))
            .style(Style::default().bg(th().element));

        let inner_input = prompt_block.inner(input_rect);
        f.render_widget(prompt_block, input_rect);

        let scroll_y = (num_lines as u16).saturating_sub(inner_input.height);
        let prompt_paragraph = Paragraph::new(display_lines)
            .scroll((scroll_y, 0));
        f.render_widget(prompt_paragraph, inner_input);

        let spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let frame_idx = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            / 80) as usize
            % spinner_frames.len();
        let spinner = spinner_frames[frame_idx];

        // Subtitle hint row beneath input box
        let hint_line = if is_chat_querying {
            Line::from(vec![
                Span::styled(format!("  {} Thinking... ", spinner), Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                Span::styled("Press [Esc] to cancel", Style::default().fg(th().text_muted)),
            ])
        } else if is_focused {
            hint_line(
                &[("/", "commands"), ("[Tab]", "complete"), ("[Enter]", "send")],
                prompt_chunks[1].width as usize,
                Style::default().fg(th().primary),
                Style::default().fg(th().border_hi),
                "  •  ",
            )
        } else {
            hint_line(
                &[("[Shift+Tab]", "focus chat"), ("[Tab]", "views"), ("[Space]", "scan")],
                prompt_chunks[1].width as usize,
                Style::default().fg(th().fg),
                Style::default().fg(th().border_hi),
                "  •  ",
            )
        };
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
                .border_style(Style::default().fg(th().border))
                .style(Style::default().bg(th().surface))
                .title(Span::styled(format!("  {}  ", ellipsize("commands [↑/↓ select, Tab complete]", (popup_rect.width as usize).saturating_sub(8))), Style::default().fg(th().fg).add_modifier(Modifier::BOLD)));

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
                        Span::styled(" ▸ ", Style::default().fg(th().on_accent).bg(th().fg).add_modifier(Modifier::BOLD)),
                        Span::styled(name_txt, Style::default().fg(th().on_accent).bg(th().fg).add_modifier(Modifier::BOLD)),
                        Span::styled(args_txt, Style::default().fg(th().border).bg(th().fg)),
                        Span::styled(desc_txt, Style::default().fg(th().on_accent).bg(th().fg)),
                    ]));
                } else {
                    suggestion_lines.push(Line::from(vec![
                        Span::styled("   ", Style::default().fg(th().text_dim)),
                        Span::styled(name_txt, Style::default().fg(th().fg).add_modifier(Modifier::BOLD)),
                        Span::styled(args_txt, Style::default().fg(th().text_muted)),
                        Span::styled(desc_txt, Style::default().fg(th().text_muted)),
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
    use crate::ui::fit::text_width;
    let mut result = Vec::new();
    for paragraph in text.lines() {
        if paragraph.trim().is_empty() {
            result.push(String::new());
            continue;
        }
        let mut current = String::new();
        let mut current_w = 0;

        for word in paragraph.split_whitespace() {
            let word_w = text_width(word);
            if word_w > max_width {
                if !current.is_empty() {
                    result.push(current);
                    current = String::new();
                    current_w = 0;
                }
                let mut chunk = String::new();
                let mut chunk_w = 0;
                for ch in word.chars() {
                    let mut buf = [0; 4];
                    let ch_s = ch.encode_utf8(&mut buf);
                    let cw = text_width(ch_s);
                    if chunk_w + cw > max_width && !chunk.is_empty() {
                        result.push(chunk);
                        chunk = String::new();
                        chunk_w = 0;
                    }
                    chunk.push(ch);
                    chunk_w += cw;
                }
                if !chunk.is_empty() {
                    current = chunk;
                    current_w = chunk_w;
                }
            } else if current.is_empty() {
                current.push_str(word);
                current_w = word_w;
            } else if current_w + 1 + word_w <= max_width {
                current.push(' ');
                current.push_str(word);
                current_w += 1 + word_w;
            } else {
                result.push(current);
                current = word.to_string();
                current_w = word_w;
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

fn wrap_text_with_indent(text: &str, indent: &'static str, max_width: usize) -> Vec<String> {
    use crate::ui::fit::text_width;
    let indent_w = text_width(indent);
    let usable_w = max_width.saturating_sub(indent_w).max(12);
    let mut result = Vec::new();

    for paragraph in text.lines() {
        let trimmed = paragraph.trim();
        if trimmed.is_empty() {
            result.push(String::new());
            continue;
        }

        let mut current = String::new();
        let mut current_w = 0;

        for word in trimmed.split_whitespace() {
            let word_w = text_width(word);
            let space_needed = if current.is_empty() { 0 } else { 1 };

            if current_w + word_w + space_needed > usable_w && !current.is_empty() {
                result.push(format!("{indent}{current}"));
                current = word.to_string();
                current_w = word_w;
            } else {
                if !current.is_empty() {
                    current.push(' ');
                    current_w += 1;
                }
                current.push_str(word);
                current_w += word_w;
            }
        }

        if !current.is_empty() {
            result.push(format!("{indent}{current}"));
        }
    }

    if result.is_empty() {
        result.push(format!("{indent}{text}"));
    }

    result
}

fn wrap_spans_to_lines(
    spans: Vec<Span<'static>>,
    indent: &'static str,
    max_width: usize,
) -> Vec<Line<'static>> {
    use crate::ui::fit::text_width;
    let indent_w = text_width(indent);
    let usable_w = max_width.saturating_sub(indent_w).max(12);

    let mut result: Vec<Line<'static>> = Vec::new();
    let mut current_line: Vec<Span<'static>> = Vec::new();
    let mut current_w = 0;

    current_line.push(Span::raw(indent));

    for span in spans {
        let style = span.style;
        let text = span.content.to_string();
        if text.is_empty() {
            continue;
        }

        for (line_idx, line_str) in text.lines().enumerate() {
            if line_idx > 0 {
                result.push(Line::from(std::mem::take(&mut current_line)));
                current_line.push(Span::raw(indent));
                current_w = 0;
            }

            let words: Vec<&str> = line_str.split(' ').collect();
            for (w_idx, word) in words.iter().enumerate() {
                if word.is_empty() {
                    if w_idx > 0 && current_w + 1 <= usable_w {
                        current_line.push(Span::styled(" ", style));
                        current_w += 1;
                    }
                    continue;
                }

                let word_w = text_width(word);
                let space = if w_idx > 0 { 1 } else { 0 };

                if current_w + word_w + space > usable_w && current_w > 0 {
                    result.push(Line::from(std::mem::take(&mut current_line)));
                    current_line.push(Span::raw(indent));
                    current_line.push(Span::styled(word.to_string(), style));
                    current_w = word_w;
                } else {
                    if space > 0 && current_w > 0 {
                        current_line.push(Span::styled(" ", style));
                        current_w += 1;
                    }
                    current_line.push(Span::styled(word.to_string(), style));
                    current_w += word_w;
                }
            }
        }
    }

    if !current_line.is_empty() && (current_line.len() > 1 || current_w > 0) {
        result.push(Line::from(current_line));
    }

    if result.is_empty() {
        result.push(Line::from(vec![Span::raw(indent)]));
    }

    result
}
