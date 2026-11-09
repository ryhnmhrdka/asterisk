use crate::types::{AgentStatus, ChatMessage, SproutedNodeInfo};
use crate::ui::markdown::parse_markdown;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame,
};

pub struct SidebarClickTargets {
    pub btn_confirm: Option<Rect>,
    pub btn_cancel: Option<Rect>,
    pub btn_pause: Option<Rect>,
    pub btn_apply: Option<Rect>,
    pub btn_send: Option<Rect>,
    pub subagent_rows: Vec<(String, Rect)>,
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
        awaiting_confirmation: bool,
    ) -> SidebarClickTargets {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5),                                               // 1. Subagent Crew Tray
                Constraint::Min(8),                                                  // 2. Chatbot Message Stream
                Constraint::Length(if awaiting_confirmation { 3 } else { 0 }),       // 3. Confirmation Buttons
                Constraint::Length(5),                                               // 4. Node Inspector Box
                Constraint::Length(3),                                               // 5. Input Prompt Row
            ])
            .split(area);

        let mut targets = SidebarClickTargets {
            btn_confirm: None,
            btn_cancel: None,
            btn_pause: None,
            btn_apply: None,
            btn_send: None,
            subagent_rows: Vec::new(),
        };

        // 1. Subagent Crew Tray
        let tray_block = Block::default()
            .borders(Borders::BOTTOM | Borders::RIGHT)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::Rgb(50, 50, 55)));

        let mut tray_lines = Vec::new();
        tray_lines.push(Line::from(vec![
            Span::styled("subagents crew: ", Style::default().fg(Color::Rgb(120, 120, 125))),
            Span::styled("(click row to focus node)", Style::default().fg(Color::Rgb(80, 80, 85))),
        ]));

        let key_subagents = vec![
            ("sub_secret_backend", "secret hunter", "backend/server.py"),
            ("sub_sast_backend", "sast analyzer", "backend/server.py"),
            ("sub_sast_frontend", "sast analyzer", "frontend/api.js"),
        ];

        let tray_area = chunks[0];
        let mut row_y = tray_area.y + 1;

        for (id, name, target) in key_subagents {
            let info = nodes_info.get(id);
            let (status_icon, status_color) = match info.map(|n| (n.status, n.is_paused)) {
                Some((_, true)) => ("⏸", Color::DarkGray),
                Some((AgentStatus::Running, false)) => ("⠋", Color::White),
                Some((AgentStatus::Success, false)) => ("✔", Color::Gray),
                _ => ("○", Color::DarkGray),
            };

            let row_rect = Rect::new(tray_area.x, row_y, tray_area.width, 1);
            targets.subagent_rows.push((id.to_string(), row_rect));

            tray_lines.push(Line::from(vec![
                Span::styled(format!(" {status_icon} "), Style::default().fg(status_color)),
                Span::styled(format!("{name:14}"), Style::default().fg(Color::White)),
                Span::styled(format!(" {target}"), Style::default().fg(Color::Rgb(100, 100, 105))),
            ]));
            row_y += 1;
        }

        f.render_widget(Paragraph::new(tray_lines).block(tray_block), tray_area);

        // 2. Chatbot Message Stream
        let chat_block = Block::default()
            .borders(Borders::RIGHT)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::Rgb(50, 50, 55)));

        let mut chat_lines = Vec::new();
        let total_msgs = chat_messages.len();
        let start_idx = total_msgs.saturating_sub(12 + chat_scroll);
        let end_idx = total_msgs.saturating_sub(chat_scroll);

        for msg in &chat_messages[start_idx..end_idx] {
            match msg {
                ChatMessage::User(text) => {
                    // Sleek user chat bubble with dark-gray background (#1e1e22)
                    let border_style = Style::default().fg(Color::Rgb(70, 70, 80));
                    let bg_style = Style::default().fg(Color::White).bg(Color::Rgb(30, 32, 36));

                    chat_lines.push(Line::from(vec![
                        Span::raw(" "),
                        Span::styled("╭─ you ────────────────────────────────╮", border_style),
                    ]));
                    for l in text.lines() {
                        chat_lines.push(Line::from(vec![
                            Span::raw(" "),
                            Span::styled("│ ", border_style),
                            Span::styled(format!(" {l} "), bg_style.add_modifier(Modifier::BOLD)),
                            Span::styled(" │", border_style),
                        ]));
                    }
                    chat_lines.push(Line::from(vec![
                        Span::raw(" "),
                        Span::styled("╰──────────────────────────────────────╯", border_style),
                    ]));
                }
                ChatMessage::Thinking { agent, thought } => {
                    chat_lines.push(Line::from(vec![
                        Span::styled(" ⠋ ", Style::default().fg(Color::Rgb(100, 100, 110))),
                        Span::styled(format!("[{agent} thinking]: "), Style::default().fg(Color::Rgb(120, 120, 130))),
                        Span::styled(thought, Style::default().fg(Color::Rgb(150, 150, 160)).add_modifier(Modifier::ITALIC)),
                    ]));
                }
                ChatMessage::ToolCall { tool, input, .. } => {
                    chat_lines.push(Line::from(vec![
                        Span::styled(" ❯ tool: ", Style::default().fg(Color::Rgb(100, 100, 110))),
                        Span::styled(format!("{tool} "), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                        Span::styled(format!("({input})"), Style::default().fg(Color::Rgb(120, 120, 130))),
                    ]));
                }
                ChatMessage::ToolResult { output, elapsed_ms, .. } => {
                    let ms_str = elapsed_ms.map(|ms| format!(" ({ms}ms)")).unwrap_or_default();
                    chat_lines.push(Line::from(vec![
                        Span::styled("   ✔ result: ", Style::default().fg(Color::Rgb(130, 190, 130))),
                        Span::styled(output, Style::default().fg(Color::Rgb(210, 210, 215))),
                        Span::styled(ms_str, Style::default().fg(Color::Rgb(100, 100, 105))),
                    ]));
                }
                ChatMessage::Agent { sender, text } => {
                    // Orchestrator / Agent has NO BOX - clean flowing markdown & latex
                    chat_lines.push(Line::from(vec![
                        Span::styled(format!("● {sender}"), Style::default().fg(Color::Rgb(85, 155, 255)).add_modifier(Modifier::BOLD)),
                    ]));

                    let parsed = parse_markdown(text);
                    for pl in parsed {
                        let mut spans = vec![Span::raw("  ")];
                        spans.extend(pl.spans);
                        chat_lines.push(Line::from(spans));
                    }
                }
                ChatMessage::System(text) => {
                    chat_lines.push(Line::from(vec![
                        Span::styled("● system: ", Style::default().fg(Color::Rgb(100, 100, 110))),
                        Span::styled(text, Style::default().fg(Color::Rgb(200, 200, 205))),
                    ]));
                }
            }
            chat_lines.push(Line::raw(""));
        }

        f.render_widget(Paragraph::new(chat_lines).block(chat_block), chunks[1]);

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
            let conf_text = Line::from(Span::styled(" [ ✓ Deploy Subagents ] ", Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD)));
            f.render_widget(Paragraph::new(conf_text).centered().block(conf_block), btn_conf_rect);

            let canc_block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(80, 80, 85)));
            let canc_text = Line::from(Span::styled(" [ ✗ Cancel ] ", Style::default().fg(Color::Rgb(150, 150, 155))));
            f.render_widget(Paragraph::new(canc_text).centered().block(canc_block), btn_canc_rect);

            targets.btn_confirm = Some(btn_conf_rect);
            targets.btn_cancel = Some(btn_canc_rect);
        }

        // 4. Selected Node Inspector with Clickable Action Buttons
        let node_block = Block::default()
            .borders(Borders::TOP | Borders::RIGHT)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::Rgb(50, 50, 55)));

        let node_area = chunks[3];
        let (node_lines, pause_rect, apply_rect) = if let Some(node) = selected_node {
            let status_str = if node.is_paused { "paused" } else { node.status.as_str() };
            let p_rect = Rect::new(node_area.x + 1, node_area.y + 3, 14.min(node_area.width.saturating_sub(2)), 1);
            let a_rect = Rect::new(node_area.x + 16, node_area.y + 3, 16.min(node_area.width.saturating_sub(17)), 1);

            let lines = vec![
                Line::from(vec![
                    Span::styled("node:   ", Style::default().fg(Color::Rgb(110, 110, 115))),
                    Span::styled(&node.id, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                    Span::styled(format!("  [{status_str}]"), Style::default().fg(if node.is_paused { Color::DarkGray } else { Color::White })),
                ]),
                Line::from(vec![
                    Span::styled("target: ", Style::default().fg(Color::Rgb(110, 110, 115))),
                    Span::styled(node.target_path.as_deref().unwrap_or("-"), Style::default().fg(Color::White)),
                ]),
                Line::from(vec![
                    Span::styled(if node.is_paused { " [ ▶ Resume ] " } else { " [ ⏸ Pause ] " }, Style::default().fg(Color::White).bg(Color::Rgb(38, 38, 42))),
                    Span::raw(" "),
                    Span::styled(" [ ✓ Apply Fix ] ", Style::default().fg(Color::White).bg(Color::Rgb(38, 38, 42))),
                ]),
            ];
            (lines, Some(p_rect), Some(a_rect))
        } else {
            let lines = vec![
                Line::from(Span::styled("click any node on graph to inspect", Style::default().fg(Color::Rgb(110, 110, 115)))),
                Line::from(Span::styled("or use arrow keys to navigate flow", Style::default().fg(Color::Rgb(80, 80, 85)))),
            ];
            (lines, None, None)
        };

        f.render_widget(Paragraph::new(node_lines).block(node_block), node_area);
        targets.btn_pause = pause_rect;
        targets.btn_apply = apply_rect;

        // 5. Interactive Chatbot Input Bar with Clickable [ Send ↵ ] Button
        let prompt_row = chunks[4];
        let input_split = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Min(10),
                Constraint::Length(10),
            ])
            .split(prompt_row);

        let input_rect = input_split[0];
        let send_rect = input_split[1];

        let prompt_block = Block::default()
            .borders(Borders::TOP | Borders::RIGHT)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::Rgb(50, 50, 55)));

        let prompt_display = if prompt_input.is_empty() {
            if awaiting_confirmation {
                vec![
                    Span::styled("> ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                    Span::styled("click [Deploy] or type 'y'... ", Style::default().fg(Color::Rgb(100, 100, 105))),
                    Span::styled("█", Style::default().fg(Color::White)),
                ]
            } else {
                vec![
                    Span::styled("> ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                    Span::styled("type message or click... ", Style::default().fg(Color::Rgb(100, 100, 105))),
                    Span::styled("█", Style::default().fg(Color::White)),
                ]
            }
        } else {
            vec![
                Span::styled("> ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                Span::styled(prompt_input, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                Span::styled("█", Style::default().fg(Color::White)),
            ]
        };

        f.render_widget(Paragraph::new(Line::from(prompt_display)).block(prompt_block), input_rect);

        // [ Send ↵ ] Button
        let send_block = Block::default()
            .borders(Borders::TOP | Borders::RIGHT)
            .border_style(Style::default().fg(Color::White));
        let send_text = Line::from(Span::styled(" Send ↵ ", Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD)));
        f.render_widget(Paragraph::new(send_text).centered().block(send_block), send_rect);

        targets.btn_send = Some(send_rect);

        targets
    }
}
