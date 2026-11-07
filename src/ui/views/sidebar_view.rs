use crate::types::{ChatMessage, SproutedNodeInfo};
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
}

pub struct SidebarView;

impl SidebarView {
    pub fn render(
        f: &mut Frame,
        area: Rect,
        chat_messages: &[ChatMessage],
        selected_node: Option<&SproutedNodeInfo>,
        prompt_input: &str,
        awaiting_confirmation: bool,
    ) -> SidebarClickTargets {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(8),
                Constraint::Length(awaiting_confirmation.then_some(3).unwrap_or(0)),
                Constraint::Length(7),
                Constraint::Length(3),
            ])
            .split(area);

        let mut targets = SidebarClickTargets {
            btn_confirm: None,
            btn_cancel: None,
            btn_pause: None,
            btn_apply: None,
            btn_send: None,
        };

        // 1. Chatbot Conversation History (Chat Bubbles style)
        let chat_block = Block::default()
            .borders(Borders::RIGHT)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::DarkGray));

        let mut chat_lines = Vec::new();
        let skip_count = chat_messages.len().saturating_sub(6);

        for msg in chat_messages.iter().skip(skip_count) {
            if msg.is_user {
                // User chat bubble (right indented, bold white)
                chat_lines.push(Line::from(vec![
                    Span::raw("   "),
                    Span::styled("┌─ you ────────────────────────┐", Style::default().fg(Color::White)),
                ]));
                chat_lines.push(Line::from(vec![
                    Span::raw("   "),
                    Span::styled("│ ", Style::default().fg(Color::White)),
                    Span::styled(&msg.text, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                ]));
                chat_lines.push(Line::from(vec![
                    Span::raw("   "),
                    Span::styled("└──────────────────────────────┘", Style::default().fg(Color::White)),
                ]));
            } else {
                // Agent chat bubble (classic dark gray frame, white text)
                chat_lines.push(Line::from(Span::styled(format!("┌─ {} ──────────────────────", msg.sender), Style::default().fg(Color::DarkGray))));
                for line in msg.text.lines() {
                    chat_lines.push(Line::from(vec![
                        Span::styled("│ ", Style::default().fg(Color::DarkGray)),
                        Span::styled(line, Style::default().fg(Color::Gray)),
                    ]));
                }
                chat_lines.push(Line::from(Span::styled("└──────────────────────────────", Style::default().fg(Color::DarkGray))));
            }
            chat_lines.push(Line::raw(""));
        }

        f.render_widget(Paragraph::new(chat_lines).block(chat_block), chunks[0]);

        // 2. Clickable Confirmation Buttons (When Awaiting Confirmation)
        if awaiting_confirmation {
            let confirm_area = chunks[1];
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
                .border_style(Style::default().fg(Color::DarkGray));
            let canc_text = Line::from(Span::styled(" [ ✗ Cancel ] ", Style::default().fg(Color::Gray)));
            f.render_widget(Paragraph::new(canc_text).centered().block(canc_block), btn_canc_rect);

            targets.btn_confirm = Some(btn_conf_rect);
            targets.btn_cancel = Some(btn_canc_rect);
        }

        // 3. Selected Node Inspector with Clickable Action Buttons
        let node_block = Block::default()
            .borders(Borders::TOP | Borders::RIGHT)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::DarkGray));

        let node_lines = if let Some(node) = selected_node {
            let status_str = if node.is_paused { "paused" } else { node.status.as_str() };
            vec![
                Line::from(vec![
                    Span::styled("node:   ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&node.id, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                    Span::styled(format!("  [{status_str}]"), Style::default().fg(if node.is_paused { Color::DarkGray } else { Color::White })),
                ]),
                Line::from(vec![
                    Span::styled("target: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(node.target_path.as_deref().unwrap_or("-"), Style::default().fg(Color::White)),
                ]),
                Line::from(vec![
                    Span::styled("task:   ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&node.label, Style::default().fg(Color::Gray)),
                ]),
                Line::from(vec![
                    Span::styled("actions: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(if node.is_paused { " [ ▶ Resume ] " } else { " [ ⏸ Pause ] " }, Style::default().fg(Color::White).bg(Color::Rgb(40, 40, 40))),
                    Span::raw(" "),
                    Span::styled(" [ ✓ Apply Fix ] ", Style::default().fg(Color::White).bg(Color::Rgb(40, 40, 40))),
                ]),
            ]
        } else {
            vec![
                Line::from(Span::styled("click any node on graph to inspect", Style::default().fg(Color::DarkGray))),
                Line::from(Span::styled("or use arrow keys to navigate flow", Style::default().fg(Color::DarkGray))),
            ]
        };

        let node_area = chunks[2];
        f.render_widget(Paragraph::new(node_lines).block(node_block), node_area);

        // Store action button rects inside the inspector box
        let btn_y = node_area.y + 4;
        if btn_y < node_area.y + node_area.height {
            targets.btn_pause = Some(Rect::new(node_area.x + 9, btn_y, 14, 1));
            targets.btn_apply = Some(Rect::new(node_area.x + 24, btn_y, 16, 1));
        }

        // 4. Interactive Chatbot Input Bar with Clickable [ Send ↵ ] Button
        let prompt_row = chunks[3];
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
            .border_style(Style::default().fg(Color::DarkGray));

        let prompt_display = if prompt_input.is_empty() {
            if awaiting_confirmation {
                vec![
                    Span::styled("> ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                    Span::styled("click [Deploy] or type 'y'... ", Style::default().fg(Color::DarkGray)),
                    Span::styled("█", Style::default().fg(Color::White)),
                ]
            } else {
                vec![
                    Span::styled("> ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                    Span::styled("type message or click... ", Style::default().fg(Color::DarkGray)),
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
