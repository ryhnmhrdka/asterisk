use crate::types::{ChatMessage, SproutedNodeInfo};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame,
};

pub struct SidebarView;

impl SidebarView {
    pub fn render(
        f: &mut Frame,
        area: Rect,
        chat_messages: &[ChatMessage],
        selected_node: Option<&SproutedNodeInfo>,
        prompt_input: &str,
        awaiting_confirmation: bool,
    ) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(8),
                Constraint::Length(8),
                Constraint::Length(3),
            ])
            .split(area);

        // 1. Chatbot Conversation History
        let chat_block = Block::default()
            .borders(Borders::RIGHT)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::DarkGray));

        let mut chat_lines = Vec::new();
        // Show last ~10 messages
        let skip_count = chat_messages.len().saturating_sub(12);
        for msg in chat_messages.iter().skip(skip_count) {
            let sender_style = if msg.is_user {
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray).add_modifier(Modifier::BOLD)
            };

            let prefix = if msg.is_user { "> user" } else { "● agent" };
            chat_lines.push(Line::from(vec![
                Span::styled(format!("{prefix}: "), sender_style),
                Span::styled(&msg.text, Style::default().fg(if msg.is_user { Color::White } else { Color::Gray })),
            ]));
            chat_lines.push(Line::raw(""));
        }

        if awaiting_confirmation {
            chat_lines.push(Line::from(vec![
                Span::styled("? confirm: ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                Span::styled("type 'y' or press [enter] to proceed with deployment", Style::default().fg(Color::White)),
            ]));
        }

        f.render_widget(Paragraph::new(chat_lines).block(chat_block), chunks[0]);

        // 2. Selected Node Inspector
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
                    Span::styled("task:   ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&node.label, Style::default().fg(Color::Gray)),
                ]),
                Line::from(vec![
                    Span::styled("target: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(node.target_path.as_deref().unwrap_or("-"), Style::default().fg(Color::White)),
                ]),
                Line::from(vec![
                    Span::styled("action: ", Style::default().fg(Color::DarkGray)),
                    Span::styled("[p] toggle pause/resume  │  [a] apply patch", Style::default().fg(Color::DarkGray)),
                ]),
            ]
        } else {
            vec![
                Line::from(Span::styled("click any node on graph to inspect", Style::default().fg(Color::DarkGray))),
                Line::from(Span::styled("or use arrow keys to navigate flow", Style::default().fg(Color::DarkGray))),
            ]
        };

        f.render_widget(Paragraph::new(node_lines).block(node_block), chunks[1]);

        // 3. Interactive Prompt Input Bar
        let prompt_block = Block::default()
            .borders(Borders::TOP | Borders::RIGHT)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::DarkGray));

        let prompt_display = if prompt_input.is_empty() {
            if awaiting_confirmation {
                vec![
                    Span::styled("> ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                    Span::styled("type 'y' to confirm / 'n' to cancel... ", Style::default().fg(Color::DarkGray)),
                    Span::styled("█", Style::default().fg(Color::White)),
                ]
            } else {
                vec![
                    Span::styled("> ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                    Span::styled("type command or message... ", Style::default().fg(Color::DarkGray)),
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

        f.render_widget(Paragraph::new(Line::from(prompt_display)).block(prompt_block), chunks[2]);
    }
}

