use rataflow::{Background, Controls, Flow, StepEdge, TextContent};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame,
};

pub struct GraphView;

impl GraphView {
    pub fn render(f: &mut Frame, area: Rect, flow: &mut Flow<TextContent, StepEdge>, is_idle: bool) {
        if is_idle {
            let empty_block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Plain)
                .border_style(Style::default().fg(Color::Rgb(50, 50, 55)))
                .title(Span::styled(" workflow graph ", Style::default().fg(Color::White)));

            let empty_msg = vec![
                Line::from(""),
                Line::from(""),
                Line::from(Span::styled("workspace idle", Style::default().fg(Color::White).add_modifier(Modifier::BOLD))),
                Line::from(""),
                Line::from(Span::styled("no active defense workflow or security audit in progress.", Style::default().fg(Color::DarkGray))),
                Line::from(""),
                Line::from(vec![
                    Span::styled("press ", Style::default().fg(Color::DarkGray)),
                    Span::styled("[space]", Style::default().fg(Color::White)),
                    Span::styled(" or type ", Style::default().fg(Color::DarkGray)),
                    Span::styled("/scan", Style::default().fg(Color::White)),
                    Span::styled(" to build dynamic analysis graph and execute security audit.", Style::default().fg(Color::DarkGray)),
                ]),
            ];
            let p = Paragraph::new(empty_msg)
                .block(empty_block)
                .alignment(ratatui::layout::Alignment::Center);
            f.render_widget(p, area);
            return;
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(8),
                Constraint::Length(4),
            ])
            .split(area);

        // 1. Rataflow Canvas
        let canvas_area = chunks[0];
        f.render_widget(Background::new(flow), canvas_area);
        f.render_widget(flow as &mut Flow<TextContent, StepEdge>, canvas_area);
        f.render_widget(Controls::new(flow), canvas_area);

        // 2. Minimalist Monochromatic Legend
        let legend_area = chunks[1];
        let legend_block = Block::default()
            .borders(Borders::TOP)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::DarkGray));

        let legend_text = vec![
            Line::from(vec![
                Span::styled("flow: ", Style::default().fg(Color::DarkGray)),
                Span::styled("orchestrator", Style::default().fg(Color::White)),
                Span::styled(" -> ", Style::default().fg(Color::DarkGray)),
                Span::styled("folders", Style::default().fg(Color::Gray)),
                Span::styled(" -> ", Style::default().fg(Color::DarkGray)),
                Span::styled("files", Style::default().fg(Color::Gray)),
                Span::styled(" -> ", Style::default().fg(Color::DarkGray)),
                Span::styled("subagents", Style::default().fg(Color::White)),
                Span::styled(" -> ", Style::default().fg(Color::DarkGray)),
                Span::styled("remediation", Style::default().fg(Color::Gray)),
                Span::styled(" -> ", Style::default().fg(Color::DarkGray)),
                Span::styled("gate", Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("edges: ", Style::default().fg(Color::DarkGray)),
                Span::styled("animating = running agent  │  static = pending/completed  │  click node to pause/inspect", Style::default().fg(Color::DarkGray)),
            ]),
        ];

        f.render_widget(Paragraph::new(legend_text).block(legend_block), legend_area);
    }
}
