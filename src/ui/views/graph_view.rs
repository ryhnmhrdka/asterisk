use rataflow::{Background, Controls, Flow, StepEdge, TextContent};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Paragraph},
    Frame,
};

pub struct GraphView;

impl GraphView {
    pub fn render(f: &mut Frame, area: Rect, flow: &mut Flow<TextContent, StepEdge>, is_idle: bool) {
        if is_idle {
            let empty_block = Block::default()
                .style(Style::default().bg(Color::Rgb(14, 15, 19)));

            let empty_msg = vec![
                Line::from(""),
                Line::from(""),
                Line::from(""),
                Line::from(vec![
                    Span::styled(" ● ", Style::default().fg(Color::Rgb(140, 200, 255))),
                    Span::styled("Workspace Defense Idle", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(""),
                Line::from(Span::styled("No active autonomous defense workflow or security audit in progress.", Style::default().fg(Color::Rgb(110, 112, 120)))),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Press ", Style::default().fg(Color::Rgb(110, 112, 120))),
                    Span::styled(" [Space] ", Style::default().fg(Color::White).bg(Color::Rgb(28, 30, 38))),
                    Span::styled(" or type ", Style::default().fg(Color::Rgb(110, 112, 120))),
                    Span::styled(" /scan ", Style::default().fg(Color::White).bg(Color::Rgb(28, 30, 38))),
                    Span::styled(" to construct dynamic AST graph and execute defense audit.", Style::default().fg(Color::Rgb(110, 112, 120))),
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

        // 2. Sleek filled legend, NO ASCII wireframes
        let legend_area = chunks[1];
        let legend_block = Block::default()
            .style(Style::default().bg(Color::Rgb(14, 15, 19)));

        let legend_text = vec![
            Line::from(vec![
                Span::raw(" "),
                Span::styled("flow: ", Style::default().fg(Color::Rgb(100, 102, 110))),
                Span::styled("orchestrator", Style::default().fg(Color::White)),
                Span::styled("  ●  ", Style::default().fg(Color::Rgb(60, 62, 70))),
                Span::styled("folders", Style::default().fg(Color::Rgb(150, 152, 160))),
                Span::styled("  ●  ", Style::default().fg(Color::Rgb(60, 62, 70))),
                Span::styled("files", Style::default().fg(Color::Rgb(150, 152, 160))),
                Span::styled("  ●  ", Style::default().fg(Color::Rgb(60, 62, 70))),
                Span::styled("subagents", Style::default().fg(Color::White)),
                Span::styled("  ●  ", Style::default().fg(Color::Rgb(60, 62, 70))),
                Span::styled("remediation", Style::default().fg(Color::Rgb(150, 152, 160))),
                Span::styled("  ●  ", Style::default().fg(Color::Rgb(60, 62, 70))),
                Span::styled("gate", Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::raw(" "),
                Span::styled("edges: ", Style::default().fg(Color::Rgb(100, 102, 110))),
                Span::styled("animating = running  │  static = completed  │  click node to pause/inspect", Style::default().fg(Color::Rgb(110, 112, 120))),
            ]),
        ];

        f.render_widget(Paragraph::new(legend_text).block(legend_block), legend_area);
    }
}
