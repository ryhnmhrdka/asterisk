use rataflow::{Background, Controls, Flow, StepEdge, TextContent};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame,
};

pub struct GraphView;

impl GraphView {
    pub fn render(f: &mut Frame, area: Rect, flow: &mut Flow<TextContent, StepEdge>) {
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
