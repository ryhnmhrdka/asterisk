use crate::orchestrator::graph::AgentNodeContent;
use rataflow::{
    Background, BackgroundStyle, BackgroundVariant, Controls, ControlsOrientation,
    ControlsPosition, Flow, MiniMap, MiniMapPosition, MiniMapStyle, StepEdge,
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Paragraph, Wrap},
    Frame,
};

pub struct GraphView;

impl GraphView {
    pub fn render(f: &mut Frame, area: Rect, flow: &mut Flow<AgentNodeContent, StepEdge>, is_idle: bool) {
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

        // Background dots
        let bg_style = BackgroundStyle::default()
            .with_pattern_color(Color::Rgb(32, 35, 46))
            .with_bg_color(Color::Rgb(14, 15, 19));
        let bg = Background::new(flow)
            .variant(BackgroundVariant::Dots)
            .gap(4, 2)
            .style(bg_style);
        f.render_widget(bg, canvas_area);

        // Flow Graph
        f.render_widget(flow as &mut Flow<AgentNodeContent, StepEdge>, canvas_area);

        // Controls
        let controls = Controls::new(flow)
            .position(ControlsPosition::BottomLeft)
            .orientation(ControlsOrientation::Horizontal);
        f.render_widget(controls, canvas_area);

        // MiniMap (Radar)
        let minimap_style = MiniMapStyle::default()
            .with_bg_color(Color::Rgb(16, 18, 24))
            .with_node_color(Color::Rgb(70, 75, 95))
            .with_selected_node_color(Color::Rgb(100, 220, 255))
            .with_viewport_color(Color::Rgb(32, 40, 56));

        let minimap_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Rgb(55, 60, 75)))
            .title(Line::from(vec![
                Span::styled(" [radar] ", Style::default().fg(Color::Rgb(130, 135, 150)).add_modifier(Modifier::BOLD)),
            ]));

        let minimap = MiniMap::new(flow)
            .position(MiniMapPosition::BottomRight)
            .size(24, 7)
            .style(minimap_style)
            .block(minimap_block);
        f.render_widget(minimap, canvas_area);

        // 2. Sleek filled legend, monochrome technical ASCII glyphs
        let legend_area = chunks[1];
        let legend_block = Block::default()
            .style(Style::default().bg(Color::Rgb(14, 15, 19)));

        let legend_text = vec![
            Line::from(vec![
                Span::raw("  "),
                Span::styled("nodes: ", Style::default().fg(Color::Rgb(100, 102, 110))),
                Span::styled("[#] orch", Style::default().fg(Color::Rgb(140, 200, 255))),
                Span::styled("  •  ", Style::default().fg(Color::Rgb(60, 62, 70))),
                Span::styled("[/] dir", Style::default().fg(Color::Rgb(160, 165, 180))),
                Span::styled("  •  ", Style::default().fg(Color::Rgb(60, 62, 70))),
                Span::styled("[.] file", Style::default().fg(Color::Rgb(160, 165, 180))),
                Span::styled("  •  ", Style::default().fg(Color::Rgb(60, 62, 70))),
                Span::styled("[>] subagent", Style::default().fg(Color::Rgb(180, 170, 255))),
                Span::styled("  •  ", Style::default().fg(Color::Rgb(60, 62, 70))),
                Span::styled("[!] remedy", Style::default().fg(Color::Rgb(255, 160, 160))),
                Span::styled("  •  ", Style::default().fg(Color::Rgb(60, 62, 70))),
                Span::styled("[✓] verify", Style::default().fg(Color::Rgb(140, 220, 180))),
                Span::styled("  •  ", Style::default().fg(Color::Rgb(60, 62, 70))),
                Span::styled("[#] gate", Style::default().fg(Color::Rgb(255, 200, 90))),
            ]),
            Line::from(vec![
                Span::raw("  "),
                Span::styled("status: ", Style::default().fg(Color::Rgb(100, 102, 110))),
                Span::styled("● running  •  ○ idle  •  ✓ passed  •  ! vuln alert  •  Space to pause/steer", Style::default().fg(Color::Rgb(120, 125, 135))),
            ]),
        ];

        f.render_widget(Paragraph::new(legend_text).wrap(Wrap { trim: false }).block(legend_block), legend_area);
    }
}
