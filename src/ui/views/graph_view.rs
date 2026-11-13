use crate::ui::theme::th;
use crate::orchestrator::graph::AgentNodeContent;
use rataflow::{
    Background, BackgroundStyle, BackgroundVariant, Controls, ControlsOrientation,
    ControlsPosition, ControlsStyle, Flow, MiniMap, MiniMapPosition, MiniMapStyle, StepEdge,
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Paragraph, Wrap},
    Frame,
};

pub struct GraphView;

impl GraphView {
    pub fn render(f: &mut Frame, area: Rect, flow: &mut Flow<AgentNodeContent, StepEdge>, is_idle: bool) {
        if is_idle {
            let empty_block = Block::default()
                .style(Style::default().bg(th().bg));

            let empty_msg = vec![
                Line::from(""),
                Line::from(""),
                Line::from(""),
                Line::from(vec![
                    Span::styled(" [●] ", Style::default().fg(th().primary)),
                    Span::styled("Autonomous Workspace Defense Idle", Style::default().fg(th().fg).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(""),
                Line::from(Span::styled("No active autonomous defense workflow or security audit currently executing.", Style::default().fg(th().text_muted))),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Press ", Style::default().fg(th().text_muted)),
                    Span::styled(" [Space] ", Style::default().fg(th().fg).bg(th().element).add_modifier(Modifier::BOLD)),
                    Span::styled(" or enter ", Style::default().fg(th().text_muted)),
                    Span::styled(" /audit ", Style::default().fg(th().primary).bg(th().element).add_modifier(Modifier::BOLD)),
                    Span::styled(" in the CLI prompt to synthesize AST DAG and start security orchestration.", Style::default().fg(th().text_muted)),
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
                Constraint::Length(5),
            ])
            .split(area);

        // 1. Rataflow Canvas
        let canvas_area = chunks[0];

        // Background dots
        let bg_style = BackgroundStyle::default()
            .with_pattern_color(th().element_hi)
            .with_bg_color(th().bg);
        flow.theme = rataflow::Theme::Custom(th().flow_palette());
        let bg = Background::new(flow)
            .variant(BackgroundVariant::Dots)
            .gap(4, 2)
            .style(bg_style);
        f.render_widget(bg, canvas_area);

        // Flow Graph
        f.render_widget(flow as &mut Flow<AgentNodeContent, StepEdge>, canvas_area);

        // Controls with clear shortcuts HUD
        let controls_style = ControlsStyle::default()
            .with_border_style(Style::default().fg(th().border))
            .with_button_style(Style::default().fg(th().fg).add_modifier(Modifier::BOLD))
            .with_hint_style(Style::default().fg(th().primary))
            .with_show_hints(true);

        let controls_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(th().border))
            .style(Style::default().bg(th().surface))
            .title(Line::from(vec![
                Span::styled(" [controls] ", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
            ]));

        let controls = Controls::new(flow)
            .position(ControlsPosition::BottomLeft)
            .orientation(ControlsOrientation::Horizontal)
            .style(controls_style)
            .block(controls_block);
        f.render_widget(controls, canvas_area);

        // MiniMap (Radar)
        let minimap_style = MiniMapStyle::default()
            .with_bg_color(th().surface)
            .with_node_color(th().border_hi)
            .with_selected_node_color(th().info)
            .with_viewport_color(th().element_hi);

        let minimap_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(th().border))
            .title(Line::from(vec![
                Span::styled(" [radar] ", Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
            ]));

        let minimap = MiniMap::new(flow)
            .position(MiniMapPosition::BottomRight)
            .size(24, 7)
            .style(minimap_style)
            .block(minimap_block);
        f.render_widget(minimap, canvas_area);

        // 2. Styled rounded block with balanced layout and explicit shortcut guide
        let legend_area = chunks[1];
        let legend_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(th().border))
            .style(Style::default().bg(th().bg))
            .title(Line::from(vec![
                Span::styled(" [flow legend & architecture guide] ", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
            ]));

        let legend_text = vec![
            Line::from(vec![
                Span::styled("  ROLES:  ", Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
                Span::styled("[#] orch", Style::default().fg(th().primary)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("[/] dir", Style::default().fg(th().text_sub)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("[.] file", Style::default().fg(th().text_sub)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("[>] subagent", Style::default().fg(th().primary)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("[!] remedy", Style::default().fg(th().destructive)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("[✓] verify", Style::default().fg(th().success)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("[#] gate", Style::default().fg(th().warning)),
            ]),
            Line::from(vec![
                Span::styled("  STATES: ", Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
                Span::styled("● running (live)", Style::default().fg(th().success)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("○ idle", Style::default().fg(th().text_muted)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("✓ passed", Style::default().fg(th().success)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("! vuln alert", Style::default().fg(th().destructive)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("■ paused", Style::default().fg(th().warning)),
            ]),
            Line::from(vec![
                Span::styled("  CANVAS: ", Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
                Span::styled("[+] Zoom In", Style::default().fg(th().fg)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("[-] Zoom Out", Style::default().fg(th().fg)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("[0] Fit View", Style::default().fg(th().fg)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("[h/j/k/l] Pan Canvas", Style::default().fg(th().fg)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("[Space] Pause/Resume Node", Style::default().fg(th().primary)),
            ]),
        ];

        f.render_widget(Paragraph::new(legend_text).wrap(Wrap { trim: false }).block(legend_block), legend_area);
    }
}
