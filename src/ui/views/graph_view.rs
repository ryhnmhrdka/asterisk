use crate::ui::theme::th;
use crate::orchestrator::graph::AgentNodeContent;
use rataflow::{
    Background, BackgroundStyle, BackgroundVariant, Controls, ControlsOrientation,
    ControlsPosition, ControlsStyle, Flow, MiniMap, MiniMapPosition, MiniMapStyle, StepEdge,
};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph, Wrap},
    Frame,
};

pub struct GraphView;

const ASTERISK_ASCII: &str = include_str!("../../../ascii.txt");

impl GraphView {
    pub fn render(f: &mut Frame, area: Rect, flow: &mut Flow<AgentNodeContent, StepEdge>, is_idle: bool) {
        if is_idle {
            let empty_block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(th().element))
                .style(Style::default().bg(th().surface));
            let inner = empty_block.inner(area);
            f.render_widget(empty_block, area);

            let mut empty_msg = Vec::new();

            let available_h = inner.height as usize;
            let text_h = 10;
            let star_lines: Vec<&str> = ASTERISK_ASCII
                .lines()
                .filter(|l| !l.trim().is_empty())
                .collect();

            let max_ascii = if available_h > text_h + 4 {
                available_h.saturating_sub(text_h + 2).min(star_lines.len())
            } else {
                0
            };

            let top_pad = available_h.saturating_sub(max_ascii + text_h) / 3;
            for _ in 0..top_pad {
                empty_msg.push(Line::raw(""));
            }

            if max_ascii > 0 {
                let skip = (star_lines.len().saturating_sub(max_ascii)) / 2;
                for line in star_lines.iter().skip(skip).take(max_ascii) {
                    empty_msg.push(Line::from(Span::styled(
                        *line,
                        Style::default().fg(th().primary),
                    )));
                }
                empty_msg.push(Line::raw(""));
            }

            empty_msg.push(Line::from(vec![
                Span::styled("✻ Asterisk Autonomous Defense Pipeline", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                Span::raw("   "),
                Span::styled(" ● STANDBY ", Style::default().fg(th().success).bg(th().element).add_modifier(Modifier::BOLD)),
            ]));
            empty_msg.push(Line::raw(""));
            empty_msg.push(Line::from(vec![
                Span::styled("Autonomous multi-agent orchestration harness is idle and ready for dispatch.", Style::default().fg(th().fg)),
            ]));
            empty_msg.push(Line::from(vec![
                Span::styled("When triggered, real-time AST dataflows, taint graphs, and subagents stream live here.", Style::default().fg(th().text_sub)),
            ]));
            empty_msg.push(Line::raw(""));
            empty_msg.push(Line::from(vec![
                Span::styled("Action Commands", Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
            ]));
            empty_msg.push(Line::from(vec![
                Span::styled("Press ", Style::default().fg(th().text_sub)),
                Span::styled("[Space]", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                Span::styled(" or enter ", Style::default().fg(th().text_sub)),
                Span::styled("/scan", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                Span::styled(" to synthesize AST DAG & start orchestration", Style::default().fg(th().text_sub)),
            ]));
            empty_msg.push(Line::from(vec![
                Span::styled("Press ", Style::default().fg(th().text_sub)),
                Span::styled("[Tab]", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                Span::styled(" or ", Style::default().fg(th().text_sub)),
                Span::styled("[Alt+1..5]", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                Span::styled(" to explore findings, patches, execution & skills", Style::default().fg(th().text_sub)),
            ]));
            empty_msg.push(Line::from(vec![
                Span::styled("Press ", Style::default().fg(th().text_sub)),
                Span::styled("[?]", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                Span::styled(" to open keyboard cheat sheet  •  ", Style::default().fg(th().text_sub)),
                Span::styled("/grill-me", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                Span::styled(" for architectural review", Style::default().fg(th().text_sub)),
            ]));

            f.render_widget(Paragraph::new(empty_msg).alignment(Alignment::Center), inner);
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
                Span::styled(" ⌥ Controls ", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
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
                Span::styled(" ⌖ Radar ", Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
            ]));

        let minimap = MiniMap::new(flow)
            .position(MiniMapPosition::BottomRight)
            .size(24, 7)
            .style(minimap_style)
            .block(minimap_block);
        f.render_widget(minimap, canvas_area);

        // 2. Styled rounded block with balanced layout and sleek modern guide
        let legend_area = chunks[1];
        let legend_block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(th().border))
            .style(Style::default().bg(th().bg))
            .title(Line::from(vec![
                Span::styled(" ◈ Architecture & Autonomous Flow Guide ", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
            ]));

        let spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let spinner_idx = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            / 80) as usize
            % spinner_frames.len();
        let spinner = spinner_frames[spinner_idx];

        let legend_text = vec![
            Line::from(vec![
                Span::styled("  ROLES:  ", Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
                Span::styled("◈ Orch", Style::default().fg(th().primary)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("📁 Dir", Style::default().fg(th().text_sub)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("📄 File", Style::default().fg(th().text_sub)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("⚡ Subagent", Style::default().fg(th().primary)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("🛡 Remedy", Style::default().fg(th().destructive)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("✓ Verifier", Style::default().fg(th().success)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("⚖ Gate", Style::default().fg(th().warning)),
            ]),
            Line::from(vec![
                Span::styled("  STATES: ", Style::default().fg(th().text_muted).add_modifier(Modifier::BOLD)),
                Span::styled(format!("{spinner} running (live)"), Style::default().fg(th().success)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("○ idle", Style::default().fg(th().text_muted)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("✓ clean", Style::default().fg(th().success)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("✕ vuln alert", Style::default().fg(th().destructive)),
                Span::styled("  •  ", Style::default().fg(th().border)),
                Span::styled("⏸ paused", Style::default().fg(th().warning)),
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
