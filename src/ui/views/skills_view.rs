use crate::types::InteractiveSkill;
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

pub struct SkillsView;

impl SkillsView {
    pub fn render(f: &mut Frame, area: Rect, skills: &[InteractiveSkill]) {
        let block = Block::default()
            .borders(Borders::NONE);

        let mut lines = Vec::new();
        lines.push(Line::from(vec![
            Span::styled("interactive skills library  ::  dynamic sub-agent capabilities", Style::default().fg(Color::DarkGray)),
        ]));
        lines.push(Line::raw(""));

        for skill in skills {
            let status_badge = if skill.active {
                Span::styled("[active]", Style::default().fg(Color::White).add_modifier(Modifier::BOLD))
            } else {
                Span::styled("[disabled]", Style::default().fg(Color::DarkGray))
            };

            lines.push(Line::from(vec![
                status_badge,
                Span::raw("  "),
                Span::styled(&skill.name, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                Span::styled(format!("  ({} / {} calls)", skill.category.to_lowercase(), skill.invocations), Style::default().fg(Color::DarkGray)),
            ]));

            lines.push(Line::from(vec![
                Span::raw("          "),
                Span::styled(&skill.description, Style::default().fg(Color::Gray)),
            ]));
            lines.push(Line::raw(""));
        }

        f.render_widget(Paragraph::new(lines).block(block), area);
    }
}
