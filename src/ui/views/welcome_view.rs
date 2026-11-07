use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame,
};

pub struct WelcomeView;

impl WelcomeView {
    pub fn render(f: &mut Frame, area: Rect, input_text: &str, default_path: &str) -> Rect {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(20),
                Constraint::Length(7),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(2),
                Constraint::Min(2),
            ])
            .split(area);

        // Minimalist monochrome ASCII logo
        let logo_lines = vec![
            Line::from(Span::styled(" _             _   _ _                                ", Style::default().fg(Color::White))),
            Line::from(Span::styled("| |____ _ _ __| |_(_) |____ _ __ _  _ _ __  ___ _ _   ", Style::default().fg(Color::White))),
            Line::from(Span::styled("| / / _` | '_ \\  _| | / / _` / _` || '_ \\/ -_) '_|  ", Style::default().fg(Color::White))),
            Line::from(Span::styled("|_\\_\\__,_| .__/\\__|_|_\\_\\__,_\\__,_(_) .__/\\___|_|    ", Style::default().fg(Color::White))),
            Line::from(Span::styled("         |_|                        |_|               ", Style::default().fg(Color::White))),
            Line::from(Span::styled("autonomous pre-production code defense harness", Style::default().fg(Color::DarkGray))),
        ];
        f.render_widget(Paragraph::new(logo_lines).centered(), chunks[1]);

        // Input prompt box
        let display_prompt = if input_text.is_empty() {
            vec![
                Span::styled("target directory: ", Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{default_path} "), Style::default().fg(Color::Gray)),
                Span::styled("█", Style::default().fg(Color::White)),
            ]
        } else {
            vec![
                Span::styled("target directory: ", Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{input_text} "), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                Span::styled("█", Style::default().fg(Color::White)),
            ]
        };

        let prompt_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::DarkGray));

        let input_area = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(25),
                Constraint::Percentage(50),
                Constraint::Percentage(25),
            ])
            .split(chunks[2])[1];

        f.render_widget(Paragraph::new(Line::from(display_prompt)).block(prompt_block), input_area);

        // Clickable Button: [ Start Audit ▶ ]
        let btn_area = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(35),
                Constraint::Percentage(30),
                Constraint::Percentage(35),
            ])
            .split(chunks[3])[1];

        let btn_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::White));

        let btn_text = Line::from(Span::styled(" [ Start Autonomous Audit ▶ ] ", Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD)));
        f.render_widget(Paragraph::new(btn_text).centered().block(btn_block), btn_area);

        // Hints
        let hint_line = Line::from(vec![
            Span::styled("click button or press ", Style::default().fg(Color::DarkGray)),
            Span::styled("[enter]", Style::default().fg(Color::White)),
            Span::styled(" to start  │  click or type path  │  ", Style::default().fg(Color::DarkGray)),
            Span::styled("[esc]", Style::default().fg(Color::White)),
            Span::styled(" to quit", Style::default().fg(Color::DarkGray)),
        ]);
        f.render_widget(Paragraph::new(hint_line).centered(), chunks[4]);

        btn_area
    }
}
