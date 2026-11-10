use crate::types::AiProvider;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
    Frame,
};

#[allow(dead_code)]
pub struct ModalClickTargets {
    pub provider_buttons: Vec<(AiProvider, Rect)>,
    pub model_preset_buttons: Vec<(String, Rect)>,
    pub field_rects: Vec<(usize, Rect)>,
    pub btn_setup_credentials: Option<Rect>,
    pub btn_save: Option<Rect>,
    pub btn_cancel: Option<Rect>,
}

pub struct ModalView;

impl ModalView {
    #[allow(dead_code)]
    pub fn render_key_modal(
        f: &mut Frame,
        area: Rect,
        provider: AiProvider,
        input_key: &str,
        error_msg: Option<&str>,
    ) {
        let _ = Self::render_single_input_modal(
            f,
            area,
            &format!("API Key ({})", provider.name()),
            "Enter API key:",
            input_key,
            true,
            error_msg,
        );
    }

    #[allow(dead_code)]
    pub fn render_config_modal(
        f: &mut Frame,
        area: Rect,
        active_provider: AiProvider,
        _active_field: usize,
        _model_input: &str,
        key_input: &str,
        _url_input: &str,
        error_msg: Option<&str>,
    ) -> ModalClickTargets {
        Self::render_single_input_modal(
            f,
            area,
            &format!("API Key ({})", active_provider.name()),
            "Enter API key:",
            key_input,
            true,
            error_msg,
        )
    }

    /// Single Clean List: Select AI Provider
    pub fn render_provider_list(
        f: &mut Frame,
        area: Rect,
        selected_index: usize,
    ) -> ModalClickTargets {
        let modal_width = 54.min(area.width.saturating_sub(4));
        let modal_height = 12.min(area.height.saturating_sub(2));

        let x = (area.width.saturating_sub(modal_width)) / 2;
        let y = (area.height.saturating_sub(modal_height)) / 2;
        let modal_rect = Rect::new(x, y, modal_width, modal_height);

        f.render_widget(Clear, modal_rect);
        let bg_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Rgb(50, 52, 64)))
            .title(Span::styled(
                "  Select AI Provider  ",
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ))
            .style(Style::default().bg(Color::Rgb(14, 15, 19)));
        f.render_widget(bg_block, modal_rect);

        let inner_chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Min(6),    // List of providers
                Constraint::Length(1), // Footer hotkeys
            ])
            .split(modal_rect);

        let mut targets = ModalClickTargets {
            provider_buttons: Vec::new(),
            model_preset_buttons: Vec::new(),
            field_rects: Vec::new(),
            btn_setup_credentials: None,
            btn_save: None,
            btn_cancel: None,
        };

        let providers = [
            (AiProvider::AnthropicClaude, "1. Anthropic Claude"),
            (AiProvider::OpenAiGpt4o, "2. OpenAI"),
            (AiProvider::GoogleGemini, "3. Google Gemini"),
            (AiProvider::DeepSeek, "4. DeepSeek"),
            (AiProvider::OllamaLocal, "5. Ollama (Local)"),
            (AiProvider::Custom, "6. Custom Provider"),
        ];

        let mut lines = Vec::new();
        let list_area = inner_chunks[0];
        let mut row_y = list_area.y;

        for (i, (prov, label)) in providers.iter().enumerate() {
            let is_sel = i == selected_index;
            let item_rect = Rect::new(list_area.x, row_y, list_area.width, 1);
            targets.provider_buttons.push((*prov, item_rect));
            row_y += 1;

            if is_sel {
                lines.push(Line::from(vec![
                    Span::styled("  ▸ ", Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD)),
                    Span::styled(format!("{:<width$}", label, width = (list_area.width.saturating_sub(6)) as usize), Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD)),
                ]));
            } else {
                lines.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(*label, Style::default().fg(Color::Rgb(175, 178, 188))),
                ]));
            }
        }
        f.render_widget(Paragraph::new(lines), list_area);

        // Footer
        let footer_line = Line::from(vec![
            Span::raw("  "),
            Span::styled("[↑/↓ or 1..6]", Style::default().fg(Color::White).bg(Color::Rgb(26, 28, 36))),
            Span::styled(" Select   ", Style::default().fg(Color::Rgb(110, 112, 120))),
            Span::styled("[Enter]", Style::default().fg(Color::White).bg(Color::Rgb(26, 28, 36))),
            Span::styled(" Next   ", Style::default().fg(Color::Rgb(110, 112, 120))),
            Span::styled("[Esc]", Style::default().fg(Color::White).bg(Color::Rgb(26, 28, 36))),
            Span::styled(" Cancel", Style::default().fg(Color::Rgb(110, 112, 120))),
        ]);
        f.render_widget(Paragraph::new(footer_line), inner_chunks[1]);

        targets
    }

    /// Single Clean List: Select Model for Active Provider
    pub fn render_model_list(
        f: &mut Frame,
        area: Rect,
        active_provider: AiProvider,
        selected_index: usize,
    ) -> ModalClickTargets {
        let presets = active_provider.preset_models();
        let list_len = presets.len().max(1);
        let modal_width = 56.min(area.width.saturating_sub(4));
        let modal_height = ((list_len + 5) as u16).min(area.height.saturating_sub(2)).max(9);

        let x = (area.width.saturating_sub(modal_width)) / 2;
        let y = (area.height.saturating_sub(modal_height)) / 2;
        let modal_rect = Rect::new(x, y, modal_width, modal_height);

        f.render_widget(Clear, modal_rect);
        let title_text = format!("  Select Model ({})  ", active_provider.name());
        let bg_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Rgb(50, 52, 64)))
            .title(Span::styled(
                title_text,
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ))
            .style(Style::default().bg(Color::Rgb(14, 15, 19)));
        f.render_widget(bg_block, modal_rect);

        let inner_chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Min(4),    // List of models
                Constraint::Length(1), // Footer hotkeys
            ])
            .split(modal_rect);

        let mut targets = ModalClickTargets {
            provider_buttons: Vec::new(),
            model_preset_buttons: Vec::new(),
            field_rects: Vec::new(),
            btn_setup_credentials: None,
            btn_save: None,
            btn_cancel: None,
        };

        let mut lines = Vec::new();
        let list_area = inner_chunks[0];
        let mut row_y = list_area.y;

        for (i, model_name) in presets.iter().enumerate() {
            let is_sel = i == selected_index;
            let item_rect = Rect::new(list_area.x, row_y, list_area.width, 1);
            targets.model_preset_buttons.push((model_name.to_string(), item_rect));
            row_y += 1;

            if is_sel {
                lines.push(Line::from(vec![
                    Span::styled("  ▸ ", Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD)),
                    Span::styled(format!("{:<width$}", model_name, width = (list_area.width.saturating_sub(6)) as usize), Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD)),
                ]));
            } else {
                lines.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(*model_name, Style::default().fg(Color::Rgb(175, 178, 188))),
                ]));
            }
        }
        f.render_widget(Paragraph::new(lines), list_area);

        // Footer
        let footer_line = Line::from(vec![
            Span::raw("  "),
            Span::styled("[↑/↓]", Style::default().fg(Color::White).bg(Color::Rgb(26, 28, 36))),
            Span::styled(" Select   ", Style::default().fg(Color::Rgb(110, 112, 120))),
            Span::styled("[Enter]", Style::default().fg(Color::White).bg(Color::Rgb(26, 28, 36))),
            Span::styled(" Confirm   ", Style::default().fg(Color::Rgb(110, 112, 120))),
            Span::styled("[Esc]", Style::default().fg(Color::White).bg(Color::Rgb(26, 28, 36))),
            Span::styled(" Close", Style::default().fg(Color::Rgb(110, 112, 120))),
        ]);
        f.render_widget(Paragraph::new(footer_line), inner_chunks[1]);

        targets
    }

    /// Single Clean Input Modal (Used for API Key or Base URL)
    pub fn render_single_input_modal(
        f: &mut Frame,
        area: Rect,
        title: &str,
        label: &str,
        input_value: &str,
        is_masked: bool,
        error_msg: Option<&str>,
    ) -> ModalClickTargets {
        let modal_width = 58.min(area.width.saturating_sub(4));
        let modal_height = 8.min(area.height.saturating_sub(2));

        let x = (area.width.saturating_sub(modal_width)) / 2;
        let y = (area.height.saturating_sub(modal_height)) / 2;
        let modal_rect = Rect::new(x, y, modal_width, modal_height);

        f.render_widget(Clear, modal_rect);
        let bg_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Rgb(50, 52, 64)))
            .title(Span::styled(
                format!("  {title}  "),
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ))
            .style(Style::default().bg(Color::Rgb(14, 15, 19)));
        f.render_widget(bg_block, modal_rect);

        let inner_chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(1), // Label / error
                Constraint::Length(2), // Single input slot
                Constraint::Length(1), // Footer buttons
            ])
            .split(modal_rect);

        let mut targets = ModalClickTargets {
            provider_buttons: Vec::new(),
            model_preset_buttons: Vec::new(),
            field_rects: Vec::new(),
            btn_setup_credentials: None,
            btn_save: None,
            btn_cancel: None,
        };

        // Row 1: Label or error message
        let top_msg = if let Some(err) = error_msg {
            Line::from(vec![
                Span::raw("  "),
                Span::styled("✖ ", Style::default().fg(Color::Rgb(255, 120, 120))),
                Span::styled(err, Style::default().fg(Color::Rgb(255, 120, 120))),
            ])
        } else {
            Line::from(vec![
                Span::raw("  "),
                Span::styled(label, Style::default().fg(Color::Rgb(140, 142, 150))),
            ])
        };
        f.render_widget(Paragraph::new(top_msg), inner_chunks[0]);

        // Row 2: Clean single input slot
        let input_rect = inner_chunks[1];
        let input_block = Block::default().style(Style::default().bg(Color::Rgb(22, 24, 30)));
        f.render_widget(input_block, input_rect);

        let display_val = if is_masked && input_value.len() > 8 {
            format!("{}...{} [configured]", &input_value[..4], &input_value[input_value.len() - 4..])
        } else if input_value.is_empty() {
            "paste or type here...".to_string()
        } else {
            input_value.to_string()
        };

        let input_line = Line::from(vec![
            Span::raw("  "),
            Span::styled("▸ ", Style::default().fg(Color::Rgb(140, 200, 255)).add_modifier(Modifier::BOLD)),
            Span::styled(
                display_val,
                if input_value.is_empty() {
                    Style::default().fg(Color::Rgb(100, 102, 110))
                } else {
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
                },
            ),
            Span::styled("█", Style::default().fg(Color::White)),
        ]);
        f.render_widget(Paragraph::new(vec![Line::raw(""), input_line]), input_rect);

        // Row 3: Footer with Save & Cancel
        let footer_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Min(10),
                Constraint::Length(14),
                Constraint::Length(1),
                Constraint::Length(12),
            ])
            .split(inner_chunks[2]);

        let hotkey_info = Line::from(vec![
            Span::raw("  "),
            Span::styled("[Enter]", Style::default().fg(Color::White).bg(Color::Rgb(26, 28, 36))),
            Span::styled(" Save", Style::default().fg(Color::Rgb(110, 112, 120))),
        ]);
        f.render_widget(Paragraph::new(hotkey_info), footer_chunks[0]);

        let btn_save_rect = footer_chunks[1];
        targets.btn_save = Some(btn_save_rect);
        let save_span = Span::styled(" Save [↵] ", Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD));
        f.render_widget(Paragraph::new(Line::from(save_span)).centered(), btn_save_rect);

        let btn_cancel_rect = footer_chunks[3];
        targets.btn_cancel = Some(btn_cancel_rect);
        let cancel_span = Span::styled(" Cancel [Esc] ", Style::default().fg(Color::Rgb(170, 172, 180)).bg(Color::Rgb(30, 32, 40)));
        f.render_widget(Paragraph::new(Line::from(cancel_span)).centered(), btn_cancel_rect);

        targets
    }
}
