use crate::types::AiProvider;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
    Frame,
};

pub struct ModalClickTargets {
    pub provider_buttons: Vec<(AiProvider, Rect)>,
    pub model_preset_buttons: Vec<(String, Rect)>,
    pub field_rects: Vec<(usize, Rect)>, // 0: Provider, 1: Model, 2: Key, 3: URL
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
        let _ = Self::render_config_modal(
            f,
            area,
            provider,
            2,
            provider.default_model(),
            input_key,
            "",
            error_msg,
        );
    }

    pub fn render_config_modal(
        f: &mut Frame,
        area: Rect,
        active_provider: AiProvider,
        active_field: usize,
        model_input: &str,
        key_input: &str,
        url_input: &str,
        error_msg: Option<&str>,
    ) -> ModalClickTargets {
        let modal_width = 76.min(area.width.saturating_sub(4));
        let modal_height = 21.min(area.height.saturating_sub(2));

        let x = (area.width.saturating_sub(modal_width)) / 2;
        let y = (area.height.saturating_sub(modal_height)) / 2;
        let modal_rect = Rect::new(x, y, modal_width, modal_height);

        // 1. Clear underlying widgets and render dark background
        f.render_widget(Clear, modal_rect);
        let bg_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Rgb(220, 220, 220)))
            .title(Span::styled(
                " ⚙  AI PROVIDER & MODEL CONFIGURATION ",
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ))
            .style(Style::default().bg(Color::Rgb(14, 14, 16)));
        f.render_widget(bg_block, modal_rect);

        // Inner vertical layout
        let inner_chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(1), // Subtitle
                Constraint::Length(3), // Field 0: Provider selection
                Constraint::Length(4), // Field 1: Model presets & input
                Constraint::Length(3), // Field 2: API Key input
                Constraint::Length(3), // Field 3: Endpoint URL input
                Constraint::Length(1), // Error / status
                Constraint::Length(1), // Footer buttons
            ])
            .split(modal_rect);

        let mut targets = ModalClickTargets {
            provider_buttons: Vec::new(),
            model_preset_buttons: Vec::new(),
            field_rects: Vec::new(),
            btn_save: None,
            btn_cancel: None,
        };

        // Subtitle
        let subtitle = Line::from(vec![
            Span::styled("Configure AI providers, LLM models, credentials, and custom endpoints.", Style::default().fg(Color::DarkGray)),
        ]);
        f.render_widget(Paragraph::new(subtitle), inner_chunks[0]);

        // Field 0: Provider Row
        let prov_rect = inner_chunks[1];
        targets.field_rects.push((0, prov_rect));
        let prov_active = active_field == 0;
        let prov_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(if prov_active { Style::default().fg(Color::White) } else { Style::default().fg(Color::Rgb(60, 60, 65)) })
            .title(Span::styled(
                if prov_active { " ▶ [1] AI Provider: (press 1..6 or Tab) " } else { " [1] AI Provider " },
                if prov_active { Style::default().fg(Color::White).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Gray) },
            ));

        let providers = [
            (AiProvider::AnthropicClaude, "1. Claude"),
            (AiProvider::OpenAiGpt4o, "2. OpenAI"),
            (AiProvider::GoogleGemini, "3. Gemini"),
            (AiProvider::DeepSeek, "4. DeepSeek"),
            (AiProvider::OllamaLocal, "5. Ollama"),
            (AiProvider::Custom, "6. Custom"),
        ];

        let mut prov_spans = Vec::new();
        prov_spans.push(Span::raw(" "));
        let mut cur_x = prov_rect.x + 2;

        for (p, label) in providers {
            let is_selected = p == active_provider;
            let badge_len = (label.len() + 2) as u16;
            let btn_rect = Rect::new(cur_x, prov_rect.y + 1, badge_len, 1);
            targets.provider_buttons.push((p, btn_rect));
            cur_x += badge_len + 1;

            if is_selected {
                prov_spans.push(Span::styled(
                    format!(" {label} "),
                    Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD),
                ));
            } else {
                prov_spans.push(Span::styled(
                    format!(" {label} "),
                    Style::default().fg(Color::Gray).bg(Color::Rgb(28, 28, 32)),
                ));
            }
            prov_spans.push(Span::raw(" "));
        }
        f.render_widget(Paragraph::new(Line::from(prov_spans)).block(prov_block), prov_rect);

        // Field 1: Model Section (Presets + Input)
        let model_rect = inner_chunks[2];
        targets.field_rects.push((1, model_rect));
        let model_active = active_field == 1;
        let model_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(if model_active { Style::default().fg(Color::White) } else { Style::default().fg(Color::Rgb(60, 60, 65)) })
            .title(Span::styled(
                if model_active { " ▶ [2] Target Model: (type custom or click preset) " } else { " [2] Target Model " },
                if model_active { Style::default().fg(Color::White).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Gray) },
            ));

        let presets = active_provider.preset_models();
        let mut preset_spans = vec![Span::styled(" presets: ", Style::default().fg(Color::DarkGray))];
        let mut p_cur_x = model_rect.x + 11;
        for preset in presets {
            let is_match = *preset == model_input;
            let p_len = (preset.len() + 2) as u16;
            let p_rect = Rect::new(p_cur_x, model_rect.y + 1, p_len, 1);
            targets.model_preset_buttons.push((preset.to_string(), p_rect));
            p_cur_x += p_len + 1;

            if is_match {
                preset_spans.push(Span::styled(
                    format!("[{preset}]"),
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                ));
            } else {
                preset_spans.push(Span::styled(
                    format!("[{preset}]"),
                    Style::default().fg(Color::DarkGray),
                ));
            }
            preset_spans.push(Span::raw(" "));
        }

        let input_line = if model_input.is_empty() {
            vec![
                Span::styled(" > ", Style::default().fg(Color::DarkGray)),
                Span::styled(active_provider.default_model(), Style::default().fg(Color::Rgb(90, 90, 95))),
                if model_active { Span::styled("█", Style::default().fg(Color::White)) } else { Span::raw("") },
            ]
        } else {
            vec![
                Span::styled(" > ", Style::default().fg(Color::White)),
                Span::styled(model_input, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                if model_active { Span::styled("█", Style::default().fg(Color::White)) } else { Span::raw("") },
            ]
        };

        let model_lines = vec![Line::from(preset_spans), Line::from(input_line)];
        f.render_widget(Paragraph::new(model_lines).block(model_block), model_rect);

        // Field 2: API Key Input
        let key_rect = inner_chunks[3];
        targets.field_rects.push((2, key_rect));
        let key_active = active_field == 2;
        let is_ollama = active_provider == AiProvider::OllamaLocal;
        let key_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(if key_active { Style::default().fg(Color::White) } else { Style::default().fg(Color::Rgb(60, 60, 65)) })
            .title(Span::styled(
                if is_ollama {
                    " [3] API Key (not required for local Ollama) "
                } else if key_active {
                    " ▶ [3] API Key: (paste or type key) "
                } else {
                    " [3] API Key "
                },
                if key_active { Style::default().fg(Color::White).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Gray) },
            ));

        let key_display = if is_ollama {
            Line::from(vec![
                Span::styled(" > ", Style::default().fg(Color::DarkGray)),
                Span::styled("(local Ollama does not require an API key)", Style::default().fg(Color::Rgb(80, 80, 85))),
            ])
        } else if key_input.is_empty() {
            Line::from(vec![
                Span::styled(" > ", Style::default().fg(Color::DarkGray)),
                Span::styled("paste or enter API key here...", Style::default().fg(Color::DarkGray)),
                if key_active { Span::styled("█", Style::default().fg(Color::White)) } else { Span::raw("") },
            ])
        } else if key_active {
            Line::from(vec![
                Span::styled(" > ", Style::default().fg(Color::White)),
                Span::styled(key_input, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                Span::styled("█", Style::default().fg(Color::White)),
            ])
        } else {
            let masked = if key_input.len() > 8 {
                format!("{}...{} [configured]", &key_input[..4], &key_input[key_input.len() - 4..])
            } else {
                "******** [configured]".to_string()
            };
            Line::from(vec![
                Span::styled(" > ", Style::default().fg(Color::White)),
                Span::styled(masked, Style::default().fg(Color::Rgb(140, 190, 255))),
            ])
        };
        f.render_widget(Paragraph::new(key_display).block(key_block), key_rect);

        // Field 3: Endpoint URL Input
        let url_rect = inner_chunks[4];
        targets.field_rects.push((3, url_rect));
        let url_active = active_field == 3;
        let url_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(if url_active { Style::default().fg(Color::White) } else { Style::default().fg(Color::Rgb(60, 60, 65)) })
            .title(Span::styled(
                if url_active { " ▶ [4] Endpoint Base URL: (leave blank for official default) " } else { " [4] Endpoint Base URL " },
                if url_active { Style::default().fg(Color::White).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Gray) },
            ));

        let default_url = active_provider.default_base_url().unwrap_or("official cloud endpoint");
        let url_display = if url_input.is_empty() {
            Line::from(vec![
                Span::styled(" > ", Style::default().fg(Color::DarkGray)),
                Span::styled(format!("default ({default_url})"), Style::default().fg(Color::Rgb(80, 80, 85))),
                if url_active { Span::styled("█", Style::default().fg(Color::White)) } else { Span::raw("") },
            ])
        } else {
            Line::from(vec![
                Span::styled(" > ", Style::default().fg(Color::White)),
                Span::styled(url_input, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                if url_active { Span::styled("█", Style::default().fg(Color::White)) } else { Span::raw("") },
            ])
        };
        f.render_widget(Paragraph::new(url_display).block(url_block), url_rect);

        // Status or Error message
        let status_line = if let Some(err) = error_msg {
            Line::from(vec![
                Span::styled("✖ ", Style::default().fg(Color::Red)),
                Span::styled(err, Style::default().fg(Color::Red)),
            ])
        } else {
            Line::from(vec![
                Span::styled("✓ ", Style::default().fg(Color::DarkGray)),
                Span::styled("Settings persist to ~/.config/constellation/config.json", Style::default().fg(Color::DarkGray)),
            ])
        };
        f.render_widget(Paragraph::new(status_line), inner_chunks[5]);

        // Footer & Action Buttons
        let footer_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Min(20),
                Constraint::Length(16),
                Constraint::Length(12),
            ])
            .split(inner_chunks[6]);

        let hotkey_info = Line::from(vec![
            Span::styled("[Tab / ↑↓]", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled(" Switch Field   ", Style::default().fg(Color::DarkGray)),
            Span::styled("[1..6]", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled(" Provider", Style::default().fg(Color::DarkGray)),
        ]);
        f.render_widget(Paragraph::new(hotkey_info), footer_chunks[0]);

        // [ Save & Apply ] button
        let btn_save_rect = footer_chunks[1];
        targets.btn_save = Some(btn_save_rect);
        let save_span = Span::styled(" Save & Apply ↵ ", Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD));
        f.render_widget(Paragraph::new(Line::from(save_span)).centered(), btn_save_rect);

        // [ Cancel ] button
        let btn_cancel_rect = footer_chunks[2];
        targets.btn_cancel = Some(btn_cancel_rect);
        let cancel_span = Span::styled(" Cancel [Esc] ", Style::default().fg(Color::Gray).bg(Color::Rgb(35, 35, 40)));
        f.render_widget(Paragraph::new(Line::from(cancel_span)).centered(), btn_cancel_rect);

        targets
    }
}
