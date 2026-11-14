use crate::ui::theme::th;
use crate::types::AiProvider;
use crate::ui::fit::{ellipsize, ellipsize_start, hint_line};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
    Frame,
};

#[allow(dead_code)]
#[derive(Default)]
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

    /// Single Clean List: Select AI Provider with Model Previews & Key Badges
    pub fn render_provider_list(
        f: &mut Frame,
        area: Rect,
        selected_index: usize,
        config: &crate::core::AppConfig,
    ) -> ModalClickTargets {
        let modal_width = 74.min(area.width.saturating_sub(4));
        let modal_height = 16.min(area.height.saturating_sub(2));

        let x = (area.width.saturating_sub(modal_width)) / 2;
        let y = (area.height.saturating_sub(modal_height)) / 2;
        let modal_rect = Rect::new(x, y, modal_width, modal_height);

        f.render_widget(Clear, modal_rect);
        let bg_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(th().element_hi))
            .title(Span::styled(
                "  AI Providers & Models Directory  ",
                Style::default().fg(th().fg).add_modifier(Modifier::BOLD),
            ))
            .style(Style::default().bg(th().bg));
        f.render_widget(bg_block, modal_rect);

        let inner_chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Min(8),    // List of providers
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

        let mut providers = Vec::new();
        for (i, p) in AiProvider::ALL.iter().enumerate() {
            let label = if *p == AiProvider::Custom {
                let custom_name = config.get_provider_display_name(AiProvider::Custom);
                if i < 9 {
                    format!("{}. {}", i + 1, custom_name)
                } else if i == 9 {
                    format!("0. {}", custom_name)
                } else {
                    format!("x. {}", custom_name)
                }
            } else {
                let p_name = p.name();
                if i < 9 {
                    format!("{}. {}", i + 1, p_name)
                } else if i == 9 {
                    format!("0. {}", p_name)
                } else {
                    format!("x. {}", p_name)
                }
            };
            providers.push((*p, label));
        }

        let mut lines = Vec::new();
        let list_area = inner_chunks[0];
        let mut row_y = list_area.y;

        for (i, (prov, label)) in providers.iter().enumerate() {
            let is_sel = i == selected_index;
            let item_rect = Rect::new(list_area.x, row_y, list_area.width, 1);
            targets.provider_buttons.push((*prov, item_rect));
            row_y += 1;

            let (badge_text, badge_color) = if *prov == AiProvider::OllamaLocal {
                ("● local offline", th().primary)
            } else if config.has_discovered_models(*prov) {
                ("● synced live", th().success)
            } else if config.is_provider_configured(*prov) {
                ("● configured", th().success)
            } else {
                ("○ not configured", th().destructive)
            };

            let preview_models = config.get_models_for_provider(*prov).join(", ");
            let snippet_w = (list_area.width as usize).saturating_sub(3 + 21 + 17 + 2).max(4);
            let models_snippet = ellipsize(&preview_models, snippet_w);

            let label_col = ellipsize(label, 20);

            if is_sel {
                lines.push(Line::from(vec![
                    Span::styled(" ▸ ", Style::default().fg(th().on_accent).bg(th().fg).add_modifier(Modifier::BOLD)),
                    Span::styled(format!("{:<20} ", label_col), Style::default().fg(th().on_accent).bg(th().fg).add_modifier(Modifier::BOLD)),
                    Span::styled(format!("{:<15} ", badge_text), Style::default().fg(th().element_hi).bg(th().fg).add_modifier(Modifier::BOLD)),
                    Span::styled(format!("[{models_snippet}]"), Style::default().fg(th().border).bg(th().fg)),
                ]));
            } else {
                lines.push(Line::from(vec![
                    Span::raw("   "),
                    Span::styled(format!("{:<20} ", label_col), Style::default().fg(th().text)),
                    Span::styled(format!("{:<15} ", badge_text), Style::default().fg(badge_color)),
                    Span::styled(format!("[{models_snippet}]"), Style::default().fg(th().text_muted)),
                ]));
            }
        }
        f.render_widget(Paragraph::new(lines), list_area);

        // Adaptive action bar: never exceeds the inner card width
        let footer_line = hint_line(
            &[
                ("[1-9,0,x/↑↓]", "Select"),
                ("[Enter]", "Setup/Hub"),
                ("[c]", "Wizard"),
                ("[k]", "Key"),
                ("[u]", "URL"),
                ("[Esc]", "Close"),
            ],
            inner_chunks[1].width as usize,
            Style::default().fg(th().fg).bg(th().element),
            Style::default().fg(th().text_dim),
            "  ",
        );
        f.render_widget(Paragraph::new(footer_line), inner_chunks[1]);

        targets
    }

    /// Dedicated Independent Hub for a Single Provider (/provider -> [Enter])
    pub fn render_provider_detail_hub(
        f: &mut Frame,
        area: Rect,
        provider: AiProvider,
        config: &crate::core::AppConfig,
    ) -> ModalClickTargets {
        let modal_width = 72.min(area.width.saturating_sub(4));
        let modal_height = 14.min(area.height.saturating_sub(2));

        let x = (area.width.saturating_sub(modal_width)) / 2;
        let y = (area.height.saturating_sub(modal_height)) / 2;
        let modal_rect = Rect::new(x, y, modal_width, modal_height);

        f.render_widget(Clear, modal_rect);
        let bg_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(th().border))
            .title(Span::styled(
                format!("  Provider Hub: {}  ", provider.name()),
                Style::default().fg(th().fg).add_modifier(Modifier::BOLD),
            ))
            .style(Style::default().bg(th().bg));
        f.render_widget(bg_block, modal_rect);

        let inner_chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(8), // Detail lines (5 lines of info + spacing)
                Constraint::Length(2), // Bottom action & navigation bar
            ])
            .split(modal_rect);

        let targets = ModalClickTargets {
            provider_buttons: Vec::new(),
            model_preset_buttons: Vec::new(),
            field_rects: Vec::new(),
            btn_setup_credentials: None,
            btn_save: None,
            btn_cancel: None,
        };

        let is_configured = config.is_provider_configured(provider);
        let key_display = config.mask_key_for_provider(provider);
        let base_url = config
            .get_base_url_for_provider(provider)
            .unwrap_or_else(|| "Default Provider Gateway".to_string());

        let max_val_len = (inner_chunks[0].width as usize).saturating_sub(18);

        let base_url_display = ellipsize(&base_url, max_val_len);

        let models_list = config.get_models_for_provider(provider);
        let has_live = config.has_discovered_models(provider);
        let raw_presets = models_list.join(", ");
        let presets_display = ellipsize(&raw_presets, max_val_len);

        let live_label = format!("● Connected ({} live models)", models_list.len());
        let (status_text, status_color) = if provider == AiProvider::OllamaLocal {
            ("● Local Air-gap (Ready)", th().primary)
        } else if has_live {
            (live_label.as_str(), th().success)
        } else if is_configured {
            ("● Connected & Authenticated", th().success)
        } else {
            ("○ Not Configured (Key Required)", th().destructive)
        };

        let lines = vec![
            Line::from(vec![
                Span::styled(" CONNECTION & CREDENTIALS OVERVIEW ", Style::default().fg(th().accent).add_modifier(Modifier::BOLD)),
            ]),
            Line::raw(""),
            Line::from(vec![
                Span::styled("   Status:       ", Style::default().fg(th().text_muted)),
                Span::styled(status_text, Style::default().fg(status_color)),
            ]),
            Line::from(vec![
                Span::styled("   API Key:      ", Style::default().fg(th().text_muted)),
                Span::styled(
                    key_display,
                    Style::default().fg(if is_configured {
                        th().text
                    } else {
                        th().text_sub
                    }),
                ),
            ]),
            Line::from(vec![
                Span::styled("   Endpoint URL: ", Style::default().fg(th().text_muted)),
                Span::styled(base_url_display, Style::default().fg(th().text_sub)),
            ]),
            Line::from(vec![
                Span::styled("   Models:       ", Style::default().fg(th().text_muted)),
                Span::styled(presets_display, Style::default().fg(th().primary)),
            ]),
        ];
        f.render_widget(Paragraph::new(lines), inner_chunks[0]);

        // Action Bar for this specific provider (sleek, properly padded, strictly within borders)
        let actions_block = Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(th().element_hi));

        let action_items = vec![hint_line(
            &[
                ("[1]", if is_configured { "Update Key" } else { "Input Key" }),
                ("[2]", "Base URL"),
                ("[3]", "Models"),
                ("[4]", "Sync Live"),
                ("[Esc]", "Back"),
            ],
            inner_chunks[1].width as usize,
            Style::default().fg(th().on_accent).bg(th().primary).add_modifier(Modifier::BOLD),
            Style::default().fg(th().fg),
            "  ",
        )];
        f.render_widget(Paragraph::new(action_items).block(actions_block), inner_chunks[1]);

        targets
    }

    /// Unified All-Providers Model Selector (OpenCode style grouped directory)
    pub fn render_grouped_model_catalog(
        f: &mut Frame,
        area: Rect,
        search_query: &str,
        items: &[(AiProvider, String, bool)],
        selected_index: usize,
        current_active_model: &str,
    ) -> ModalClickTargets {
        let modal_width = 72.min(area.width.saturating_sub(4));
        let modal_height = 20.min(area.height.saturating_sub(2));

        let x = (area.width.saturating_sub(modal_width)) / 2;
        let y = (area.height.saturating_sub(modal_height)) / 2;
        let modal_rect = Rect::new(x, y, modal_width, modal_height);

        f.render_widget(Clear, modal_rect);
        let bg_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(th().border))
            .title(Span::styled(
                "  Select model  ",
                Style::default().fg(th().fg).add_modifier(Modifier::BOLD),
            ))
            .style(Style::default().bg(th().bg));
        f.render_widget(bg_block, modal_rect);

        let inner_chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(2), // Search bar input
                Constraint::Min(8),    // Grouped list
                Constraint::Length(1), // Sleek footer
            ])
            .split(modal_rect);

        let targets = ModalClickTargets {
            provider_buttons: Vec::new(),
            model_preset_buttons: Vec::new(),
            field_rects: Vec::new(),
            btn_setup_credentials: None,
            btn_save: None,
            btn_cancel: None,
        };

        // 1. Search Box
        let search_display = if search_query.is_empty() {
            Line::from(vec![
                Span::styled("Search models (e.g. claude, gpt-4o, llama, deepseek)...", Style::default().fg(th().border_hi)),
            ])
        } else {
            Line::from(vec![
                Span::styled("Search: ", Style::default().fg(th().text_muted)),
                Span::styled(search_query, Style::default().fg(th().fg).add_modifier(Modifier::BOLD)),
                Span::styled("█", Style::default().fg(th().primary)),
            ])
        };
        let search_block = Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(th().element));
        f.render_widget(Paragraph::new(search_display).block(search_block), inner_chunks[0]);

        // 2. Grouped Models List (OpenCode Style)
        let list_area = inner_chunks[1];
        let mut lines = Vec::new();

        if items.is_empty() {
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled("No models match your search query.", Style::default().fg(th().text_muted)),
            ]));
        } else {
            let max_visible = list_area.height as usize;
            let mut all_lines = Vec::new();
            let mut selected_line_idx = 0;

            let mut prev_prov: Option<AiProvider> = None;
            
            // Rakit semua baris terlebih dahulu tanpa .skip() dan .take()
            for (idx, (prov, model_name, is_conf)) in items.iter().enumerate() {
                // Section header jika grup provider baru
                if prev_prov != Some(*prov) {
                    prev_prov = Some(*prov);
                    let (section_badge, section_color) = if *prov == AiProvider::OllamaLocal {
                        ("Offline", th().primary)
                    } else if *is_conf {
                        ("Ready", th().success)
                    } else {
                        ("Key Required", th().destructive)
                    };
                    all_lines.push(Line::from(vec![
                        Span::raw(" "),
                        Span::styled(prov.name(), Style::default().fg(th().accent).add_modifier(Modifier::BOLD)),
                        Span::raw("  "),
                        Span::styled(format!("[{section_badge}]"), Style::default().fg(section_color)),
                    ]));
                }

                let is_sel = idx == selected_index;
                if is_sel {
                    // Catat posisi baris sebenarnya (setelah ditambah header)
                    selected_line_idx = all_lines.len();
                }

                let is_active = model_name == current_active_model;
                let active_bullet = if is_active { "● " } else { "  " };

                let access_tier = if *prov == AiProvider::OllamaLocal {
                    "Local"
                } else if *is_conf {
                    "Connected"
                } else {
                    "No Key"
                };

                let avail_color = if *prov == AiProvider::OllamaLocal || *is_conf {
                    th().text_muted
                } else {
                    th().destructive
                };

                let row_width = (list_area.width.saturating_sub(18)) as usize;
                let truncated_name = ellipsize(model_name, row_width);

                if is_sel {
                    all_lines.push(Line::from(vec![
                        Span::styled(format!(" {active_bullet}"), Style::default().fg(th().on_accent).bg(th().primary).add_modifier(Modifier::BOLD)),
                        Span::styled(format!("{:<width$}", truncated_name, width = row_width), Style::default().fg(th().on_accent).bg(th().primary).add_modifier(Modifier::BOLD)),
                        Span::styled(format!("{:>10} ", access_tier), Style::default().fg(th().element).bg(th().primary).add_modifier(Modifier::BOLD)),
                    ]));
                } else {
                    all_lines.push(Line::from(vec![
                        Span::styled(format!(" {active_bullet}"), if is_active { Style::default().fg(th().success) } else { Style::default().fg(th().border_hi) }),
                        Span::styled(format!("{:<width$}", truncated_name, width = row_width), Style::default().fg(if is_active { th().fg } else { th().text })),
                        Span::styled(format!("{:>10} ", access_tier), Style::default().fg(avail_color)),
                    ]));
                }
            }

            // Hitung offset scroll berdasarkan total baris nyata (model + header)
            let start_line = if max_visible > 0 && selected_line_idx >= max_visible {
                selected_line_idx + 1 - max_visible
            } else {
                0
            };

            // Jika item pertama (indeks 0) sedang dipilih, pastikan header di atasnya ikut terlihat
            let start_line = if selected_index == 0 { 0 } else { start_line };

            // Potong baris agar pas dengan tinggi layar
            lines = all_lines.into_iter().skip(start_line).take(max_visible).collect();
        }
        f.render_widget(Paragraph::new(lines), list_area);

        // 3. OpenCode-style adaptive footer
        let footer_line = hint_line(
            &[
                ("[↑/↓]", "Navigate"),
                ("[Enter]", "Select"),
                ("[Ctrl+K]", "Set Key"),
                ("[Esc]", "Back"),
            ],
            inner_chunks[2].width as usize,
            Style::default().fg(th().fg).bg(th().element),
            Style::default().fg(th().text_dim),
            "  ",
        );
        f.render_widget(Paragraph::new(footer_line), inner_chunks[2]);

        targets
    }

    #[allow(dead_code)]
    pub fn render_model_list(
        f: &mut Frame,
        area: Rect,
        active_provider: AiProvider,
        selected_index: usize,
        has_api_key: bool,
    ) -> ModalClickTargets {
        let is_locked = !has_api_key && active_provider.requires_api_key();
        let presets = if is_locked {
            &[]
        } else {
            active_provider.preset_models()
        };
        let list_len = presets.len().max(if is_locked { 3 } else { 1 });
        let modal_width = 58.min(area.width.saturating_sub(4));
        let modal_height = ((list_len + 5) as u16).min(area.height.saturating_sub(2)).max(9);

        let x = (area.width.saturating_sub(modal_width)) / 2;
        let y = (area.height.saturating_sub(modal_height)) / 2;
        let modal_rect = Rect::new(x, y, modal_width, modal_height);

        f.render_widget(Clear, modal_rect);
        let title_text = format!("  Select Model ({})  ", active_provider.name());
        let bg_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(if is_locked { th().destructive } else { th().element_hi }))
            .title(Span::styled(
                title_text,
                Style::default().fg(th().fg).add_modifier(Modifier::BOLD),
            ))
            .style(Style::default().bg(th().bg));
        f.render_widget(bg_block, modal_rect);

        let inner_chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Min(4),    // List of models / status
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

        if is_locked {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled("⚠️  No API Key Configured", Style::default().fg(th().warning).add_modifier(Modifier::BOLD)),
            ]));
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled("Models are locked and cannot be accessed yet.", Style::default().fg(th().text_muted)),
            ]));
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::styled("  ▸ Press [Enter] to configure API Key", Style::default().fg(th().fg).add_modifier(Modifier::BOLD)),
            ]));
        } else {
            // 1. Dapatkan tinggi area yang terlihat (berapa baris yang muat)
            let visible_height = list_area.height as usize;
            
            // 2. Hitung dari indeks ke berapa kita harus mulai menggambar agar selected_index selalu terlihat
            let start_index = if selected_index >= visible_height {
                selected_index.saturating_sub(visible_height - 1)
            } else {
                0
            };

            let mut row_y = list_area.y;
            
            // 3. Gunakan .skip() dan .take() agar HANYA memproses model yang terlihat di layar
            for (i, model_name) in presets.iter().enumerate().skip(start_index).take(visible_height) {
                let is_sel = i == selected_index;
                let item_rect = Rect::new(list_area.x, row_y, list_area.width, 1);
                targets.model_preset_buttons.push((model_name.to_string(), item_rect));
                row_y += 1;

                if is_sel {
                    lines.push(Line::from(vec![
                        Span::styled("  ▸ ", Style::default().fg(th().on_accent).bg(th().fg).add_modifier(Modifier::BOLD)),
                        Span::styled(format!("{:<width$}", model_name, width = (list_area.width.saturating_sub(6)) as usize), Style::default().fg(th().on_accent).bg(th().fg).add_modifier(Modifier::BOLD)),
                    ]));
                } else {
                    lines.push(Line::from(vec![
                        Span::raw("    "),
                        Span::styled(*model_name, Style::default().fg(th().text_sub)),
                    ]));
                }
            }
        }
        
        f.render_widget(Paragraph::new(lines), list_area);

        // Footer
        let footer_line = if is_locked {
            Line::from(vec![
                Span::raw("  "),
                Span::styled("[Enter]", Style::default().fg(th().fg).bg(th().element)),
                Span::styled(" Setup Key   ", Style::default().fg(th().text_dim)),
                Span::styled("[Esc]", Style::default().fg(th().fg).bg(th().element)),
                Span::styled(" Cancel", Style::default().fg(th().text_dim)),
            ])
        } else {
            Line::from(vec![
                Span::raw("  "),
                Span::styled("[↑/↓]", Style::default().fg(th().fg).bg(th().element)),
                Span::styled(" Select   ", Style::default().fg(th().text_dim)),
                Span::styled("[Enter]", Style::default().fg(th().fg).bg(th().element)),
                Span::styled(" Confirm   ", Style::default().fg(th().text_dim)),
                Span::styled("[Esc]", Style::default().fg(th().fg).bg(th().element)),
                Span::styled(" Close", Style::default().fg(th().text_dim)),
            ])
        };
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
            .border_style(Style::default().fg(th().element_hi))
            .title(Span::styled(
                format!("  {}  ", ellipsize(title, (modal_width as usize).saturating_sub(8))),
                Style::default().fg(th().fg).add_modifier(Modifier::BOLD),
            ))
            .style(Style::default().bg(th().bg));
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
                Span::styled("✖ ", Style::default().fg(th().destructive)),
                Span::styled(ellipsize(err, (inner_chunks[0].width as usize).saturating_sub(5)), Style::default().fg(th().destructive)),
            ])
        } else {
            Line::from(vec![
                Span::raw("  "),
                Span::styled(ellipsize(label, (inner_chunks[0].width as usize).saturating_sub(3)), Style::default().fg(th().text_muted)),
            ])
        };
        f.render_widget(Paragraph::new(top_msg), inner_chunks[0]);

        // Row 2: Clean single input slot
        let input_rect = inner_chunks[1];
        let input_block = Block::default().style(Style::default().bg(th().element));
        f.render_widget(input_block, input_rect);

        let input_w = (input_rect.width as usize).saturating_sub(2 + 2 + 1 + 1);
        let display_val = if is_masked && input_value.chars().count() > 8 {
            let chars: Vec<char> = input_value.chars().collect();
            let head: String = chars[..4].iter().collect();
            let tail: String = chars[chars.len() - 4..].iter().collect();
            ellipsize(&format!("{head}...{tail} [configured]"), input_w)
        } else if input_value.is_empty() {
            ellipsize("paste or type here...", input_w)
        } else {
            // keep the end of long values visible (where the user is typing)
            ellipsize_start(input_value, input_w)
        };

        let input_line = Line::from(vec![
            Span::raw("  "),
            Span::styled("▸ ", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
            Span::styled(
                display_val,
                if input_value.is_empty() {
                    Style::default().fg(th().text_dim)
                } else {
                    Style::default().fg(th().fg).add_modifier(Modifier::BOLD)
                },
            ),
            Span::styled("█", Style::default().fg(th().fg)),
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
            Span::styled("[Enter]", Style::default().fg(th().fg).bg(th().element)),
            Span::styled(" Save", Style::default().fg(th().text_dim)),
        ]);
        f.render_widget(Paragraph::new(hotkey_info), footer_chunks[0]);

        let btn_save_rect = footer_chunks[1];
        targets.btn_save = Some(btn_save_rect);
        let save_span = Span::styled(" Save [↵] ", Style::default().fg(th().on_accent).bg(th().fg).add_modifier(Modifier::BOLD));
        f.render_widget(Paragraph::new(Line::from(save_span)).centered(), btn_save_rect);

        let btn_cancel_rect = footer_chunks[3];
        targets.btn_cancel = Some(btn_cancel_rect);
        let cancel_span = Span::styled(" Cancel [Esc] ", Style::default().fg(th().text_sub).bg(th().element));
        f.render_widget(Paragraph::new(Line::from(cancel_span)).centered(), btn_cancel_rect);

        targets
    }

    /// Sleek, Modern AI Connection & Credentials Dashboard (/config)
    pub fn render_config_dashboard(
        f: &mut Frame,
        area: Rect,
        config: &crate::core::AppConfig,
    ) -> ModalClickTargets {
        let modal_width = 72.min(area.width.saturating_sub(4));
        let modal_height = 16.min(area.height.saturating_sub(2));

        let x = (area.width.saturating_sub(modal_width)) / 2;
        let y = (area.height.saturating_sub(modal_height)) / 2;
        let modal_rect = Rect::new(x, y, modal_width, modal_height);

        f.render_widget(Clear, modal_rect);
        let bg_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(th().border))
            .title(Span::styled(
                "  AI Engine & Security Configuration (/config)  ",
                Style::default().fg(th().fg).add_modifier(Modifier::BOLD),
            ))
            .style(Style::default().bg(th().bg));
        f.render_widget(bg_block, modal_rect);

        let inner_chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Min(8),    // Active System Profile Overview
                Constraint::Length(3), // Action shortcuts bar at bottom
                Constraint::Length(1), // Footer exit hint
            ])
            .split(modal_rect);

        let targets = ModalClickTargets {
            provider_buttons: Vec::new(),
            model_preset_buttons: Vec::new(),
            field_rects: Vec::new(),
            btn_setup_credentials: None,
            btn_save: None,
            btn_cancel: None,
        };

        let prov = config.provider;
        let model = config.get_model();
        let key_status = config.mask_key_for_provider(prov);
        let base_url = config.get_base_url().unwrap_or_else(|| "Default Upstream".to_string());
        let is_ready = config.is_provider_configured(prov);
        let val_w = (inner_chunks[0].width as usize).saturating_sub(15 + 2);
        let model = ellipsize(&model, val_w);
        let base_url = ellipsize(&base_url, val_w);
        let key_status = ellipsize(&key_status, val_w);

        // 1. Full-width Profile Info Overview
        let profile_lines = vec![
            Line::from(vec![
                Span::styled(" CURRENT ACTIVE PROFILE ", Style::default().fg(th().accent).add_modifier(Modifier::BOLD)),
            ]),
            Line::raw(""),
            Line::from(vec![
                Span::styled("   Provider:   ", Style::default().fg(th().text_muted)),
                Span::styled(prov.name(), Style::default().fg(th().fg).add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::styled(
                    if is_ready { "● ready" } else { "○ unauthenticated" },
                    Style::default().fg(if is_ready { th().success } else { th().destructive }),
                ),
            ]),
            Line::from(vec![
                Span::styled("   Model:      ", Style::default().fg(th().text_muted)),
                Span::styled(model, Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("   Secret Key: ", Style::default().fg(th().text_muted)),
                Span::styled(key_status, Style::default().fg(th().text)),
            ]),
            Line::from(vec![
                Span::styled("   Endpoint:   ", Style::default().fg(th().text_muted)),
                Span::styled(base_url, Style::default().fg(th().text_sub)),
            ]),
            Line::from(vec![
                Span::styled("   Isolation:  ", Style::default().fg(th().text_muted)),
                Span::styled(
                    if prov == AiProvider::OllamaLocal { "Offline Local Air-gap" } else { "Sandboxed Cloud Proxy" },
                    Style::default().fg(th().text_sub),
                ),
            ]),
        ];
        f.render_widget(Paragraph::new(profile_lines), inner_chunks[0]);

        // 2. Simple Action Shortcuts Bar at Bottom (Pill badges with subtle border)
        let actions_block = Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(th().element));

        let action_items = vec![
            Line::raw(""),
            hint_line(
                &[
                    ("[1]", "Provider"),
                    ("[2]", "Models"),
                    ("[3]", "API Key"),
                    ("[4]", "Base URL"),
                ],
                inner_chunks[1].width as usize,
                Style::default().fg(th().on_accent).bg(th().text).add_modifier(Modifier::BOLD),
                Style::default().fg(th().fg),
                "  ",
            ),
        ];
        f.render_widget(Paragraph::new(action_items).block(actions_block), inner_chunks[1]);

        // 3. Subtle Footer Line
        let footer_line = Line::from(vec![
            Span::raw(" "),
            Span::styled("[Esc]", Style::default().fg(th().fg).bg(th().element)),
            Span::styled(" Exit Settings", Style::default().fg(th().text_dim)),
        ]);
        f.render_widget(Paragraph::new(footer_line), inner_chunks[2]);

        targets
    }

    pub fn render_help_modal(f: &mut Frame, area: Rect) {
        let width = 76.min(area.width.saturating_sub(4));
        let height = 22.min(area.height.saturating_sub(2));
        let x = (area.width.saturating_sub(width)) / 2;
        let y = (area.height.saturating_sub(height)) / 2;
        let modal_area = Rect::new(x, y, width, height);

        f.render_widget(Clear, modal_area);

        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(th().ring))
            .style(Style::default().bg(th().surface))
            .title(Line::from(vec![
                Span::styled(" ✻ ASTERISK ", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
                Span::styled("• Keyboard Shortcuts & Command Guide ", Style::default().fg(th().fg).add_modifier(Modifier::BOLD)),
            ]))
            .title_bottom(Line::from(vec![
                Span::styled(" Press ", Style::default().fg(th().text_muted)),
                Span::styled(" [Esc] ", Style::default().fg(th().fg).bg(th().element).add_modifier(Modifier::BOLD)),
                Span::styled(" or ", Style::default().fg(th().text_muted)),
                Span::styled(" [?] ", Style::default().fg(th().fg).bg(th().element).add_modifier(Modifier::BOLD)),
                Span::styled(" to close ", Style::default().fg(th().text_muted)),
            ]));

        let inner = block.inner(modal_area);
        f.render_widget(block, modal_area);

        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(50),
                Constraint::Percentage(50),
            ])
            .split(inner);

        // Left Column: Navigation & Triage
        let left_lines = vec![
            Line::raw(""),
            Line::from(vec![
                Span::styled("  ◈ GLOBAL & NAVIGATION", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
            ]),
            Line::raw(""),
            Line::from(vec![
                Span::styled("   Shift+Tab ", Style::default().fg(th().fg).bg(th().element).add_modifier(Modifier::BOLD)),
                Span::styled(" Switch pane (Chat ↔ Views)", Style::default().fg(th().text)),
            ]),
            Line::from(vec![
                Span::styled("   Alt+1..5  ", Style::default().fg(th().fg).bg(th().element).add_modifier(Modifier::BOLD)),
                Span::styled(" Quick switch tab 1 to 5", Style::default().fg(th().text)),
            ]),
            Line::from(vec![
                Span::styled("   Tab       ", Style::default().fg(th().fg).bg(th().element).add_modifier(Modifier::BOLD)),
                Span::styled(" Cycle workspace tabs", Style::default().fg(th().text)),
            ]),
            Line::from(vec![
                Span::styled("   Ctrl+T    ", Style::default().fg(th().fg).bg(th().element).add_modifier(Modifier::BOLD)),
                Span::styled(" Cycle UI themes instantly", Style::default().fg(th().text)),
            ]),
            Line::from(vec![
                Span::styled("   ?         ", Style::default().fg(th().fg).bg(th().element).add_modifier(Modifier::BOLD)),
                Span::styled(" Toggle this help cheat sheet", Style::default().fg(th().text)),
            ]),
            Line::raw(""),
            Line::from(vec![
                Span::styled("  ◈ WORKSPACE & TRIAGE", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
            ]),
            Line::raw(""),
            Line::from(vec![
                Span::styled("   j / k     ", Style::default().fg(th().fg).bg(th().element).add_modifier(Modifier::BOLD)),
                Span::styled(" Navigate rows & findings", Style::default().fg(th().text)),
            ]),
            Line::from(vec![
                Span::styled("   r         ", Style::default().fg(th().fg).bg(th().element).add_modifier(Modifier::BOLD)),
                Span::styled(" Filter reachable findings", Style::default().fg(th().text)),
            ]),
            Line::from(vec![
                Span::styled("   Ctrl+A    ", Style::default().fg(th().fg).bg(th().element).add_modifier(Modifier::BOLD)),
                Span::styled(" Apply selected patch to disk", Style::default().fg(th().text)),
            ]),
            Line::from(vec![
                Span::styled("   Esc+Esc   ", Style::default().fg(th().fg).bg(th().element).add_modifier(Modifier::BOLD)),
                Span::styled(" Rewind workspace checkpoint", Style::default().fg(th().text)),
            ]),
        ];

        // Right Column: Chat, Terminal & Slash Commands
        let right_lines = vec![
            Line::raw(""),
            Line::from(vec![
                Span::styled("  ◈ CHAT & STREAM SCROLL", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
            ]),
            Line::raw(""),
            Line::from(vec![
                Span::styled("   PgUp/PgDn ", Style::default().fg(th().fg).bg(th().element).add_modifier(Modifier::BOLD)),
                Span::styled(" Scroll conversation stream", Style::default().fg(th().text)),
            ]),
            Line::from(vec![
                Span::styled("   Ctrl+U/D  ", Style::default().fg(th().fg).bg(th().element).add_modifier(Modifier::BOLD)),
                Span::styled(" Half-page chat scroll", Style::default().fg(th().text)),
            ]),
            Line::from(vec![
                Span::styled("   ↑ / ↓     ", Style::default().fg(th().fg).bg(th().element).add_modifier(Modifier::BOLD)),
                Span::styled(" Scroll chat or recall input", Style::default().fg(th().text)),
            ]),
            Line::raw(""),
            Line::from(vec![
                Span::styled("  ◈ SLASH COMMANDS", Style::default().fg(th().primary).add_modifier(Modifier::BOLD)),
            ]),
            Line::raw(""),
            Line::from(vec![
                Span::styled("   /scan     ", Style::default().fg(th().primary).bg(th().element).add_modifier(Modifier::BOLD)),
                Span::styled(" Autonomous defense audit", Style::default().fg(th().text)),
            ]),
            Line::from(vec![
                Span::styled("   /provider ", Style::default().fg(th().primary).bg(th().element).add_modifier(Modifier::BOLD)),
                Span::styled(" Choose AI provider & key", Style::default().fg(th().text)),
            ]),
            Line::from(vec![
                Span::styled("   /model    ", Style::default().fg(th().primary).bg(th().element).add_modifier(Modifier::BOLD)),
                Span::styled(" Select model preset", Style::default().fg(th().text)),
            ]),
            Line::from(vec![
                Span::styled("   /theme    ", Style::default().fg(th().primary).bg(th().element).add_modifier(Modifier::BOLD)),
                Span::styled(" Interactive theme browser", Style::default().fg(th().text)),
            ]),
            Line::from(vec![
                Span::styled("   /skills   ", Style::default().fg(th().primary).bg(th().element).add_modifier(Modifier::BOLD)),
                Span::styled(" Manage custom security skills", Style::default().fg(th().text)),
            ]),
            Line::from(vec![
                Span::styled("   /config   ", Style::default().fg(th().primary).bg(th().element).add_modifier(Modifier::BOLD)),
                Span::styled(" Credential & endpoint status", Style::default().fg(th().text)),
            ]),
        ];

        f.render_widget(Paragraph::new(left_lines), columns[0]);
        f.render_widget(Paragraph::new(right_lines), columns[1]);
    }
}
