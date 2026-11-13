//! Interactive theme picker modal: radio list with live preview.
//!
//! Keyboard: ↑/↓ · j/k · 1-7 · Home/End move (theme previews instantly),
//! Enter/Space apply, Esc revert. Mouse: click a row to preview, click it
//! again (or the Apply button) to apply, scroll wheel to move.

use crate::ui::fit::hint_line;
use crate::ui::theme::{presets, th, Theme};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Clear, Paragraph},
    Frame,
};

#[derive(Debug, Default, Clone)]
pub struct ThemePickerTargets {
    pub modal_rect: Rect,
    pub rows: Vec<(usize, Rect)>,
    pub btn_apply: Option<Rect>,
    pub btn_cancel: Option<Rect>,
}

pub struct ThemePickerView;

fn tagline(t: &Theme) -> &'static str {
    match t.name {
        "default_dark" => "shadcn OKLCH off-white & violet",
        "adaptive" => "dynamically adjusts terminal contrast",
        "terminal" => "native ANSI with dark control wells",
        "catppuccin" => "soft pastel on deep crust",
        "nord" => "arctic frost blue on polar night",
        "tokyo_night" => "neon blues & violets on deep indigo",
        "gruvbox" => "retro warm yellow & earth tones",
        "solarized" => "precision-tuned teal classic",
        "asterisk" => "cool blue on graphite",
        _ => "",
    }
}

/// Small color strip rendered with the *candidate* theme's own colors.
fn swatches(t: &Theme) -> Vec<Span<'static>> {
    [t.bg, t.surface, t.primary, t.secondary, t.accent, t.success, t.warning, t.destructive]
        .into_iter()
        .map(|c| Span::styled("██", Style::default().fg(c)))
        .collect()
}

impl ThemePickerView {
    pub fn render(f: &mut Frame, area: Rect, selected: usize, saved_name: &str) -> ThemePickerTargets {
        let list = presets();
        let roomy = area.height >= list.len() as u16 * 2 + 8;
        let row_h: u16 = if roomy { 2 } else { 1 };
        let list_h = (list.len() as u16 * row_h).min(area.height.saturating_sub(6));

        let modal_w = 78.min(area.width.saturating_sub(4));
        let modal_h = (list_h + 4).min(area.height.saturating_sub(2));
        let modal_rect = Rect::new(
            area.x + (area.width.saturating_sub(modal_w)) / 2,
            area.y + (area.height.saturating_sub(modal_h)) / 2,
            modal_w,
            modal_h,
        );

        f.render_widget(Clear, modal_rect);
        let frame = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(th().ring))
            .style(Style::default().bg(th().bg))
            .title(Line::from(Span::styled(
                " [select theme] ",
                Style::default().fg(th().primary).add_modifier(Modifier::BOLD),
            )))
            .title_bottom(Line::from(Span::styled(
                format!(" {} / {} ", selected + 1, list.len()),
                Style::default().fg(th().text_dim),
            )));
        let inner = frame.inner(modal_rect);
        f.render_widget(frame, modal_rect);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),                          // subtitle (compact & clean)
                Constraint::Length(list_h),                     // radio list (exact height, no gap)
                Constraint::Length(1),                          // keybinds (tight, right below radio list)
            ])
            .split(inner);

        // Subtitle
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("  live preview ", Style::default().fg(th().text_muted)),
                Span::styled("·", Style::default().fg(th().border)),
                Span::styled(" selection restyles UI instantly", Style::default().fg(th().text_dim)),
            ])),
            chunks[0],
        );

        // Radio list
        let mut targets = ThemePickerTargets { modal_rect, ..Default::default() };
        let list_area = chunks[1];
        let visible = (list_area.height / row_h).max(1) as usize;
        let start = selected.saturating_sub(visible.saturating_sub(1));

        for (vis_i, (idx, t)) in list.iter().enumerate().skip(start).take(visible).enumerate() {
            let y = list_area.y + vis_i as u16 * row_h;
            let rect = Rect::new(list_area.x, y, list_area.width, row_h);
            targets.rows.push((idx, rect));

            let is_sel = idx == selected;
            let is_saved = t.name == saved_name;
            let row_bg = if is_sel { th().element_hi } else { th().bg };
            let base = Style::default().bg(row_bg);

            let radio = if is_sel { "(●)" } else { "( )" };
            let radio_style = if is_sel {
                base.fg(th().primary).add_modifier(Modifier::BOLD)
            } else {
                base.fg(th().text_dim)
            };
            let label_style = if is_sel {
                base.fg(th().fg).add_modifier(Modifier::BOLD)
            } else {
                base.fg(th().text)
            };

            let marker = if is_sel { "▌" } else { " " };
            let label_w = 26usize;
            let mut spans = vec![
                Span::styled(marker, base.fg(th().ring)),
                Span::styled(format!(" {radio} "), radio_style),
                Span::styled(format!("{:<label_w$}", t.label), label_style),
                Span::styled("   ", base),
            ];
            spans.extend(swatches(t).into_iter().map(|s| Span::styled(s.content, s.style.bg(row_bg))));
            if is_saved {
                spans.push(Span::styled("  [saved]", base.fg(th().success)));
            }
            let pad = (rect.width as usize).saturating_sub(spans.iter().map(|s| s.width()).sum());
            spans.push(Span::styled(" ".repeat(pad), base));

            let mut lines = vec![Line::from(spans)];
            if row_h == 2 {
                let sub = format!("       {:<label_w$}   {}", t.name, tagline(t));
                let sub_w = rect.width as usize;
                let sub: String = sub.chars().take(sub_w).collect();
                let pad = sub_w.saturating_sub(sub.chars().count());
                lines.push(Line::from(vec![
                    Span::styled(marker, base.fg(th().ring)),
                    Span::styled(sub, base.fg(if is_sel { th().text_muted } else { th().text_dim })),
                    Span::styled(" ".repeat(pad.saturating_sub(1)), base),
                ]));
            }
            f.render_widget(Paragraph::new(lines), rect);
        }

        // Key hints (placed tightly right below the radio list)
        let hints = hint_line(
            &[
                ("[↑↓/jk]", "move"),
                ("[1-9]", "jump"),
                ("[Enter/Space]", "apply"),
                ("[Click]", "select/apply"),
                ("[Esc]", "cancel"),
            ],
            chunks[2].width as usize,
            Style::default().fg(th().fg).bg(th().element),
            Style::default().fg(th().text_dim),
            "  ",
        );
        f.render_widget(Paragraph::new(hints), chunks[2]);

        targets
    }
}

