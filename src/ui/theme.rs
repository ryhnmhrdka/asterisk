//! Dynamic semantic theme engine matching official `ratcn` / shadcn specifications.
//!
//! Upstream reference: `https://github.com/kristoferlund/ratcn` (crates/ratcn/src/theme.rs & color.rs)
//! and `https://ratcn.com` (demos/landing).
//!
//! Every color role matches ratcn's exact sRGB definitions so that Asterisk
//! displays identical aesthetics to `cargo run -p landing` and `ssh ratcn.com`.

use ratatui::style::Color;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::LazyLock;

/// A complete semantic palette matching ratcn roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    /// Machine name used by `/theme <name>` and persisted in config.
    pub name: &'static str,
    /// Human readable label.
    pub label: &'static str,

    // ── Canvas & surfaces (back to front) ────────────────────────────
    /// Deepest background (footer strips, wells).
    pub bg_alt: Color,
    /// The furthest-back surface, behind everything else (ratcn `background`).
    pub bg: Color,
    /// Raised surfaces that sit above background — dialogs, toasts, cards (ratcn `surface`).
    pub surface: Color,
    /// Control surfaces — lists, select panels, input wells (ratcn `field`).
    pub element: Color,
    /// Elevated chips, selected / hovered controls.
    pub element_hi: Color,

    // ── Lines & focus ────────────────────────────────────────────────
    /// Borders and separators at rest (ratcn `border`).
    pub border: Color,
    /// Stronger edges / secondary borders.
    pub border_hi: Color,
    /// The focus accent around a container / active input (ratcn `ring`).
    pub ring: Color,

    // ── Text ladder ──────────────────────────────────────────────────
    /// De-emphasized text: placeholders, disabled labels (ratcn `muted_foreground`).
    pub text_dim: Color,
    pub text_muted: Color,
    pub text_sub: Color,
    /// Ordinary text (ratcn `foreground`).
    pub text: Color,
    /// Strongest foreground (titles, bright labels).
    pub fg: Color,
    /// Text drawn on top of primary/bright fills (ratcn `primary_foreground`).
    pub on_accent: Color,

    // ── Accents & statuses ───────────────────────────────────────────
    /// The workhorse accent: default buttons, selected rows (ratcn `primary`).
    pub primary: Color,
    /// Informational blue/cyan.
    pub info: Color,
    /// Quieter accent, for secondary buttons and inactive tabs (ratcn `secondary`).
    pub secondary: Color,
    /// Vivid signature splash color (ratcn `accent`).
    pub accent: Color,
    /// Success feedback.
    pub success: Color,
    /// Warnings (ratcn `warning`).
    pub warning: Color,
    /// Destructive actions and error states (ratcn `destructive`).
    pub destructive: Color,

    // ── Tinted status fills (badges / banners) ───────────────────────
    pub primary_bg: Color,
    pub secondary_bg: Color,
    pub success_bg: Color,
    pub warning_bg: Color,
    pub destructive_bg: Color,
}

pub const fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color::Rgb(r, g, b)
}

// ─────────────────────────────────────────────────────────────────────────────
// ratcn Color Math & State Constants (from crates/ratcn/src/color.rs & theme.rs)
// ─────────────────────────────────────────────────────────────────────────────

pub const FOCUS_SHIFT: u16 = 6;
pub const HOVER_SHIFT: u16 = 12;
pub const FIELD_FOCUS_SHIFT: u16 = 4;
pub const FIELD_HOVER_SHIFT: u16 = 8;
pub const ROW_FOCUS_SHIFT: u16 = 15;
pub const DISABLED_DIM: u16 = 50;
pub const RING_DIM: u16 = 10;

const WELL_MIN: f64 = 1.10;
const WELL_MAX: f64 = 1.35;
const WELL_TARGET: f64 = 1.20;
const SURFACE_MIN: f64 = 1.03;
const VISIBLE_STEP: f64 = 1.05;
const MUTED_STEP: f64 = 1.15;
const LINE_FLOOR: f64 = 3.0;
const TEXT_FLOOR: f64 = 4.5;
const DISABLED_LEGIBILITY: f64 = 2.0;
const NEUTRAL_FILL_SHIFT: u16 = 90;
const QUIET_FILL_SHIFT: u16 = 13;

/// Resolve a color to rgb channels matching ratcn's VGA table.
#[must_use]
pub const fn resolve_rgb(color: Color) -> Option<(u8, u8, u8)> {
    match color {
        Color::Rgb(r, g, b) => Some((r, g, b)),
        Color::Black => Some((0, 0, 0)),
        Color::Red => Some((128, 0, 0)),
        Color::Green => Some((0, 128, 0)),
        Color::Yellow => Some((128, 128, 0)),
        Color::Blue => Some((0, 0, 128)),
        Color::Magenta => Some((128, 0, 128)),
        Color::Cyan => Some((0, 128, 128)),
        Color::Gray => Some((192, 192, 192)),
        Color::DarkGray => Some((128, 128, 128)),
        Color::LightRed => Some((255, 0, 0)),
        Color::LightGreen => Some((0, 255, 0)),
        Color::LightYellow => Some((255, 255, 0)),
        Color::LightBlue => Some((0, 0, 255)),
        Color::LightMagenta => Some((255, 0, 255)),
        Color::LightCyan => Some((0, 255, 255)),
        Color::White => Some((255, 255, 255)),
        Color::Indexed(_) | Color::Reset => None,
    }
}

/// The sRGB transfer function: one channel, linearised.
fn linear(channel: u8) -> f64 {
    let value = f64::from(channel) / 255.0;
    if value <= 0.039_28 {
        value / 12.92
    } else {
        ((value + 0.055) / 1.055).powf(2.4)
    }
}

/// Relative luminance of the channels per WCAG 2.1.
#[must_use]
pub fn luminance(color: Color) -> Option<f64> {
    let (r, g, b) = resolve_rgb(color)?;
    Some(0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b))
}

/// The WCAG 2.1 contrast ratio between two colors, from 1.0 to 21.0.
#[must_use]
pub fn contrast(a: Color, b: Color) -> Option<f64> {
    match (luminance(a), luminance(b)) {
        (Some(a), Some(b)) => Some((a.max(b) + 0.05) / (a.min(b) + 0.05)),
        _ => None,
    }
}

fn contrast_or_zero(a: Color, b: Color) -> f64 {
    contrast(a, b).unwrap_or(0.0)
}

#[must_use]
pub fn is_light(anchor: Color) -> bool {
    luminance(anchor).is_some_and(|l| l > 0.5)
}

#[must_use]
pub fn away_from(anchor: Color) -> Color {
    if is_light(anchor) {
        Color::Black
    } else {
        Color::White
    }
}

#[must_use]
pub fn nearest_to(anchor: Color) -> Color {
    if is_light(anchor) {
        Color::White
    } else {
        Color::Black
    }
}

#[must_use]
pub const fn blendable(color: Color, fallback: Color) -> Color {
    match resolve_rgb(color) {
        Some(_) => color,
        None => fallback,
    }
}

/// Linear interpolation matching ratcn::color::dim
#[must_use]
pub const fn dim(color: Color, toward: Color, amount: u16) -> Color {
    match (resolve_rgb(color), resolve_rgb(toward)) {
        (Some((r, g, b)), Some((tr, tg, tb))) => {
            let amount = if amount > 100 { 100 } else { amount };
            let keep = 100 - amount;
            Color::Rgb(
                ((r as u16 * keep + tr as u16 * amount + 50) / 100) as u8,
                ((g as u16 * keep + tg as u16 * amount + 50) / 100) as u8,
                ((b as u16 * keep + tb as u16 * amount + 50) / 100) as u8,
            )
        }
        _ => color,
    }
}

fn first_blend(from: Color, toward: Color, ok: impl Fn(Color) -> bool) -> Color {
    (0..=100)
        .map(|amount| dim(from, toward, amount))
        .find(|blend| ok(*blend))
        .unwrap_or_else(|| dim(from, toward, 100))
}

struct Layers {
    background: Color,
    surface: Color,
    field: Color,
    secondary: Color,
    primary: Color,
    ring: Color,
    foreground: Color,
    muted_foreground: Color,
}

impl Layers {
    fn solve(background: Color, queried_text: Color, away: Color) -> Option<Self> {
        let field = solve_well(background, away);
        let surface = solve_surface(background, field);
        let rungs = well_rungs(field, away);
        if !(WELL_MIN..=WELL_MAX).contains(&contrast_or_zero(field, background))
            || !climbs_visibly(background, &[field, rungs[0], rungs[1], rungs[2]])
        {
            return None;
        }

        let secondary = dim(background, away, QUIET_FILL_SHIFT);
        let backdrops = [background, surface, rungs[0], rungs[1], rungs[2]];

        let (foreground, muted_foreground) =
            solve_text(queried_text, background, field, &backdrops)?;

        let primary = dim(background, away, NEUTRAL_FILL_SHIFT);
        let ring = ring_of(primary, background, surface)?;

        Some(Self {
            background,
            surface,
            field,
            secondary,
            primary,
            ring,
            foreground,
            muted_foreground,
        })
    }
}

fn recedes_from(
    foreground: Color,
    background: Color,
    readable: &impl Fn(Color) -> bool,
) -> Option<Color> {
    let reach = contrast_or_zero(foreground, background);
    let holds = |muted: Color| {
        readable(muted)
            && contrast_or_zero(muted, background) < reach
            && contrast_or_zero(muted, foreground) >= MUTED_STEP
    };
    let coarse = (0..=10)
        .rev()
        .map(|step| step * 10)
        .find(|amount| holds(dim(foreground, background, *amount)))?;
    (coarse..coarse + 10)
        .map(|amount| dim(foreground, background, amount))
        .take_while(|muted| holds(*muted))
        .last()
        .or_else(|| Some(dim(foreground, background, coarse)))
}

fn ring_of(primary: Color, background: Color, surface: Color) -> Option<Color> {
    (0..=RING_DIM)
        .map(|softening| dim(primary, background, softening))
        .take_while(|ring| {
            contrast_or_zero(*ring, background) >= LINE_FLOOR
                && contrast_or_zero(*ring, surface) >= LINE_FLOOR
        })
        .last()
}

fn solve_well(background: Color, away: Color) -> Color {
    first_blend(background, away, |field| {
        contrast_or_zero(field, background) >= WELL_TARGET
    })
}

fn solve_surface(background: Color, field: Color) -> Color {
    first_blend(background, field, |surface| {
        contrast_or_zero(surface, background) >= SURFACE_MIN
            && contrast_or_zero(field, surface) >= WELL_MIN
    })
}

fn climbs_visibly(background: Color, ladder: &[Color]) -> bool {
    let mut previous = background;
    for rung in ladder {
        if contrast_or_zero(*rung, previous) < VISIBLE_STEP {
            return false;
        }
        previous = *rung;
    }
    true
}

fn well_rungs(field: Color, away: Color) -> [Color; 3] {
    let focused = dim(field, away, FIELD_FOCUS_SHIFT);
    [
        focused,
        dim(field, away, FIELD_HOVER_SHIFT),
        dim(focused, away, ROW_FOCUS_SHIFT),
    ]
}

fn worst_contrast(text: Color, backdrops: &[Color]) -> f64 {
    backdrops
        .iter()
        .map(|backdrop| contrast_or_zero(text, *backdrop))
        .fold(f64::INFINITY, f64::min)
}

fn solve_text(
    queried_text: Color,
    background: Color,
    field: Color,
    backdrops: &[Color],
) -> Option<(Color, Color)> {
    let disabled_well = dim(field, background, DISABLED_DIM);
    let readable = |text: Color| {
        worst_contrast(text, backdrops) >= TEXT_FLOOR
            && contrast_or_zero(dim(text, background, DISABLED_DIM), disabled_well)
                >= DISABLED_LEGIBILITY
    };
    let pushed = |amount: u16| {
        [Color::White, Color::Black]
            .into_iter()
            .map(|end| dim(queried_text, end, amount))
            .filter(|text| readable(*text))
            .find_map(|text| Some((text, recedes_from(text, background, &readable)?)))
    };
    let coarse = (0..=20)
        .map(|step| step * 5)
        .find(|amount| pushed(*amount).is_some())?;
    (coarse.saturating_sub(4)..=coarse).find_map(pushed)
}

fn fill_states(fill: Color, pressed: Color) -> [Color; 3] {
    [
        fill,
        dim(fill, pressed, FOCUS_SHIFT),
        dim(fill, pressed, HOVER_SHIFT),
    ]
}

fn steps_visibly(fill: Color, pressed: Color) -> bool {
    let states = fill_states(fill, pressed);
    contrast_or_zero(states[0], states[1]) >= VISIBLE_STEP
        && contrast_or_zero(states[1], states[2]) >= VISIBLE_STEP
}

fn best_label(fill: Color, pressed: Color, candidates: &[Color]) -> Color {
    let states = fill_states(fill, pressed);
    let score = |label: Color| worst_contrast(label, &states);
    let extremes = [Color::Rgb(255, 255, 255), Color::Rgb(0, 0, 0)];
    let mut best = candidates.first().copied().unwrap_or(extremes[0]);
    let mut best_score = score(best);
    for candidate in candidates.iter().copied().chain(extremes) {
        let candidate_score = score(candidate);
        if candidate_score > best_score {
            best = candidate;
            best_score = candidate_score;
        }
        if best_score >= TEXT_FLOOR {
            break;
        }
    }
    best
}

struct Hues {
    accent: Color,
    destructive: Color,
    warning: Color,
}

impl Hues {
    const RED: usize = 9;
    const YELLOW: usize = 11;
    const MAGENTA: usize = 13;

    fn solve(
        palette16: Option<&[Color; 16]>,
        layers: &Layers,
        away: Color,
        near: Color,
    ) -> Option<Self> {
        let from_palette = |index: usize, seed: Color| {
            palette16
                .and_then(|palette| resolve_rgb(palette[index]).map(|_| palette[index]))
                .unwrap_or(seed)
        };

        let repair = |hue: Color, is_a_fill: bool, taken: &[Color]| {
            (0..=100)
                .map(|amount| dim(hue, away, amount))
                .find(|candidate| {
                    let candidate = *candidate;
                    if taken.contains(&candidate) {
                        return false;
                    }
                    let states = fill_states(candidate, near);
                    let shown = if is_a_fill { &states[..] } else { &states[..1] };
                    shown
                        .iter()
                        .all(|state| contrast_or_zero(*state, layers.surface) >= LINE_FLOOR)
                        && (!is_a_fill
                            || (steps_visibly(candidate, near)
                                && worst_contrast(
                                    best_label(candidate, near, &[layers.background]),
                                    &states,
                                ) >= TEXT_FLOOR))
                })
        };

        let destructive = repair(
            from_palette(Self::RED, Color::Rgb(255, 100, 103)),
            true,
            &[],
        )?;
        let warning = repair(
            from_palette(Self::YELLOW, Color::Rgb(250, 204, 21)),
            false,
            &[destructive],
        )?;
        let accent = repair(
            from_palette(Self::MAGENTA, Color::Rgb(139, 92, 246)),
            false,
            &[destructive, warning],
        )?;
        Some(Self {
            accent,
            destructive,
            warning,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in Themes (Matching official ratcn presets & adaptive derivation)
// ─────────────────────────────────────────────────────────────────────────────

impl Theme {
    /// Official `default_dark()` from `ratcn` / `https://ratcn.com` (demos/landing).
    /// Inspired by shadcn/ui's default OKLCH palette translated to sRGB.
    pub const fn default_dark() -> Self {
        let primary = rgb(229, 229, 229);
        let background = rgb(10, 10, 10);
        let surface = rgb(18, 18, 18);
        let field = rgb(31, 31, 31);
        let ring = dim(primary, background, 10); // rgb(207, 207, 207)
        Self {
            name: "default_dark",
            label: "ratcn Default (Dark)",
            bg_alt: rgb(5, 5, 5),
            bg: background,
            surface,
            element: field,
            element_hi: rgb(45, 45, 45),
            border: rgb(94, 94, 94),
            border_hi: rgb(130, 130, 130),
            ring,
            text_dim: rgb(115, 115, 115),
            text_muted: rgb(161, 161, 161),
            text_sub: rgb(200, 200, 200),
            text: rgb(230, 230, 230),
            fg: rgb(250, 250, 250),
            on_accent: rgb(23, 23, 23),
            primary,
            info: rgb(139, 92, 246),
            secondary: rgb(38, 38, 38),
            accent: rgb(139, 92, 246), // violet #8b5cf6
            success: rgb(110, 230, 150),
            warning: rgb(250, 204, 21), // yellow #facc15
            destructive: rgb(255, 100, 103), // coral red #ff6467
            primary_bg: rgb(38, 38, 38),
            secondary_bg: rgb(32, 24, 46),
            success_bg: rgb(18, 48, 30),
            warning_bg: rgb(52, 44, 16),
            destructive_bg: rgb(58, 22, 24),
        }
    }

    /// Official `Theme::adaptive(background, foreground, palette16)` from `ratcn`.
    ///
    /// Dynamically derives mathematically consistent layers, WCAG-compliant contrast,
    /// and repaired accent/destructive/warning hues to perfectly fit any terminal.
    pub fn adaptive(background: Color, foreground: Color, palette16: Option<&[Color; 16]>) -> Self {
        let fallback = Self::default_dark();
        let queried_background = blendable(background, fallback.bg);
        let queried_text = blendable(foreground, fallback.text);
        let away = away_from(queried_background);
        let near = nearest_to(queried_background);

        let solved = (0..=100)
            .map(|deepen| dim(queried_background, near, deepen))
            .find_map(|bg| {
                let layers = Layers::solve(bg, queried_text, away)?;
                let hues = Hues::solve(palette16, &layers, away, near)?;
                Some((layers, hues))
            });

        let Some((layers, hues)) = solved else {
            return fallback;
        };

        let labels = [layers.background, layers.foreground];
        let primary_foreground = best_label(layers.primary, near, &labels);
        let border = first_blend(layers.background, away, |line| {
            contrast_or_zero(line, layers.background) >= LINE_FLOOR
        });
        let border_hi = dim(border, away, 15);
        let success = Color::Rgb(110, 230, 150);

        Self {
            name: "adaptive",
            label: "ratcn Adaptive",
            bg_alt: dim(layers.background, near, 20),
            bg: layers.background,
            surface: layers.surface,
            element: layers.field,
            element_hi: dim(layers.field, away, FIELD_FOCUS_SHIFT),
            border,
            border_hi,
            ring: layers.ring,
            text_dim: dim(layers.muted_foreground, layers.background, 30),
            text_muted: layers.muted_foreground,
            text_sub: dim(layers.foreground, layers.muted_foreground, 40),
            text: layers.foreground,
            fg: layers.foreground,
            on_accent: primary_foreground,
            primary: layers.primary,
            info: hues.accent,
            secondary: layers.secondary,
            accent: hues.accent,
            success,
            warning: hues.warning,
            destructive: hues.destructive,
            primary_bg: dim(layers.primary, layers.background, 85),
            secondary_bg: dim(layers.secondary, layers.background, 80),
            success_bg: dim(success, layers.background, 85),
            warning_bg: dim(hues.warning, layers.background, 85),
            destructive_bg: dim(hues.destructive, layers.background, 85),
        }
    }

    /// Detects current terminal background and foreground from environment (e.g. `COLORFGBG`),
    /// falling back to ratcn Default Dark colors `(#0a0a0a, #fafafa)`.
    pub fn detect_terminal_colors() -> (Color, Color) {
        if let Ok(val) = std::env::var("COLORFGBG") {
            let parts: Vec<&str> = val.split(';').collect();
            if parts.len() >= 2 {
                let fg_num = parts[0].parse::<u8>().ok();
                let bg_num = parts.last().and_then(|s| s.parse::<u8>().ok());
                if let (Some(fg), Some(bg)) = (fg_num, bg_num) {
                    let fg_color = if fg >= 7 { rgb(250, 250, 250) } else { rgb(23, 23, 23) };
                    let bg_color = if bg < 8 { rgb(10, 10, 10) } else { rgb(255, 255, 255) };
                    return (bg_color, fg_color);
                }
            }
        }
        (rgb(10, 10, 10), rgb(250, 250, 250))
    }

    /// Solves an adaptive theme dynamically using colors detected from the current terminal.
    pub fn adaptive_default() -> Self {
        let (bg, fg) = Self::detect_terminal_colors();
        Self::adaptive(bg, fg, None)
    }

    /// Official `terminal()` from `ratcn` aligned with Default palette colors.
    ///
    /// Preserves the exact ratcn landing color palette while providing terminal compatibility.
    pub const fn terminal() -> Self {
        let primary = rgb(229, 229, 229);
        let background = rgb(10, 10, 10);
        let surface = rgb(18, 18, 18);
        let field = rgb(31, 31, 31);
        let ring = dim(primary, background, 10);
        Self {
            name: "terminal",
            label: "ratcn Terminal (Default)",
            bg_alt: rgb(5, 5, 5),
            bg: background,
            surface,
            element: field,
            element_hi: rgb(45, 45, 45),
            border: rgb(94, 94, 94),
            border_hi: rgb(130, 130, 130),
            ring,
            text_dim: rgb(115, 115, 115),
            text_muted: rgb(161, 161, 161),
            text_sub: rgb(200, 200, 200),
            text: rgb(230, 230, 230),
            fg: rgb(250, 250, 250),
            on_accent: rgb(23, 23, 23),
            primary,
            info: rgb(139, 92, 246),
            secondary: rgb(38, 38, 38),
            accent: rgb(139, 92, 246),
            success: rgb(110, 230, 150),
            warning: rgb(250, 204, 21),
            destructive: rgb(255, 100, 103),
            primary_bg: rgb(38, 38, 38),
            secondary_bg: rgb(32, 24, 46),
            success_bg: rgb(18, 48, 30),
            warning_bg: rgb(52, 44, 16),
            destructive_bg: rgb(58, 22, 24),
        }
    }

    /// Official `catppuccin()` from `ratcn` (Catppuccin Mocha palette).
    pub const fn catppuccin() -> Self {
        let primary = rgb(137, 180, 250); // blue #89b4fa
        let background = rgb(17, 17, 27); // crust #11111b
        let field = rgb(30, 30, 46);      // base #1e1e2e
        let surface = dim(background, field, 30); // rgb(21, 21, 33)
        let ring = dim(primary, background, 10);
        Self {
            name: "catppuccin",
            label: "Catppuccin Mocha",
            bg_alt: rgb(14, 14, 23),
            bg: background,
            surface,
            element: field,
            element_hi: rgb(49, 50, 68), // surface0 #313244
            border: rgb(108, 112, 134),  // overlay0 #6c7086
            border_hi: rgb(147, 153, 178),
            ring,
            text_dim: rgb(127, 132, 156),
            text_muted: rgb(166, 173, 200), // subtext0 #a6adc8
            text_sub: rgb(186, 194, 222),
            text: rgb(205, 214, 244), // text #cdd6f4
            fg: rgb(205, 214, 244),
            on_accent: rgb(17, 17, 27),
            primary,
            info: rgb(137, 220, 235), // sapphire
            secondary: rgb(49, 50, 68),
            accent: rgb(203, 166, 247), // mauve #cba6f7
            success: rgb(166, 227, 161), // green #a6e3a1
            warning: rgb(249, 226, 175), // yellow #f9e2af
            destructive: rgb(243, 139, 168), // red #f38ba8
            primary_bg: rgb(24, 38, 64),
            secondary_bg: rgb(32, 34, 52),
            success_bg: rgb(24, 46, 34),
            warning_bg: rgb(54, 48, 28),
            destructive_bg: rgb(56, 24, 32),
        }
    }

    /// Official `nord()` from `ratcn` (Nord Arctic palette).
    pub const fn nord() -> Self {
        let primary = rgb(136, 192, 208); // Frost blue #88c0d0
        let background = rgb(46, 52, 64); // Polar Night #2e3440
        let surface = rgb(59, 66, 82);    // #3b4252
        let field = rgb(67, 76, 94);      // #434c5e
        let ring = dim(primary, background, 10);
        Self {
            name: "nord",
            label: "Nord Arctic",
            bg_alt: rgb(36, 41, 51),
            bg: background,
            surface,
            element: field,
            element_hi: rgb(76, 86, 106), // #4c566a
            border: rgb(96, 106, 126),
            border_hi: rgb(140, 150, 170),
            ring,
            text_dim: rgb(160, 170, 190),
            text_muted: rgb(216, 222, 233), // Snow Storm #d8dee9
            text_sub: rgb(229, 233, 240),
            text: rgb(236, 239, 244), // Snow Storm #eceff4
            fg: rgb(236, 239, 244),
            on_accent: rgb(46, 52, 64),
            primary,
            info: rgb(129, 161, 193), // Frost #81a1c1
            secondary: rgb(76, 86, 106),
            accent: rgb(180, 142, 173), // Aurora purple #b48ead
            success: rgb(163, 190, 140), // Aurora green #a3be8c
            warning: rgb(235, 203, 139), // Aurora yellow #ebcb8b
            destructive: rgb(191, 97, 106), // Aurora red #bf616a
            primary_bg: rgb(34, 58, 72),
            secondary_bg: rgb(38, 48, 64),
            success_bg: rgb(36, 56, 40),
            warning_bg: rgb(64, 52, 28),
            destructive_bg: rgb(64, 28, 34),
        }
    }

    /// Official `tokyo_night()` from `ratcn` (Tokyo Night Moon palette).
    pub const fn tokyo_night() -> Self {
        let primary = rgb(122, 162, 247); // blue #7aa2f7
        let background = rgb(26, 27, 38); // dark indigo #1a1b26
        let field = rgb(36, 40, 59);      // #24283b
        let surface = dim(background, field, 30);
        let ring = dim(primary, background, 10);
        Self {
            name: "tokyo_night",
            label: "Tokyo Night",
            bg_alt: rgb(18, 19, 28),
            bg: background,
            surface,
            element: field,
            element_hi: rgb(47, 53, 78),
            border: rgb(86, 95, 137), // #565f89
            border_hi: rgb(120, 130, 175),
            ring,
            text_dim: rgb(110, 118, 155),
            text_muted: rgb(169, 177, 214), // #a9b1d6
            text_sub: rgb(185, 193, 230),
            text: rgb(192, 202, 245), // #c0caf5
            fg: rgb(192, 202, 245),
            on_accent: rgb(26, 27, 38),
            primary,
            info: rgb(125, 207, 255), // cyan #7dcfff
            secondary: rgb(41, 46, 66),
            accent: rgb(187, 154, 247), // purple #bb9af7
            success: rgb(158, 206, 106), // green #9ece6a
            warning: rgb(224, 175, 104), // yellow #e0af68
            destructive: rgb(247, 118, 142), // red #f7768e
            primary_bg: rgb(24, 38, 72),
            secondary_bg: rgb(34, 32, 60),
            success_bg: rgb(24, 48, 32),
            warning_bg: rgb(56, 44, 22),
            destructive_bg: rgb(60, 24, 32),
        }
    }

    /// Official `gruvbox()` from `ratcn` (Gruvbox Dark palette).
    pub const fn gruvbox() -> Self {
        let primary = rgb(250, 189, 47); // bright yellow #fabd2f
        let background = rgb(40, 40, 40); // bg0 #282828
        let surface = rgb(50, 48, 47);    // bg0_h #32302f
        let field = rgb(60, 56, 54);      // bg1 #3c3836
        let ring = dim(primary, background, 10);
        Self {
            name: "gruvbox",
            label: "Gruvbox Dark",
            bg_alt: rgb(29, 32, 33), // bg0_s
            bg: background,
            surface,
            element: field,
            element_hi: rgb(80, 73, 69), // bg2 #504945
            border: rgb(102, 92, 84),    // bg4 #665c54
            border_hi: rgb(146, 131, 116), // gray #928374
            ring,
            text_dim: rgb(168, 153, 132), // fg4 #a89984
            text_muted: rgb(213, 196, 161), // fg2 #d5c4a1
            text_sub: rgb(235, 219, 178), // fg1 #ebdbb2
            text: rgb(251, 241, 199),     // fg0 #fbf1c7
            fg: rgb(251, 241, 199),
            on_accent: rgb(40, 40, 40),
            primary,
            info: rgb(131, 165, 152), // blue #83a598
            secondary: rgb(80, 73, 69),
            accent: rgb(211, 134, 155), // purple #d3869b
            success: rgb(184, 187, 38), // green #b8bb26
            warning: rgb(254, 128, 25), // orange #fe8019
            destructive: rgb(251, 73, 52), // red #fb4934
            primary_bg: rgb(60, 48, 18),
            secondary_bg: rgb(48, 40, 36),
            success_bg: rgb(36, 48, 22),
            warning_bg: rgb(60, 36, 16),
            destructive_bg: rgb(60, 24, 22),
        }
    }

    /// Official `solarized()` from `ratcn` (Solarized Dark palette).
    pub const fn solarized() -> Self {
        let primary = rgb(38, 139, 210); // blue #268bd2
        let background = rgb(0, 43, 54); // base03 #002b36
        let surface = rgb(7, 54, 66);    // base02 #073642
        let field = rgb(7, 54, 66);
        let ring = dim(primary, background, 10);
        Self {
            name: "solarized",
            label: "Solarized Dark",
            bg_alt: rgb(0, 33, 42),
            bg: background,
            surface,
            element: field,
            element_hi: rgb(14, 68, 82),
            border: rgb(88, 110, 117), // base01 #586e75
            border_hi: rgb(101, 123, 131), // base00 #657b83
            ring,
            text_dim: rgb(101, 123, 131),
            text_muted: rgb(131, 148, 150), // base0 #839496
            text_sub: rgb(147, 161, 161),  // base1 #93a1a1
            text: rgb(238, 232, 213),      // base2 #eee8d5
            fg: rgb(253, 246, 227),        // base3 #fdf6e3
            on_accent: rgb(0, 43, 54),
            primary,
            info: rgb(42, 161, 152), // cyan #2aa198
            secondary: rgb(88, 110, 117),
            accent: rgb(211, 54, 130), // magenta #d33682
            success: rgb(133, 153, 0), // green #859900
            warning: rgb(181, 137, 0), // yellow #b58900
            destructive: rgb(220, 50, 47), // red #dc322f
            primary_bg: rgb(10, 56, 80),
            secondary_bg: rgb(28, 52, 80),
            success_bg: rgb(24, 56, 36),
            warning_bg: rgb(44, 52, 30),
            destructive_bg: rgb(54, 34, 40),
        }
    }

    /// Asterisk Classic theme (cool cyan/blue on graphite).
    pub const fn asterisk() -> Self {
        Self {
            name: "asterisk",
            label: "Asterisk Classic",
            bg_alt: rgb(12, 13, 16),
            bg: rgb(14, 15, 19),
            surface: rgb(16, 18, 24),
            element: rgb(26, 28, 36),
            element_hi: rgb(40, 42, 54),
            border: rgb(55, 60, 75),
            border_hi: rgb(85, 90, 105),
            ring: rgb(140, 200, 255),
            text_dim: rgb(110, 112, 120),
            text_muted: rgb(140, 145, 160),
            text_sub: rgb(170, 172, 180),
            text: rgb(210, 215, 225),
            fg: Color::White,
            on_accent: Color::Black,
            primary: rgb(140, 200, 255),
            info: rgb(100, 220, 255),
            secondary: rgb(180, 160, 255),
            accent: rgb(255, 120, 160),
            success: rgb(110, 210, 140),
            warning: rgb(240, 160, 80),
            destructive: rgb(240, 110, 110),
            primary_bg: rgb(22, 45, 70),
            secondary_bg: rgb(50, 32, 72),
            success_bg: rgb(20, 48, 34),
            warning_bg: rgb(56, 44, 20),
            destructive_bg: rgb(60, 22, 24),
        }
    }

    /// Maps the semantic palette onto rataflow's canvas palette so the DAG
    /// background, controls, minimap and handles follow the active theme.
    pub fn flow_palette(&self) -> rataflow::Palette {
        rataflow::Palette {
            canvas_bg: self.bg,
            surface: self.surface,
            muted: self.border,
            subtle: self.element_hi,
            accent: self.ring,
            text: self.text,
            success: self.success,
            error: self.destructive,
        }
    }
}

static PRESETS: LazyLock<Vec<Theme>> = LazyLock::new(|| {
    vec![
        Theme::default_dark(),
        Theme::adaptive_default(),
        Theme::terminal(),
        Theme::catppuccin(),
        Theme::nord(),
        Theme::tokyo_night(),
        Theme::gruvbox(),
        Theme::solarized(),
        Theme::asterisk(),
    ]
});

static CURRENT: AtomicUsize = AtomicUsize::new(0);

/// The active theme. Cheap (`&'static`), lock-free, callable from any view.
#[inline]
pub fn th() -> &'static Theme {
    let p = presets();
    &p[CURRENT.load(Ordering::Relaxed) % p.len()]
}

/// All built-in presets.
pub fn presets() -> &'static [Theme] {
    &PRESETS
}

fn normalize(name: &str) -> String {
    let n = name.trim().to_lowercase().replace(['-', ' '], "_");
    match n.as_str() {
        "default" | "dark" | "default_dark" | "ratcn" | "ratcn_dark" | "landing" => "default_dark".into(),
        "adaptive" | "auto" | "dynamic" => "adaptive".into(),
        "tokyo" | "tokyonight" => "tokyo_night".into(),
        "catppuccin_mocha" | "mocha" => "catppuccin".into(),
        "gruvbox_dark" => "gruvbox".into(),
        "solarized_dark" => "solarized".into(),
        "ansi" | "term" => "terminal".into(),
        "classic" => "asterisk".into(),
        _ => n,
    }
}

/// Activates a preset by name (aliases accepted). Returns it on success.
pub fn set_theme(name: &str) -> Option<&'static Theme> {
    let n = normalize(name);
    let p = presets();
    let idx = p.iter().position(|t| t.name == n)?;
    CURRENT.store(idx, Ordering::Relaxed);
    Some(&p[idx])
}

/// Advances to the next preset (wraps around).
pub fn cycle_theme() -> &'static Theme {
    let p = presets();
    let next = (CURRENT.load(Ordering::Relaxed) + 1) % p.len();
    CURRENT.store(next, Ordering::Relaxed);
    &p[next]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_theme_switching_and_aliases() {
        assert_eq!(set_theme("Tokyo Night").map(|t| t.name), Some("tokyo_night"));
        assert_eq!(th().name, "tokyo_night");
        assert_eq!(set_theme("adaptive").map(|t| t.name), Some("adaptive"));
        assert_eq!(th().name, "adaptive");
        assert_eq!(set_theme("mocha").map(|t| t.name), Some("catppuccin"));
        assert!(set_theme("does-not-exist").is_none());
        assert_eq!(th().name, "catppuccin");
        set_theme("default");
        assert_eq!(th().name, "default_dark");
        assert_eq!(set_theme("terminal").map(|t| t.name), Some("terminal"));
        assert_eq!(th().name, "terminal");
        set_theme("default_dark");
        let names: Vec<_> = presets().iter().map(|t| t.name).collect();
        assert_eq!(names.len(), 9);
        assert!(names.contains(&"adaptive"));
        assert!(names.contains(&"default_dark"));
    }

    #[test]
    fn test_adaptive_solving() {
        // Dark terminal adaptive solving
        let dark = Theme::adaptive(Color::Rgb(10, 10, 10), Color::Rgb(250, 250, 250), None);
        assert_eq!(dark.name, "adaptive");
        assert!(luminance(dark.element).unwrap() > luminance(dark.bg).unwrap());

        // Light terminal adaptive solving
        let light = Theme::adaptive(Color::Rgb(253, 246, 227), Color::Rgb(101, 123, 131), None);
        assert_eq!(light.name, "adaptive");
        assert!(luminance(light.element).unwrap() < luminance(light.bg).unwrap());
    }
}
