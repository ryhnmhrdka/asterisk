//! Width-aware text fitting helpers (display-width based, ellipsis style like OpenCode tab strips).
use ratatui::{
    style::Style,
    text::{Line, Span},
};

pub fn text_width(s: &str) -> usize {
    Span::raw(s).width()
}

/// Truncate at the end with `…` so the result never exceeds `max` display cells.
pub fn ellipsize(s: &str, max: usize) -> String {
    if text_width(s) <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let mut out = String::new();
    let mut w = 0;
    for c in s.chars() {
        let cw = text_width(&c.to_string());
        if w + cw + 1 > max {
            break;
        }
        out.push(c);
        w += cw;
    }
    out.push('…');
    out
}

/// Truncate at the start (keeps the tail, useful for paths): `…/project/src`.
pub fn ellipsize_start(s: &str, max: usize) -> String {
    if text_width(s) <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let chars: Vec<char> = s.chars().collect();
    let mut tail = String::new();
    let mut w = 0;
    for c in chars.iter().rev() {
        let cw = text_width(&c.to_string());
        if w + cw + 1 > max {
            break;
        }
        tail.insert(0, *c);
        w += cw;
    }
    format!("…{tail}")
}

/// Pad (right) or truncate to exactly `width` cells.
pub fn fit_pad(s: &str, width: usize) -> String {
    let t = ellipsize(s, width);
    let pad = width.saturating_sub(text_width(&t));
    format!("{t}{}", " ".repeat(pad))
}

/// Shortcut hint row that adapts to `width`: full -> drops middle items -> keys only.
/// `items` = (key, label). The last item (usually Esc) is always kept.
pub fn hint_line(
    items: &[(&str, &str)],
    width: usize,
    key_style: Style,
    label_style: Style,
    gap: &str,
) -> Line<'static> {
    let render = |sel: &[(&str, &str)], keys_only: bool| -> (Vec<Span<'static>>, usize) {
        let mut spans = vec![Span::raw(" ")];
        let mut w = 1;
        for (i, (k, l)) in sel.iter().enumerate() {
            if i > 0 {
                spans.push(Span::raw(gap.to_string()));
                w += text_width(gap);
            }
            spans.push(Span::styled((*k).to_string(), key_style));
            w += text_width(k);
            if !keys_only && !l.is_empty() {
                let lab = format!(" {l}");
                w += text_width(&lab);
                spans.push(Span::styled(lab, label_style));
            }
        }
        (spans, w)
    };

    let mut sel: Vec<(&str, &str)> = items.to_vec();
    loop {
        let (spans, w) = render(&sel, false);
        if w <= width {
            return Line::from(spans);
        }
        if sel.len() <= 2 {
            break;
        }
        sel.remove(sel.len() - 2);
    }
    let (spans, w) = render(items, true);
    if w <= width {
        return Line::from(spans);
    }
    // Last resort: ellipsized single line of keys.
    let joined: String = items.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(" ");
    Line::from(vec![Span::raw(" "), Span::styled(ellipsize(&joined, width.saturating_sub(1)), key_style)])
}

/// OpenCode-style tab widths: tabs keep natural width when they fit; otherwise the
/// active tab stays complete and the others share the remaining room (ellipsized).
pub fn tab_widths(natural: &[usize], active: usize, avail: usize, gap: usize) -> Vec<usize> {
    let n = natural.len();
    if n == 0 {
        return Vec::new();
    }
    let total: usize = natural.iter().sum::<usize>() + gap * (n - 1);
    if total <= avail {
        return natural.to_vec();
    }
    let min_w = 5usize;
    let active_w = natural[active.min(n - 1)].min(avail.saturating_sub((n - 1) * (min_w + gap)).max(min_w));
    let others = n - 1;
    let rest = avail.saturating_sub(active_w + gap * (n - 1));
    let per = if others > 0 { (rest / others).max(min_w) } else { 0 };
    natural
        .iter()
        .enumerate()
        .map(|(i, nat)| if i == active { active_w } else { per.min(*nat) })
        .collect()
}
