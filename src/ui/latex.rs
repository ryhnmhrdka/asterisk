use regex::Regex;
use std::sync::LazyLock;

static FRAC_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\\frac\{([^{}]+)\}\{([^{}]+)\}").unwrap()
});

static SQRT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\\sqrt\{([^{}]+)\}").unwrap()
});

static SUP_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\^\{([^{}]+)\}").unwrap()
});

static SUB_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"_\{([^{}]+)\}").unwrap()
});

pub fn latex_to_unicode(input: &str) -> String {
    let mut text = input.to_string();

    // Replace fractions
    while let Some(caps) = FRAC_REGEX.captures(&text) {
        let full = caps.get(0).unwrap().as_str();
        let num = caps.get(1).unwrap().as_str();
        let den = caps.get(2).unwrap().as_str();
        let repl = format!("({num}/{den})");
        text = text.replace(full, &repl);
    }

    // Replace square roots
    while let Some(caps) = SQRT_REGEX.captures(&text) {
        let full = caps.get(0).unwrap().as_str();
        let inner = caps.get(1).unwrap().as_str();
        let repl = format!("√({inner})");
        text = text.replace(full, &repl);
    }

    // Replace superscripts with curly braces
    while let Some(caps) = SUP_REGEX.captures(&text) {
        let full = caps.get(0).unwrap().as_str();
        let inner = caps.get(1).unwrap().as_str();
        let repl = to_superscript(inner);
        text = text.replace(full, &repl);
    }

    // Replace subscripts with curly braces
    while let Some(caps) = SUB_REGEX.captures(&text) {
        let full = caps.get(0).unwrap().as_str();
        let inner = caps.get(1).unwrap().as_str();
        let repl = to_subscript(inner);
        text = text.replace(full, &repl);
    }

    // Single char superscripts and subscripts
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '^' && i + 1 < chars.len() {
            let next_c = chars[i + 1];
            if let Some(sup) = char_to_superscript(next_c) {
                out.push(sup);
                i += 2;
                continue;
            }
        } else if chars[i] == '_' && i + 1 < chars.len() {
            let next_c = chars[i + 1];
            if let Some(sub) = char_to_subscript(next_c) {
                out.push(sub);
                i += 2;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    text = out;

    // Common Greek and math symbols
    let replacements = [
        (r"\alpha", "α"),
        (r"\beta", "β"),
        (r"\gamma", "γ"),
        (r"\delta", "δ"),
        (r"\epsilon", "ε"),
        (r"\theta", "θ"),
        (r"\lambda", "λ"),
        (r"\mu", "μ"),
        (r"\pi", "π"),
        (r"\rho", "ρ"),
        (r"\sigma", "σ"),
        (r"\tau", "τ"),
        (r"\phi", "φ"),
        (r"\omega", "ω"),
        (r"\Delta", "Δ"),
        (r"\Sigma", "Σ"),
        (r"\Omega", "Ω"),
        (r"\sum", "∑"),
        (r"\prod", "∏"),
        (r"\int", "∫"),
        (r"\infty", "∞"),
        (r"\approx", "≈"),
        (r"\neq", "≠"),
        (r"\le", "≤"),
        (r"\leq", "≤"),
        (r"\ge", "≥"),
        (r"\geq", "≥"),
        (r"\to", "→"),
        (r"\rightarrow", "→"),
        (r"\leftarrow", "←"),
        (r"\times", "×"),
        (r"\div", "÷"),
        (r"\pm", "±"),
        (r"\cdot", "·"),
        (r"\in", "∈"),
        (r"\notin", "∉"),
        (r"\subset", "⊂"),
        (r"\partial", "∂"),
        (r"\nabla", "∇"),
    ];

    for (pattern, repl) in replacements {
        text = text.replace(pattern, repl);
    }

    text
}

fn to_superscript(s: &str) -> String {
    s.chars().map(|c| char_to_superscript(c).unwrap_or(c)).collect()
}

fn to_subscript(s: &str) -> String {
    s.chars().map(|c| char_to_subscript(c).unwrap_or(c)).collect()
}

fn char_to_superscript(c: char) -> Option<char> {
    match c {
        '0' => Some('⁰'),
        '1' => Some('¹'),
        '2' => Some('²'),
        '3' => Some('³'),
        '4' => Some('⁴'),
        '5' => Some('⁵'),
        '6' => Some('⁶'),
        '7' => Some('⁷'),
        '8' => Some('⁸'),
        '9' => Some('⁹'),
        '+' => Some('⁺'),
        '-' => Some('⁻'),
        '=' => Some('⁼'),
        '(' => Some('⁽'),
        ')' => Some('⁾'),
        'n' => Some('ⁿ'),
        'i' => Some('ⁱ'),
        _ => None,
    }
}

fn char_to_subscript(c: char) -> Option<char> {
    match c {
        '0' => Some('₀'),
        '1' => Some('₁'),
        '2' => Some('₂'),
        '3' => Some('₃'),
        '4' => Some('₄'),
        '5' => Some('₅'),
        '6' => Some('₆'),
        '7' => Some('₇'),
        '8' => Some('₈'),
        '9' => Some('₉'),
        '+' => Some('₊'),
        '-' => Some('₋'),
        '=' => Some('₌'),
        '(' => Some('₍'),
        ')' => Some('₎'),
        'a' => Some('ₐ'),
        'e' => Some('ₑ'),
        'i' => Some('ᵢ'),
        'j' => Some('ⱼ'),
        'o' => Some('ₒ'),
        'r' => Some('ᵣ'),
        'u' => Some('ᵤ'),
        'v' => Some('ᵥ'),
        'x' => Some('ₓ'),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latex_to_unicode() {
        let expr = r"\alpha + \beta^2 \le \frac{x_1}{y_2}";
        let res = latex_to_unicode(expr);
        assert_eq!(res, "α + β² ≤ (x₁/y₂)");
    }
}
