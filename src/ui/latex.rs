use regex::Regex;
use std::sync::LazyLock;

static INLINE_DOLLAR_MATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\A|[^\\])\$([^\s\$][^\$\n]*?[^\s\$]|\S)\$").unwrap()
});

/// Finds the matching closing bracket/brace for an opening delimiter at `start_idx`.
fn find_matching_delimiter(s: &str, start_idx: usize, open: char, close: char) -> Option<usize> {
    let mut depth = 0;
    for (idx, c) in s[start_idx..].char_indices() {
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Some(start_idx + idx);
            }
        }
    }
    None
}

/// Recursively replaces balanced \frac{num}{den}, \dfrac, \cfrac with (num/den).
fn replace_fractions(mut text: String) -> String {
    let frac_keywords = ["\\frac", "\\dfrac", "\\cfrac"];
    let mut changed = true;
    let mut iterations = 0;
    while changed && iterations < 30 {
        changed = false;
        iterations += 1;

        for kw in &frac_keywords {
            if let Some(kw_pos) = text.find(kw) {
                let after_kw = kw_pos + kw.len();
                let remaining = &text[after_kw..];
                let trimmed_start = remaining.find('{');
                if let Some(first_open_offset) = trimmed_start {
                    if remaining[..first_open_offset].trim().is_empty() {
                        let first_open = after_kw + first_open_offset;
                        if let Some(first_close) = find_matching_delimiter(&text, first_open, '{', '}') {
                            let num = &text[first_open + 1..first_close];
                            let after_first = &text[first_close + 1..];
                            if let Some(second_open_offset) = after_first.find('{') {
                                if after_first[..second_open_offset].trim().is_empty() {
                                    let second_open = first_close + 1 + second_open_offset;
                                    if let Some(second_close) = find_matching_delimiter(&text, second_open, '{', '}') {
                                        let den = &text[second_open + 1..second_close];
                                        let num_fmt = latex_to_unicode(num);
                                        let den_fmt = latex_to_unicode(den);
                                        let replacement = if num_fmt.is_empty() && den_fmt.is_empty() {
                                            "(…/…)".to_string()
                                        } else {
                                            let num_part = if (num_fmt.contains(' ') || num_fmt.contains('±') || num_fmt.contains('+') || num_fmt.contains('-'))
                                                && !(num_fmt.starts_with('(') && num_fmt.ends_with(')'))
                                            {
                                                format!("({num_fmt})")
                                            } else {
                                                num_fmt
                                            };
                                            let den_part = if (den_fmt.contains(' ') || den_fmt.contains('+') || den_fmt.contains('-'))
                                                && !(den_fmt.starts_with('(') && den_fmt.ends_with(')'))
                                            {
                                                format!("({den_fmt})")
                                            } else {
                                                den_fmt
                                            };
                                            format!("({num_part}/{den_part})")
                                        };
                                        text.replace_range(kw_pos..=second_close, &replacement);
                                        changed = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    text
}

/// Recursively replaces balanced \sqrt{inner} and \sqrt[degree]{inner}.
fn replace_sqrts(mut text: String) -> String {
    let mut changed = true;
    let mut iterations = 0;
    while changed && iterations < 30 {
        changed = false;
        iterations += 1;

        if let Some(pos) = text.find("\\sqrt") {
            let after = pos + 5;
            let mut degree = None;
            let mut arg_start = after;

            if text[after..].starts_with('[') {
                if let Some(close_bracket) = find_matching_delimiter(&text, after, '[', ']') {
                    degree = Some(text[after + 1..close_bracket].to_string());
                    arg_start = close_bracket + 1;
                }
            }

            let rem_arg = &text[arg_start..];
            if let Some(open_offset) = rem_arg.find('{') {
                if rem_arg[..open_offset].trim().is_empty() {
                    let open_idx = arg_start + open_offset;
                    if let Some(close_idx) = find_matching_delimiter(&text, open_idx, '{', '}') {
                        let inner = &text[open_idx + 1..close_idx];
                        let inner_fmt = latex_to_unicode(inner);
                        let root_symbol = match degree.as_deref() {
                            Some("3") => "∛".to_string(),
                            Some("4") => "∜".to_string(),
                            Some(d) => format!("{}√", to_superscript(d)),
                            None => "√".to_string(),
                        };
                        let replacement = if inner_fmt.is_empty() {
                            format!("{root_symbol}(…)")
                        } else {
                            format!("{root_symbol}({inner_fmt})")
                        };
                        text.replace_range(pos..=close_idx, &replacement);
                        changed = true;
                    }
                }
            }
        }
    }
    text
}

/// Replaces text wrappers like \text{...}, \mathrm{...}, \mathbf{...}.
fn replace_text_wrappers(mut text: String) -> String {
    let wrappers = [
        "\\text", "\\mathrm", "\\mathbf", "\\mathit", "\\boldsymbol",
        "\\textbf", "\\texttt", "\\operatorname", "\\operatorname*",
    ];
    for w in &wrappers {
        while let Some(pos) = text.find(w) {
            let after = pos + w.len();
            let rem = &text[after..];
            if let Some(open_offset) = rem.find('{') {
                if rem[..open_offset].trim().is_empty() {
                    let open_idx = after + open_offset;
                    if let Some(close_idx) = find_matching_delimiter(&text, open_idx, '{', '}') {
                        let inner = text[open_idx + 1..close_idx].to_string();
                        text.replace_range(pos..=close_idx, &inner);
                        continue;
                    }
                }
            }
            break;
        }
    }
    text
}

/// Strips LaTeX math environments and cleans alignment markers.
fn strip_latex_environments(mut text: String) -> String {
    let envs = [
        "align*", "align", "equation*", "equation", "gather*", "gather",
        "matrix", "pmatrix", "bmatrix", "vmatrix", "Vmatrix",
    ];
    for env in &envs {
        let b = format!("\\begin{{{env}}}");
        let e = format!("\\end{{{env}}}");
        text = text.replace(&b, "");
        text = text.replace(&e, "");
    }
    text = text.replace("&=", "= ");
    text = text.replace("&", " ");
    text = text.replace(r"\\", "\n");
    text
}

/// Cleans parentheses, braces, delimiters, and LaTeX spacing commands.
fn clean_delimiters(mut text: String) -> String {
    text = text.replace(r"\left(", "(").replace(r"\right)", ")");
    text = text.replace(r"\left[", "[").replace(r"\right]", "]");
    text = text.replace(r"\left\{", "{").replace(r"\right\}", "}");
    text = text.replace(r"\left|", "|").replace(r"\right|", "|");
    text = text.replace(r"\left.", "").replace(r"\right.", "");
    text = text.replace(r"\{", "{").replace(r"\}", "}");
    text = text.replace(r"\,", " ").replace(r"\:", " ").replace(r"\;", " ").replace(r"\!", "");
    text = text.replace(r"\quad", "  ").replace(r"\qquad", "    ");
    text
}

/// Replaces superscripts enclosed in curly braces: ^{...}
fn replace_braced_superscripts(mut text: String) -> String {
    while let Some(pos) = text.find("^{") {
        if let Some(close_idx) = find_matching_delimiter(&text, pos + 1, '{', '}') {
            let inner = &text[pos + 2..close_idx];
            let repl = to_superscript(inner);
            text.replace_range(pos..=close_idx, &repl);
        } else {
            break;
        }
    }
    text
}

/// Replaces subscripts enclosed in curly braces: _{...}
fn replace_braced_subscripts(mut text: String) -> String {
    while let Some(pos) = text.find("_{") {
        if let Some(close_idx) = find_matching_delimiter(&text, pos + 1, '{', '}') {
            let inner = &text[pos + 2..close_idx];
            let repl = to_subscript(inner);
            text.replace_range(pos..=close_idx, &repl);
        } else {
            break;
        }
    }
    text
}

/// Replaces single char superscripts (^x) and subscripts (_x).
fn replace_single_char_scripts(text: String) -> String {
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
    out
}

/// Replaces LaTeX mathematical symbols and Greek letters with Unicode equivalents.
fn replace_math_symbols(mut text: String) -> String {
    // Note: Longer prefixes must come before shorter ones to prevent partial replacements.
    let replacements = [
        // Complex symbols & long arrows first
        (r"\leftrightarrow", "↔"),
        (r"\Leftrightarrow", "⇔"),
        (r"\rightarrow", "→"),
        (r"\leftarrow", "←"),
        (r"\Rightarrow", "⇒"),
        (r"\Leftarrow", "⇐"),
        (r"\mapsto", "↦"),
        (r"\uparrow", "↑"),
        (r"\downarrow", "↓"),
        // Relations & Equivalence
        (r"\approx", "≈"),
        (r"\simeq", "≃"),
        (r"\cong", "≅"),
        (r"\equiv", "≡"),
        (r"\propto", "∝"),
        (r"\neq", "≠"),
        (r"\ne", "≠"),
        (r"\leq", "≤"),
        (r"\geq", "≥"),
        (r"\sim", "∼"),
        (r"\ll", "≪"),
        (r"\gg", "≫"),
        // Operators
        (r"\bullet", "•"),
        (r"\times", "×"),
        (r"\cdot", "·"),
        (r"\circ", "∘"),
        (r"\star", "⋆"),
        (r"\ast", "∗"),
        (r"\pm", "±"),
        (r"\mp", "∓"),
        (r"\div", "÷"),
        // Calculus & Analysis (longer integrals first)
        (r"\iiint", "∭"),
        (r"\iint", "∬"),
        (r"\oint", "∮"),
        (r"\int", "∫"),
        (r"\coprod", "∐"),
        (r"\prod", "∏"),
        (r"\sum", "∑"),
        (r"\partial", "∂"),
        (r"\nabla", "∇"),
        (r"\infty", "∞"),
        (r"\prime", "′"),
        // Logic & Set Theory
        (r"\forall", "∀"),
        (r"\exists", "∃"),
        (r"\nexists", "∄"),
        (r"\emptyset", "∅"),
        (r"\empty", "∅"),
        (r"\notin", "∉"),
        (r"\in", "∈"),
        (r"\subseteq", "⊆"),
        (r"\subset", "⊂"),
        (r"\supseteq", "⊇"),
        (r"\supset", "⊃"),
        (r"\setminus", "∖"),
        (r"\cup", "∪"),
        (r"\cap", "∩"),
        (r"\land", "∧"),
        (r"\lor", "∨"),
        (r"\neg", "¬"),
        // Constants & Units
        (r"\hbar", "ℏ"),
        (r"\degree", "°"),
        (r"\deg", "°"),
        // Greek lowercase (check prefixes e.g. \varepsilon before \epsilon)
        (r"\varepsilon", "ε"),
        (r"\epsilon", "ε"),
        (r"\vartheta", "ϑ"),
        (r"\theta", "θ"),
        (r"\varpi", "ϖ"),
        (r"\pi", "π"),
        (r"\varrho", "ϱ"),
        (r"\rho", "ρ"),
        (r"\varsigma", "ς"),
        (r"\sigma", "σ"),
        (r"\varphi", "ϕ"),
        (r"\phi", "φ"),
        (r"\alpha", "α"),
        (r"\beta", "β"),
        (r"\gamma", "γ"),
        (r"\delta", "δ"),
        (r"\zeta", "ζ"),
        (r"\eta", "η"),
        (r"\iota", "ι"),
        (r"\kappa", "κ"),
        (r"\lambda", "λ"),
        (r"\mu", "μ"),
        (r"\nu", "ν"),
        (r"\xi", "ξ"),
        (r"\tau", "τ"),
        (r"\upsilon", "υ"),
        (r"\chi", "χ"),
        (r"\psi", "ψ"),
        (r"\omega", "ω"),
        // Greek uppercase
        (r"\Gamma", "Γ"),
        (r"\Delta", "Δ"),
        (r"\Theta", "Θ"),
        (r"\Lambda", "Λ"),
        (r"\Xi", "Ξ"),
        (r"\Pi", "Π"),
        (r"\Sigma", "Σ"),
        (r"\Upsilon", "Υ"),
        (r"\Phi", "Φ"),
        (r"\Psi", "Ψ"),
        (r"\Omega", "Ω"),
        // Short forms last to avoid collisions
        (r"\to", "→"),
        (r"\le", "≤"),
        (r"\ge", "≥"),
    ];

    for (pattern, repl) in replacements {
        text = text.replace(pattern, repl);
    }
    text
}

/// Strips inline math dollar delimiters: $expr$ -> expr.
fn clean_dollar_delimiters(mut text: String) -> String {
    while let Some(caps) = INLINE_DOLLAR_MATH.captures(&text) {
        let full = caps.get(0).unwrap().as_str();
        let inner = caps.get(1).unwrap().as_str();
        let leading = if full.starts_with('$') { "" } else { &full[..1] };
        let repl = format!("{leading}{inner}");
        text = text.replace(full, &repl);
    }
    text
}

pub fn latex_to_unicode(input: &str) -> String {
    let mut text = input.to_string();

    // 1. Strip document wrappers
    text = text.replace(r"\begin{document}", "");
    text = text.replace(r"\end{document}", "");

    // 2. Math environments
    text = strip_latex_environments(text);

    // 3. Delimiters \( \), \[ \], $$
    text = text.replace(r"\(", "").replace(r"\)", "");
    text = text.replace(r"\[", "").replace(r"\]", "");
    text = text.replace("$$", "");

    // 4. Text wrappers
    text = replace_text_wrappers(text);

    // 5. Parentheses & spacing
    text = clean_delimiters(text);

    // 6. Balanced fractions
    text = replace_fractions(text);

    // 7. Balanced square roots
    text = replace_sqrts(text);

    // 8. Braced superscripts
    text = replace_braced_superscripts(text);

    // 9. Braced subscripts
    text = replace_braced_subscripts(text);

    // 10. Single char scripts
    text = replace_single_char_scripts(text);

    // 11. Mathematical symbols & Greek letters
    text = replace_math_symbols(text);

    // 12. Dollar math delimiters
    text = clean_dollar_delimiters(text);

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
        'a' => Some('ᵃ'),
        'b' => Some('ᵇ'),
        'c' => Some('ᶜ'),
        'd' => Some('ᵈ'),
        'e' => Some('ᵉ'),
        'f' => Some('ᶠ'),
        'g' => Some('ᵍ'),
        'h' => Some('ʰ'),
        'i' => Some('ⁱ'),
        'j' => Some('ʲ'),
        'k' => Some('ᵏ'),
        'l' => Some('ˡ'),
        'm' => Some('ᵐ'),
        'n' => Some('ⁿ'),
        'o' => Some('ᵒ'),
        'p' => Some('ᵖ'),
        'r' => Some('ʳ'),
        's' => Some('ˢ'),
        't' => Some('ᵗ'),
        'u' => Some('ᵘ'),
        'v' => Some('ᵛ'),
        'w' => Some('ʷ'),
        'x' => Some('ˣ'),
        'y' => Some('ʸ'),
        'z' => Some('ᶻ'),
        'A' => Some('ᴬ'),
        'B' => Some('ᴮ'),
        'D' => Some('ᴰ'),
        'E' => Some('ᴱ'),
        'G' => Some('ᴳ'),
        'H' => Some('ᴴ'),
        'I' => Some('ᴵ'),
        'J' => Some('ᴶ'),
        'K' => Some('ᴷ'),
        'L' => Some('ᴸ'),
        'M' => Some('ᴹ'),
        'N' => Some('ᴺ'),
        'O' => Some('ᴼ'),
        'P' => Some('ᴾ'),
        'R' => Some('ᴿ'),
        'T' => Some('ᵀ'),
        'U' => Some('ᵁ'),
        'W' => Some('ᵂ'),
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
        'h' => Some('ₕ'),
        'i' => Some('ᵢ'),
        'j' => Some('ⱼ'),
        'k' => Some('ₖ'),
        'l' => Some('ₗ'),
        'm' => Some('ₘ'),
        'n' => Some('ₙ'),
        'o' => Some('ₒ'),
        'p' => Some('ₚ'),
        'r' => Some('ᵣ'),
        's' => Some('ₛ'),
        't' => Some('ₜ'),
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

    #[test]
    fn test_quadratic_formula_nested_braces() {
        let expr = r"x = \frac{-b \pm \sqrt{b^2 - 4ac}}{2a}";
        let res = latex_to_unicode(expr);
        assert_eq!(res, "x = ((-b ± √(b² - 4ac))/2a)");
    }

    #[test]
    fn test_inline_and_display_delimiters() {
        let inline = r"Here is an inline equation: \( ax^2 + bx + c = 0 \).";
        let res = latex_to_unicode(inline);
        assert!(res.contains("ax² + bx + c = 0"));
        assert!(!res.contains(r"\("));
        assert!(!res.contains(r"\)"));

        let display = "\\[\nx = 1\n\\]";
        let res_d = latex_to_unicode(display);
        assert!(!res_d.contains(r"\["));
        assert!(!res_d.contains(r"\]"));
    }

    #[test]
    fn test_align_environment() {
        let align = "\\begin{align}\ny &= mx + b \\\\\nE &= mc^2\n\\end{align}";
        let res = latex_to_unicode(align);
        assert!(res.contains("y =  mx + b"));
        assert!(res.contains("E =  mc²"));
        assert!(!res.contains(r"\begin"));
        assert!(!res.contains(r"\end"));
    }

    #[test]
    fn test_empty_fractions_and_roots() {
        let expr = r"fractions \frac{}{} , square roots \sqrt{}";
        let res = latex_to_unicode(expr);
        assert!(res.contains("(…/…)"));
        assert!(res.contains("√(…)"));
    }
}
