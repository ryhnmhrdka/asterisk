use crate::ui::theme::th;
use super::latex::latex_to_unicode;
use pulldown_cmark::{Event, Parser, Tag, TagEnd};
use ratatui::{
    style::{Modifier, Style},
    text::{Line, Span},
};

pub fn preprocess_reasoning_tags(input: &str) -> String {
    let mut out = input.to_string();
    let lower = out.to_lowercase();
    if lower.contains("<think>") {
        out = out.replace("<think>", "\n\n> 💭 **Thinking Process**:\n> *")
                 .replace("<THINK>", "\n\n> 💭 **Thinking Process**:\n> *")
                 .replace("</think>", "*\n\n")
                 .replace("</THINK>", "*\n\n");
    }
    if lower.contains("<thought>") {
        out = out.replace("<thought>", "\n\n> 💭 **Thinking Process**:\n> *")
                 .replace("<THOUGHT>", "\n\n> 💭 **Thinking Process**:\n> *")
                 .replace("</thought>", "*\n\n")
                 .replace("</THOUGHT>", "*\n\n");
    }
    if lower.contains("<reasoning>") {
        out = out.replace("<reasoning>", "\n\n> 💭 **Thinking Process**:\n> *")
                 .replace("<REASONING>", "\n\n> 💭 **Thinking Process**:\n> *")
                 .replace("</reasoning>", "*\n\n")
                 .replace("</REASONING>", "*\n\n");
    }
    out
}

pub fn parse_markdown(input: &str) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut current_spans: Vec<Span<'static>> = Vec::new();

    let mut is_bold = false;
    let mut is_italic = false;
    let mut is_code_block = false;
    let mut heading_level: Option<usize> = None;
    let mut list_index: Option<u64> = None;
    let mut in_blockquote = false;

    let preprocessed = preprocess_reasoning_tags(input);
    let parser = Parser::new(&preprocessed);

    for event in parser {
        match event {
            Event::Start(tag) => match tag {
                Tag::Heading { level, .. } => {
                    if !current_spans.is_empty() {
                        lines.push(Line::from(std::mem::take(&mut current_spans)));
                    }
                    if !lines.is_empty() {
                        lines.push(Line::raw(""));
                    }
                    heading_level = Some(level as usize);
                }
                Tag::Paragraph => {
                    if !current_spans.is_empty() {
                        lines.push(Line::from(std::mem::take(&mut current_spans)));
                    }
                }
                Tag::List(start_num) => {
                    if !current_spans.is_empty() {
                        lines.push(Line::from(std::mem::take(&mut current_spans)));
                    }
                    list_index = start_num;
                }
                Tag::Item => {
                    if !current_spans.is_empty() {
                        lines.push(Line::from(std::mem::take(&mut current_spans)));
                    }
                    let prefix = if let Some(idx) = list_index {
                        let p = format!("  {idx}. ");
                        list_index = Some(idx + 1);
                        p
                    } else {
                        "  • ".to_string()
                    };
                    current_spans.push(Span::styled(prefix, Style::default().fg(th().text_muted)));
                }
                Tag::BlockQuote(_) => {
                    in_blockquote = true;
                }
                Tag::CodeBlock(_) => {
                    if !current_spans.is_empty() {
                        lines.push(Line::from(std::mem::take(&mut current_spans)));
                    }
                    is_code_block = true;
                }
                Tag::Emphasis => is_italic = true,
                Tag::Strong => is_bold = true,
                _ => {}
            },
            Event::End(tag_end) => match tag_end {
                TagEnd::Heading(_) => {
                    heading_level = None;
                    if !current_spans.is_empty() {
                        lines.push(Line::from(std::mem::take(&mut current_spans)));
                    }
                }
                TagEnd::Paragraph => {
                    if !current_spans.is_empty() {
                        lines.push(Line::from(std::mem::take(&mut current_spans)));
                    }
                }
                TagEnd::List(_) => {
                    list_index = None;
                }
                TagEnd::Item => {
                    if !current_spans.is_empty() {
                        lines.push(Line::from(std::mem::take(&mut current_spans)));
                    }
                }
                TagEnd::BlockQuote(_) => {
                    in_blockquote = false;
                }
                TagEnd::CodeBlock => {
                    is_code_block = false;
                    if !current_spans.is_empty() {
                        lines.push(Line::from(std::mem::take(&mut current_spans)));
                    }
                }
                TagEnd::Emphasis => is_italic = false,
                TagEnd::Strong => is_bold = false,
                _ => {}
            },
            Event::Text(cow_str) => {
                let processed_text = latex_to_unicode(&cow_str);

                if is_code_block {
                    for line in processed_text.lines() {
                        lines.push(Line::from(vec![
                            Span::styled("    │ ", Style::default().fg(th().text_dim)),
                            Span::styled(
                                line.to_string(),
                                Style::default().fg(th().text),
                            ),
                        ]));
                    }
                } else {
                    let mut style = Style::default();
                    if let Some(lvl) = heading_level {
                        style = match lvl {
                            1 => style.fg(th().fg).add_modifier(Modifier::BOLD),
                            2 => style.fg(th().text).add_modifier(Modifier::BOLD),
                            _ => style.fg(th().text_muted).add_modifier(Modifier::BOLD),
                        };
                    } else {
                        style = style.fg(th().fg);
                    }

                    if is_bold {
                        style = style.add_modifier(Modifier::BOLD);
                    }
                    if is_italic || in_blockquote {
                        style = style.add_modifier(Modifier::ITALIC);
                    }
                    if in_blockquote {
                        style = style.fg(th().text_sub);
                    }

                    current_spans.push(Span::styled(processed_text, style));
                }
            }
            Event::Code(cow_code) => {
                let processed = latex_to_unicode(&cow_code);
                current_spans.push(Span::styled(
                    format!(" {processed} "),
                    Style::default()
                        .fg(th().info)
                        .bg(th().element),
                ));
            }
            Event::SoftBreak | Event::HardBreak => {
                if !current_spans.is_empty() {
                    lines.push(Line::from(std::mem::take(&mut current_spans)));
                }
            }
            _ => {}
        }
    }

    if !current_spans.is_empty() {
        lines.push(Line::from(current_spans));
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_markdown_and_latex() {
        let md = "# Title\n- Item 1 with `code`\n- Formula $\\alpha + \\beta^2$";
        let lines = parse_markdown(md);
        assert!(!lines.is_empty());
    }

    #[test]
    fn test_thinking_tag_preprocessing() {
        let md = "<think>Analyzing taint flow graph...</think>\nFound zero leaks.";
        let lines = parse_markdown(md);
        assert!(!lines.is_empty());
        let text = lines.iter().flat_map(|l| l.spans.iter().map(|s| s.content.to_string())).collect::<Vec<_>>().join(" ");
        assert!(text.contains("Thinking Process") || text.contains("Analyzing taint flow"));
    }
}
