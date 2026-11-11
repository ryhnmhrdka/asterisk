#![allow(dead_code)]

use crate::types::WorkspaceProfile;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct SecurityContextRules {
    pub trusted_sanitizers: Vec<String>,
    pub ignored_paths: Vec<PathBuf>,
    pub architecture_rules: Vec<String>,
    pub raw_content: String,
}

impl SecurityContextRules {
    pub fn parse(content: &str) -> Self {
        let mut trusted_sanitizers = Vec::new();
        let mut ignored_paths = Vec::new();
        let mut architecture_rules = Vec::new();

        let mut current_section = "";

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if trimmed.starts_with('#') {
                let header = trimmed.trim_start_matches('#').trim().to_lowercase();
                if header.contains("sanitizer") || header.contains("validator") {
                    current_section = "sanitizers";
                } else if header.contains("ignore") || header.contains("excluded") {
                    current_section = "ignored";
                } else if header.contains("architecture") || header.contains("invariants") || header.contains("rules") {
                    current_section = "architecture";
                } else {
                    current_section = "";
                }
                continue;
            }

            // Parse list items (- item, * item, or 1. item)
            let item = if let Some(stripped) = trimmed.strip_prefix('-') {
                stripped.trim()
            } else if let Some(stripped) = trimmed.strip_prefix('*') {
                stripped.trim()
            } else if trimmed.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) && trimmed.contains(". ") {
                let parts: Vec<&str> = trimmed.splitn(2, ". ").collect();
                if parts.len() == 2 {
                    parts[1].trim()
                } else {
                    trimmed
                }
            } else {
                trimmed
            };

            // Remove inline code ticks `func_name`
            let clean_item = item.trim_matches('`').trim();

            match current_section {
                "sanitizers" => {
                    let token = clean_item.split_whitespace().next().unwrap_or(clean_item);
                    let func_name = token.trim_end_matches("()");
                    if !func_name.is_empty() {
                        trusted_sanitizers.push(func_name.to_string());
                    }
                }
                "ignored" => {
                    let path_str = clean_item.split_whitespace().next().unwrap_or(clean_item);
                    if !path_str.is_empty() {
                        ignored_paths.push(PathBuf::from(path_str));
                    }
                }
                "architecture" => {
                    if !clean_item.is_empty() {
                        architecture_rules.push(clean_item.to_string());
                    }
                }
                _ => {}
            }
        }

        Self {
            trusted_sanitizers,
            ignored_paths,
            architecture_rules,
            raw_content: content.to_string(),
        }
    }

    pub fn load_from_workspace(root: &Path) -> Option<Self> {
        let sec_path = root.join("SECURITY.md");
        if sec_path.exists() {
            if let Ok(content) = fs::read_to_string(&sec_path) {
                return Some(Self::parse(&content));
            }
        }
        None
    }

    pub fn is_trusted_sanitizer(&self, func_name: &str) -> bool {
        let clean = func_name.trim().trim_end_matches("()");
        self.trusted_sanitizers.iter().any(|s| s == clean)
    }

    pub fn is_path_ignored(&self, file_path: &Path) -> bool {
        for ignored in &self.ignored_paths {
            if file_path.starts_with(ignored) || file_path.ends_with(ignored) {
                return true;
            }
        }
        false
    }

    pub fn init_default_file(root: &Path, profile: &WorkspaceProfile) -> Result<PathBuf, String> {
        let target_path = root.join("SECURITY.md");
        if target_path.exists() {
            return Ok(target_path);
        }

        let langs = if profile.languages.is_empty() {
            "General Codebase".to_string()
        } else {
            profile.languages.join(", ")
        };

        let default_content = format!(
            r#"# Security Architecture & AI Triage Context Policy (SECURITY.md)

Project Root: `{}`
Detected Toolchains: {}

## 1. Trusted Sanitizers & Validators
- `sanitize_input`
- `validate_schema`
- `escape_sql`
- `param_binding`
- `int`
- `parseInt`

## 2. Excluded / Ignored Paths
- `tests/`
- `fixtures/`
- `target/`
- `node_modules/`
- `.asterisk/`

## 3. Architecture Invariants
- All public HTTP endpoints must pass input through request validation middleware before invoking business logic.
- External system commands (`exec`, `Command::new`) are strictly restricted to vetted constant arguments.
- Database write operations must utilize parameterized SQL queries or ORM models.
"#,
            root.display(),
            langs
        );

        fs::write(&target_path, default_content)
            .map_err(|e| format!("Failed to create SECURITY.md: {e}"))?;
        Ok(target_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_md_parsing() {
        let sample = r#"
# Security Policy

## Trusted Sanitizers
- `custom_clean_string`
* `validate_user_id()`
- `sanitize_sql`

## Excluded Paths
- tests/mock_data
- fixtures/
- vendor/

## Architecture Invariants
- Direct shell execution forbidden without policy approval.
- All secrets must be loaded from environment variables.
"#;

        let rules = SecurityContextRules::parse(sample);
        assert_eq!(rules.trusted_sanitizers.len(), 3);
        assert!(rules.is_trusted_sanitizer("custom_clean_string"));
        assert!(rules.is_trusted_sanitizer("validate_user_id"));
        assert!(rules.is_trusted_sanitizer("sanitize_sql"));
        assert!(!rules.is_trusted_sanitizer("evil_query"));

        assert_eq!(rules.ignored_paths.len(), 3);
        assert!(rules.is_path_ignored(Path::new("tests/mock_data/sample.json")));
        assert!(rules.is_path_ignored(Path::new("fixtures/vulnerable.py")));
        assert!(!rules.is_path_ignored(Path::new("src/main.rs")));

        assert_eq!(rules.architecture_rules.len(), 2);
    }
}
