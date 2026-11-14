#![allow(dead_code)]

use crate::types::{InteractiveSkill, WorkspaceProfile};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SkillFrontmatter {
    #[serde(default)]
    pub skill_id: String,
    #[serde(default)]
    pub name: String,
    pub tier: Option<String>,
    #[serde(default)]
    pub target_languages: Vec<String>,
    pub trigger_conditions: Option<serde_yaml::Value>,
    #[serde(default)]
    pub required_mcp_tools: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SkillEntry {
    pub frontmatter: SkillFrontmatter,
    pub file_path: Option<PathBuf>,
    pub cached_body: Option<String>,
}

pub struct SkillRegistry {
    pub skills: Vec<InteractiveSkill>,
    pub loaded_skills: HashMap<String, SkillEntry>,
}

impl Default for SkillRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SkillRegistry {
    pub fn user_skills_dir() -> PathBuf {
        if let Ok(override_dir) = std::env::var("ASTERISK_SKILLS_DIR") {
            return PathBuf::from(override_dir);
        }
        if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".asterisk").join("skills")
        } else {
            PathBuf::from(".asterisk").join("skills")
        }
    }

    pub fn new() -> Self {
        let mut registry = Self {
            skills: Vec::new(),
            loaded_skills: HashMap::new(),
        };

        // 1. User Global Skills (~/.asterisk/skills/)
        let user_skills = Self::user_skills_dir();
        let _ = fs::create_dir_all(&user_skills);
        if user_skills.exists() {
            registry.load_skills_from_dir(&user_skills, "user-global");
        }

        // 2. Try loading from default assets/builtin_skills directory
        let asset_dir = Path::new("assets/builtin_skills");
        if asset_dir.exists() {
            registry.load_skills_from_dir(asset_dir, "default");
        }

        // 3. If no skills found, initialize default fallback skills
        if registry.skills.is_empty() {
            registry.init_fallback_skills();
        }

        registry
    }

    pub fn load_from_workspace(root: &Path) -> Self {
        let mut registry = Self::new();

        // 1. Workspace Skills (.asterisk/skills)
        let ws_skills = root.join(".asterisk").join("skills");
        if ws_skills.exists() {
            registry.load_skills_from_dir(&ws_skills, "user-workspace");
        }

        // 2. User Custom Skills (.asterisk/skills/custom)
        let custom_dir = root.join(".asterisk").join("skills").join("custom");
        if custom_dir.exists() {
            registry.load_skills_from_dir(&custom_dir, "user-custom");
        }

        // 3. Orchestrator Synthesized Skills (.asterisk/skills/synthesized)
        let synth_dir = root.join(".asterisk").join("skills").join("synthesized");
        if synth_dir.exists() {
            registry.load_skills_from_dir(&synth_dir, "orchestrator-synthesized");
        }

        registry
    }

    fn init_fallback_skills(&mut self) {
        let default_items = vec![
            ("owasp-sast-triage", "OWASP SAST Triage & Taint Elimination", "Static Analysis", "Deep source inspection for SQL injection, Command Injection, and Path Traversal."),
            ("sca-reachability-triage", "SCA Dependency Reachability Analysis", "Dependency Audit", "Traces BFS call paths from entrypoints to vulnerable third-party symbols."),
            ("apk-manifest-guard", "Android APK & Manifest Security Guard", "Mobile Defense", "Audits exported components, intent-filters, and release debugging flags."),
            ("malicious-package-heuristics", "Phantom Dependency & Typosquatting Shield", "Supply Chain", "Compares imported symbols against manifest declarations to spot unpinned dependencies."),
            ("secret-validation-triage", "Shannon Entropy & Secret Leak Validator", "Secret Detection", "Traverses commit histories to detect leaked high-entropy tokens and private keys."),
            ("container-code-reachability", "Container Isolation & Port Reachability Guard", "Container Security", "Inspects Dockerfiles and compose specs for wildcard 0.0.0.0 binds and root execution."),
            ("contextual-code-hardening", "Contextual Code Hardening & Unified Diff Synthesizer", "Remediation", "Synthesizes minimal non-breaking unified diff patches adhering to repository coding styles."),
            ("vendor-hotfix-backport", "Vendor Hotfix Backport & Minimal Remediation", "Vendor Patching", "Ingests upstream security fixes for libraries to mitigate breaking API changes."),
        ];

        for (id, name, cat, desc) in default_items {
            let frontmatter = SkillFrontmatter {
                skill_id: id.to_string(),
                name: name.to_string(),
                tier: Some("default".to_string()),
                target_languages: vec!["all".to_string()],
                trigger_conditions: None,
                required_mcp_tools: Vec::new(),
            };

            self.loaded_skills.insert(
                id.to_string(),
                SkillEntry {
                    frontmatter,
                    file_path: None,
                    cached_body: Some(format!("# {name}\n\n{desc}")),
                },
            );

            self.skills.push(InteractiveSkill {
                id: id.to_string(),
                name: name.to_string(),
                category: cat.to_string(),
                description: desc.to_string(),
                invocations: 0,
                active: true,
            });
        }
    }

    pub fn load_skills_from_dir(&mut self, dir: &Path, default_tier: &str) {
        use walkdir::WalkDir;

        for entry in WalkDir::new(dir).max_depth(4).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() {
                let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if fname.ends_with(".skill.md") || fname.ends_with(".md") {
                    if let Ok(content) = fs::read_to_string(path) {
                        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("custom-skill");
                        let clean_stem = stem.strip_suffix(".skill").unwrap_or(stem);

                        let (frontmatter, _body) = if let Some((mut fm, body)) = parse_skill_file(&content) {
                            if fm.skill_id.is_empty() {
                                fm.skill_id = if !fm.name.is_empty() {
                                    fm.name.to_lowercase().replace(' ', "-")
                                } else {
                                    clean_stem.to_string()
                                };
                            }
                            if fm.name.is_empty() {
                                fm.name = clean_stem.replace(['-', '_'], " ");
                            }
                            (fm, body)
                        } else {
                            // Support standard Markdown skills without YAML frontmatter
                            let title = content.lines()
                                .find(|l| l.trim().starts_with('#'))
                                .map(|l| l.trim().trim_start_matches('#').trim().to_string())
                                .unwrap_or_else(|| clean_stem.replace(['-', '_'], " "));
                            let fm = SkillFrontmatter {
                                skill_id: clean_stem.to_string(),
                                name: title,
                                tier: Some(default_tier.to_string()),
                                target_languages: vec!["all".to_string()],
                                trigger_conditions: None,
                                required_mcp_tools: Vec::new(),
                            };
                            (fm, content.clone())
                        };

                        let skill_id = frontmatter.skill_id.clone();
                        let name = frontmatter.name.clone();
                        let tier = frontmatter.tier.clone().unwrap_or_else(|| default_tier.to_string());
                        let category = match tier.as_str() {
                            "user-global" => "Global Skill (~/.asterisk/skills)",
                            "user-workspace" => "Workspace Skill",
                            "user-custom" => "Custom Skill",
                            "orchestrator-synthesized" => "Synthesized Skill",
                            _ => "Built-in Skill",
                        }
                        .to_string();

                        let desc = if frontmatter.target_languages.is_empty() || frontmatter.target_languages == ["all"] {
                            format!("Custom security skill loaded from {}", path.display())
                        } else {
                            format!("Target: {}", frontmatter.target_languages.join(", "))
                        };

                        self.loaded_skills.insert(
                            skill_id.clone(),
                            SkillEntry {
                                frontmatter,
                                file_path: Some(path.to_path_buf()),
                                cached_body: None,
                            },
                        );

                        if let Some(existing) = self.skills.iter_mut().find(|s| s.id == skill_id) {
                            existing.name = name;
                            existing.category = category;
                        } else {
                            self.skills.push(InteractiveSkill {
                                id: skill_id,
                                name,
                                category,
                                description: desc,
                                invocations: 0,
                                active: true,
                            });
                        }
                    }
                }
            }
        }
    }

    /// Progressive Disclosure: Loads the full Markdown instructions on-demand and increments invocation counter
    pub fn disclose_full_instructions(&mut self, skill_id: &str) -> Option<String> {
        let (body, file_path) = match self.loaded_skills.get(skill_id) {
            Some(entry) => (entry.cached_body.clone(), entry.file_path.clone()),
            None => return None,
        };

        // Increment counter in UI skill list
        if let Some(skill) = self.skills.iter_mut().find(|s| s.id == skill_id) {
            skill.invocations += 1;
        }

        if let Some(b) = body {
            return Some(b);
        }

        if let Some(p) = file_path {
            if let Ok(content) = fs::read_to_string(&p) {
                if let Some((_frontmatter, parsed_body)) = parse_skill_file(&content) {
                    if let Some(entry) = self.loaded_skills.get_mut(skill_id) {
                        entry.cached_body = Some(parsed_body.clone());
                    }
                    return Some(parsed_body);
                }
            }
        }

        None
    }

    /// Tier-2: Import external custom skill into .asterisk/skills/custom/
    pub fn import_custom_skill(&mut self, root: &Path, source_file: &Path) -> Result<String, String> {
        let content = fs::read_to_string(source_file)
            .map_err(|e| format!("Failed to read source skill file {}: {e}", source_file.display()))?;

        let (frontmatter, _body) = parse_skill_file(&content)
            .ok_or_else(|| "Invalid .skill.md format: missing valid YAML frontmatter".to_string())?;

        let dest_dir = root.join(".asterisk").join("skills").join("custom");
        fs::create_dir_all(&dest_dir)
            .map_err(|e| format!("Failed to create custom skills dir: {e}"))?;

        let dest_file = dest_dir.join(format!("{}.skill.md", frontmatter.skill_id));
        fs::write(&dest_file, &content)
            .map_err(|e| format!("Failed to write imported skill: {e}"))?;

        let skill_id = frontmatter.skill_id.clone();
        self.load_skills_from_dir(&dest_dir, "user-custom");

        Ok(skill_id)
    }

    /// Tier-3: Synthesize a project-specific skill tailored to detected tech stacks
    pub fn synthesize_project_skill(
        &mut self,
        root: &Path,
        profile: &WorkspaceProfile,
    ) -> Result<String, String> {
        let synth_dir = root.join(".asterisk").join("skills").join("synthesized");
        fs::create_dir_all(&synth_dir)
            .map_err(|e| format!("Failed to create synthesized skills dir: {e}"))?;

        let langs_str = if profile.languages.is_empty() {
            "all".to_string()
        } else {
            profile.languages.join("\", \"")
        };

        let skill_id = format!("project-synth-guard-{}", Utc::now().timestamp());
        let skill_content = format!(
            r#"---
skill_id: "{skill_id}"
name: "Tailored Architecture Invariant Guard"
tier: "orchestrator-synthesized"
target_languages: ["{langs_str}"]
trigger_conditions:
  workspace_file_count: {}
required_mcp_tools: ["read_file_scoped", "run_sandbox_unit_test"]
---

# Tailored Architecture Invariant Guard

Automatically synthesized for project at `{}`.
Enforces strict sanitization and input parameterization rules across all detected tech stacks.
"#,
            profile.total_files,
            root.display()
        );

        let dest_file = synth_dir.join(format!("{skill_id}.skill.md"));
        fs::write(&dest_file, skill_content)
            .map_err(|e| format!("Failed to write synthesized skill: {e}"))?;

        self.load_skills_from_dir(&synth_dir, "orchestrator-synthesized");
        Ok(skill_id)
    }

    #[allow(dead_code)]
    pub fn record_invocation(&mut self, skill_id: &str) {
        if let Some(skill) = self.skills.iter_mut().find(|s| s.id == skill_id) {
            skill.invocations += 1;
        }
    }
}

/// Helper function to parse YAML frontmatter and Markdown body from .skill.md content
fn parse_skill_file(content: &str) -> Option<(SkillFrontmatter, String)> {
    let trimmed = content.trim_start();
    if !trimmed.starts_with("---") {
        return None;
    }

    let rest = &trimmed[3..];
    let end_idx = rest.find("---")?;
    let yaml_str = &rest[..end_idx];
    let body = rest[end_idx + 3..].trim().to_string();

    let frontmatter: SkillFrontmatter = serde_yaml::from_str(yaml_str).ok()?;
    Some((frontmatter, body))
}

use chrono::Utc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skill_frontmatter_parsing_and_progressive_disclosure() {
        let sample_skill = r#"---
skill_id: "test-sql-guard"
name: "SQL Injection Guard"
tier: "default"
target_languages: ["python", "rust"]
required_mcp_tools: ["trace_taint_flow"]
---

# Instruction Title
Full instructions to guide the sub-agent during triage.
"#;

        let parsed = parse_skill_file(sample_skill);
        assert!(parsed.is_some());
        let (meta, body) = parsed.unwrap();
        assert_eq!(meta.skill_id, "test-sql-guard");
        assert_eq!(meta.name, "SQL Injection Guard");
        assert_eq!(meta.target_languages, vec!["python", "rust"]);
        assert!(body.contains("Full instructions to guide the sub-agent"));
    }

    #[test]
    fn test_skill_registry_progressive_disclosure() {
        let mut registry = SkillRegistry::new();
        assert!(!registry.skills.is_empty());

        let skill_id = "owasp-sast-triage";
        let body = registry.disclose_full_instructions(skill_id);
        assert!(body.is_some());
        assert!(body.unwrap().contains("OWASP SAST Triage"));

        let skill_entry = registry.skills.iter().find(|s| s.id == skill_id).unwrap();
        assert_eq!(skill_entry.invocations, 1);
    }
}
