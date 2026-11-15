use std::path::Path;
use walkdir::WalkDir;
use crate::types::{WorkflowPlan, WorkflowTaskNode, WorkspaceProfile};
use crate::core::agent::SecurityAgentHub;
use crate::execution::EngineMessage;
use crate::types::ChatMessage;
use tokio::sync::mpsc::UnboundedSender;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DefensePlan {
    pub strategy_name: String,
    pub target_summary: String,
    pub rules_applied: Vec<String>,
    pub phases: Vec<PlanPhase>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PlanPhase {
    pub id: String,
    pub title: String,
    pub subagent_role: String,
    pub goal: String,
}

pub struct StrategyPlanner;

impl StrategyPlanner {
    /// Collects all non-ignored project file paths relative to `target_dir`.
    pub fn scan_workspace_file_list(target_dir: &Path) -> Vec<String> {
        let mut files = Vec::new();

        for entry in WalkDir::new(target_dir)
            .max_depth(4)
            .into_iter()
            .filter_entry(|e| {
                if e.path() == target_dir {
                    return true;
                }
                let name = e.file_name().to_string_lossy();
                !name.starts_with('.')
                    && name != "target"
                    && name != "node_modules"
                    && name != "dist"
                    && name != "build"
                    && name != "vendor"
                    && name != "fixtures"
                    && name != ".asterisk"
            })
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let rel = entry.path().strip_prefix(target_dir).unwrap_or(entry.path());
                files.push(rel.to_string_lossy().to_string());
            }
        }

        files.sort();
        files
    }

    /// Constructs the specialized LLM prompt requesting a structured WorkflowPlan JSON.
    pub fn create_ai_workflow_prompt(file_list: &[String], target_dir: &Path, user_directive: Option<&str>) -> String {
        let directive_section = if let Some(dir) = user_directive {
            format!(
                "\n\nCRITICAL USER DIRECTIVE:\n\
                \"{}\"\n\
                The user explicitly provided this custom instruction. You MUST prioritize, structure the workflow branches, and order the targets to address this directive first!\n",
                dir
            )
        } else {
            String::new()
        };

        format!(
            "You are Asterisk's autonomous pre-production code defense orchestrator.\n\
            Target directory: {}\n\n\
            Here is the complete list of discovered project files:\n\
            ```text\n\
            {}\n\
            ```{directive_section}\n\n\
            CRITICAL INSTRUCTIONS:\n\
            1. FIRST, think deeply inside <think>...</think> tags. Analyze which files represent genuine attack surfaces (auth, API, inputs, crypto) and explicitly explain which low-level files (Cargo.toml, lockfiles, etc.) you are skipping.\n\
            2. Automatically identify and IGNORE low-level config or trivial files (such as Cargo.toml, package-lock.json, .gitignore, README.md, build configs) unless they represent critical security boundaries.\n\
            3. Select and prioritize meaningful application files (e.g. authentication, API routes, database queries, controllers, token verification, network input handlers).\n\
            4. Synthesize a clean, prioritized, step-by-step modular security workflow pipeline (consecutive order 1, 2, 3...). Each stage should audit a focused surface in sequential order. Do NOT produce complex branching or tree roots.\n\
            5. Return STRICTLY valid JSON conforming to this exact schema:\n\
            {{\n\
              \"workflow_name\": \"Pre-Production Threat Defense Workflow\",\n\
              \"target_summary\": \"High-level summary of relevant project files and detected attack surfaces\",\n\
              \"nodes\": [\n\
                {{\n\
                  \"id\": \"task_auth_sast\",\n\
                  \"title\": \"Auth & Taint Flow Guard\",\n\
                  \"subtitle\": \"src/auth.rs\",\n\
                  \"agent\": \"sast\",\n\
                  \"tier\": \"sast\",\n\
                  \"targets\": [\"src/auth.rs\"],\n\
                  \"description\": \"Scan authentication, session tokens, and input validation for taint leaks\",\n\
                  \"order\": 1,\n\
                  \"depends_on\": []\n\
                }}\n\
              ]\n\
            }}\n",
            target_dir.display(),
            file_list.join("\n")
        )
    }

    /// Extracts clean JSON content even if wrapped in markdown code blocks.
    pub fn extract_json_payload(raw: &str) -> Option<&str> {
        let trimmed = raw.trim();
        let s = if let Some(code_start) = trimmed.find("```json") {
            let after = &trimmed[code_start + 7..];
            if let Some(code_end) = after.find("```") {
                &after[..code_end]
            } else {
                after
            }
        } else if let Some(code_start) = trimmed.find("```") {
            let after = &trimmed[code_start + 3..];
            if let Some(code_end) = after.find("```") {
                &after[..code_end]
            } else {
                after
            }
        } else {
            trimmed
        };

        if let Some(first_brace) = s.find('{') {
            if let Some(last_brace) = s.rfind('}') {
                if last_brace >= first_brace {
                    return Some(&s[first_brace..=last_brace]);
                }
            }
        }
        None
    }

    /// Parses workflow JSON string into a structured `WorkflowPlan`.
    pub fn parse_workflow_json(raw: &str) -> Result<WorkflowPlan, String> {
        let payload = Self::extract_json_payload(raw)
            .ok_or_else(|| "No valid JSON object detected in AI response".to_string())?;

        serde_json::from_str::<WorkflowPlan>(payload)
            .map_err(|e| format!("Workflow JSON schema parsing error: {e}"))
    }

    /// Generates a smart fallback workflow plan based on file inspection and optional user directives.
    #[allow(dead_code)]
    pub fn create_heuristic_workflow_plan(file_list: &[String], user_directive: Option<&str>) -> WorkflowPlan {
        let mut nodes = Vec::new();
        let mut order = 1;
        let mut prev_id: Option<String> = None;

        // 0. If user gave a specific directive (e.g. "tolong scan folder ... dulu"), find matching files and create priority task
        if let Some(directive) = user_directive {
            let lower_dir = directive.to_lowercase();
            let stop_words = ["tolong", "scan", "folder", "direktori", "file", "dulu", "gitu", "aja", "please", "audit", "the", "and", "for", "code"];
            let terms: Vec<&str> = lower_dir
                .split_whitespace()
                .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric() && c != '/' && c != '_' && c != '.'))
                .filter(|w| w.len() >= 3 && !stop_words.contains(w))
                .collect();

            let matched_files: Vec<String> = file_list
                .iter()
                .filter(|f| {
                    let lf = f.to_lowercase();
                    terms.iter().any(|t| lf.contains(t))
                })
                .take(10)
                .cloned()
                .collect();

            let targets = if matched_files.is_empty() {
                file_list.iter().take(4).cloned().collect()
            } else {
                matched_files
            };

            let task_id = "task_user_priority".to_string();
            nodes.push(WorkflowTaskNode {
                id: task_id.clone(),
                title: "User Directed Scope".to_string(),
                subtitle: format!("{} target file(s)", targets.len()),
                agent: "sast".to_string(),
                tier: "sast".to_string(),
                targets,
                description: format!("Prioritized audit focusing on user directive: \"{}\"", directive),
                order,
                depends_on: prev_id.map(|p| vec![p]).unwrap_or_default(),
            });
            prev_id = Some(task_id);
            order += 1;
        }

        // Stage 1: Secrets analysis
        let secret_targets: Vec<String> = file_list
            .iter()
            .filter(|f| {
                let lower = f.to_lowercase();
                lower.contains("secret")
                    || lower.contains("config")
                    || lower.contains("auth")
                    || lower.contains("env")
                    || lower.ends_with(".env")
                    || lower.ends_with(".rs")
                    || lower.ends_with(".js")
                    || lower.ends_with(".py")
            })
            .take(6)
            .cloned()
            .collect();

        if !secret_targets.is_empty() {
            let sec_id = "sub_secrets".to_string();
            nodes.push(WorkflowTaskNode {
                id: sec_id.clone(),
                title: "Secret & Key Miner".to_string(),
                subtitle: "credential leak audit".to_string(),
                agent: "secrets".to_string(),
                tier: "secrets".to_string(),
                targets: secret_targets,
                description: "Deep entropy scanning for hardcoded secrets, tokens, and API credentials.".to_string(),
                order,
                depends_on: prev_id.map(|p| vec![p]).unwrap_or_default(),
            });
            prev_id = Some(sec_id);
            order += 1;
        }

        // Stage 2: High priority code files for SAST
        let sast_targets: Vec<String> = file_list
            .iter()
            .filter(|f| {
                !f.ends_with("Cargo.toml")
                    && !f.ends_with("Cargo.lock")
                    && !f.ends_with("package.json")
                    && !f.ends_with("package-lock.json")
                    && !f.ends_with(".md")
                    && (f.ends_with(".rs") || f.ends_with(".js") || f.ends_with(".ts") || f.ends_with(".py") || f.ends_with(".go"))
            })
            .take(8)
            .cloned()
            .collect();

        if !sast_targets.is_empty() {
            let sast_id = "sub_sast".to_string();
            nodes.push(WorkflowTaskNode {
                id: sast_id.clone(),
                title: "AST Taint Flow Guard".to_string(),
                subtitle: format!("{} target files", sast_targets.len()),
                agent: "sast".to_string(),
                tier: "sast".to_string(),
                targets: sast_targets,
                description: "Static taint analysis tracing untrusted user input directly to sensitive sinks.".to_string(),
                order,
                depends_on: prev_id.map(|p| vec![p]).unwrap_or_default(),
            });
            prev_id = Some(sast_id);
            order += 1;
        }

        // Stage 3: Network surface check
        let net_id = "sub_net".to_string();
        nodes.push(WorkflowTaskNode {
            id: net_id.clone(),
            title: "Network Surface Prober".to_string(),
            subtitle: "bind & transport audit".to_string(),
            agent: "net".to_string(),
            tier: "net".to_string(),
            targets: Vec::new(),
            description: "Audits network port bindings (0.0.0.0), wildcard CORS, and plaintext transports.".to_string(),
            order,
            depends_on: prev_id.map(|p| vec![p]).unwrap_or_default(),
        });
        prev_id = Some(net_id);
        order += 1;

        // Stage 4: SCA dependency audit
        let sca_id = "sub_sca".to_string();
        nodes.push(WorkflowTaskNode {
            id: sca_id.clone(),
            title: "Supply-Chain Guard".to_string(),
            subtitle: "phantom dependency check".to_string(),
            agent: "sca".to_string(),
            tier: "sca".to_string(),
            targets: Vec::new(),
            description: "Cross-checks dependencies against active lockfiles to prevent phantom attacks.".to_string(),
            order,
            depends_on: prev_id.map(|p| vec![p]).unwrap_or_default(),
        });
        prev_id = Some(sca_id);
        order += 1;

        // Stage 5: Verification & Remediation Gate
        let verifier_id = "sub_verifier".to_string();
        nodes.push(WorkflowTaskNode {
            id: verifier_id.clone(),
            title: "Remediation & Sandbox Gate".to_string(),
            subtitle: "AST patch & test gate".to_string(),
            agent: "verifier".to_string(),
            tier: "verifier".to_string(),
            targets: Vec::new(),
            description: "Verifies safe AST outputs and synthesizes atomic hardening patches.".to_string(),
            order,
            depends_on: prev_id.map(|p| vec![p]).unwrap_or_default(),
        });

        let summary = if let Some(dir) = user_directive {
            format!("Sequential defense workflow tailored to user directive: \"{}\"", dir)
        } else {
            format!("Sequential multi-agent defense workflow over {} repository files", file_list.len())
        };

        WorkflowPlan {
            workflow_name: "Pre-Production Autonomous Defense Pipeline".to_string(),
            target_summary: summary,
            nodes,
        }
    }

    /// Queries the AI hub to synthesize an intelligent workflow plan with live reasoning feedback.
    pub async fn generate_ai_workflow_with_feedback(
        hub: &SecurityAgentHub,
        target_dir: &Path,
        user_directive: Option<&str>,
        sender: Option<&UnboundedSender<EngineMessage>>,
    ) -> Result<WorkflowPlan, String> {
        let file_list = Self::scan_workspace_file_list(target_dir);
        if file_list.is_empty() {
            return Err("Target workspace directory contains no readable files".to_string());
        }

        let prompt = Self::create_ai_workflow_prompt(&file_list, target_dir, user_directive);
        let response = hub.query(&prompt).await;

        if response.starts_with("⚠️ ")
            || response.contains("API Request Failed")
            || response.contains("API Key Missing")
            || response.contains("Connection Error")
        {
            return Err(response);
        }

        // Extract real AI reasoning thoughts and stream directly to chat
        let (thought_opt, clean_reply) = crate::core::agent::parse_ai_thinking_content(&response);
        let plan = match Self::parse_workflow_json(&clean_reply).or_else(|_| Self::parse_workflow_json(&response)) {
            Ok(p) => {
                if p.nodes.is_empty() {
                    return Err("Model returned an empty workflow plan".to_string());
                }
                p
            }
            Err(err) => return Err(err),
        };

        // Guarantee that the AI's reasoning thought process is visibly streamed to chat before proposing workflow
        let thought = thought_opt.unwrap_or_else(|| {
            format!(
                "Evaluated repository architecture across {} discovered files.\nThreat reconnaissance: {}\nSynthesized {} focused sequential defense stages.",
                file_list.len(),
                plan.target_summary,
                plan.nodes.len()
            )
        });

        if let Some(s) = sender {
            let _ = s.send(EngineMessage::Chat(ChatMessage::Thinking {
                agent: format!("ai_planner:{}", hub.config.get_model()),
                thought,
            }));
        }

        Ok(plan)
    }

    /// Queries the AI hub to synthesize an intelligent workflow plan.
    #[allow(dead_code)]
    pub async fn generate_ai_workflow(
        hub: &SecurityAgentHub,
        target_dir: &Path,
        user_directive: Option<&str>,
    ) -> Result<WorkflowPlan, String> {
        Self::generate_ai_workflow_with_feedback(hub, target_dir, user_directive, None).await
    }

    pub fn create_plan(profile: &WorkspaceProfile) -> DefensePlan {
        let mut rules = vec![
            "Capability Jail Confinement (cap-std filesystem boundaries)".to_string(),
            "Pre-Execution Gate Evaluation (cedar-policy deny-by-default)".to_string(),
            "Shannon Entropy Credential Mining (git2 commit history traversal)".to_string(),
            "AST Code Context Reachability Analysis (Tflow = Sinput -> Dsink)".to_string(),
            "Phantom Dependency Detection (SCA manifest cross-audit)".to_string(),
            "Isolated Worktree Verification Sandbox (.asterisk/worktrees)".to_string(),
        ];

        if profile.has_docker {
            rules.push("Container Isolation Audit (Dockerfile configuration check)".to_string());
        }

        let mut phases = vec![
            PlanPhase {
                id: "phase_recon".to_string(),
                title: "1. Workspace Surface Reconnaissance".to_string(),
                subagent_role: "Orchestrator Core".to_string(),
                goal: "Map repository filesystem structure and detect active language toolchains.".to_string(),
            },
            PlanPhase {
                id: "phase_secrets".to_string(),
                title: "2. Cryptographic Secret & Entropy Audit".to_string(),
                subagent_role: "Secret Hunter".to_string(),
                goal: "Scan source files and Git commit log history for exposed API keys and high-entropy tokens.".to_string(),
            },
            PlanPhase {
                id: "phase_sast".to_string(),
                title: "3. Static Vulnerability & Reachability Analysis".to_string(),
                subagent_role: "SAST & Graph Engine".to_string(),
                goal: "Traverse AST nodes and call graph to trace untrusted user input to sensitive sinks.".to_string(),
            },
            PlanPhase {
                id: "phase_sca".to_string(),
                title: "4. Supply-Chain & Dependency Audit".to_string(),
                subagent_role: "SCA Dependency Auditor".to_string(),
                goal: "Cross-reference imported modules with manifests to prevent phantom dependency attacks.".to_string(),
            },
            PlanPhase {
                id: "phase_verify".to_string(),
                title: "5. Pre-Production Defense Gate Evaluation".to_string(),
                subagent_role: "Policy Gate".to_string(),
                goal: "Evaluate Cedar security policy in worktree sandbox prior to release authorization.".to_string(),
            },
        ];

        if profile.has_docker {
            phases.push(PlanPhase {
                id: "phase_container".to_string(),
                title: "6. Container Base Image Verification".to_string(),
                subagent_role: "Container Auditor".to_string(),
                goal: "Verify Dockerfile directives and non-root execution posture.".to_string(),
            });
        }

        DefensePlan {
            strategy_name: "Autonomous Pre-Production Defense Matrix".to_string(),
            target_summary: format!(
                "Target: {} file(s) across [{}] (Docker: {})",
                profile.total_files,
                profile.languages.join(", "),
                profile.has_docker
            ),
            rules_applied: rules,
            phases,
        }
    }
}

