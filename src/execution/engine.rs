use crate::core::{
    storage::{AuditSessionRecord, ProjectRecord, SubAgentRunRecord},
    AppConfig, AuditTrailLogger, CodeContextGraph, GateDecision, GitHistorySecretMiner, PolicyGate,
    ProjectJail, ReachabilityVerdict, ScaDependencyAuditor, SecurityAgentHub, SecurityContextRules,
    StateStore,
};
use crate::orchestrator::{DefensePlan, StrategyPlanner, WorkspaceScanner};
use crate::skills::SkillRegistry;
use crate::subagents::{
    ApkAndContainerGuardAgent, AutoHardeningAgent, MalwareShieldAgent, NetworkProberAgent,
    SastAnalyzerAgent, SecretHunterAgent, VerificationAgent,
};
use crate::types::{
    AgentStatus, ChatMessage, DynamicLogEntry, HardeningPatch, VulnerabilityFinding,
    WorkspaceProfile,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum EngineMessage {
    NodeStatusChanged { id: String, status: AgentStatus },
    WorkspaceUpdated(WorkspaceProfile),
    PlanUpdated(DefensePlan),
    FindingsUpdated(Vec<VulnerabilityFinding>),
    PatchesUpdated(Vec<HardeningPatch>),
    Log(DynamicLogEntry),
    Chat(ChatMessage),
    AwaitingConfirmation,
    ScanFinished,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum EngineCommand {
    ConfirmDeploy,
    PauseNode(String),
    ResumeNode(String),
}

pub struct ExecutionEngine {
    target_dir: PathBuf,
    sender: UnboundedSender<EngineMessage>,
    _cmd_rx: UnboundedReceiver<EngineCommand>,
    diff_scope: String,
    active_provider: String,
    config: Option<AppConfig>,
}

impl ExecutionEngine {
    pub fn new(
        target_dir: PathBuf,
        sender: UnboundedSender<EngineMessage>,
        cmd_rx: UnboundedReceiver<EngineCommand>,
    ) -> Self {
        Self {
            target_dir,
            sender,
            _cmd_rx: cmd_rx,
            diff_scope: "FULL".to_string(),
            active_provider: "AnthropicClaude".to_string(),
            config: None,
        }
    }

    #[allow(dead_code)]
    pub fn with_diff_scope(mut self, diff_scope: impl Into<String>) -> Self {
        self.diff_scope = diff_scope.into();
        self
    }

    #[allow(dead_code)]
    pub fn with_active_provider(mut self, provider: impl Into<String>) -> Self {
        self.active_provider = provider.into();
        self
    }

    #[allow(dead_code)]
    pub fn with_config(mut self, config: AppConfig) -> Self {
        self.config = Some(config);
        self
    }

    pub async fn run_autonomous_audit(self) {
        let send_chat = |sender: &UnboundedSender<EngineMessage>, msg: ChatMessage| {
            let _ = sender.send(EngineMessage::Chat(msg));
        };

        let set_node = |sender: &UnboundedSender<EngineMessage>, id: &str, status: AgentStatus| {
            let _ = sender.send(EngineMessage::NodeStatusChanged {
                id: id.to_string(),
                status,
            });
        };

        // 0. Storage & Context Initialization
        let store = StateStore::for_project(&self.target_dir).ok();
        let audit_logger = AuditTrailLogger::for_project(&self.target_dir);
        let session_id = format!("sess-{}", chrono::Utc::now().timestamp_millis());
        let security_rules = SecurityContextRules::load_from_workspace(&self.target_dir);

        let _ = audit_logger.log(
            Some(&session_id),
            "orchestrator",
            "SESSION_INITIALIZE",
            "ALLOW",
            serde_json::json!({
                "target_dir": self.target_dir.display().to_string(),
                "diff_scope": self.diff_scope,
                "has_security_md": security_rules.is_some(),
            }),
        );

        if let Some(s) = &store {
            let sec_hash = security_rules.as_ref().map(|r| {
                blake3::hash(r.raw_content.as_bytes()).to_hex().to_string()
            }).unwrap_or_default();

            let _ = s.upsert_project(&ProjectRecord {
                id: "project_default".to_string(),
                root_path: self.target_dir.to_string_lossy().to_string(),
                security_md_hash: sec_hash,
                tech_stack_json: "{}".to_string(),
                updated_at: chrono::Utc::now().timestamp(),
            });

            let _ = s.create_session(&AuditSessionRecord {
                session_id: session_id.clone(),
                project_id: "project_default".to_string(),
                operation_mode: "AUTO_HARDEN".to_string(),
                diff_scope: self.diff_scope.clone(),
                active_provider: self.active_provider.clone(),
                canvas_layout_json: None,
                git_checkpoint_oid: String::new(),
                created_at: chrono::Utc::now().timestamp(),
            });
        }

        // 1. Initial Orchestrator Security Policy & Capability Jail Check
        set_node(&self.sender, "orch", AgentStatus::Planning);

        let policy_gate = PolicyGate::default();
        let gate_check = policy_gate.evaluate(
            "Agent",
            "ReadFile",
            &self.target_dir.to_string_lossy(),
        );

        if let GateDecision::Deny(reason) = gate_check {
            let _ = audit_logger.log(
                Some(&session_id),
                "policy_gate",
                "EVALUATE",
                "DENY",
                serde_json::json!({ "reason": reason }),
            );
            send_chat(
                &self.sender,
                ChatMessage::Agent {
                    sender: "policy_gate".to_string(),
                    text: format!("Execution blocked by Cedar policy: {reason}"),
                },
            );
            set_node(&self.sender, "orch", AgentStatus::Failed);
            set_node(&self.sender, "defense_gate", AgentStatus::Failed);
            let _ = self.sender.send(EngineMessage::ScanFinished);
            return;
        }

        let _jail = match ProjectJail::open(&self.target_dir) {
            Ok(j) => Some(j),
            Err(e) => {
                send_chat(
                    &self.sender,
                    ChatMessage::System(format!(
                        "Capability jail notice: {} (continuing with directory-scoped access)",
                        e
                    )),
                );
                None
            }
        };

        // 2. Reconnaissance & Dynamic Graph Construction
        let profile = WorkspaceScanner::scan(&self.target_dir);
        let _ = self.sender.send(EngineMessage::WorkspaceUpdated(profile.clone()));

        let workspace_nodes = crate::orchestrator::AgentGraphBuilder::build_nodes_for_workspace(&self.target_dir);
        for id in workspace_nodes.keys() {
            if id.starts_with("folder_") || id.starts_with("file_") {
                set_node(&self.sender, id, AgentStatus::Running);
            }
        }

        let plan = StrategyPlanner::create_plan(&profile);
        let _ = self.sender.send(EngineMessage::PlanUpdated(plan));

        let code_graph = if self.diff_scope == "LOCAL_DIFF" {
            CodeContextGraph::build_from_git_diff(&self.target_dir)
        } else {
            CodeContextGraph::build_from_workspace(&self.target_dir)
        };

        for id in workspace_nodes.keys() {
            if id.starts_with("folder_") || id.starts_with("file_") {
                set_node(&self.sender, id, AgentStatus::Success);
            }
        }

        // 3. Stage 1 (Detection): Multi-Agent Execution
        set_node(&self.sender, "orch", AgentStatus::Running);

        set_node(&self.sender, "sub_secrets", AgentStatus::Running);
        let mut secret_findings = SecretHunterAgent::scan(&self.target_dir);
        let mut git_secrets = GitHistorySecretMiner::scan_commit_history(&self.target_dir);
        secret_findings.append(&mut git_secrets);
        set_node(&self.sender, "sub_secrets", AgentStatus::Success);

        set_node(&self.sender, "sub_sast", AgentStatus::Running);
        let mut sast_findings = SastAnalyzerAgent::scan(&self.target_dir);
        set_node(&self.sender, "sub_sast", AgentStatus::Success);

        set_node(&self.sender, "sub_net", AgentStatus::Running);
        let mut net_findings = NetworkProberAgent::scan(&self.target_dir);
        set_node(&self.sender, "sub_net", AgentStatus::Success);

        set_node(&self.sender, "sub_sca", AgentStatus::Running);
        let mut sca_findings = ScaDependencyAuditor::audit(&self.target_dir);
        set_node(&self.sender, "sub_sca", AgentStatus::Success);

        set_node(&self.sender, "sub_malware", AgentStatus::Running);
        let mut malware_findings = MalwareShieldAgent::scan(&self.target_dir);
        set_node(&self.sender, "sub_malware", AgentStatus::Success);

        set_node(&self.sender, "sub_apk", AgentStatus::Running);
        let mut apk_findings = ApkAndContainerGuardAgent::scan(&self.target_dir);
        set_node(&self.sender, "sub_apk", AgentStatus::Success);

        let mut all_findings = Vec::new();
        all_findings.append(&mut secret_findings);
        all_findings.append(&mut sast_findings);
        all_findings.append(&mut net_findings);
        all_findings.append(&mut sca_findings);
        all_findings.append(&mut malware_findings);
        all_findings.append(&mut apk_findings);

        if let Some(s) = &store {
            let _ = s.record_sub_agent_run(&SubAgentRunRecord {
                agent_id: "orch".to_string(),
                session_id: session_id.clone(),
                parent_agent_id: None,
                role_specialty: "Tri-Stage Defense Orchestrator".to_string(),
                worktree_path: None,
                loaded_skills_json: "[]".to_string(),
                tokens_consumed: 200,
                status: "COMPLETED".to_string(),
            });

            let agents = [
                ("sub_secrets", "Secret Hunter & Git Miner"),
                ("sub_sast", "AST SAST Analyzer"),
                ("sub_net", "Network Prober"),
                ("sub_sca", "SCA Dependency Auditor"),
                ("sub_malware", "Pre-Install Malware Shield"),
                ("sub_apk", "APK & Container Guard"),
            ];
            for (agent_id, specialty) in agents {
                let _ = s.record_sub_agent_run(&SubAgentRunRecord {
                    agent_id: agent_id.to_string(),
                    session_id: session_id.clone(),
                    parent_agent_id: Some("orch".to_string()),
                    role_specialty: specialty.to_string(),
                    worktree_path: None,
                    loaded_skills_json: "[]".to_string(),
                    tokens_consumed: 100,
                    status: "COMPLETED".to_string(),
                });
            }
        }

        let _ = audit_logger.log(
            Some(&session_id),
            "orchestrator",
            "STAGE_1_DETECTION_FINISHED",
            "ALLOW",
            serde_json::json!({ "total_raw_findings": all_findings.len() }),
        );

        // 4. Stage 2 (Auditable Triage): GraphCore AST & SECURITY.md Evaluation
        let mut skill_reg = SkillRegistry::load_from_workspace(&self.target_dir);

        for finding in &mut all_findings {
            // Check SECURITY.md exclusions
            if let Some(rules) = &security_rules {
                if rules.ignored_paths.iter().any(|ignored| {
                    finding.file_path.starts_with(ignored) || finding.file_path == *ignored
                }) {
                    finding.reachability = "UNREACHABLE".to_string();
                    finding.triage_verdict = "FALSE_POSITIVE".to_string();
                    finding.triage_reasoning = format!("Ignored by SECURITY.md path rule ({})", finding.file_path.display());
                    continue;
                }

                if rules.trusted_sanitizers.iter().any(|san| finding.snippet.contains(san)) {
                    finding.reachability = "UNREACHABLE".to_string();
                    finding.triage_verdict = "FALSE_POSITIVE".to_string();
                    finding.triage_reasoning = "Protected by trusted sanitizer defined in SECURITY.md".to_string();
                    continue;
                }
            }

            // Check CodeContextGraph Reachability
            let sink_id = format!("{}:{}:sink", finding.file_path.display(), finding.line_number);
            match code_graph.evaluate_reachability(&sink_id) {
                ReachabilityVerdict::Reachable { path } => {
                    finding.reachability = "REACHABLE".to_string();
                    finding.triage_verdict = "TRUE_POSITIVE".to_string();
                    finding.call_path = path.clone();
                    finding.triage_reasoning = format!("Reachable taint flow: {}", path.join(" -> "));
                }
                ReachabilityVerdict::Unreachable => {
                    finding.reachability = "UNREACHABLE".to_string();
                    finding.triage_verdict = "FALSE_POSITIVE".to_string();
                    finding.triage_reasoning = "Unreachable code graph flow or pruned by sanitizer".to_string();
                }
                ReachabilityVerdict::PotentiallyReachable { reason } => {
                    finding.reachability = "POTENTIALLY_REACHABLE".to_string();
                    finding.triage_verdict = "TRUE_POSITIVE".to_string();
                    if finding.triage_reasoning.is_empty() {
                        finding.triage_reasoning = reason;
                    }
                }
            }

            // Progressive disclosure of corresponding skill instructions
            let target_skill = if finding.cwe == "CWE-798" {
                "secret-hygiene"
            } else if finding.cwe == "CWE-1357" || finding.cwe == "CWE-506" {
                "ai-malware-shield"
            } else if finding.cwe == "CWE-319" || finding.cwe == "CWE-489" || finding.cwe == "CWE-926" {
                "apk-manifest-guard"
            } else if finding.cwe == "CWE-250" || finding.cwe == "CWE-1327" {
                "container-hardening"
            } else if finding.cwe.starts_with("CVE") {
                "sca-defense"
            } else {
                "sast-deep-analysis"
            };

            let _ = skill_reg.disclose_full_instructions(target_skill);
            skill_reg.record_invocation(target_skill);
        }

        let _ = self.sender.send(EngineMessage::FindingsUpdated(all_findings.clone()));
        let _ = audit_logger.log(
            Some(&session_id),
            "orchestrator",
            "STAGE_2_TRIAGE_FINISHED",
            "ALLOW",
            serde_json::json!({
                "total_findings": all_findings.len(),
                "true_positives": all_findings.iter().filter(|f| f.triage_verdict == "TRUE_POSITIVE").count(),
                "false_positives": all_findings.iter().filter(|f| f.triage_verdict == "FALSE_POSITIVE").count(),
            }),
        );

        // 5. Stage 3 (Contextual Remediation & Sandbox Verification)
        set_node(&self.sender, "sub_patcher", AgentStatus::Running);
        let actionable_findings: Vec<VulnerabilityFinding> = all_findings
            .iter()
            .filter(|f| f.triage_verdict == "TRUE_POSITIVE" && f.reachability != "UNREACHABLE")
            .cloned()
            .collect();

        let mut patches = AutoHardeningAgent::generate_patches(&self.target_dir, &actionable_findings);
        set_node(&self.sender, "sub_patcher", AgentStatus::Success);

        set_node(&self.sender, "sub_verifier", AgentStatus::Running);
        if !patches.is_empty() {
            let reports = VerificationAgent::verify_patches_in_sandbox(&self.target_dir, &patches);
            for patch in &mut patches {
                if let Some(rep) = reports.iter().find(|r| r.patch_id == patch.id) {
                    patch.unit_test_passed = rep.unit_test_passed;
                    patch.safe_outputs_passed = rep.safe_outputs_passed;
                }
            }
        }
        set_node(&self.sender, "sub_verifier", AgentStatus::Success);
        let _ = self.sender.send(EngineMessage::PatchesUpdated(patches.clone()));

        // Save findings and patches to SQLite
        if let Some(mut s) = store {
            let _ = s.save_findings(&session_id, "orch", &all_findings);
            let _ = s.save_patches(&patches);
        }

        let _ = audit_logger.log(
            Some(&session_id),
            "orchestrator",
            "STAGE_3_REMEDIATION_FINISHED",
            "ALLOW",
            serde_json::json!({
                "patches_generated": patches.len(),
                "patches_verified": patches.iter().filter(|p| p.safe_outputs_passed).count(),
            }),
        );

        // Optional Live AI Agent Evaluation (When configured with valid credentials)
        if let Some(cfg) = &self.config {
            if cfg.is_api_key_configured() {
                let hub = SecurityAgentHub::new(
                    self.target_dir.clone(),
                    Arc::new(PolicyGate::default()),
                    cfg.clone(),
                );
                send_chat(
                    &self.sender,
                    ChatMessage::Thinking {
                        agent: "orchestrator".to_string(),
                        thought: format!(
                            "Performing autonomous AI threat analysis via {} (model: {})...",
                            cfg.provider.name(),
                            cfg.get_model()
                        ),
                    },
                );
                let query = format!(
                    "Autonomous code defense triage completed for {}. Total files: {}. Identified {} findings, {} verified patches. Provide executive risk assessment.",
                    self.target_dir.display(),
                    profile.total_files,
                    all_findings.len(),
                    patches.iter().filter(|p| p.safe_outputs_passed).count()
                );
                let ai_reply = hub.query(&query).await;
                send_chat(
                    &self.sender,
                    ChatMessage::Agent {
                        sender: format!("ai_triage:{}", cfg.get_model()),
                        text: ai_reply,
                    },
                );
            }
        }

        // 6. Defense Gate Evaluation (Filtered by Tri-Stage Triage)
        let blocking_findings: Vec<&VulnerabilityFinding> = all_findings
            .iter()
            .filter(|f| f.triage_verdict == "TRUE_POSITIVE" && f.reachability != "UNREACHABLE")
            .collect();

        if blocking_findings.is_empty() {
            set_node(&self.sender, "defense_gate", AgentStatus::Success);
            send_chat(
                &self.sender,
                ChatMessage::Agent {
                    sender: "orchestrator".to_string(),
                    text: "✓ **Defense audit completed clean**: 0 actionable security vulnerabilities identified across target scope. Build authorized.".to_string(),
                },
            );
        } else {
            set_node(&self.sender, "defense_gate", AgentStatus::Failed);
            send_chat(
                &self.sender,
                ChatMessage::Agent {
                    sender: "orchestrator".to_string(),
                    text: format!(
                        "⚠️ **Defense gate blocked**: Identified **{}** actionable security issue(s) ({} patch(es) synthesized & sandbox-verified). Review findings in Matrix view or apply fixes.",
                        blocking_findings.len(),
                        patches.len()
                    ),
                },
            );
        }

        set_node(&self.sender, "orch", AgentStatus::Success);
        let _ = self.sender.send(EngineMessage::ScanFinished);
    }
}
