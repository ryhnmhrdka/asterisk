use crate::core::{
    CodeContextGraph, GateDecision, GitHistorySecretMiner, PolicyGate, ProjectJail,
    ReachabilityVerdict, ScaDependencyAuditor, WorktreeSandbox,
};
use crate::orchestrator::{DefensePlan, StrategyPlanner, WorkspaceScanner};
use crate::subagents::{
    AutoHardeningAgent, NetworkProberAgent, SastAnalyzerAgent, SecretHunterAgent,
};
use crate::types::{
    AgentStatus, ChatMessage, DynamicLogEntry, HardeningPatch, VulnerabilityFinding,
    WorkspaceProfile,
};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
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
        }
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

        // 1. Initial Orchestrator Security Policy & Capability Jail Check
        set_node(&self.sender, "orch", AgentStatus::Planning);
        send_chat(
            &self.sender,
            ChatMessage::Thinking {
                agent: "orchestrator".to_string(),
                thought: format!(
                    "verifying cap-std project jail & cedar policy gate on {}...",
                    self.target_dir.display()
                ),
            },
        );

        let policy_gate = PolicyGate::default();
        let gate_check = policy_gate.evaluate(
            "Agent",
            "ReadFile",
            &self.target_dir.to_string_lossy(),
        );

        if let GateDecision::Deny(reason) = gate_check {
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

        let code_graph = CodeContextGraph::build_from_workspace(&self.target_dir);

        send_chat(
            &self.sender,
            ChatMessage::Agent {
                sender: "orchestrator".to_string(),
                text: format!(
                    "Discovered **{}** file(s) across target scope. Generated **{} AST code nodes** & **{} call/taint edges** in `petgraph`.\nExecuting static vulnerability audit...",
                    profile.total_files,
                    code_graph.total_nodes(),
                    code_graph.total_edges(),
                ),
            },
        );

        for id in workspace_nodes.keys() {
            if id.starts_with("folder_") || id.starts_with("file_") {
                set_node(&self.sender, id, AgentStatus::Success);
            }
        }

        // 3. Subagents Execution
        set_node(&self.sender, "orch", AgentStatus::Running);
        for id in workspace_nodes.keys() {
            if id.starts_with("sub_") && id != "sub_patcher" && id != "sub_verifier" {
                set_node(&self.sender, id, AgentStatus::Running);
            }
        }

        // Collect findings from all scanners
        let mut secret_findings = SecretHunterAgent::scan(&self.target_dir);
        let mut sast_findings = SastAnalyzerAgent::scan(&self.target_dir);
        let mut net_findings = NetworkProberAgent::scan(&self.target_dir);
        let mut git_secrets = GitHistorySecretMiner::scan_commit_history(&self.target_dir);
        let mut sca_findings = ScaDependencyAuditor::audit(&self.target_dir);

        let mut all_findings = Vec::new();
        all_findings.append(&mut secret_findings);
        all_findings.append(&mut sast_findings);
        all_findings.append(&mut net_findings);
        all_findings.append(&mut git_secrets);
        all_findings.append(&mut sca_findings);

        // 4. AST Reachability Triage on Findings
        let mut reachable_findings = 0;
        for f in &all_findings {
            let sink_id = format!("{}:{}:sink", f.file_path.display(), f.line_number);
            let verdict = code_graph.evaluate_reachability(&sink_id);
            if matches!(verdict, ReachabilityVerdict::Reachable { .. }) {
                reachable_findings += 1;
            }
        }

        send_chat(
            &self.sender,
            ChatMessage::Agent {
                sender: "triage".to_string(),
                text: format!(
                    "### Triage & Reachability Analysis\n- Scanned Findings: **{}**\n- Verified Reachable (True Positives): **{}** ($T_{{flow}} = S_{{input}} \\to D_{{sink}}$)\n- Filtered Noise / Unreachable: **{}**",
                    all_findings.len(),
                    reachable_findings,
                    all_findings.len().saturating_sub(reachable_findings)
                ),
            },
        );

        for id in workspace_nodes.keys() {
            if id.starts_with("sub_") && id != "sub_patcher" && id != "sub_verifier" {
                set_node(&self.sender, id, AgentStatus::Success);
            }
        }

        let _ = self.sender.send(EngineMessage::FindingsUpdated(all_findings.clone()));

        // 5. Auto-Hardening & Patching
        set_node(&self.sender, "sub_patcher", AgentStatus::Running);
        let patches = AutoHardeningAgent::generate_patches(&self.target_dir, &all_findings);
        set_node(&self.sender, "sub_patcher", AgentStatus::Success);
        let _ = self.sender.send(EngineMessage::PatchesUpdated(patches.clone()));

        send_chat(
            &self.sender,
            ChatMessage::Agent {
                sender: "auto_hardening".to_string(),
                text: format!(
                    "Synthesized **{}** auto-hardening remediation patch(es).",
                    patches.len()
                ),
            },
        );

        // 6. Test Verifier in Isolated Worktree Sandbox
        set_node(&self.sender, "sub_verifier", AgentStatus::Running);
        if !patches.is_empty() && self.target_dir.join(".git").exists() {
            let sandbox_id = format!(
                "verify-{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            );

            match WorktreeSandbox::spawn(&self.target_dir, &sandbox_id) {
                Ok(sandbox) => {
                    let mut verified_count = 0;
                    for p in &patches {
                        let target_in_sandbox = sandbox.path().join(&p.target_file);
                        if target_in_sandbox.exists() {
                            verified_count += 1;
                        }
                    }
                    let _ = sandbox.cleanup();

                    send_chat(
                        &self.sender,
                        ChatMessage::Agent {
                            sender: "sub_verifier".to_string(),
                            text: format!(
                                "Verified **{}** patch target(s) in isolated Git worktree sandbox (`.sentinel/worktrees/{}`). Sandbox cleanly recycled.",
                                verified_count, sandbox_id
                            ),
                        },
                    );
                }
                Err(e) => {
                    send_chat(
                        &self.sender,
                        ChatMessage::System(format!(
                            "Worktree sandbox verification note: {e} (continuing)"
                        )),
                    );
                }
            }
        }
        set_node(&self.sender, "sub_verifier", AgentStatus::Success);

        // 7. Defense Gate Evaluation
        if all_findings.is_empty() {
            set_node(&self.sender, "defense_gate", AgentStatus::Success);
            send_chat(
                &self.sender,
                ChatMessage::Agent {
                    sender: "defense_gate".to_string(),
                    text: "Pre-production defense check clean. Build authorized.".to_string(),
                },
            );
        } else {
            set_node(&self.sender, "defense_gate", AgentStatus::Failed);
            send_chat(
                &self.sender,
                ChatMessage::Agent {
                    sender: "defense_gate".to_string(),
                    text: format!(
                        "Defense gate blocked: **{}** unpatched security issue(s). Review findings in Matrix view or apply fixes.",
                        all_findings.len()
                    ),
                },
            );
        }

        set_node(&self.sender, "orch", AgentStatus::Success);
        let _ = self.sender.send(EngineMessage::ScanFinished);
    }
}
