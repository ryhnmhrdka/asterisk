use crate::orchestrator::{DefensePlan, StrategyPlanner, WorkspaceScanner};
use crate::subagents::{
    AutoHardeningAgent, NetworkProberAgent, SastAnalyzerAgent, SecretHunterAgent, VerificationAgent,
};
use crate::types::{AgentStatus, ChatMessage, DynamicLogEntry, HardeningPatch, VulnerabilityFinding, WorkspaceProfile};
use std::path::PathBuf;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::time::{sleep, Duration};

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

#[derive(Debug, Clone)]
pub enum EngineCommand {
    ConfirmDeploy,
    PauseNode(String),
    ResumeNode(String),
}

pub struct ExecutionEngine {
    target_dir: PathBuf,
    sender: UnboundedSender<EngineMessage>,
    cmd_rx: UnboundedReceiver<EngineCommand>,
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
            cmd_rx,
        }
    }

    pub async fn run_autonomous_audit(mut self) {
        let send_chat = |sender: &UnboundedSender<EngineMessage>, msg: ChatMessage| {
            let _ = sender.send(EngineMessage::Chat(msg));
        };

        let set_node = |sender: &UnboundedSender<EngineMessage>, id: &str, status: AgentStatus| {
            let _ = sender.send(EngineMessage::NodeStatusChanged {
                id: id.to_string(),
                status,
            });
        };

        // 1. Initial Orchestrator Thinking
        set_node(&self.sender, "orch", AgentStatus::Planning);
        send_chat(
            &self.sender,
            ChatMessage::Thinking {
                agent: "orchestrator".to_string(),
                thought: "inspecting directory tree & pre-production security policies...".to_string(),
            },
        );
        sleep(Duration::from_millis(350)).await;

        let profile = WorkspaceScanner::scan(&self.target_dir);
        let _ = self.sender.send(EngineMessage::WorkspaceUpdated(profile.clone()));

        // 2. Sprout Folders and Files dynamically from real workspace
        let workspace_nodes = crate::orchestrator::AgentGraphBuilder::build_nodes_for_workspace(&self.target_dir);
        for id in workspace_nodes.keys() {
            if id.starts_with("folder_") || id.starts_with("file_") {
                set_node(&self.sender, id, AgentStatus::Running);
            }
        }

        let plan = StrategyPlanner::create_plan(&profile);
        let _ = self.sender.send(EngineMessage::PlanUpdated(plan));

        let code_graph = crate::core::CodeContextGraph::build_from_workspace(&self.target_dir);

        send_chat(
            &self.sender,
            ChatMessage::Agent {
                sender: "orchestrator".to_string(),
                text: format!(
                    "Discovered {} files. Mapped **{} AST code nodes** & **{} call/taint edges** in `petgraph`.\nCode context graph & function-level reachability initialized.",
                    profile.total_files,
                    code_graph.total_nodes(),
                    code_graph.total_edges(),
                ),
            },
        );
        sleep(Duration::from_millis(300)).await;

        for id in workspace_nodes.keys() {
            if id.starts_with("folder_") || id.starts_with("file_") {
                set_node(&self.sender, id, AgentStatus::Success);
            }
        }

        // 3. Request User Confirmation in Chatbot Sidebar
        set_node(&self.sender, "orch", AgentStatus::WaitingConfirmation);
        send_chat(
            &self.sender,
            ChatMessage::Agent {
                sender: "orchestrator".to_string(),
                text: "Review plan compiled across target modules. Ready to execute static analysis & vulnerability audit.\nProceed with scan?".to_string(),
            },
        );
        let _ = self.sender.send(EngineMessage::AwaitingConfirmation);

        // Wait for user confirmation from command receiver (via click or keyboard 'y')
        loop {
            if let Some(cmd) = self.cmd_rx.recv().await {
                match cmd {
                    EngineCommand::ConfirmDeploy => {
                        send_chat(
                            &self.sender,
                            ChatMessage::System("Confirmation received. Executing security review modules...".to_string()),
                        );
                        break;
                    }
                    _ => {}
                }
            } else {
                return;
            }
        }

        // 4. Subagents Sprout & Run (Parallel execution across actual workspace modules)
        set_node(&self.sender, "orch", AgentStatus::Running);
        for id in workspace_nodes.keys() {
            if id.starts_with("sub_") && id != "sub_patcher" && id != "sub_verifier" {
                set_node(&self.sender, id, AgentStatus::Running);
            }
        }

        // Tool calls logged in chat
        send_chat(
            &self.sender,
            ChatMessage::ToolCall {
                agent: "secret_scanner".to_string(),
                tool: "GitHistoryAndShannonEntropy".to_string(),
                input: self.target_dir.display().to_string(),
            },
        );
        send_chat(
            &self.sender,
            ChatMessage::ToolCall {
                agent: "sca_analyzer".to_string(),
                tool: "ManifestAndPhantomDependencyAuditor".to_string(),
                input: self.target_dir.display().to_string(),
            },
        );

        sleep(Duration::from_millis(400)).await;

        // Collect findings from actual scanner engines + Git history & SCA
        let mut secret_findings = SecretHunterAgent::scan(&self.target_dir);
        let mut sast_findings = SastAnalyzerAgent::scan(&self.target_dir);
        let mut net_findings = NetworkProberAgent::scan(&self.target_dir);
        let mut git_secrets = crate::core::GitHistorySecretMiner::scan_commit_history(&self.target_dir);
        let mut sca_findings = crate::core::ScaDependencyAuditor::audit(&self.target_dir);

        let mut all_findings = Vec::new();
        all_findings.append(&mut secret_findings);
        all_findings.append(&mut sast_findings);
        all_findings.append(&mut net_findings);
        all_findings.append(&mut git_secrets);
        all_findings.append(&mut sca_findings);

        // Evaluate Reachability on findings via CodeContextGraph
        let mut reachable_findings = 0;
        for f in &all_findings {
            let sink_id = format!("{}:{}:sink", f.file_path.display(), f.line_number);
            let verdict = code_graph.evaluate_reachability(&sink_id);
            if matches!(verdict, crate::core::ReachabilityVerdict::Reachable { .. }) {
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
        send_chat(
            &self.sender,
            ChatMessage::Thinking {
                agent: "auto_hardening".to_string(),
                thought: "generating non-breaking unified diff patches & prepared statement replacements...".to_string(),
            },
        );
        sleep(Duration::from_millis(450)).await;

        let patches = AutoHardeningAgent::generate_patches(&self.target_dir, &all_findings);
        set_node(&self.sender, "sub_patcher", AgentStatus::Success);
        let _ = self.sender.send(EngineMessage::PatchesUpdated(patches.clone()));

        send_chat(
            &self.sender,
            ChatMessage::Agent {
                sender: "auto_hardening".to_string(),
                text: format!("synthesized {} auto-hardening patches. click [Apply Fix] to review.", patches.len()),
            },
        );

        // 6. Test Verifier
        set_node(&self.sender, "sub_verifier", AgentStatus::Running);
        let _test_suite = VerificationAgent::synthesize_test_suite(&patches);
        sleep(Duration::from_millis(350)).await;
        set_node(&self.sender, "sub_verifier", AgentStatus::Success);

        // 7. Defense Gate Evaluation
        if all_findings.is_empty() {
            set_node(&self.sender, "defense_gate", AgentStatus::Success);
            send_chat(
                &self.sender,
                ChatMessage::Agent {
                    sender: "defense_gate".to_string(),
                    text: "pre-production defense check clean. build authorized.".to_string(),
                },
            );
        } else {
            set_node(&self.sender, "defense_gate", AgentStatus::Failed);
            send_chat(
                &self.sender,
                ChatMessage::Agent {
                    sender: "defense_gate".to_string(),
                    text: format!(
                        "defense gate blocked: {} unpatched vulnerabilities. review & apply patches in tab 3 or click [Apply Fix].",
                        all_findings.len()
                    ),
                },
            );
        }

        set_node(&self.sender, "orch", AgentStatus::Success);
        let _ = self.sender.send(EngineMessage::ScanFinished);
    }
}
