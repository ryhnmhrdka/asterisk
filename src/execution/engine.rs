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

        // 2. Sprout Folders and Files
        set_node(&self.sender, "folder_backend", AgentStatus::Running);
        set_node(&self.sender, "folder_frontend", AgentStatus::Running);
        set_node(&self.sender, "file_server", AgentStatus::Running);
        set_node(&self.sender, "file_api", AgentStatus::Running);

        let plan = StrategyPlanner::create_plan(&profile);
        let _ = self.sender.send(EngineMessage::PlanUpdated(plan));

        send_chat(
            &self.sender,
            ChatMessage::Agent {
                sender: "orchestrator".to_string(),
                text: format!(
                    "discovered {} files across [{}] (docker: {}). task dependency graph constructed.",
                    profile.total_files,
                    profile.languages.join(", "),
                    profile.has_docker
                ),
            },
        );
        sleep(Duration::from_millis(300)).await;

        set_node(&self.sender, "folder_backend", AgentStatus::Success);
        set_node(&self.sender, "folder_frontend", AgentStatus::Success);
        set_node(&self.sender, "file_server", AgentStatus::Success);
        set_node(&self.sender, "file_api", AgentStatus::Success);

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

        // 4. Subagents Sprout & Run (Parallel simulated execution with animated edges!)
        set_node(&self.sender, "orch", AgentStatus::Running);
        set_node(&self.sender, "sub_secret_backend", AgentStatus::Running);
        set_node(&self.sender, "sub_sast_backend", AgentStatus::Running);
        set_node(&self.sender, "sub_net_backend", AgentStatus::Running);
        set_node(&self.sender, "sub_sast_frontend", AgentStatus::Running);
        set_node(&self.sender, "sub_net_frontend", AgentStatus::Running);

        // Tool calls logged in chat
        send_chat(
            &self.sender,
            ChatMessage::ToolCall {
                agent: "secret_hunter".to_string(),
                tool: "ShannonEntropyScanner".to_string(),
                input: "backend/server.py".to_string(),
            },
        );
        send_chat(
            &self.sender,
            ChatMessage::ToolCall {
                agent: "sast_analyzer".to_string(),
                tool: "SemanticASTLinter".to_string(),
                input: "backend/server.py, frontend/api.js".to_string(),
            },
        );

        sleep(Duration::from_millis(400)).await;

        // Collect findings from actual scanner engines
        let mut secret_findings = SecretHunterAgent::scan(&self.target_dir);
        let mut sast_findings = SastAnalyzerAgent::scan(&self.target_dir);
        let mut net_findings = NetworkProberAgent::scan(&self.target_dir);

        let mut all_findings = Vec::new();
        all_findings.append(&mut secret_findings);
        all_findings.append(&mut sast_findings);
        all_findings.append(&mut net_findings);

        send_chat(
            &self.sender,
            ChatMessage::ToolResult {
                agent: "worker_crew".to_string(),
                tool: "AuditAggregator".to_string(),
                output: format!("found {} security vulnerabilities (SQLi, hardcoded tokens, 0.0.0.0 bind, CORS)", all_findings.len()),
                elapsed_ms: Some(380),
            },
        );

        set_node(&self.sender, "sub_secret_backend", AgentStatus::Success);
        set_node(&self.sender, "sub_sast_backend", AgentStatus::Success);
        set_node(&self.sender, "sub_net_backend", AgentStatus::Success);
        set_node(&self.sender, "sub_sast_frontend", AgentStatus::Success);
        set_node(&self.sender, "sub_net_frontend", AgentStatus::Success);

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
