use crate::orchestrator::{DefensePlan, StrategyPlanner, WorkspaceScanner};
use crate::subagents::{
    AutoHardeningAgent, NetworkProberAgent, SastAnalyzerAgent, SecretHunterAgent, VerificationAgent,
};
use crate::types::{AgentStatus, DynamicLogEntry, HardeningPatch, VulnerabilityFinding, WorkspaceProfile};
use chrono::Utc;
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
    Chat(String),
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
        let send_chat = |sender: &UnboundedSender<EngineMessage>, msg: &str| {
            let _ = sender.send(EngineMessage::Chat(msg.to_string()));
            let _ = sender.send(EngineMessage::Log(DynamicLogEntry {
                timestamp: Utc::now(),
                agent_name: "orchestrator".to_string(),
                level: "INFO".to_string(),
                message: msg.to_string(),
                is_improvisation: false,
            }));
        };

        let set_node = |sender: &UnboundedSender<EngineMessage>, id: &str, status: AgentStatus| {
            let _ = sender.send(EngineMessage::NodeStatusChanged {
                id: id.to_string(),
                status,
            });
        };

        // 1. Initial Orchestrator Scan
        set_node(&self.sender, "orch", AgentStatus::Planning);
        send_chat(&self.sender, "analyzing target workspace layout...");
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
            &format!(
                "discovered {} files across [{}] (docker: {}).",
                profile.total_files,
                profile.languages.join(", "),
                profile.has_docker
            ),
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
            "ready to deploy specialized worker subagents:\n  • secret hunter (backend/server.py)\n  • sast analyzer (backend/server.py, frontend/api.js)\n  • network prober (backend/server.py, frontend/api.js)\nproceed with deployment? (y/n)",
        );
        let _ = self.sender.send(EngineMessage::AwaitingConfirmation);

        // Wait for user confirmation from command receiver
        loop {
            if let Some(cmd) = self.cmd_rx.recv().await {
                match cmd {
                    EngineCommand::ConfirmDeploy => {
                        send_chat(&self.sender, "confirmation received. deploying subagents...");
                        break;
                    }
                    _ => {}
                }
            } else {
                return;
            }
        }

        // 4. Subagents Sprout & Run (Parallel simulated execution)
        set_node(&self.sender, "orch", AgentStatus::Running);
        set_node(&self.sender, "sub_secret_backend", AgentStatus::Running);
        set_node(&self.sender, "sub_sast_backend", AgentStatus::Running);
        set_node(&self.sender, "sub_net_backend", AgentStatus::Running);
        set_node(&self.sender, "sub_sast_frontend", AgentStatus::Running);
        set_node(&self.sender, "sub_net_frontend", AgentStatus::Running);

        sleep(Duration::from_millis(400)).await;

        // Collect findings from actual scanner engines
        let mut secret_findings = SecretHunterAgent::scan(&self.target_dir);
        let mut sast_findings = SastAnalyzerAgent::scan(&self.target_dir);
        let mut net_findings = NetworkProberAgent::scan(&self.target_dir);

        let mut all_findings = Vec::new();
        all_findings.append(&mut secret_findings);
        all_findings.append(&mut sast_findings);
        all_findings.append(&mut net_findings);

        set_node(&self.sender, "sub_secret_backend", AgentStatus::Success);
        set_node(&self.sender, "sub_sast_backend", AgentStatus::Success);
        set_node(&self.sender, "sub_net_backend", AgentStatus::Success);
        set_node(&self.sender, "sub_sast_frontend", AgentStatus::Success);
        set_node(&self.sender, "sub_net_frontend", AgentStatus::Success);

        send_chat(
            &self.sender,
            &format!("subagents finished. {} vulnerabilities identified.", all_findings.len()),
        );
        let _ = self.sender.send(EngineMessage::FindingsUpdated(all_findings.clone()));

        // 5. Auto-Hardening & Patching
        set_node(&self.sender, "sub_patcher", AgentStatus::Running);
        send_chat(&self.sender, "synthesizing auto-hardening unified diff patches...");
        sleep(Duration::from_millis(450)).await;

        let patches = AutoHardeningAgent::generate_patches(&self.target_dir, &all_findings);
        set_node(&self.sender, "sub_patcher", AgentStatus::Success);
        let _ = self.sender.send(EngineMessage::PatchesUpdated(patches.clone()));

        // 6. Test Verifier
        set_node(&self.sender, "sub_verifier", AgentStatus::Running);
        let _test_suite = VerificationAgent::synthesize_test_suite(&patches);
        sleep(Duration::from_millis(350)).await;
        set_node(&self.sender, "sub_verifier", AgentStatus::Success);

        // 7. Defense Gate Evaluation
        if all_findings.is_empty() {
            set_node(&self.sender, "defense_gate", AgentStatus::Success);
            send_chat(&self.sender, "pre-production defense check clean. build authorized.");
        } else {
            set_node(&self.sender, "defense_gate", AgentStatus::Failed);
            send_chat(
                &self.sender,
                &format!(
                    "defense gate blocked: {} unresolved vulnerabilities. press [a] or type '/apply' to patch.",
                    all_findings.len()
                ),
            );
        }

        set_node(&self.sender, "orch", AgentStatus::Success);
        let _ = self.sender.send(EngineMessage::ScanFinished);
    }
}
