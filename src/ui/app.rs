use crate::execution::{EngineCommand, EngineMessage, ExecutionEngine};
use crate::orchestrator::{AgentGraphBuilder, DefensePlan, WorkspaceScanner};
use crate::skills::SkillRegistry;
use crate::subagents::AutoHardeningAgent;
use crate::types::{
    get_matching_commands, AgentStatus, AiProvider, ChatMessage, DynamicLogEntry, HardeningPatch,
    SproutedNodeInfo, VulnerabilityFinding, WorkspaceProfile,
};
use crate::ui::views::{
    GraphView, LogsView, MatrixView, ModalClickTargets, ModalView, PatchClickTargets, PatchView,
    SidebarClickTargets, SidebarView, SkillsView, WelcomeView,
};
use chrono::Utc;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use rataflow::{Flow, FlowEvent, StepEdge, TextContent};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Paragraph, Tabs},
    Frame,
};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use crate::core::{AppConfig, PolicyGate, SecurityAgentHub};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppMode {
    Welcome,
    Workspace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveModal {
    None,
    SelectProvider,
    SelectModel,
    ApiKeyInput,
    BaseUrlInput,
}

#[derive(Default)]
pub struct AppClickTargets {
    pub welcome_btn: Option<Rect>,
    pub tab_rects: Vec<(usize, Rect)>,
    pub sidebar: Option<SidebarClickTargets>,
    pub findings_table: Option<Rect>,
    pub patches: Option<PatchClickTargets>,
    pub modal: Option<ModalClickTargets>,
}

pub struct App {
    pub mode: AppMode,
    pub current_tab: usize,
    pub target_dir: PathBuf,
    pub welcome_input: String,
    pub prompt_input: String,

    pub flow: Flow<TextContent, StepEdge>,
    pub nodes_info: HashMap<String, SproutedNodeInfo>,
    pub selected_node_id: Option<String>,

    pub profile: WorkspaceProfile,
    pub plan: Option<DefensePlan>,
    pub findings: Vec<VulnerabilityFinding>,
    pub patches: Vec<HardeningPatch>,
    pub logs: Vec<DynamicLogEntry>,
    pub chat_messages: Vec<ChatMessage>,
    pub chat_scroll: usize,
    pub skills: SkillRegistry,

    pub selected_matrix_row: usize,
    pub selected_patch_row: usize,
    pub action_msg: Option<String>,
    pub is_running: bool,
    pub awaiting_confirmation: bool,
    pub active_provider: AiProvider,
    pub config: AppConfig,
    pub expanded_messages: HashSet<usize>,
    pub show_key_modal: bool,
    pub active_modal: ActiveModal,
    pub selected_provider_index: usize,
    pub selected_model_index: usize,
    pub modal_field: usize,
    pub key_modal_input: String,
    pub model_modal_input: String,
    pub url_modal_input: String,
    pub key_modal_error: Option<String>,
    pub suggestion_index: usize,
    pub should_quit: bool,

    pub engine_rx: UnboundedReceiver<EngineMessage>,
    pub engine_tx: UnboundedSender<EngineMessage>,
    pub cmd_tx: UnboundedSender<EngineCommand>,
    pub cmd_rx: Option<UnboundedReceiver<EngineCommand>>,

    pub click_targets: AppClickTargets,
}

impl App {
    pub fn new(initial_target: PathBuf, start_in_welcome: bool) -> Self {
        let (tx, rx) = unbounded_channel();
        let (cmd_tx, cmd_rx) = unbounded_channel();

        let profile = WorkspaceScanner::scan(&initial_target);
        let nodes_info = std::collections::HashMap::new();
        let flow = Flow::new();
        let skills = SkillRegistry::new();
        let config = AppConfig::load();
        let active_provider = config.provider;

        Self {
            mode: if start_in_welcome { AppMode::Welcome } else { AppMode::Workspace },
            current_tab: 0,
            target_dir: initial_target,
            welcome_input: String::new(),
            prompt_input: String::new(),
            flow,
            nodes_info,
            selected_node_id: None,
            profile,
            plan: None,
            findings: Vec::new(),
            patches: Vec::new(),
            logs: Vec::new(),
            chat_messages: Vec::new(),
            chat_scroll: 0,
            skills,
            selected_matrix_row: 0,
            selected_patch_row: 0,
            action_msg: None,
            is_running: false,
            awaiting_confirmation: false,
            active_provider,
            config,
            expanded_messages: HashSet::new(),
            show_key_modal: false,
            active_modal: ActiveModal::None,
            selected_provider_index: 0,
            selected_model_index: 0,
            modal_field: 0,
            key_modal_input: String::new(),
            model_modal_input: String::new(),
            url_modal_input: String::new(),
            key_modal_error: None,
            suggestion_index: 0,
            should_quit: false,
            engine_rx: rx,
            engine_tx: tx,
            cmd_tx,
            cmd_rx: Some(cmd_rx),
            click_targets: AppClickTargets::default(),
        }
    }

    pub fn open_provider_modal(&mut self) {
        self.show_key_modal = true;
        self.active_modal = ActiveModal::SelectProvider;
        self.modal_field = 0;
        self.key_modal_error = None;
        let all = AiProvider::ALL;
        self.selected_provider_index = all.iter().position(|p| *p == self.active_provider).unwrap_or(0);
    }

    pub fn open_model_modal(&mut self) {
        self.show_key_modal = true;
        self.active_modal = ActiveModal::SelectModel;
        self.modal_field = 1;
        self.key_modal_error = None;
        self.model_modal_input = self.config.get_model();
        let presets = self.active_provider.preset_models();
        self.selected_model_index = presets.iter().position(|m| *m == self.model_modal_input).unwrap_or(0);
    }

    pub fn open_key_modal(&mut self) {
        self.show_key_modal = true;
        self.active_modal = ActiveModal::ApiKeyInput;
        self.modal_field = 2;
        self.key_modal_error = None;
        self.key_modal_input = self.config.get_api_key().unwrap_or_default();
    }

    pub fn open_url_modal(&mut self) {
        self.show_key_modal = true;
        self.active_modal = ActiveModal::BaseUrlInput;
        self.modal_field = 1;
        self.key_modal_error = None;
        self.url_modal_input = self.config.get_base_url().unwrap_or_default();
    }

    pub fn open_provider_model_modal(&mut self, initial_field: usize) {
        if initial_field == 0 {
            self.open_provider_modal();
        } else {
            self.open_model_modal();
        }
    }

    pub fn open_setup_modal(&mut self, initial_field: usize) {
        if initial_field == 1 {
            self.open_url_modal();
        } else {
            self.open_key_modal();
        }
    }

    pub fn open_config_modal(&mut self, initial_field: usize) {
        match initial_field {
            0 => self.open_provider_modal(),
            1 => self.open_model_modal(),
            2 => self.open_key_modal(),
            _ => self.open_url_modal(),
        }
    }

    pub fn trigger_audit(&mut self) {
        if self.is_running {
            return;
        }

        if !self.config.is_api_key_configured() {
            self.open_key_modal();
            self.action_msg = Some("API key required to execute defense workflow.".to_string());
            return;
        }

        self.is_running = true;
        self.awaiting_confirmation = false;
        self.action_msg = Some("scanning workspace...".to_string());

        // Construct dynamic workflow graph for target
        self.nodes_info = AgentGraphBuilder::build_nodes_for_workspace(&self.target_dir);
        if let Ok(flow) = AgentGraphBuilder::build_sprouted_graph(&self.nodes_info) {
            self.flow = flow;
        }
        self.selected_node_id = Some("orch".to_string());

        let target = self.target_dir.clone();
        let sender = self.engine_tx.clone();
        let cmd_rx = self.cmd_rx.take().unwrap_or_else(|| {
            let (new_tx, new_rx) = unbounded_channel();
            self.cmd_tx = new_tx;
            new_rx
        });

        tokio::spawn(async move {
            let engine = ExecutionEngine::new(target, sender, cmd_rx);
            engine.run_autonomous_audit().await;
        });
    }

    pub fn confirm_subagent_deployment(&mut self) {
        self.awaiting_confirmation = false;
        let _ = self.cmd_tx.send(EngineCommand::ConfirmDeploy);
    }

    pub fn cancel_subagent_deployment(&mut self) {
        self.awaiting_confirmation = false;
        self.is_running = false;
    }

    pub fn toggle_pause_selected_node(&mut self) {
        if let Some(id) = &self.selected_node_id {
            let node_id = id.clone();
            if let Some(node) = self.nodes_info.get_mut(&node_id) {
                node.is_paused = !node.is_paused;
                let state_str = if node.is_paused { "paused" } else { "resumed" };
                self.action_msg = Some(format!("node {} {state_str}", node.id));

                if node.is_paused {
                    let _ = self.cmd_tx.send(EngineCommand::PauseNode(node_id));
                } else {
                    let _ = self.cmd_tx.send(EngineCommand::ResumeNode(node_id));
                }
            }
            if let Ok(updated_flow) = AgentGraphBuilder::build_sprouted_graph(&self.nodes_info) {
                self.flow = updated_flow;
            }
        }
    }

    pub fn check_defense_gate_status(&mut self) {
        let unpatched_count = self.findings.iter().filter(|f| !f.patched).count();
        if unpatched_count == 0 && !self.findings.is_empty() {
            if let Some(gate) = self.nodes_info.get_mut("defense_gate") {
                gate.status = AgentStatus::Success;
            }
            if let Ok(updated_flow) = AgentGraphBuilder::build_sprouted_graph(&self.nodes_info) {
                self.flow = updated_flow;
            }
            self.action_msg = Some("all vulnerabilities mitigated. defense gate open.".to_string());
        }
    }

    pub fn export_security_report(&mut self) {
        let report_path = self.target_dir.join("security-audit-report.json");
        let report = serde_json::json!({
            "generated_at": Utc::now().to_rfc3339(),
            "target": self.target_dir.display().to_string(),
            "total_files": self.profile.total_files,
            "languages": self.profile.languages,
            "findings_count": self.findings.len(),
            "unpatched_count": self.findings.iter().filter(|f| !f.patched).count(),
            "findings": self.findings,
            "patches": self.patches,
        });

        match std::fs::write(&report_path, serde_json::to_string_pretty(&report).unwrap_or_default()) {
            Ok(()) => {
                let name = report_path.file_name().unwrap_or_default().to_string_lossy();
                self.action_msg = Some(format!("report exported -> {name}"));
                self.chat_messages.push(ChatMessage::System(format!("security report written to {name}.")));
            }
            Err(e) => {
                self.action_msg = Some(format!("export error: {e}"));
            }
        }
    }

    pub fn update(&mut self) {
        while let Ok(msg) = self.engine_rx.try_recv() {
            match msg {
                EngineMessage::NodeStatusChanged { id, status } => {
                    if let Some(node) = self.nodes_info.get_mut(&id) {
                        node.status = status;
                    }
                    if let Ok(updated_flow) = AgentGraphBuilder::build_sprouted_graph(&self.nodes_info) {
                        self.flow = updated_flow;
                    }
                }
                EngineMessage::WorkspaceUpdated(p) => {
                    self.profile = p;
                }
                EngineMessage::PlanUpdated(pl) => {
                    self.plan = Some(pl);
                }
                EngineMessage::FindingsUpdated(f) => {
                    self.findings = f;
                }
                EngineMessage::PatchesUpdated(p) => {
                    self.patches = p;
                }
                EngineMessage::Log(l) => {
                    self.logs.push(l);
                }
                EngineMessage::Chat(msg) => {
                    self.chat_messages.push(msg);
                }
                EngineMessage::AwaitingConfirmation => {
                    self.awaiting_confirmation = true;
                    self.action_msg = Some("click [Deploy Subagents] or type 'y' in sidebar...".to_string());
                }
                EngineMessage::ScanFinished => {
                    self.is_running = false;
                    self.awaiting_confirmation = false;
                    self.check_defense_gate_status();
                    self.action_msg = Some(format!(
                        "scan finished. {} findings, {} patches ready.",
                        self.findings.len(),
                        self.patches.len()
                    ));
                }
            }
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        if self.should_quit {
            return true;
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return true;
        }

        if self.show_key_modal {
            return self.handle_modal_key(key);
        }

        let res = match self.mode {
            AppMode::Welcome => self.handle_welcome_key(key),
            AppMode::Workspace => self.handle_workspace_key(key),
        };
        res || self.should_quit
    }

    pub fn save_key_modal(&mut self) -> bool {
        let k = self.key_modal_input.trim();
        if k.is_empty() && self.config.requires_api_key() {
            self.key_modal_error = Some("API key cannot be empty.".to_string());
            return false;
        }
        self.config.api_key = if k.is_empty() { None } else { Some(k.to_string()) };
        self.config.provider = self.active_provider;
        let _ = self.config.save();
        self.show_key_modal = false;
        self.active_modal = ActiveModal::None;
        self.key_modal_error = None;
        self.action_msg = Some(format!("API key configured for {}.", self.active_provider.name()));
        true
    }

    pub fn save_modal_config(&mut self) -> bool {
        match self.active_modal {
            ActiveModal::ApiKeyInput => self.save_key_modal(),
            ActiveModal::BaseUrlInput => {
                let u = self.url_modal_input.trim();
                self.config.base_url = if u.is_empty() { None } else { Some(u.to_string()) };
                let _ = self.config.save();
                if self.config.requires_api_key() && !self.config.is_api_key_configured() {
                    self.open_key_modal();
                } else {
                    self.show_key_modal = false;
                    self.active_modal = ActiveModal::None;
                }
                true
            }
            ActiveModal::SelectModel => {
                self.handle_model_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()))
            }
            ActiveModal::SelectProvider => {
                self.handle_provider_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()))
            }
            ActiveModal::None => {
                self.show_key_modal = false;
                true
            }
        }
    }

    fn handle_modal_key(&mut self, key: KeyEvent) -> bool {
        match self.active_modal {
            ActiveModal::SelectProvider => self.handle_provider_key(key),
            ActiveModal::SelectModel => self.handle_model_key(key),
            ActiveModal::ApiKeyInput => self.handle_key_input_key(key),
            ActiveModal::BaseUrlInput => self.handle_url_input_key(key),
            ActiveModal::None => {
                self.show_key_modal = false;
                false
            }
        }
    }

    fn handle_provider_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.show_key_modal = false;
                self.active_modal = ActiveModal::None;
                false
            }
            KeyCode::Up => {
                let len = AiProvider::ALL.len();
                if self.selected_provider_index == 0 {
                    self.selected_provider_index = len - 1;
                } else {
                    self.selected_provider_index -= 1;
                }
                if let Some(p) = AiProvider::ALL.get(self.selected_provider_index) {
                    self.active_provider = *p;
                    self.config.provider = *p;
                }
                false
            }
            KeyCode::Down | KeyCode::Tab => {
                let len = AiProvider::ALL.len();
                self.selected_provider_index = (self.selected_provider_index + 1) % len;
                if let Some(p) = AiProvider::ALL.get(self.selected_provider_index) {
                    self.active_provider = *p;
                    self.config.provider = *p;
                }
                false
            }
            KeyCode::Char(c @ '1'..='6') => {
                let idx = (c as usize) - ('1' as usize);
                if idx < AiProvider::ALL.len() {
                    self.selected_provider_index = idx;
                    self.active_provider = AiProvider::ALL[idx];
                    self.config.provider = self.active_provider;
                }
                false
            }
            KeyCode::Enter => {
                if let Some(p) = AiProvider::ALL.get(self.selected_provider_index) {
                    self.active_provider = *p;
                    self.config.provider = *p;
                }
                if self.active_provider == AiProvider::Custom && self.config.get_base_url().is_none() {
                    self.open_url_modal();
                } else {
                    self.open_model_modal();
                }
                false
            }
            _ => false,
        }
    }

    fn handle_model_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.show_key_modal = false;
                self.active_modal = ActiveModal::None;
                false
            }
            KeyCode::Up => {
                let presets = self.active_provider.preset_models();
                if !presets.is_empty() {
                    if self.selected_model_index == 0 {
                        self.selected_model_index = presets.len() - 1;
                    } else {
                        self.selected_model_index -= 1;
                    }
                    self.model_modal_input = presets[self.selected_model_index].to_string();
                }
                false
            }
            KeyCode::Down | KeyCode::Tab => {
                let presets = self.active_provider.preset_models();
                if !presets.is_empty() {
                    self.selected_model_index = (self.selected_model_index + 1) % presets.len();
                    self.model_modal_input = presets[self.selected_model_index].to_string();
                }
                false
            }
            KeyCode::Enter => {
                let presets = self.active_provider.preset_models();
                let chosen = if let Some(m) = presets.get(self.selected_model_index) {
                    m.to_string()
                } else {
                    self.active_provider.default_model().to_string()
                };
                self.config.provider = self.active_provider;
                self.config.model = Some(chosen.clone());
                self.model_modal_input = chosen.clone();

                if self.config.requires_api_key() && !self.config.is_api_key_configured() {
                    self.open_key_modal();
                } else {
                    let _ = self.config.save();
                    self.show_key_modal = false;
                    self.active_modal = ActiveModal::None;
                    self.action_msg = Some(format!("provider & model set to {} / {chosen}.", self.active_provider.name()));
                }
                false
            }
            _ => false,
        }
    }

    fn handle_key_input_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.show_key_modal = false;
                self.active_modal = ActiveModal::None;
                self.key_modal_error = None;
                false
            }
            KeyCode::Backspace => {
                self.key_modal_input.pop();
                false
            }
            KeyCode::Enter => {
                self.save_key_modal();
                false
            }
            KeyCode::Char(c) => {
                self.key_modal_input.push(c);
                false
            }
            _ => false,
        }
    }

    fn handle_url_input_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.show_key_modal = false;
                self.active_modal = ActiveModal::None;
                self.key_modal_error = None;
                false
            }
            KeyCode::Backspace => {
                self.url_modal_input.pop();
                false
            }
            KeyCode::Enter => {
                let u = self.url_modal_input.trim();
                self.config.base_url = if u.is_empty() { None } else { Some(u.to_string()) };
                let _ = self.config.save();
                if self.config.requires_api_key() && !self.config.is_api_key_configured() {
                    self.open_key_modal();
                } else {
                    self.show_key_modal = false;
                    self.active_modal = ActiveModal::None;
                    self.action_msg = Some(format!("base URL updated for {}.", self.active_provider.name()));
                }
                false
            }
            KeyCode::Char(c) => {
                self.url_modal_input.push(c);
                false
            }
            _ => false,
        }
    }

    fn handle_welcome_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => true,
            KeyCode::Tab => {
                self.active_provider = self.active_provider.next();
                self.config.provider = self.active_provider;
                let _ = self.config.save();
                false
            }
            KeyCode::Enter => {
                if !self.config.is_api_key_configured() {
                    self.open_config_modal(2);
                    self.action_msg = Some("authentication required: please set API key to proceed.".to_string());
                    return false;
                }

                let input = self.welcome_input.trim().to_string();
                if !input.is_empty() {
                    if std::path::Path::new(&input).exists() {
                        self.target_dir = PathBuf::from(&input);
                    } else {
                        self.chat_messages.push(ChatMessage::User(input.clone()));
                        let hub = SecurityAgentHub::new(self.target_dir.clone(), Arc::new(PolicyGate::default()), self.config.clone());
                        let sender = self.engine_tx.clone();
                        tokio::spawn(async move {
                            let reply = hub.query(&input).await;
                            let _ = sender.send(EngineMessage::Chat(ChatMessage::Agent {
                                sender: "orchestrator".to_string(),
                                text: reply,
                            }));
                        });
                    }
                }
                self.profile = WorkspaceScanner::scan(&self.target_dir);
                self.mode = AppMode::Workspace;
                false
            }
            KeyCode::Backspace => {
                self.welcome_input.pop();
                false
            }
            KeyCode::Char(c) => {
                self.welcome_input.push(c);
                false
            }
            _ => false,
        }
    }

    fn handle_workspace_key(&mut self, key: KeyEvent) -> bool {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return true;
        }

        let suggestions = get_matching_commands(&self.prompt_input);
        let has_suggestions = !suggestions.is_empty();

        if has_suggestions {
            match key.code {
                KeyCode::Up => {
                    if self.suggestion_index > 0 {
                        self.suggestion_index -= 1;
                    } else {
                        self.suggestion_index = suggestions.len().saturating_sub(1);
                    }
                    return false;
                }
                KeyCode::Down => {
                    if self.suggestion_index + 1 < suggestions.len() {
                        self.suggestion_index += 1;
                    } else {
                        self.suggestion_index = 0;
                    }
                    return false;
                }
                KeyCode::Tab => {
                    if let Some(cmd) = suggestions.get(self.suggestion_index) {
                        self.prompt_input = if cmd.args.is_empty() {
                            cmd.name.to_string()
                        } else {
                            format!("{} ", cmd.name)
                        };
                        self.suggestion_index = 0;
                    }
                    return false;
                }
                KeyCode::Esc => {
                    self.prompt_input.clear();
                    self.suggestion_index = 0;
                    return false;
                }
                KeyCode::Enter => {
                    if let Some(cmd) = suggestions.get(self.suggestion_index) {
                        if self.prompt_input == cmd.name || cmd.args.is_empty() {
                            self.prompt_input = cmd.name.to_string();
                            return self.submit_prompt_input();
                        } else {
                            self.prompt_input = format!("{} ", cmd.name);
                            self.suggestion_index = 0;
                            return false;
                        }
                    }
                }
                KeyCode::Backspace => {
                    self.prompt_input.pop();
                    self.suggestion_index = 0;
                    return false;
                }
                KeyCode::Char(c) => {
                    self.prompt_input.push(c);
                    self.suggestion_index = 0;
                    return false;
                }
                _ => {}
            }
        }

        match key.code {
            KeyCode::Esc => {
                if !self.prompt_input.is_empty() {
                    self.prompt_input.clear();
                    self.suggestion_index = 0;
                } else {
                    return true;
                }
            }
            KeyCode::Tab => {
                self.current_tab = (self.current_tab + 1) % 5;
            }
            KeyCode::F(1) => self.current_tab = 0,
            KeyCode::F(2) => self.current_tab = 1,
            KeyCode::F(3) => self.current_tab = 2,
            KeyCode::F(4) => self.current_tab = 3,
            KeyCode::F(5) => self.current_tab = 4,
            KeyCode::Char(c @ '1'..='5') if self.prompt_input.is_empty() => {
                self.current_tab = (c as usize) - ('1' as usize);
            }

            KeyCode::Enter => {
                return self.submit_prompt_input();
            }
            KeyCode::Backspace => {
                self.prompt_input.pop();
                self.suggestion_index = 0;
            }
            KeyCode::Char('p') if self.prompt_input.is_empty() => {
                if self.is_running {
                    self.toggle_pause_selected_node();
                }
            }
            KeyCode::Char('a') if self.prompt_input.is_empty() => {
                if !self.patches.is_empty() {
                    self.apply_current_patch();
                }
            }
            KeyCode::Char('r') if self.prompt_input.is_empty() => {
                if !self.patches.is_empty() {
                    self.rollback_current_patch();
                }
            }
            KeyCode::Char('e') if self.prompt_input.is_empty() => {
                self.export_security_report();
            }
            KeyCode::Char(' ') if self.prompt_input.is_empty() => {
                if !self.config.is_api_key_configured() {
                    self.open_config_modal(2);
                    self.action_msg = Some("authentication required: please set API key to run audit.".to_string());
                } else {
                    self.trigger_audit();
                }
            }
            KeyCode::Up => {
                if self.current_tab == 1 && self.selected_matrix_row > 0 {
                    self.selected_matrix_row -= 1;
                } else if self.current_tab == 2 && self.selected_patch_row > 0 {
                    self.selected_patch_row -= 1;
                }
            }
            KeyCode::Down => {
                if self.current_tab == 1 && self.selected_matrix_row + 1 < self.findings.len() {
                    self.selected_matrix_row += 1;
                } else if self.current_tab == 2 && self.selected_patch_row + 1 < self.patches.len() {
                    self.selected_patch_row += 1;
                }
            }
            KeyCode::Char(c) => {
                self.prompt_input.push(c);
                self.suggestion_index = 0;
            }
            _ => {
                if self.current_tab == 0 {
                    self.flow.handle_key_event(key);
                    if let Some(id) = self.flow.first_selected_node_id() {
                        self.selected_node_id = Some(id.clone());
                    }
                }
            }
        }
        false
    }

    pub fn submit_prompt_input(&mut self) -> bool {
        let input = self.prompt_input.trim().to_string();
        self.prompt_input.clear();
        self.suggestion_index = 0;

        if self.awaiting_confirmation {
            if input.is_empty() || input.eq_ignore_ascii_case("y") || input.eq_ignore_ascii_case("yes") {
                self.confirm_subagent_deployment();
                return false;
            } else if input.eq_ignore_ascii_case("n") || input.eq_ignore_ascii_case("no") {
                self.cancel_subagent_deployment();
                return false;
            }
        }

        if !input.is_empty() {
            self.chat_messages.push(ChatMessage::User(input.clone()));

            if input == "/exit" || input == "/quit" || input == "exit" || input == "quit" {
                self.should_quit = true;
                return true;
            } else if input == "/clear" || input == "clear" {
                self.chat_messages.clear();
                self.action_msg = Some("chat history cleared".to_string());
            } else if input == "/help" || input == "help" {
                self.chat_messages.push(ChatMessage::Agent {
                    sender: "orchestrator".to_string(),
                    text: "### Constellation Security Defense Command Reference\n\n\
                           | Command | Description |\n\
                           | :--- | :--- |\n\
                           | `/scan` | Execute autonomous code defense scan & AST flow |\n\
                           | `/model [name]` | Open supported model selector modal or set model |\n\
                           | `/provider [name]` | Open supported provider list or switch provider |\n\
                           | `/custom [url]` | Add & configure custom AI provider endpoint & credentials |\n\
                           | `/key [api_key]` | Open credentials setup or set API key |\n\
                           | `/url [endpoint]` | Open endpoint setup or set base URL |\n\
                           | `/config` | Display provider credentials & connection setup |\n\
                           | `/apply` | Apply selected hardening patch to source code |\n\
                           | `/rollback` | Rollback previously applied hardening patch |\n\
                           | `/export` | Export defense audit report to HTML & Markdown |\n\
                           | `/pause` | Pause / resume selected agent node in workflow |\n\
                           | `/clear` | Clear chat message history |\n\
                           | `/help` | Display this command reference |\n\
                           | `/exit` | Exit constellation defense harness |\n\n\
                           **Keyboard Shortcuts:**\n\
                           - `[1]`..`[5]`: Switch tabs (Flow, Findings, Patches, Execution, Skills)\n\
                           - `[Space]`: Run security audit\n\
                           - `[a]`: Apply patch │ `[r]`: Rollback patch │ `[p]`: Pause node │ `[e]`: Export report\n\
                           - `[↑/↓]`: Navigate list / suggestions │ `[Tab]`: Autocomplete command │ `[Esc]`: Clear / Cancel".to_string(),
                });
            } else if input == "/model" || input == "model" {
                self.open_provider_model_modal(1);
            } else if let Some(model_str) = input.strip_prefix("/model ") {
                let model = model_str.trim().to_string();
                self.config.model = Some(model.clone());
                let _ = self.config.save();
                self.action_msg = Some(format!("model configured: {model}"));
            } else if input == "/pause" || input == "pause" {
                self.toggle_pause_selected_node();
            } else if input == "/apply" || input == "apply" || input == "a" {
                self.apply_current_patch();
            } else if input == "/rollback" || input == "rollback" || input == "r" {
                self.rollback_current_patch();
            } else if input == "/export" || input == "export" || input == "e" {
                self.export_security_report();
            } else if input == "/scan" || input == "scan" {
                self.trigger_audit();
            } else if input == "/provider" {
                self.open_provider_model_modal(0);
            } else if let Some(prov_str) = input.strip_prefix("/provider ") {
                let lower = prov_str.trim().to_lowercase();
                if lower.contains("custom") {
                    self.active_provider = AiProvider::Custom;
                } else if lower.contains("claude") || lower.contains("anthropic") {
                    self.active_provider = AiProvider::AnthropicClaude;
                } else if lower.contains("gpt") || lower.contains("openai") {
                    self.active_provider = AiProvider::OpenAiGpt4o;
                } else if lower.contains("gemini") || lower.contains("google") {
                    self.active_provider = AiProvider::GoogleGemini;
                } else if lower.contains("deepseek") {
                    self.active_provider = AiProvider::DeepSeek;
                } else if lower.contains("ollama") {
                    self.active_provider = AiProvider::OllamaLocal;
                }
                self.config.provider = self.active_provider;
                let _ = self.config.save();
                self.action_msg = Some(format!("provider switched to {}", self.active_provider.name()));
            } else if input == "/key" {
                self.open_setup_modal(2);
            } else if let Some(key_str) = input.strip_prefix("/key ") {
                let key = key_str.trim().to_string();
                self.config.api_key = Some(key);
                let _ = self.config.save();
                self.action_msg = Some("API key saved.".to_string());
            } else if input == "/url" {
                self.open_setup_modal(1);
            } else if let Some(url_str) = input.strip_prefix("/url ") {
                let url = url_str.trim().to_string();
                self.config.base_url = Some(url.clone());
                let _ = self.config.save();
                self.action_msg = Some(format!("endpoint URL updated: {url}"));
            } else if input == "/custom" || input == "/add-provider" {
                self.active_provider = AiProvider::Custom;
                self.config.provider = AiProvider::Custom;
                self.open_setup_modal(1);
            } else if let Some(custom_url) = input.strip_prefix("/custom ") {
                self.active_provider = AiProvider::Custom;
                self.config.provider = AiProvider::Custom;
                self.config.base_url = Some(custom_url.trim().to_string());
                let _ = self.config.save();
                self.open_setup_modal(2);
            } else if input == "/config" || input == "/status" || input == "/settings" {
                self.open_setup_modal(0);
            } else {
                if !self.config.is_api_key_configured() {
                    self.open_setup_modal(2);
                    self.action_msg = Some("authentication required: please set API key.".to_string());
                    return false;
                }
                let hub = SecurityAgentHub::new(self.target_dir.clone(), Arc::new(PolicyGate::default()), self.config.clone());
                let sender = self.engine_tx.clone();
                let prompt_text = input.clone();
                tokio::spawn(async move {
                    let reply = hub.query(&prompt_text).await;
                    let _ = sender.send(EngineMessage::Chat(ChatMessage::Agent {
                        sender: "orchestrator".to_string(),
                        text: reply,
                    }));
                });
            }
        }
        false
    }

    pub fn apply_current_patch(&mut self) {
        if let Some(patch) = self.patches.get_mut(self.selected_patch_row) {
            let finding_id = patch.finding_id.clone();
            match AutoHardeningAgent::apply_patch(patch) {
                Ok(()) => {
                    self.action_msg = Some(format!("applied patch {}", patch.id));
                    self.chat_messages.push(ChatMessage::Agent {
                        sender: "auto_hardening".to_string(),
                        text: format!("applied hardening patch {} to disk.", patch.id),
                    });
                    if let Some(f) = self.findings.iter_mut().find(|f| f.id == finding_id) {
                        f.patched = true;
                    }
                    self.check_defense_gate_status();
                }
                Err(e) => {
                    self.action_msg = Some(format!("patch error: {e}"));
                }
            }
        }
    }

    pub fn rollback_current_patch(&mut self) {
        if let Some(patch) = self.patches.get_mut(self.selected_patch_row) {
            let finding_id = patch.finding_id.clone();
            match AutoHardeningAgent::rollback_patch(patch) {
                Ok(()) => {
                    self.action_msg = Some(format!("rolled back {}", patch.id));
                    self.chat_messages.push(ChatMessage::Agent {
                        sender: "auto_hardening".to_string(),
                        text: format!("rolled back patch {}.", patch.id),
                    });
                    if let Some(f) = self.findings.iter_mut().find(|f| f.id == finding_id) {
                        f.patched = false;
                    }
                    self.check_defense_gate_status();
                }
                Err(e) => {
                    self.action_msg = Some(format!("rollback error: {e}"));
                }
            }
        }
    }

    pub fn handle_mouse(&mut self, mouse: MouseEvent) {
        let col = mouse.column;
        let row = mouse.row;
        let is_left_click = matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left));

        if self.show_key_modal {
            if is_left_click {
                if let Some(modal_targets) = &self.click_targets.modal {
                    if let Some(btn_save) = modal_targets.btn_save {
                        if in_rect(btn_save, col, row) {
                            self.save_modal_config();
                            return;
                        }
                    }
                    if let Some(btn_cancel) = modal_targets.btn_cancel {
                        if in_rect(btn_cancel, col, row) {
                            self.show_key_modal = false;
                            self.active_modal = ActiveModal::None;
                            self.key_modal_error = None;
                            return;
                        }
                    }
                    for (provider, rect) in &modal_targets.provider_buttons {
                        if in_rect(*rect, col, row) {
                            self.active_provider = *provider;
                            self.config.provider = *provider;
                            let all = AiProvider::ALL;
                            self.selected_provider_index = all.iter().position(|p| *p == *provider).unwrap_or(0);
                            if *provider == AiProvider::Custom && self.config.get_base_url().is_none() {
                                self.open_url_modal();
                            } else {
                                self.open_model_modal();
                            }
                            return;
                        }
                    }
                    for (preset, rect) in &modal_targets.model_preset_buttons {
                        if in_rect(*rect, col, row) {
                            self.config.provider = self.active_provider;
                            self.config.model = Some(preset.clone());
                            self.model_modal_input = preset.clone();
                            if self.config.requires_api_key() && !self.config.is_api_key_configured() {
                                self.open_key_modal();
                            } else {
                                let _ = self.config.save();
                                self.show_key_modal = false;
                                self.active_modal = ActiveModal::None;
                                self.action_msg = Some(format!("model selected: {preset} ({})", self.active_provider.name()));
                            }
                            return;
                        }
                    }
                }
            }
            return;
        }

        // Scroll handlers (inspired by SynapsCLI's mouse wheel scrolling)
        if matches!(mouse.kind, MouseEventKind::ScrollUp) {
            if self.chat_scroll < self.chat_messages.len().saturating_sub(2) {
                self.chat_scroll += 1;
            }
            return;
        }
        if matches!(mouse.kind, MouseEventKind::ScrollDown) {
            if self.chat_scroll > 0 {
                self.chat_scroll -= 1;
            }
            return;
        }

        // 1. Welcome Screen Clicks
        if self.mode == AppMode::Welcome {
            if is_left_click {
                if let Some(btn) = self.click_targets.welcome_btn {
                    if in_rect(btn, col, row) {
                        if !self.config.is_api_key_configured() {
                            self.open_config_modal(2);
                            self.action_msg = Some("authentication required: please set API key.".to_string());
                            return;
                        }

                        let input = self.welcome_input.trim().to_string();
                        if !input.is_empty() {
                            if std::path::Path::new(&input).exists() {
                                self.target_dir = PathBuf::from(&input);
                            } else {
                                self.chat_messages.push(ChatMessage::User(input.clone()));
                                let hub = SecurityAgentHub::new(self.target_dir.clone(), Arc::new(PolicyGate::default()), self.config.clone());
                                let sender = self.engine_tx.clone();
                                tokio::spawn(async move {
                                    let reply = hub.query(&input).await;
                                    let _ = sender.send(EngineMessage::Chat(ChatMessage::Agent {
                                        sender: "orchestrator".to_string(),
                                        text: reply,
                                    }));
                                });
                            }
                        }
                        self.profile = WorkspaceScanner::scan(&self.target_dir);
                        self.mode = AppMode::Workspace;
                    }
                }
            }
            return;
        }

        // 2. Workspace Screen Clicks
        if is_left_click {
            // A. Tab clicks
            for (tab_idx, rect) in &self.click_targets.tab_rects {
                if in_rect(*rect, col, row) {
                    self.current_tab = *tab_idx;
                    return;
                }
            }

            // B. Sidebar Chatbot Buttons
            if let Some(sidebar_targets) = &self.click_targets.sidebar {
                if let Some(btn_conf) = sidebar_targets.btn_confirm {
                    if in_rect(btn_conf, col, row) {
                        self.confirm_subagent_deployment();
                        return;
                    }
                }
                if let Some(btn_canc) = sidebar_targets.btn_cancel {
                    if in_rect(btn_canc, col, row) {
                        self.cancel_subagent_deployment();
                        return;
                    }
                }
                if let Some(btn_pause) = sidebar_targets.btn_pause {
                    if in_rect(btn_pause, col, row) {
                        self.toggle_pause_selected_node();
                        return;
                    }
                }
                if let Some(btn_apply) = sidebar_targets.btn_apply {
                    if in_rect(btn_apply, col, row) {
                        self.apply_current_patch();
                        return;
                    }
                }
                if let Some(btn_send) = sidebar_targets.btn_send {
                    if in_rect(btn_send, col, row) {
                        self.submit_prompt_input();
                        return;
                    }
                }

                // Command autocomplete suggestion click
                for (cmd_name, cmd_args, row_rect) in &sidebar_targets.suggestion_rows {
                    if in_rect(*row_rect, col, row) {
                        self.prompt_input = if cmd_args.is_empty() {
                            cmd_name.to_string()
                        } else {
                            format!("{cmd_name} ")
                        };
                        self.suggestion_index = 0;
                        return;
                    }
                }

                // Review module row clicks (focusing node)
                for (node_id, row_rect) in &sidebar_targets.subagent_rows {
                    if in_rect(*row_rect, col, row) {
                        self.selected_node_id = Some(node_id.clone());
                        self.action_msg = Some(format!("focused module {node_id}"));
                        return;
                    }
                }

                // User chat bubble expand / collapse clicks
                for (msg_idx, rect) in &sidebar_targets.user_msg_expand {
                    if in_rect(*rect, col, row) {
                        if self.expanded_messages.contains(msg_idx) {
                            self.expanded_messages.remove(msg_idx);
                        } else {
                            self.expanded_messages.insert(*msg_idx);
                        }
                        return;
                    }
                }
            }

            // C. Tab 1: Findings Table row click
            if self.current_tab == 1 {
                if let Some(table_rect) = self.click_targets.findings_table {
                    if in_rect(table_rect, col, row) {
                        let clicked_idx = (row.saturating_sub(table_rect.y + 1)) as usize;
                        if clicked_idx < self.findings.len() {
                            self.selected_matrix_row = clicked_idx;
                            return;
                        }
                    }
                }
            }

            // D. Tab 2: Patches View click
            if self.current_tab == 2 {
                if let Some(patch_targets) = &self.click_targets.patches {
                    if let Some(btn_app) = patch_targets.btn_apply {
                        if in_rect(btn_app, col, row) {
                            self.apply_current_patch();
                            return;
                        }
                    }
                    if let Some(btn_roll) = patch_targets.btn_rollback {
                        if in_rect(btn_roll, col, row) {
                            self.rollback_current_patch();
                            return;
                        }
                    }
                    if in_rect(patch_targets.list_area, col, row) {
                        let clicked_patch = (row.saturating_sub(patch_targets.list_area.y)) as usize / 3;
                        if clicked_patch < self.patches.len() {
                            self.selected_patch_row = clicked_patch;
                            return;
                        }
                    }
                }
            }
        }

        // E. Forward Mouse to Rataflow Canvas on Tab 0 (Node drag, node click, pan, zoom)
        if self.current_tab == 0 {
            for event in self.flow.handle_mouse_event(mouse).into_events() {
                match event {
                    FlowEvent::NodeClicked { node_id } => {
                        self.selected_node_id = Some(node_id.clone());
                        self.action_msg = Some(format!("selected node {node_id}"));
                    }
                    _ => {}
                }
            }
        }
    }

    pub fn render(&mut self, f: &mut Frame) {
        let area = f.area();
        match self.mode {
            AppMode::Welcome => {
                let targets = WelcomeView::render(
                    f,
                    area,
                    &self.welcome_input,
                    &self.target_dir.display().to_string(),
                    self.active_provider,
                );
                self.click_targets.welcome_btn = Some(targets.prompt_box);
            }
            AppMode::Workspace => {
                self.render_workspace(f, area);
            }
        }

        if self.show_key_modal {
            let modal_targets = match self.active_modal {
                ActiveModal::SelectProvider => {
                    ModalView::render_provider_list(
                        f,
                        area,
                        self.selected_provider_index,
                    )
                }
                ActiveModal::SelectModel => {
                    ModalView::render_model_list(
                        f,
                        area,
                        self.active_provider,
                        self.selected_model_index,
                    )
                }
                ActiveModal::ApiKeyInput => {
                    ModalView::render_single_input_modal(
                        f,
                        area,
                        &format!("API Key ({})", self.active_provider.name()),
                        "Enter API key:",
                        &self.key_modal_input,
                        true,
                        self.key_modal_error.as_deref(),
                    )
                }
                ActiveModal::BaseUrlInput => {
                    ModalView::render_single_input_modal(
                        f,
                        area,
                        &format!("Endpoint URL ({})", self.active_provider.name()),
                        "Enter endpoint base URL:",
                        &self.url_modal_input,
                        false,
                        self.key_modal_error.as_deref(),
                    )
                }
                ActiveModal::None => crate::ui::views::modal_view::ModalClickTargets {
                    provider_buttons: Vec::new(),
                    model_preset_buttons: Vec::new(),
                    field_rects: Vec::new(),
                    btn_setup_credentials: None,
                    btn_save: None,
                    btn_cancel: None,
                },
            };
            self.click_targets.modal = Some(modal_targets);
        } else {
            self.click_targets.modal = None;
        }
    }

    fn render_workspace(&mut self, f: &mut Frame, area: Rect) {
        // Deep obsidian background fill
        f.render_widget(Block::default().style(Style::default().bg(Color::Rgb(12, 13, 16))), area);

        let root_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(8),
                Constraint::Length(1),
            ])
            .split(area);

        // Top Header Bar with sleek surface fill
        let header_block = Block::default().style(Style::default().bg(Color::Rgb(18, 19, 24)));
        f.render_widget(header_block, root_chunks[0]);

        let status_badge = if self.awaiting_confirmation {
            Span::styled(" ● awaiting confirmation ", Style::default().fg(Color::Rgb(255, 200, 100)).bg(Color::Rgb(36, 30, 20)).add_modifier(Modifier::BOLD))
        } else if self.is_running {
            Span::styled(" ● scanning ", Style::default().fg(Color::Rgb(140, 200, 255)).bg(Color::Rgb(20, 28, 40)).add_modifier(Modifier::BOLD))
        } else {
            Span::styled(" ● ready ", Style::default().fg(Color::Rgb(150, 220, 150)).bg(Color::Rgb(20, 30, 22)))
        };

        let unpatched_count = self.findings.iter().filter(|x| !x.patched).count();
        let findings_pill = if unpatched_count > 0 {
            Span::styled(format!(" {unpatched_count} unresolved "), Style::default().fg(Color::Rgb(255, 140, 140)).bg(Color::Rgb(40, 22, 26)).add_modifier(Modifier::BOLD))
        } else {
            Span::styled(" 0 findings ", Style::default().fg(Color::Rgb(150, 152, 160)).bg(Color::Rgb(26, 27, 33)))
        };

        let top_header = Line::from(vec![
            Span::raw(" "),
            Span::styled(" constellation ", Style::default().fg(Color::White).bg(Color::Rgb(28, 29, 36)).add_modifier(Modifier::BOLD)),
            Span::raw("  "),
            Span::styled(format!(" {} ", self.target_dir.display()), Style::default().fg(Color::Rgb(170, 172, 180)).bg(Color::Rgb(24, 25, 31))),
            Span::raw("  "),
            Span::styled(format!(" {} files ", self.profile.total_files), Style::default().fg(Color::Rgb(150, 152, 160)).bg(Color::Rgb(24, 25, 31))),
            Span::raw("  "),
            findings_pill,
            Span::raw("  "),
            Span::styled(format!(" {} patches ", self.patches.len()), Style::default().fg(Color::Rgb(150, 152, 160)).bg(Color::Rgb(24, 25, 31))),
            Span::raw("  "),
            Span::styled(format!(" {} ", self.active_provider.name()), Style::default().fg(Color::Rgb(160, 200, 255)).bg(Color::Rgb(22, 28, 40))),
            Span::raw("   "),
            status_badge,
        ]);
        f.render_widget(Paragraph::new(top_header), root_chunks[0]);

        // Main Horizontal Split: Left Sidebar Chatbot (36%) vs Right Workspace Area (64%)
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(36),
                Constraint::Percentage(64),
            ])
            .split(root_chunks[1]);

        // Left Sidebar Chatbot
        let sel_node = self.selected_node_id.as_ref().and_then(|id| self.nodes_info.get(id));
        let sidebar_targets = SidebarView::render(
            f,
            main_chunks[0],
            &self.chat_messages,
            self.chat_scroll,
            &self.nodes_info,
            sel_node,
            &self.prompt_input,
            self.suggestion_index,
            self.awaiting_confirmation,
            &self.expanded_messages,
            !self.patches.is_empty(),
        );
        self.click_targets.sidebar = Some(sidebar_targets);

        // Right Workspace Area: Tab Strip + Viewport
        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(6),
            ])
            .split(main_chunks[1]);

        // Modern Tab Bar surface
        let tab_bar_area = right_chunks[0];
        f.render_widget(Block::default().style(Style::default().bg(Color::Rgb(14, 15, 19))), tab_bar_area);

        let tab_width = tab_bar_area.width / 5;
        let mut tab_rects = Vec::new();
        for i in 0..5 {
            tab_rects.push((
                i,
                Rect::new(tab_bar_area.x + i as u16 * tab_width, tab_bar_area.y, tab_width, tab_bar_area.height),
            ));
        }
        self.click_targets.tab_rects = tab_rects;

        let findings_count = self.findings.len();
        let patches_count = self.patches.len();
        let titles = vec![
            format!("  [1] Flow  "),
            format!("  [2] Findings ({findings_count})  "),
            format!("  [3] Patches ({patches_count})  "),
            format!("  [4] Execution  "),
            format!("  [5] Skills  "),
        ];
        let tabs = Tabs::new(titles)
            .select(self.current_tab)
            .style(Style::default().fg(Color::Rgb(130, 132, 142)).bg(Color::Rgb(14, 15, 19)))
            .highlight_style(Style::default().fg(Color::White).bg(Color::Rgb(36, 38, 48)).add_modifier(Modifier::BOLD))
            .divider(Span::styled(" ", Style::default().bg(Color::Rgb(14, 15, 19))));
        f.render_widget(tabs, right_chunks[0]);

        let content_area = right_chunks[1];
        match self.current_tab {
            0 => GraphView::render(f, content_area, &mut self.flow, self.nodes_info.is_empty()),
            1 => {
                let table_rect = MatrixView::render(f, content_area, &self.findings, self.selected_matrix_row);
                self.click_targets.findings_table = Some(table_rect);
            }
            2 => {
                let patch_targets = PatchView::render(f, content_area, &self.patches, self.selected_patch_row, &self.action_msg);
                self.click_targets.patches = Some(patch_targets);
            }
            3 => LogsView::render(f, content_area, &self.logs, 0),
            4 => SkillsView::render(f, content_area, &self.skills.skills),
            _ => {}
        }

        // Bottom Footer Bar (Sleek surface fill, no ASCII pipe spam)
        let footer_block = Block::default().style(Style::default().bg(Color::Rgb(14, 15, 19)));
        f.render_widget(footer_block, root_chunks[2]);

        let footer = if self.patches.is_empty() {
            Line::from(vec![
                Span::raw("  "),
                Span::styled(" [Space] ", Style::default().fg(Color::White).bg(Color::Rgb(26, 28, 36))),
                Span::styled(" audit    ", Style::default().fg(Color::Rgb(120, 122, 132))),
                Span::styled(" [Tab] ", Style::default().fg(Color::White).bg(Color::Rgb(26, 28, 36))),
                Span::styled(" views    ", Style::default().fg(Color::Rgb(120, 122, 132))),
                Span::styled(" [/config] ", Style::default().fg(Color::White).bg(Color::Rgb(26, 28, 36))),
                Span::styled(" settings    ", Style::default().fg(Color::Rgb(120, 122, 132))),
                Span::styled(" [Esc] ", Style::default().fg(Color::White).bg(Color::Rgb(26, 28, 36))),
                Span::styled(" quit", Style::default().fg(Color::Rgb(120, 122, 132))),
            ])
        } else {
            Line::from(vec![
                Span::raw("  "),
                Span::styled(" [Tab] ", Style::default().fg(Color::White).bg(Color::Rgb(26, 28, 36))),
                Span::styled(" views    ", Style::default().fg(Color::Rgb(120, 122, 132))),
                Span::styled(" [a] ", Style::default().fg(Color::White).bg(Color::Rgb(26, 28, 36))),
                Span::styled(" apply patch    ", Style::default().fg(Color::Rgb(120, 122, 132))),
                Span::styled(" [r] ", Style::default().fg(Color::White).bg(Color::Rgb(26, 28, 36))),
                Span::styled(" rollback    ", Style::default().fg(Color::Rgb(120, 122, 132))),
                Span::styled(" [Esc] ", Style::default().fg(Color::White).bg(Color::Rgb(26, 28, 36))),
                Span::styled(" quit", Style::default().fg(Color::Rgb(120, 122, 132))),
            ])
        };
        f.render_widget(Paragraph::new(footer), root_chunks[2]);
    }
}

fn in_rect(rect: Rect, col: u16, row: u16) -> bool {
    col >= rect.x && col < rect.x + rect.width && row >= rect.y && row < rect.y + rect.height
}
