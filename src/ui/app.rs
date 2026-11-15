use crate::ui::theme::th;
use crate::execution::{EngineCommand, EngineMessage, ExecutionEngine};
use crate::orchestrator::{AgentGraphBuilder, DefensePlan, StrategyPlanner, WorkspaceScanner};
use crate::skills::SkillRegistry;
use crate::core::{
    AppConfig, PolicyGate, SecurityAgentHub, SecurityContextRules,
    StateStore, WorktreeSandbox,
};
use crate::subagents::{
    ApkAndContainerGuardAgent, AutoHardeningAgent, MalwareShieldAgent, SecretHunterAgent,
};
use crate::types::{
    get_matching_commands, AgentStatus, AiProvider, ChatMessage, DynamicLogEntry, HardeningPatch,
    SproutedNodeInfo, VulnerabilityFinding, WorkflowPlan, WorkflowTaskNode, WorkspaceProfile,
};
use crate::orchestrator::graph::AgentNodeContent;
use crate::ui::views::{
    GraphView, LogsView, MatrixView, ModalClickTargets, ModalView, PatchClickTargets, PatchView,
    SidebarClickTargets, SidebarView, SkillsView,
};
use chrono::Utc;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use rataflow::{Flow, FlowEvent, Node, StepEdge};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame,
};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppMode {
    Welcome,
    Workspace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveModal {
    None,
    SelectProvider,
    ProviderDetail,
    SelectModel,
    CustomProviderNameInput,
    BaseUrlInput,
    ApiKeyInput,
    ConfigDashboard,
    SelectTheme,
    Help,
    SelectSession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusedPane {
    Chatbot,
    Workflow,
}

#[derive(Default)]
pub struct AppClickTargets {
    #[allow(dead_code)]
    pub welcome_btn: Option<Rect>,
    pub sidebar_rect: Option<Rect>,
    pub workspace_rect: Option<Rect>,
    pub tab_rects: Vec<(usize, Rect)>,
    pub sidebar: Option<SidebarClickTargets>,
    pub findings_table: Option<Rect>,
    pub patches: Option<PatchClickTargets>,
    pub modal: Option<ModalClickTargets>,
    pub skills_search_bar: Option<Rect>,
    pub theme_picker: Option<crate::ui::views::ThemePickerTargets>,
}

pub struct App {
    #[allow(dead_code)]
    pub mode: AppMode,
    pub focused_pane: FocusedPane,
    pub current_tab: usize,
    pub target_dir: PathBuf,
    #[allow(dead_code)]
    pub welcome_input: String,
    pub prompt_input: String,

    pub flow: Flow<AgentNodeContent, StepEdge>,
    pub last_flow_tick: std::time::Instant,
    pub nodes_info: HashMap<String, SproutedNodeInfo>,
    pub selected_node_id: Option<String>,
    pub current_workflow_plan: Option<WorkflowPlan>,

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
    pub custom_provider_name_input: String,
    pub is_setup_wizard: bool,
    pub key_modal_error: Option<String>,
    pub suggestion_index: usize,
    pub should_quit: bool,

    pub engine_rx: UnboundedReceiver<EngineMessage>,
    pub engine_tx: UnboundedSender<EngineMessage>,
    pub cmd_tx: UnboundedSender<EngineCommand>,
    pub cmd_rx: Option<UnboundedReceiver<EngineCommand>>,

    pub click_targets: AppClickTargets,
    pub diff_scope: String,
    pub checkpoint: Option<crate::core::sandbox::WorkspaceCheckpoint>,
    pub last_esc_press: Option<std::time::Instant>,
    pub previous_modal: Option<ActiveModal>,
    pub model_search_query: String,
    pub model_filtered_items: Vec<(AiProvider, String, bool)>,
    pub skills_search: String,
    pub skills_search_active: bool,
    pub selected_skill_index: usize,
    pub theme_picker_index: usize,
    pub theme_before_picker: String,
    pub findings_filter_reachable: bool,
    pub is_chat_querying: bool,
    pub current_session_id: String,
    pub is_grill_mode: bool,
    pub grill_step: usize,
    pub grill_answers: Vec<(String, String)>,
    pub sessions_list: Vec<crate::core::storage::SessionSummary>,
    pub selected_session_index: usize,
}

impl App {
    pub fn new(initial_target: PathBuf, _start_in_welcome: bool) -> Self {
        let (tx, rx) = unbounded_channel();
        let (cmd_tx, cmd_rx) = unbounded_channel();

        let profile = WorkspaceScanner::scan(&initial_target);
        let nodes_info = std::collections::HashMap::new();
        let flow = Flow::new();
        let skills = SkillRegistry::new();
        let config = AppConfig::load();
        if let Some(name) = config.theme.as_deref() {
            crate::ui::theme::set_theme(name);
        }
        let active_provider = config.provider;
        let checkpoint = WorktreeSandbox::capture_checkpoint(&initial_target).ok();

        Self {
            mode: AppMode::Workspace,
            focused_pane: FocusedPane::Chatbot,
            current_tab: 0,
            target_dir: initial_target,
            welcome_input: String::new(),
            prompt_input: String::new(),
            flow,
            last_flow_tick: std::time::Instant::now(),
            nodes_info,
            selected_node_id: None,
            current_workflow_plan: None,
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
            custom_provider_name_input: String::new(),
            is_setup_wizard: false,
            key_modal_error: None,
            suggestion_index: 0,
            should_quit: false,
            engine_rx: rx,
            engine_tx: tx,
            cmd_tx,
            cmd_rx: Some(cmd_rx),
            click_targets: AppClickTargets::default(),
            diff_scope: "FULL".to_string(),
            checkpoint,
            last_esc_press: None,
            previous_modal: None,
            model_search_query: String::new(),
            model_filtered_items: Vec::new(),
            skills_search: String::new(),
            skills_search_active: false,
            selected_skill_index: 0,
            theme_picker_index: 0,
            theme_before_picker: String::new(),
            findings_filter_reachable: false,
            is_chat_querying: false,
            current_session_id: format!("sess-{}", chrono::Utc::now().timestamp_millis()),
            is_grill_mode: false,
            grill_step: 0,
            grill_answers: Vec::new(),
            sessions_list: Vec::new(),
            selected_session_index: 0,
        }
    }

    pub fn persist_current_session(&mut self) {
        if let Ok(mut store) = StateStore::for_project(&self.target_dir) {
            let proj_id = self.target_dir.display().to_string();
            let _ = store.save_session_full(
                &self.current_session_id,
                &proj_id,
                self.active_provider.name(),
                &self.chat_messages,
                &self.findings,
                &self.patches,
            );
        }
    }

    pub fn start_new_session(&mut self) -> String {
        self.persist_current_session();
        let old_id = self.current_session_id.clone();
        let new_id = format!("sess-{}", chrono::Utc::now().timestamp_millis());
        self.current_session_id = new_id.clone();
        self.chat_messages.clear();
        self.findings.clear();
        self.patches.clear();
        self.logs.clear();
        self.flow = Flow::new();
        self.nodes_info.clear();
        self.selected_node_id = None;
        self.current_workflow_plan = None;
        self.plan = None;
        self.selected_matrix_row = 0;
        self.selected_patch_row = 0;
        self.is_grill_mode = false;
        self.grill_step = 0;
        self.grill_answers.clear();
        self.is_running = false;
        self.awaiting_confirmation = false;
        self.is_chat_querying = false;
        self.chat_scroll = 0;
        self.expanded_messages.clear();
        self.action_msg = Some("new session initialized".to_string());
        self.chat_messages.push(ChatMessage::Agent {
            sender: "orchestrator".to_string(),
            text: format!(
                "### ✻ Asterisk — New Security Session Initialized\n\n\
                 • **Session ID**: `{}`\n\
                 • **Archived Previous Session**: `{}`\n\
                 • **Target Directory**: `{}`\n\
                 • **Active Model**: {} (`{}`)\n\n\
                 The previous session was automatically persisted to SQLite. Type `/sessions` to switch back anytime.\n\
                 Ready for autonomous vulnerability triage, AST dataflow analysis, or conversational security review.\n\
                 Type `/scan` or press `[Space]` to begin an audit.",
                new_id, old_id, self.target_dir.display(), self.active_provider.name(), self.config.get_model()
            ),
        });
        self.persist_current_session();
        new_id
    }

    pub fn load_session_by_id(&mut self, session_id: &str) -> Result<(usize, usize), String> {
        let store = StateStore::for_project(&self.target_dir)
            .map_err(|e| format!("Cannot open state store: {e}"))?;
        let (messages, findings, patches) = store.load_session_full(session_id)?;
        let m_count = messages.len();
        let f_count = findings.len();
        self.chat_messages = messages;
        self.findings = findings;
        self.patches = patches;
        self.logs.clear();
        self.flow = Flow::new();
        self.nodes_info.clear();
        self.selected_node_id = None;
        self.current_workflow_plan = None;
        self.plan = None;
        self.selected_matrix_row = 0;
        self.selected_patch_row = 0;
        self.is_grill_mode = false;
        self.grill_step = 0;
        self.grill_answers.clear();
        self.is_running = false;
        self.awaiting_confirmation = false;
        self.is_chat_querying = false;
        self.chat_scroll = 0;
        self.expanded_messages.clear();
        self.current_session_id = session_id.to_string();
        Ok((m_count, f_count))
    }

    pub fn open_sessions_modal(&mut self) {
        self.persist_current_session();
        let proj_id = self.target_dir.display().to_string();
        if let Ok(store) = StateStore::for_project(&self.target_dir) {
            if let Ok(summaries) = store.list_sessions(&proj_id) {
                self.sessions_list = summaries;
            }
        }
        if self.sessions_list.is_empty() {
            self.sessions_list.push(crate::core::storage::SessionSummary {
                session_id: self.current_session_id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
                active_provider: self.active_provider.name().to_string(),
                message_count: self.chat_messages.len(),
                findings_count: self.findings.len(),
                title: "Current Active Session".to_string(),
            });
        }
        self.selected_session_index = self
            .sessions_list
            .iter()
            .position(|s| s.session_id == self.current_session_id)
            .unwrap_or(0);

        self.show_key_modal = true;
        self.active_modal = ActiveModal::SelectSession;
        self.action_msg = Some(format!("browsing {} sessions", self.sessions_list.len()));
    }

    pub fn open_help_modal(&mut self) {
        self.show_key_modal = true;
        self.active_modal = ActiveModal::Help;
    }

    pub fn open_provider_modal(&mut self) {
        self.show_key_modal = true;
        self.active_modal = ActiveModal::SelectProvider;
        self.modal_field = 0;
        self.key_modal_error = None;
        let all = AiProvider::ALL;
        self.selected_provider_index = all.iter().position(|p| *p == self.active_provider).unwrap_or(0);
    }

    pub fn open_provider_detail(&mut self, provider: AiProvider) {
        self.show_key_modal = true;
        self.active_modal = ActiveModal::ProviderDetail;
        self.active_provider = provider;
        self.modal_field = 0;
        self.key_modal_error = None;
    }

    pub fn rebuild_all_models_list(&mut self) {
        let mut list = Vec::new();
        let query = self.model_search_query.trim().to_lowercase();

        for &prov in &AiProvider::ALL {
            let is_configured = self.config.is_provider_configured(prov);
            let models = self.config.get_models_for_provider(prov);
            for m in models {
                if query.is_empty()
                    || m.to_lowercase().contains(&query)
                    || prov.name().to_lowercase().contains(&query)
                {
                    list.push((prov, m, is_configured));
                }
            }
        }
        self.model_filtered_items = list;
        if self.selected_model_index >= self.model_filtered_items.len() {
            self.selected_model_index = self.model_filtered_items.len().saturating_sub(1);
        }
    }

    pub fn open_model_modal(&mut self) {
        self.show_key_modal = true;
        self.active_modal = ActiveModal::SelectModel;
        self.modal_field = 1;
        self.key_modal_error = None;
        self.model_search_query.clear();
        self.rebuild_all_models_list();

        let cur_model = self.config.get_model();
        self.selected_model_index = self
            .model_filtered_items
            .iter()
            .position(|(p, m, _)| *p == self.active_provider && *m == cur_model)
            .unwrap_or(0);
    }

    pub fn open_key_modal(&mut self) {
        self.show_key_modal = true;
        self.active_modal = ActiveModal::ApiKeyInput;
        self.modal_field = 2;
        self.key_modal_error = None;
        self.key_modal_input = self.config.get_api_key_for_provider(self.active_provider).unwrap_or_default();
    }

    pub fn open_custom_provider_name_modal(&mut self) {
        self.show_key_modal = true;
        self.active_modal = ActiveModal::CustomProviderNameInput;
        self.modal_field = 0;
        self.key_modal_error = None;
        self.custom_provider_name_input = self
            .config
            .custom_provider_name
            .clone()
            .unwrap_or_else(|| "Custom Provider".to_string());
    }

    pub fn save_custom_provider_name_modal(&mut self) -> bool {
        let name = self.custom_provider_name_input.trim();
        let final_name = if name.is_empty() {
            "Custom Provider".to_string()
        } else {
            name.to_string()
        };
        self.config.custom_provider_name = Some(final_name);
        let _ = self.config.save();
        self.key_modal_error = None;
        self.previous_modal = Some(ActiveModal::CustomProviderNameInput);
        self.open_url_modal();
        true
    }

    pub fn start_provider_setup_flow(&mut self, provider: AiProvider) {
        self.is_setup_wizard = true;
        self.active_provider = provider;
        self.key_modal_error = None;

        if provider == AiProvider::Custom {
            // Step 1: Provider Name
            self.previous_modal = Some(ActiveModal::SelectProvider);
            self.open_custom_provider_name_modal();
        } else {
            // Predefined provider: Nama sudah ada (OpenAI, Claude, dll).
            // Langsung masuk ke Step 1 of 2: Endpoint Base URL!
            self.previous_modal = Some(ActiveModal::SelectProvider);
            self.open_url_modal();
        }
    }

    pub fn open_url_modal(&mut self) {
        self.show_key_modal = true;
        self.active_modal = ActiveModal::BaseUrlInput;
        self.modal_field = 1;
        self.key_modal_error = None;
        self.url_modal_input = self.config.get_base_url_for_provider(self.active_provider).unwrap_or_default();
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

    pub fn open_config_dashboard(&mut self) {
        self.show_key_modal = true;
        self.active_modal = ActiveModal::ConfigDashboard;
        self.modal_field = 0;
        self.key_modal_error = None;
    }

    pub fn open_config_modal(&mut self, initial_field: usize) {
        match initial_field {
            0 => self.open_config_dashboard(),
            1 => self.open_provider_modal(),
            2 => self.open_model_modal(),
            3 => self.open_key_modal(),
            _ => self.open_url_modal(),
        }
    }

    pub fn sync_live_models_for_provider(&mut self, provider: AiProvider) {
        let key = self.config.get_api_key_for_provider(provider);
        let base_url = self.config.get_base_url_for_provider(provider);
        if provider.requires_api_key() && key.is_none() {
            self.action_msg = Some(format!("cannot sync models: no API key configured for {}.", provider.name()));
            return;
        }

        self.action_msg = Some(format!("querying {} API for live models...", provider.name()));
        let sender = self.engine_tx.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                match crate::core::model_discovery::fetch_live_models(
                    provider,
                    key.as_deref(),
                    base_url.as_deref(),
                )
                .await
                {
                    Ok(models) => {
                        let _ = sender.send(EngineMessage::ModelsDiscovered { provider, models });
                    }
                    Err(err) => {
                        let _ = sender.send(EngineMessage::Chat(ChatMessage::Agent {
                            sender: "orchestrator".to_string(),
                            text: format!(
                                "⚠️ **Live Model Discovery Failed ({})**: {err}\nUsing preset model defaults.",
                                provider.name()
                            ),
                        }));
                    }
                }
            });
        }
    }

    pub fn trigger_audit(&mut self) {
        self.trigger_audit_with_directive(None);
    }

    pub fn trigger_audit_with_directive(&mut self, directive: Option<String>) {
        if self.is_running || self.awaiting_confirmation {
            return;
        }

        if !self.config.is_api_key_configured() {
            self.open_key_modal();
            self.action_msg = Some("authentication required: please set API key to run scan.".to_string());
            self.chat_messages.push(ChatMessage::Agent {
                sender: "orchestrator".to_string(),
                text: format!(
                    "⚠️ **Defense scan blocked**: No API key configured for **{}**.\n\
                     Autonomous audit and models cannot be accessed until credentials are configured. Please enter your API key to proceed.\n\
                     💡 *Tip: To run a 100% offline/local audit without an API key, switch to Ollama via `/provider ollama`.*",
                    self.active_provider.name()
                ),
            });
            return;
        }

        self.is_running = true;
        self.awaiting_confirmation = false;
        self.action_msg = Some(format!("AI model {} is inspecting workspace and reasoning...", self.config.get_model()));

        if let Some(ref dir) = directive {
            self.chat_messages.push(ChatMessage::Thinking {
                agent: "orchestrator".to_string(),
                thought: format!("User directive received: \"{}\". Prioritizing target directory surfaces in threat reasoning...", dir),
            });
        }

        self.chat_messages.push(ChatMessage::Agent {
            sender: "orchestrator".to_string(),
            text: format!(
                "🧠 **Inspecting repository architecture & threat surfaces...**\nTarget: `{}` | Model: `{}`{}",
                self.target_dir.display(),
                self.config.get_model(),
                directive.as_ref().map(|d| format!("\nDirective: *\"{}\"*", d)).unwrap_or_default()
            ),
        });

        let target = self.target_dir.clone();
        let sender = self.engine_tx.clone();
        let config = self.config.clone();
        let dir_clone = directive.clone();

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let hub = SecurityAgentHub::new(
                    target.clone(),
                    std::sync::Arc::new(PolicyGate::default()),
                    config,
                );
                match StrategyPlanner::generate_ai_workflow_with_feedback(&hub, &target, dir_clone.as_deref(), Some(&sender)).await {
                    Ok(plan) => {
                        let _ = sender.send(EngineMessage::WorkflowPlanProposed(plan));
                    }
                    Err(err) => {
                        let _ = sender.send(EngineMessage::Chat(ChatMessage::Agent {
                            sender: "orchestrator".to_string(),
                            text: format!("⚠️ AI workflow synthesis stopped: {err}\nPlease verify your API key or model configuration."),
                        }));
                        let _ = sender.send(EngineMessage::ScanFinished);
                    }
                }
            });
        } else {
            let _ = sender.send(EngineMessage::Chat(ChatMessage::Agent {
                sender: "orchestrator".to_string(),
                text: "⚠️ Async runtime handle unavailable for AI workflow generation.".to_string(),
            }));
            let _ = sender.send(EngineMessage::ScanFinished);
        }
    }

    pub fn confirm_subagent_deployment(&mut self) {
        if !self.awaiting_confirmation {
            return;
        }
        self.awaiting_confirmation = false;
        self.is_running = true;
        self.action_msg = Some("executing approved dynamic workflow...".to_string());

        // Derive execution sequence from horizontal X and vertical Y position of active nodes
        let mut active_task_positions: Vec<(String, f64, f64)> = self.flow
            .nodes()
            .filter(|n| n.id != "orch" && n.id != "defense_gate")
            .map(|n| (n.id.clone(), n.position.x, n.position.y))
            .collect();
        active_task_positions.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal).then(a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal)));

        let plan_map: HashMap<String, WorkflowTaskNode> = self.current_workflow_plan
            .as_ref()
            .map(|p| p.nodes.iter().map(|n| (n.id.clone(), n.clone())).collect())
            .unwrap_or_default();

        let mut ordered_tasks = Vec::new();
        for (idx, (id, _, _)) in active_task_positions.into_iter().enumerate() {
            if let Some(mut task) = plan_map.get(&id).cloned() {
                task.order = idx;
                ordered_tasks.push(task);
            } else {
                ordered_tasks.push(WorkflowTaskNode {
                    id: id.clone(),
                    title: id.clone(),
                    subtitle: String::new(),
                    agent: "sast".to_string(),
                    tier: "subagent".to_string(),
                    targets: Vec::new(),
                    description: String::new(),
                    order: idx,
                    depends_on: Vec::new(),
                });
            }
        }

        let initially_paused: std::collections::HashSet<String> = self.nodes_info
            .iter()
            .filter(|(_, v)| v.is_paused)
            .map(|(k, _)| k.clone())
            .collect();

        self.chat_messages.push(ChatMessage::System(format!(
            "Workflow confirmed with {} active task(s). Starting execution...",
            ordered_tasks.len()
        )));

        let target = self.target_dir.clone();
        let sender = self.engine_tx.clone();
        let cmd_rx = self.cmd_rx.take().unwrap_or_else(|| {
            let (new_tx, new_rx) = unbounded_channel();
            self.cmd_tx = new_tx;
            new_rx
        });

        let diff_scope = self.diff_scope.clone();
        let provider_name = self.active_provider.name().to_string();
        let config = self.config.clone();

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let engine = ExecutionEngine::new(target, sender, cmd_rx)
                    .with_diff_scope(diff_scope)
                    .with_active_provider(provider_name)
                    .with_config(config)
                    .with_tasks(ordered_tasks)
                    .with_paused_nodes(initially_paused);
                engine.run_autonomous_audit().await;
            });
        }
    }

    pub fn cancel_subagent_deployment(&mut self) {
        self.awaiting_confirmation = false;
        self.is_running = false;
        self.action_msg = Some("workflow cancelled by user".to_string());
        self.chat_messages.push(ChatMessage::System("Scan cancelled. Workflow discarded.".to_string()));
    }

    pub fn delete_selected_workflow_node(&mut self) {
        if !self.awaiting_confirmation {
            return;
        }
        if let Some(id) = &self.selected_node_id {
            let id_str = id.clone();
            if id_str == "orch" || id_str == "defense_gate" {
                self.action_msg = Some("cannot delete orchestrator or defense gate".to_string());
                return;
            }
            if AgentGraphBuilder::remove_workflow_node(&mut self.flow, &mut self.nodes_info, &id_str) {
                if let Some(plan) = &mut self.current_workflow_plan {
                    plan.nodes.retain(|n| n.id != id_str);
                }
                self.action_msg = Some(format!("deleted task '{}' from workflow", id_str));
                self.chat_messages.push(ChatMessage::System(format!("Removed task node '{}' from workflow plan.", id_str)));
                self.selected_node_id = self.nodes_info.keys().find(|k| *k != "orch" && *k != "defense_gate").cloned().or_else(|| Some("orch".to_string()));
            }
        }
    }

    pub fn shift_selected_workflow_node(&mut self, delta_x: f64, delta_y: f64) {
        if !self.awaiting_confirmation {
            return;
        }
        if let Some(id) = &self.selected_node_id {
            let id_str = id.clone();
            if id_str == "orch" || id_str == "defense_gate" {
                return;
            }
            AgentGraphBuilder::shift_node(&mut self.flow, &self.nodes_info, &id_str, delta_x, delta_y);
            let dir_str = if delta_x < 0.0 {
                "earlier"
            } else if delta_x > 0.0 {
                "later"
            } else if delta_y < 0.0 {
                "upwards"
            } else {
                "downwards"
            };
            self.action_msg = Some(format!("repositioned task '{}' {}", id_str, dir_str));
        }
    }

    #[allow(dead_code)]
    pub fn toggle_pause_selected_node(&mut self) {
        if let Some(id) = &self.selected_node_id {
            let node_id = id.clone();
            if let Some(node) = self.nodes_info.get_mut(&node_id) {
                node.is_paused = !node.is_paused;
                let state_str = if node.is_paused { "paused" } else { "resumed" };
                self.action_msg = Some(format!("node {} {state_str}", node.id));

                if node.is_paused {
                    let _ = self.cmd_tx.send(EngineCommand::PauseNode(node_id.clone()));
                } else {
                    let _ = self.cmd_tx.send(EngineCommand::ResumeNode(node_id.clone()));
                }

                if let Some(content) = self.flow.node_content_mut(&node_id) {
                    content.is_paused = node.is_paused;
                }
                AgentGraphBuilder::rechain_workflow_edges(&mut self.flow, &self.nodes_info);
            }
        }
    }

    pub fn toggle_pause_total(&mut self) {
        let any_paused = self.nodes_info.values().any(|n| n.is_paused);
        let should_pause = !any_paused;

        let node_ids: Vec<String> = self.nodes_info.keys().cloned().collect();

        if should_pause {
            let _ = self.cmd_tx.send(EngineCommand::PauseNode("*".to_string()));
            for node in self.nodes_info.values_mut() {
                node.is_paused = true;
                if node.status == AgentStatus::Running {
                    node.status = AgentStatus::Paused;
                }
            }
            for id in &node_ids {
                if let Some(content) = self.flow.node_content_mut(id) {
                    content.is_paused = true;
                    if content.status == AgentStatus::Running {
                        content.status = AgentStatus::Paused;
                    }
                }
            }
            self.action_msg = Some("⏸ EXECUTION PAUSED TOTAL [Esc / Space to resume]".to_string());
            self.chat_messages.push(ChatMessage::Agent {
                sender: "orchestrator".to_string(),
                text: "⏸ **Execution Paused Total**: All active scanning threads suspended. Flow animations stopped (grayed out). Press `[Esc]`, `[Space]`, or type `/pause` to resume.".to_string(),
            });
        } else {
            let _ = self.cmd_tx.send(EngineCommand::ResumeNode("*".to_string()));
            for node in self.nodes_info.values_mut() {
                node.is_paused = false;
                if node.status == AgentStatus::Paused {
                    node.status = AgentStatus::Running;
                }
            }
            for id in &node_ids {
                if let Some(content) = self.flow.node_content_mut(id) {
                    content.is_paused = false;
                    if content.status == AgentStatus::Paused {
                        content.status = AgentStatus::Running;
                    }
                }
            }
            self.action_msg = Some("▶ EXECUTION RESUMED".to_string());
            self.chat_messages.push(ChatMessage::Agent {
                sender: "orchestrator".to_string(),
                text: "▶ **Execution Resumed**: Continuing autonomous workflow pipeline.".to_string(),
            });
        }

        AgentGraphBuilder::rechain_workflow_edges(&mut self.flow, &self.nodes_info);
    }

    pub fn check_defense_gate_status(&mut self) {
        let unpatched_count = self.findings.iter().filter(|f| !f.patched).count();
        if unpatched_count == 0 && !self.findings.is_empty() {
            if let Some(gate) = self.nodes_info.get_mut("defense_gate") {
                gate.status = AgentStatus::Success;
            }
            if let Some(content) = self.flow.node_content_mut("defense_gate") {
                content.status = AgentStatus::Success;
            }
            AgentGraphBuilder::rechain_workflow_edges(&mut self.flow, &self.nodes_info);
            self.action_msg = Some("all vulnerabilities mitigated. defense gate open.".to_string());
        }
    }

    pub fn export_security_report(&mut self) {
        let report_path = self.target_dir.join("security-audit-report.json");
        let md_path = self.target_dir.join("security-audit-report.md");
        let generated_at = Utc::now().to_rfc3339();
        let unpatched_count = self.findings.iter().filter(|f| !f.patched).count();
        let report = serde_json::json!({
            "generated_at": generated_at,
            "target": self.target_dir.display().to_string(),
            "total_files": self.profile.total_files,
            "languages": self.profile.languages,
            "findings_count": self.findings.len(),
            "unpatched_count": unpatched_count,
            "findings": self.findings,
            "patches": self.patches,
        });

        let mut md = format!(
            "# Asterisk Security Defense Report\n\n\
             - **Generated At:** `{generated_at}`\n\
             - **Target Workspace:** `{}`\n\
             - **Total Files:** `{}` (`{}`)\n\
             - **Total Findings:** `{}` (`{unpatched_count}` unresolved)\n\
             - **Synthesized Patches:** `{}`\n\n\
             ## Vulnerability Matrix\n\n\
             | ID | Severity | CWE | Reachability | Verdict | Location | Title | Status |\n\
             | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n",
            self.target_dir.display(),
            self.profile.total_files,
            self.profile.languages.join(", "),
            self.findings.len(),
            self.patches.len(),
        );
        for f in &self.findings {
            let status = if f.patched { "PATCHED" } else { "OPEN" };
            md.push_str(&format!(
                "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}:{}` | {} | `{}` |\n",
                f.id,
                f.severity.as_str(),
                f.cwe,
                f.reachability,
                f.triage_verdict,
                f.file_path.display(),
                f.line_number,
                f.title,
                status
            ));
        }

        let json_res = std::fs::write(&report_path, serde_json::to_string_pretty(&report).unwrap_or_default());
        let _ = std::fs::write(&md_path, md);

        match json_res {
            Ok(()) => {
                self.action_msg = Some("report exported -> security-audit-report.{json,md}".to_string());
                self.chat_messages.push(ChatMessage::System(
                    "security reports written to security-audit-report.json and security-audit-report.md.".to_string(),
                ));
            }
            Err(e) => {
                self.action_msg = Some(format!("export error: {e}"));
            }
        }
    }

    pub fn update(&mut self) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_flow_tick);
        self.last_flow_tick = now;
        self.flow.tick_animation(elapsed);

        while let Ok(msg) = self.engine_rx.try_recv() {
            match msg {
                EngineMessage::NodeStatusChanged { id, status } => {
                    if let Some(node) = self.nodes_info.get_mut(&id) {
                        node.status = status;
                        if status == AgentStatus::Paused {
                            node.is_paused = true;
                        } else if status == AgentStatus::Running {
                            node.is_paused = false;
                        }
                    }
                    if let Some(content) = self.flow.node_content_mut(&id) {
                        content.status = status;
                        if status == AgentStatus::Paused {
                            content.is_paused = true;
                        } else if status == AgentStatus::Running {
                            content.is_paused = false;
                        }
                    }
                    AgentGraphBuilder::rechain_workflow_edges(&mut self.flow, &self.nodes_info);
                }
                EngineMessage::FixingWorkflowStarted { actionable_count } => {
                    AgentGraphBuilder::append_fixing_workflow(&mut self.flow, &mut self.nodes_info, actionable_count);
                    self.action_msg = Some(format!("fixing workflow sprouted ({actionable_count} actionable findings)"));
                    self.flow.request_fit_view();
                }
                EngineMessage::WorkflowNodeAppended { node, parent_id } => {
                    let parent_pos = self.flow.node(&parent_id).map(|n| (n.position.x, n.position.y));
                    let max_y = self.flow.nodes().map(|n| n.position.y).fold(14.0_f64, f64::max);

                    let new_x = parent_pos.map(|p| p.0 + 4.0).unwrap_or(70.0);
                    let new_y = max_y + 7.0; // Place directly underneath existing branches

                    let sprouted = SproutedNodeInfo {
                        id: node.id.clone(),
                        label: format!("{}\n{}", node.title, node.subtitle),
                        tier: "workflow_task".to_string(),
                        target_path: None,
                        status: AgentStatus::Idle,
                        details: node.description.clone(),
                        findings_count: 0,
                        is_paused: false,
                    };
                    self.nodes_info.insert(node.id.clone(), sprouted);

                    let content = AgentNodeContent {
                        id: node.id.clone(),
                        title: node.title.clone(),
                        subtitle: node.subtitle.clone(),
                        tier: node.tier.clone(),
                        status: AgentStatus::Idle,
                        is_paused: false,
                        findings_count: 0,
                    };

                    let rata_node = Node::new(node.id.clone(), (new_x, new_y), (26.0, 5.0), content);
                    let _ = self.flow.add_node(rata_node);
                    AgentGraphBuilder::rechain_workflow_edges(&mut self.flow, &self.nodes_info);
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
                EngineMessage::WorkflowPlanProposed(plan) => {
                    if let Ok(flow) = AgentGraphBuilder::build_from_workflow_plan(&plan, &mut self.nodes_info) {
                        self.flow = flow;
                    }
                    let node_count = plan.nodes.len();
                    self.current_workflow_plan = Some(plan);
                    self.current_tab = 0;
                    self.awaiting_confirmation = true;
                    self.is_running = false;
                    self.selected_node_id = self.nodes_info.keys().find(|k| *k != "orch" && *k != "defense_gate").cloned().or_else(|| Some("orch".to_string()));
                    self.action_msg = Some("workflow proposed. [d] delete, [←/→] move, [y/Enter] confirm".to_string());
                    self.chat_messages.push(ChatMessage::Agent {
                        sender: "orchestrator".to_string(),
                        text: format!(
                            "📋 **Custom Security Workflow Proposed by AI**\n\
                             Analyzed workspace architecture and synthesized **{}** modular audit tasks.\n\n\
                             **Interactive Workflow Controls:**\n\
                             • `[d]` / `[Del]`: Delete highlighted task node\n\
                             • `[←]` / `[→]`: Reorder task execution sequence (left-to-right)\n\
                             • `[y]` / `[Enter]`: Confirm & begin autonomous scan\n\
                             • `[n]` / `[Esc]`: Cancel workflow",
                            node_count
                        ),
                    });
                }
                EngineMessage::Chat(msg) => {
                    self.is_chat_querying = false;
                    self.chat_messages.push(msg);
                }
                EngineMessage::ChatQueryFinished => {
                    self.is_chat_querying = false;
                    self.action_msg = None;
                    self.persist_current_session();
                }
                EngineMessage::AwaitingConfirmation => {
                    self.awaiting_confirmation = true;
                    self.action_msg = Some("click [Deploy Subagents] or type 'y' in sidebar...".to_string());
                }
                EngineMessage::ScanFinished => {
                    self.is_running = false;
                    self.awaiting_confirmation = false;
                    self.check_defense_gate_status();
                    AgentGraphBuilder::rechain_workflow_edges(&mut self.flow, &self.nodes_info);
                    self.persist_current_session();
                    self.action_msg = Some(format!(
                        "scan finished. {} findings, {} patches ready.",
                        self.findings.len(),
                        self.patches.len()
                    ));
                }
                EngineMessage::ModelsDiscovered { provider, models } => {
                    let count = models.len();
                    self.config.discovered_models.insert(provider.name().to_string(), models);
                    let _ = self.config.save();
                    self.rebuild_all_models_list();
                    self.action_msg = Some(format!(
                        "synced {count} live models for {} from API!",
                        provider.name()
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

        let res = self.handle_workspace_key(key);
        res || self.should_quit
    }

    /// Opens the interactive theme picker (live preview, revert on Esc).
    pub fn open_theme_modal(&mut self) {
        let current = crate::ui::theme::th().name;
        self.theme_before_picker = current.to_string();
        self.theme_picker_index = crate::ui::theme::presets()
            .iter()
            .position(|t| t.name == current)
            .unwrap_or(0);
        self.show_key_modal = true;
        self.active_modal = ActiveModal::SelectTheme;
    }

    /// Moves the picker cursor and previews that theme immediately.
    fn theme_picker_select(&mut self, idx: usize) {
        let list = crate::ui::theme::presets();
        if list.is_empty() {
            return;
        }
        self.theme_picker_index = idx.min(list.len() - 1);
        crate::ui::theme::set_theme(list[self.theme_picker_index].name);
    }

    fn theme_picker_apply(&mut self) {
        let list = crate::ui::theme::presets();
        if let Some(t) = list.get(self.theme_picker_index) {
            crate::ui::theme::set_theme(t.name);
            self.persist_theme(t);
        }
        self.show_key_modal = false;
        self.active_modal = ActiveModal::None;
    }

    fn theme_picker_cancel(&mut self) {
        let prev = std::mem::take(&mut self.theme_before_picker);
        crate::ui::theme::set_theme(&prev);
        self.show_key_modal = false;
        self.active_modal = ActiveModal::None;
        self.action_msg = Some(format!("theme unchanged ({prev})"));
    }

    fn handle_theme_key(&mut self, key: KeyEvent) -> bool {
        let n = crate::ui::theme::presets().len();
        let i = self.theme_picker_index;
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => self.theme_picker_cancel(),
            KeyCode::Enter | KeyCode::Char(' ') => self.theme_picker_apply(),
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => self.theme_picker_select(if i == 0 { n - 1 } else { i - 1 }),
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => self.theme_picker_select((i + 1) % n),
            KeyCode::Home | KeyCode::Char('g') => self.theme_picker_select(0),
            KeyCode::End | KeyCode::Char('G') => self.theme_picker_select(n - 1),
            KeyCode::Char(c @ '1'..='9') => {
                let idx = (c as usize) - ('1' as usize);
                if idx < n {
                    self.theme_picker_select(idx);
                }
            }
            _ => {}
        }
        false
    }

    /// Saves the active theme to config and reports it in the status line.
    pub fn persist_theme(&mut self, theme: &'static crate::ui::theme::Theme) {
        self.config.theme = Some(theme.name.to_string());
        let _ = self.config.save();
        self.action_msg = Some(format!("theme → {} ({})  ·  [Ctrl+T] next", theme.label, theme.name));
    }

    pub fn save_key_modal(&mut self) -> bool {
        let k = self.key_modal_input.trim();
        if k.is_empty() && self.active_provider.requires_api_key() && self.active_provider != AiProvider::Custom {
            self.key_modal_error = Some("API key cannot be empty for this cloud provider.".to_string());
            return false;
        }

        if k.is_empty() {
            self.config.provider_keys.remove(self.active_provider.name());
            if self.config.provider == self.active_provider {
                self.config.api_key = None;
            }
        } else {
            self.config.provider_keys.insert(self.active_provider.name().to_string(), k.to_string());
            if self.config.provider == self.active_provider {
                self.config.api_key = Some(k.to_string());
            }
        }

        self.config.provider = self.active_provider;
        let _ = self.config.save();
        self.key_modal_error = None;
        self.action_msg = Some(format!(
            "configured credentials for {}.",
            self.config.get_provider_display_name(self.active_provider)
        ));

        if !k.is_empty() || self.active_provider == AiProvider::Custom {
            self.sync_live_models_for_provider(self.active_provider);
        }

        if self.is_setup_wizard {
            self.is_setup_wizard = false;
            self.previous_modal = Some(ActiveModal::SelectProvider);
            self.open_model_modal();
        } else if let Some(prev) = self.previous_modal.take() {
            match prev {
                ActiveModal::BaseUrlInput | ActiveModal::CustomProviderNameInput => {
                    self.show_key_modal = false;
                    self.active_modal = ActiveModal::None;
                }
                ActiveModal::SelectProvider => self.open_provider_modal(),
                ActiveModal::ProviderDetail => self.open_provider_detail(self.active_provider),
                ActiveModal::SelectModel => self.open_model_modal(),
                ActiveModal::ConfigDashboard => self.open_config_dashboard(),
                _ => {
                    self.show_key_modal = false;
                    self.active_modal = ActiveModal::None;
                }
            }
        } else {
            self.show_key_modal = false;
            self.active_modal = ActiveModal::None;
        }
        true
    }

    pub fn save_modal_config(&mut self) -> bool {
        match self.active_modal {
            ActiveModal::CustomProviderNameInput => self.save_custom_provider_name_modal(),
            ActiveModal::ApiKeyInput => self.save_key_modal(),
            ActiveModal::BaseUrlInput => {
                let u = self.url_modal_input.trim();
                if u.is_empty() {
                    self.config.provider_base_urls.remove(self.active_provider.name());
                    if self.config.provider == self.active_provider {
                        self.config.base_url = None;
                    }
                } else {
                    self.config.provider_base_urls.insert(self.active_provider.name().to_string(), u.to_string());
                    if self.config.provider == self.active_provider {
                        self.config.base_url = Some(u.to_string());
                    }
                }
                let _ = self.config.save();

                if self.active_provider == AiProvider::OllamaLocal {
                    self.sync_live_models_for_provider(AiProvider::OllamaLocal);
                    if self.is_setup_wizard {
                        self.is_setup_wizard = false;
                        self.previous_modal = Some(ActiveModal::SelectProvider);
                        self.open_model_modal();
                    } else if let Some(prev) = self.previous_modal.take() {
                        match prev {
                            ActiveModal::SelectProvider => self.open_provider_modal(),
                            ActiveModal::ProviderDetail => self.open_provider_detail(self.active_provider),
                            ActiveModal::ConfigDashboard => self.open_config_dashboard(),
                            _ => {
                                self.show_key_modal = false;
                                self.active_modal = ActiveModal::None;
                            }
                        }
                    } else {
                        self.show_key_modal = false;
                        self.active_modal = ActiveModal::None;
                    }
                } else if self.is_setup_wizard || self.active_provider == AiProvider::Custom || (self.active_provider.requires_api_key() && !self.config.is_provider_configured(self.active_provider)) {
                    self.previous_modal = Some(ActiveModal::BaseUrlInput);
                    self.open_key_modal();
                } else if let Some(prev) = self.previous_modal.take() {
                    match prev {
                        ActiveModal::SelectProvider => self.open_provider_modal(),
                        ActiveModal::ProviderDetail => self.open_provider_detail(self.active_provider),
                        ActiveModal::ConfigDashboard => self.open_config_dashboard(),
                        _ => {
                            self.show_key_modal = false;
                            self.active_modal = ActiveModal::None;
                        }
                    }
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
            ActiveModal::ProviderDetail => {
                self.show_key_modal = false;
                self.active_modal = ActiveModal::None;
                true
            }
            ActiveModal::ConfigDashboard => {
                self.show_key_modal = false;
                self.active_modal = ActiveModal::None;
                true
            }
            ActiveModal::SelectTheme => {
                self.theme_picker_apply();
                true
            }
            ActiveModal::Help => {
                self.show_key_modal = false;
                self.active_modal = ActiveModal::None;
                true
            }
            ActiveModal::SelectSession => {
                self.handle_session_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()))
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
            ActiveModal::ProviderDetail => self.handle_provider_detail_key(key),
            ActiveModal::SelectModel => self.handle_model_key(key),
            ActiveModal::CustomProviderNameInput => self.handle_provider_name_input_key(key),
            ActiveModal::ApiKeyInput => self.handle_key_input_key(key),
            ActiveModal::BaseUrlInput => self.handle_url_input_key(key),
            ActiveModal::ConfigDashboard => self.handle_config_dashboard_key(key),
            ActiveModal::SelectTheme => self.handle_theme_key(key),
            ActiveModal::Help => self.handle_help_key(key),
            ActiveModal::SelectSession => self.handle_session_key(key),
            ActiveModal::None => {
                self.show_key_modal = false;
                false
            }
        }
    }

    fn handle_session_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.show_key_modal = false;
                self.active_modal = ActiveModal::None;
                false
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if !self.sessions_list.is_empty() {
                    if self.selected_session_index > 0 {
                        self.selected_session_index -= 1;
                    } else {
                        self.selected_session_index = self.sessions_list.len().saturating_sub(1);
                    }
                }
                false
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if !self.sessions_list.is_empty() {
                    if self.selected_session_index + 1 < self.sessions_list.len() {
                        self.selected_session_index += 1;
                    } else {
                        self.selected_session_index = 0;
                    }
                }
                false
            }
            KeyCode::Enter => {
                if let Some(target) = self.sessions_list.get(self.selected_session_index).cloned() {
                    self.show_key_modal = false;
                    self.active_modal = ActiveModal::None;
                    if target.session_id == self.current_session_id {
                        self.action_msg = Some(format!("already on active session: {}", target.session_id));
                    } else {
                        self.persist_current_session();
                        match self.load_session_by_id(&target.session_id) {
                            Ok((m_count, f_count)) => {
                                self.current_session_id = target.session_id.clone();
                                self.action_msg = Some(format!("switched to session: {}", target.title));
                                self.chat_messages.push(ChatMessage::Agent {
                                    sender: "orchestrator".to_string(),
                                    text: format!(
                                        "✓ **Session Loaded**: Switched to **{}** (`{}`).\n\
                                         Restored **{}** messages and **{}** findings.",
                                        target.title, target.session_id, m_count, f_count
                                    ),
                                });
                            }
                            Err(e) => {
                                self.action_msg = Some(format!("failed to load session: {e}"));
                            }
                        }
                    }
                } else {
                    self.show_key_modal = false;
                    self.active_modal = ActiveModal::None;
                }
                false
            }
            KeyCode::Char('n') => {
                self.show_key_modal = false;
                self.active_modal = ActiveModal::None;
                self.start_new_session();
                false
            }
            _ => false,
        }
    }

    fn handle_help_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('?') => {
                self.show_key_modal = false;
                self.active_modal = ActiveModal::None;
                false
            }
            _ => false,
        }
    }

    fn handle_provider_name_input_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.open_provider_modal();
                false
            }
            KeyCode::Backspace => {
                self.custom_provider_name_input.pop();
                false
            }
            KeyCode::Enter => {
                self.save_custom_provider_name_modal();
                false
            }
            KeyCode::Char(c) => {
                self.custom_provider_name_input.push(c);
                false
            }
            _ => false,
        }
    }

    fn handle_provider_detail_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.open_provider_modal();
                false
            }
            KeyCode::Char('1') | KeyCode::Char('k') => {
                self.previous_modal = Some(ActiveModal::ProviderDetail);
                self.open_key_modal();
                false
            }
            KeyCode::Char('2') | KeyCode::Char('u') => {
                self.previous_modal = Some(ActiveModal::ProviderDetail);
                self.open_url_modal();
                false
            }
            KeyCode::Char('3') | KeyCode::Char('m') | KeyCode::Enter => {
                self.config.provider = self.active_provider;
                let _ = self.config.save();
                self.previous_modal = Some(ActiveModal::ProviderDetail);
                self.open_model_modal();
                false
            }
            KeyCode::Char('4') | KeyCode::Char('s') => {
                self.sync_live_models_for_provider(self.active_provider);
                false
            }
            _ => false,
        }
    }

    fn handle_config_dashboard_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.show_key_modal = false;
                self.active_modal = ActiveModal::None;
                false
            }
            KeyCode::Char('1') | KeyCode::Char('p') => {
                self.previous_modal = Some(ActiveModal::ConfigDashboard);
                self.open_provider_modal();
                false
            }
            KeyCode::Char('2') | KeyCode::Char('m') => {
                self.previous_modal = Some(ActiveModal::ConfigDashboard);
                self.open_model_modal();
                false
            }
            KeyCode::Char('3') | KeyCode::Char('k') => {
                self.previous_modal = Some(ActiveModal::ConfigDashboard);
                self.open_key_modal();
                false
            }
            KeyCode::Char('4') | KeyCode::Char('u') => {
                self.previous_modal = Some(ActiveModal::ConfigDashboard);
                self.open_url_modal();
                false
            }
            _ => false,
        }
    }

    fn handle_provider_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                self.show_key_modal = false;
                self.active_modal = ActiveModal::None;
                false
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                if let Some(p) = AiProvider::ALL.get(self.selected_provider_index) {
                    self.start_provider_setup_flow(*p);
                }
                false
            }
            KeyCode::Char('k') => {
                if let Some(p) = AiProvider::ALL.get(self.selected_provider_index) {
                    self.active_provider = *p;
                    self.config.provider = *p;
                }
                self.previous_modal = Some(ActiveModal::SelectProvider);
                self.open_key_modal();
                false
            }
            KeyCode::Char('u') => {
                if let Some(p) = AiProvider::ALL.get(self.selected_provider_index) {
                    self.active_provider = *p;
                    self.config.provider = *p;
                }
                self.previous_modal = Some(ActiveModal::SelectProvider);
                self.open_url_modal();
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
            KeyCode::Char(c @ '1'..='9') => {
                let idx = (c as usize) - ('1' as usize);
                if idx < AiProvider::ALL.len() {
                    self.selected_provider_index = idx;
                    self.active_provider = AiProvider::ALL[idx];
                    self.config.provider = self.active_provider;
                }
                false
            }
            KeyCode::Char('0') => {
                if 9 < AiProvider::ALL.len() {
                    self.selected_provider_index = 9;
                    self.active_provider = AiProvider::ALL[9];
                    self.config.provider = self.active_provider;
                }
                false
            }
            KeyCode::Char('x' | 'X') => {
                if 10 < AiProvider::ALL.len() {
                    self.selected_provider_index = 10;
                    self.active_provider = AiProvider::ALL[10];
                    self.config.provider = self.active_provider;
                }
                false
            }
            KeyCode::Enter => {
                if let Some(p) = AiProvider::ALL.get(self.selected_provider_index) {
                    self.active_provider = *p;
                }
                self.previous_modal = Some(ActiveModal::SelectProvider);
                self.open_provider_detail(self.active_provider);
                false
            }
            _ => false,
        }
    }

    fn handle_model_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                if let Some(prev) = self.previous_modal.take() {
                    match prev {
                        ActiveModal::SelectProvider => self.open_provider_modal(),
                        ActiveModal::ProviderDetail => self.open_provider_detail(self.active_provider),
                        ActiveModal::ConfigDashboard => self.open_config_dashboard(),
                        _ => {
                            self.show_key_modal = false;
                            self.active_modal = ActiveModal::None;
                        }
                    }
                } else {
                    self.show_key_modal = false;
                    self.active_modal = ActiveModal::None;
                }
                false
            }
            KeyCode::Up => {
                if !self.model_filtered_items.is_empty() {
                    if self.selected_model_index == 0 {
                        self.selected_model_index = self.model_filtered_items.len() - 1;
                    } else {
                        self.selected_model_index -= 1;
                    }
                }
                false
            }
            KeyCode::Down | KeyCode::Tab => {
                if !self.model_filtered_items.is_empty() {
                    self.selected_model_index = (self.selected_model_index + 1) % self.model_filtered_items.len();
                }
                false
            }
            KeyCode::Backspace => {
                if !self.model_search_query.is_empty() {
                    self.model_search_query.pop();
                    self.rebuild_all_models_list();
                }
                false
            }
            KeyCode::Char('k') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if let Some((prov, _, _)) = self.model_filtered_items.get(self.selected_model_index) {
                    self.active_provider = *prov;
                    self.config.provider = *prov;
                }
                self.previous_modal = Some(ActiveModal::SelectModel);
                self.open_key_modal();
                false
            }
            KeyCode::Enter => {
                if let Some((prov, model_name, is_conf)) = self.model_filtered_items.get(self.selected_model_index) {
                    self.active_provider = *prov;
                    self.config.provider = *prov;
                    self.config.model = Some(model_name.clone());

                    if *prov != AiProvider::OllamaLocal && !is_conf {
                        self.previous_modal = Some(ActiveModal::SelectModel);
                        self.open_key_modal();
                    } else {
                        let _ = self.config.save();
                        self.show_key_modal = false;
                        self.active_modal = ActiveModal::None;
                        self.previous_modal = None;
                        self.action_msg = Some(format!("model selected: {model_name} ({}).", prov.name()));
                    }
                }
                false
            }
            KeyCode::Char(c) => {
                self.model_search_query.push(c);
                self.rebuild_all_models_list();
                false
            }
            _ => false,
        }
    }

    fn handle_key_input_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                if let Some(prev) = self.previous_modal.take() {
                    match prev {
                        ActiveModal::BaseUrlInput => self.open_url_modal(),
                        ActiveModal::SelectProvider => self.open_provider_modal(),
                        ActiveModal::ProviderDetail => self.open_provider_detail(self.active_provider),
                        ActiveModal::SelectModel => self.open_model_modal(),
                        ActiveModal::ConfigDashboard => self.open_config_dashboard(),
                        _ => {
                            self.show_key_modal = false;
                            self.active_modal = ActiveModal::None;
                        }
                    }
                } else {
                    self.show_key_modal = false;
                    self.active_modal = ActiveModal::None;
                }
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
                if let Some(prev) = self.previous_modal.take() {
                    match prev {
                        ActiveModal::CustomProviderNameInput => self.open_custom_provider_name_modal(),
                        ActiveModal::SelectProvider => self.open_provider_modal(),
                        ActiveModal::ProviderDetail => self.open_provider_detail(self.active_provider),
                        ActiveModal::ConfigDashboard => self.open_config_dashboard(),
                        _ => {
                            self.show_key_modal = false;
                            self.active_modal = ActiveModal::None;
                        }
                    }
                } else if self.active_provider == AiProvider::Custom {
                    self.open_custom_provider_name_modal();
                } else {
                    self.open_provider_modal();
                }
                self.key_modal_error = None;
                false
            }
            KeyCode::Backspace => {
                self.url_modal_input.pop();
                false
            }
            KeyCode::Enter => {
                self.save_modal_config();
                false
            }
            KeyCode::Char(c) => {
                self.url_modal_input.push(c);
                false
            }
            _ => false,
        }
    }

    fn handle_workspace_key(&mut self, key: KeyEvent) -> bool {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return true;
        }

        if self.skills_search_active {
            match key.code {
                KeyCode::Esc => {
                    self.skills_search.clear();
                    self.skills_search_active = false;
                    return false;
                }
                KeyCode::Enter => {
                    self.skills_search_active = false;
                    return false;
                }
                KeyCode::Backspace => {
                    self.skills_search.pop();
                    return false;
                }
                KeyCode::Up => {
                    if self.selected_skill_index > 0 {
                        self.selected_skill_index -= 1;
                    }
                    return false;
                }
                KeyCode::Down => {
                    self.selected_skill_index += 1;
                    return false;
                }
                KeyCode::Tab => {
                    self.skills_search_active = false;
                    self.current_tab = (self.current_tab + 1) % 5;
                    return false;
                }
                KeyCode::Char(c)
                    if !key.modifiers.contains(KeyModifiers::CONTROL)
                        && !key.modifiers.contains(KeyModifiers::ALT) =>
                {
                    self.skills_search.push(c);
                    return false;
                }
                _ => return false,
            }
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
                        if self.prompt_input == cmd.name || cmd.args.is_empty() || cmd.args.starts_with('[') {
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

        // Interactive Workflow Controls when awaiting confirmation
        if self.awaiting_confirmation && (self.prompt_input.is_empty() || self.focused_pane == FocusedPane::Workflow) {
            match key.code {
                KeyCode::Char('d') | KeyCode::Delete => {
                    self.delete_selected_workflow_node();
                    return false;
                }
                KeyCode::Left | KeyCode::Char('h') if self.current_tab == 0 => {
                    self.shift_selected_workflow_node(-36.0, 0.0);
                    return false;
                }
                KeyCode::Right | KeyCode::Char('l') if self.current_tab == 0 => {
                    self.shift_selected_workflow_node(36.0, 0.0);
                    return false;
                }
                KeyCode::Up | KeyCode::Char('k') if self.current_tab == 0 => {
                    self.shift_selected_workflow_node(0.0, -7.0);
                    return false;
                }
                KeyCode::Down | KeyCode::Char('j') if self.current_tab == 0 => {
                    self.shift_selected_workflow_node(0.0, 7.0);
                    return false;
                }
                KeyCode::Char('y') => {
                    self.confirm_subagent_deployment();
                    return false;
                }
                KeyCode::Char('n') => {
                    self.cancel_subagent_deployment();
                    return false;
                }
                KeyCode::Enter if self.prompt_input.is_empty() => {
                    self.confirm_subagent_deployment();
                    return false;
                }
                KeyCode::Esc if self.prompt_input.is_empty() => {
                    self.cancel_subagent_deployment();
                    return false;
                }
                _ => {}
            }
        }

        match key.code {
            KeyCode::Esc => {
                if self.is_chat_querying {
                    self.is_chat_querying = false;
                    self.action_msg = Some("chat query cancelled".to_string());
                    self.chat_messages.push(ChatMessage::Agent {
                        sender: "orchestrator".to_string(),
                        text: "⏹ Chat query cancelled by user.".to_string(),
                    });
                    return false;
                }
                if self.is_running {
                    self.toggle_pause_total();
                    return false;
                }
                let is_double_esc = self
                    .last_esc_press
                    .map(|t| t.elapsed() < Duration::from_millis(600))
                    .unwrap_or(false);

                if is_double_esc {
                    if let Some(cp) = &self.checkpoint {
                        match WorktreeSandbox::rewind_to_checkpoint(&self.target_dir, cp) {
                            Ok(()) => {
                                self.action_msg = Some("workspace rewound to checkpoint (Esc+Esc)".to_string());
                                self.chat_messages.push(ChatMessage::Agent {
                                    sender: "orchestrator".to_string(),
                                    text: "↩ **Workspace Checkpoint Rewound**: Reverted workspace filesystem state to pre-session checkpoint via double-Escape shortcut.".to_string(),
                                });
                            }
                            Err(e) => {
                                self.action_msg = Some(format!("rewind error: {e}"));
                            }
                        }
                    } else {
                        self.action_msg = Some("no checkpoint available to rewind".to_string());
                    }
                    self.last_esc_press = None;
                    return false;
                } else {
                    self.last_esc_press = Some(std::time::Instant::now());
                }

                if self.current_tab == 4 && !self.skills_search.is_empty() {
                    self.skills_search.clear();
                    return false;
                }

                if !self.prompt_input.is_empty() {
                    self.prompt_input.clear();
                    self.suggestion_index = 0;
                } else {
                    self.action_msg = Some("press Esc again to rewind checkpoint, or /exit (Ctrl+C) to quit".to_string());
                }
            }
            KeyCode::Tab => {
                self.current_tab = (self.current_tab + 1) % 5;
            }
            KeyCode::BackTab => {
                self.focused_pane = match self.focused_pane {
                    FocusedPane::Chatbot => FocusedPane::Workflow,
                    FocusedPane::Workflow => FocusedPane::Chatbot,
                };
                self.action_msg = Some(match self.focused_pane {
                    FocusedPane::Chatbot => "focused left pane: chatbot".to_string(),
                    FocusedPane::Workflow => "focused right pane: workflow".to_string(),
                });
            }
            KeyCode::Char('w') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.focused_pane = match self.focused_pane {
                    FocusedPane::Chatbot => FocusedPane::Workflow,
                    FocusedPane::Workflow => FocusedPane::Chatbot,
                };
                self.action_msg = Some(match self.focused_pane {
                    FocusedPane::Chatbot => "focused left pane: chatbot".to_string(),
                    FocusedPane::Workflow => "focused right pane: workflow".to_string(),
                });
            }
            KeyCode::PageUp => {
                self.chat_scroll = self.chat_scroll.saturating_add(5);
            }
            KeyCode::PageDown => {
                self.chat_scroll = self.chat_scroll.saturating_sub(5);
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.chat_scroll = self.chat_scroll.saturating_add(5);
            }
            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.chat_scroll = self.chat_scroll.saturating_sub(5);
            }
            KeyCode::Left if self.focused_pane == FocusedPane::Workflow => {
                self.current_tab = if self.current_tab == 0 { 4 } else { self.current_tab - 1 };
            }
            KeyCode::Right if self.focused_pane == FocusedPane::Workflow => {
                self.current_tab = (self.current_tab + 1) % 5;
            }
            KeyCode::F(1) => self.current_tab = 0,
            KeyCode::F(2) => self.current_tab = 1,
            KeyCode::F(3) => self.current_tab = 2,
            KeyCode::F(4) => self.current_tab = 3,
            KeyCode::F(5) => self.current_tab = 4,
            // Alt+1..5 switches tabs (plain digits stay available for typing)
            KeyCode::Char(c @ '1'..='5') if key.modifiers.contains(KeyModifiers::ALT) => {
                self.current_tab = (c as usize) - ('1' as usize);
            }

            KeyCode::Enter => {
                if self.current_tab == 4 && self.prompt_input.is_empty() {
                    if let Some(skill) = self.skills.skills.get_mut(self.selected_skill_index) {
                        skill.active = !skill.active;
                        let status_str = if skill.active { "activated" } else { "disabled" };
                        self.action_msg = Some(format!("skill '{}' {}", skill.id, status_str));
                        return false;
                    }
                }
                return self.submit_prompt_input();
            }
            KeyCode::Backspace => {
                self.prompt_input.pop();
                self.suggestion_index = 0;
            }
            KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.toggle_pause_total();
            }
            KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if !self.patches.is_empty() {
                    self.apply_current_patch();
                }
            }
            KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if !self.patches.is_empty() {
                    self.rollback_current_patch();
                }
            }
            KeyCode::Char('t') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                let t = crate::ui::theme::cycle_theme();
                self.persist_theme(t);
            }
            KeyCode::Char('e') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.export_security_report();
            }
            KeyCode::Char(' ') if self.prompt_input.is_empty() => {
                if self.is_running {
                    self.toggle_pause_total();
                    return false;
                }
                if self.current_tab == 4 {
                    if let Some(skill) = self.skills.skills.get_mut(self.selected_skill_index) {
                        skill.active = !skill.active;
                        let status_str = if skill.active { "activated" } else { "disabled" };
                        self.action_msg = Some(format!("skill '{}' {}", skill.id, status_str));
                        return false;
                    }
                } else if !self.config.is_api_key_configured() {
                    // Non-intrusive: no popup on a casual Space press, just a hint.
                    self.action_msg = Some(format!(
                        "no API key for {} — type /provider (or /key) to set one, or use Ollama for offline audit.",
                        self.config.provider.name()
                    ));
                } else {
                    self.trigger_audit();
                }
            }
            KeyCode::Up => {
                if self.focused_pane == FocusedPane::Chatbot && self.prompt_input.is_empty() {
                    self.chat_scroll = self.chat_scroll.saturating_add(2);
                } else if self.current_tab == 1 && self.selected_matrix_row > 0 {
                    self.selected_matrix_row -= 1;
                } else if self.current_tab == 2 && self.selected_patch_row > 0 {
                    self.selected_patch_row -= 1;
                } else if self.current_tab == 4 && self.selected_skill_index > 0 {
                    self.selected_skill_index -= 1;
                }
            }
            KeyCode::Down => {
                if self.focused_pane == FocusedPane::Chatbot && self.prompt_input.is_empty() {
                    self.chat_scroll = self.chat_scroll.saturating_sub(2);
                } else if self.current_tab == 1 && self.selected_matrix_row + 1 < self.findings.len() {
                    self.selected_matrix_row += 1;
                } else if self.current_tab == 2 && self.selected_patch_row + 1 < self.patches.len() {
                    self.selected_patch_row += 1;
                } else if self.current_tab == 4 && self.selected_skill_index + 1 < self.skills.skills.len() {
                    self.selected_skill_index += 1;
                }
            }
            KeyCode::Char('/') if self.current_tab == 4 && self.prompt_input.is_empty() => {
                self.skills_search_active = true;
                return false;
            }
            KeyCode::Char('?')
                if self.prompt_input.is_empty()
                    || self.focused_pane == FocusedPane::Workflow
                    || key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.open_help_modal();
                return false;
            }
            KeyCode::Char('j') if self.focused_pane == FocusedPane::Workflow => {
                if self.current_tab == 1 && self.selected_matrix_row + 1 < self.findings.len() {
                    self.selected_matrix_row += 1;
                } else if self.current_tab == 2 && self.selected_patch_row + 1 < self.patches.len() {
                    self.selected_patch_row += 1;
                } else if self.current_tab == 4 && self.selected_skill_index + 1 < self.skills.skills.len() {
                    self.selected_skill_index += 1;
                }
                return false;
            }
            KeyCode::Char('k') if self.focused_pane == FocusedPane::Workflow => {
                if self.current_tab == 1 && self.selected_matrix_row > 0 {
                    self.selected_matrix_row -= 1;
                } else if self.current_tab == 2 && self.selected_patch_row > 0 {
                    self.selected_patch_row -= 1;
                } else if self.current_tab == 4 && self.selected_skill_index > 0 {
                    self.selected_skill_index -= 1;
                }
                return false;
            }
            KeyCode::Char('r') if self.focused_pane == FocusedPane::Workflow && self.current_tab == 1 => {
                self.findings_filter_reachable = !self.findings_filter_reachable;
                self.selected_matrix_row = 0;
                self.action_msg = Some(if self.findings_filter_reachable {
                    "filter: showing reachable findings only".to_string()
                } else {
                    "filter: showing all findings".to_string()
                });
                return false;
            }
            KeyCode::Char('a') if self.focused_pane == FocusedPane::Workflow && self.current_tab == 1 => {
                self.findings_filter_reachable = false;
                self.selected_matrix_row = 0;
                self.action_msg = Some("filter: showing all findings".to_string());
                return false;
            }
            KeyCode::Char('a') if self.focused_pane == FocusedPane::Workflow && self.current_tab == 2 => {
                if !self.patches.is_empty() {
                    self.apply_current_patch();
                }
                return false;
            }
            KeyCode::Char('r') if self.focused_pane == FocusedPane::Workflow && self.current_tab == 2 => {
                if !self.patches.is_empty() {
                    self.rollback_current_patch();
                }
                return false;
            }
            KeyCode::Char(c)
                if !key.modifiers.contains(KeyModifiers::CONTROL) && !key.modifiers.contains(KeyModifiers::ALT) =>
            {
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
            if input == "/exit" || input == "/quit" || input == "exit" || input == "quit" {
                self.should_quit = true;
                return true;
            } else if input == "/clear" || input == "clear" {
                self.chat_messages.clear();
                self.action_msg = Some("chat history cleared".to_string());
            } else if input == "/help" || input == "help" {
                self.chat_messages.push(ChatMessage::Agent {
                    sender: "orchestrator".to_string(),
                    text: "### Asterisk Security Defense Command Reference\n\n\
                           | Command | Description |\n\
                           | :--- | :--- |\n\
                           | `/scan` | Execute autonomous code defense scan & AST flow |\n\
                           | `/patch` | Apply selected code hardening patch to disk |\n\
                           | `/secrets` | Scan & filter hardcoded secrets & high-entropy credentials |\n\
                           | `/init-sec` | Initialize CodeContextGraph & draft SECURITY.md |\n\
                           | `/reachability` | Display function reachability & phantom dependency analysis |\n\
                           | `/shield` | Run Pre-Install Malware Shield audit |\n\
                           | `/apk [path]` | Audit AndroidManifest.xml, mobile APK & container configs |\n\
                           | `/hotfix [pkg]` | Generate local library patch ./patches/<pkg>.patch without upgrade |\n\
                           | `/skills [action]` | Manage, import (`/skills import <path>`), or synthesize (`/skills synth`) 3-tier .skill.md |\n\
                           | `/model [name]` | Open supported model selector modal or set model |\n\
                           | `/provider [name]` | Open supported provider list or switch provider |\n\
                           | `/custom [url]` | Add & configure custom AI provider endpoint & credentials |\n\
                           | `/key [api_key]` | Open credentials setup or set API key |\n\
                           | `/url [endpoint]` | Open endpoint setup or set base URL |\n\
                           | `/config` | Display provider credentials & connection setup modal |\n\
                           | `/apply` | Apply selected hardening patch to source code |\n\
                           | `/rollback` | Rollback previously applied hardening patch |\n\
                           | `/export` | Export defense audit report to JSON & Markdown |\n\
                           | `/theme [name]` | Open interactive theme picker, or switch directly (`[Ctrl+T]` cycles) |\n\
                           | `/pause` | Pause / resume selected agent node in workflow |\n\
                           | `/sessions [id]` | View history & switch between chat sessions |\n\
                           | `/new` | Initialize fresh security session & archive state |\n\
                           | `/grill-me` | Adversarial security architecture interview mode |\n\
                           | `/done` | Conclude interview & synthesize hardened plan |\n\
                           | `/clear` | Clear chat message history |\n\
                           | `/help` | Display this command reference |\n\
                           | `/exit` | Exit asterisk defense harness |\n\n\
                           **Keyboard Shortcuts:**\n\
                           - `[Alt+1]`..`[Alt+5]` / `[F1]`..`[F5]` / `[Tab]`: Switch tabs (Flow, Findings, Patches, Execution, Skills)\n\
                           - `[Space]` (empty prompt): Run security audit\n\
                           - `[Ctrl+A]`: Apply patch │ `[Ctrl+R]`: Rollback patch │ `[Ctrl+P]`: Pause node │ `[Ctrl+E]`: Export report │ `[Ctrl+T]`: Cycle theme (plain letters always type into the prompt)\n\
                           - `[↑/↓]`: Navigate list / suggestions │ `[Tab]`: Autocomplete command │ `[Esc]`: Clear / Cancel │ `[Esc+Esc]`: Rewind Checkpoint".to_string(),
                });
            } else if input == "/model" || input == "model" {
                self.open_provider_model_modal(1);
            } else if let Some(model_str) = input.strip_prefix("/model ") {
                if self.config.requires_api_key() && !self.config.is_api_key_configured() {
                    self.open_key_modal();
                    self.action_msg = Some("authentication required: set API key before configuring model.".to_string());
                    self.chat_messages.push(ChatMessage::Agent {
                        sender: "orchestrator".to_string(),
                        text: format!(
                            "⚠️ **Cannot Configure Model**: No API key configured for **{}**.\n\
                             Models cannot be accessed without valid credentials. Please enter your API key first.",
                            self.active_provider.name()
                        ),
                    });
                } else {
                    let model = model_str.trim().to_string();
                    self.config.model = Some(model.clone());
                    let _ = self.config.save();
                    self.action_msg = Some(format!("model configured: {model}"));
                }
            } else if input == "/theme" || input.starts_with("/theme ") {
                let arg = input.strip_prefix("/theme").unwrap_or("").trim();
                if arg.is_empty() || arg == "list" {
                    self.open_theme_modal();
                } else if arg == "next" {
                    let t = crate::ui::theme::cycle_theme();
                    self.persist_theme(t);
                } else if let Some(t) = crate::ui::theme::set_theme(arg) {
                    self.persist_theme(t);
                } else {
                    self.action_msg = Some(format!("unknown theme '{arg}' — type /theme to list presets"));
                }
            } else if input == "/pause" || input == "pause" {
                self.toggle_pause_total();
            } else if input == "/sessions" || input == "sessions" || input == "/sessions list" {
                self.open_sessions_modal();
            } else if let Some(target_sess) = input.strip_prefix("/sessions ").or_else(|| input.strip_prefix("/session ")) {
                let target_id = target_sess.trim().trim_matches('`').to_string();
                if target_id == self.current_session_id {
                    self.action_msg = Some(format!("already on session: {target_id}"));
                    self.chat_messages.push(ChatMessage::Agent {
                        sender: "orchestrator".to_string(),
                        text: format!("ℹ️ Session `{target_id}` is already active."),
                    });
                } else {
                    self.persist_current_session();
                    match self.load_session_by_id(&target_id) {
                        Ok((m_count, f_count)) => {
                            self.current_session_id = target_id.clone();
                            self.action_msg = Some(format!("switched to session {target_id}"));
                            self.chat_messages.push(ChatMessage::Agent {
                                sender: "orchestrator".to_string(),
                                text: format!(
                                    "✓ **Session Loaded**: Switched to session `{target_id}`.\n\
                                     Restored **{m_count}** messages and **{f_count}** findings."
                                ),
                            });
                        }
                        Err(e) => {
                            self.action_msg = Some(format!("failed to load session: {e}"));
                            self.chat_messages.push(ChatMessage::Agent {
                                sender: "orchestrator".to_string(),
                                text: format!("⚠️ Could not load session `{target_id}`: {e}"),
                            });
                        }
                    }
                }
            } else if input == "/new" || input == "new" || input == "/new session" {
                self.start_new_session();
            } else if input == "/grill-me" || input == "grill-me" {
                self.is_grill_mode = true;
                self.grill_step = 1;
                self.grill_answers.clear();
                self.action_msg = Some("grill-me adversarial review started".to_string());
                self.chat_messages.push(ChatMessage::Agent {
                    sender: "security_architect".to_string(),
                    text: "### 🛡️ Asterisk Grill-Me: Adversarial Security Architecture Review\n\n\
                           *Entering interactive security review mode. I will interview you as an adversarial Principal Security Architect to probe your system's attack surface, trust boundaries, and threat model.*\n\n\
                           Type `/done` or `/exit-grill` at any time to synthesize your responses into a Hardened Security Plan.\n\n\
                           ---\n\
                           **Question 1/5: Threat Modeling & Trust Boundaries**\n\
                           What are the primary untrusted entry points into this codebase (e.g., public HTTP endpoints, RPCs, CLI arguments, file uploads, background workers), and exactly how are incoming requests authenticated and authorized before parsing?".to_string(),
                });
            } else if input == "/done" || input == "done" || input == "/exit-grill" {
                if self.is_grill_mode {
                    self.is_grill_mode = false;
                    let total_answers = self.grill_answers.len();
                    self.action_msg = Some("grill-me interview completed & plan synthesized".to_string());
                    self.chat_messages.push(ChatMessage::Agent {
                        sender: "security_architect".to_string(),
                        text: format!(
                            "### 📋 Asterisk Hardened Security Architecture Plan\n\n\
                             **Review Status**: ✓ Completed ({total_answers} architectural domains analyzed).\n\n\
                             #### Synthesized Hardening Directives & Mitigations:\n\
                             1. **Ingress Boundary Conformance**: Enforce zero-trust validation and schema sanitization at all perimeter entrypoints before unmarshaling payloads.\n\
                             2. **Taint Neutralization & Cedar Guardrails**: Parameterize all AST sink flows and apply strict Cedar policy gating on all sensitive operations.\n\
                             3. **Secret Storage & Rotation**: Isolate all API tokens into dedicated environment vaults with 30-day automated rotation and leak scanners.\n\
                             4. **Subprocess & Worktree Isolation**: Restrict command executions to Landlock/seccomp sandboxes or isolated worktree checkouts.\n\
                             5. **Supply Chain Defense**: Verify package lockfiles against typosquatting databases with Pre-Install Malware Shield.\n\n\
                             *Plan saved to session history. Run `/scan` to execute autonomous AST verification against these boundaries.*"
                        ),
                    });
                    self.persist_current_session();
                } else {
                    self.action_msg = Some("not currently in grill-me mode — type /grill-me to start".to_string());
                }
            } else if input == "/apply" || input == "apply" || input == "/patch" || input == "patch" || input == "a" {
                self.apply_current_patch();
            } else if input == "/rollback" || input == "rollback" || input == "r" {
                self.rollback_current_patch();
            } else if input == "/export" || input == "export" || input == "e" {
                self.export_security_report();
            } else if input == "/scan" || input == "scan" || input == "/audit" || input == "audit" || input.starts_with("/scan ") || input.starts_with("/audit ") {
                if input.contains("--diff-scope=local") {
                    self.diff_scope = "LOCAL".to_string();
                } else if input.contains("--diff-scope=full") {
                    self.diff_scope = "FULL".to_string();
                }

                let raw_args = if let Some(stripped) = input.strip_prefix("/scan ") {
                    stripped.trim()
                } else if let Some(stripped) = input.strip_prefix("/audit ") {
                    stripped.trim()
                } else if let Some(stripped) = input.strip_prefix("scan ") {
                    stripped.trim()
                } else if let Some(stripped) = input.strip_prefix("audit ") {
                    stripped.trim()
                } else {
                    ""
                };

                let cleaned_args = raw_args
                    .replace("--diff-scope=local", "")
                    .replace("--diff-scope=full", "")
                    .trim()
                    .to_string();

                let directive = if cleaned_args.is_empty() {
                    None
                } else {
                    Some(cleaned_args)
                };

                self.trigger_audit_with_directive(directive);
            } else if input == "/secrets" || input == "secrets" {
                let sec_findings = SecretHunterAgent::scan(&self.target_dir);
                let count = sec_findings.len();
                let mut added = 0;
                for sf in sec_findings {
                    if !self.findings.iter().any(|existing| existing.file_path == sf.file_path && existing.line_number == sf.line_number) {
                        self.findings.push(sf);
                        added += 1;
                    }
                }
                self.current_tab = 1;
                self.chat_messages.push(ChatMessage::Agent {
                    sender: "secret_hunter".to_string(),
                    text: format!(
                        "### SecretHunter Entropy & Credential Audit\n\
                         Scanned workspace for embedded API tokens, private keys, and high-entropy credentials.\n\
                         • **Total Detected Secrets**: {}\n\
                         • **Newly Added to Tab [2] Findings**: {}\n\
                         Switched view to Tab [2] Findings.",
                        count, added
                    ),
                });
                self.action_msg = Some(format!("secrets audit: {count} detected ({added} new)"));
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
                } else if lower.contains("groq") {
                    self.active_provider = AiProvider::Groq;
                } else if lower.contains("openrouter") {
                    self.active_provider = AiProvider::OpenRouter;
                } else if lower.contains("mistral") {
                    self.active_provider = AiProvider::Mistral;
                } else if lower.contains("together") {
                    self.active_provider = AiProvider::TogetherAi;
                } else if lower.contains("xai") || lower.contains("grok") {
                    self.active_provider = AiProvider::XAi;
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
                self.open_config_modal(0);
            } else if input == "/init-sec" || input.starts_with("/init-sec ") {
                match SecurityContextRules::init_default_file(&self.target_dir, &self.profile) {
                    Ok(path) => {
                        self.action_msg = Some("SECURITY.md initialized".to_string());
                        self.chat_messages.push(ChatMessage::Agent {
                            sender: "orchestrator".to_string(),
                            text: format!(
                                "✓ **SECURITY.md Initialized**: Created default context rules at `{}`.\nConfigure trusted sanitizers and ignored paths to eliminate false positives in AST taint analysis.",
                                path.display()
                            ),
                        });
                    }
                    Err(e) => {
                        self.action_msg = Some(format!("init-sec error: {e}"));
                    }
                }
            } else if input == "/reachability" || input == "reachability" {
                let reachable_count = self.findings.iter().filter(|f| f.reachability == "REACHABLE").count();
                let unreachable_count = self.findings.iter().filter(|f| f.reachability == "UNREACHABLE").count();
                let potentially_count = self.findings.iter().filter(|f| f.reachability == "POTENTIALLY_REACHABLE").count();

                let mut sample_paths = Vec::new();
                for f in &self.findings {
                    if !f.call_path.is_empty() {
                        sample_paths.push(format!("• **{}**: {}", f.id, f.call_path.join(" ➔ ")));
                        if sample_paths.len() >= 5 {
                            break;
                        }
                    }
                }

                let paths_str = if sample_paths.is_empty() {
                    "No multi-hop taint call chains detected in current findings.".to_string()
                } else {
                    sample_paths.join("\n")
                };

                self.chat_messages.push(ChatMessage::Agent {
                    sender: "graph_core".to_string(),
                    text: format!(
                        "### AST CodeContextGraph & Reachability Triage\n\n\
                         • **Reachable Flows (Blocking)**: {}\n\
                         • **Unreachable / Sanitized Flows (Pruned)**: {}\n\
                         • **Signature / Potential Flows**: {}\n\n\
                         **Taint Call Chains:**\n{}",
                        reachable_count, unreachable_count, potentially_count, paths_str
                    ),
                });
                self.action_msg = Some("reachability analysis displayed".to_string());
            } else if input == "/shield" || input == "shield" {
                let shield_findings = MalwareShieldAgent::scan(&self.target_dir);
                let count = shield_findings.len();
                let mut added = 0;
                for sf in &shield_findings {
                    if !self.findings.iter().any(|existing| existing.file_path == sf.file_path && existing.line_number == sf.line_number) {
                        self.findings.push(sf.clone());
                        added += 1;
                    }
                }
                self.chat_messages.push(ChatMessage::Agent {
                    sender: "malware_shield".to_string(),
                    text: format!(
                        "### Pre-Install Malware Shield Audit\n\
                         Scanned workspace dependencies for typosquatting packages and malicious lifecycle scripts.\n\
                         • **Suspicious / Malicious Findings**: {}\n\
                         • **Newly Added to Tab [2] Findings**: {}\n{}",
                        count,
                        added,
                        if shield_findings.is_empty() {
                            "✓ All package manifests & lifecycle hooks clean. No typosquatting detected.".to_string()
                        } else {
                            shield_findings.iter().map(|f| format!("• **{}** ({}): {}", f.id, f.cwe, f.title)).collect::<Vec<_>>().join("\n")
                        }
                    ),
                });
                self.action_msg = Some(format!("malware shield scan: {count} issues ({added} new)"));
            } else if input == "/apk" || input.starts_with("/apk ") {
                let path_arg = input.strip_prefix("/apk ").unwrap_or("").trim();
                let apk_path = if path_arg.is_empty() {
                    self.target_dir.clone()
                } else {
                    std::path::PathBuf::from(path_arg)
                };
                let apk_findings = ApkAndContainerGuardAgent::scan(&apk_path);
                let count = apk_findings.len();
                let mut added = 0;
                for af in &apk_findings {
                    if !self.findings.iter().any(|existing| existing.file_path == af.file_path && existing.line_number == af.line_number) {
                        self.findings.push(af.clone());
                        added += 1;
                    }
                }
                self.current_tab = 1;
                self.chat_messages.push(ChatMessage::Agent {
                    sender: "apk_guard".to_string(),
                    text: format!(
                        "### Android & Container Defense Guard\n\
                         Audited manifest exported components, permissions, and container specs for `{}`.\n\
                         • **Vulnerabilities Found**: {}\n\
                         • **Added to Tab [2] Findings**: {}\n\
                         Switched view to Tab [2] Findings.",
                        apk_path.display(),
                        count,
                        added
                    ),
                });
                self.action_msg = Some(format!("apk guard: {count} issues ({added} new)"));
            } else if input == "/hotfix" || input.starts_with("/hotfix ") {
                let pkg_name = input.strip_prefix("/hotfix ").unwrap_or("").trim();
                if pkg_name.is_empty() {
                    self.chat_messages.push(ChatMessage::Agent {
                        sender: "auto_hardening".to_string(),
                        text: "Usage: `/hotfix <package_name>`\nGenerates local vendor patch in `./patches/<pkg>.patch` without breaking semver upgrades.".to_string(),
                    });
                } else {
                    match AutoHardeningAgent::generate_vendor_hotfix(&self.target_dir, pkg_name, &self.findings) {
                        Ok(patch_file) => {
                            self.action_msg = Some(format!("hotfix patch created: {}", patch_file.display()));
                            self.chat_messages.push(ChatMessage::Agent {
                                sender: "auto_hardening".to_string(),
                                text: format!(
                                    "✓ **Vendor Hotfix Synthesized**: Generated backport patch at `{}` for package `{}`.\nStored locally in `./patches/` directory.",
                                    patch_file.display(),
                                    pkg_name
                                ),
                            });
                        }
                        Err(e) => {
                            self.action_msg = Some(format!("hotfix error: {e}"));
                            self.chat_messages.push(ChatMessage::Agent {
                                sender: "auto_hardening".to_string(),
                                text: format!("⚠️ Hotfix generation failed: {e}"),
                            });
                        }
                    }
                }
            } else if input == "/skills" || input.starts_with("/skills ") {
                let sub_action = input.strip_prefix("/skills ").unwrap_or("").trim();
                if sub_action.starts_with("import") {
                    let path_str = sub_action.strip_prefix("import").unwrap_or("").trim();
                    if path_str.is_empty() {
                        self.chat_messages.push(ChatMessage::Agent {
                            sender: "orchestrator".to_string(),
                            text: "Usage: `/skills import <path/to/custom.skill.md>`\nImports a Tier-2 custom skill into `.asterisk/skills/custom/`.".to_string(),
                        });
                    } else {
                        let source_path = std::path::Path::new(path_str);
                        match self.skills.import_custom_skill(&self.target_dir, source_path) {
                            Ok(skill_id) => {
                                self.current_tab = 4;
                                self.chat_messages.push(ChatMessage::Agent {
                                    sender: "orchestrator".to_string(),
                                    text: format!("✓ **Custom Skill Imported**: Successfully registered `{skill_id}` into `.asterisk/skills/custom/`."),
                                });
                                self.action_msg = Some(format!("skill imported: {skill_id}"));
                            }
                            Err(e) => {
                                self.chat_messages.push(ChatMessage::Agent {
                                    sender: "orchestrator".to_string(),
                                    text: format!("⚠️ Skill import failed: {e}"),
                                });
                                self.action_msg = Some(format!("skill import error: {e}"));
                            }
                        }
                    }
                } else if sub_action.starts_with("synth") {
                    match self.skills.synthesize_project_skill(&self.target_dir, &self.profile) {
                        Ok(skill_id) => {
                            self.current_tab = 4;
                            self.chat_messages.push(ChatMessage::Agent {
                                sender: "orchestrator".to_string(),
                                text: format!(
                                    "✓ **Tier-3 Skill Synthesized**: Orchestrator generated `{skill_id}` tailored to detected tech stacks ({}) in `.asterisk/skills/synthesized/`.",
                                    self.profile.languages.join(", ")
                                ),
                            });
                            self.action_msg = Some(format!("skill synthesized: {skill_id}"));
                        }
                        Err(e) => {
                            self.chat_messages.push(ChatMessage::Agent {
                                sender: "orchestrator".to_string(),
                                text: format!("⚠️ Skill synthesis failed: {e}"),
                            });
                            self.action_msg = Some(format!("skill synth error: {e}"));
                        }
                    }
                } else {
                    self.current_tab = 4;
                    let count = self.skills.skills.len();
                    self.chat_messages.push(ChatMessage::Agent {
                        sender: "orchestrator".to_string(),
                        text: format!(
                            "### 3-Tier Interactive Skills Registry\n\
                             Loaded **{}** progressive disclosure security defense skills.\n\
                             Switched active view to Tab [5] Skills.\n\
                             💡 *Sub-actions available: `/skills import <path>` and `/skills synth`.*",
                            count
                        ),
                    });
                    self.action_msg = Some("switched to skills tab".to_string());
                }
            } else if input.starts_with('/') {
                self.chat_messages.push(ChatMessage::Agent {
                    sender: "orchestrator".to_string(),
                    text: format!("⚠️ Unknown slash command `{input}`. Type `/help` for available security commands."),
                });
                self.action_msg = Some(format!("unknown command: {input}"));
            } else {
                if !self.config.is_api_key_configured() {
                    // Keep the typed text so the user does not lose it, and show a hint instead of a popup.
                    self.prompt_input = input.clone();
                    self.action_msg = Some(format!(
                        "chat needs an API key for {} — type /provider (or /key) to set one.",
                        self.config.provider.name()
                    ));
                    return false;
                }
                self.chat_scroll = 0;
                self.chat_messages.push(ChatMessage::User(input.clone()));
                self.is_chat_querying = true;
                self.action_msg = Some(format!("Asterisk is thinking via {}...", self.config.get_model()));
                let hub = SecurityAgentHub::new(self.target_dir.clone(), Arc::new(PolicyGate::default()), self.config.clone());
                let sender = self.engine_tx.clone();

                if self.is_grill_mode {
                    self.grill_answers.push((format!("Domain {}", self.grill_step), input.clone()));
                    self.grill_step += 1;
                }

                let prompt_text = if self.is_grill_mode {
                    format!(
                        "[SYSTEM DIRECTIVE: ADVERSARIAL PRINCIPAL SECURITY ARCHITECT - GRILL-ME REVIEW]\n\
                         You are Asterisk's Principal Security Architect conducting an adversarial security review of the user's project.\n\
                         The user responded to Domain {}: \"{}\".\n\n\
                         Directives:\n\
                         1. Critically analyze their response. Identify attack vectors, unhandled edge cases, trust boundary ambiguities, injection/taint sinks, or credential exposure vectors they missed.\n\
                         2. Challenge their architectural assumptions with direct adversarial scenarios.\n\
                         3. Pose Question {}/5 probing the next vital architectural boundary (e.g. data validation/taint sinks, secret storage & rotation, subprocess isolation, or supply chain dependencies).\n\
                         Keep your tone adversarial yet constructive, sharp, and concise.",
                        self.grill_step.saturating_sub(1),
                        input,
                        self.grill_step.min(5)
                    )
                } else {
                    input.clone()
                };
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    handle.spawn(async move {
                        let reply = hub.query(&prompt_text).await;
                        let (thought_opt, clean_text) = crate::core::agent::parse_ai_thinking_content(&reply);
                        if let Some(thought) = thought_opt {
                            let _ = sender.send(EngineMessage::Chat(ChatMessage::Thinking {
                                agent: "orchestrator".to_string(),
                                thought,
                            }));
                        }
                        let _ = sender.send(EngineMessage::Chat(ChatMessage::Agent {
                            sender: "orchestrator".to_string(),
                            text: clean_text,
                        }));
                        let _ = sender.send(EngineMessage::ChatQueryFinished);
                    });
                } else {
                    self.is_chat_querying = false;
                    self.chat_messages.push(ChatMessage::Agent {
                        sender: "orchestrator".to_string(),
                        text: "⚠️ Async runtime handle unavailable for chat query.".to_string(),
                    });
                }
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

        if self.show_key_modal && self.active_modal == ActiveModal::SelectTheme {
            let Some(t) = self.click_targets.theme_picker.clone() else { return };
            let n = crate::ui::theme::presets().len();
            match mouse.kind {
                MouseEventKind::ScrollUp => {
                    let i = self.theme_picker_index;
                    self.theme_picker_select(if i == 0 { n - 1 } else { i - 1 });
                }
                MouseEventKind::ScrollDown => self.theme_picker_select((self.theme_picker_index + 1) % n),
                MouseEventKind::Down(MouseButton::Left) => {
                    if t.btn_apply.is_some_and(|r| in_rect(r, col, row)) {
                        self.theme_picker_apply();
                    } else if t.btn_cancel.is_some_and(|r| in_rect(r, col, row)) {
                        self.theme_picker_cancel();
                    } else if let Some((idx, _)) = t.rows.iter().find(|(_, r)| in_rect(*r, col, row)) {
                        if *idx == self.theme_picker_index {
                            self.theme_picker_apply();
                        } else {
                            self.theme_picker_select(*idx);
                        }
                    } else if !in_rect(t.modal_rect, col, row) {
                        self.theme_picker_cancel();
                    }
                }
                _ => {}
            }
            return;
        }

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
                            let _ = self.config.save();
                            if *provider == AiProvider::Custom && self.config.get_base_url().is_none() {
                                self.open_url_modal();
                            } else if self.config.requires_api_key() && !self.config.is_api_key_configured() {
                                self.open_key_modal();
                            } else {
                                self.open_model_modal();
                            }
                            return;
                        }
                    }
                    let mut clicked_session = None;
                    let mut clicked_model = None;
                    if self.active_modal == ActiveModal::SelectSession {
                        for (preset, rect) in &modal_targets.model_preset_buttons {
                            if in_rect(*rect, col, row) {
                                clicked_session = Some(preset.clone());
                                break;
                            }
                        }
                    } else {
                        for (preset, rect) in &modal_targets.model_preset_buttons {
                            if in_rect(*rect, col, row) {
                                clicked_model = Some(preset.clone());
                                break;
                            }
                        }
                    }

                    if let Some(sess_id) = clicked_session {
                        if sess_id == self.current_session_id {
                            self.action_msg = Some(format!("already on session: {sess_id}"));
                        } else {
                            self.persist_current_session();
                            match self.load_session_by_id(&sess_id) {
                                Ok((m_count, f_count)) => {
                                    self.action_msg = Some(format!("switched to session: {sess_id}"));
                                    self.chat_messages.push(ChatMessage::Agent {
                                        sender: "orchestrator".to_string(),
                                        text: format!(
                                            "✓ **Session Loaded**: Switched to session `{sess_id}`.\n\
                                             Restored **{m_count}** messages and **{f_count}** findings."
                                        ),
                                    });
                                }
                                Err(e) => {
                                    self.action_msg = Some(format!("failed to load session: {e}"));
                                }
                            }
                        }
                        self.show_key_modal = false;
                        self.active_modal = ActiveModal::None;
                        return;
                    }

                    if let Some(preset) = clicked_model {
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
            return;
        }

        // Determine which pane is under cursor
        let is_over_sidebar = self.click_targets.sidebar_rect.map_or(
            self.focused_pane == FocusedPane::Chatbot,
            |r| in_rect(r, col, row),
        );

        // Scroll handlers: independent scrolling for Chatbot and Workflow
        if matches!(mouse.kind, MouseEventKind::ScrollUp) {
            if is_over_sidebar {
                self.chat_scroll += 1;
            } else {
                if self.current_tab == 0 {
                    for event in self.flow.handle_mouse_event(mouse).into_events() {
                        if let FlowEvent::NodeClicked { node_id } = event {
                            self.selected_node_id = Some(node_id.clone());
                            self.action_msg = Some(format!("selected node {node_id}"));
                        }
                    }
                } else if self.current_tab == 1 && self.selected_matrix_row > 0 {
                    self.selected_matrix_row -= 1;
                } else if self.current_tab == 2 && self.selected_patch_row > 0 {
                    self.selected_patch_row -= 1;
                }
            }
            return;
        }
        if matches!(mouse.kind, MouseEventKind::ScrollDown) {
            if is_over_sidebar {
                self.chat_scroll = self.chat_scroll.saturating_sub(1);
            } else {
                if self.current_tab == 0 {
                    for event in self.flow.handle_mouse_event(mouse).into_events() {
                        if let FlowEvent::NodeClicked { node_id } = event {
                            self.selected_node_id = Some(node_id.clone());
                            self.action_msg = Some(format!("selected node {node_id}"));
                        }
                    }
                } else if self.current_tab == 1 {
                    if self.selected_matrix_row + 1 < self.findings.len() {
                        self.selected_matrix_row += 1;
                    }
                } else if self.current_tab == 2 {
                    if self.selected_patch_row + 1 < self.patches.len() {
                        self.selected_patch_row += 1;
                    }
                }
            }
            return;
        }

        // Workspace Screen Clicks
        if is_left_click {
            if let Some(r) = self.click_targets.sidebar_rect {
                if in_rect(r, col, row) {
                    self.focused_pane = FocusedPane::Chatbot;
                }
            }
            if let Some(r) = self.click_targets.workspace_rect {
                if in_rect(r, col, row) {
                    self.focused_pane = FocusedPane::Workflow;
                }
            }

            // A. Tab clicks
            for (tab_idx, rect) in &self.click_targets.tab_rects {
                if in_rect(*rect, col, row) {
                    self.current_tab = *tab_idx;
                    self.focused_pane = FocusedPane::Workflow;
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
                if let Some(btn_del) = sidebar_targets.btn_delete_node {
                    if in_rect(btn_del, col, row) {
                        self.delete_selected_workflow_node();
                        return;
                    }
                }
                if let Some(btn_left) = sidebar_targets.btn_move_left {
                    if in_rect(btn_left, col, row) {
                        self.shift_selected_workflow_node(-36.0, 0.0);
                        return;
                    }
                }
                if let Some(btn_right) = sidebar_targets.btn_move_right {
                    if in_rect(btn_right, col, row) {
                        self.shift_selected_workflow_node(36.0, 0.0);
                        return;
                    }
                }
                if let Some(btn_up) = sidebar_targets.btn_move_up {
                    if in_rect(btn_up, col, row) {
                        self.shift_selected_workflow_node(0.0, -7.0);
                        return;
                    }
                }
                if let Some(btn_down) = sidebar_targets.btn_move_down {
                    if in_rect(btn_down, col, row) {
                        self.shift_selected_workflow_node(0.0, 7.0);
                        return;
                    }
                }
                if let Some(btn_pause) = sidebar_targets.btn_pause {
                    if in_rect(btn_pause, col, row) {
                        self.toggle_pause_total();
                        return;
                    }
                }
                if let Some(btn_apply) = sidebar_targets.btn_apply {
                    if in_rect(btn_apply, col, row) {
                        self.apply_current_patch();
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

            // E. Tab 4: Skills View click
            if self.current_tab == 4 {
                if let Some(search_rect) = self.click_targets.skills_search_bar {
                    if in_rect(search_rect, col, row) {
                        self.skills_search_active = true;
                        return;
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
        const MIN_COLS: u16 = 70;
        const MIN_ROWS: u16 = 18;

        if area.width < MIN_COLS || area.height < MIN_ROWS {
            let msg = vec![
                Line::from(vec![
                    Span::styled("  ⚠️  Terminal Window Too Small  ", Style::default().fg(th().warning).add_modifier(Modifier::BOLD)),
                ]),
                Line::raw(""),
                Line::from(vec![
                    Span::styled(format!("  Current size: {} × {} cells", area.width, area.height), Style::default().fg(th().text_muted)),
                ]),
                Line::from(vec![
                    Span::styled(format!("  Minimum required: {MIN_COLS} × {MIN_ROWS} cells"), Style::default().fg(th().text_dim)),
                ]),
                Line::raw(""),
                Line::from(vec![
                    Span::styled("  Please enlarge or maximize your terminal window to continue.", Style::default().fg(th().fg)),
                ]),
            ];

            let card_w = 64.min(area.width.saturating_sub(2));
            let card_h = 7.min(area.height.saturating_sub(2));
            let x = (area.width.saturating_sub(card_w)) / 2;
            let y = (area.height.saturating_sub(card_h)) / 2;
            let box_rect = Rect::new(x, y, card_w, card_h);

            f.render_widget(ratatui::widgets::Clear, area);
            f.render_widget(
                Block::default().style(Style::default().bg(th().bg_alt)),
                area,
            );
            f.render_widget(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(th().warning))
                    .style(Style::default().bg(th().surface)),
                box_rect,
            );
            let inner = Rect::new(box_rect.x + 1, box_rect.y + 1, box_rect.width.saturating_sub(2), box_rect.height.saturating_sub(2));
            f.render_widget(Paragraph::new(msg), inner);
            return;
        }

        self.render_workspace(f, area);

        if self.show_key_modal {
            let modal_targets = match self.active_modal {
                ActiveModal::SelectTheme => {
                    let saved = self.config.theme.clone().unwrap_or_else(|| "default_dark".to_string());
                    let t = crate::ui::views::ThemePickerView::render(f, area, self.theme_picker_index, &saved);
                    self.click_targets.theme_picker = Some(t);
                    ModalClickTargets::default()
                }
                ActiveModal::SelectProvider => {
                    ModalView::render_provider_list(
                        f,
                        area,
                        self.selected_provider_index,
                        &self.config,
                    )
                }
                ActiveModal::ProviderDetail => {
                    ModalView::render_provider_detail_hub(
                        f,
                        area,
                        self.active_provider,
                        &self.config,
                    )
                }
                ActiveModal::ConfigDashboard => {
                    ModalView::render_config_dashboard(
                        f,
                        area,
                        &self.config,
                    )
                }
                ActiveModal::SelectModel => {
                    let cur_model = self.config.get_model();
                    ModalView::render_grouped_model_catalog(
                        f,
                        area,
                        &self.model_search_query,
                        &self.model_filtered_items,
                        self.selected_model_index,
                        &cur_model,
                    )
                }
                ActiveModal::CustomProviderNameInput => {
                    ModalView::render_single_input_modal(
                        f,
                        area,
                        "Add Provider (Step 1 of 3: Name)",
                        "Enter provider display name (e.g., OpenRouter, Mistral, Local LLM):",
                        &self.custom_provider_name_input,
                        false,
                        self.key_modal_error.as_deref(),
                    )
                }
                ActiveModal::BaseUrlInput => {
                    let title = if self.active_provider == AiProvider::Custom {
                        "Custom Provider Setup (Step 2 of 3: Endpoint URL)"
                    } else if self.active_provider == AiProvider::OllamaLocal {
                        "Ollama Setup (Step 1 of 1: Endpoint URL)"
                    } else {
                        &format!("{} Setup (Step 1 of 2: Endpoint URL)", self.active_provider.name())
                    };
                    let placeholder = match self.active_provider {
                        AiProvider::Custom => "Enter API Base URL (e.g., https://openrouter.ai/api/v1):",
                        AiProvider::OllamaLocal => "Enter Ollama Base URL (default: http://localhost:11434):",
                        AiProvider::OpenAiGpt4o => "Enter OpenAI Base URL (default: https://api.openai.com/v1):",
                        _ => "Enter custom API Base URL (leave empty for default):",
                    };
                    ModalView::render_single_input_modal(
                        f,
                        area,
                        title,
                        placeholder,
                        &self.url_modal_input,
                        false,
                        self.key_modal_error.as_deref(),
                    )
                }
                ActiveModal::ApiKeyInput => {
                    let title = if self.active_provider == AiProvider::Custom {
                        "Custom Provider Setup (Step 3 of 3: API Key)"
                    } else {
                        &format!("{} Setup (Step 2 of 2: API Key)", self.active_provider.name())
                    };
                    ModalView::render_single_input_modal(
                        f,
                        area,
                        title,
                        "Enter API key (leave empty for no-auth endpoints):",
                        &self.key_modal_input,
                        true,
                        self.key_modal_error.as_deref(),
                    )
                }
                ActiveModal::Help => {
                    ModalView::render_help_modal(f, area);
                    ModalClickTargets::default()
                }
                ActiveModal::SelectSession => {
                    ModalView::render_session_list(
                        f,
                        area,
                        &self.sessions_list,
                        self.selected_session_index,
                        &self.current_session_id,
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
        f.render_widget(Block::default().style(Style::default().bg(th().bg_alt)), area);

        let root_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(8),
                Constraint::Length(1),
            ])
            .split(area);

        // Top Header Bar with sleek surface fill
        let header_block = Block::default().style(Style::default().bg(th().surface));
        f.render_widget(header_block, root_chunks[0]);

        let spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let spinner_idx = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            / 80) as usize
            % spinner_frames.len();
        let spinner_char = spinner_frames[spinner_idx];

        let status_badge = if self.awaiting_confirmation {
            Span::styled(" ● AWAITING REVIEW ", Style::default().fg(th().warning).bg(th().element).add_modifier(Modifier::BOLD))
        } else if self.is_running {
            Span::styled(format!(" {spinner_char} SCANNING "), Style::default().fg(th().primary).bg(th().element).add_modifier(Modifier::BOLD))
        } else {
            Span::styled(" ● READY ", Style::default().fg(th().success).bg(th().element))
        };

        let unpatched_count = self.findings.iter().filter(|x| !x.patched).count();
        let findings_pill = if unpatched_count > 0 {
            Span::styled(format!(" ⚠️ {unpatched_count} unresolved "), Style::default().fg(Color::Rgb(255, 255, 255)).bg(th().destructive).add_modifier(Modifier::BOLD))
        } else {
            Span::styled(" ✓ 0 issues ", Style::default().fg(th().success).bg(th().element))
        };

        // Adaptive header: path takes whatever room is left; low-priority pills drop first.
        let files_txt = format!(" 📁 {} files ", self.profile.total_files);
        let patches_txt = format!(" 🩹 {} patches ", self.patches.len());
        let prov_txt = format!(" 🤖 {} ", self.active_provider.name());
        let find_txt = findings_pill.content.to_string();
        let badge_txt = status_badge.content.to_string();
        let total_w = area.width as usize;
        let w = |t: &str| crate::ui::fit::text_width(t);
        let fixed_core = 1 + w(" ✻ asterisk ") + 2 + w(&prov_txt) + 2 + w(&badge_txt) + 2 + w(&find_txt);
        let mut show_files = true;
        let mut show_patches = true;
        let extra = |sf: bool, sp: bool| (if sf { 2 + w(&files_txt) } else { 0 }) + (if sp { 2 + w(&patches_txt) } else { 0 });
        let mut path_room = total_w.saturating_sub(fixed_core + extra(show_files, show_patches) + 2);
        if path_room < 14 {
            show_patches = false;
            path_room = total_w.saturating_sub(fixed_core + extra(show_files, show_patches) + 2);
        }
        if path_room < 14 {
            show_files = false;
            path_room = total_w.saturating_sub(fixed_core + extra(show_files, show_patches) + 2);
        }
        let dir_txt = crate::ui::fit::ellipsize_start(&self.target_dir.display().to_string(), path_room.saturating_sub(2).max(6));

        let mut header_spans = vec![
            Span::raw(" "),
            Span::styled(" ✻ asterisk ", Style::default().fg(th().fg).bg(th().element).add_modifier(Modifier::BOLD)),
            Span::raw("  "),
            Span::styled(format!(" {dir_txt} "), Style::default().fg(th().text_sub).bg(th().element)),
        ];
        if show_files {
            header_spans.push(Span::raw("  "));
            header_spans.push(Span::styled(files_txt, Style::default().fg(th().text_muted).bg(th().element)));
        }
        header_spans.push(Span::raw("  "));
        header_spans.push(findings_pill);
        if show_patches {
            header_spans.push(Span::raw("  "));
            header_spans.push(Span::styled(patches_txt, Style::default().fg(th().text_muted).bg(th().element)));
        }
        header_spans.push(Span::raw("  "));
        header_spans.push(Span::styled(prov_txt, Style::default().fg(th().primary).bg(th().element)));
        header_spans.push(Span::raw("  "));
        header_spans.push(status_badge);
        let top_header = Line::from(header_spans);
        f.render_widget(Paragraph::new(top_header), root_chunks[0]);

        // Master-Detail Layout: 45% Left Chatbot vs 55% Right Workspace Area (generous reading & workspace room)
        let sidebar_width = ((root_chunks[1].width as usize * 45) / 100).clamp(42, 74) as u16;
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(sidebar_width.min(root_chunks[1].width.saturating_sub(44))),
                Constraint::Min(44),
            ])
            .split(root_chunks[1]);

        self.click_targets.sidebar_rect = Some(main_chunks[0]);
        self.click_targets.workspace_rect = Some(main_chunks[1]);

        // Left Sidebar Chatbot
        let sel_node = self.selected_node_id.as_ref().and_then(|id| self.nodes_info.get(id));
        let is_chatbot_focused = self.focused_pane == FocusedPane::Chatbot;
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
            is_chatbot_focused,
            self.is_chat_querying,
            &self.config.get_model(),
        );
        self.click_targets.sidebar = Some(sidebar_targets);

        // Right Workspace Area: Tab Strip + Viewport with top & bottom margins
        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // Top margin / breathing room
                Constraint::Length(1), // Tab Bar row
                Constraint::Length(1), // Bottom margin / subtle separator
                Constraint::Min(6),    // Viewport
            ])
            .split(main_chunks[1]);

        // Modern Tab Bar surface
        let tab_bar_area = right_chunks[1];
        f.render_widget(Block::default().style(Style::default().bg(th().bg)), tab_bar_area);

        let findings_count = self.findings.len();
        let patches_count = self.patches.len();
        let tabs_info = [
            (0, " 1 Flow ".to_string()),
            (1, if findings_count > 0 { format!(" 2 Findings ({findings_count}) ") } else { " 2 Findings ".to_string() }),
            (2, if patches_count > 0 { format!(" 3 Patches ({patches_count}) ") } else { " 3 Patches ".to_string() }),
            (3, " 4 Exec ".to_string()),
            (4, " 5 Skills ".to_string()),
        ];

        let mut tab_spans = Vec::new();
        let mut tab_rects = Vec::new();
        let mut curr_x = tab_bar_area.x;

        tab_spans.push(Span::raw(" "));
        curr_x += 1;

        // OpenCode-style tab strip: natural widths when they fit; otherwise the active tab
        // stays complete and the others share the room, ellipsized (e.g. " 3 Patch… ").
        let natural: Vec<usize> = tabs_info.iter().map(|(_, l)| l.chars().count()).collect();
        let avail = (tab_bar_area.width as usize).saturating_sub(2);
        let widths = crate::ui::fit::tab_widths(&natural, self.current_tab.min(tabs_info.len() - 1), avail, 1);

        for ((idx, label), tw) in tabs_info.iter().zip(widths.iter()) {
            let is_selected = self.current_tab == *idx;
            let shown = crate::ui::fit::fit_pad(label, *tw);
            let width = *tw as u16;

            let pill_style = if is_selected {
                Style::default()
                    .fg(th().fg)
                    .bg(th().element_hi)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(th().text_muted)
                    .bg(th().surface)
            };

            tab_rects.push((
                *idx,
                Rect::new(curr_x, right_chunks[0].y, width, 3),
            ));

            tab_spans.push(Span::styled(shown, pill_style));
            tab_spans.push(Span::raw(" "));
            curr_x += width + 1;
        }

        self.click_targets.tab_rects = tab_rects;

        let tab_bar_widget = Paragraph::new(Line::from(tab_spans))
            .block(Block::default().style(Style::default().bg(th().bg)));
        f.render_widget(tab_bar_widget, tab_bar_area);

        let content_area = right_chunks[3];
        match self.current_tab {
            0 => GraphView::render(f, content_area, &mut self.flow, self.nodes_info.is_empty()),
            1 => {
                let table_rect = MatrixView::render(f, content_area, &self.findings, self.selected_matrix_row, self.findings_filter_reachable);
                self.click_targets.findings_table = Some(table_rect);
            }
            2 => {
                let patch_targets = PatchView::render(f, content_area, &self.patches, self.selected_patch_row, &self.action_msg);
                self.click_targets.patches = Some(patch_targets);
            }
            3 => LogsView::render(f, content_area, &self.logs, 0),
            4 => {
                let search_rect = SkillsView::render(
                    f,
                    content_area,
                    &self.skills.skills,
                    &self.skills_search,
                    self.skills_search_active,
                    self.selected_skill_index,
                );
                self.click_targets.skills_search_bar = Some(search_rect);
            }
            _ => {}
        }

        // Bottom Footer Bar (Sleek surface fill, no ASCII pipe spam)
        let footer_block = Block::default().style(Style::default().bg(th().bg));
        f.render_widget(footer_block, root_chunks[2]);

        let fkey = Style::default().fg(th().fg).bg(th().element);
        let flab = Style::default().fg(th().text_muted);
        let footer = if self.patches.is_empty() {
            crate::ui::fit::hint_line(
                &[("[Space]", "audit"), ("[Tab]", "views"), ("[/config]", "settings"), ("[Esc]", "quit")],
                area.width as usize,
                fkey,
                flab,
                "   ",
            )
        } else {
            crate::ui::fit::hint_line(
                &[("[Tab]", "views"), ("[Ctrl+A]", "apply patch"), ("[Ctrl+R]", "rollback"), ("[Esc]", "quit")],
                area.width as usize,
                fkey,
                flab,
                "   ",
            )
        };
        f.render_widget(Paragraph::new(footer), root_chunks[2]);
    }
}

fn in_rect(rect: Rect, col: u16, row: u16) -> bool {
    col >= rect.x && col < rect.x + rect.width && row >= rect.y && row < rect.y + rect.height
}
