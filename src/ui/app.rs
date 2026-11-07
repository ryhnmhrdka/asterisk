use crate::execution::{EngineCommand, EngineMessage, ExecutionEngine};
use crate::orchestrator::{AgentGraphBuilder, DefensePlan, WorkspaceScanner};
use crate::skills::SkillRegistry;
use crate::subagents::AutoHardeningAgent;
use crate::types::{
    AgentStatus, ChatMessage, DynamicLogEntry, HardeningPatch, SproutedNodeInfo,
    VulnerabilityFinding, WorkspaceProfile,
};
use crate::ui::views::{
    GraphView, LogsView, MatrixView, PatchClickTargets, PatchView, SidebarClickTargets,
    SidebarView, SkillsView, WelcomeView,
};
use chrono::Utc;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use rataflow::{Flow, FlowEvent, StepEdge, TextContent};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Tabs},
    Frame,
};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppMode {
    Welcome,
    Workspace,
}

#[derive(Default)]
pub struct AppClickTargets {
    pub welcome_btn: Option<Rect>,
    pub tab_rects: Vec<(usize, Rect)>,
    pub sidebar: Option<SidebarClickTargets>,
    pub findings_table: Option<Rect>,
    pub patches: Option<PatchClickTargets>,
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
        let nodes_info = AgentGraphBuilder::default_nodes_map();
        let flow = AgentGraphBuilder::build_sprouted_graph(&nodes_info).unwrap_or_else(|_| Flow::new());
        let skills = SkillRegistry::new();

        Self {
            mode: if start_in_welcome { AppMode::Welcome } else { AppMode::Workspace },
            current_tab: 0,
            target_dir: initial_target,
            welcome_input: String::new(),
            prompt_input: String::new(),
            flow,
            nodes_info,
            selected_node_id: Some("orch".to_string()),
            profile,
            plan: None,
            findings: Vec::new(),
            patches: Vec::new(),
            logs: Vec::new(),
            chat_messages: vec![ChatMessage::System("autonomous code defense harness initialized.".to_string())],
            chat_scroll: 0,
            skills,
            selected_matrix_row: 0,
            selected_patch_row: 0,
            action_msg: None,
            is_running: false,
            awaiting_confirmation: false,
            engine_rx: rx,
            engine_tx: tx,
            cmd_tx,
            cmd_rx: Some(cmd_rx),
            click_targets: AppClickTargets::default(),
        }
    }

    pub fn trigger_audit(&mut self) {
        if self.is_running {
            return;
        }
        self.is_running = true;
        self.awaiting_confirmation = false;
        self.action_msg = Some("scanning workspace...".to_string());

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
        self.chat_messages.push(ChatMessage::User("y (confirmed via click)".to_string()));
        self.awaiting_confirmation = false;
        let _ = self.cmd_tx.send(EngineCommand::ConfirmDeploy);
    }

    pub fn cancel_subagent_deployment(&mut self) {
        self.chat_messages.push(ChatMessage::User("deployment cancelled by user.".to_string()));
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

                self.chat_messages.push(ChatMessage::System(format!("node [{}] marked as {state_str}.", node.id)));

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
        match self.mode {
            AppMode::Welcome => self.handle_welcome_key(key),
            AppMode::Workspace => self.handle_workspace_key(key),
        }
    }

    fn handle_welcome_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => true,
            KeyCode::Enter => {
                if !self.welcome_input.trim().is_empty() {
                    self.target_dir = PathBuf::from(self.welcome_input.trim());
                }
                self.profile = WorkspaceScanner::scan(&self.target_dir);
                self.mode = AppMode::Workspace;
                self.trigger_audit();
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

        match key.code {
            KeyCode::Esc => {
                if !self.prompt_input.is_empty() {
                    self.prompt_input.clear();
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

            KeyCode::Enter => {
                self.submit_prompt_input();
            }
            KeyCode::Backspace => {
                self.prompt_input.pop();
            }
            KeyCode::Char('p') if self.prompt_input.is_empty() => {
                self.toggle_pause_selected_node();
            }
            KeyCode::Char('a') if self.prompt_input.is_empty() => {
                self.apply_current_patch();
            }
            KeyCode::Char('r') if self.prompt_input.is_empty() => {
                self.rollback_current_patch();
            }
            KeyCode::Char('e') if self.prompt_input.is_empty() => {
                self.export_security_report();
            }
            KeyCode::Char(' ') if self.prompt_input.is_empty() => {
                self.trigger_audit();
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

    pub fn submit_prompt_input(&mut self) {
        let input = self.prompt_input.trim().to_string();
        self.prompt_input.clear();

        if self.awaiting_confirmation {
            if input.is_empty() || input.eq_ignore_ascii_case("y") || input.eq_ignore_ascii_case("yes") {
                self.confirm_subagent_deployment();
                return;
            } else if input.eq_ignore_ascii_case("n") || input.eq_ignore_ascii_case("no") {
                self.cancel_subagent_deployment();
                return;
            }
        }

        if !input.is_empty() {
            self.chat_messages.push(ChatMessage::User(input.clone()));

            if input == "/pause" || input == "pause" {
                self.toggle_pause_selected_node();
            } else if input == "/apply" || input == "apply" || input == "a" {
                self.apply_current_patch();
            } else if input == "/rollback" || input == "rollback" || input == "r" {
                self.rollback_current_patch();
            } else if input == "/export" || input == "export" || input == "e" {
                self.export_security_report();
            } else if input == "/scan" || input == "scan" {
                self.trigger_audit();
            } else {
                self.chat_messages.push(ChatMessage::Agent {
                    sender: "orchestrator".to_string(),
                    text: format!("command received: '{input}'. use /apply, /rollback, /pause, or click action buttons."),
                });
            }
        }
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
                        if !self.welcome_input.trim().is_empty() {
                            self.target_dir = PathBuf::from(self.welcome_input.trim());
                        }
                        self.profile = WorkspaceScanner::scan(&self.target_dir);
                        self.mode = AppMode::Workspace;
                        self.trigger_audit();
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

                // Subagent Tray row clicks (focusing subagent)
                for (node_id, row_rect) in &sidebar_targets.subagent_rows {
                    if in_rect(*row_rect, col, row) {
                        self.selected_node_id = Some(node_id.clone());
                        self.action_msg = Some(format!("focused subagent {node_id}"));
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
                let btn = WelcomeView::render(f, area, &self.welcome_input, &self.target_dir.display().to_string());
                self.click_targets.welcome_btn = Some(btn);
            }
            AppMode::Workspace => {
                self.render_workspace(f, area);
            }
        }
    }

    fn render_workspace(&mut self, f: &mut Frame, area: Rect) {
        let root_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),
                Constraint::Min(8),
                Constraint::Length(1),
            ])
            .split(area);

        // Top Header
        let status_badge = if self.awaiting_confirmation {
            Span::styled(" [confirm?] ", Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD))
        } else if self.is_running {
            Span::styled(" [running] ", Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD))
        } else {
            Span::styled(" [ready] ", Style::default().fg(Color::DarkGray))
        };

        let unpatched_count = self.findings.iter().filter(|x| !x.patched).count();
        let top_header = Line::from(vec![
            Span::styled("kartikacyber", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled(" :: ", Style::default().fg(Color::DarkGray)),
            Span::styled(self.target_dir.display().to_string(), Style::default().fg(Color::White)),
            Span::styled("  │  files: ", Style::default().fg(Color::DarkGray)),
            Span::styled(self.profile.total_files.to_string(), Style::default().fg(Color::White)),
            Span::styled("  │  findings: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{} ({} unpatched)", self.findings.len(), unpatched_count), Style::default().fg(Color::White)),
            Span::styled("  │  patches: ", Style::default().fg(Color::DarkGray)),
            Span::styled(self.patches.len().to_string(), Style::default().fg(Color::White)),
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
            self.awaiting_confirmation,
        );
        self.click_targets.sidebar = Some(sidebar_targets);

        // Right Workspace Area: Tab Strip + Viewport
        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),
                Constraint::Min(6),
            ])
            .split(main_chunks[1]);

        // Calculate Clickable Tab Rectangles
        let tab_bar_area = right_chunks[0];
        let tab_width = tab_bar_area.width / 5;
        let mut tab_rects = Vec::new();
        for i in 0..5 {
            tab_rects.push((
                i,
                Rect::new(tab_bar_area.x + i as u16 * tab_width, tab_bar_area.y, tab_width, tab_bar_area.height),
            ));
        }
        self.click_targets.tab_rects = tab_rects;

        let titles = vec![
            " 1 flow graph ",
            " 2 findings ",
            " 3 patches ",
            " 4 execution ",
            " 5 skills ",
        ];
        let tabs = Tabs::new(titles)
            .select(self.current_tab)
            .style(Style::default().fg(Color::DarkGray))
            .highlight_style(Style::default().fg(Color::Black).bg(Color::White).add_modifier(Modifier::BOLD))
            .divider(Span::styled(" │ ", Style::default().fg(Color::DarkGray)));
        f.render_widget(tabs, right_chunks[0]);

        let content_area = right_chunks[1];
        match self.current_tab {
            0 => GraphView::render(f, content_area, &mut self.flow),
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

        // Bottom Footer Bar
        let footer = Line::from(vec![
            Span::styled("click anywhere to interact  │  ", Style::default().fg(Color::DarkGray)),
            Span::styled("tab", Style::default().fg(Color::White)),
            Span::styled(" views  │  ", Style::default().fg(Color::DarkGray)),
            Span::styled("p", Style::default().fg(Color::White)),
            Span::styled(" pause/resume  │  ", Style::default().fg(Color::DarkGray)),
            Span::styled("a", Style::default().fg(Color::White)),
            Span::styled(" apply  │  ", Style::default().fg(Color::DarkGray)),
            Span::styled("r", Style::default().fg(Color::White)),
            Span::styled(" rollback  │  ", Style::default().fg(Color::DarkGray)),
            Span::styled("esc", Style::default().fg(Color::White)),
            Span::styled(" quit", Style::default().fg(Color::DarkGray)),
        ]);
        f.render_widget(Paragraph::new(footer), root_chunks[2]);
    }
}

fn in_rect(rect: Rect, col: u16, row: u16) -> bool {
    col >= rect.x && col < rect.x + rect.width && row >= rect.y && row < rect.y + rect.height
}
