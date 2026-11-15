use crate::ui::theme::th;
use crate::types::{AgentStatus, SproutedNodeInfo, WorkflowPlan, WorkflowTaskNode};
use rataflow::{
    Edge, EdgeMarker, EdgeStyle, Flow, Node, NodeContent, NodeRenderContext, StepEdge,
};
use ratatui::{
    buffer::Buffer,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Widget},
};
use std::collections::HashMap;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, Default)]
pub struct AgentNodeContent {
    pub id: String,
    pub title: String,
    pub subtitle: String,
    pub tier: String,
    pub status: AgentStatus,
    pub is_paused: bool,
    pub findings_count: usize,
}

impl NodeContent for AgentNodeContent {
    fn render(&self, ctx: &NodeRenderContext, buf: &mut Buffer) {
        if ctx.area.width < 6 || ctx.area.height < 3 {
            return;
        }

        // 1. Fill solid background to prevent canvas dots bleeding through
        for y in ctx.area.top()..ctx.area.bottom() {
            for x in ctx.area.left()..ctx.area.right() {
                if let Some(cell) = buf.cell_mut((x, y)) {
                    cell.set_char(' ');
                    cell.set_bg(th().surface);
                }
            }
        }

        // 2. Technical ASCII-like monochrome tags (No emojis)
        let (tag, tag_color) = match self.tier.as_str() {
            "planner" => ("[#] ORCH", th().primary),
            "folder" => ("[/] DIR", th().text_sub),
            "file" => ("[.] FILE", th().text_sub),
            "gate" => ("[#] GATE", th().warning),
            "secrets" => ("[>] SECRET", th().primary),
            "sast" => ("[>] SAST", th().primary),
            "sca" => ("[>] SCA", th().primary),
            "net" => ("[>] NET", th().primary),
            "malware" => ("[!] MALWARE", th().destructive),
            "apk" => ("[#] APK", th().secondary),
            "verifier" => ("[✓] VERIFY", th().success),
            "patcher" => ("[!] PATCH", th().destructive),
            "remediator" => ("[#] FIX-ORCH", th().warning),
            "rewriter" => ("[✎] REWRITE", th().primary),
            "injector" => ("[+] GUARD", th().secondary),
            "executor" => ("[$] EXEC", th().info),
            "release_gate" => ("[★] RELEASE", th().success),
            "subagent" => match self.id.as_str() {
                "sub_secrets" => ("[>] SECRET", th().primary),
                "sub_sast" => ("[>] SAST", th().primary),
                "sub_sca" => ("[>] SCA", th().primary),
                "sub_net" => ("[>] NET", th().primary),
                "sub_malware" => ("[!] MALWARE", th().destructive),
                "sub_apk" => ("[#] APK", th().secondary),
                "sub_patcher" => ("[!] PATCH", th().destructive),
                "sub_verifier" => ("[✓] VERIFY", th().success),
                _ => ("[>] AGENT", th().primary),
            },
            _ => ("[>] TASK", th().info),
        };

        // 3. Border styling
        let border_color = if ctx.selected {
            th().info
        } else if self.is_paused {
            Color::Rgb(120, 120, 120)
        } else if self.status == AgentStatus::Running {
            th().primary
        } else if self.status == AgentStatus::Failed || self.findings_count > 0 {
            th().destructive
        } else if self.status == AgentStatus::Success {
            th().success
        } else {
            th().border
        };

        let mut border_style = Style::default().fg(border_color);
        if ctx.selected {
            border_style = border_style.add_modifier(Modifier::BOLD);
        }

        let mut block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(border_style)
            .title_top(Line::from(vec![
                Span::styled(format!(" {} ", tag), Style::default().fg(tag_color).add_modifier(Modifier::BOLD)),
            ]));

        if ctx.selected {
            let action_hint = if self.is_paused {
                "[Space: resume]"
            } else {
                "[Space: pause]"
            };
            block = block.title_bottom(Line::from(vec![
                Span::styled(format!(" {} ", action_hint), Style::default().fg(th().info).add_modifier(Modifier::BOLD)),
            ]));
        }

        let inner = block.inner(ctx.area);
        block.render(ctx.area, buf);

        if inner.height == 0 || inner.width < 4 {
            return;
        }

        let content_x = inner.x + 1;
        let avail_w = (inner.width as usize).saturating_sub(2);

        // 4. Row 0: Title text
        let title_style = if ctx.selected {
            Style::default().fg(th().fg).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(th().text)
        };
        let title_truncated = if self.title.len() > avail_w {
            format!("{}...", &self.title[..avail_w.saturating_sub(3)])
        } else {
            self.title.clone()
        };
        buf.set_string(content_x, inner.y, &title_truncated, title_style);

        // 5. Row 1: Subtitle / Scope description
        if inner.height > 1 {
            let sub_style = Style::default().fg(th().text_muted);
            let sub_truncated = if self.subtitle.len() > avail_w {
                format!("{}...", &self.subtitle[..avail_w.saturating_sub(3)])
            } else {
                self.subtitle.clone()
            };
            buf.set_string(content_x, inner.y + 1, &sub_truncated, sub_style);
        }

        // 6. Row 2: Status pill + findings count badge
        if inner.height > 2 {
            let spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let spinner_idx = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                / 80) as usize
                % spinner_frames.len();
            let spinner = spinner_frames[spinner_idx];

            let running_str = format!("{spinner} RUNNING");
            let planning_str = format!("{spinner} PLAN");

            let (status_text, status_fg, status_bg, is_bold) = if self.is_paused {
                ("■ PAUSED", th().text_sub, th().element_hi, false)
            } else {
                match self.status {
                    AgentStatus::Idle => ("○ IDLE", th().text_muted, th().element, false),
                    AgentStatus::Planning => (planning_str.as_str(), th().primary, th().primary_bg, true),
                    AgentStatus::WaitingConfirmation => ("▲ CONFIRM", th().warning, th().warning_bg, true),
                    AgentStatus::Running => (running_str.as_str(), th().info, th().primary_bg, true),
                    AgentStatus::Paused => ("■ PAUSED", th().text_sub, th().element_hi, false),
                    AgentStatus::Adapting => ("◈ ADAPTING", th().secondary, th().secondary_bg, true),
                    AgentStatus::Success => ("✓ PASSED", th().success, th().success_bg, true),
                    AgentStatus::Failed => ("✗ ALERT", th().destructive, th().destructive_bg, true),
                }
            };

            let mut status_style = Style::default().fg(status_fg).bg(status_bg);
            if is_bold {
                status_style = status_style.add_modifier(Modifier::BOLD);
            }

            let status_span = Span::styled(format!(" {} ", status_text), status_style);
            let mut line_spans = vec![status_span];

            if self.findings_count > 0 {
                line_spans.push(Span::raw(" "));
                line_spans.push(Span::styled(
                    format!(" !{} VULN ", self.findings_count),
                    Style::default().fg(th().fg).bg(th().destructive).add_modifier(Modifier::BOLD),
                ));
            } else if self.status == AgentStatus::Success {
                line_spans.push(Span::raw(" "));
                line_spans.push(Span::styled(
                    " ✓ CLEAN ",
                    Style::default().fg(th().success).bg(th().element),
                ));
            }

            let line = Line::from(line_spans);
            buf.set_line(content_x, inner.y + 2, &line, avail_w as u16);
        }
    }
}

pub struct AgentGraphBuilder;

impl AgentGraphBuilder {
    pub fn build_nodes_for_workspace(target_path: &Path) -> HashMap<String, SproutedNodeInfo> {
        let mut map = HashMap::new();

        // 1. Root Orchestrator
        map.insert(
            "orch".to_string(),
            SproutedNodeInfo {
                id: "orch".to_string(),
                label: "Orchestrator\nautonomous threat planner".to_string(),
                tier: "planner".to_string(),
                target_path: None,
                status: AgentStatus::Idle,
                details: "autonomous strategy planner & threat modeler".to_string(),
                findings_count: 0,
                is_paused: false,
            },
        );

        // 2. Scan actual directories and source files (up to depth 2)
        let mut discovered_folders = Vec::new();
        let mut discovered_files = Vec::new();

        for entry in WalkDir::new(target_path)
            .max_depth(2)
            .into_iter()
            .filter_entry(|e| {
                if e.path() == target_path {
                    return true;
                }
                let name = e.file_name().to_string_lossy();
                !name.starts_with('.')
                    && name != "target"
                    && name != "node_modules"
                    && name != "vendor"
                    && name != "reference"
                    && name != "fixtures"
            })
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path == target_path {
                continue;
            }

            let rel_path = path.strip_prefix(target_path).unwrap_or(path);
            let rel_str = rel_path.to_string_lossy().to_string();

            if entry.file_type().is_dir() && discovered_folders.len() < 4 {
                discovered_folders.push(rel_str);
            } else if entry.file_type().is_file() && discovered_files.len() < 4 {
                discovered_files.push(rel_str);
            }
        }

        // If no subfolders found, add root project folder
        if discovered_folders.is_empty() {
            discovered_folders.push("root/".to_string());
        }

        for (idx, folder) in discovered_folders.iter().enumerate() {
            let id = format!("folder_{idx}");
            map.insert(
                id.clone(),
                SproutedNodeInfo {
                    id,
                    label: format!("{folder}\ndirectory scope"),
                    tier: "folder".to_string(),
                    target_path: Some(folder.clone()),
                    status: AgentStatus::Idle,
                    details: format!("directory scope: {folder}"),
                    findings_count: 0,
                    is_paused: false,
                },
            );
        }

        for (idx, file) in discovered_files.iter().enumerate() {
            let id = format!("file_{idx}");
            map.insert(
                id.clone(),
                SproutedNodeInfo {
                    id: id.clone(),
                    label: format!("{file}\ntarget source file"),
                    tier: "file".to_string(),
                    target_path: Some(file.clone()),
                    status: AgentStatus::Idle,
                    details: format!("target source file: {file}"),
                    findings_count: 0,
                    is_paused: false,
                },
            );

        }

        // 3. Real Security Analysis Modules
        map.insert(
            "sub_secrets".to_string(),
            SproutedNodeInfo {
                id: "sub_secrets".to_string(),
                label: "Secret Hunter\nentropy & git scan".to_string(),
                tier: "subagent".to_string(),
                target_path: None,
                status: AgentStatus::Idle,
                details: "scans commit history & source files for high-entropy secrets and API keys".to_string(),
                findings_count: 0,
                is_paused: false,
            },
        );

        map.insert(
            "sub_sast".to_string(),
            SproutedNodeInfo {
                id: "sub_sast".to_string(),
                label: "AST Code Guard\ntaint flow analysis".to_string(),
                tier: "subagent".to_string(),
                target_path: None,
                status: AgentStatus::Idle,
                details: "static syntax & dataflow analysis from sources to sensitive sinks".to_string(),
                findings_count: 0,
                is_paused: false,
            },
        );

        map.insert(
            "sub_net".to_string(),
            SproutedNodeInfo {
                id: "sub_net".to_string(),
                label: "Surface Linter\nnetwork & transport".to_string(),
                tier: "subagent".to_string(),
                target_path: None,
                status: AgentStatus::Idle,
                details: "detects 0.0.0.0 binds, CORS wildcards, and unencrypted transports".to_string(),
                findings_count: 0,
                is_paused: false,
            },
        );

        map.insert(
            "sub_sca".to_string(),
            SproutedNodeInfo {
                id: "sub_sca".to_string(),
                label: "Dependency Guard\nphantom sca audit".to_string(),
                tier: "subagent".to_string(),
                target_path: None,
                status: AgentStatus::Idle,
                details: "audits package manifests and identifies phantom unpinned dependencies".to_string(),
                findings_count: 0,
                is_paused: false,
            },
        );

        // 3. Remediation, Verification & Gate
        map.insert(
            "sub_patcher".to_string(),
            SproutedNodeInfo {
                id: "sub_patcher".to_string(),
                label: "Remediation Engine\nauto-hardening patch".to_string(),
                tier: "subagent".to_string(),
                target_path: None,
                status: AgentStatus::Idle,
                details: "synthesizes non-breaking code patches in worktree".to_string(),
                findings_count: 0,
                is_paused: false,
            },
        );

        map.insert(
            "sub_verifier".to_string(),
            SproutedNodeInfo {
                id: "sub_verifier".to_string(),
                label: "Test Verifier\nsandbox unit tests".to_string(),
                tier: "subagent".to_string(),
                target_path: None,
                status: AgentStatus::Idle,
                details: "executes security verification tests in sandbox".to_string(),
                findings_count: 0,
                is_paused: false,
            },
        );

        map.insert(
            "defense_gate".to_string(),
            SproutedNodeInfo {
                id: "defense_gate".to_string(),
                label: "Pre-Prod Defense Gate\nbuild certification".to_string(),
                tier: "gate".to_string(),
                target_path: None,
                status: AgentStatus::Idle,
                details: "certifies security posture prior to production build".to_string(),
                findings_count: 0,
                is_paused: false,
            },
        );

        map
    }

    #[allow(dead_code)]
    pub fn default_nodes_map() -> HashMap<String, SproutedNodeInfo> {
        Self::build_nodes_for_workspace(Path::new("."))
    }

    #[allow(dead_code)]
    pub fn build_sprouted_graph(
        nodes_info: &HashMap<String, SproutedNodeInfo>,
    ) -> Result<Flow<AgentNodeContent, StepEdge>, rataflow::Error> {
        let mut nodes = Vec::new();

        // Categorize into horizontal columns
        let mut folder_nodes: Vec<&SproutedNodeInfo> = Vec::new();
        let mut file_nodes: Vec<&SproutedNodeInfo> = Vec::new();
        let mut subagent_nodes: Vec<&SproutedNodeInfo> = Vec::new();

        for n in nodes_info.values() {
            if n.tier == "folder" {
                folder_nodes.push(n);
            } else if n.tier == "file" {
                file_nodes.push(n);
            } else if n.tier == "subagent" && !n.id.starts_with("sub_patcher") && !n.id.starts_with("sub_verifier") {
                subagent_nodes.push(n);
            }
        }

        folder_nodes.sort_by_key(|n| &n.id);
        file_nodes.sort_by_key(|n| &n.id);
        subagent_nodes.sort_by_key(|n| &n.id);

        let mut layout_coords: Vec<(String, (f64, f64), String)> = Vec::new();

        // Column 0: Orchestrator (x = 2.0, y = 13.0)
        let orch_label = nodes_info
            .get("orch")
            .map(|n| n.label.clone())
            .unwrap_or_else(|| "Orchestrator\nautonomous threat planner".to_string());
        layout_coords.push(("orch".to_string(), (2.0, 13.0), orch_label));

        // Column 1: Folders (x = 36.0, gap = 8.0)
        let folder_count = folder_nodes.len().max(1);
        let folder_gap = 24.0 / (folder_count as f64);
        for (i, f) in folder_nodes.iter().enumerate() {
            let y = if folder_count == 1 {
                13.0
            } else {
                2.0 + (i as f64) * folder_gap
            };
            layout_coords.push((f.id.clone(), (36.0, y), f.label.clone()));
        }

        // Column 2: Files (x = 70.0, gap = 8.0)
        let file_count = file_nodes.len().max(1);
        let file_gap = 24.0 / (file_count as f64);
        for (i, f) in file_nodes.iter().enumerate() {
            let y = if file_count == 1 {
                13.0
            } else {
                2.0 + (i as f64) * file_gap
            };
            layout_coords.push((f.id.clone(), (70.0, y), f.label.clone()));
        }

        // Column 3: Review Modules (x = 104.0, gap = 8.0)
        let sub_count = subagent_nodes.len().max(1);
        let sub_gap = 26.0 / (sub_count as f64);
        for (i, s) in subagent_nodes.iter().enumerate() {
            let y = if sub_count == 1 {
                13.0
            } else {
                2.0 + (i as f64) * sub_gap
            };
            layout_coords.push((s.id.clone(), (104.0, y), s.label.clone()));
        }

        // Column 4: Remediation & Verification (x = 138.0, gap = 8.0)
        let patcher_label = nodes_info
            .get("sub_patcher")
            .map(|n| n.label.clone())
            .unwrap_or_else(|| "Remediation Engine\nauto-hardening patch".to_string());
        let verifier_label = nodes_info
            .get("sub_verifier")
            .map(|n| n.label.clone())
            .unwrap_or_else(|| "Test Verifier\nsandbox unit tests".to_string());
        layout_coords.push(("sub_patcher".to_string(), (138.0, 8.0), patcher_label));
        layout_coords.push(("sub_verifier".to_string(), (138.0, 18.0), verifier_label));

        // Column 5: Defense Gate (x = 172.0, gap = 8.0)
        let gate_label = nodes_info
            .get("defense_gate")
            .map(|n| n.label.clone())
            .unwrap_or_else(|| "Pre-Prod Defense Gate\nbuild certification".to_string());
        layout_coords.push(("defense_gate".to_string(), (172.0, 13.0), gate_label));

        for (id, pos, label) in &layout_coords {
            let default_info = SproutedNodeInfo {
                id: id.clone(),
                label: label.clone(),
                tier: "worker".to_string(),
                target_path: None,
                status: AgentStatus::Idle,
                details: String::new(),
                findings_count: 0,
                is_paused: false,
            };

            let info = nodes_info.get(id).unwrap_or(&default_info);

            let (title, subtitle) = if let Some((t, s)) = label.split_once('\n') {
                (t.trim().to_string(), s.trim().to_string())
            } else {
                (label.clone(), String::new())
            };

            let content = AgentNodeContent {
                id: id.clone(),
                title,
                subtitle,
                tier: info.tier.clone(),
                status: info.status,
                is_paused: info.is_paused,
                findings_count: info.findings_count,
            };

            let node = Node::new(id.clone(), *pos, (26.0, 5.0), content);
            nodes.push(node);
        }

        // Horizontal Edges
        let mut edges: Vec<Edge<StepEdge>> = Vec::new();

        // 1. Orch -> Folders
        for f in &folder_nodes {
            edges.push(create_step_edge(&format!("e_orch_{}", f.id), "orch", &f.id, nodes_info));
        }

        // 2. Folders -> Files
        for (i, file) in file_nodes.iter().enumerate() {
            if let Some(folder) = folder_nodes.get(i % folder_nodes.len().max(1)) {
                edges.push(create_step_edge(&format!("e_fold_{}", file.id), &folder.id, &file.id, nodes_info));
            }
        }

        // 3. Files -> Subagents
        for (i, sub) in subagent_nodes.iter().enumerate() {
            if let Some(file) = file_nodes.get(i % file_nodes.len().max(1)) {
                edges.push(create_step_edge(&format!("e_file_{}", sub.id), &file.id, &sub.id, nodes_info));
            }
            // 4. Subagents -> Patcher
            edges.push(create_step_edge(&format!("e_sub_patch_{}", sub.id), &sub.id, "sub_patcher", nodes_info));
        }

        // 5. Patcher -> Verifier -> Gate
        edges.push(create_step_edge("e_patch_verify", "sub_patcher", "sub_verifier", nodes_info));
        edges.push(create_step_edge("e_verify_gate", "sub_verifier", "defense_gate", nodes_info));

        let mut flow = Flow::with_graph(nodes, edges)?;
        flow.request_fit_view();
        Ok(flow)
    }

    pub fn build_from_workflow_plan(
        plan: &WorkflowPlan,
        nodes_info: &mut HashMap<String, SproutedNodeInfo>,
    ) -> Result<Flow<AgentNodeContent, StepEdge>, rataflow::Error> {
        nodes_info.clear();

        // 1. Root Orchestrator
        nodes_info.insert(
            "orch".to_string(),
            SproutedNodeInfo {
                id: "orch".to_string(),
                label: "Orchestrator\nautonomous threat planner".to_string(),
                tier: "planner".to_string(),
                target_path: None,
                status: AgentStatus::WaitingConfirmation,
                details: if plan.target_summary.is_empty() {
                    format!("Workflow: {}", plan.workflow_name)
                } else {
                    format!("Workflow: {} | {}", plan.workflow_name, plan.target_summary)
                },
                findings_count: 0,
                is_paused: false,
            },
        );

        // 2. Task nodes from AI plan
        for task in &plan.nodes {
            let label = if task.subtitle.is_empty() {
                task.title.clone()
            } else {
                format!("{}\n{}", task.title, task.subtitle)
            };
            let target_str = if task.targets.is_empty() {
                None
            } else {
                Some(task.targets.join(", "))
            };
            nodes_info.insert(
                task.id.clone(),
                SproutedNodeInfo {
                    id: task.id.clone(),
                    label,
                    tier: task.tier.clone(),
                    target_path: target_str,
                    status: AgentStatus::Idle,
                    details: task.description.clone(),
                    findings_count: 0,
                    is_paused: false,
                },
            );
        }

        // 3. Defense Gate
        nodes_info.insert(
            "defense_gate".to_string(),
            SproutedNodeInfo {
                id: "defense_gate".to_string(),
                label: "Pre-Prod Defense Gate\nbuild certification".to_string(),
                tier: "gate".to_string(),
                target_path: None,
                status: AgentStatus::Idle,
                details: "certifies security posture prior to production build".to_string(),
                findings_count: 0,
                is_paused: false,
            },
        );

        // Compute topological layers for branching layout
        let mut node_layer: HashMap<String, usize> = HashMap::new();
        for _ in 0..plan.nodes.len().max(1) {
            for task in &plan.nodes {
                let current_max_dep = task
                    .depends_on
                    .iter()
                    .filter_map(|dep| node_layer.get(dep).copied())
                    .max()
                    .unwrap_or(0);
                node_layer.insert(task.id.clone(), current_max_dep + 1);
            }
        }

        let mut layers: std::collections::BTreeMap<usize, Vec<&WorkflowTaskNode>> = std::collections::BTreeMap::new();
        for task in &plan.nodes {
            let l = node_layer.get(&task.id).copied().unwrap_or(1);
            layers.entry(l).or_default().push(task);
        }

        // Construct nodes with positions
        let mut nodes = Vec::new();

        // Orch at (4.0, 14.0)
        let orch_content = AgentNodeContent {
            id: "orch".to_string(),
            title: "Orchestrator".to_string(),
            subtitle: "autonomous threat planner".to_string(),
            tier: "planner".to_string(),
            status: AgentStatus::WaitingConfirmation,
            is_paused: false,
            findings_count: 0,
        };
        nodes.push(Node::new("orch".to_string(), (4.0, 14.0), (26.0, 5.0), orch_content));

        // Layout layers: each layer column is at x = 4.0 + layer * 36.0
        // Vertically distribute parallel branches around y = 14.0!
        for (layer_idx, tasks_in_layer) in &layers {
            let col_x = 4.0 + (*layer_idx as f64) * 36.0;
            let count = tasks_in_layer.len();
            let spacing = 7.0;
            let start_y = 14.0 - ((count as f64 - 1.0) * spacing) / 2.0;

            for (idx, task) in tasks_in_layer.iter().enumerate() {
                let y = (start_y + (idx as f64) * spacing).max(2.0);
                let content = AgentNodeContent {
                    id: task.id.clone(),
                    title: task.title.clone(),
                    subtitle: task.subtitle.clone(),
                    tier: task.tier.clone(),
                    status: AgentStatus::Idle,
                    is_paused: false,
                    findings_count: 0,
                };
                nodes.push(Node::new(task.id.clone(), (col_x, y), (26.0, 5.0), content));
            }
        }

        // Gate at the end
        let max_layer = layers.keys().max().copied().unwrap_or(1);
        let gate_x = 4.0 + ((max_layer + 1) as f64) * 36.0;
        let gate_content = AgentNodeContent {
            id: "defense_gate".to_string(),
            title: "Pre-Prod Defense Gate".to_string(),
            subtitle: "build certification".to_string(),
            tier: "gate".to_string(),
            status: AgentStatus::Idle,
            is_paused: false,
            findings_count: 0,
        };
        nodes.push(Node::new("defense_gate".to_string(), (gate_x, 14.0), (26.0, 5.0), gate_content));

        let mut flow = Flow::with_graph(nodes, Vec::new())?;
        flow.animation_speed_ms = 80;
        Self::rechain_workflow_edges(&mut flow, nodes_info);
        flow.request_fit_view();
        Ok(flow)
    }

    pub fn remove_workflow_node(
        flow: &mut Flow<AgentNodeContent, StepEdge>,
        nodes_info: &mut HashMap<String, SproutedNodeInfo>,
        node_id: &str,
    ) -> bool {
        if node_id == "orch" || node_id == "defense_gate" {
            return false;
        }
        let removed = flow.remove_node(node_id).is_some();
        if removed {
            nodes_info.remove(node_id);
            Self::rechain_workflow_edges(flow, nodes_info);
        }
        removed
    }

    pub fn shift_node(
        flow: &mut Flow<AgentNodeContent, StepEdge>,
        nodes_info: &HashMap<String, SproutedNodeInfo>,
        node_id: &str,
        delta_x: f64,
        delta_y: f64,
    ) {
        if node_id == "orch" || node_id == "defense_gate" {
            return;
        }
        flow.move_node(node_id, (delta_x, delta_y));
        Self::rechain_workflow_edges(flow, nodes_info);
    }

    #[allow(dead_code)]
    pub fn shift_node_x(
        flow: &mut Flow<AgentNodeContent, StepEdge>,
        nodes_info: &HashMap<String, SproutedNodeInfo>,
        node_id: &str,
        delta_x: f64,
    ) {
        Self::shift_node(flow, nodes_info, node_id, delta_x, 0.0);
    }

    /// Sprouts a dedicated Fixing / Auto-Hardening Remediation workflow directly below the Scan workflow.
    /// Start Point: `fix_orch` (Remediation Orchestrator)
    /// Stages: `fix_rewrite` (AST Code Rewriter) -> `fix_add_code` (Security Guard Injection) ->
    ///         `fix_exec` (Sandbox Command Exec) -> `fix_verify` (Regression Verifier)
    /// Endpoint: `fix_gate` (Production Release Gate)
    pub fn append_fixing_workflow(
        flow: &mut Flow<AgentNodeContent, StepEdge>,
        nodes_info: &mut HashMap<String, SproutedNodeInfo>,
        actionable_count: usize,
    ) {
        if flow.node("fix_orch").is_some() {
            return;
        }

        let fix_y = 26.0;

        // 1. New Start Point: Remediation Orchestrator
        let fix_orch_content = AgentNodeContent {
            id: "fix_orch".to_string(),
            title: "Remediation Orchestrator".to_string(),
            subtitle: "auto-hardening planner".to_string(),
            tier: "remediator".to_string(),
            status: AgentStatus::Running,
            is_paused: false,
            findings_count: actionable_count,
        };
        nodes_info.insert(
            "fix_orch".to_string(),
            SproutedNodeInfo {
                id: "fix_orch".to_string(),
                label: "Remediation Orchestrator\nauto-hardening planner".to_string(),
                tier: "remediator".to_string(),
                target_path: None,
                status: AgentStatus::Running,
                details: format!("Coordinates autonomous code repair and verification across {actionable_count} actionable findings."),
                findings_count: actionable_count,
                is_paused: false,
            },
        );
        let _ = flow.add_node(Node::new("fix_orch".to_string(), (4.0, fix_y), (26.0, 5.0), fix_orch_content));

        // 2. Fixing Step 1: AST Code Rewriter ("rewrite")
        let rewrite_content = AgentNodeContent {
            id: "fix_rewrite".to_string(),
            title: "AST Code Rewriter".to_string(),
            subtitle: "sink taint remediation".to_string(),
            tier: "rewriter".to_string(),
            status: AgentStatus::Idle,
            is_paused: false,
            findings_count: actionable_count,
        };
        nodes_info.insert(
            "fix_rewrite".to_string(),
            SproutedNodeInfo {
                id: "fix_rewrite".to_string(),
                label: "AST Code Rewriter\nsink taint remediation".to_string(),
                tier: "rewriter".to_string(),
                target_path: None,
                status: AgentStatus::Idle,
                details: "Rewrites vulnerable syntax trees, escapes tainted inputs, and replaces insecure APIs.".to_string(),
                findings_count: actionable_count,
                is_paused: false,
            },
        );
        let _ = flow.add_node(Node::new("fix_rewrite".to_string(), (40.0, fix_y), (26.0, 5.0), rewrite_content));

        // 3. Fixing Step 2: Security Guard Injection ("add code")
        let add_code_content = AgentNodeContent {
            id: "fix_add_code".to_string(),
            title: "Security Guard Injection".to_string(),
            subtitle: "auth & input boundaries".to_string(),
            tier: "injector".to_string(),
            status: AgentStatus::Idle,
            is_paused: false,
            findings_count: 0,
        };
        nodes_info.insert(
            "fix_add_code".to_string(),
            SproutedNodeInfo {
                id: "fix_add_code".to_string(),
                label: "Security Guard Injection\nauth & input boundaries".to_string(),
                tier: "injector".to_string(),
                target_path: None,
                status: AgentStatus::Idle,
                details: "Injects runtime parameter validation, boundary sanitization, and defensive guards.".to_string(),
                findings_count: 0,
                is_paused: false,
            },
        );
        let _ = flow.add_node(Node::new("fix_add_code".to_string(), (76.0, fix_y), (26.0, 5.0), add_code_content));

        // 4. Fixing Step 3: Sandbox Command Exec ("execute commands dll")
        let exec_content = AgentNodeContent {
            id: "fix_exec".to_string(),
            title: "Sandbox Command Exec".to_string(),
            subtitle: "isolated build & test run".to_string(),
            tier: "executor".to_string(),
            status: AgentStatus::Idle,
            is_paused: false,
            findings_count: 0,
        };
        nodes_info.insert(
            "fix_exec".to_string(),
            SproutedNodeInfo {
                id: "fix_exec".to_string(),
                label: "Sandbox Command Exec\nisolated build & test run".to_string(),
                tier: "executor".to_string(),
                target_path: None,
                status: AgentStatus::Idle,
                details: "Executes build commands (cargo test, npm test, linters) in isolated worktree sandbox.".to_string(),
                findings_count: 0,
                is_paused: false,
            },
        );
        let _ = flow.add_node(Node::new("fix_exec".to_string(), (112.0, fix_y), (26.0, 5.0), exec_content));

        // 5. Fixing Step 4: Regression Verifier
        let verify_content = AgentNodeContent {
            id: "fix_verify".to_string(),
            title: "Regression Verifier".to_string(),
            subtitle: "zero-leak verification".to_string(),
            tier: "verifier".to_string(),
            status: AgentStatus::Idle,
            is_paused: false,
            findings_count: 0,
        };
        nodes_info.insert(
            "fix_verify".to_string(),
            SproutedNodeInfo {
                id: "fix_verify".to_string(),
                label: "Regression Verifier\nzero-leak verification".to_string(),
                tier: "verifier".to_string(),
                target_path: None,
                status: AgentStatus::Idle,
                details: "Re-verifies reachability graph and confirms patches introduced zero security side-effects.".to_string(),
                findings_count: 0,
                is_paused: false,
            },
        );
        let _ = flow.add_node(Node::new("fix_verify".to_string(), (148.0, fix_y), (26.0, 5.0), verify_content));

        // 6. New Endpoint: Production Release Gate
        let fix_gate_content = AgentNodeContent {
            id: "fix_gate".to_string(),
            title: "Production Release Gate".to_string(),
            subtitle: "hardened certification".to_string(),
            tier: "release_gate".to_string(),
            status: AgentStatus::Idle,
            is_paused: false,
            findings_count: 0,
        };
        nodes_info.insert(
            "fix_gate".to_string(),
            SproutedNodeInfo {
                id: "fix_gate".to_string(),
                label: "Production Release Gate\nhardened certification".to_string(),
                tier: "release_gate".to_string(),
                target_path: None,
                status: AgentStatus::Idle,
                details: "Certifies codebase is hardened, tests pass, and ready for production deployment.".to_string(),
                findings_count: 0,
                is_paused: false,
            },
        );
        let _ = flow.add_node(Node::new("fix_gate".to_string(), (184.0, fix_y), (26.0, 5.0), fix_gate_content));

        Self::rechain_workflow_edges(flow, nodes_info);
    }

    pub fn rechain_workflow_edges(
        flow: &mut Flow<AgentNodeContent, StepEdge>,
        nodes_info: &HashMap<String, SproutedNodeInfo>,
    ) {
        let mut new_edges = Vec::new();

        // ----------------------------------------------------
        // 1. Scan Workflow Pipeline (Row 1: y around 14.0)
        // ----------------------------------------------------
        let scan_tasks: Vec<(String, f64, f64)> = flow
            .nodes()
            .filter(|n| n.id != "orch" && n.id != "defense_gate" && !n.id.starts_with("fix_"))
            .map(|n| (n.id.clone(), n.position.x, n.position.y))
            .collect();

        if scan_tasks.is_empty() {
            if flow.node("orch").is_some() && flow.node("defense_gate").is_some() {
                new_edges.push(create_step_edge("e_orch_gate", "orch", "defense_gate", nodes_info));
            }
        } else {
            let mut sorted_scan = scan_tasks.clone();
            sorted_scan.sort_by(|a, b| {
                a.1.partial_cmp(&b.1)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then(a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal))
            });

            // orch -> scan[0]
            if flow.node("orch").is_some() {
                new_edges.push(create_step_edge(
                    &format!("e_orch_{}", sorted_scan[0].0),
                    "orch",
                    &sorted_scan[0].0,
                    nodes_info,
                ));
            }

            // scan[i] -> scan[i+1]
            for i in 0..sorted_scan.len() - 1 {
                let from_id = &sorted_scan[i].0;
                let to_id = &sorted_scan[i + 1].0;
                new_edges.push(create_step_edge(
                    &format!("e_{from_id}_{to_id}"),
                    from_id,
                    to_id,
                    nodes_info,
                ));
            }

            // scan.last() -> defense_gate
            if flow.node("defense_gate").is_some() {
                let last_id = &sorted_scan.last().unwrap().0;
                new_edges.push(create_step_edge(
                    &format!("e_{last_id}_gate"),
                    last_id,
                    "defense_gate",
                    nodes_info,
                ));
            }
        }

        // ----------------------------------------------------
        // 2. Fixing / Auto-Hardening Pipeline (Row 2: y around 26.0)
        // ----------------------------------------------------
        if flow.node("fix_orch").is_some() {
            let fix_tasks: Vec<(String, f64, f64)> = flow
                .nodes()
                .filter(|n| n.id.starts_with("fix_") && n.id != "fix_orch" && n.id != "fix_gate")
                .map(|n| (n.id.clone(), n.position.x, n.position.y))
                .collect();

            if fix_tasks.is_empty() {
                if flow.node("fix_gate").is_some() {
                    new_edges.push(create_step_edge("e_fix_orch_gate", "fix_orch", "fix_gate", nodes_info));
                }
            } else {
                let mut sorted_fix = fix_tasks.clone();
                sorted_fix.sort_by(|a, b| {
                    a.1.partial_cmp(&b.1)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then(a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal))
                });

                // fix_orch -> fix[0]
                new_edges.push(create_step_edge(
                    &format!("e_fix_orch_{}", sorted_fix[0].0),
                    "fix_orch",
                    &sorted_fix[0].0,
                    nodes_info,
                ));

                // fix[i] -> fix[i+1]
                for i in 0..sorted_fix.len() - 1 {
                    let from_id = &sorted_fix[i].0;
                    let to_id = &sorted_fix[i + 1].0;
                    new_edges.push(create_step_edge(
                        &format!("e_{from_id}_{to_id}"),
                        from_id,
                        to_id,
                        nodes_info,
                    ));
                }

                // fix.last() -> fix_gate
                if flow.node("fix_gate").is_some() {
                    let last_id = &sorted_fix.last().unwrap().0;
                    new_edges.push(create_step_edge(
                        &format!("e_{last_id}_fix_gate"),
                        last_id,
                        "fix_gate",
                        nodes_info,
                    ));
                }
            }
        }

        let _ = flow.set_edges(new_edges);
    }
}

fn create_step_edge(
    edge_id: &str,
    src: &str,
    dst: &str,
    nodes_info: &HashMap<String, SproutedNodeInfo>,
) -> Edge<StepEdge> {
    let src_info = nodes_info.get(src);
    let dst_info = nodes_info.get(dst);

    let src_status = src_info.map(|n| (n.status, n.is_paused));
    let dst_status = dst_info.map(|n| (n.status, n.is_paused));

    let is_paused_edge = match (src_status, dst_status) {
        (Some((_, true)), _) | (_, Some((_, true))) => true,
        (Some((AgentStatus::Paused, _)), _) | (_, Some((AgentStatus::Paused, _))) => true,
        _ => false,
    };

    let is_animating = if is_paused_edge {
        false // Stop animation completely when paused!
    } else {
        match (src_status, dst_status) {
            (Some((AgentStatus::Running, false)), _) => true,
            (_, Some((AgentStatus::Running, false))) => true,
            _ => false,
        }
    };

    let is_failed = match (src_status, dst_status) {
        (Some((AgentStatus::Failed, _)), _) => true,
        (_, Some((AgentStatus::Failed, _))) => true,
        _ => false,
    };

    let is_success = match (src_status, dst_status) {
        (Some((AgentStatus::Success, _)), Some((AgentStatus::Success, _))) => true,
        _ => false,
    };

    let stroke_color = if is_paused_edge {
        Color::Rgb(120, 120, 120) // Gray (abu-abu)!
    } else if is_failed {
        th().destructive
    } else if is_animating {
        th().info
    } else if is_success {
        th().success
    } else {
        th().border
    };

    let style = EdgeStyle::default()
        .with_stroke_style(Style::default().fg(stroke_color))
        .with_marker_end(EdgeMarker::ArrowClosed);

    Edge::new(edge_id.to_string(), src.to_string(), dst.to_string())
        .with_content(StepEdge::default().with_style(style).with_stem_length(2.0))
        .with_animated(is_animating)
}
