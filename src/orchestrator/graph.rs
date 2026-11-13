use crate::ui::theme::th;
use crate::types::{AgentStatus, SproutedNodeInfo};
use rataflow::{
    Edge, EdgeMarker, EdgeStyle, Flow, Node, NodeContent, NodeRenderContext, StepEdge,
};
use ratatui::{
    buffer::Buffer,
    style::{Modifier, Style},
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
            "subagent" => match self.id.as_str() {
                "sub_secrets" => ("[>] SECRET", th().primary),
                "sub_sast" => ("[>] SAST", th().primary),
                "sub_sca" => ("[>] SCA", th().primary),
                "sub_net" => ("[>] NET", th().primary),
                "sub_patcher" => ("[!] PATCH", th().destructive),
                "sub_verifier" => ("[✓] VERIFY", th().success),
                _ => ("[>] AGENT", th().primary),
            },
            "gate" => ("[#] GATE", th().warning),
            _ => ("[*] NODE", th().text_sub),
        };

        // 3. Border styling
        let border_color = if ctx.selected {
            th().info
        } else if self.is_paused {
            th().border
        } else if self.status == AgentStatus::Running {
            th().primary
        } else if self.findings_count > 0 {
            th().destructive
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
            let (status_text, status_fg, status_bg, is_bold) = if self.is_paused {
                ("■ PAUSED", th().text_sub, th().element_hi, false)
            } else {
                match self.status {
                    AgentStatus::Idle => ("○ IDLE", th().text_muted, th().element, false),
                    AgentStatus::Planning => ("◐ PLAN", th().primary, th().primary_bg, true),
                    AgentStatus::WaitingConfirmation => ("▲ CONFIRM", th().warning, th().warning_bg, true),
                    AgentStatus::Running => ("● RUNNING", th().info, th().primary_bg, true),
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
}

fn create_step_edge(
    edge_id: &str,
    src: &str,
    dst: &str,
    nodes_info: &HashMap<String, SproutedNodeInfo>,
) -> Edge<StepEdge> {
    let src_status = nodes_info.get(src).map(|n| (n.status, n.is_paused));
    let dst_status = nodes_info.get(dst).map(|n| (n.status, n.is_paused));

    let is_animating = match (src_status, dst_status) {
        (Some((AgentStatus::Running, false)), _) => true,
        (_, Some((AgentStatus::Running, false))) => true,
        _ => false,
    };

    let is_success = match (src_status, dst_status) {
        (Some((AgentStatus::Success, _)), Some((AgentStatus::Success, _))) => true,
        _ => false,
    };

    let stroke_color = if is_animating {
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
