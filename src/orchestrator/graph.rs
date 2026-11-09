use crate::types::{AgentStatus, SproutedNodeInfo};
use rataflow::{Edge, Flow, Node, StepEdge, TextContent};
use ratatui::style::{Color, Modifier, Style};
use std::collections::HashMap;
use std::path::Path;
use walkdir::WalkDir;

pub struct AgentGraphBuilder;

impl AgentGraphBuilder {
    pub fn build_nodes_for_workspace(target_path: &Path) -> HashMap<String, SproutedNodeInfo> {
        let mut map = HashMap::new();

        // 1. Root Orchestrator
        map.insert(
            "orch".to_string(),
            SproutedNodeInfo {
                id: "orch".to_string(),
                label: "orchestrator\ncore planner".to_string(),
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
                let name = e.file_name().to_string_lossy();
                !name.starts_with('.') && name != "target" && name != "node_modules" && name != "vendor"
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
                    label: format!("folder\n{folder}"),
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
                    label: format!("file\n{file}"),
                    tier: "file".to_string(),
                    target_path: Some(file.clone()),
                    status: AgentStatus::Idle,
                    details: format!("target source file: {file}"),
                    findings_count: 0,
                    is_paused: false,
                },
            );

            // Active review module for this real file
            let sec_id = format!("sub_sec_{idx}");
            map.insert(
                sec_id.clone(),
                SproutedNodeInfo {
                    id: sec_id,
                    label: format!("secret scanner\n[{file}]"),
                    tier: "subagent".to_string(),
                    target_path: Some(file.clone()),
                    status: AgentStatus::Idle,
                    details: format!("credential audit on {file}"),
                    findings_count: 0,
                    is_paused: false,
                },
            );

            let sast_id = format!("sub_sast_{idx}");
            map.insert(
                sast_id.clone(),
                SproutedNodeInfo {
                    id: sast_id,
                    label: format!("sast analyzer\n[{file}]"),
                    tier: "subagent".to_string(),
                    target_path: Some(file.clone()),
                    status: AgentStatus::Idle,
                    details: format!("static vulnerability audit on {file}"),
                    findings_count: 0,
                    is_paused: false,
                },
            );
        }

        // 3. Remediation, Verification & Gate
        map.insert(
            "sub_patcher".to_string(),
            SproutedNodeInfo {
                id: "sub_patcher".to_string(),
                label: "remediation engine\n[auto-hardening]".to_string(),
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
                label: "test verifier\n[security unit tests]".to_string(),
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
                label: "pre-prod defense gate\n[build guard]".to_string(),
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

    pub fn default_nodes_map() -> HashMap<String, SproutedNodeInfo> {
        Self::build_nodes_for_workspace(Path::new("."))
    }

    pub fn build_sprouted_graph(
        nodes_info: &HashMap<String, SproutedNodeInfo>,
    ) -> Result<Flow<TextContent, StepEdge>, rataflow::Error> {
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

        // Column 0: Orchestrator
        layout_coords.push(("orch".to_string(), (2.0, 14.0), "orchestrator\ncore planner".to_string()));

        // Column 1: Folders (x = 28.0)
        let folder_count = folder_nodes.len().max(1);
        let folder_gap = 24.0 / (folder_count as f64);
        for (i, f) in folder_nodes.iter().enumerate() {
            let y = 6.0 + (i as f64) * folder_gap;
            layout_coords.push((f.id.clone(), (28.0, y), f.label.clone()));
        }

        // Column 2: Files (x = 54.0)
        let file_count = file_nodes.len().max(1);
        let file_gap = 24.0 / (file_count as f64);
        for (i, f) in file_nodes.iter().enumerate() {
            let y = 6.0 + (i as f64) * file_gap;
            layout_coords.push((f.id.clone(), (54.0, y), f.label.clone()));
        }

        // Column 3: Review Modules (x = 82.0)
        let sub_count = subagent_nodes.len().max(1);
        let sub_gap = 26.0 / (sub_count as f64);
        for (i, s) in subagent_nodes.iter().enumerate() {
            let y = 3.0 + (i as f64) * sub_gap;
            layout_coords.push((s.id.clone(), (82.0, y), s.label.clone()));
        }

        // Column 4: Remediation & Verification (x = 114.0)
        layout_coords.push(("sub_patcher".to_string(), (114.0, 9.0), "remediation\n[auto-hardening]".to_string()));
        layout_coords.push(("sub_verifier".to_string(), (114.0, 19.0), "test verifier\n[security unit tests]".to_string()));

        // Column 5: Defense Gate (x = 146.0)
        layout_coords.push(("defense_gate".to_string(), (146.0, 14.0), "pre-prod defense gate\n[build guard]".to_string()));

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

            let (border_color, status_text, is_bold) = if info.is_paused {
                (Color::DarkGray, "paused", false)
            } else {
                match info.status {
                    AgentStatus::Idle => (Color::DarkGray, "idle", false),
                    AgentStatus::Planning => (Color::Gray, "planning", false),
                    AgentStatus::WaitingConfirmation => (Color::White, "confirm?", true),
                    AgentStatus::Running => (Color::White, "running", true),
                    AgentStatus::Paused => (Color::DarkGray, "paused", false),
                    AgentStatus::Adapting => (Color::White, "adapting", true),
                    AgentStatus::Success => (Color::Gray, "completed", false),
                    AgentStatus::Failed => (Color::White, "action required", true),
                }
            };

            let display_text = format!("{}\n[{}]", label, status_text);
            let mut node = Node::from_text(id.clone(), *pos, display_text);
            node.content.border_style = Some(Style::default().fg(border_color));

            let mut text_style = Style::default().fg(if is_bold { Color::White } else { Color::Gray });
            if is_bold {
                text_style = text_style.add_modifier(Modifier::BOLD);
            }
            node.content.text_style = Some(text_style);
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

fn create_step_edge(edge_id: &str, src: &str, dst: &str, nodes_info: &HashMap<String, SproutedNodeInfo>) -> Edge<StepEdge> {
    let src_status = nodes_info.get(src).map(|n| (n.status, n.is_paused));
    let dst_status = nodes_info.get(dst).map(|n| (n.status, n.is_paused));

    let is_animating = match (src_status, dst_status) {
        (Some((AgentStatus::Running, false)), _) => true,
        (_, Some((AgentStatus::Running, false))) => true,
        _ => false,
    };

    Edge::new(edge_id.to_string(), src.to_string(), dst.to_string()).with_animated(is_animating)
}
