use crate::types::{AgentStatus, SproutedNodeInfo};
use rataflow::{Edge, Flow, Node, StepEdge, TextContent};
use ratatui::style::{Color, Modifier, Style};
use std::collections::HashMap;

pub struct AgentGraphBuilder;

impl AgentGraphBuilder {
    pub fn build_sprouted_graph(
        nodes_info: &HashMap<String, SproutedNodeInfo>,
    ) -> Result<Flow<TextContent, StepEdge>, rataflow::Error> {
        let mut nodes = Vec::new();

        // Node definitions with coordinates in horizontal layout (Tiered Left to Right)
        let layout_coords: Vec<(&str, (f64, f64), &str)> = vec![
            ("orch", (2.0, 13.0), "orchestrator\ncore planner"),
            ("folder_backend", (26.0, 6.0), "folder\nbackend/"),
            ("folder_frontend", (26.0, 20.0), "folder\nfrontend/"),
            ("file_server", (50.0, 6.0), "file\nserver.py"),
            ("file_api", (50.0, 20.0), "file\napi.js"),
            ("sub_secret_backend", (76.0, 2.0), "secret hunter\n[server.py]"),
            ("sub_sast_backend", (76.0, 7.0), "sast analyzer\n[server.py]"),
            ("sub_net_backend", (76.0, 12.0), "network prober\n[server.py]"),
            ("sub_sast_frontend", (76.0, 18.0), "sast analyzer\n[api.js]"),
            ("sub_net_frontend", (76.0, 23.0), "network prober\n[api.js]"),
            ("sub_patcher", (106.0, 8.0), "auto-hardening\n[diff patcher]"),
            ("sub_verifier", (106.0, 18.0), "test verifier\n[unit tests]"),
            ("defense_gate", (136.0, 13.0), "pre-prod defense gate\n[build guard]"),
        ];

        for (id, pos, label) in &layout_coords {
            let default_info = SproutedNodeInfo {
                id: id.to_string(),
                label: label.to_string(),
                tier: "worker".to_string(),
                target_path: None,
                status: AgentStatus::Idle,
                details: String::new(),
                findings_count: 0,
                is_paused: false,
            };

            let info = nodes_info.get(*id).unwrap_or(&default_info);

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
            let mut node = Node::from_text(*id, *pos, display_text);
            node.content.border_style = Some(Style::default().fg(border_color));

            let mut text_style = Style::default().fg(if is_bold { Color::White } else { Color::Gray });
            if is_bold {
                text_style = text_style.add_modifier(Modifier::BOLD);
            }
            node.content.text_style = Some(text_style);
            nodes.push(node);
        }

        // Horizontal Edge Definitions
        let raw_edges = vec![
            ("e_orch_backend", "orch", "folder_backend"),
            ("e_orch_frontend", "orch", "folder_frontend"),
            ("e_back_server", "folder_backend", "file_server"),
            ("e_front_api", "folder_frontend", "file_api"),
            ("e_serv_secret", "file_server", "sub_secret_backend"),
            ("e_serv_sast", "file_server", "sub_sast_backend"),
            ("e_serv_net", "file_server", "sub_net_backend"),
            ("e_api_sast", "file_api", "sub_sast_frontend"),
            ("e_api_net", "file_api", "sub_net_frontend"),
            ("e_sub_patch1", "sub_secret_backend", "sub_patcher"),
            ("e_sub_patch2", "sub_sast_backend", "sub_patcher"),
            ("e_sub_patch3", "sub_net_backend", "sub_patcher"),
            ("e_sub_patch4", "sub_sast_frontend", "sub_patcher"),
            ("e_sub_patch5", "sub_net_frontend", "sub_patcher"),
            ("e_patch_verify", "sub_patcher", "sub_verifier"),
            ("e_verify_gate", "sub_verifier", "defense_gate"),
        ];

        let mut edges: Vec<Edge<StepEdge>> = Vec::new();
        for (edge_id, src, dst) in raw_edges {
            let src_status = nodes_info.get(src).map(|n| (n.status, n.is_paused));
            let dst_status = nodes_info.get(dst).map(|n| (n.status, n.is_paused));

            // Determine if edge should be animated (only when source or destination is currently running and not paused)
            let is_animating = match (src_status, dst_status) {
                (Some((AgentStatus::Running, false)), _) => true,
                (_, Some((AgentStatus::Running, false))) => true,
                _ => false,
            };

            let edge = Edge::new(edge_id, src, dst).with_animated(is_animating);
            edges.push(edge);
        }

        let mut flow = Flow::with_graph(nodes, edges)?;
        flow.request_fit_view();
        Ok(flow)
    }

    pub fn default_nodes_map() -> HashMap<String, SproutedNodeInfo> {
        let mut map = HashMap::new();
        let items = vec![
            ("orch", "orchestrator", "core planner", None),
            ("folder_backend", "folder", "backend module", Some("backend/")),
            ("folder_frontend", "folder", "frontend module", Some("frontend/")),
            ("file_server", "file", "server.py", Some("backend/server.py")),
            ("file_api", "file", "api.js", Some("frontend/api.js")),
            ("sub_secret_backend", "subagent", "secret hunter", Some("backend/server.py")),
            ("sub_sast_backend", "subagent", "sast analyzer", Some("backend/server.py")),
            ("sub_net_backend", "subagent", "network prober", Some("backend/server.py")),
            ("sub_sast_frontend", "subagent", "sast analyzer", Some("frontend/api.js")),
            ("sub_net_frontend", "subagent", "network prober", Some("frontend/api.js")),
            ("sub_patcher", "subagent", "auto-hardening patcher", None),
            ("sub_verifier", "subagent", "test verifier", None),
            ("defense_gate", "gate", "pre-production gate", None),
        ];

        for (id, tier, label, path) in items {
            map.insert(
                id.to_string(),
                SproutedNodeInfo {
                    id: id.to_string(),
                    label: label.to_string(),
                    tier: tier.to_string(),
                    target_path: path.map(String::from),
                    status: AgentStatus::Idle,
                    details: format!("task assigned: {label}"),
                    findings_count: 0,
                    is_paused: false,
                },
            );
        }
        map
    }
}
