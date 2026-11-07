use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentStatus {
    Idle,
    Planning,
    WaitingConfirmation,
    Running,
    Paused,
    Adapting,
    Success,
    Failed,
}

impl AgentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentStatus::Idle => "idle",
            AgentStatus::Planning => "planning",
            AgentStatus::WaitingConfirmation => "awaiting confirmation",
            AgentStatus::Running => "running",
            AgentStatus::Paused => "paused",
            AgentStatus::Adapting => "adapting",
            AgentStatus::Success => "completed",
            AgentStatus::Failed => "blocked",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    pub id: String,
    pub title: String,
    pub cwe: String,
    pub severity: Severity,
    pub file_path: PathBuf,
    pub line_number: usize,
    pub snippet: String,
    pub description: String,
    pub recommendation: String,
    pub patched: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningPatch {
    pub id: String,
    pub finding_id: String,
    pub target_file: PathBuf,
    pub original_snippet: String,
    pub hardened_snippet: String,
    pub unified_diff: String,
    pub unit_test_code: String,
    pub applied: bool,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractiveSkill {
    pub id: String,
    pub name: String,
    pub category: String,
    pub description: String,
    pub invocations: usize,
    pub active: bool,
}

#[derive(Debug, Clone)]
pub struct DynamicLogEntry {
    pub timestamp: DateTime<Utc>,
    pub agent_name: String,
    pub level: String,
    pub message: String,
    pub is_improvisation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceProfile {
    pub root_path: PathBuf,
    pub total_files: usize,
    pub languages: Vec<String>,
    pub frameworks: Vec<String>,
    pub has_docker: bool,
    pub has_env_files: bool,
    pub has_mobile: bool,
}

#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub sender: String,
    pub text: String,
    pub is_user: bool,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SproutedNodeInfo {
    pub id: String,
    pub label: String,
    pub tier: String,
    pub target_path: Option<String>,
    pub status: AgentStatus,
    pub details: String,
    pub findings_count: usize,
    pub is_paused: bool,
}
