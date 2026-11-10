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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AiProvider {
    AnthropicClaude,
    OpenAiGpt4o,
    GoogleGemini,
    DeepSeek,
    Custom,
    OllamaLocal,
}

impl AiProvider {
    pub fn name(&self) -> &'static str {
        match self {
            AiProvider::AnthropicClaude => "Anthropic Claude",
            AiProvider::OpenAiGpt4o => "OpenAI",
            AiProvider::GoogleGemini => "Google Gemini",
            AiProvider::DeepSeek => "DeepSeek",
            AiProvider::Custom => "Custom Provider",
            AiProvider::OllamaLocal => "Ollama Local",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            AiProvider::AnthropicClaude => AiProvider::OpenAiGpt4o,
            AiProvider::OpenAiGpt4o => AiProvider::GoogleGemini,
            AiProvider::GoogleGemini => AiProvider::DeepSeek,
            AiProvider::DeepSeek => AiProvider::Custom,
            AiProvider::Custom => AiProvider::OllamaLocal,
            AiProvider::OllamaLocal => AiProvider::AnthropicClaude,
        }
    }

    pub fn default_model(&self) -> &'static str {
        match self {
            AiProvider::AnthropicClaude => "claude-3-7-sonnet-20250219",
            AiProvider::OpenAiGpt4o => "gpt-4o",
            AiProvider::GoogleGemini => "gemini-2.0-flash",
            AiProvider::DeepSeek => "deepseek-chat",
            AiProvider::Custom => "gpt-4o",
            AiProvider::OllamaLocal => "llama3.2",
        }
    }

    pub fn default_base_url(&self) -> Option<&'static str> {
        match self {
            AiProvider::DeepSeek => Some("https://api.deepseek.com/v1"),
            AiProvider::Custom => Some("http://localhost:8000/v1"),
            AiProvider::OllamaLocal => Some("http://localhost:11434"),
            _ => None,
        }
    }
}

/// Rich Chat Message model
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum ChatMessage {
    User(String),
    Thinking {
        agent: String,
        thought: String,
    },
    Agent {
        sender: String,
        text: String,
    },
    ToolCall {
        agent: String,
        tool: String,
        input: String,
    },
    ToolResult {
        agent: String,
        tool: String,
        output: String,
        elapsed_ms: Option<u64>,
    },
    System(String),
}

#[allow(dead_code)]
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
