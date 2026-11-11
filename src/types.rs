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
    #[serde(default = "default_reachability")]
    pub reachability: String,
    #[serde(default = "default_triage_verdict")]
    pub triage_verdict: String,
    #[serde(default)]
    pub triage_reasoning: String,
    #[serde(default)]
    pub call_path: Vec<String>,
}

fn default_reachability() -> String {
    "POTENTIALLY_REACHABLE".to_string()
}

fn default_triage_verdict() -> String {
    "TRUE_POSITIVE".to_string()
}

impl Default for VulnerabilityFinding {
    fn default() -> Self {
        Self {
            id: String::new(),
            title: String::new(),
            cwe: String::new(),
            severity: Severity::Medium,
            file_path: PathBuf::new(),
            line_number: 0,
            snippet: String::new(),
            description: String::new(),
            recommendation: String::new(),
            patched: false,
            reachability: default_reachability(),
            triage_verdict: default_triage_verdict(),
            triage_reasoning: String::new(),
            call_path: Vec::new(),
        }
    }
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
    #[serde(default)]
    pub unit_test_passed: bool,
    #[serde(default)]
    pub safe_outputs_passed: bool,
}

impl Default for HardeningPatch {
    fn default() -> Self {
        Self {
            id: String::new(),
            finding_id: String::new(),
            target_file: PathBuf::new(),
            original_snippet: String::new(),
            hardened_snippet: String::new(),
            unified_diff: String::new(),
            unit_test_code: String::new(),
            applied: false,
            explanation: String::new(),
            unit_test_passed: false,
            safe_outputs_passed: false,
        }
    }
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
    pub const ALL: [AiProvider; 6] = [
        AiProvider::AnthropicClaude,
        AiProvider::OpenAiGpt4o,
        AiProvider::GoogleGemini,
        AiProvider::DeepSeek,
        AiProvider::OllamaLocal,
        AiProvider::Custom,
    ];

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

    pub fn requires_api_key(&self) -> bool {
        *self != AiProvider::OllamaLocal
    }

    pub fn preset_models(&self) -> &'static [&'static str] {
        match self {
            AiProvider::AnthropicClaude => &[
                "claude-3-7-sonnet-20250219",
                "claude-3-5-sonnet-20241022",
                "claude-3-5-haiku-20241022",
            ],
            AiProvider::OpenAiGpt4o => &["gpt-4o", "gpt-4o-mini", "o3-mini", "o1"],
            AiProvider::GoogleGemini => &["gemini-2.0-flash", "gemini-1.5-pro", "gemini-2.5-flash"],
            AiProvider::DeepSeek => &["deepseek-chat", "deepseek-reasoner"],
            AiProvider::OllamaLocal => &[
                "llama3.2",
                "qwen2.5-coder:7b",
                "llama3.3:70b",
                "deepseek-r1:8b",
            ],
            AiProvider::Custom => &["gpt-4o", "meta-llama/Llama-3.3-70B-Instruct"],
        }
    }

    #[allow(dead_code)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandSuggestion {
    pub name: &'static str,
    pub args: &'static str,
    pub description: &'static str,
}

pub const AVAILABLE_COMMANDS: &[CommandSuggestion] = &[
    CommandSuggestion {
        name: "/scan",
        args: "",
        description: "Run autonomous security audit on workspace",
    },
    CommandSuggestion {
        name: "/model",
        args: "[name]",
        description: "Open model selection popup or set model",
    },
    CommandSuggestion {
        name: "/provider",
        args: "[name]",
        description: "Open supported provider list or switch provider",
    },
    CommandSuggestion {
        name: "/custom",
        args: "[url]",
        description: "Add & configure custom AI provider endpoint & credentials",
    },
    CommandSuggestion {
        name: "/key",
        args: "[api_key]",
        description: "Open API key configuration popup",
    },
    CommandSuggestion {
        name: "/url",
        args: "[base_url]",
        description: "Open endpoint URL configuration popup",
    },
    CommandSuggestion {
        name: "/config",
        args: "",
        description: "Open AI provider & model settings popup",
    },
    CommandSuggestion {
        name: "/apply",
        args: "",
        description: "Apply selected code hardening patch",
    },
    CommandSuggestion {
        name: "/rollback",
        args: "",
        description: "Rollback applied hardening patch",
    },
    CommandSuggestion {
        name: "/export",
        args: "",
        description: "Export defense report to HTML & Markdown",
    },
    CommandSuggestion {
        name: "/init-sec",
        args: "",
        description: "Initialize CodeContextGraph & draft SECURITY.md",
    },
    CommandSuggestion {
        name: "/reachability",
        args: "",
        description: "Display function reachability & phantom dependency analysis",
    },
    CommandSuggestion {
        name: "/shield",
        args: "",
        description: "Run Pre-Install Malware Shield audit",
    },
    CommandSuggestion {
        name: "/hotfix",
        args: "[pkg]",
        description: "Generate local library patch ./patches/<pkg>.patch without upgrade",
    },
    CommandSuggestion {
        name: "/skills",
        args: "[action]",
        description: "Manage, import, or synthesize 3-tier .skill.md",
    },
    CommandSuggestion {
        name: "/pause",
        args: "",
        description: "Pause / resume selected agent in workflow",
    },
    CommandSuggestion {
        name: "/clear",
        args: "",
        description: "Clear chat message history",
    },
    CommandSuggestion {
        name: "/help",
        args: "",
        description: "Show command reference & keyboard shortcuts",
    },
    CommandSuggestion {
        name: "/exit",
        args: "",
        description: "Exit asterisk application cleanly",
    },
];

pub fn get_matching_commands(input: &str) -> Vec<&'static CommandSuggestion> {
    if !input.starts_with('/') || input.contains(' ') {
        return Vec::new();
    }
    AVAILABLE_COMMANDS
        .iter()
        .filter(|c| c.name.starts_with(input))
        .collect()
}
