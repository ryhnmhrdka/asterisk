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

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AgentStatus {
    #[default]
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
    Groq,
    OpenRouter,
    Mistral,
    TogetherAi,
    XAi,
    OllamaLocal,
    Custom,
}

impl AiProvider {
    pub const ALL: [AiProvider; 11] = [
        AiProvider::AnthropicClaude,
        AiProvider::OpenAiGpt4o,
        AiProvider::GoogleGemini,
        AiProvider::DeepSeek,
        AiProvider::Groq,
        AiProvider::OpenRouter,
        AiProvider::Mistral,
        AiProvider::TogetherAi,
        AiProvider::XAi,
        AiProvider::OllamaLocal,
        AiProvider::Custom,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            AiProvider::AnthropicClaude => "Anthropic Claude",
            AiProvider::OpenAiGpt4o => "OpenAI",
            AiProvider::GoogleGemini => "Google Gemini",
            AiProvider::DeepSeek => "DeepSeek",
            AiProvider::Groq => "Groq",
            AiProvider::OpenRouter => "OpenRouter",
            AiProvider::Mistral => "Mistral AI",
            AiProvider::TogetherAi => "Together AI",
            AiProvider::XAi => "xAI (Grok)",
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
            AiProvider::Groq => &[
                "llama-3.3-70b-versatile",
                "deepseek-r1-distill-llama-70b",
                "llama-3.1-8b-instant",
                "mixtral-8x7b-32768",
                "gemma2-9b-it",
            ],
            AiProvider::OpenRouter => &[
                "anthropic/claude-3.7-sonnet",
                "deepseek/deepseek-r1",
                "openai/gpt-4o",
                "meta-llama/llama-3.3-70b-instruct",
                "google/gemini-2.0-flash-001",
            ],
            AiProvider::Mistral => &[
                "mistral-large-latest",
                "codestral-latest",
                "mistral-small-latest",
            ],
            AiProvider::TogetherAi => &[
                "deepseek-ai/DeepSeek-R1",
                "meta-llama/Llama-3.3-70B-Instruct-Turbo",
                "Qwen/Qwen2.5-Coder-32B-Instruct",
            ],
            AiProvider::XAi => &["grok-2-latest", "grok-beta"],
            AiProvider::OllamaLocal => &[
                "llama3.2",
                "qwen2.5-coder:7b",
                "llama3.3:70b",
                "deepseek-r1:8b",
            ],
            AiProvider::Custom => &["deepseek-ai/DeepSeek-V4-Flash-0731", "zai-org/GLM-5.3-Flash"],
        }
    }

    #[allow(dead_code)]
    pub fn next(&self) -> Self {
        let all = Self::ALL;
        let pos = all.iter().position(|p| p == self).unwrap_or(0);
        all[(pos + 1) % all.len()]
    }

    pub fn default_model(&self) -> &'static str {
        match self {
            AiProvider::AnthropicClaude => "claude-3-7-sonnet-20250219",
            AiProvider::OpenAiGpt4o => "gpt-4o",
            AiProvider::GoogleGemini => "gemini-2.0-flash",
            AiProvider::DeepSeek => "deepseek-chat",
            AiProvider::Groq => "llama-3.3-70b-versatile",
            AiProvider::OpenRouter => "anthropic/claude-3.7-sonnet",
            AiProvider::Mistral => "mistral-large-latest",
            AiProvider::TogetherAi => "deepseek-ai/DeepSeek-R1",
            AiProvider::XAi => "grok-2-latest",
            AiProvider::Custom => "gpt-4o",
            AiProvider::OllamaLocal => "llama3.2",
        }
    }

    pub fn default_base_url(&self) -> Option<&'static str> {
        match self {
            AiProvider::DeepSeek => Some("https://api.deepseek.com/v1"),
            AiProvider::Groq => Some("https://api.groq.com/openai/v1"),
            AiProvider::OpenRouter => Some("https://openrouter.ai/api/v1"),
            AiProvider::Mistral => Some("https://api.mistral.ai/v1"),
            AiProvider::TogetherAi => Some("https://api.together.xyz/v1"),
            AiProvider::XAi => Some("https://api.x.ai/v1"),
            AiProvider::Custom => Some("http://localhost:8000/v1"),
            AiProvider::OllamaLocal => Some("http://localhost:11434"),
            _ => None,
        }
    }
}

/// Rich Chat Message model
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowTaskNode {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub subtitle: String,
    #[serde(default = "default_agent_type")]
    pub agent: String, // "sast", "secrets", "sca", "net", "malware", "verifier"
    #[serde(default = "default_tier")]
    pub tier: String,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub order: usize,
    #[serde(default)]
    pub depends_on: Vec<String>,
}

fn default_agent_type() -> String {
    "sast".to_string()
}

fn default_tier() -> String {
    "subagent".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowPlan {
    pub workflow_name: String,
    #[serde(default)]
    pub target_summary: String,
    pub nodes: Vec<WorkflowTaskNode>,
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
        args: "[--diff-scope=local]",
        description: "Run autonomous security audit on workspace",
    },
    CommandSuggestion {
        name: "/patch",
        args: "",
        description: "Apply selected code hardening patch to disk",
    },
    CommandSuggestion {
        name: "/secrets",
        args: "",
        description: "Scan & filter hardcoded secrets & high-entropy keys",
    },
    CommandSuggestion {
        name: "/model",
        args: "[name]",
        description: "Select active AI model from current provider's catalog",
    },
    CommandSuggestion {
        name: "/provider",
        args: "[name]",
        description: "View providers, model catalogs & API key readiness status",
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
        description: "Open AI settings dashboard & credentials manager",
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
        description: "Export defense report to JSON & Markdown",
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
        name: "/apk",
        args: "[path]",
        description: "Audit AndroidManifest.xml, mobile APK & container configs",
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
        name: "/theme",
        args: "[name]",
        description: "Switch UI theme live (asterisk, tokyo_night, catppuccin, nord, gruvbox, solarized, terminal)",
    },
    CommandSuggestion {
        name: "/pause",
        args: "",
        description: "Pause / resume selected agent in workflow",
    },
    CommandSuggestion {
        name: "/sessions",
        args: "[id/list]",
        description: "View session history or switch to past chat session",
    },
    CommandSuggestion {
        name: "/new",
        args: "",
        description: "Start a fresh security audit & chat session",
    },
    CommandSuggestion {
        name: "/grill-me",
        args: "",
        description: "Interactive adversarial security architecture interview",
    },
    CommandSuggestion {
        name: "/done",
        args: "",
        description: "Finish interview & synthesize hardened security plan",
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
