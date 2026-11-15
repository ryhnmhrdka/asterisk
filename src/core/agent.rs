use crate::core::{
    config::AppConfig,
    policy::PolicyGate,
};
use crate::types::AiProvider;
use rig::completion::CompletionRequest;
use rig::providers::anthropic::wire::AnthropicConfig;
use rig::providers::gemini::GeminiConfig;
use rig::providers::ollama::wire::OllamaConfig;
use rig::providers::openai::wire::OpenAIConfig;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct SubagentAuditResult {
    pub thought: Option<String>,
    pub clean_text: String,
    pub follow_up_verification: Option<FollowUpTarget>,
}

#[derive(Debug, Clone)]
pub struct FollowUpTarget {
    pub target: String,
    pub reason: String,
}

pub struct SecurityAgentHub {
    pub target_dir: PathBuf,
    #[allow(dead_code)]
    pub policy_gate: Arc<PolicyGate>,
    pub config: AppConfig,
}

impl SecurityAgentHub {
    pub fn new(target_dir: PathBuf, policy_gate: Arc<PolicyGate>, config: AppConfig) -> Self {
        Self {
            target_dir,
            policy_gate,
            config,
        }
    }

    /// Primary production entrypoint: executes a direct live API call to the configured provider.
    /// Returns the live model response or an explicit API error diagnostic.
    pub async fn query(&self, prompt: &str) -> String {
        let system_prompt = format!(
            "You are Asterisk, an autonomous pre-production code defense and security audit assistant.\nWorkspace Target: {}\n\nUser Question/Command:\n{}",
            self.target_dir.display(),
            prompt
        );

        match self.config.provider {
            AiProvider::AnthropicClaude => {
                let api_key = match self.config.get_api_key() {
                    Some(k) if !k.is_empty() => k,
                    _ => {
                        return "⚠️ **Anthropic Claude: API Key Missing**\nPlease configure your key by typing `/key <your_api_key>` in the chat prompt, or export `ANTHROPIC_API_KEY=\"...\"` in your shell environment.".to_string();
                    }
                };

                let mut anthropic_cfg = AnthropicConfig::new(api_key);
                if let Some(base_url) = self.config.get_base_url() {
                    anthropic_cfg = anthropic_cfg.with_base_url(base_url);
                }

                let client = anthropic_cfg.client();
                let model_name = self.config.get_model();
                let model = client.completion(model_name.clone());
                let req = CompletionRequest::new(system_prompt);

                match model.call(req).await {
                    Ok(res) => extract_completion_text(&res),
                    Err(e) => format!(
                        "⚠️ **Anthropic API Request Failed** (Model: `{}`)\nError: `{}`\nVerify your API key with `/key` or change model with `/model`.",
                        model_name, e
                    ),
                }
            }

            AiProvider::OpenAiGpt4o => {
                let api_key = match self.config.get_api_key() {
                    Some(k) if !k.is_empty() => k,
                    _ => {
                        return "⚠️ **OpenAI: API Key Missing**\nPlease configure your key by typing `/key <your_api_key>` in the chat prompt, or export `OPENAI_API_KEY=\"...\"` in your shell environment.".to_string();
                    }
                };

                let mut openai_cfg = OpenAIConfig::new(api_key);
                if let Some(base_url) = self.config.get_base_url() {
                    openai_cfg = openai_cfg.with_base_url(base_url);
                }

                let client = openai_cfg.client();
                let model_name = self.config.get_model();
                let model = client.completion(model_name.clone());
                let req = CompletionRequest::new(system_prompt);

                match model.call(req).await {
                    Ok(res) => extract_completion_text(&res),
                    Err(e) => format!(
                        "⚠️ **OpenAI API Request Failed** (Model: `{}`)\nError: `{}`\nVerify your API key with `/key` or change model with `/model`.",
                        model_name, e
                    ),
                }
            }

            AiProvider::GoogleGemini => {
                let api_key = match self.config.get_api_key() {
                    Some(k) if !k.is_empty() => k,
                    _ => {
                        return "⚠️ **Google Gemini: API Key Missing**\nPlease configure your key by typing `/key <your_api_key>` in the chat prompt, or export `GEMINI_API_KEY=\"...\"` in your shell environment.".to_string();
                    }
                };

                let gemini_cfg = GeminiConfig::new(api_key);
                let client = gemini_cfg.client();
                let model_name = self.config.get_model();
                let model = client.completion(model_name.clone());
                let req = CompletionRequest::new(system_prompt);

                match model.call(req).await {
                    Ok(res) => extract_completion_text(&res),
                    Err(e) => format!(
                        "⚠️ **Google Gemini API Request Failed** (Model: `{}`)\nError: `{}`\nVerify your API key with `/key` or change model with `/model`.",
                        model_name, e
                    ),
                }
            }

            AiProvider::DeepSeek
            | AiProvider::Groq
            | AiProvider::OpenRouter
            | AiProvider::Mistral
            | AiProvider::TogetherAi
            | AiProvider::XAi => {
                let default_url = self.config.provider.default_base_url().unwrap_or("https://api.openai.com/v1");
                let prov_name = self.config.provider.name();
                let api_key = match self.config.get_api_key() {
                    Some(k) if !k.is_empty() => k,
                    _ => {
                        return format!(
                            "⚠️ **{prov_name}: API Key Missing**\nPlease configure your key by typing `/key <your_api_key>` in the chat prompt, or export `{}_API_KEY=\"...\"` in your shell environment.",
                            match self.config.provider {
                                AiProvider::DeepSeek => "DEEPSEEK",
                                AiProvider::Groq => "GROQ",
                                AiProvider::OpenRouter => "OPENROUTER",
                                AiProvider::Mistral => "MISTRAL",
                                AiProvider::TogetherAi => "TOGETHER",
                                AiProvider::XAi => "XAI",
                                _ => "API",
                            }
                        );
                    }
                };

                let base_url = self
                    .config
                    .get_base_url()
                    .unwrap_or_else(|| default_url.to_string());
                let openai_cfg = OpenAIConfig::new(api_key).with_base_url(base_url.clone());
                let client = openai_cfg.client();
                let model_name = self.config.get_model();
                let model = client.completion(model_name.clone());
                let req = CompletionRequest::new(system_prompt);

                match model.call(req).await {
                    Ok(res) => extract_completion_text(&res),
                    Err(e) => format!(
                        "⚠️ **{prov_name} API Request Failed** (Model: `{}`)\nEndpoint: `{}`\nError: `{}`\nVerify your API key with `/key` or change model with `/model`.",
                        model_name, base_url, e
                    ),
                }
            }

            AiProvider::Custom => {
                let base_url = self
                    .config
                    .get_base_url()
                    .unwrap_or_else(|| "http://localhost:8000/v1".to_string());
                let api_key = self
                    .config
                    .get_api_key()
                    .unwrap_or_else(|| "custom-key".to_string());
                let model_name = self.config.get_model();

                // Direct HTTP call using reqwest to preserve reasoning_content / reasoning from OpenAI-compatible models (e.g. DeepSeek / vLLM)
                let endpoint = if base_url.ends_with("/chat/completions") {
                    base_url.clone()
                } else if base_url.ends_with('/') {
                    format!("{base_url}chat/completions")
                } else {
                    format!("{base_url}/chat/completions")
                };

                let http_client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(60))
                    .build()
                    .unwrap_or_default();

                let body = serde_json::json!({
                    "model": model_name,
                    "messages": [
                        {"role": "user", "content": system_prompt}
                    ]
                });

                let res = http_client
                    .post(&endpoint)
                    .header("Authorization", format!("Bearer {api_key}"))
                    .header("Content-Type", "application/json")
                    .json(&body)
                    .send()
                    .await;

                match res {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(json) = resp.json::<serde_json::Value>().await {
                            let message = &json["choices"][0]["message"];
                            let content = message["content"].as_str().unwrap_or_default().to_string();
                            let reasoning = message["reasoning"]
                                .as_str()
                                .or_else(|| message["reasoning_content"].as_str())
                                .unwrap_or_default();

                            if !reasoning.is_empty() {
                                format!("<think>\n{}\n</think>\n{}", reasoning, content)
                            } else {
                                content
                            }
                        } else {
                            "⚠️ **Custom Provider Response Error**: Unable to parse JSON response body.".to_string()
                        }
                    }
                    Ok(resp) => {
                        let status = resp.status();
                        let text = resp.text().await.unwrap_or_default();
                        format!(
                            "⚠️ **Custom Provider API Request Failed** (HTTP {status})\nEndpoint: `{}`\nModel: `{}`\nResponse: `{}`\nTip: You can change endpoint via `/url <url>`, key via `/key <key>`, or model via `/model <model>`.",
                            endpoint, model_name, text
                        )
                    }
                    Err(e) => {
                        format!(
                            "⚠️ **Custom Provider API Request Failed**\nEndpoint: `{}`\nModel: `{}`\nError: `{}`\nTip: You can change endpoint via `/url <url>`, key via `/key <key>`, or model via `/model <model>`.",
                            endpoint, model_name, e
                        )
                    }
                }
            }

            AiProvider::OllamaLocal => {
                let base_url = self
                    .config
                    .get_base_url()
                    .unwrap_or_else(|| "http://localhost:11434".to_string());
                let model_name = self.config.get_model();

                let mut ollama_cfg = OllamaConfig::new().with_base_url(base_url.clone());
                if let Some(key) = self.config.get_api_key() {
                    ollama_cfg = ollama_cfg.with_api_key(key);
                }

                let client = ollama_cfg.client();
                let model = client.completion(model_name.clone());
                let req = CompletionRequest::new(system_prompt);

                match model.call(req).await {
                    Ok(res) => extract_completion_text(&res),
                    Err(e) => format!(
                        "⚠️ **Ollama Local Connection Error**\nEndpoint: `{}`\nModel: `{}`\nError: `{}`\nEnsure Ollama daemon is running (`ollama serve`), or switch to a cloud/custom provider using `/provider custom`.",
                        base_url, model_name, e
                    ),
                }
            }
        }
    }

    /// Audits code from a specialized subagent perspective using live AI provider.
    pub async fn query_subagent(
        &self,
        agent_id: &str,
        title: &str,
        targets: &[String],
        target_dir: &Path,
    ) -> Result<SubagentAuditResult, String> {
        let mut context = String::new();
        let mut checked_files = 0;
        for t in targets {
            let path = target_dir.join(t);
            if path.is_file() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let preview: Vec<&str> = content.lines().take(60).collect();
                    context.push_str(&format!("\n--- Target: {} ---\n{}\n", t, preview.join("\n")));
                    checked_files += 1;
                    if checked_files >= 3 {
                        break;
                    }
                }
            }
        }

        let prompt = format!(
            "You are security subagent '{}' ({}) analyzing target repository '{}'.\n\
             Files to analyze:\n{}\n\n\
             Instructions:\n\
             1. Think through potential security risks, taint flows, or vulnerabilities inside <think>...</think>.\n\
             2. Provide your concise audit findings.\n\
             3. If your analysis detects that another uninspected file or component must be verified (e.g. secondary endpoints, auth modules, database queries), add this exact marker:\n\
             VERIFY_FOLLOWUP: <target_file> | <reason>",
            title, agent_id, target_dir.display(),
            if context.is_empty() { "(general directory scope)" } else { &context }
        );

        let raw = self.query(&prompt).await;

        if raw.starts_with("⚠️ ")
            || raw.contains("API Request Failed")
            || raw.contains("API Key Missing")
            || raw.contains("Connection Error")
        {
            return Err(raw);
        }

        let (thought, clean_text) = parse_ai_thinking_content(&raw);

        // Check if follow-up verification was requested by the AI
        let mut follow_up_verification = None;
        for line in raw.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("VERIFY_FOLLOWUP:") {
                let parts: Vec<&str> = rest.splitn(2, '|').collect();
                if !parts.is_empty() {
                    let target = parts[0].trim().to_string();
                    let reason = parts.get(1).map(|s| s.trim()).unwrap_or("Secondary verification required").to_string();
                    if !target.is_empty() {
                        follow_up_verification = Some(FollowUpTarget { target, reason });
                        break;
                    }
                }
            }
        }

        if follow_up_verification.is_none() {
            for line in raw.lines() {
                let lower = line.to_lowercase();
                if lower.contains("must verify") || lower.contains("need to verify") || lower.contains("should verify") {
                    for word in line.split_whitespace() {
                        let clean_word = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '/' && c != '.' && c != '_' && c != '-');
                        if (clean_word.ends_with(".rs") || clean_word.ends_with(".py") || clean_word.ends_with(".js") || clean_word.ends_with(".ts") || clean_word.ends_with(".go"))
                            && !targets.iter().any(|t| t.contains(clean_word))
                        {
                            follow_up_verification = Some(FollowUpTarget {
                                target: clean_word.to_string(),
                                reason: format!("AI discovered unverified dependency: {}", clean_word),
                            });
                            break;
                        }
                    }
                    if follow_up_verification.is_some() {
                        break;
                    }
                }
            }
        }

        Ok(SubagentAuditResult {
            thought,
            clean_text,
            follow_up_verification,
        })
    }
}

fn extract_completion_text(res: &rig::completion::CompletionResponse) -> String {
    let text = res
        .choice
        .iter()
        .filter_map(|c| match c {
            rig::completion::message::AssistantContent::Text(t) => Some(t.text.clone()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n");

    if text.is_empty() {
        "✓ Request executed successfully (empty response body).".to_string()
    } else {
        text
    }
}

/// Parses reasoning tags like `<think>...</think>`, `<thought>...</thought>`, or `<reasoning>...</reasoning>`
/// commonly produced by reasoning models (DeepSeek-R1, Qwen Reasoning, Claude Thinking, etc.).
/// Returns `(Option<ThinkingContent>, CleanResponseText)`.
pub fn parse_ai_thinking_content(raw: &str) -> (Option<String>, String) {
    let lower = raw.to_lowercase();
    let tags = [
        ("<think>", "</think>"),
        ("<thought>", "</thought>"),
        ("<reasoning>", "</reasoning>"),
    ];

    for (open_tag, close_tag) in tags {
        if let Some(start_idx) = lower.find(open_tag) {
            let content_start = start_idx + open_tag.len();
            if let Some(end_offset) = lower[content_start..].find(close_tag) {
                let content_end = content_start + end_offset;
                let thought = raw[content_start..content_end].trim().to_string();
                let mut remaining = String::new();
                remaining.push_str(&raw[..start_idx]);
                remaining.push_str(&raw[content_end + close_tag.len()..]);
                let clean = remaining.trim().to_string();
                return (
                    Some(thought),
                    if clean.is_empty() {
                        "Analysis completed.".to_string()
                    } else {
                        clean
                    },
                );
            } else {
                // Open tag without closing tag
                let thought = raw[content_start..].trim().to_string();
                let clean = raw[..start_idx].trim().to_string();
                return (
                    Some(thought),
                    if clean.is_empty() {
                        "Reasoning in progress...".to_string()
                    } else {
                        clean
                    },
                );
            }
        }
    }

    (None, raw.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_security_agent_hub_missing_key_diagnostic() {
        let dir = std::env::current_dir().unwrap();
        let gate = Arc::new(PolicyGate::new().expect("policy gate init"));
        let mut cfg = AppConfig::default();
        cfg.provider = AiProvider::AnthropicClaude;
        cfg.api_key = None;

        let hub = SecurityAgentHub::new(dir, gate, cfg);
        let res = hub.query("analyze security posture").await;
        assert!(res.contains("API Key Missing"));
    }

    #[tokio::test]
    async fn test_security_agent_hub_custom_provider_attempt() {
        let dir = std::env::current_dir().unwrap();
        let gate = Arc::new(PolicyGate::new().expect("policy gate init"));
        let mut cfg = AppConfig::default();
        cfg.provider = AiProvider::Custom;
        cfg.base_url = Some("http://127.0.0.1:54321/v1".to_string());
        cfg.model = Some("test-model".to_string());
        cfg.api_key = Some("test-key".to_string());

        let hub = SecurityAgentHub::new(dir, gate, cfg);
        let res = hub.query("ping").await;
        // Should make real attempt to http://127.0.0.1:54321/v1 and report connection failure, not dummy string!
        assert!(res.contains("Custom Provider API Request Failed") || res.contains("error"));
    }
}
