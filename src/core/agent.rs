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
use std::path::PathBuf;
use std::sync::Arc;

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
            "You are Constellation, an autonomous pre-production code defense and security audit assistant.\nWorkspace Target: {}\n\nUser Question/Command:\n{}",
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

                let openai_cfg = OpenAIConfig::new(api_key).with_base_url(base_url.clone());
                let client = openai_cfg.client();
                let model = client.completion(model_name.clone());
                let req = CompletionRequest::new(system_prompt);

                match model.call(req).await {
                    Ok(res) => extract_completion_text(&res),
                    Err(e) => format!(
                        "⚠️ **Custom Provider API Request Failed**\nEndpoint: `{}`\nModel: `{}`\nError: `{}`\nTip: You can change endpoint via `/url <url>`, key via `/key <key>`, or model via `/model <model>`.",
                        base_url, model_name, e
                    ),
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
