use crate::types::AiProvider;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub provider: AiProvider,
    pub model: Option<String>,
    pub api_key: Option<String>,
    pub base_url: Option<String>,
    #[serde(default)]
    pub provider_keys: HashMap<String, String>,
    #[serde(default)]
    pub provider_base_urls: HashMap<String, String>,
    #[serde(default)]
    pub discovered_models: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub custom_provider_name: Option<String>,
    #[serde(default)]
    pub theme: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            provider: AiProvider::AnthropicClaude,
            model: None,
            api_key: None,
            base_url: None,
            provider_keys: HashMap::new(),
            provider_base_urls: HashMap::new(),
            discovered_models: HashMap::new(),
            custom_provider_name: None,
            theme: None,
        }
    }
}

impl AppConfig {
    pub fn config_path() -> PathBuf {
        let local_path = PathBuf::from(".asterisk").join("config.json");
        if local_path.exists() {
            return local_path;
        }
        if let Ok(home) = env::var("HOME") {
            let path = PathBuf::from(home).join(".config/asterisk/config.json");
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            path
        } else {
            local_path
        }
    }

    pub fn load() -> Self {
        // 1. Try local workspace .asterisk/config.json
        if let Ok(data) = fs::read_to_string(".asterisk/config.json") {
            if let Ok(cfg) = serde_json::from_str::<AppConfig>(&data) {
                return cfg;
            }
        }

        // 2. Try ~/.config/asterisk/config.json
        let p = Self::config_path();
        if let Ok(data) = fs::read_to_string(&p) {
            if let Ok(cfg) = serde_json::from_str::<AppConfig>(&data) {
                return cfg;
            }
        }

        // 3. Fallback to environment variables
        let mut cfg = Self::default();
        if env::var("ANTHROPIC_API_KEY").is_ok() {
            cfg.provider = AiProvider::AnthropicClaude;
        } else if env::var("OPENAI_API_KEY").is_ok() {
            cfg.provider = AiProvider::OpenAiGpt4o;
        } else if env::var("GEMINI_API_KEY").is_ok() {
            cfg.provider = AiProvider::GoogleGemini;
        } else if env::var("DEEPSEEK_API_KEY").is_ok() {
            cfg.provider = AiProvider::DeepSeek;
        } else if env::var("CUSTOM_API_KEY").is_ok() || env::var("OPENAI_BASE_URL").is_ok() {
            cfg.provider = AiProvider::Custom;
        }

        cfg
    }

    pub fn save(&self) -> Result<(), String> {
        let p = Self::config_path();
        if let Some(parent) = p.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialization error: {e}"))?;
        fs::write(&p, json).map_err(|e| format!("Failed to write config {}: {e}", p.display()))?;
        Ok(())
    }

    pub fn get_model(&self) -> String {
        if let Some(m) = &self.model {
            if !m.trim().is_empty() {
                return m.trim().to_string();
            }
        }
        if let Ok(m) = env::var("AI_MODEL") {
            if !m.trim().is_empty() {
                return m.trim().to_string();
            }
        }
        self.provider.default_model().to_string()
    }

    pub fn get_api_key_for_provider(&self, provider: AiProvider) -> Option<String> {
        if let Some(k) = self.provider_keys.get(provider.name()) {
            let trimmed = k.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
        if let Some(k) = self.provider_keys.get(&format!("{:?}", provider)) {
            let trimmed = k.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }

        if self.provider == provider {
            if let Some(k) = &self.api_key {
                let trimmed = k.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }

        match provider {
            AiProvider::AnthropicClaude => env::var("ANTHROPIC_API_KEY").ok(),
            AiProvider::OpenAiGpt4o => env::var("OPENAI_API_KEY").ok(),
            AiProvider::GoogleGemini => env::var("GEMINI_API_KEY").ok(),
            AiProvider::DeepSeek => env::var("DEEPSEEK_API_KEY").ok(),
            AiProvider::Custom => env::var("CUSTOM_API_KEY")
                .or_else(|_| env::var("AI_API_KEY"))
                .or_else(|_| env::var("OPENAI_API_KEY"))
                .ok(),
            AiProvider::OllamaLocal => None,
        }
        .and_then(|k| {
            let trimmed = k.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
    }

    pub fn is_provider_configured(&self, provider: AiProvider) -> bool {
        if !provider.requires_api_key() {
            return true;
        }
        self.get_api_key_for_provider(provider).is_some()
    }

    pub fn get_api_key(&self) -> Option<String> {
        self.get_api_key_for_provider(self.provider)
    }

    pub fn get_base_url_for_provider(&self, provider: AiProvider) -> Option<String> {
        if let Some(u) = self.provider_base_urls.get(provider.name()) {
            let trimmed = u.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
        if let Some(u) = self.provider_base_urls.get(&format!("{:?}", provider)) {
            let trimmed = u.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }

        if self.provider == provider {
            if let Some(u) = &self.base_url {
                let trimmed = u.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }

        match provider {
            AiProvider::OpenAiGpt4o | AiProvider::Custom => {
                if let Ok(u) = env::var("OPENAI_BASE_URL") {
                    let trimmed = u.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
                if let Ok(u) = env::var("AI_BASE_URL") {
                    let trimmed = u.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
            _ => {}
        }

        provider.default_base_url().map(|s| s.to_string())
    }

    pub fn get_base_url(&self) -> Option<String> {
        self.get_base_url_for_provider(self.provider)
    }

    pub fn requires_api_key(&self) -> bool {
        self.provider != AiProvider::OllamaLocal
    }

    pub fn is_api_key_configured(&self) -> bool {
        if !self.requires_api_key() {
            return true;
        }
        self.get_api_key().is_some()
    }

    #[allow(dead_code)]
    pub fn mask_key_for_provider(&self, provider: AiProvider) -> String {
        if provider == AiProvider::OllamaLocal {
            return "Not Required (Offline Local)".to_string();
        }
        match self.get_api_key_for_provider(provider) {
            Some(k) if k.len() > 8 => {
                let prefix = &k[..4];
                let suffix = &k[k.len() - 4..];
                format!("{prefix}••••••••{suffix}")
            }
            Some(k) if !k.is_empty() => "••••••••".to_string(),
            _ => "None (Unset)".to_string(),
        }
    }

    #[allow(dead_code)]
    pub fn mask_key(&self) -> String {
        self.mask_key_for_provider(self.provider)
    }

    pub fn get_models_for_provider(&self, provider: AiProvider) -> Vec<String> {
        if let Some(list) = self.discovered_models.get(provider.name()) {
            if !list.is_empty() {
                return list.clone();
            }
        }
        if let Some(list) = self.discovered_models.get(&format!("{:?}", provider)) {
            if !list.is_empty() {
                return list.clone();
            }
        }
        provider.preset_models().iter().map(|s| s.to_string()).collect()
    }

    pub fn has_discovered_models(&self, provider: AiProvider) -> bool {
        self.discovered_models
            .get(provider.name())
            .map(|l| !l.is_empty())
            .unwrap_or(false)
            || self
                .discovered_models
                .get(&format!("{:?}", provider))
                .map(|l| !l.is_empty())
                .unwrap_or(false)
    }

    pub fn get_provider_display_name(&self, provider: AiProvider) -> String {
        if provider == AiProvider::Custom {
            if let Some(name) = &self.custom_provider_name {
                let trimmed = name.trim();
                if !trimmed.is_empty() {
                    return format!("Custom ({trimmed})");
                }
            }
        }
        provider.name().to_string()
    }
}

