use crate::types::AiProvider;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub provider: AiProvider,
    pub model: Option<String>,
    pub api_key: Option<String>,
    pub base_url: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            provider: AiProvider::AnthropicClaude,
            model: None,
            api_key: None,
            base_url: None,
        }
    }
}

impl AppConfig {
    pub fn config_path() -> PathBuf {
        if let Ok(home) = env::var("HOME") {
            let path = PathBuf::from(home).join(".config/constellation/config.json");
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            path
        } else {
            PathBuf::from(".constellation.json")
        }
    }

    pub fn load() -> Self {
        // 1. Try local workspace .constellation.json
        if let Ok(data) = fs::read_to_string(".constellation.json") {
            if let Ok(cfg) = serde_json::from_str::<AppConfig>(&data) {
                return cfg;
            }
        }

        // 2. Try ~/.config/constellation/config.json
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

    pub fn get_api_key(&self) -> Option<String> {
        if let Some(k) = &self.api_key {
            let trimmed = k.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }

        match self.provider {
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
    }

    pub fn get_base_url(&self) -> Option<String> {
        if let Some(u) = &self.base_url {
            let trimmed = u.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }

        if let Ok(u) = env::var("OPENAI_BASE_URL") {
            if !u.trim().is_empty() {
                return Some(u.trim().to_string());
            }
        }
        if let Ok(u) = env::var("AI_BASE_URL") {
            if !u.trim().is_empty() {
                return Some(u.trim().to_string());
            }
        }

        self.provider.default_base_url().map(|s| s.to_string())
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

    pub fn mask_key(&self) -> String {
        match self.get_api_key() {
            Some(k) if k.len() > 8 => {
                let prefix = &k[..4];
                let suffix = &k[k.len() - 4..];
                format!("{prefix}••••{suffix}")
            }
            Some(_) => "••••••••".to_string(),
            None => "None (Unset)".to_string(),
        }
    }
}

