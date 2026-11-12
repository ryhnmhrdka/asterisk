use crate::types::AiProvider;
use serde_json::Value;
use std::time::Duration;

/// Fetch available models directly from provider REST API using the configured API key and base URL.
pub async fn fetch_live_models(
    provider: AiProvider,
    api_key: Option<&str>,
    custom_base_url: Option<&str>,
) -> Result<Vec<String>, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let mut models = Vec::new();

    match provider {
        AiProvider::OpenAiGpt4o => {
            let key = api_key.ok_or_else(|| "OpenAI API key is missing".to_string())?;
            let base = custom_base_url
                .unwrap_or("https://api.openai.com/v1")
                .trim_end_matches('/');
            let url = format!("{base}/models");

            let res = client
                .get(&url)
                .header("Authorization", format!("Bearer {key}"))
                .send()
                .await
                .map_err(|e| format!("Failed to connect to OpenAI ({url}): {e}"))?;

            if !res.status().is_success() {
                let status = res.status();
                let err_text = res.text().await.unwrap_or_default();
                return Err(format!("OpenAI API returned HTTP {status}: {err_text}"));
            }

            let json: Value = res
                .json()
                .await
                .map_err(|e| format!("Invalid JSON from OpenAI: {e}"))?;

            if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                for item in data {
                    if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                        // Filter for relevant GPT & reasoning models
                        if id.contains("gpt") || id.contains("o1") || id.contains("o3") || id.contains("chat") {
                            models.push(id.to_string());
                        }
                    }
                }
            }
        }

        AiProvider::GoogleGemini => {
            let key = api_key.ok_or_else(|| "Google Gemini API key is missing".to_string())?;
            let url = format!("https://generativelanguage.googleapis.com/v1beta/models?key={key}");

            let res = client
                .get(&url)
                .send()
                .await
                .map_err(|e| format!("Failed to connect to Gemini API: {e}"))?;

            if !res.status().is_success() {
                let status = res.status();
                let err_text = res.text().await.unwrap_or_default();
                return Err(format!("Gemini API returned HTTP {status}: {err_text}"));
            }

            let json: Value = res
                .json()
                .await
                .map_err(|e| format!("Invalid JSON from Gemini: {e}"))?;

            if let Some(items) = json.get("models").and_then(|m| m.as_array()) {
                for item in items {
                    if let Some(name) = item.get("name").and_then(|v| v.as_str()) {
                        // Strip 'models/' prefix: e.g. "models/gemini-2.0-flash" -> "gemini-2.0-flash"
                        let clean_name = name.strip_prefix("models/").unwrap_or(name);
                        if clean_name.contains("gemini") {
                            models.push(clean_name.to_string());
                        }
                    }
                }
            }
        }

        AiProvider::AnthropicClaude => {
            let key = api_key.ok_or_else(|| "Anthropic API key is missing".to_string())?;
            let url = "https://api.anthropic.com/v1/models";

            let res = client
                .get(url)
                .header("x-api-key", key)
                .header("anthropic-version", "2023-06-01")
                .send()
                .await
                .map_err(|e| format!("Failed to connect to Anthropic API: {e}"))?;

            if !res.status().is_success() {
                let status = res.status();
                let err_text = res.text().await.unwrap_or_default();
                return Err(format!("Anthropic API returned HTTP {status}: {err_text}"));
            }

            let json: Value = res
                .json()
                .await
                .map_err(|e| format!("Invalid JSON from Anthropic: {e}"))?;

            if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                for item in data {
                    if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                        models.push(id.to_string());
                    }
                }
            }
        }

        AiProvider::DeepSeek => {
            let key = api_key.ok_or_else(|| "DeepSeek API key is missing".to_string())?;
            let base = custom_base_url
                .unwrap_or("https://api.deepseek.com")
                .trim_end_matches('/');
            let url = format!("{base}/models");

            let res = client
                .get(&url)
                .header("Authorization", format!("Bearer {key}"))
                .send()
                .await
                .map_err(|e| format!("Failed to connect to DeepSeek ({url}): {e}"))?;

            if !res.status().is_success() {
                let status = res.status();
                let err_text = res.text().await.unwrap_or_default();
                return Err(format!("DeepSeek API returned HTTP {status}: {err_text}"));
            }

            let json: Value = res
                .json()
                .await
                .map_err(|e| format!("Invalid JSON from DeepSeek: {e}"))?;

            if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                for item in data {
                    if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                        models.push(id.to_string());
                    }
                }
            }
        }

        AiProvider::OllamaLocal => {
            let base = custom_base_url
                .unwrap_or("http://localhost:11434")
                .trim_end_matches('/');
            let url = format!("{base}/api/tags");

            let res = client
                .get(&url)
                .send()
                .await
                .map_err(|e| format!("Failed to connect to local Ollama daemon at {url}: {e}"))?;

            if !res.status().is_success() {
                let status = res.status();
                return Err(format!("Ollama daemon returned HTTP {status}"));
            }

            let json: Value = res
                .json()
                .await
                .map_err(|e| format!("Invalid JSON from Ollama: {e}"))?;

            if let Some(items) = json.get("models").and_then(|m| m.as_array()) {
                for item in items {
                    if let Some(name) = item.get("name").and_then(|v| v.as_str()) {
                        models.push(name.to_string());
                    }
                }
            }
        }

        AiProvider::Custom => {
            let base = custom_base_url
                .unwrap_or("http://localhost:8000/v1")
                .trim_end_matches('/');
            let url = format!("{base}/models");

            let mut req = client.get(&url);
            if let Some(key) = api_key {
                if !key.trim().is_empty() {
                    req = req.header("Authorization", format!("Bearer {key}"));
                }
            }

            let res = req
                .send()
                .await
                .map_err(|e| format!("Failed to connect to custom endpoint ({url}): {e}"))?;

            if !res.status().is_success() {
                let status = res.status();
                return Err(format!("Custom endpoint returned HTTP {status}"));
            }

            let json: Value = res
                .json()
                .await
                .map_err(|e| format!("Invalid JSON from custom endpoint: {e}"))?;

            if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                for item in data {
                    if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                        models.push(id.to_string());
                    }
                }
            }
        }
    }

    // Sort and deduplicate
    models.sort();
    models.dedup();

    if models.is_empty() {
        Err(format!("No matching models found in {} API response", provider.name()))
    } else {
        Ok(models)
    }
}
