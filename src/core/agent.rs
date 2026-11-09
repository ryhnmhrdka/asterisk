use crate::core::{
    policy::PolicyGate,
    rig_tools::{
        PolicyGateArgs, PolicyGateTool, ReachabilityArgs,
        ReachabilityTool, ScaAuditorArgs,
        ScaDependencyAuditorTool, SecretMinerArgs, SecretMinerTool,
    },
};
use crate::types::AiProvider;
use rig::completion::CompletionRequest;
use rig::providers::anthropic::wire::AnthropicConfig;
use rig::providers::gemini::GeminiConfig;
use rig::providers::ollama::wire::OllamaConfig;
use rig::providers::openai::wire::OpenAIConfig;
use rig::tool::PortableTool;
use std::path::PathBuf;
use std::sync::Arc;

pub struct SecurityAgentHub {
    pub target_dir: PathBuf,
    pub policy_gate: Arc<PolicyGate>,
    pub provider: AiProvider,
}

impl SecurityAgentHub {
    pub fn new(target_dir: PathBuf, policy_gate: Arc<PolicyGate>, provider: AiProvider) -> Self {
        Self {
            target_dir,
            policy_gate,
            provider,
        }
    }

    /// Primary entrypoint: asks the configured AI provider, with graceful fallback to
    /// deterministic local Rig tool execution and analysis if offline or unauthenticated.
    pub async fn query(&self, prompt: &str) -> String {
        match self.provider {
            AiProvider::AnthropicClaude => {
                if let Ok(config) = AnthropicConfig::from_env() {
                    let client = config.client();
                    let model = client.completion("claude-3-7-sonnet-20250219");
                    let req = CompletionRequest::new(format!(
                        "You are Constellation Security Agent. Workspace: {}\nUser Prompt: {}",
                        self.target_dir.display(),
                        prompt
                    ));
                    if let Ok(res) = model.call(req).await {
                        let text = res
                            .choice
                            .iter()
                            .filter_map(|c| match c {
                                rig::completion::message::AssistantContent::Text(t) => {
                                    Some(t.text.clone())
                                }
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join("\n");
                        if !text.is_empty() {
                            return text;
                        }
                    }
                }
            }
            AiProvider::OpenAiGpt4o => {
                if let Ok(config) = OpenAIConfig::from_env() {
                    let client = config.client();
                    let model = client.completion("gpt-4o");
                    let req = CompletionRequest::new(format!(
                        "You are Constellation Security Agent. Workspace: {}\nUser Prompt: {}",
                        self.target_dir.display(),
                        prompt
                    ));
                    if let Ok(res) = model.call(req).await {
                        let text = res
                            .choice
                            .iter()
                            .filter_map(|c| match c {
                                rig::completion::message::AssistantContent::Text(t) => {
                                    Some(t.text.clone())
                                }
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join("\n");
                        if !text.is_empty() {
                            return text;
                        }
                    }
                }
            }
            AiProvider::GoogleGemini => {
                if let Ok(config) = GeminiConfig::from_env() {
                    let client = config.client();
                    let model = client.completion("gemini-2.0-flash");
                    let req = CompletionRequest::new(format!(
                        "You are Constellation Security Agent. Workspace: {}\nUser Prompt: {}",
                        self.target_dir.display(),
                        prompt
                    ));
                    if let Ok(res) = model.call(req).await {
                        let text = res
                            .choice
                            .iter()
                            .filter_map(|c| match c {
                                rig::completion::message::AssistantContent::Text(t) => {
                                    Some(t.text.clone())
                                }
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join("\n");
                        if !text.is_empty() {
                            return text;
                        }
                    }
                }
            }
            AiProvider::OllamaLocal => {
                if let Ok(config) = OllamaConfig::from_env() {
                    let client = config.client();
                    let model = client.completion("llama3.2");
                    let req = CompletionRequest::new(format!(
                        "You are Constellation Security Agent. Workspace: {}\nUser Prompt: {}",
                        self.target_dir.display(),
                        prompt
                    ));
                    if let Ok(res) = model.call(req).await {
                        let text = res
                            .choice
                            .iter()
                            .filter_map(|c| match c {
                                rig::completion::message::AssistantContent::Text(t) => {
                                    Some(t.text.clone())
                                }
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join("\n");
                        if !text.is_empty() {
                            return text;
                        }
                    }
                }
            }
            AiProvider::DeepSeek => {
                // DeepSeek uses OpenAI-compatible endpoint
                if let Ok(mut config) = OpenAIConfig::from_env() {
                    config.base_url = "https://api.deepseek.com/v1".to_string();
                    let client = config.client();
                    let model = client.completion("deepseek-chat");
                    let req = CompletionRequest::new(prompt);
                    if let Ok(res) = model.call(req).await {
                        let text = res
                            .choice
                            .iter()
                            .filter_map(|c| match c {
                                rig::completion::message::AssistantContent::Text(t) => {
                                    Some(t.text.clone())
                                }
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join("\n");
                        if !text.is_empty() {
                            return text;
                        }
                    }
                }
            }
        }

        // Local Deterministic Rig-Tool Security Engine Fallback
        self.execute_local_security_triage(prompt).await
    }

    /// Local deterministic security triage executing our Rig tools
    pub async fn execute_local_security_triage(&self, prompt: &str) -> String {
        let p_lower = prompt.to_lowercase();

        // 1. AST Reachability Query
        if p_lower.contains("reachab") || p_lower.contains("taint") || p_lower.contains("sink") || p_lower.contains("dataflow") {
            let tool = ReachabilityTool::new(&self.target_dir);
            let res = tool
                .call(ReachabilityArgs {
                    source_id: "http_input".to_string(),
                    sink_id: "db_query".to_string(),
                })
                .await;

            return match res {
                Ok(r) => format!(
                    "### Call Graph & Reachability Evaluation\n- **Verdict**: `{}`\n- **Status**: {}\n- **Formula**: $T_{{reach}} = \\exists p \\in \\mathcal{{P}}(S_{{source}}, D_{{sink}})$\n- **Details**: {}",
                    r.verdict,
                    if r.is_reachable { "⚠️ Execution Path Confirmed" } else { "✓ Mitigated / Safe" },
                    r.details
                ),
                Err(e) => format!("Reachability analysis error: {e}"),
            };
        }

        // 2. Secret & Entropy Query
        if p_lower.contains("secret") || p_lower.contains("entropy") || p_lower.contains("key") || p_lower.contains("leak") {
            let tool = SecretMinerTool::new(&self.target_dir);
            let res = tool.call(SecretMinerArgs { max_commits: Some(30) }).await;

            return match res {
                Ok(r) => format!(
                    "### Secret Leak & Shannon Entropy Mining\n- **Total High-Entropy Secrets**: `{}`\n- **Formula**: $H(X) = -\\sum_{{i=1}}^n P(x_i) \\log_2 P(x_i)$\n- **Result**: {}",
                    r.findings_count,
                    r.details
                ),
                Err(e) => format!("Secret mining error: {e}"),
            };
        }

        // 3. SCA & Supply-chain Query
        if p_lower.contains("sca") || p_lower.contains("dep") || p_lower.contains("phantom") || p_lower.contains("package") || p_lower.contains("supply") {
            let tool = ScaDependencyAuditorTool::new(&self.target_dir);
            let res = tool.call(ScaAuditorArgs { check_phantom: Some(true) }).await;

            return match res {
                Ok(r) => format!(
                    "### Software Composition Analysis (SCA)\n- **Findings Count**: `{}`\n- **Manifests Checked**: `Cargo.toml`, `package.json`, `requirements.txt`\n- **Details**: {}",
                    r.findings_count,
                    r.details
                ),
                Err(e) => format!("SCA audit error: {e}"),
            };
        }

        // 4. Policy Gate Query
        if p_lower.contains("policy") || p_lower.contains("gate") || p_lower.contains("cedar") || p_lower.contains("permission") {
            let tool = PolicyGateTool::new(self.policy_gate.clone());
            let res = tool
                .call(PolicyGateArgs {
                    principal: "Agent::Triage".to_string(),
                    action: "Action::DeployPatch".to_string(),
                    resource: "Resource::ProductionCode".to_string(),
                })
                .await;

            return match res {
                Ok(r) => format!(
                    "### Cedar Pre-Execution Policy Gate\n- **Decision**: `{}`\n- **Allowed**: `{}`\n- **Reason**: {}",
                    r.decision,
                    r.is_allowed,
                    r.reason
                ),
                Err(e) => format!("Policy gate error: {e}"),
            };
        }

        // 5. General Security Summary
        let profile = crate::orchestrator::WorkspaceScanner::scan(&self.target_dir);
        let graph = crate::core::CodeContextGraph::build_from_workspace(&self.target_dir);

        format!(
            "### Pre-Production Code Defense Summary\n- **Active Provider**: `{}` (Offline Local Engine)\n- **Target Workspace**: `{}`\n- **Scanned Files**: `{}`\n- **AST Graph Vertices**: `{}`\n- **Call & Taint Edges**: `{}`\n\nAll tools (`cap-std` jail, `cedar-policy` gate, `git2` worktree sandbox, `petgraph` reachability) are operating within local boundaries.",
            self.provider.name(),
            self.target_dir.display(),
            profile.total_files,
            graph.total_nodes(),
            graph.total_edges()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_security_agent_hub_local_triage() {
        let dir = std::env::current_dir().unwrap();
        let gate = Arc::new(PolicyGate::new().expect("policy gate init"));
        let hub = SecurityAgentHub::new(dir, gate, AiProvider::OllamaLocal);

        let ans_reach = hub.query("check reachability and taint flows").await;
        assert!(ans_reach.contains("Call Graph & Reachability Evaluation"));

        let ans_secret = hub.query("mine commit history for leaked secrets").await;
        assert!(ans_secret.contains("Secret Leak & Shannon Entropy Mining"));

        let ans_sca = hub.query("scan dependency packages for phantom deps").await;
        assert!(ans_sca.contains("Software Composition Analysis"));

        let ans_policy = hub.query("evaluate policy gate with cedar").await;
        assert!(ans_policy.contains("Cedar Pre-Execution Policy Gate"));
    }
}
