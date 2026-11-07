use crate::types::WorkspaceProfile;

#[derive(Debug, Clone)]
pub struct DefensePlan {
    pub strategy_name: String,
    pub target_summary: String,
    pub rules_applied: Vec<String>,
    pub phases: Vec<PlanPhase>,
}

#[derive(Debug, Clone)]
pub struct PlanPhase {
    pub id: String,
    pub title: String,
    pub subagent_role: String,
    pub goal: String,
}

pub struct StrategyPlanner;

impl StrategyPlanner {
    pub fn create_plan(profile: &WorkspaceProfile) -> DefensePlan {
        let mut rules = vec![
            "OWASP Top 10 (2025/2026 Edition) Pre-Build Enforcement".to_string(),
            "CWE-798: No Hardcoded Cryptographic Keys or Tokens".to_string(),
            "CWE-89/78: Strict Input Sanitization & Parameterization".to_string(),
            "CWE-942: Zero-Trust Permissive CORS Prevention".to_string(),
            "Pre-Deployment Automated Unit Test Verification Guarantee".to_string(),
        ];

        if profile.has_docker {
            rules.push("CIS Docker Benchmark: Rootless & Secure Base Policy".to_string());
        }
        if profile.has_mobile {
            rules.push("OWASP Mobile Top 10: Insecure Storage & Communication Audit".to_string());
        }

        let phases = vec![
            PlanPhase {
                id: "phase_recon".to_string(),
                title: "1. Target Recon & Surface Mapping".to_string(),
                subagent_role: "Orchestrator General Agent".to_string(),
                goal: "Analyze folder layout, language stacks, and configure active subagents.".to_string(),
            },
            PlanPhase {
                id: "phase_secrets".to_string(),
                title: "2. Secret & Credential Hunter".to_string(),
                subagent_role: "SecretHunter SubAgent".to_string(),
                goal: "Scan files and environment templates for leaked keys, JWTs, and high-entropy credentials.".to_string(),
            },
            PlanPhase {
                id: "phase_sast".to_string(),
                title: "3. SAST Vulnerability Deep Scan".to_string(),
                subagent_role: "SastAnalyzer SubAgent".to_string(),
                goal: "Inspect AST/regex code paths for Command Injection, SQLi, and Path Traversal.".to_string(),
            },
            PlanPhase {
                id: "phase_net".to_string(),
                title: "4. Network & Exposure Audit".to_string(),
                subagent_role: "NetworkProber SubAgent".to_string(),
                goal: "Detect dangerous 0.0.0.0 binds, CORS wildcards, and unencrypted transports.".to_string(),
            },
            PlanPhase {
                id: "phase_patch".to_string(),
                title: "5. Auto-Hardening Patch Generation".to_string(),
                subagent_role: "AutoHardening SubAgent".to_string(),
                goal: "Synthesize immediate unified diff code patches for identified security vulnerabilities.".to_string(),
            },
            PlanPhase {
                id: "phase_verify".to_string(),
                title: "6. Unit Test Synthesizer & Verification".to_string(),
                subagent_role: "Verification SubAgent".to_string(),
                goal: "Synthesize unit test cases ensuring defense patches withstand exploits without regressions.".to_string(),
            },
        ];

        DefensePlan {
            strategy_name: "Autonomous Pre-Production Defense Matrix".to_string(),
            target_summary: format!(
                "Scanned {} files across [{}] (Docker: {}, Mobile: {})",
                profile.total_files,
                profile.languages.join(", "),
                profile.has_docker,
                profile.has_mobile
            ),
            rules_applied: rules,
            phases,
        }
    }
}

