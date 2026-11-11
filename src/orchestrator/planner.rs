use crate::types::WorkspaceProfile;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DefensePlan {
    pub strategy_name: String,
    pub target_summary: String,
    pub rules_applied: Vec<String>,
    pub phases: Vec<PlanPhase>,
}

#[allow(dead_code)]
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
            "Capability Jail Confinement (cap-std filesystem boundaries)".to_string(),
            "Pre-Execution Gate Evaluation (cedar-policy deny-by-default)".to_string(),
            "Shannon Entropy Credential Mining (git2 commit history traversal)".to_string(),
            "AST Code Context Reachability Analysis (Tflow = Sinput -> Dsink)".to_string(),
            "Phantom Dependency Detection (SCA manifest cross-audit)".to_string(),
            "Isolated Worktree Verification Sandbox (.asterisk/worktrees)".to_string(),
        ];

        if profile.has_docker {
            rules.push("Container Isolation Audit (Dockerfile configuration check)".to_string());
        }

        let mut phases = vec![
            PlanPhase {
                id: "phase_recon".to_string(),
                title: "1. Workspace Surface Reconnaissance".to_string(),
                subagent_role: "Orchestrator Core".to_string(),
                goal: "Map repository filesystem structure and detect active language toolchains.".to_string(),
            },
            PlanPhase {
                id: "phase_secrets".to_string(),
                title: "2. Cryptographic Secret & Entropy Audit".to_string(),
                subagent_role: "Secret Hunter".to_string(),
                goal: "Scan source files and Git commit log history for exposed API keys and high-entropy tokens.".to_string(),
            },
            PlanPhase {
                id: "phase_sast".to_string(),
                title: "3. Static Vulnerability & Reachability Analysis".to_string(),
                subagent_role: "SAST & Graph Engine".to_string(),
                goal: "Traverse AST nodes and call graph to trace untrusted user input to sensitive sinks.".to_string(),
            },
            PlanPhase {
                id: "phase_sca".to_string(),
                title: "4. Supply-Chain & Dependency Audit".to_string(),
                subagent_role: "SCA Dependency Auditor".to_string(),
                goal: "Cross-reference imported modules with manifests to prevent phantom dependency attacks.".to_string(),
            },
            PlanPhase {
                id: "phase_verify".to_string(),
                title: "5. Pre-Production Defense Gate Evaluation".to_string(),
                subagent_role: "Policy Gate".to_string(),
                goal: "Evaluate Cedar security policy in worktree sandbox prior to release authorization.".to_string(),
            },
        ];

        if profile.has_docker {
            phases.push(PlanPhase {
                id: "phase_container".to_string(),
                title: "6. Container Base Image Verification".to_string(),
                subagent_role: "Container Auditor".to_string(),
                goal: "Verify Dockerfile directives and non-root execution posture.".to_string(),
            });
        }

        DefensePlan {
            strategy_name: "Autonomous Pre-Production Defense Matrix".to_string(),
            target_summary: format!(
                "Target: {} file(s) across [{}] (Docker: {})",
                profile.total_files,
                profile.languages.join(", "),
                profile.has_docker
            ),
            rules_applied: rules,
            phases,
        }
    }
}

