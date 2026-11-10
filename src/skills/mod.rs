use crate::types::InteractiveSkill;

pub struct SkillRegistry {
    pub skills: Vec<InteractiveSkill>,
}

impl Default for SkillRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SkillRegistry {
    pub fn new() -> Self {
        let skills = vec![
            InteractiveSkill {
                id: "skill-entropy".to_string(),
                name: "Shannon Entropy Analyzer".to_string(),
                category: "Secret Detection".to_string(),
                description: "Calculates character distribution randomness to detect high-entropy crypto tokens, API keys, and hashes.".to_string(),
                invocations: 0,
                active: true,
            },
            InteractiveSkill {
                id: "skill-ast-sast".to_string(),
                name: "AST & Heuristic SAST Engine".to_string(),
                category: "Static Analysis".to_string(),
                description: "Deep source inspection for SQL injection, Command Injection, Path Traversal, and dangerous unsafe blocks.".to_string(),
                invocations: 0,
                active: true,
            },
            InteractiveSkill {
                id: "skill-net-audit".to_string(),
                name: "Network Surface Linter".to_string(),
                category: "Network & Config".to_string(),
                description: "Inspects bind addresses (0.0.0.0), CORS wildcard headers (*), missing TLS configurations, and dev ports.".to_string(),
                invocations: 0,
                active: true,
            },
            InteractiveSkill {
                id: "skill-patcher".to_string(),
                name: "Auto-Hardening Patch Synthesizer".to_string(),
                category: "Remediation".to_string(),
                description: "Generates unified diffs and non-breaking defense code transformations (prepared statements, sanitizers).".to_string(),
                invocations: 0,
                active: true,
            },
            InteractiveSkill {
                id: "skill-test-synth".to_string(),
                name: "Automated Unit Test Generator".to_string(),
                category: "Verification".to_string(),
                description: "Synthesizes targeted exploit-verification unit tests to prove mitigation integrity before build/deploy.".to_string(),
                invocations: 0,
                active: true,
            },
            InteractiveSkill {
                id: "skill-self-heal".to_string(),
                name: "Agentic Self-Healing & Improvisation".to_string(),
                category: "Dynamic Execution".to_string(),
                description: "Dynamically recovers from failed parser passes, adjusts regex/heuristics on compiler feedback, and retries.".to_string(),
                invocations: 0,
                active: true,
            },
        ];
        Self { skills }
    }

    #[allow(dead_code)]
    pub fn record_invocation(&mut self, skill_id: &str) {
        if let Some(skill) = self.skills.iter_mut().find(|s| s.id == skill_id) {
            skill.invocations += 1;
        }
    }
}

