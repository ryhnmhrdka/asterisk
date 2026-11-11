use cedar_policy::{Authorizer, Decision, Entities, EntityUid, PolicySet, Request};
use std::str::FromStr;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    Allow,
    AskUser(String),
    Deny(String),
}

#[allow(dead_code)]
pub struct PolicyGate {
    authorizer: Authorizer,
    policies: PolicySet,
    entities: Entities,
}

#[allow(dead_code)]
impl PolicyGate {
    pub fn new() -> Result<Self, String> {
        let default_policy_src = r#"
            // Allow agents to read files within the workspace
            permit(
                principal in Role::"Agent",
                action == Action::"ReadFile",
                resource
            );

            // Permit writing files only when explicitly operating in sandbox
            permit(
                principal == Role::"PatcherAgent",
                action == Action::"WriteSandboxFile",
                resource
            );

            // Forbid any direct system modification or out-of-scope actions
            forbid(
                principal,
                action == Action::"ExecuteShellCommand",
                resource
            );
        "#;

        let policies = PolicySet::from_str(default_policy_src)
            .map_err(|e| format!("Failed to parse default Cedar policies: {e}"))?;

        Ok(Self {
            authorizer: Authorizer::new(),
            policies,
            entities: Entities::empty(),
        })
    }

    pub fn evaluate(
        &self,
        agent_role: &str,
        action: &str,
        resource_path: &str,
    ) -> GateDecision {
        // Immediate hard block on sensitive system paths or directory traversals
        if resource_path.contains("../") || resource_path.starts_with("/etc") || resource_path.starts_with("/root") {
            return GateDecision::Deny(format!("Security boundary violation: target path '{resource_path}' blocked."));
        }

        let principal_str = format!("Role::\"{}\"", agent_role);
        let action_str = format!("Action::\"{}\"", action);
        let resource_str = format!("Resource::\"{}\"", resource_path.replace('"', ""));

        let principal = match EntityUid::from_str(&principal_str) {
            Ok(uid) => uid,
            Err(e) => return GateDecision::Deny(format!("Invalid principal format: {e}")),
        };
        let action_uid = match EntityUid::from_str(&action_str) {
            Ok(uid) => uid,
            Err(e) => return GateDecision::Deny(format!("Invalid action format: {e}")),
        };
        let resource = match EntityUid::from_str(&resource_str) {
            Ok(uid) => uid,
            Err(e) => return GateDecision::Deny(format!("Invalid resource format: {e}")),
        };

        let request = match Request::new(principal, action_uid, resource, cedar_policy::Context::empty(), None) {
            Ok(req) => req,
            Err(e) => return GateDecision::Deny(format!("Failed to build Cedar request: {e}")),
        };

        let response = self.authorizer.is_authorized(&request, &self.policies, &self.entities);

        match response.decision() {
            Decision::Allow => GateDecision::Allow,
            Decision::Deny => {
                if action == "ExecuteShellCommand" || action == "ApplyCodePatch" {
                    GateDecision::AskUser(format!("Operation '{action}' on '{resource_path}' requires user authorization."))
                } else {
                    GateDecision::Deny(format!("Cedar policy rejected action '{action}' on '{resource_path}'."))
                }
            }
        }
    }
}

impl Default for PolicyGate {
    fn default() -> Self {
        Self::new().expect("Failed to initialize default Cedar policy set")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cedar_policy_evaluation() {
        let gate = PolicyGate::new().expect("Must create policy gate");
        assert_eq!(
            gate.evaluate("PatcherAgent", "WriteSandboxFile", ".asterisk/worktrees/wt-1"),
            GateDecision::Allow
        );
        assert_eq!(
            gate.evaluate("Agent", "ReadFile", "src/main.rs"),
            GateDecision::Allow
        );
        match gate.evaluate("Agent", "ExecuteShellCommand", "rm -rf /") {
            GateDecision::Deny(_) | GateDecision::AskUser(_) => {}
            _ => panic!("Must not allow shell execution"),
        }
    }
}
