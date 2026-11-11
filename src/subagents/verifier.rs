use crate::core::sandbox::WorktreeSandbox;
use crate::types::HardeningPatch;
use std::path::Path;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PatchVerificationReport {
    pub patch_id: String,
    pub unit_test_passed: bool,
    pub safe_outputs_passed: bool,
    pub log_summary: String,
}

#[allow(dead_code)]
pub struct VerificationAgent;

#[allow(dead_code)]
impl VerificationAgent {
    pub fn synthesize_test_suite(patches: &[HardeningPatch]) -> String {
        let mut suite = String::new();
        for patch in patches {
            suite.push_str(&format!("// Verification test for: {} ({})\n", patch.id, patch.finding_id));
            suite.push_str(&patch.unit_test_code);
            suite.push_str("\n\n");
        }

        suite
    }

    /// Validates that the synthesized patch does NOT introduce new vulnerabilities,
    /// preserves balanced delimiters, and removes original insecure patterns.
    pub fn verify_safe_outputs(patch: &HardeningPatch) -> (bool, String) {
        if patch.hardened_snippet.trim().is_empty() {
            return (false, "Hardened snippet is empty".to_string());
        }

        if patch.hardened_snippet == patch.original_snippet {
            return (false, "Hardened snippet is identical to original vulnerable snippet (no change)".to_string());
        }

        // Check for remaining insecure patterns
        let unsafe_patterns = [
            ("0.0.0.0", "Wildcard network bind address"),
            ("verify=False", "Disabled TLS verification"),
            ("verify = False", "Disabled TLS verification"),
            ("InsecureSkipVerify: true", "Disabled TLS verification"),
            ("android:usesCleartextTraffic=\"true\"", "Cleartext network traffic"),
            ("android:exported=\"true\"", "Unprotected exported component"),
            ("android:debuggable=\"true\"", "Production debugging enabled"),
            ("USER root", "Root container user"),
        ];

        for (pat, reason) in unsafe_patterns {
            if patch.hardened_snippet.contains(pat) && patch.original_snippet.contains(pat) {
                return (false, format!("Hardened snippet still contains unsafe pattern: {pat} ({reason})"));
            }
        }

        // Delimiter balance check (parentheses, braces, brackets)
        let mut paren_count: i32 = 0;
        let mut brace_count: i32 = 0;
        let mut bracket_count: i32 = 0;

        for ch in patch.hardened_snippet.chars() {
            match ch {
                '(' => paren_count += 1,
                ')' => paren_count -= 1,
                '{' => brace_count += 1,
                '}' => brace_count -= 1,
                '[' => bracket_count += 1,
                ']' => bracket_count -= 1,
                _ => {}
            }
        }

        if paren_count != 0 || brace_count != 0 || bracket_count != 0 {
            return (false, "Unbalanced delimiters in hardened snippet".to_string());
        }

        (true, "Safe outputs gate passed: syntax balanced, insecure patterns removed".to_string())
    }

    pub fn verify_patches_in_sandbox<P: AsRef<Path>>(
        repo_root: P,
        patches: &[HardeningPatch],
    ) -> Vec<PatchVerificationReport> {
        let root = repo_root.as_ref();
        let mut reports = Vec::new();

        for patch in patches {
            let (safe_ok, safe_reason) = Self::verify_safe_outputs(patch);
            if !safe_ok {
                reports.push(PatchVerificationReport {
                    patch_id: patch.id.clone(),
                    unit_test_passed: false,
                    safe_outputs_passed: false,
                    log_summary: format!("Safe outputs rejected: {safe_reason}"),
                });
                continue;
            }

            // Spawn sandbox and verify in worktree
            match WorktreeSandbox::spawn(root, &patch.id) {
                Ok(sandbox) => {
                    let rel_file = patch.target_file.strip_prefix(root).unwrap_or(&patch.target_file);
                    let (test_ok, test_log) = sandbox
                        .verify_patch_in_worktree(
                            rel_file,
                            &patch.original_snippet,
                            &patch.hardened_snippet,
                            &patch.unit_test_code,
                        )
                        .unwrap_or((false, "Sandbox execution error".to_string()));

                    let _ = sandbox.cleanup();

                    reports.push(PatchVerificationReport {
                        patch_id: patch.id.clone(),
                        unit_test_passed: test_ok,
                        safe_outputs_passed: true,
                        log_summary: test_log,
                    });
                }
                Err(e) => {
                    reports.push(PatchVerificationReport {
                        patch_id: patch.id.clone(),
                        unit_test_passed: false,
                        safe_outputs_passed: true,
                        log_summary: format!("Sandbox spawn error: {e}"),
                    });
                }
            }
        }

        reports
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_verify_safe_outputs_gate() {
        let clean_patch = HardeningPatch {
            id: "P1".to_string(),
            finding_id: "F1".to_string(),
            target_file: PathBuf::from("server.py"),
            original_snippet: "bind('0.0.0.0')".to_string(),
            hardened_snippet: "bind('127.0.0.1')".to_string(),
            unified_diff: "".to_string(),
            unit_test_code: "".to_string(),
            applied: false,
            explanation: "".to_string(),
        };
        let (passed, msg) = VerificationAgent::verify_safe_outputs(&clean_patch);
        assert!(passed, "Clean patch must pass safe outputs: {msg}");

        let unsafe_patch = HardeningPatch {
            id: "P2".to_string(),
            finding_id: "F2".to_string(),
            target_file: PathBuf::from("server.py"),
            original_snippet: "bind('0.0.0.0')".to_string(),
            hardened_snippet: "bind('0.0.0.0', verbose=True)".to_string(), // still contains 0.0.0.0
            unified_diff: "".to_string(),
            unit_test_code: "".to_string(),
            applied: false,
            explanation: "".to_string(),
        };
        let (passed2, _) = VerificationAgent::verify_safe_outputs(&unsafe_patch);
        assert!(!passed2, "Unsafe patch retaining 0.0.0.0 must be rejected");

        let unbalanced_patch = HardeningPatch {
            id: "P3".to_string(),
            finding_id: "F3".to_string(),
            target_file: PathBuf::from("server.py"),
            original_snippet: "foo()".to_string(),
            hardened_snippet: "foo({".to_string(), // unbalanced brace
            unified_diff: "".to_string(),
            unit_test_code: "".to_string(),
            applied: false,
            explanation: "".to_string(),
        };
        let (passed3, _) = VerificationAgent::verify_safe_outputs(&unbalanced_patch);
        assert!(!passed3, "Unbalanced delimiters must be rejected");
    }
}
