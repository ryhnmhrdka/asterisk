---
skill_id: "contextual-code-hardening"
name: "Contextual Code Hardening & Unified Diff Synthesizer"
tier: "default"
target_languages: ["typescript", "javascript", "python", "rust", "go", "java"]
trigger_conditions:
  verified_verdicts: ["TRUE_POSITIVE"]
required_mcp_tools: ["synthesize_diff", "verify_sandbox_build"]
---

# Contextual Code Hardening & Unified Diff Synthesizer

## 1. Patch Synthesis Guidelines
1. Synthesize minimal, non-breaking unified diff patches adhering to repository coding styles.
2. Preserve existing variable naming conventions and module export signatures.
3. Automatically generate accompanying unit test scripts to verify exploit resistance before applying changes.

## 2. Verification Protocol
Apply patch inside isolated `.asterisk/worktrees/wt-*` sandbox and run test suite before presenting patch to user.
