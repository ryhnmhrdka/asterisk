---
skill_id: "owasp-sast-triage"
name: "OWASP SAST Triage & Taint Elimination"
tier: "default"
target_languages: ["typescript", "javascript", "python", "go", "rust", "java", "php"]
trigger_conditions:
  ast_edge_types: ["TAINT_SOURCE_TO_SINK"]
  sink_patterns: ["query", "raw", "execute", "exec", "eval", "system", "Command::new"]
required_mcp_tools: ["trace_taint_flow", "read_file_scoped", "run_sandbox_unit_test"]
---

# OWASP SAST Triage & Taint Elimination

## 1. Triage Protocol
1. Verify if user-controlled input reaches sensitive execution sinks (SQL, OS Command, Code Eval, Path Traversal).
2. Inspect `SECURITY.md` in workspace root to identify trusted middleware and input validation functions.
3. If an input passes through an approved validator, mark finding as `FALSE_POSITIVE` with technical reasoning.

## 2. Hardening Pattern
Convert dynamic string concatenations into parameterized statements or validated safe constructs.
