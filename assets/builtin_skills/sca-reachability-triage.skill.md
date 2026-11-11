---
skill_id: "sca-reachability-triage"
name: "SCA Dependency Reachability Analysis"
tier: "default"
target_languages: ["typescript", "javascript", "python", "rust", "go", "java"]
trigger_conditions:
  manifest_files: ["package.json", "Cargo.toml", "requirements.txt", "pom.xml", "go.mod"]
  check_types: ["CVE_REACHABILITY", "TRANSITIVE_CALL_PATH"]
required_mcp_tools: ["audit_dependencies", "trace_call_graph", "sandbox_patch_apply"]
---

# SCA Dependency Reachability Analysis

## 1. Reachability Triage
1. Classify CVE vulnerability reachability as `REACHABLE`, `POTENTIALLY_REACHABLE`, or `UNREACHABLE`.
2. Trace BFS call graph from entrypoints to determine whether vulnerable third-party symbols are actually invoked.
3. Filter out transitive library vulnerabilities if zero code paths intersect the affected package methods.

## 2. Remediation Strategy
Upgrade to nearest patch version or backport non-breaking security patches without breaking API contracts.
