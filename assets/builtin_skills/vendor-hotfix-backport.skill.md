---
skill_id: "vendor-hotfix-backport"
name: "Vendor Hotfix Backport & Minimal Remediation"
tier: "default"
target_languages: ["all"]
trigger_conditions:
  action: "VENDOR_HOTFIX_BACKPORT"
required_mcp_tools: ["fetch_upstream_commit", "cherry_pick_patch", "test_sandbox_suite"]
---

# Vendor Hotfix Backport & Minimal Remediation

## 1. Upstream Patch Ingestion
1. Ingest upstream security fixes for libraries where major version upgrades introduce breaking API changes.
2. Backport only the targeted vulnerability remediation hunk directly into vendor/worktree copy.
3. Validate that runtime interfaces and public ABI remain 100% binary-compatible.

## 2. Regression Avoidance
Execute test suite in isolated git worktree to confirm zero regression on dependents.
