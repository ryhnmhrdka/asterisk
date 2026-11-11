---
skill_id: "malicious-package-heuristics"
name: "Phantom Dependency & Typosquatting Shield"
tier: "default"
target_languages: ["typescript", "javascript", "python", "rust"]
trigger_conditions:
  behavior_indicators: ["install_scripts", "obfuscated_eval", "domain_levenshtein"]
required_mcp_tools: ["audit_package_manifest", "query_registry_metadata"]
---

# Phantom Dependency & Typosquatting Shield

## 1. Phantom Dependency Detection
1. Compare all external package symbols imported in source files against manifest declared dependencies.
2. Flag any undeclared external package imports as `PHANTOM_DEP`.
3. Detect typosquatting using Levenshtein distance on top 1000 popular package namespaces.

## 2. Remediation Strategy
Explicitly pin package versions and declare verified dependency entries in lockfiles.
