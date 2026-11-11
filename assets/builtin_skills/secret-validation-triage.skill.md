---
skill_id: "secret-validation-triage"
name: "Shannon Entropy & Secret Leak Validator"
tier: "default"
target_languages: ["all"]
trigger_conditions:
  entropy_threshold: 4.5
  secret_patterns: ["akias", "bearer", "private_key", "password", "token"]
required_mcp_tools: ["scan_git_history", "test_entropy_distribution"]
---

# Shannon Entropy & Secret Leak Validator

## 1. Secret Validation Protocol
1. Calculate character distribution Shannon entropy on detected strings.
2. Filter out known mock strings, test hashes, and UUIDs to minimize false positives.
3. Traverse git revision tree with `git2::Revwalk` to identify historical leak commits.

## 2. Hardening Strategy
Move credentials to environment variables, system secret managers, or `.env` files guarded in `.gitignore`.
