---
skill_id: "container-code-reachability"
name: "Container Isolation & Port Reachability Guard"
tier: "default"
target_languages: ["dockerfile", "yaml", "shell"]
trigger_conditions:
  files: ["Dockerfile", "docker-compose.yml", "compose.yaml"]
  patterns: ["EXPOSE", "0.0.0.0", "privileged: true", "USER root"]
required_mcp_tools: ["audit_dockerfile", "check_port_binding"]
---

# Container Isolation & Port Reachability Guard

## 1. Container Configuration Audit
1. Audit exposed container ports to ensure services do not bind to wildcard `0.0.0.0` unless explicitly intended.
2. Flag containers executing as default root user without a non-root `USER` directive.
3. Detect dangerous privilege escalation flags such as `--privileged` or sensitive volume mounts.

## 2. Hardening Strategy
Create a dedicated non-root application user and bind local network services strictly to `127.0.0.1`.
