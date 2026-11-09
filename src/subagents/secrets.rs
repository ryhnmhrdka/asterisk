use crate::types::{Severity, VulnerabilityFinding};
use regex::Regex;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

pub struct SecretHunterAgent;

impl SecretHunterAgent {
    pub fn scan<P: AsRef<Path>>(root: P) -> Vec<VulnerabilityFinding> {
        let mut findings = Vec::new();
        let root_path = root.as_ref();

        let patterns = vec![
            (
                "AWS Access Key ID",
                Regex::new(r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}").unwrap(),
                Severity::Critical,
                "CWE-798",
                "Hardcoded AWS Cloud Access Key detected in source file.",
                "Extract secret into environment variable or AWS Secrets Manager / Vault."
            ),
            (
                "Private Encryption Key Block",
                Regex::new(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----").unwrap(),
                Severity::Critical,
                "CWE-312",
                "Unencrypted Private Key Block embedded directly in source code.",
                "Store private certificates in hardware security module (HSM) or secure key store."
            ),
            (
                "Hardcoded JWT Token",
                Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}").unwrap(),
                Severity::High,
                "CWE-798",
                "Hardcoded JSON Web Token (JWT) detected with static signature.",
                "Generate ephemeral JWTs via cryptographic signer with short TTL."
            ),
            (
                "Exposed Secret Variable Assignment",
                Regex::new(r#"(?i)(api_key|secret_key|jwt_secret|db_password|auth_token)\s*=\s*['"][a-zA-Z0-9_\-\.]{8,}['"]"#).unwrap(),
                Severity::High,
                "CWE-798",
                "Sensitive credential or password hardcoded into source code string literal.",
                "Replace hardcoded credential with dynamic runtime configuration (os.getenv/std::env)."
            ),
        ];

        for entry in WalkDir::new(root_path)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                !name.starts_with('.') && name != "target" && name != "node_modules" && name != "vendor"
            })
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();
            let relative_path = path.strip_prefix(root_path).unwrap_or(path);

            let raw_content = fs::read_to_string(path).or_else(|_| {
                fs::read(path).map(|b| String::from_utf8_lossy(&b).to_string())
            });

            if let Ok(content) = raw_content {
                for (idx, line) in content.lines().enumerate() {
                    for (name, re, sev, cwe, desc, rec) in &patterns {
                        if re.is_match(line) {
                            findings.push(VulnerabilityFinding {
                                id: format!("SEC-{:04}", findings.len() + 1),
                                title: format!("{}: {}", name, relative_path.display()),
                                cwe: cwe.to_string(),
                                severity: *sev,
                                file_path: relative_path.to_path_buf(),
                                line_number: idx + 1,
                                snippet: line.trim().to_string(),
                                description: desc.to_string(),
                                recommendation: rec.to_string(),
                                patched: false,
                            });
                        }
                    }
                }
            }
        }

        findings
    }
}

