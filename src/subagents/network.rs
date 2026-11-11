use crate::types::{Severity, VulnerabilityFinding};
use regex::Regex;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

pub struct NetworkProberAgent;

impl NetworkProberAgent {
    pub fn scan<P: AsRef<Path>>(root: P) -> Vec<VulnerabilityFinding> {
        let mut findings = Vec::new();
        let root_path = root.as_ref();

        let rules = vec![
            (
                "Insecure Wildcard Host Binding (0.0.0.0)",
                Regex::new(r#"(?i)(host|bind|listen|address)\s*[:=]\s*['"]0\.0\.0\.0['"]|\.listen\([0-9]+,\s*['"]0\.0\.0\.0['"]"#).unwrap(),
                Severity::High,
                "CWE-1327",
                "Service binds to all network interfaces (0.0.0.0), exposing internal endpoints to local networks before hardening.",
                "Bind to loopback interface 127.0.0.1 for local development or configure explicit ingress proxy with authentication."
            ),
            (
                "Permissive CORS Wildcard Policy (*)",
                Regex::new(r#"(?i)Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]\*['"]|cors\(\s*\{\s*origin:\s*['"]\*['"]"#).unwrap(),
                Severity::High,
                "CWE-942",
                "Overly permissive Cross-Origin Resource Sharing (CORS) wildcard (*) allows any external domain to issue cross-origin requests.",
                "Specify explicit allowed domain origins and never use wildcard origins with authenticated session cookies."
            ),
            (
                "TLS Verification Explicitly Disabled",
                Regex::new(r#"(?i)verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?|InsecureSkipVerify\s*:\s*true"#).unwrap(),
                Severity::Critical,
                "CWE-295",
                "SSL/TLS certificate validation is disabled, enabling Man-in-the-Middle (MitM) attacks.",
                "Enable full certificate chain validation with trusted system CA authorities."
            ),
            (
                "Cleartext Insecure HTTP Transport",
                Regex::new(r#"['"]http://(api\.|auth\.|login\.|backend\.)"#).unwrap(),
                Severity::Medium,
                "CWE-319",
                "Sensitive communication transmitted over cleartext HTTP without transport encryption.",
                "Enforce HTTPS for all external API and authentication endpoints."
            ),
        ];

        for entry in WalkDir::new(root_path)
            .into_iter()
            .filter_entry(|e| {
                if e.path() == root_path {
                    return true;
                }
                let name = e.file_name().to_string_lossy();
                !name.starts_with('.')
                    && name != "target"
                    && name != "node_modules"
                    && name != "vendor"
                    && name != "reference"
                    && name != "fixtures"
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
                    let trimmed = line.trim();
                    // Ignore analyzer rule definitions, string checks, and regex builders
                    if trimmed.starts_with("Regex::new")
                        || trimmed.starts_with("r#\"")
                        || trimmed.contains(".replace(")
                        || trimmed.contains(".contains(\"")
                        || trimmed.starts_with("//")
                    {
                        continue;
                    }

                    for (title, re, sev, cwe, desc, rec) in &rules {
                        if re.is_match(line) {
                            findings.push(VulnerabilityFinding {
                                id: format!("NET-{:04}", findings.len() + 1),
                                title: format!("{}: {}", title, relative_path.display()),
                                cwe: cwe.to_string(),
                                severity: *sev,
                                file_path: relative_path.to_path_buf(),
                                line_number: idx + 1,
                                snippet: line.trim().to_string(),
                                description: desc.to_string(),
                                recommendation: rec.to_string(),
                                patched: false,
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }

        findings
    }
}

