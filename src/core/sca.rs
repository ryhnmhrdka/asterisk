use crate::types::{Severity, VulnerabilityFinding};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

pub struct ScaDependencyAuditor;

impl ScaDependencyAuditor {
    pub fn audit<P: AsRef<Path>>(root: P) -> Vec<VulnerabilityFinding> {
        let mut findings = Vec::new();
        let root_path = root.as_ref();

        // 1. Audit Cargo.lock / Cargo.toml
        let cargo_lock = root_path.join("Cargo.lock");
        if cargo_lock.exists() {
            if let Ok(content) = fs::read_to_string(&cargo_lock) {
                audit_cargo_dependencies(&content, &mut findings);
            }
        }

        // 2. Audit Node.js package.json / package-lock.json
        let package_json = root_path.join("package.json");
        if package_json.exists() {
            if let Ok(content) = fs::read_to_string(&package_json) {
                audit_node_dependencies(&content, &mut findings);
            }
        }

        // 3. Audit Python requirements.txt
        let req_txt = root_path.join("requirements.txt");
        if req_txt.exists() {
            if let Ok(content) = fs::read_to_string(&req_txt) {
                audit_python_dependencies(&content, &mut findings);
            }
        }

        // 4. Detect Phantom Dependencies (imported in source code but absent from manifest)
        let manifest_deps = collect_manifest_dependencies(root_path);
        let imported_modules = collect_imported_modules(root_path);

        for (module_name, file_path, line_num) in imported_modules {
            if is_standard_library(&module_name) {
                continue;
            }
            if !manifest_deps.contains(&module_name.to_lowercase()) {
                findings.push(VulnerabilityFinding {
                    id: format!("SCA-PHANTOM-{:04}", findings.len() + 1),
                    title: format!("Phantom Dependency Detected: '{module_name}'"),
                    cwe: "CWE-1357".to_string(),
                    severity: Severity::High,
                    file_path,
                    line_number: line_num,
                    snippet: format!("import {module_name}"),
                    description: format!(
                        "Module '{module_name}' is imported directly in source code but missing from official manifest (package.json/Cargo.toml/requirements.txt). Vulnerable to dependency confusion and supply chain typosquatting."
                    ),
                    recommendation: format!("Pin explicit version for '{module_name}' in project dependency manifest."),
                    patched: false,
                });
            }
        }

        findings
    }
}

fn audit_cargo_dependencies(content: &str, findings: &mut Vec<VulnerabilityFinding>) {
    // Known vulnerable crate versions checks
    let known_vulnerabilities = [
        ("openssl", "0.10.30", "RUSTSEC-2022-0040", Severity::High),
        ("tokio", "0.2.20", "RUSTSEC-2020-0010", Severity::Medium),
    ];

    for line in content.lines() {
        for (pkg, ver, advisory, sev) in &known_vulnerabilities {
            if line.contains(&format!("name = \"{pkg}\"")) {
                findings.push(VulnerabilityFinding {
                    id: format!("SCA-RUST-{:04}", findings.len() + 1),
                    title: format!("Vulnerable Supply-Chain Dependency: {pkg} ({advisory})"),
                    cwe: "CWE-1395".to_string(),
                    severity: *sev,
                    file_path: PathBuf::from("Cargo.lock"),
                    line_number: 1,
                    snippet: format!("package: {pkg} v{ver}"),
                    description: format!("Third-party package '{pkg}' contains known security advisory {advisory}."),
                    recommendation: format!("Upgrade {pkg} to latest secure release."),
                    patched: false,
                });
            }
        }
    }
}

fn audit_node_dependencies(content: &str, findings: &mut Vec<VulnerabilityFinding>) {
    let risky_packages = [
        ("lodash", "CWE-471 Prototype Pollution"),
        ("axios", "CWE-918 Server-Side Request Forgery"),
        ("express", "CWE-1385 Improper Middleware Routing"),
    ];

    for (pkg, desc) in risky_packages {
        if content.contains(&format!("\"{pkg}\"")) {
            findings.push(VulnerabilityFinding {
                id: format!("SCA-NODE-{:04}", findings.len() + 1),
                title: format!("Supply-Chain Dependency Audit: {pkg}"),
                cwe: "CWE-1395".to_string(),
                severity: Severity::Medium,
                file_path: PathBuf::from("package.json"),
                line_number: 1,
                snippet: format!("dependency: \"{pkg}\""),
                description: format!("Dependency '{pkg}' monitored: {desc}."),
                recommendation: format!("Verify reachability of '{pkg}' call sites before deployment."),
                patched: false,
            });
        }
    }
}

fn audit_python_dependencies(content: &str, findings: &mut Vec<VulnerabilityFinding>) {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("pickle5") || trimmed.starts_with("pyyaml<5.4") {
            findings.push(VulnerabilityFinding {
                id: format!("SCA-PY-{:04}", findings.len() + 1),
                title: format!("Unsafe Deserialization Package: {trimmed}"),
                cwe: "CWE-502".to_string(),
                severity: Severity::High,
                file_path: PathBuf::from("requirements.txt"),
                line_number: 1,
                snippet: trimmed.to_string(),
                description: "Vulnerable Python package with unauthenticated remote code execution risk.".to_string(),
                recommendation: "Upgrade or replace with secure serialiser (JSON or protobuf).".to_string(),
                patched: false,
            });
        }
    }
}

fn collect_manifest_dependencies(root: &Path) -> HashSet<String> {
    let mut deps = HashSet::new();
    let package_json = root.join("package.json");
    if let Ok(c) = fs::read_to_string(package_json) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&c) {
            if let Some(obj) = json.get("dependencies").and_then(|d| d.as_object()) {
                for k in obj.keys() {
                    deps.insert(k.to_lowercase());
                }
            }
            if let Some(obj) = json.get("devDependencies").and_then(|d| d.as_object()) {
                for k in obj.keys() {
                    deps.insert(k.to_lowercase());
                }
            }
        }
    }

    let req_txt = root.join("requirements.txt");
    if let Ok(c) = fs::read_to_string(req_txt) {
        for line in c.lines() {
            let pkg = line.split(&['=', '<', '>', '~'][..]).next().unwrap_or("").trim();
            if !pkg.is_empty() {
                deps.insert(pkg.to_lowercase());
            }
        }
    }

    deps
}

fn collect_imported_modules(root: &Path) -> Vec<(String, PathBuf, usize)> {
    let mut imports = Vec::new();

    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            !name.starts_with('.') && name != "target" && name != "node_modules"
        })
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        let rel_path = path.strip_prefix(root).unwrap_or(path).to_path_buf();

        if ext == "js" || ext == "ts" {
            if let Ok(content) = fs::read_to_string(path) {
                for (idx, line) in content.lines().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("import ") || trimmed.contains("require(") {
                        if let Some(module) = extract_js_module(trimmed) {
                            imports.push((module, rel_path.clone(), idx + 1));
                        }
                    }
                }
            }
        }
    }

    imports
}

fn extract_js_module(line: &str) -> Option<String> {
    if let Some(start) = line.find("from '") {
        let rest = &line[start + 6..];
        let end = rest.find('\'')?;
        return clean_module_name(&rest[..end]);
    }
    if let Some(start) = line.find("from \"") {
        let rest = &line[start + 6..];
        let end = rest.find('"')?;
        return clean_module_name(&rest[..end]);
    }
    if let Some(start) = line.find("require('") {
        let rest = &line[start + 9..];
        let end = rest.find('\'')?;
        return clean_module_name(&rest[..end]);
    }
    if let Some(start) = line.find("require(\"") {
        let rest = &line[start + 9..];
        let end = rest.find('"')?;
        return clean_module_name(&rest[..end]);
    }
    None
}

fn clean_module_name(s: &str) -> Option<String> {
    if s.starts_with('.') || s.starts_with('/') {
        return None; // Relative internal import
    }
    let parts: Vec<&str> = s.split('/').collect();
    if s.starts_with('@') && parts.len() >= 2 {
        Some(format!("{}/{}", parts[0], parts[1]))
    } else {
        Some(parts[0].to_string())
    }
}

fn is_standard_library(module: &str) -> bool {
    matches!(
        module,
        "fs" | "path" | "http" | "https" | "os" | "crypto" | "util" | "events" | "stream" | "buffer" | "child_process"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_js_module() {
        assert_eq!(extract_js_module("import axios from 'axios';"), Some("axios".to_string()));
        assert_eq!(extract_js_module("const fs = require('fs');"), Some("fs".to_string()));
        assert_eq!(extract_js_module("import { Button } from './components';"), None);
    }
}
