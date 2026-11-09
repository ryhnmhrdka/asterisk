use crate::types::{Severity, VulnerabilityFinding};
use regex::Regex;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

pub struct SastAnalyzerAgent;

impl SastAnalyzerAgent {
    pub fn scan<P: AsRef<Path>>(root: P) -> Vec<VulnerabilityFinding> {
        let mut findings = Vec::new();
        let root_path = root.as_ref();

        let rules = vec![
            (
                "SQL Injection (Dynamic Query Concatenation)",
                Regex::new(r#"(?i)(SELECT|INSERT|UPDATE|DELETE).*\+.*req\.|f"(SELECT|INSERT|UPDATE|DELETE).*\{|execute\([f"'].*(\+|%s|\{)"#).unwrap(),
                Severity::Critical,
                "CWE-89",
                "Unparameterized SQL query constructed via string concatenation or f-strings.",
                "Use parameterized queries or prepared statements (e.g. cursor.execute(query, (params,))) to prevent injection."
            ),
            (
                "Arbitrary Command Injection (Shell Invocation)",
                Regex::new(r#"(?i)os\.system\(|subprocess\.(call|Popen|run)\(.*shell\s*=\s*True|Runtime\.getRuntime\(\)\.exec\(|child_process\.exec\("#).unwrap(),
                Severity::Critical,
                "CWE-78",
                "Operating system command executed through shell interpreter with potential tainted input.",
                "Avoid shell invocation. Pass arguments as an array/vector directly to the executable or use safe APIs."
            ),
            (
                "Path Traversal (Unsanitized File Access)",
                Regex::new(r#"(?i)(open|readFile|createReadStream|fs\.readFileSync)\(.*(req\.query|req\.params|user_input|filename)"#).unwrap(),
                Severity::High,
                "CWE-22",
                "File path constructed from unvalidated user input allowing directory traversal outside sandbox.",
                "Sanitize path using canonicalization and verify the target path resides within an allowed root directory."
            ),
            (
                "Insecure Dynamic Code Execution (eval)",
                Regex::new(r#"(?i)\beval\(|\bFunction\(.*req\."#).unwrap(),
                Severity::Critical,
                "CWE-95",
                "Dynamic code evaluation (eval) allows execution of untrusted input as program code.",
                "Replace dynamic eval with structured parsers (e.g., JSON.parse or dedicated mathematical expression evaluators)."
            ),
            (
                "Insecure Object Deserialization",
                Regex::new(r#"(?i)pickle\.loads\(|yaml\.load\(.*Loader\s*=\s*(yaml\.)?Loader"#).unwrap(),
                Severity::High,
                "CWE-502",
                "Deserialization of untrusted data can lead to arbitrary remote code execution.",
                "Use safe formats like JSON or safe loaders (e.g., yaml.safe_load, protobuf)."
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
                    for (title, re, sev, cwe, desc, rec) in &rules {
                        if re.is_match(line) {
                            findings.push(VulnerabilityFinding {
                                id: format!("SAST-{:04}", findings.len() + 1),
                                title: format!("{}: {}", title, relative_path.display()),
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

