#![allow(dead_code)]

use crate::types::{Severity, VulnerabilityFinding};
use std::fs;
use std::path::Path;

pub struct ApkAndContainerGuardAgent;

impl ApkAndContainerGuardAgent {
    pub fn scan<P: AsRef<Path>>(root: P) -> Vec<VulnerabilityFinding> {
        let root_path = root.as_ref();
        let mut findings = Vec::new();

        for entry in walkdir::WalkDir::new(root_path)
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
            let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");

            // 1. Android Manifest Audit
            if file_name == "AndroidManifest.xml" {
                if let Ok(content) = fs::read_to_string(path) {
                    Self::audit_android_manifest(path, &content, &mut findings);
                }
            }

            // 2. Android Source (Kotlin/Java) WebView & Intent Audit
            if ext == "kt" || ext == "java" {
                if let Ok(content) = fs::read_to_string(path) {
                    Self::audit_android_code(path, &content, &mut findings);
                }
            }

            // 3. Dockerfile Audit
            if file_name == "Dockerfile" || file_name.ends_with(".dockerfile") {
                if let Ok(content) = fs::read_to_string(path) {
                    Self::audit_dockerfile(path, &content, &mut findings);
                }
            }

            // 4. Docker Compose Audit
            if file_name == "docker-compose.yml" || file_name == "compose.yaml" || file_name == "compose.yml" {
                if let Ok(content) = fs::read_to_string(path) {
                    Self::audit_docker_compose(path, &content, &mut findings);
                }
            }
        }

        findings
    }

    fn audit_android_manifest(path: &Path, content: &str, findings: &mut Vec<VulnerabilityFinding>) {
        let lines: Vec<&str> = content.lines().collect();

        // Check cleartext traffic
        if content.contains("android:usesCleartextTraffic=\"true\"") || content.contains("cleartextTrafficPermitted=\"true\"") {
            for (idx, line) in lines.iter().enumerate() {
                if line.contains("android:usesCleartextTraffic=\"true\"") || line.contains("cleartextTrafficPermitted=\"true\"") {
                    findings.push(VulnerabilityFinding {
                        id: format!("APK-CLEARTEXT-{}", findings.len() + 1),
                        title: "Android Cleartext Traffic Permitted (CWE-319)".to_string(),
                        cwe: "CWE-319".to_string(),
                        severity: Severity::High,
                        file_path: path.to_path_buf(),
                        line_number: idx + 1,
                        snippet: line.trim().to_string(),
                        description: "android:usesCleartextTraffic='true' allows unencrypted HTTP network communication, exposing app traffic to man-in-the-middle sniffing.".to_string(),
                        recommendation: "Set android:usesCleartextTraffic='false' and enforce TLS/HTTPS via network security config.".to_string(),
                        patched: false,
                    });
                }
            }
        }

        // Check debuggable
        if content.contains("android:debuggable=\"true\"") {
            for (idx, line) in lines.iter().enumerate() {
                if line.contains("android:debuggable=\"true\"") {
                    findings.push(VulnerabilityFinding {
                        id: format!("APK-DEBUG-{}", findings.len() + 1),
                        title: "Android Application Debuggable Flag Enabled (CWE-489)".to_string(),
                        cwe: "CWE-489".to_string(),
                        severity: Severity::Critical,
                        file_path: path.to_path_buf(),
                        line_number: idx + 1,
                        snippet: line.trim().to_string(),
                        description: "android:debuggable='true' allows external attackers and debuggers (jdb) to attach and inspect memory, extract secrets, and manipulate app execution.".to_string(),
                        recommendation: "Remove android:debuggable='true' or set to false for release production builds.".to_string(),
                        patched: false,
                    });
                }
            }
        }

        // Check allowBackup
        if content.contains("android:allowBackup=\"true\"") {
            for (idx, line) in lines.iter().enumerate() {
                if line.contains("android:allowBackup=\"true\"") {
                    findings.push(VulnerabilityFinding {
                        id: format!("APK-BACKUP-{}", findings.len() + 1),
                        title: "Android Insecure ADB Backup Enabled (CWE-530)".to_string(),
                        cwe: "CWE-530".to_string(),
                        severity: Severity::Medium,
                        file_path: path.to_path_buf(),
                        line_number: idx + 1,
                        snippet: line.trim().to_string(),
                        description: "android:allowBackup='true' permits local physical attackers to dump private app data via 'adb backup'.".to_string(),
                        recommendation: "Set android:allowBackup='false' unless an encrypted enterprise backup agent is explicitly implemented.".to_string(),
                        patched: false,
                    });
                }
            }
        }

        // Check exported components without permission guard
        let mut in_component = false;
        let mut component_name = "";
        let mut comp_start_line = 0;
        let mut comp_buffer = String::new();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("<activity")
                || trimmed.starts_with("<service")
                || trimmed.starts_with("<receiver")
                || trimmed.starts_with("<provider")
            {
                in_component = true;
                component_name = if trimmed.starts_with("<activity") {
                    "Activity"
                } else if trimmed.starts_with("<service") {
                    "Service"
                } else if trimmed.starts_with("<receiver") {
                    "BroadcastReceiver"
                } else {
                    "ContentProvider"
                };
                comp_start_line = idx + 1;
                comp_buffer.clear();
            }

            if in_component {
                comp_buffer.push_str(trimmed);
                comp_buffer.push(' ');

                if trimmed.contains("/>") || trimmed.contains("</activity>") || trimmed.contains("</service>") || trimmed.contains("</receiver>") || trimmed.contains("</provider>") {
                    if comp_buffer.contains("android:exported=\"true\"") && !comp_buffer.contains("android:permission=") {
                        findings.push(VulnerabilityFinding {
                            id: format!("APK-EXPORT-{}", findings.len() + 1),
                            title: format!("Exported Android {component_name} Without Permission Guard (CWE-926)"),
                            cwe: "CWE-926".to_string(),
                            severity: Severity::High,
                            file_path: path.to_path_buf(),
                            line_number: comp_start_line,
                            snippet: comp_buffer.trim().to_string(),
                            description: format!(
                                "Android {component_name} is explicitly exported (android:exported='true') without requiring an android:permission. Any third-party app installed on device can invoke this component."
                            ),
                            recommendation: "Set android:exported='false' for internal components or enforce signature-level permission requirement.".to_string(),
                            patched: false,
                        });
                    }
                    in_component = false;
                    comp_buffer.clear();
                }
            }
        }
    }

    fn audit_android_code(path: &Path, content: &str, findings: &mut Vec<VulnerabilityFinding>) {
        let has_js_interface = content.contains("addJavascriptInterface(");
        let has_js_enabled = content.contains("setJavaScriptEnabled(true)") || content.contains("javaScriptEnabled = true");

        if has_js_interface && has_js_enabled {
            for (idx, line) in content.lines().enumerate() {
                if line.contains("addJavascriptInterface(") {
                    findings.push(VulnerabilityFinding {
                        id: format!("APK-WEBVIEW-{}", findings.len() + 1),
                        title: "Insecure Android WebView JavaScript Interface Exposure (CWE-749)".to_string(),
                        cwe: "CWE-749".to_string(),
                        severity: Severity::Critical,
                        file_path: path.to_path_buf(),
                        line_number: idx + 1,
                        snippet: line.trim().to_string(),
                        description: "addJavascriptInterface exposes native Java/Kotlin methods to JavaScript loaded inside WebView. If WebView navigates to untrusted web content, arbitrary native code execution is possible.".to_string(),
                        recommendation: "Validate target URLs before loading into WebView and avoid injecting sensitive native interface methods.".to_string(),
                        patched: false,
                    });
                }
            }
        }
    }

    fn audit_dockerfile(path: &Path, content: &str, findings: &mut Vec<VulnerabilityFinding>) {
        let lines: Vec<&str> = content.lines().collect();
        let mut has_non_root_user = false;

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // 1. Check unpinned :latest tag
            if trimmed.starts_with("FROM ") && (trimmed.contains(":latest") || !trimmed.contains(':')) {
                findings.push(VulnerabilityFinding {
                    id: format!("DOCKER-LATEST-{}", findings.len() + 1),
                    title: "Unpinned Docker Base Image ':latest' Tag (CWE-1357)".to_string(),
                    cwe: "CWE-1357".to_string(),
                    severity: Severity::Medium,
                    file_path: path.to_path_buf(),
                    line_number: idx + 1,
                    snippet: trimmed.to_string(),
                    description: "Using unpinned ':latest' base image introduces non-deterministic builds and risks pulling upstream breaking changes or tampered images.".to_string(),
                    recommendation: "Pin base image with explicit SHA256 digest or immutable semver version tag.".to_string(),
                    patched: false,
                });
            }

            // 2. Check sensitive ports (22 SSH, 2375 Docker daemon)
            if trimmed.starts_with("EXPOSE ") {
                if trimmed.contains(" 22") || trimmed.contains(" 2375") || trimmed.contains(" 2376") {
                    findings.push(VulnerabilityFinding {
                        id: format!("DOCKER-PORT-{}", findings.len() + 1),
                        title: "Sensitive Remote Control Port Exposed in Dockerfile (CWE-284)".to_string(),
                        cwe: "CWE-284".to_string(),
                        severity: Severity::Critical,
                        file_path: path.to_path_buf(),
                        line_number: idx + 1,
                        snippet: trimmed.to_string(),
                        description: "Exposing SSH (22) or unauthenticated Docker daemon (2375) ports inside container creates high-risk remote execution vectors.".to_string(),
                        recommendation: "Remove SSH/Docker daemon port exposition; use container orchestration exec APIs instead.".to_string(),
                        patched: false,
                    });
                }
            }

            // 3. Check USER instruction
            if trimmed.starts_with("USER ") {
                let user_name = trimmed.trim_start_matches("USER ").trim();
                if user_name != "root" && user_name != "0" {
                    has_non_root_user = true;
                }
            }
        }

        // Flag missing non-root USER
        if !has_non_root_user {
            findings.push(VulnerabilityFinding {
                id: format!("DOCKER-ROOT-{}", findings.len() + 1),
                title: "Container Defaults to Root Execution (CWE-250)".to_string(),
                cwe: "CWE-250".to_string(),
                severity: Severity::High,
                file_path: path.to_path_buf(),
                line_number: 1,
                snippet: "FROM ... [no non-root USER instruction]".to_string(),
                description: "Container runs as root user by default. A container breakout vulnerability would yield host-level root privileges.".to_string(),
                recommendation: "Add 'USER appuser' or 'USER 1000:1000' directive before ENTRYPOINT/CMD.".to_string(),
                patched: false,
            });
        }
    }

    fn audit_docker_compose(path: &Path, content: &str, findings: &mut Vec<VulnerabilityFinding>) {
        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.contains("privileged: true") {
                findings.push(VulnerabilityFinding {
                    id: format!("COMPOSE-PRIV-{}", findings.len() + 1),
                    title: "Docker Compose Privileged Mode Enabled (CWE-250)".to_string(),
                    cwe: "CWE-250".to_string(),
                    severity: Severity::Critical,
                    file_path: path.to_path_buf(),
                    line_number: idx + 1,
                    snippet: trimmed.to_string(),
                    description: "privileged: true disables all Linux namespace and capability security boundaries, granting full kernel capabilities to the container.".to_string(),
                    recommendation: "Remove 'privileged: true' and grant only specific required capabilities via 'cap_add'.".to_string(),
                    patched: false,
                });
            }
            if trimmed.contains("network_mode: \"host\"") || trimmed.contains("network_mode: host") {
                findings.push(VulnerabilityFinding {
                    id: format!("COMPOSE-NET-{}", findings.len() + 1),
                    title: "Docker Compose Host Network Mode (CWE-1327)".to_string(),
                    cwe: "CWE-1327".to_string(),
                    severity: Severity::High,
                    file_path: path.to_path_buf(),
                    line_number: idx + 1,
                    snippet: trimmed.to_string(),
                    description: "network_mode: host bypasses container network isolation, giving container direct access to all host network interfaces.".to_string(),
                    recommendation: "Use user-defined bridge network instead of host networking.".to_string(),
                    patched: false,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_android_manifest_audit() {
        let manifest = r#"<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:usesCleartextTraffic="true" android:debuggable="true" android:allowBackup="true">
        <activity android:name=".MainActivity" android:exported="true" />
    </application>
</manifest>"#;

        let mut findings = Vec::new();
        ApkAndContainerGuardAgent::audit_android_manifest(Path::new("AndroidManifest.xml"), manifest, &mut findings);

        assert!(findings.iter().any(|f| f.cwe == "CWE-319"));
        assert!(findings.iter().any(|f| f.cwe == "CWE-489"));
        assert!(findings.iter().any(|f| f.cwe == "CWE-530"));
        assert!(findings.iter().any(|f| f.cwe == "CWE-926"));
    }

    #[test]
    fn test_dockerfile_audit() {
        let dockerfile = r#"FROM node:latest
EXPOSE 22
CMD ["npm", "start"]
"#;
        let mut findings = Vec::new();
        ApkAndContainerGuardAgent::audit_dockerfile(Path::new("Dockerfile"), dockerfile, &mut findings);

        assert!(findings.iter().any(|f| f.cwe == "CWE-1357")); // :latest
        assert!(findings.iter().any(|f| f.cwe == "CWE-284"));  // EXPOSE 22
        assert!(findings.iter().any(|f| f.cwe == "CWE-250"));  // no non-root USER
    }
}
