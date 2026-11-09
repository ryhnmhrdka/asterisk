use crate::types::WorkspaceProfile;
use std::collections::HashSet;
use std::path::Path;
use walkdir::WalkDir;

pub struct WorkspaceScanner;

impl WorkspaceScanner {
    pub fn scan<P: AsRef<Path>>(root: P) -> WorkspaceProfile {
        let root_path = root.as_ref().to_path_buf();
        let mut total_files = 0;
        let mut languages = HashSet::new();
        let mut frameworks = HashSet::new();
        let mut has_docker = false;
        let mut has_env_files = false;
        let mut has_mobile = false;

        if root_path.is_file() {
            total_files = 1;
            let file_name = root_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let ext = root_path.extension().and_then(|s| s.to_str()).unwrap_or("");

            match ext {
                "rs" => { languages.insert("Rust".to_string()); }
                "py" => { languages.insert("Python".to_string()); }
                "js" | "jsx" | "ts" | "tsx" => { languages.insert("TypeScript/JavaScript".to_string()); }
                "go" => { languages.insert("Go".to_string()); }
                "java" | "kt" => { languages.insert("Java/Kotlin".to_string()); }
                "c" | "cpp" | "h" => { languages.insert("C/C++".to_string()); }
                "log" | "jsonl" | "out" => {
                    languages.insert("Log / Event Stream".to_string());
                    frameworks.insert("Audit Log Ingestion".to_string());
                }
                "apk" => {
                    has_mobile = true;
                    languages.insert("Android Package (APK)".to_string());
                    frameworks.insert("Mobile Binary Audit".to_string());
                }
                "so" | "dll" | "dylib" | "exe" | "bin" => {
                    languages.insert("Compiled Binary Artifact".to_string());
                    frameworks.insert("Binary Analysis (Symbols & Strings)".to_string());
                }
                _ => {
                    if file_name.contains("log") {
                        languages.insert("Log / Event Stream".to_string());
                    } else {
                        languages.insert("Binary / Raw Asset".to_string());
                    }
                }
            }

            return WorkspaceProfile {
                root_path,
                total_files,
                languages: languages.into_iter().collect(),
                frameworks: frameworks.into_iter().collect(),
                has_docker,
                has_env_files,
                has_mobile,
            };
        }

        for entry in WalkDir::new(&root_path)
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
            if entry.file_type().is_file() {
                total_files += 1;
                let path = entry.path();
                let file_name = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default();
                let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");

                match ext {
                    "rs" => { languages.insert("Rust".to_string()); }
                    "py" => { languages.insert("Python".to_string()); }
                    "js" | "jsx" | "ts" | "tsx" => { languages.insert("TypeScript/JavaScript".to_string()); }
                    "go" => { languages.insert("Go".to_string()); }
                    "java" | "kt" => { languages.insert("Java/Kotlin".to_string()); }
                    "c" | "cpp" | "h" => { languages.insert("C/C++".to_string()); }
                    "log" | "jsonl" => { languages.insert("Log File".to_string()); }
                    "apk" => {
                        has_mobile = true;
                        languages.insert("Android APK".to_string());
                    }
                    "so" | "dll" | "dylib" | "exe" => {
                        languages.insert("Compiled Binary".to_string());
                    }
                    _ => {}
                }

                if file_name.contains("Dockerfile") || file_name.contains("docker-compose") {
                    has_docker = true;
                    frameworks.insert("Container / Docker".to_string());
                }
                if file_name.starts_with(".env") || file_name.ends_with(".env") {
                    has_env_files = true;
                }
                if file_name == "AndroidManifest.xml" || file_name.ends_with(".apk") || ext == "kt" {
                    has_mobile = true;
                    frameworks.insert("Android / Mobile".to_string());
                }
                if file_name == "Cargo.toml" {
                    frameworks.insert("Cargo".to_string());
                }
                if file_name == "package.json" {
                    frameworks.insert("Node / NPM".to_string());
                }
                if file_name == "requirements.txt" || file_name == "Pipfile" || file_name == "pyproject.toml" {
                    frameworks.insert("Python Ecosystem".to_string());
                }
                if file_name == "go.mod" {
                    frameworks.insert("Go Modules".to_string());
                }
            }
        }

        WorkspaceProfile {
            root_path,
            total_files,
            languages: languages.into_iter().collect(),
            frameworks: frameworks.into_iter().collect(),
            has_docker,
            has_env_files,
            has_mobile,
        }
    }
}
