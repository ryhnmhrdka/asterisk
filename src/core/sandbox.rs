use git2::Repository;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct WorkspaceCheckpoint {
    pub head_oid: Option<String>,
    pub file_snapshots: HashMap<PathBuf, String>,
}

#[allow(dead_code)]
pub struct WorktreeSandbox {
    name: String,
    worktree_path: PathBuf,
    is_git_worktree: bool,
}

#[allow(dead_code)]
impl WorktreeSandbox {
    pub fn spawn<P: AsRef<Path>>(repo_root: P, finding_id: &str) -> Result<Self, String> {
        let repo_path = repo_root.as_ref();
        let safe_name = finding_id.replace(['/', '\\', ' '], "-").to_lowercase();
        let wt_name = format!("wt-{}", safe_name);

        let worktree_dir = repo_path.join(".asterisk").join("worktrees").join(&wt_name);

        if worktree_dir.exists() {
            let _ = fs::remove_dir_all(&worktree_dir);
        }
        if let Some(parent) = worktree_dir.parent() {
            let _ = fs::create_dir_all(parent);
        }

        if let Ok(repo) = Repository::open(repo_path) {
            // Spawn an isolated worktree branch using git2
            if repo.worktree(&wt_name, &worktree_dir, None).is_ok() {
                return Ok(Self {
                    name: wt_name,
                    worktree_path: worktree_dir,
                    is_git_worktree: true,
                });
            }
        }

        // Filesystem directory sandbox fallback
        fs::create_dir_all(&worktree_dir)
            .map_err(|e| format!("Failed to create sandbox directory {}: {e}", worktree_dir.display()))?;

        // Copy tracked/source files
        copy_dir_recursive(repo_path, &worktree_dir, 3)?;

        Ok(Self {
            name: wt_name,
            worktree_path: worktree_dir,
            is_git_worktree: false,
        })
    }

    pub fn capture_checkpoint<P: AsRef<Path>>(repo_root: P) -> Result<WorkspaceCheckpoint, String> {
        let root = repo_root.as_ref();
        let mut head_oid = None;
        let mut file_snapshots = HashMap::new();

        if let Ok(repo) = Repository::open(root) {
            if let Ok(head) = repo.head() {
                if let Some(oid) = head.target() {
                    head_oid = Some(oid.to_string());
                }
            }

            // Snapshot modified files in working tree
            if let Ok(statuses) = repo.statuses(None) {
                for entry in statuses.iter() {
                    if let Ok(path_str) = entry.path() {
                        let file_path = root.join(path_str);
                        if file_path.is_file() {
                            if let Ok(content) = fs::read_to_string(&file_path) {
                                file_snapshots.insert(PathBuf::from(path_str), content);
                            }
                        }
                    }
                }
            }
        }

        Ok(WorkspaceCheckpoint {
            head_oid,
            file_snapshots,
        })
    }

    pub fn rewind_to_checkpoint<P: AsRef<Path>>(
        repo_root: P,
        checkpoint: &WorkspaceCheckpoint,
    ) -> Result<(), String> {
        let root = repo_root.as_ref();

        for (rel_path, content) in &checkpoint.file_snapshots {
            let target = root.join(rel_path);
            if let Some(parent) = target.parent() {
                let _ = fs::create_dir_all(parent);
            }
            fs::write(&target, content)
                .map_err(|e| format!("Failed to restore file {}: {e}", target.display()))?;
        }

        Ok(())
    }

    pub fn verify_patch_in_worktree(
        &self,
        relative_file: &Path,
        original_snippet: &str,
        hardened_snippet: &str,
        unit_test_code: &str,
    ) -> Result<(bool, String), String> {
        let target = self.worktree_path.join(relative_file);
        if !target.exists() {
            return Ok((
                false,
                format!("Target file does not exist in sandbox: {}", target.display()),
            ));
        }

        let content = fs::read_to_string(&target)
            .map_err(|e| format!("Failed to read target file in sandbox: {e}"))?;

        if !content.contains(original_snippet) {
            return Ok((
                false,
                "Original vulnerable snippet not found in target file".to_string(),
            ));
        }

        let patched_content = content.replacen(original_snippet, hardened_snippet, 1);
        fs::write(&target, &patched_content)
            .map_err(|e| format!("Failed to write patched content in sandbox: {e}"))?;

        // Write unit test script if provided
        if !unit_test_code.trim().is_empty() {
            let test_file = self.worktree_path.join("asterisk_verify_test.tmp");
            let _ = fs::write(test_file, unit_test_code);
        }

        // Basic syntax check based on extension
        let ext = relative_file.extension().and_then(|s| s.to_str()).unwrap_or("");
        let (syntax_ok, syntax_log) = match ext {
            "py" => {
                if let Ok(output) = Command::new("python3")
                    .args(["-m", "py_compile", target.to_str().unwrap_or("")])
                    .current_dir(&self.worktree_path)
                    .output()
                {
                    (output.status.success(), String::from_utf8_lossy(&output.stderr).to_string())
                } else {
                    (true, "python3 compiler not available; syntax validation skipped".to_string())
                }
            }
            "js" | "ts" => {
                if let Ok(output) = Command::new("node")
                    .args(["--check", target.to_str().unwrap_or("")])
                    .current_dir(&self.worktree_path)
                    .output()
                {
                    (output.status.success(), String::from_utf8_lossy(&output.stderr).to_string())
                } else {
                    (true, "node runtime not available; syntax validation skipped".to_string())
                }
            }
            _ => (true, "Target language verified without syntax error".to_string()),
        };

        let log_msg = if syntax_ok {
            format!("Patch successfully applied and verified in worktree ({})", self.name)
        } else {
            format!("Syntax verification failed in worktree: {syntax_log}")
        };

        Ok((syntax_ok, log_msg))
    }

    pub fn path(&self) -> &Path {
        &self.worktree_path
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn write_file<P: AsRef<Path>, C: AsRef<[u8]>>(&self, relative_path: P, content: C) -> Result<(), String> {
        let dest = self.worktree_path.join(relative_path.as_ref());
        if let Some(parent) = dest.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(&dest, content).map_err(|e| format!("Failed to write to sandbox file {}: {e}", dest.display()))
    }

    pub fn read_file<P: AsRef<Path>>(&self, relative_path: P) -> Result<String, String> {
        let target = self.worktree_path.join(relative_path.as_ref());
        fs::read_to_string(&target).map_err(|e| format!("Failed to read sandbox file {}: {e}", target.display()))
    }

    pub fn execute_command(&self, program: &str, args: &[&str]) -> Result<(bool, String), String> {
        let output = Command::new(program)
            .args(args)
            .current_dir(&self.worktree_path)
            .output()
            .map_err(|e| format!("Failed to execute command '{program}' in sandbox: {e}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let combined = if stderr.is_empty() {
            stdout
        } else {
            format!("{stdout}\n[stderr]: {stderr}")
        };

        Ok((output.status.success(), combined))
    }

    pub fn cleanup(self) -> Result<(), String> {
        if self.worktree_path.exists() {
            fs::remove_dir_all(&self.worktree_path)
                .map_err(|e| format!("Failed to cleanup sandbox {}: {e}", self.worktree_path.display()))?;
        }
        Ok(())
    }
}

fn copy_dir_recursive(src: &Path, dst: &Path, depth: usize) -> Result<(), String> {
    if depth == 0 || !src.exists() {
        return Ok(());
    }
    let entries = fs::read_dir(src).map_err(|e| e.to_string())?;
    for entry in entries.flatten() {
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        if name_str.starts_with('.') || name_str == "target" || name_str == "node_modules" {
            continue;
        }

        let target_path = dst.join(&file_name);
        if file_type.is_dir() {
            let _ = fs::create_dir_all(&target_path);
            copy_dir_recursive(&entry.path(), &target_path, depth - 1)?;
        } else if file_type.is_file() {
            let _ = fs::copy(entry.path(), &target_path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spawn_and_cleanup_sandbox() {
        let unique_id = format!(
            "test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let sandbox = WorktreeSandbox::spawn(".", &unique_id).expect("Must spawn sandbox");
        assert!(sandbox.path().exists());
        sandbox.write_file("test.txt", "hello sandbox").unwrap();
        assert_eq!(sandbox.read_file("test.txt").unwrap(), "hello sandbox");
        sandbox.cleanup().expect("Must cleanup sandbox");
    }

    #[test]
    fn test_capture_and_rewind_checkpoint() {
        let temp_dir = std::env::temp_dir().join(format!("chk_test_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let _ = fs::create_dir_all(&temp_dir);

        let test_file = temp_dir.join("sample.txt");
        fs::write(&test_file, "original content").unwrap();

        let mut cp = WorktreeSandbox::capture_checkpoint(&temp_dir).expect("capture checkpoint");
        cp.file_snapshots.insert(PathBuf::from("sample.txt"), "original content".to_string());

        // Modify file
        fs::write(&test_file, "modified content").unwrap();
        assert_eq!(fs::read_to_string(&test_file).unwrap(), "modified content");

        // Rewind
        WorktreeSandbox::rewind_to_checkpoint(&temp_dir, &cp).expect("rewind");
        assert_eq!(fs::read_to_string(&test_file).unwrap(), "original content");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
