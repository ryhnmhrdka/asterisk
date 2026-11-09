use git2::Repository;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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

        let worktree_dir = repo_path.join(".sentinel").join("worktrees").join(&wt_name);

        if worktree_dir.exists() {
            let _ = fs::remove_dir_all(&worktree_dir);
        }
        if let Some(parent) = worktree_dir.parent() {
            let _ = fs::create_dir_all(parent);
        }

        if let Ok(repo) = Repository::open(repo_path) {
            // Spawn an isolated worktree branch using git2
            match repo.worktree(&wt_name, &worktree_dir, None) {
                Ok(_) => {
                    return Ok(Self {
                        name: wt_name,
                        worktree_path: worktree_dir,
                        is_git_worktree: true,
                    });
                }
                Err(_) => {
                    // Fallback to isolated directory copy if git worktree fails (e.g. bare repo)
                }
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
}
