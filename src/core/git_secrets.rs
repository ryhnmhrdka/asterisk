use crate::types::{Severity, VulnerabilityFinding};
use entropy::shannon_entropy;
use git2::{Commit, DiffOptions, Repository};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub struct GitHistorySecretMiner;

impl GitHistorySecretMiner {
    /// Scans Git commit history across all branches using git2::Revwalk and Shannon Entropy
    pub fn scan_commit_history<P: AsRef<Path>>(repo_path: P) -> Vec<VulnerabilityFinding> {
        let mut findings = Vec::new();
        let path = repo_path.as_ref();

        let repo = match Repository::open(path) {
            Ok(r) => r,
            Err(_) => return findings, // Not a git repository, skip history traversal
        };

        let mut revwalk = match repo.revwalk() {
            Ok(rw) => rw,
            Err(_) => return findings,
        };

        // Push HEAD and all references
        if revwalk.push_head().is_err() {
            let _ = revwalk.push_glob("refs/heads/*");
        }

        let mut seen_secrets = HashSet::new();
        let mut diff_opts = DiffOptions::new();
        diff_opts.context_lines(0);

        for oid_res in revwalk.take(50) {
            let oid = match oid_res {
                Ok(id) => id,
                Err(_) => continue,
            };

            let commit = match repo.find_commit(oid) {
                Ok(c) => c,
                Err(_) => continue,
            };

            inspect_commit_diff(&repo, &commit, &mut diff_opts, &mut findings, &mut seen_secrets);
        }

        findings
    }
}

fn inspect_commit_diff(
    repo: &Repository,
    commit: &Commit,
    opts: &mut DiffOptions,
    findings: &mut Vec<VulnerabilityFinding>,
    seen_secrets: &mut HashSet<String>,
) {
    let parent_tree = commit.parent(0).ok().and_then(|p| p.tree().ok());
    let commit_tree = match commit.tree() {
        Ok(t) => t,
        Err(_) => return,
    };

    let diff = match repo.diff_tree_to_tree(parent_tree.as_ref(), Some(&commit_tree), Some(opts)) {
        Ok(d) => d,
        Err(_) => return,
    };

    let commit_id_short = &commit.id().to_string()[..8];
    let author = commit.author().name().unwrap_or("unknown").to_string();

    let _ = diff.print(git2::DiffFormat::Patch, |delta, _hunk, line| {
        if line.origin() == '+' {
            let line_str = String::from_utf8_lossy(line.content());
            let trimmed = line_str.trim();

            if let Some(secret) = detect_high_entropy_secret(trimmed) {
                if seen_secrets.insert(secret.clone()) {
                    let file_path = delta
                        .new_file()
                        .path()
                        .map(PathBuf::from)
                        .unwrap_or_else(|| PathBuf::from("git-history"));

                    findings.push(VulnerabilityFinding {
                        id: format!("HIST-SEC-{:04}", findings.len() + 1),
                        title: format!("Leaked Credential in Commit History ({commit_id_short})"),
                        cwe: "CWE-798".to_string(),
                        severity: Severity::Critical,
                        file_path,
                        line_number: 1,
                        snippet: format!("{trimmed} (commit: {commit_id_short} by {author})"),
                        description: format!(
                            "High-entropy secret token committed to Git history in commit {commit_id_short}. Even if deleted later, secret remains in Git history."
                        ),
                        recommendation: "Rotate secret token immediately and purge commit history using git-filter-repo or BFG.".to_string(),
                        patched: false,
                    });
                }
            }
        }
        true
    });
}

fn detect_high_entropy_secret(line: &str) -> Option<String> {
    for word in line.split(|c: char| c.is_whitespace() || c == '=' || c == ':' || c == '"' || c == '\'') {
        let clean = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '-' && c != '_');
        if clean.len() >= 24 {
            let ent = shannon_entropy(clean);
            // High entropy threshold for cryptographic keys/tokens
            if ent >= 4.2 {
                return Some(clean.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_detector() {
        let high_ent = "secret_key = 'x9#kL2@mQ9!vP4$wZ8*jR1^yN5&bC3(dF7)'";
        assert!(detect_high_entropy_secret(high_ent).is_some());

        let low_ent = "normal_word_variable_name_without_randomness";
        assert!(detect_high_entropy_secret(low_ent).is_none());
    }
}
