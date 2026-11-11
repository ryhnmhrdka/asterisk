use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeKind {
    Source,             // Untrusted user input / HTTP endpoint / CLI arg
    Function,           // Internal application function
    Sanitizer,          // Sanitization / validation middleware
    Sink,               // Vulnerable operation (SQL query, command exec, eval, etc.)
    ExternalDependency, // Library / third-party package
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct CodeNode {
    pub id: String,
    pub symbol: String,
    pub kind: NodeKind,
    pub file_path: PathBuf,
    pub line_number: usize,
    pub ast_blake3_hash: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeKind {
    Calls,
    Imports,
    TaintFlow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachabilityVerdict {
    Reachable { path: Vec<String> },
    PotentiallyReachable { reason: String },
    Unreachable,
}

#[derive(Default)]
pub struct CodeContextGraph {
    graph: DiGraph<CodeNode, EdgeKind>,
    node_indices: HashMap<String, NodeIndex>,
    file_hashes: HashMap<PathBuf, String>,
}

impl CodeContextGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_indices: HashMap::new(),
            file_hashes: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, node: CodeNode) -> NodeIndex {
        let id = node.id.clone();
        if let Some(&idx) = self.node_indices.get(&id) {
            return idx;
        }
        let idx = self.graph.add_node(node);
        self.node_indices.insert(id, idx);
        idx
    }

    pub fn add_edge(&mut self, from_id: &str, to_id: &str, edge: EdgeKind) {
        if let (Some(&from_idx), Some(&to_idx)) = (self.node_indices.get(from_id), self.node_indices.get(to_id)) {
            self.graph.add_edge(from_idx, to_idx, edge);
        }
    }

    #[allow(dead_code)]
    pub fn total_nodes(&self) -> usize {
        self.graph.node_count()
    }

    #[allow(dead_code)]
    pub fn total_edges(&self) -> usize {
        self.graph.edge_count()
    }

    #[allow(dead_code)]
    pub fn file_hashes(&self) -> &HashMap<PathBuf, String> {
        &self.file_hashes
    }

    #[allow(dead_code)]
    pub fn get_file_hash(&self, file_path: &Path) -> Option<&str> {
        self.file_hashes.get(file_path).map(|s| s.as_str())
    }

    #[allow(dead_code)]
    pub fn is_file_unchanged(&self, file_path: &Path, content: &[u8]) -> bool {
        if let Some(existing_hash) = self.get_file_hash(file_path) {
            let current_hash = blake3::hash(content).to_hex().to_string();
            existing_hash == current_hash
        } else {
            false
        }
    }

    /// Evaluates if a given sink or vulnerable node is reachable from any user-controlled input source
    /// Takes into account Sanitizer nodes: paths that pass through a Sanitizer node are deemed sanitized/unreachable.
    pub fn evaluate_reachability(&self, sink_id: &str) -> ReachabilityVerdict {
        let sink_idx = match self.node_indices.get(sink_id) {
            Some(&idx) => idx,
            None => {
                return ReachabilityVerdict::PotentiallyReachable {
                    reason: format!("Node '{sink_id}' not explicitly mapped in graph index"),
                };
            }
        };

        // Find all Source nodes in the graph
        let sources: Vec<NodeIndex> = self
            .graph
            .node_indices()
            .filter(|&idx| matches!(self.graph[idx].kind, NodeKind::Source))
            .collect();

        if sources.is_empty() {
            return ReachabilityVerdict::PotentiallyReachable {
                reason: "No entrypoint sources mapped in workspace; evaluating as potentially reachable".to_string(),
            };
        }

        // Trace paths using BFS, filtering out paths that pass through Sanitizer nodes
        for &source_idx in &sources {
            if let Some(unsanitized_path) = self.find_unsanitized_path(source_idx, sink_idx) {
                return ReachabilityVerdict::Reachable { path: unsanitized_path };
            }
        }

        ReachabilityVerdict::Unreachable
    }

    /// Finds an unsanitized path from start (Source) to target (Sink)
    /// A path is sanitized (and thus pruned) if an intermediate node has NodeKind::Sanitizer.
    fn find_unsanitized_path(&self, start: NodeIndex, target: NodeIndex) -> Option<Vec<String>> {
        let mut queue: VecDeque<(NodeIndex, Vec<NodeIndex>)> = VecDeque::new();
        let mut visited: HashSet<NodeIndex> = HashSet::new();

        queue.push_back((start, vec![start]));
        visited.insert(start);

        while let Some((current, path)) = queue.pop_front() {
            if current == target {
                let formatted = path
                    .into_iter()
                    .map(|idx| {
                        format!(
                            "{}:{}",
                            self.graph[idx].file_path.display(),
                            self.graph[idx].symbol
                        )
                    })
                    .collect();
                return Some(formatted);
            }

            for neighbor in self.graph.neighbors(current) {
                // If neighbor is a Sanitizer, do NOT proceed through this path to target sink
                if matches!(self.graph[neighbor].kind, NodeKind::Sanitizer) && neighbor != target {
                    continue;
                }

                if !visited.contains(&neighbor) {
                    visited.insert(neighbor);
                    let mut next_path = path.clone();
                    next_path.push(neighbor);
                    queue.push_back((neighbor, next_path));
                }
            }
        }

        None
    }

    /// Automatically scans directory files and populates AST nodes & call edges
    pub fn build_from_workspace<P: AsRef<Path>>(root: P) -> Self {
        let mut graph = Self::new();
        let root_path = root.as_ref();

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
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            let rel_path = path.strip_prefix(root_path).unwrap_or(path);

            if matches!(ext, "py" | "js" | "ts" | "jsx" | "tsx" | "rs" | "go" | "java" | "kt") {
                if let Ok(content) = std::fs::read_to_string(path) {
                    let hash_str = blake3::hash(content.as_bytes()).to_hex().to_string();
                    graph.file_hashes.insert(rel_path.to_path_buf(), hash_str.clone());
                    parse_file_nodes(&mut graph, rel_path, &content, Some(&hash_str));
                }
            }
        }

        graph
    }

    /// Builds incremental sub-graph specifically for files changed in Git working tree / index (--diff-scope=local)
    #[allow(dead_code)]
    pub fn build_from_git_diff<P: AsRef<Path>>(root: P) -> Self {
        let root_path = root.as_ref();
        let mut changed_rel_paths = Vec::new();

        if let Ok(repo) = git2::Repository::open(root_path) {
            let mut opts = git2::StatusOptions::new();
            opts.include_untracked(true).recurse_untracked_dirs(true);

            if let Ok(statuses) = repo.statuses(Some(&mut opts)) {
                for entry in statuses.iter() {
                    if let Ok(path_str) = entry.path() {
                        let path = PathBuf::from(path_str);
                        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                        if matches!(ext, "py" | "js" | "ts" | "jsx" | "tsx" | "rs" | "go" | "java" | "kt") {
                            changed_rel_paths.push(path);
                        }
                    }
                }
            }
        }

        // Fallback to full workspace if no changes detected or outside git repo
        if changed_rel_paths.is_empty() {
            return Self::build_from_workspace(root_path);
        }

        let mut graph = Self::new();
        for rel_path in changed_rel_paths {
            let full_path = root_path.join(&rel_path);
            if full_path.is_file() {
                if let Ok(content) = std::fs::read_to_string(&full_path) {
                    let hash_str = blake3::hash(content.as_bytes()).to_hex().to_string();
                    graph.file_hashes.insert(rel_path.clone(), hash_str.clone());
                    parse_file_nodes(&mut graph, &rel_path, &content, Some(&hash_str));
                }
            }
        }

        graph
    }
}

/// Helper function to strip single-line and multi-line comments from source code across languages
/// Preserves line numbers by returning (line_number, stripped_text)
fn strip_comments(content: &str, _ext: &str) -> Vec<(usize, String)> {
    let mut result = Vec::new();
    let mut in_c_block = false;
    let mut in_py_block = false;

    for (idx, line) in content.lines().enumerate() {
        let line_num = idx + 1;
        let mut cleaned = String::new();
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            if in_c_block {
                if i + 1 < chars.len() && chars[i] == '*' && chars[i + 1] == '/' {
                    in_c_block = false;
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }

            if in_py_block {
                if i + 2 < chars.len()
                    && ((chars[i] == '"' && chars[i + 1] == '"' && chars[i + 2] == '"')
                        || (chars[i] == '\'' && chars[i + 1] == '\'' && chars[i + 2] == '\''))
                {
                    in_py_block = false;
                    i += 3;
                    continue;
                }
                i += 1;
                continue;
            }

            // Check for block comment start
            if i + 2 < chars.len()
                && ((chars[i] == '"' && chars[i + 1] == '"' && chars[i + 2] == '"')
                    || (chars[i] == '\'' && chars[i + 1] == '\'' && chars[i + 2] == '\''))
            {
                in_py_block = true;
                i += 3;
                continue;
            }

            if i + 1 < chars.len() && chars[i] == '/' && chars[i + 1] == '*' {
                in_c_block = true;
                i += 2;
                continue;
            }

            // Check for line comment start (# in Python/Ruby/Shell or // in C/Rust/JS/Go)
            if chars[i] == '#' {
                break;
            }
            if i + 1 < chars.len() && chars[i] == '/' && chars[i + 1] == '/' {
                break;
            }

            cleaned.push(chars[i]);
            i += 1;
        }

        result.push((line_num, cleaned));
    }

    result
}

fn parse_file_nodes(
    graph: &mut CodeContextGraph,
    file_path: &Path,
    content: &str,
    blake3_hash: Option<&str>,
) {
    let ext = file_path.extension().and_then(|s| s.to_str()).unwrap_or("");
    let stripped_lines = strip_comments(content, ext);

    let mut current_source_id: Option<String> = None;
    let mut current_sanitizer_id: Option<String> = None;

    for (line_num, line) in stripped_lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // 1. Detect Source / Entrypoint
        if trimmed.contains("@app.route")
            || trimmed.contains("app.get")
            || trimmed.contains("app.post")
            || trimmed.contains("req.body")
            || trimmed.contains("request.args")
            || trimmed.contains("sys.argv")
            || trimmed.contains("std::env::args")
        {
            let id = format!("{}:{}:src", file_path.display(), line_num);
            graph.add_node(CodeNode {
                id: id.clone(),
                symbol: "http_request_handler".to_string(),
                kind: NodeKind::Source,
                file_path: file_path.to_path_buf(),
                line_number: line_num,
                ast_blake3_hash: blake3_hash.map(|s| s.to_string()),
            });
            current_source_id = Some(id);
            current_sanitizer_id = None; // Reset sanitizer for new source
        }

        // 2. Detect Sanitizer / Input validation
        if trimmed.contains("sanitize")
            || trimmed.contains("validate")
            || trimmed.contains("escape")
            || trimmed.contains("int(")
            || trimmed.contains("parseInt(")
            || trimmed.contains("escape_string")
            || trimmed.contains("parameterize")
        {
            let san_id = format!("{}:{}:sanitizer", file_path.display(), line_num);
            graph.add_node(CodeNode {
                id: san_id.clone(),
                symbol: "sanitization_middleware".to_string(),
                kind: NodeKind::Sanitizer,
                file_path: file_path.to_path_buf(),
                line_number: line_num,
                ast_blake3_hash: blake3_hash.map(|s| s.to_string()),
            });

            // If an active source exists, route TaintFlow into the sanitizer
            if let Some(src_id) = &current_source_id {
                graph.add_edge(src_id, &san_id, EdgeKind::TaintFlow);
            }
            current_sanitizer_id = Some(san_id);
        }

        // 3. Detect Sink (SQLi, Command Injection, Eval)
        if trimmed.contains(".query(")
            || trimmed.contains(".execute(")
            || trimmed.contains("eval(")
            || trimmed.contains("exec(")
            || trimmed.contains("os.system(")
            || trimmed.contains("subprocess.")
            || trimmed.contains("Command::new")
        {
            let sink_id = format!("{}:{}:sink", file_path.display(), line_num);
            graph.add_node(CodeNode {
                id: sink_id.clone(),
                symbol: "sensitive_execution_sink".to_string(),
                kind: NodeKind::Sink,
                file_path: file_path.to_path_buf(),
                line_number: line_num,
                ast_blake3_hash: blake3_hash.map(|s| s.to_string()),
            });

            if let Some(san_id) = &current_sanitizer_id {
                // If a sanitizer exists between source and sink, connect through sanitizer
                graph.add_edge(san_id, &sink_id, EdgeKind::Calls);
            } else if let Some(src_id) = &current_source_id {
                // Unsanitized direct taint flow
                graph.add_edge(src_id, &sink_id, EdgeKind::TaintFlow);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reachability_graph() {
        let mut graph = CodeContextGraph::new();

        let src = CodeNode {
            id: "src_1".to_string(),
            symbol: "endpoint".to_string(),
            kind: NodeKind::Source,
            file_path: PathBuf::from("server.py"),
            line_number: 10,
            ast_blake3_hash: None,
        };

        let fn_call = CodeNode {
            id: "fn_1".to_string(),
            symbol: "process_data".to_string(),
            kind: NodeKind::Function,
            file_path: PathBuf::from("server.py"),
            line_number: 20,
            ast_blake3_hash: None,
        };

        let sink = CodeNode {
            id: "sink_1".to_string(),
            symbol: "db_query".to_string(),
            kind: NodeKind::Sink,
            file_path: PathBuf::from("db.py"),
            line_number: 50,
            ast_blake3_hash: None,
        };

        graph.add_node(src);
        graph.add_node(fn_call);
        graph.add_node(sink);

        graph.add_edge("src_1", "fn_1", EdgeKind::Calls);
        graph.add_edge("fn_1", "sink_1", EdgeKind::TaintFlow);

        let verdict = graph.evaluate_reachability("sink_1");
        assert!(matches!(verdict, ReachabilityVerdict::Reachable { .. }));

        // Unconnected sink must evaluate to Unreachable
        let orphan_sink = CodeNode {
            id: "orphan_1".to_string(),
            symbol: "orphan_exec".to_string(),
            kind: NodeKind::Sink,
            file_path: PathBuf::from("unused.py"),
            line_number: 100,
            ast_blake3_hash: None,
        };
        graph.add_node(orphan_sink);
        let unreach = graph.evaluate_reachability("orphan_1");
        assert_eq!(unreach, ReachabilityVerdict::Unreachable);
    }

    #[test]
    fn test_comment_stripping_prevents_false_positives() {
        let python_with_comments = r#"
# db.execute("SELECT * FROM users")
// eval("malicious_code()")
/*
   os.system("rm -rf /")
*/
def normal_function():
    return 42
"#;
        let mut graph = CodeContextGraph::new();
        parse_file_nodes(&mut graph, Path::new("clean.py"), python_with_comments, None);

        // No sink should be created from comments
        assert_eq!(graph.total_nodes(), 0);
    }

    #[test]
    fn test_sanitizer_evaluated_as_unreachable() {
        let sanitized_code = r#"
@app.route("/profile")
def get_profile():
    raw_id = request.args.get("id")
    safe_id = sanitize_int(raw_id)
    db.execute(f"SELECT * FROM users WHERE id = {safe_id}")
"#;
        let mut graph = CodeContextGraph::new();
        parse_file_nodes(&mut graph, Path::new("sanitized.py"), sanitized_code, None);

        let sink_id = "sanitized.py:6:sink";
        let verdict = graph.evaluate_reachability(sink_id);
        assert_eq!(verdict, ReachabilityVerdict::Unreachable, "Sanitized path must be deemed Unreachable");
    }

    #[test]
    fn test_unsanitized_path_evaluated_as_reachable() {
        let vulnerable_code = r#"
@app.route("/search")
def search():
    query = request.args.get("q")
    db.execute(f"SELECT * FROM items WHERE name = '{query}'")
"#;
        let mut graph = CodeContextGraph::new();
        parse_file_nodes(&mut graph, Path::new("vuln.py"), vulnerable_code, None);

        let sink_id = "vuln.py:5:sink";
        let verdict = graph.evaluate_reachability(sink_id);
        assert!(matches!(verdict, ReachabilityVerdict::Reachable { .. }), "Unsanitized path must be Reachable");
    }

    #[test]
    fn test_build_from_git_diff_in_repo() {
        // Test that build_from_git_diff runs without error on the current repository
        let graph = CodeContextGraph::build_from_git_diff(".");
        let _ = graph.total_nodes();
    }
}
