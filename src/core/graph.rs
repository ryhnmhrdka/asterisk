use petgraph::algo::has_path_connecting;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;
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
}

impl CodeContextGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_indices: HashMap::new(),
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

    /// Evaluates if a given sink or vulnerable node is reachable from any user-controlled input source
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

        // Trace paths using BFS
        for &source_idx in &sources {
            if has_path_connecting(&self.graph, source_idx, sink_idx, None) {
                let path = self.reconstruct_path(source_idx, sink_idx);
                return ReachabilityVerdict::Reachable { path };
            }
        }

        ReachabilityVerdict::Unreachable
    }

    fn reconstruct_path(&self, start: NodeIndex, target: NodeIndex) -> Vec<String> {
        // Simple BFS shortest path reconstruction
        use std::collections::VecDeque;

        let mut queue = VecDeque::new();
        let mut visited = HashMap::new();

        queue.push_back(start);
        visited.insert(start, None);

        let mut found = false;
        while let Some(current) = queue.pop_front() {
            if current == target {
                found = true;
                break;
            }

            for neighbor in self.graph.neighbors(current) {
                if !visited.contains_key(&neighbor) {
                    visited.insert(neighbor, Some(current));
                    queue.push_back(neighbor);
                }
            }
        }

        if !found {
            return vec![
                self.graph[start].symbol.clone(),
                self.graph[target].symbol.clone(),
            ];
        }

        let mut path = Vec::new();
        let mut curr = Some(target);
        while let Some(node) = curr {
            path.push(format!(
                "{}:{}",
                self.graph[node].file_path.display(),
                self.graph[node].symbol
            ));
            curr = visited.get(&node).copied().flatten();
        }

        path.reverse();
        path
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

            if matches!(ext, "py" | "js" | "ts" | "jsx" | "tsx" | "rs" | "go") {
                if let Ok(content) = std::fs::read_to_string(path) {
                    parse_file_nodes(&mut graph, rel_path, &content);
                }
            }
        }

        graph
    }
}

fn parse_file_nodes(graph: &mut CodeContextGraph, file_path: &Path, content: &str) {
    let mut last_source_id: Option<String> = None;

    for (idx, line) in content.lines().enumerate() {
        let line_num = idx + 1;
        let trimmed = line.trim();

        // 1. Detect Source / Entrypoint
        if trimmed.contains("@app.route")
            || trimmed.contains("app.get")
            || trimmed.contains("app.post")
            || trimmed.contains("req.body")
            || trimmed.contains("request.args")
            || trimmed.contains("sys.argv")
        {
            let id = format!("{}:{}:src", file_path.display(), line_num);
            graph.add_node(CodeNode {
                id: id.clone(),
                symbol: "http_request_handler".to_string(),
                kind: NodeKind::Source,
                file_path: file_path.to_path_buf(),
                line_number: line_num,
            });
            last_source_id = Some(id);
        }

        // 2. Detect Sink (SQLi, Command Injection, Eval)
        if trimmed.contains(".query(")
            || trimmed.contains(".execute(")
            || trimmed.contains("eval(")
            || trimmed.contains("exec(")
            || trimmed.contains("os.system(")
            || trimmed.contains("subprocess.")
        {
            let sink_id = format!("{}:{}:sink", file_path.display(), line_num);
            graph.add_node(CodeNode {
                id: sink_id.clone(),
                symbol: "sensitive_execution_sink".to_string(),
                kind: NodeKind::Sink,
                file_path: file_path.to_path_buf(),
                line_number: line_num,
            });

            // If an active source is in the same function or file, link them with a TaintFlow edge
            if let Some(src_id) = &last_source_id {
                graph.add_edge(src_id, &sink_id, EdgeKind::TaintFlow);
            }
        }

        // 3. Detect Sanitizer / Input validation
        if trimmed.contains("sanitize") || trimmed.contains("validate") || trimmed.contains("escape") {
            let san_id = format!("{}:{}:sanitizer", file_path.display(), line_num);
            graph.add_node(CodeNode {
                id: san_id.clone(),
                symbol: "sanitization_middleware".to_string(),
                kind: NodeKind::Sanitizer,
                file_path: file_path.to_path_buf(),
                line_number: line_num,
            });
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
        };

        let fn_call = CodeNode {
            id: "fn_1".to_string(),
            symbol: "process_data".to_string(),
            kind: NodeKind::Function,
            file_path: PathBuf::from("server.py"),
            line_number: 20,
        };

        let sink = CodeNode {
            id: "sink_1".to_string(),
            symbol: "db_query".to_string(),
            kind: NodeKind::Sink,
            file_path: PathBuf::from("db.py"),
            line_number: 50,
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
        };
        graph.add_node(orphan_sink);
        let unreach = graph.evaluate_reachability("orphan_1");
        assert_eq!(unreach, ReachabilityVerdict::Unreachable);
    }
}

