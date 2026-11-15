#![allow(dead_code)]

use crate::types::{ChatMessage, HardeningPatch, Severity, VulnerabilityFinding};
use chrono::Utc;
use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub created_at: i64,
    pub active_provider: String,
    pub message_count: usize,
    pub findings_count: usize,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectRecord {
    pub id: String,
    pub root_path: String,
    pub security_md_hash: String,
    pub tech_stack_json: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeGraphNodeRecord {
    pub node_id: String,
    pub project_id: String,
    pub kind: String,
    pub symbol_name: String,
    pub file_path: String,
    pub start_line: i64,
    pub end_line: i64,
    pub ast_blake3_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeGraphEdgeRecord {
    pub edge_id: String,
    pub project_id: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub edge_type: String,
    pub metadata_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSessionRecord {
    pub session_id: String,
    pub project_id: String,
    pub operation_mode: String,
    pub diff_scope: String,
    pub active_provider: String,
    pub canvas_layout_json: Option<String>,
    pub git_checkpoint_oid: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubAgentRunRecord {
    pub agent_id: String,
    pub session_id: String,
    pub parent_agent_id: Option<String>,
    pub role_specialty: String,
    pub worktree_path: Option<String>,
    pub loaded_skills_json: String,
    pub tokens_consumed: i64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrailEntry {
    pub timestamp: String,
    pub session_id: Option<String>,
    pub agent_id: String,
    pub action: String,
    pub policy_decision: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxMessage {
    pub id: String,
    pub timestamp: String,
    pub sender: String,
    pub recipient: String,
    pub message_type: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct AuditTrailLogger {
    log_path: PathBuf,
}

impl AuditTrailLogger {
    pub fn for_project(project_root: &Path) -> Self {
        let asterisk_dir = project_root.join(".asterisk");
        let _ = fs::create_dir_all(&asterisk_dir);
        Self {
            log_path: asterisk_dir.join("audit_trail.jsonl"),
        }
    }

    pub fn log(
        &self,
        session_id: Option<&str>,
        agent_id: &str,
        action: &str,
        policy_decision: &str,
        details: serde_json::Value,
    ) -> Result<(), String> {
        let entry = AuditTrailEntry {
            timestamp: Utc::now().to_rfc3339(),
            session_id: session_id.map(|s| s.to_string()),
            agent_id: agent_id.to_string(),
            action: action.to_string(),
            policy_decision: policy_decision.to_string(),
            details,
        };

        let line = serde_json::to_string(&entry)
            .map_err(|e| format!("Failed to serialize audit entry: {e}"))?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(|e| format!("Failed to open {}: {e}", self.log_path.display()))?;

        writeln!(file, "{line}").map_err(|e| format!("Failed to write audit entry: {e}"))?;
        Ok(())
    }
}

pub struct StateStore {
    conn: Connection,
    base_dir: PathBuf,
}

impl StateStore {
    pub fn for_project(project_root: &Path) -> Result<Self, String> {
        let asterisk_dir = project_root.join(".asterisk");
        if !asterisk_dir.exists() {
            fs::create_dir_all(&asterisk_dir)
                .map_err(|e| format!("Failed to create .asterisk directory: {e}"))?;
        }
        let db_path = asterisk_dir.join("state.sqlite");
        Self::open_path(&db_path, asterisk_dir)
    }

    pub fn in_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory()
            .map_err(|e| format!("Failed to open in-memory SQLite: {e}"))?;
        let mut store = Self {
            conn,
            base_dir: PathBuf::from("."),
        };
        store.init_pragmas()?;
        store.init_schema()?;
        Ok(store)
    }

    pub fn open_path(db_path: &Path, base_dir: PathBuf) -> Result<Self, String> {
        let conn = Connection::open(db_path)
            .map_err(|e| format!("Failed to open SQLite database at {}: {e}", db_path.display()))?;
        let mut store = Self { conn, base_dir };
        store.init_pragmas()?;
        store.init_schema()?;
        Ok(store)
    }

    fn init_pragmas(&self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = NORMAL;
                 PRAGMA foreign_keys = ON;",
            )
            .map_err(|e| format!("Failed to configure SQLite pragmas: {e}"))?;
        Ok(())
    }

    pub fn init_schema(&mut self) -> Result<(), String> {
        let ddl = "
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            root_path TEXT NOT NULL UNIQUE,
            security_md_hash TEXT NOT NULL,
            tech_stack_json TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS code_graph_nodes (
            node_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            kind TEXT NOT NULL CHECK(kind IN ('FILE', 'FUNCTION', 'CLASS', 'ENDPOINT', 'DIRECT_DEP', 'TRANSITIVE_DEP', 'PHANTOM_DEP', 'MANIFEST_PERM')),
            symbol_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            start_line INTEGER NOT NULL,
            end_line INTEGER NOT NULL,
            ast_blake3_hash TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_graph_nodes_file ON code_graph_nodes(project_id, file_path);
        CREATE INDEX IF NOT EXISTS idx_graph_nodes_kind ON code_graph_nodes(project_id, kind);

        CREATE TABLE IF NOT EXISTS code_graph_edges (
            edge_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            source_node_id TEXT NOT NULL REFERENCES code_graph_nodes(node_id) ON DELETE CASCADE,
            target_node_id TEXT NOT NULL REFERENCES code_graph_nodes(node_id) ON DELETE CASCADE,
            edge_type TEXT NOT NULL CHECK(edge_type IN ('CALLS', 'IMPORTS', 'TAINT_SOURCE_TO_SINK', 'EXPOSES_CONTAINER_PORT', 'PHANTOM_IMPORT')),
            metadata_json TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_graph_edges_src ON code_graph_edges(source_node_id);
        CREATE INDEX IF NOT EXISTS idx_graph_edges_dst ON code_graph_edges(target_node_id);

        CREATE TABLE IF NOT EXISTS audit_sessions (
            session_id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            operation_mode TEXT NOT NULL CHECK(operation_mode IN ('PLAN', 'AUDIT_ONLY', 'AUTO_HARDEN')),
            diff_scope TEXT NOT NULL CHECK(diff_scope IN ('FULL', 'LOCAL_DIFF')),
            active_provider TEXT NOT NULL,
            canvas_layout_json TEXT,
            git_checkpoint_oid TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sub_agent_runs (
            agent_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL REFERENCES audit_sessions(session_id) ON DELETE CASCADE,
            parent_agent_id TEXT,
            role_specialty TEXT NOT NULL,
            worktree_path TEXT,
            loaded_skills_json TEXT NOT NULL,
            tokens_consumed INTEGER DEFAULT 0,
            status TEXT NOT NULL CHECK(status IN ('SPAWNING', 'RUNNING', 'PAUSED', 'WAITING_APPROVAL', 'COMPLETED', 'FAILED'))
        );

        CREATE TABLE IF NOT EXISTS security_findings (
            finding_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL REFERENCES audit_sessions(session_id) ON DELETE CASCADE,
            agent_id TEXT NOT NULL REFERENCES sub_agent_runs(agent_id),
            category TEXT NOT NULL CHECK(category IN ('SAST', 'SCA_CVE', 'PHANTOM_DEP', 'MALICIOUS_PKG', 'SECRET_LEAK', 'APK_MANIFEST', 'CONTAINER_CONFIG')),
            severity TEXT NOT NULL CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
            reachability_status TEXT NOT NULL CHECK(reachability_status IN ('REACHABLE', 'UNREACHABLE', 'POTENTIALLY_REACHABLE')),
            triage_verdict TEXT NOT NULL CHECK(triage_verdict IN ('TRUE_POSITIVE', 'FALSE_POSITIVE', 'PENDING')),
            triage_reasoning TEXT NOT NULL,
            file_path TEXT NOT NULL,
            line_number INTEGER NOT NULL,
            call_path_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS remediation_patches (
            patch_id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL UNIQUE REFERENCES security_findings(finding_id) ON DELETE CASCADE,
            patch_strategy TEXT NOT NULL CHECK(patch_strategy IN ('SOURCE_HARDENING', 'VENDOR_HOTFIX_BACKPORT')),
            git_diff_content TEXT NOT NULL,
            unit_test_script TEXT NOT NULL,
            unit_test_passed INTEGER NOT NULL DEFAULT 0,
            safe_outputs_passed INTEGER NOT NULL DEFAULT 0,
            applied_to_main INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS session_chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            message_json TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_session_chat_msgs ON session_chat_messages(session_id);
        ";

        self.conn
            .execute_batch(ddl)
            .map_err(|e| format!("Failed to initialize SQLite DDL schema: {e}"))?;
        Ok(())
    }

    // Projects CRUD
    pub fn upsert_project(&self, project: &ProjectRecord) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO projects (id, root_path, security_md_hash, tech_stack_json, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(id) DO UPDATE SET
                    root_path = excluded.root_path,
                    security_md_hash = excluded.security_md_hash,
                    tech_stack_json = excluded.tech_stack_json,
                    updated_at = excluded.updated_at;",
                params![
                    project.id,
                    project.root_path,
                    project.security_md_hash,
                    project.tech_stack_json,
                    project.updated_at
                ],
            )
            .map_err(|e| format!("Failed to upsert project: {e}"))?;
        Ok(())
    }

    pub fn get_file_blake3_hash(&self, project_id: &str, file_path: &str) -> Option<String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT ast_blake3_hash FROM code_graph_nodes
                 WHERE project_id = ?1 AND file_path = ?2 LIMIT 1;",
            )
            .ok()?;
        stmt.query_row(params![project_id, file_path], |row| row.get(0))
            .ok()
    }

    pub fn save_graph_snapshot(
        &mut self,
        project_id: &str,
        nodes: &[CodeGraphNodeRecord],
        edges: &[CodeGraphEdgeRecord],
    ) -> Result<(), String> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("Failed to begin transaction: {e}"))?;

        // Clear existing graph for project
        tx.execute(
            "DELETE FROM code_graph_edges WHERE project_id = ?1;",
            params![project_id],
        )
        .map_err(|e| format!("Failed to clear old edges: {e}"))?;
        tx.execute(
            "DELETE FROM code_graph_nodes WHERE project_id = ?1;",
            params![project_id],
        )
        .map_err(|e| format!("Failed to clear old nodes: {e}"))?;

        for node in nodes {
            tx.execute(
                "INSERT INTO code_graph_nodes (node_id, project_id, kind, symbol_name, file_path, start_line, end_line, ast_blake3_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8);",
                params![
                    node.node_id,
                    node.project_id,
                    node.kind,
                    node.symbol_name,
                    node.file_path,
                    node.start_line,
                    node.end_line,
                    node.ast_blake3_hash
                ],
            )
            .map_err(|e| format!("Failed to insert node {}: {e}", node.node_id))?;
        }

        for edge in edges {
            tx.execute(
                "INSERT INTO code_graph_edges (edge_id, project_id, source_node_id, target_node_id, edge_type, metadata_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6);",
                params![
                    edge.edge_id,
                    edge.project_id,
                    edge.source_node_id,
                    edge.target_node_id,
                    edge.edge_type,
                    edge.metadata_json
                ],
            )
            .map_err(|e| format!("Failed to insert edge {}: {e}", edge.edge_id))?;
        }

        tx.commit()
            .map_err(|e| format!("Failed to commit graph snapshot: {e}"))?;
        Ok(())
    }

    pub fn create_session(&self, session: &AuditSessionRecord) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO audit_sessions (session_id, project_id, operation_mode, diff_scope, active_provider, canvas_layout_json, git_checkpoint_oid, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8);",
                params![
                    session.session_id,
                    session.project_id,
                    session.operation_mode,
                    session.diff_scope,
                    session.active_provider,
                    session.canvas_layout_json,
                    session.git_checkpoint_oid,
                    session.created_at
                ],
            )
            .map_err(|e| format!("Failed to create audit session: {e}"))?;
        Ok(())
    }

    pub fn save_session_full(
        &mut self,
        session_id: &str,
        project_id: &str,
        provider: &str,
        messages: &[ChatMessage],
        findings: &[VulnerabilityFinding],
        patches: &[HardeningPatch],
    ) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp_millis();
        let existing_project_id: Option<String> = self.conn.query_row(
            "SELECT id FROM projects WHERE id = ?1 OR root_path = ?2 LIMIT 1;",
            params![project_id, project_id],
            |row| row.get(0),
        ).ok();

        let effective_proj_id = if let Some(existing_id) = existing_project_id {
            existing_id
        } else {
            let _ = self.conn.execute(
                "INSERT OR IGNORE INTO projects (id, root_path, security_md_hash, tech_stack_json, updated_at) VALUES (?1, ?2, '', '{}', ?3);",
                params![project_id, project_id, now],
            );
            project_id.to_string()
        };

        let patches_json = serde_json::to_string(patches).unwrap_or_else(|_| "[]".to_string());
        self.conn.execute(
            "INSERT INTO audit_sessions (session_id, project_id, operation_mode, diff_scope, active_provider, canvas_layout_json, git_checkpoint_oid, created_at)
             VALUES (?1, ?2, 'AUDIT_ONLY', 'FULL', ?3, ?4, '', ?5)
             ON CONFLICT(session_id) DO UPDATE SET
                active_provider = excluded.active_provider,
                canvas_layout_json = excluded.canvas_layout_json;",
            params![session_id, effective_proj_id, provider, patches_json, now],
        ).map_err(|e| format!("Failed to upsert audit session: {e}"))?;

        let _ = self.conn.execute("DELETE FROM session_chat_messages WHERE session_id = ?1;", params![session_id]);

        let tx = self.conn.transaction().map_err(|e| format!("Transaction error: {e}"))?;
        for msg in messages {
            let msg_json = serde_json::to_string(msg).unwrap_or_default();
            tx.execute(
                "INSERT INTO session_chat_messages (session_id, message_json, created_at) VALUES (?1, ?2, ?3);",
                params![session_id, msg_json, now],
            ).map_err(|e| format!("Failed to insert message: {e}"))?;
        }
        tx.commit().map_err(|e| format!("Failed to commit messages: {e}"))?;

        let _ = self.conn.execute("DELETE FROM security_findings WHERE session_id = ?1;", params![session_id]);
        if !findings.is_empty() {
            let orch_agent = format!("orch-{}", session_id);
            let _ = self.conn.execute(
                "INSERT INTO sub_agent_runs (agent_id, session_id, role_specialty, loaded_skills_json, status)
                 VALUES (?1, ?2, 'orchestrator', '[]', 'COMPLETED')
                 ON CONFLICT(agent_id) DO UPDATE SET session_id = excluded.session_id;",
                params![orch_agent, session_id],
            );
            let _ = self.save_findings(session_id, &orch_agent, findings);
        }

        Ok(())
    }

    pub fn list_sessions(&self, project_id: &str) -> Result<Vec<SessionSummary>, String> {
        let existing_project_id: Option<String> = self.conn.query_row(
            "SELECT id FROM projects WHERE id = ?1 OR root_path = ?2 LIMIT 1;",
            params![project_id, project_id],
            |row| row.get(0),
        ).ok();
        let target_project_id = existing_project_id.as_deref().unwrap_or(project_id);

        let mut stmt = self.conn.prepare(
            "SELECT s.session_id, s.created_at, s.active_provider,
                    (SELECT COUNT(*) FROM session_chat_messages WHERE session_id = s.session_id) as msg_count,
                    (SELECT COUNT(*) FROM security_findings WHERE session_id = s.session_id) as finding_count
             FROM audit_sessions s
             WHERE s.project_id = ?1
             ORDER BY s.created_at DESC;",
        ).map_err(|e| format!("Query prepare error: {e}"))?;

        let rows = stmt.query_map(params![target_project_id], |row| {
            let session_id: String = row.get(0)?;
            let created_at: i64 = row.get(1)?;
            let active_provider: String = row.get(2)?;
            let message_count: i64 = row.get(3)?;
            let findings_count: i64 = row.get(4)?;
            Ok((session_id, created_at, active_provider, message_count as usize, findings_count as usize))
        }).map_err(|e| format!("Query map error: {e}"))?;

        let mut list = Vec::new();
        for r in rows {
            let (session_id, created_at, active_provider, message_count, findings_count) = r.map_err(|e| e.to_string())?;

            let mut title = format!("Security Session {}", &session_id);
            if let Ok(mut msg_stmt) = self.conn.prepare(
                "SELECT message_json FROM session_chat_messages WHERE session_id = ?1 ORDER BY id ASC LIMIT 10;"
            ) {
                let msg_rows = msg_stmt.query_map(params![&session_id], |row| row.get::<_, String>(0));
                if let Ok(m_rows) = msg_rows {
                    for m_res in m_rows.flatten() {
                        if let Ok(ChatMessage::User(u_txt)) = serde_json::from_str::<ChatMessage>(&m_res) {
                            let trimmed = u_txt.trim();
                            if !trimmed.is_empty() {
                                title = if trimmed.len() > 40 {
                                    format!("{}...", &trimmed[..37])
                                } else {
                                    trimmed.to_string()
                                };
                                break;
                            }
                        }
                    }
                }
            }

            list.push(SessionSummary {
                session_id,
                created_at,
                active_provider,
                message_count,
                findings_count,
                title,
            });
        }
        Ok(list)
    }

    pub fn load_session_full(
        &self,
        session_id: &str,
    ) -> Result<(Vec<ChatMessage>, Vec<VulnerabilityFinding>, Vec<HardeningPatch>), String> {
        let mut messages = Vec::new();
        let mut stmt = self.conn.prepare(
            "SELECT message_json FROM session_chat_messages WHERE session_id = ?1 ORDER BY id ASC;"
        ).map_err(|e| format!("Prepare error: {e}"))?;

        let rows = stmt.query_map(params![session_id], |row| row.get::<_, String>(0))
            .map_err(|e| format!("Query error: {e}"))?;

        for r in rows {
            if let Ok(json_str) = r {
                if let Ok(msg) = serde_json::from_str::<ChatMessage>(&json_str) {
                    messages.push(msg);
                }
            }
        }

        let mut findings = Vec::new();
        if let Ok(mut f_stmt) = self.conn.prepare(
            "SELECT sf.finding_id, sf.category, sf.severity, sf.file_path, sf.line_number, sf.triage_reasoning, sf.call_path_json,
                    COALESCE(rp.applied_to_main, 0) as patched, sf.reachability_status, sf.triage_verdict
             FROM security_findings sf
             LEFT JOIN remediation_patches rp ON sf.finding_id = rp.finding_id
             WHERE sf.session_id = ?1
             ORDER BY sf.line_number ASC;"
        ) {
            if let Ok(f_rows) = f_stmt.query_map(params![session_id], |row| {
                let id: String = row.get(0)?;
                let category: String = row.get(1)?;
                let sev_str: String = row.get(2)?;
                let file_path: String = row.get(3)?;
                let line_number: i64 = row.get(4)?;
                let recommendation: String = row.get(5)?;
                let call_path_json: String = row.get(6)?;
                let patched_int: i64 = row.get(7)?;
                let reachability: String = row.get(8)?;
                let triage_verdict: String = row.get(9)?;

                let severity = match sev_str.as_str() {
                    "CRITICAL" => Severity::Critical,
                    "HIGH" => Severity::High,
                    "MEDIUM" => Severity::Medium,
                    "LOW" => Severity::Low,
                    _ => Severity::Info,
                };

                let meta: serde_json::Value =
                    serde_json::from_str(&call_path_json).unwrap_or(serde_json::Value::Null);
                let title = meta["title"]
                    .as_str()
                    .unwrap_or("Security Finding")
                    .to_string();
                let description = meta["description"].as_str().unwrap_or("").to_string();
                let snippet = meta["snippet"].as_str().unwrap_or("").to_string();
                let call_path = meta["call_path"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();

                Ok(VulnerabilityFinding {
                    id,
                    title,
                    cwe: category,
                    severity,
                    file_path: PathBuf::from(file_path),
                    line_number: line_number as usize,
                    snippet,
                    description,
                    recommendation: recommendation.clone(),
                    patched: patched_int > 0,
                    reachability,
                    triage_verdict,
                    triage_reasoning: recommendation,
                    call_path,
                })
            }) {
                for f in f_rows.flatten() {
                    findings.push(f);
                }
            }
        }

        let mut patches = Vec::new();
        if let Ok(mut p_stmt) = self.conn.prepare("SELECT canvas_layout_json FROM audit_sessions WHERE session_id = ?1;") {
            if let Ok(p_str) = p_stmt.query_row(params![session_id], |row| row.get::<_, Option<String>>(0)) {
                if let Some(s) = p_str {
                    if let Ok(pts) = serde_json::from_str::<Vec<HardeningPatch>>(&s) {
                        patches = pts;
                    }
                }
            }
        }

        Ok((messages, findings, patches))
    }

    pub fn record_sub_agent_run(&self, run: &SubAgentRunRecord) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO sub_agent_runs (agent_id, session_id, parent_agent_id, role_specialty, worktree_path, loaded_skills_json, tokens_consumed, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(agent_id) DO UPDATE SET
                    tokens_consumed = excluded.tokens_consumed,
                    status = excluded.status;",
                params![
                    run.agent_id,
                    run.session_id,
                    run.parent_agent_id,
                    run.role_specialty,
                    run.worktree_path,
                    run.loaded_skills_json,
                    run.tokens_consumed,
                    run.status
                ],
            )
            .map_err(|e| format!("Failed to record sub agent run: {e}"))?;
        Ok(())
    }

    pub fn save_findings(
        &mut self,
        session_id: &str,
        agent_id: &str,
        findings: &[VulnerabilityFinding],
    ) -> Result<(), String> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("Failed to start transaction: {e}"))?;

        for f in findings {
            let cat = match f.cwe.as_str() {
                "CWE-798" | "CWE-200" | "CWE-312" => "SECRET_LEAK",
                "CWE-1327" | "CWE-942" | "CWE-295" => "CONTAINER_CONFIG",
                "CWE-489" | "CWE-530" | "CWE-926" | "CWE-749" => "APK_MANIFEST",
                "CWE-506" => "MALICIOUS_PKG",
                "CWE-1357" | "CWE-1104" => "PHANTOM_DEP",
                s if s.starts_with("CVE") => "SCA_CVE",
                _ => "SAST",
            };

            let sev = match f.severity {
                Severity::Critical => "CRITICAL",
                Severity::High => "HIGH",
                Severity::Medium => "MEDIUM",
                Severity::Low => "LOW",
                Severity::Info => "INFO",
            };

            let reach = match f.reachability.as_str() {
                "REACHABLE" => "REACHABLE",
                "UNREACHABLE" => "UNREACHABLE",
                _ => "POTENTIALLY_REACHABLE",
            };
            let triage_v = match f.triage_verdict.as_str() {
                "FALSE_POSITIVE" => "FALSE_POSITIVE",
                "PENDING" => "PENDING",
                _ => "TRUE_POSITIVE",
            };
            let triage_r = if f.triage_reasoning.is_empty() { &f.recommendation } else { &f.triage_reasoning };

            tx.execute(
                "INSERT INTO security_findings (finding_id, session_id, agent_id, category, severity, reachability_status, triage_verdict, triage_reasoning, file_path, line_number, call_path_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(finding_id) DO UPDATE SET
                    reachability_status = excluded.reachability_status,
                    triage_verdict = excluded.triage_verdict,
                    triage_reasoning = excluded.triage_reasoning;",
                params![
                    f.id,
                    session_id,
                    agent_id,
                    cat,
                    sev,
                    reach,
                    triage_v,
                    triage_r,
                    f.file_path.to_string_lossy().to_string(),
                    f.line_number as i64,
                    serde_json::json!({
                        "title": f.title,
                        "description": f.description,
                        "snippet": f.snippet,
                        "call_path": f.call_path
                    }).to_string()
                ],
            )
            .map_err(|e| format!("Failed to insert finding {}: {e}", f.id))?;
        }

        tx.commit()
            .map_err(|e| format!("Failed to commit findings: {e}"))?;
        Ok(())
    }

    pub fn load_latest_findings(
        &self,
        project_id: &str,
    ) -> SqlResult<Vec<VulnerabilityFinding>> {
        let mut stmt = self.conn.prepare(
            "SELECT sf.finding_id, sf.category, sf.severity, sf.file_path, sf.line_number, sf.triage_reasoning, sf.call_path_json,
                    COALESCE(rp.applied_to_main, 0) as patched, sf.reachability_status, sf.triage_verdict
             FROM security_findings sf
             JOIN audit_sessions s ON sf.session_id = s.session_id
             LEFT JOIN remediation_patches rp ON sf.finding_id = rp.finding_id
             WHERE s.project_id = ?1
             ORDER BY sf.line_number ASC;",
        )?;

        let rows = stmt.query_map(params![project_id], |row| {
            let id: String = row.get(0)?;
            let category: String = row.get(1)?;
            let sev_str: String = row.get(2)?;
            let file_path: String = row.get(3)?;
            let line_number: i64 = row.get(4)?;
            let recommendation: String = row.get(5)?;
            let call_path_json: String = row.get(6)?;
            let patched_int: i64 = row.get(7)?;
            let reachability: String = row.get(8)?;
            let triage_verdict: String = row.get(9)?;

            let severity = match sev_str.as_str() {
                "CRITICAL" => Severity::Critical,
                "HIGH" => Severity::High,
                "MEDIUM" => Severity::Medium,
                "LOW" => Severity::Low,
                _ => Severity::Info,
            };

            let meta: serde_json::Value =
                serde_json::from_str(&call_path_json).unwrap_or(serde_json::Value::Null);
            let title = meta["title"]
                .as_str()
                .unwrap_or("Security Finding")
                .to_string();
            let description = meta["description"].as_str().unwrap_or("").to_string();
            let snippet = meta["snippet"].as_str().unwrap_or("").to_string();
            let call_path = meta["call_path"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            Ok(VulnerabilityFinding {
                id,
                title,
                cwe: category,
                severity,
                file_path: PathBuf::from(file_path),
                line_number: line_number as usize,
                snippet,
                description,
                recommendation: recommendation.clone(),
                patched: patched_int > 0,
                reachability,
                triage_verdict,
                triage_reasoning: recommendation,
                call_path,
            })
        })?;

        let mut results = Vec::new();
        for r in rows {
            results.push(r?);
        }
        Ok(results)
    }

    pub fn save_patches(&mut self, patches: &[HardeningPatch]) -> Result<(), String> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("Failed to start transaction: {e}"))?;

        for p in patches {
            tx.execute(
                "INSERT INTO remediation_patches (patch_id, finding_id, patch_strategy, git_diff_content, unit_test_script, unit_test_passed, safe_outputs_passed, applied_to_main)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(finding_id) DO UPDATE SET
                    git_diff_content = excluded.git_diff_content,
                    unit_test_script = excluded.unit_test_script,
                    unit_test_passed = excluded.unit_test_passed,
                    safe_outputs_passed = excluded.safe_outputs_passed,
                    applied_to_main = excluded.applied_to_main;",
                params![
                    p.id,
                    p.finding_id,
                    "SOURCE_HARDENING",
                    p.unified_diff,
                    p.unit_test_code,
                    if p.unit_test_passed { 1 } else { 0 },
                    if p.safe_outputs_passed { 1 } else { 0 },
                    if p.applied { 1 } else { 0 }
                ],
            )
            .map_err(|e| format!("Failed to insert patch {}: {e}", p.id))?;
        }

        tx.commit()
            .map_err(|e| format!("Failed to commit patches: {e}"))?;
        Ok(())
    }

    pub fn mark_patch_applied(&self, patch_id: &str, applied: bool) -> Result<(), String> {
        let val = if applied { 1 } else { 0 };
        self.conn
            .execute(
                "UPDATE remediation_patches SET applied_to_main = ?1 WHERE patch_id = ?2;",
                params![val, patch_id],
            )
            .map_err(|e| format!("Failed to update patch status: {e}"))?;
        Ok(())
    }

    // Immutable Audit Trail Logger & JSONL Mailbox
    pub fn append_audit_trail(
        &self,
        session_id: Option<&str>,
        agent_id: &str,
        action: &str,
        policy_decision: &str,
        details: serde_json::Value,
    ) -> Result<(), String> {
        let entry = AuditTrailEntry {
            timestamp: Utc::now().to_rfc3339(),
            session_id: session_id.map(|s| s.to_string()),
            agent_id: agent_id.to_string(),
            action: action.to_string(),
            policy_decision: policy_decision.to_string(),
            details,
        };

        let file_path = self.base_dir.join("audit_trail.jsonl");
        let line = serde_json::to_string(&entry)
            .map_err(|e| format!("Failed to serialize audit trail entry: {e}"))?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
            .map_err(|e| format!("Failed to open {}: {e}", file_path.display()))?;

        writeln!(file, "{line}").map_err(|e| format!("Failed to write audit trail: {e}"))?;
        Ok(())
    }

    pub fn append_mailbox(
        &self,
        sender: &str,
        recipient: &str,
        message_type: &str,
        payload: serde_json::Value,
    ) -> Result<(), String> {
        let msg = MailboxMessage {
            id: format!("msg-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)),
            timestamp: Utc::now().to_rfc3339(),
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            message_type: message_type.to_string(),
            payload,
        };

        let file_path = self.base_dir.join("mailbox.jsonl");
        let line = serde_json::to_string(&msg)
            .map_err(|e| format!("Failed to serialize mailbox message: {e}"))?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
            .map_err(|e| format!("Failed to open {}: {e}", file_path.display()))?;

        writeln!(file, "{line}").map_err(|e| format!("Failed to write mailbox: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempTestDir(PathBuf);
    impl TempTestDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("asterisk_test_{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)));
            let _ = fs::create_dir_all(&p);
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempTestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_sqlite_wal_storage_and_schema_lifecycle() {
        let dir = TempTestDir::new();
        let mut store = StateStore::for_project(dir.path()).expect("create store");

        // Verify project upsert
        let project = ProjectRecord {
            id: "proj_test".to_string(),
            root_path: dir.path().to_string_lossy().to_string(),
            security_md_hash: "blake3_hash_dummy".to_string(),
            tech_stack_json: serde_json::json!(["Rust", "Tokio"]).to_string(),
            updated_at: Utc::now().timestamp(),
        };
        store.upsert_project(&project).expect("upsert project");

        // Verify session creation
        let session = AuditSessionRecord {
            session_id: "sess_01".to_string(),
            project_id: "proj_test".to_string(),
            operation_mode: "AUTO_HARDEN".to_string(),
            diff_scope: "FULL".to_string(),
            active_provider: "AnthropicClaude".to_string(),
            canvas_layout_json: None,
            git_checkpoint_oid: "4b825dc642cb6eb9a060e54bf8d69288fbee4904".to_string(),
            created_at: Utc::now().timestamp(),
        };
        store.create_session(&session).expect("create session");

        // Verify subagent run record
        let subagent = SubAgentRunRecord {
            agent_id: "agent_sast".to_string(),
            session_id: "sess_01".to_string(),
            parent_agent_id: None,
            role_specialty: "SAST Analyzer".to_string(),
            worktree_path: None,
            loaded_skills_json: "[]".to_string(),
            tokens_consumed: 150,
            status: "RUNNING".to_string(),
        };
        store.record_sub_agent_run(&subagent).expect("record subagent");

        // Verify findings persistence
        let findings = vec![VulnerabilityFinding {
            id: "finding-sqli-01".to_string(),
            title: "SQL Injection Vulnerability".to_string(),
            cwe: "CWE-89".to_string(),
            severity: Severity::Critical,
            file_path: PathBuf::from("src/db.rs"),
            line_number: 42,
            snippet: "SELECT * FROM users WHERE id = ".to_string(),
            description: "Unsanitized user input concatenated to SQL statement".to_string(),
            recommendation: "Use parameterized queries".to_string(),
            patched: false,
            ..Default::default()
        }];
        store
            .save_findings("sess_01", "agent_sast", &findings)
            .expect("save findings");

        // Verify patches persistence
        let patches = vec![HardeningPatch {
            id: "patch-sqli-01".to_string(),
            finding_id: "finding-sqli-01".to_string(),
            target_file: PathBuf::from("src/db.rs"),
            original_snippet: "SELECT * FROM users WHERE id = ".to_string(),
            hardened_snippet: "SELECT * FROM users WHERE id = ?1".to_string(),
            unified_diff: "--- a/src/db.rs\n+++ b/src/db.rs\n@@ -42 +42 @@\n-SELECT * FROM users WHERE id = \n+SELECT * FROM users WHERE id = ?1".to_string(),
            unit_test_code: "#[test] fn test_patch() {}".to_string(),
            applied: false,
            explanation: "Parameterize query to prevent SQL injection".to_string(),
            ..Default::default()
        }];
        store.save_patches(&patches).expect("save patches");

        // Load latest findings
        let loaded = store
            .load_latest_findings("proj_test")
            .expect("load findings");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "finding-sqli-01");
        assert_eq!(loaded[0].severity, Severity::Critical);
        assert!(!loaded[0].patched);

        // Mark patch applied and verify
        store
            .mark_patch_applied("patch-sqli-01", true)
            .expect("mark applied");
        let reloaded = store
            .load_latest_findings("proj_test")
            .expect("reload findings");
        assert!(reloaded[0].patched);

        // Verify append-only audit trail and mailbox
        store
            .append_audit_trail(
                Some("sess_01"),
                "agent_sast",
                "ExecuteScan",
                "ALLOW",
                serde_json::json!({ "files_scanned": 1 }),
            )
            .expect("append audit trail");

        store
            .append_mailbox(
                "agent_sast",
                "orchestrator",
                "SCAN_COMPLETE",
                serde_json::json!({ "findings_count": 1 }),
            )
            .expect("append mailbox");

        let audit_log = dir.path().join(".asterisk").join("audit_trail.jsonl");
        let mailbox_log = dir.path().join(".asterisk").join("mailbox.jsonl");
        assert!(audit_log.exists());
        assert!(mailbox_log.exists());
        let audit_content = fs::read_to_string(audit_log).expect("read audit log");
        assert!(audit_content.contains("ExecuteScan"));
        let mailbox_content = fs::read_to_string(mailbox_log).expect("read mailbox log");
        assert!(mailbox_content.contains("SCAN_COMPLETE"));
    }
}
