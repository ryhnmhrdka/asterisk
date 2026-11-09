# TDD

# TECHNICAL DESIGN DOCUMENT (TDD)

## Sistem: SentinelHarness (AegisCode)

**Subjudul:** *Autonomous Pre-Production Code Defense, Supply-Chain Reachability & Security Audit Harness***Versi Dokumen:** 2.0 (Final Architecture Release)**Target Kategori:** Penangkalan Siber (Deteksi Dini, Pencegahan, dan Respons Otomatis Pra-Produksi)**Bahasa & Ekosistem Utama:** 100% Rust (*Single Static Binary Architecture*)**Antarmuka Pengguna:** Full Native TUI (*Split-Pane Command Center + Interactive Node-Graph Whiteboard Canvas*)

***

## 1. Tinjauan Arsitektur & Prinsip Rekayasa

### 1.1 Tujuan Dokumen

Dokumen ini menjadi acuan teknis tunggal bagi tim *engineer* dalam mengimplementasikan **SentinelHarness**—sebuah *AI Agent Execution Harness* yang bekerja di lingkungan pengembangan lokal (*developer workstation*) untuk mengaudit *source code*, memverifikasi keterjangkauan kerentanan (*function-level reachability*), mencegah penyusupan *malware* paket pihak ketiga, serta melakukan penambalan kode otomatis (*auto-hardening* & *vendor hotfix*) sebelum aplikasi dikompilasi menjadi APK atau di-*deploy* ke server produksi.

### 1.2 Persamaan Dasar Arsitektur Sistem

Sistem dirancang mengikuti prinsip pemisahan antara mesin penalaran probabilistik (LLM) dan infrastruktur eksekusi deterministik (*Harness*):

$\text{SentinelHarness} = \text{Multi-Model Router} + \underbrace{(\text{GraphCore} + \text{MCP Tools} + \text{3-Tier Skills} + \text{Worktree Sandbox} + \text{Policy Gate} + \text{TUI Canvas})}_{\text{Deterministic Rust Execution Harness}}$

### 1.3 Keputusan Arsitektur Kunci (*Key Architectural Decisions*)

1. **Modular Monolith dalam Satu Biner Tunggal (*****Single Static Binary*****):** Menghindari penggunaan *microservices* yang rumit diinstal oleh *developer*. Seluruh komponen (TUI, Kernel Orkestrator, Mesin AST, dan Database SQLite) dikompilasi menjadi satu berkas eksekusi mandiri.
2. **Komunikasi Internal Berbasis Actor & Channel Asinkron:** Setiap komponen berjalan sebagai *task* independen di atas *runtime* `tokio` dan berkomunikasi melalui saluran pesan *non-blocking* (`mpsc` dan `broadcast`), menjamin antarmuka TUI tetap responsif pada 60 FPS meskipun agen sedang memindai ribuan berkas di latar belakang.
3. **Deterministic-First, AI-Second:** Agen AI tidak diizinkan membaca seluruh repositori secara mentah. Mesin deterministik (`GraphCore`) membangun peta hubungan fungsi dan alur data terlebih dahulu, lalu menyuapkan konteks yang sudah terfokus kepada *Sub-Agent*.

***

## 2. Spesifikasi Tech Stack (Ekosistem Rust)

Seluruh kode sumber sistem ditulis dalam bahasa **Rust (Edition 2024, MSRV 1.82+)** dengan rincian pustaka (*crates*) sebagai berikut:

| Kategori Komponen               | Crate Utama                           | Versi / Fitur Kunci                               | Alasan Pemilihan & Peran Teknis                                                                                                          |
| ------------------------------- | ------------------------------------- | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **TUI Rendering Engine**        | `ratatui` + `crossterm`               | `ratatui >= 0.29`                                 | *Immediate-mode terminal rendering* dengan *double-buffering diff* yang sangat hemat CPU dan memori.                                     |
| **TUI Infinite Whiteboard**     | `rataflow` + `tui-overlay`            | *Sugiyama Layout, Braille Edges*                  | Menyediakan kanvas *node-graph* interaktif di terminal (mendukung *pan*, *zoom*, *drag node* dengan *mouse*, dan *MiniMap*).             |
| **Async Runtime & Parallelism** | `tokio` + `rayon`                     | `tokio (full)`, `rayon`                           | `tokio` mengelola I/O jaringan LLM dan *event loop* TUI; `rayon` memparalelkan parsing AST ribuan berkas di seluruh *core* CPU.          |
| **Code Context Graph & AST**    | `tree-sitter` + `petgraph`            | Multi-grammar (JS/TS, Py, Go, Java, Kotlin, Rust) | Membedah kode sumber menjadi *Abstract Syntax Tree* (AST) dan membangun graf berarah (*Call Graph* & *Taint Flow*) di memori.            |
| **File & Git Operations**       | `ignore` + `git2` + `similar`         | *libgit2 binding*, *diff engine*                  | Menyapu pohon direktori dengan menghormati `.gitignore`, membuat **Git Worktree** terisolasi, menyapu `--git-logs`, dan merender *diff*. |
| **MCP & Agent Protocol**        | `model-context-protocol`              | JSON-RPC 2.0, `#[mcp_tool]`                       | Standarisasi pemanggilan alat oleh *Orchestrator* dan *Sub-Agent* dengan validasi skema JSON otomatis.                                   |
| **Multi-Model AI Gateway**      | `reqwest` + `eventsource-stream`      | HTTP/2, SSE Streaming                             | Menghubungkan *Smart Router* ke model lokal (**Ollama**, **LM Studio**) maupun API Cloud (Claude, OpenAI, Gemini, DeepSeek).             |
| **Embedded Storage**            | `rusqlite` (bundled)                  | Mode `WAL`, FTS5                                  | Menyimpan graf kode, status sesi, dan hasil audit dalam satu berkas `.sentinel/state.sqlite` tanpa instalasi server DB eksternal.        |
| **Serialization & Config**      | `serde` + `serde_json` + `serde_yaml` | Derive macros                                     | Mem-parsing *frontmatter* YAML pada `.skill.md`, membaca `SECURITY.md`, dan mengelola aliran *Async JSONL Mailbox*.                      |
| **Telemetry & Audit Log**       | `tracing` + `opentelemetry`           | JSONL Exporter                                    | Mencatat seluruh jejak keputusan agen dan pemanggilan alat secara *append-only* untuk kepatuhan audit.                                   |

***

## 3. Arsitektur Sistem & Diagram Alir

### 3.1 Diagram Arsitektur Tingkat Tinggi (*High-Level Component Architecture*)

```markdown
+===================================================================================================+
|                             SENTINEL-HARNESS SINGLE BINARY (RUST)                                 |
|                                                                                                   |
|  +---------------------------------------------------------------------------------------------+  |
|  | [LAPISAN 3: PRESENTATION & STEERING LAYER] (crate: sentinel-tui | Thread Utama @ 60 FPS)     |  |
|  |                                                                                             |  |
|  |  +---------------------------------------+   +-------------------------------------------+  |  |
|  |  | Rataflow Interactive Whiteboard       |   | Split-Pane Inspector & Diff Viewer        |  |  |
|  |  | • Node Orchestrator & Organic Agents  |   | • Side-by-Side Git Diff (Before vs After) |  |  |
|  |  | • Code Context Call-Graph View        |   | • Live Security Unit-Test Runner Output   |  |  |
|  |  | • Dynamic Decision Tree & Braille Edge|   | • Auditable Triage Reasoning Inspector    |  |  |
|  |  +---------------------------------------+   +-------------------------------------------+  |  |
|  |  +---------------------------------------------------------------------------------------+  |  |
|  |  | Steerable Slash-Command REPL (/init-sec, /audit, /reachability, /patch, /hotfix, dll) |  |  |
|  |  +---------------------------------------------------------------------------------------+  |  |
|  +----------------------------------------------+----------------------------------------------+  |
|                                                 |                                                 |
|                     UiActionChannel (mpsc)      |      TelemetryBroadcast (broadcast)             |
|                                                 v                                                 |
|  +---------------------------------------------------------------------------------------------+  |
|  | [LAPISAN 2: HARNESS GOVERNANCE & ISOLATION KERNEL] (crate: sentinel-core | Tokio Runtime)   |  |
|  |                                                                                             |  |
|  |  +-----------------------------+  +-----------------------------+  +---------------------+  |  |
|  |  | Pre-Execution Policy Gate   |  | Background Sec Classifier   |  | Workspace Isolator  |  |  |
|  |  | • Hierarki: Deny->Ask->Allow|  | • Anti-Prompt Injection     |  | • Git Worktree Pool |  |  |
|  |  | • Session Scope Lock        |  | • Tool Call Schema Validator|  | • Snapshot Rewind   |  |  |
|  |  +-----------------------------+  +-----------------------------+  +---------------------+  |  |
|  |  +-----------------------------------------------+  +------------------------------------+  |  |
|  |  | Async JSONL Mailbox Router (Inter-Agent Bus)  |  | Immutable Audit Trail & SafeOutput |  |  |
|  |  +-----------------------------------------------+  +------------------------------------+  |  |
|  +----------------------------------------------+----------------------------------------------+  |
|                                                 |                                                 |
|                                                 v                                                 |
|  +---------------------------------------------------------------------------------------------+  |
|  | [LAPISAN 1: CORE INTELLIGENCE & DETERMINISTIC ENGINES] (crates: sentinel-agents & engines)  |  |
|  |                                                                                             |  |
|  |  +---------------------------------------+   +-------------------------------------------+  |  |
|  |  | Orchestrator & Organic Spawner        |   | Multi-Model Smart Router (AI Gateway)     |  |  |
|  |  | • Threat Modeling & Task Graph Builder|   | • Local Offline: Ollama / LM Studio       |  |  |
|  |  | • Dynamic Sub-Agent Instantiation     |   | • Cloud API: Claude / GPT / Gemini / GLM  |  |  |
|  |  | • 3-Tier Skill Registry & Synthesizer |   | • Context Compaction Middleware (75% Cap) |  |  |
|  |  +---------------------------------------+   +-------------------------------------------+  |  |
|  |                                                                                             |  |
|  |  +---------------------------------------------------------------------------------------+  |  |
|  |  | Deterministic MCP Core Engine Server (#[mcp_server])                                  |  |  |
|  |  |  [1. GraphCore AST]   [2. Tri-Stage SAST]   [3. SCA Reachability & Phantom Detector]  |  |  |
|  |  |  [4. Pre-Install Malware & Git-Secret]  [5. APK & Dockerfile Guard]  [6. Hotfix Gen]  |  |  |
|  |  +---------------------------------------------------------------------------------------+  |  |
|  +----------------------------------------------+----------------------------------------------+  |
+=================================================|=================================================+
                                                  |
                                                  v
  +---------------------------------------------------------------------------------------------+
  | [LOCAL WORKSPACE STORAGE & SANDBOX] (Direktori Proyek Lokal: ./.sentinel/ & ./SECURITY.md)   |
  |  ├─ state.sqlite (WAL Mode)     ├─ mailbox.jsonl & audit_trail.jsonl     ├─ worktrees/wt-*   |
  |  └─ skills/ (Tier-1 Built-in, Tier-2 User Import/Export, Tier-3 Orchestrator Synthesized)    |
  +---------------------------------------------------------------------------------------------+
```

***

### 3.2 Diagram Urutan Eksekusi End-to-End (*Sequence Diagram: Siklus Audit, Triage & Auto-Hardening*)

Diagram berikut menggambarkan interaksi antar-komponen saat pengguna mengeksekusi perintah `/audit --diff-scope=local` hingga penambalan otomatis (`/patch`):

```markdown
Developer (TUI)       Sentinel-TUI        Sentinel-Core       GraphCore & MCP      Orchestrator      Sub-Agents (Isolated)
      |                    |                    |                    |                  |                      |
      |-- /audit --diff -->|                    |                    |                  |                      |
      |                    |-- UiAction::Audit->|                    |                  |                      |
      |                    |                    |-- Lock Scope & --->|                  |                      |
      |                    |                    |   Parse Git Diff   |                  |                      |
      |                    |                    |<-- AST CallGraph --|                  |                      |
      |                    |                    |                    |                  |                      |
      |                    |                    |-- Start Session --------------------->|                      |
      |                    |                    |                    |                  |-- Read SECURITY.md   |
      |                    |                    |                    |                  |-- Synth Custom Skill |
      |                    |                    |                    |                  |-- Spawn Organic ---->|
      |                    |<-- Event: AgentSpawned (Render Nodes on Rataflow Canvas) --|   (SAST, SCA, Patch) |
      |                    |                    |                    |                  |                      |
      |                    |                    |                    |<-- Load Skill Header (YAML Only) -------|
      |                    |                    |<-- Request MCP Tool: trace_taint_flow -----------------------|
      |                    |                    |-- Policy Gate (Allow) --------------->|                      |
      |                    |                    |                    |-- Return Taint ->|--------------------->|
      |                    |                    |                    |                  |                      |
      |                    |                    |                    |<-- On-Demand Load Full .skill.md -------|
      |                    |                    |                    |                  |                      |
      |                    |<-- Event: MailboxRouted (SAST -> Triage Agent: Finding #01) ----------------------|
      |                    |                    |                    |                  |                      |
      |                    |                    |                    |                  |   [Triage Verdict:   |
      |                    |                    |                    |                  |    REACHABLE / TP]   |
      |                    |                    |                    |                  |                      |
      |                    |                    |<-- Create Git Worktree (wt-patch-01) ------------------------|
      |                    |                    |                    |                  |   • Write Unit-Test  |
      |                    |                    |                    |                  |   • Apply Code Patch |
      |                    |                    |                    |                  |   • Run Test (PASS)  |
      |                    |                    |-- Run Safe Outputs Gate (Semgrep/Secret Check) ------------->|
      |                    |<-- Event: PatchReady (Node Turns Green, Diff Available) --------------------------|
      |                    |                    |                    |                  |                      |
      |-- Press [Enter] -->|                    |                    |                  |                      |
      |   to Apply Patch   |-- Merge Worktree ->|                    |                  |                      |
      |<-- Diff Applied ---|                    |                    |                  |                      |
```

***

## 4. Desain Database & Struktur Penyimpanan Lokal (ERD & DDL)

### 4.1 Struktur Direktori Penyimpanan Lokal (`.sentinel/`)

Saat pengguna menjalankan `/init-sec` pada suatu repositori proyek lokal, sistem membuat struktur direktori tersembunyi berikut:

```markdown
<project-root>/
├── SECURITY.md                        # Memori konteks arsitektur & AI Context Rules (Ground Truth)
├── patches/                           # Berkas .patch untuk Local Dependency Hotfix (tanpa upgrade)
└── .sentinel/
    ├── config.toml                    # Konfigurasi provider model (Ollama/Cloud) & preferensi TUI
    ├── state.sqlite                   # Database utama (Graph Cache, Findings, Checkpoints)
    ├── state.sqlite-wal               # Write-Ahead Log untuk akses konkuren baca/tulis cepat
    ├── mailbox.jsonl                  # Bus pesan asinkron antar Sub-Agent
    ├── audit_trail.jsonl              # Log kepatuhan OpenTelemetry yang tidak dapat diubah
    ├── skills/
    │   ├── custom/                    # Tier-2: Skill hasil kreasi manual / import pengguna
    │   └── synthesized/               # Tier-3: Skill yang di-generate otomatis oleh Orchestrator
    └── worktrees/                     # Ruang isolasi Git Worktree untuk uji coba & penambalan
        ├── wt-agent-sast-01/
        └── wt-agent-patcher-01/
```

### 4.2 Entity Relationship Diagram (ERD)

```markdown
+----------------------+       1:N       +------------------------+
|       projects       |---------------->|     audit_sessions     |
+----------------------+                 +------------------------+
| PK id (TEXT)         |                 | PK session_id (TEXT)   |
| UQ root_path (TEXT)  |                 | FK project_id (TEXT)   |
|    security_md_hash  |                 |    operation_mode      |
|    tech_stack_json   |                 |    canvas_layout_json  |
+----------+-----------+                 +-----------+------------+
           |                                         |
           | 1:N                                     | 1:N
           v                                         v
+----------------------+                 +------------------------+       1:N       +----------------------+
|   code_graph_nodes   |                 |     sub_agent_runs     |---------------->|   tool_invocations   |
+----------------------+                 +------------------------+                 +----------------------+
| PK node_id (TEXT)    |                 | PK agent_id (TEXT)     |                 | PK call_id (TEXT)    |
| FK project_id (TEXT) |                 | FK session_id (TEXT)   |                 | FK agent_id (TEXT)   |
|    kind (ENUM)       |                 |    parent_agent_id     |                 |    mcp_tool_name     |
|    symbol_name       |                 |    role_specialty      |                 |    args_json         |
|    file_path         |                 |    worktree_path       |                 |    policy_decision   |
|    ast_blake3_hash   |                 |    tokens_consumed     |                 |    duration_ms       |
+----------+-----------+                 +-----------+------------+                 +----------------------+
           |                                         |
           | 1:N (Source / Target)                   | 1:N
           v                                         v
+----------------------+                 +------------------------+       1:1       +----------------------+
|   code_graph_edges   |                 |   security_findings    |---------------->| remediation_patches  |
+----------------------+                 +------------------------+                 +----------------------+
| PK edge_id (TEXT)    |                 | PK finding_id (TEXT)   |                 | PK patch_id (TEXT)   |
| FK source_node_id    |                 | FK session_id (TEXT)   |                 | FK finding_id (TEXT) |
| FK target_node_id    |                 | FK agent_id (TEXT)     |                 |    patch_strategy    |
|    edge_type (ENUM)  |                 |    category            |                 |    git_diff_content  |
|    taint_metadata    |                 |    reachability_status |                 |    unit_test_script  |
+----------------------+                 |    triage_verdict      |                 |    test_passed (BOOL)|
                                         |    triage_reasoning    |                 |    safe_output_passed|
                                         |    call_path_json      |                 +----------------------+
                                         +------------------------+
```

### 4.3 Skema DDL SQLite (`crates/sentinel-core/migrations/001_init.sql`)

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

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
CREATE INDEX idx_graph_nodes_file ON code_graph_nodes(project_id, file_path);
CREATE INDEX idx_graph_nodes_kind ON code_graph_nodes(project_id, kind);

CREATE TABLE IF NOT EXISTS code_graph_edges (
    edge_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    source_node_id TEXT NOT NULL REFERENCES code_graph_nodes(node_id) ON DELETE CASCADE,
    target_node_id TEXT NOT NULL REFERENCES code_graph_nodes(node_id) ON DELETE CASCADE,
    edge_type TEXT NOT NULL CHECK(edge_type IN ('CALLS', 'IMPORTS', 'TAINT_SOURCE_TO_SINK', 'EXPOSES_CONTAINER_PORT', 'PHANTOM_IMPORT')),
    metadata_json TEXT
);
CREATE INDEX idx_graph_edges_src ON code_graph_edges(source_node_id);
CREATE INDEX idx_graph_edges_dst ON code_graph_edges(target_node_id);

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
```

***

## 5. Spesifikasi 6 Modul Mesin Inti (*Core Engine Modules*)

Enam modul berikut diimplementasikan di dalam *crate* `sentinel-graph` dan `sentinel-scanners` untuk menyuplai data deterministik berakurasi tinggi kepada *Sub-Agent*:

### 5.1 Modul 1: `GraphCore AST & Taint Engine`

* **Input:** Direktori *source code* lokal atau daftar berkas yang berubah dari `git diff`.
* **Algoritma & Proses:**
  1. Menghitung *hash* `BLAKE3` setiap berkas dan membandingkannya dengan kolom `ast_blake3_hash` di SQLite. Hanya berkas yang memiliki *hash* baru yang di-parsing ulang (*Incremental Parsing*).
  2. Menjalankan `tree-sitter` secara paralel menggunakan `rayon::par_iter` untuk mengekstrak deklarasi fungsi, kelas, rute API (*entrypoints*), pernyataan `import`, dan pemanggilan fungsi.
  3. Menyusun struktur graf berarah di memori menggunakan `petgraph::graph::DiGraph` dan melacak jalur aliran data (*Taint Analysis*) dari titik masuk pengguna (`req.body`, `Intent.getExtras()`, `sys.argv`) menuju titik eksekusi sensitif (`db.query()`, `exec()`, `WebView.loadUrl()`).

### 5.2 Modul 2: `Tri-Stage AI SAST & Contextual Triage Engine`

* **Arsitektur Pipeline:**
  1. **Stage 1 (Detection):** Mengambil sub-graf yang memiliki jalur *Taint Source-to-Sink* dari `GraphCore`.
  2. **Stage 2 (Auditable Triage):** Menggabungkan sub-graf tersebut dengan aturan fakta manusia di dalam **`SECURITY.md`****&#x20;(*****AI Context Rules*****)**. *Triage Sub-Agent* mengevaluasi apakah jalur tersebut sudah melewati fungsi sanitasi/autentikasi, lalu mengeluarkan status `TRUE_POSITIVE` atau `FALSE_POSITIVE` beserta argumen teknis yang disimpan di kolom `triage_reasoning`.
  3. **Stage 3 (Contextual Remediation):** Hanya temuan `TRUE_POSITIVE` yang diteruskan ke *Patcher Sub-Agent*.

### 5.3 Modul 3: `SCA Function-Level Reachability & Phantom Resolver`

* **Deteksi Phantom Dependency:** Membandingkan himpunan seluruh modul eksternal yang dipanggil pada simpul AST (`IMPORTS`) dengan daftar dependensi langsung di berkas manifest (`package.json`, `Cargo.toml`, `requirements.txt`, `pom.xml`, `build.gradle`). Setiap paket yang diimpor di kode tetapi absen di manifest langsung ditandai sebagai `PHANTOM_DEP`.
* **Analisis Reachability Tiga Lapis:**
  1. *Function-Level Reachability:* Menggunakan algoritma *Breadth-First Search (BFS)* pada `petgraph` untuk memeriksa apakah ada jalur panggilan dari kode aplikasi menuju fungsi spesifik di dalam *library* yang memiliki CVE.
  2. *Dependency-Level:* Paket diimpor, namun fungsi spesifik tidak dapat dipetakan secara statis (`POTENTIALLY_REACHABLE`).
  3. *Unreachable:* Paket ada di pohon dependensi transitif, tetapi tidak ada satu pun jalur panggilan dari aplikasi yang menyentuhnya (`UNREACHABLE` $\to$ otomatis disaring dari daftar prioritas).

### 5.4 Modul 4: `Pre-Install Malware Shield & Git-History Secret Validator`

* **Pre-Install Malware Inspector:**
  * Menghitung jarak *Levenshtein* dan *Jaro-Winkler* pada nama paket terhadap daftar 10.000 paket paling populer di tiap ekosistem untuk menangkal *typosquatting*.
  * Memeriksa kait skrip instalasi (`preinstall`, `postinstall`, `setup.py`) terhadap pola pencurian kredensial, pembacaan variabel lingkungan sensitif, eksekusi *shell* terenkode (`base64`, `eval`), dan pemanggilan jaringan ke IP mencurigakan.
* **Git-Logs Secret Extractor:**
  * Menelusuri seluruh *commit* di semua *branch* menggunakan `git2::Revwalk` (`--git-logs`), mengekstrak kandidat kunci rahasia dengan analisis entropi Shannon dan pola struktur token, lalu menugaskan *Secret Validator Sub-Agent* untuk memeriksa konteks kode di sekitarnya guna memisahkan kredensial produksi asli dari *dummy test token*.

### 5.5 Modul 5: `Pre-Build Mobile APK & Container Config Guard`

* **Audit Pra-Kompilasi APK Android:** Mem-parsing `AndroidManifest.xml` dan konfigurasi `build.gradle` untuk mendeteksi komponen `Activity`, `Service`, `BroadcastReceiver`, dan `ContentProvider` yang memiliki atribut `android:exported="true"` tanpa proteksi izin, penggunaan `cleartextTrafficPermitted`, konfigurasi *WebView* berisiko (`setJavaScriptEnabled(true)` + `addJavascriptInterface`), serta celah *Intent Spoofing* pada kode Kotlin/Java/Flutter.
* **Code-to-Container Reachability:** Mem-parsing `Dockerfile` dan `docker-compose.yml` lokal (memeriksa eksekusi *user* `root`, *port* yang diekspos, dan *base image* rentan) lalu menghubungkannya ke simpul *endpoint* pada `GraphCore`.

### 5.6 Modul 6: `Sandbox Auto-Hardening & Vendor Hotfix Engine`

* **Auto-Hardening pada Source Code Sendiri:** Membuat *Git Worktree* baru di `.sentinel/worktrees/`, menulis skrip **Security Unit Test** yang menyimulasikan input berbahaya pada fungsi rentan, menulis kode perbaikan pada *source code*, dan mengeksekusi *test runner* lokal hingga lulus.
* **Vendor Hotfix Backport (Tanpa Upgrade Versi):** Apabila celah berada di dalam fungsi *library* pihak ketiga dan *upgrade* versi berisiko merusak kompilasi (*breaking changes*), agen memodifikasi fungsi *library* lokal secara terisolasi dan menghasilkan berkas tambalan standar di direktori `./patches/<nama-paket>+<versi>.patch` yang otomatis diterapkan saat proses *build*.

***

## 6. Desain Antarmuka Internal, Kontrak Event & Protokol MCP

### 6.1 Definisi Tipe Data Komunikasi Asinkron (`crates/sentinel-core/src/events.rs`)

```rust
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Aksi yang dikirim dari Thread TUI ke Kernel Harness melalui mpsc::Sender
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UiCommand {
    ExecuteSlash {
        command: String,
        args: Vec<String>,
    },
    SteerAgent {
        agent_id: Uuid,
        user_hint: String,
    },
    PauseOrResumeAgent {
        agent_id: Uuid,
    },
    PruneDecisionBranch {
        agent_id: Uuid,
        branch_id: String,
    },
    ResolvePermissionGate {
        call_id: Uuid,
        approved: bool,
    },
    ApplyRemediationPatch {
        patch_id: Uuid,
    },
    RewindToCheckpoint {
        session_id: Uuid,
    },
}

/// Event telemetri real-time dari Kernel & Sub-Agent ke TUI melalui broadcast::Sender
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HarnessTelemetryEvent {
    GraphMappingCompleted {
        total_files: usize,
        total_nodes: usize,
        total_edges: usize,
        duration_ms: u64,
    },
    OrganicAgentSpawned {
        agent_id: Uuid,
        parent_id: Option<Uuid>,
        role_specialty: String,
        assigned_skills: Vec<String>,
    },
    SkillSynthesizedByOrchestrator {
        skill_id: String,
        file_path: String,
        trigger_summary: String,
    },
    MailboxMessageRouted {
        from_agent: Uuid,
        to_agent: Uuid,
        finding_id: Option<Uuid>,
        headline: String,
    },
    DecisionNodeUpdated {
        agent_id: Uuid,
        branch_id: String,
        label: String,
        state: DecisionNodeState,
    },
    PatchVerificationCompleted {
        patch_id: Uuid,
        finding_id: Uuid,
        unit_test_passed: bool,
        safe_outputs_passed: bool,
        git_diff_preview: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecisionNodeState {
    Pending,
    Executing,
    VerifiedTruePositive,
    FilteredFalsePositive,
    HardenedAndPassed,
    FailedWithError(String),
}
```

### 6.2 Kontrak Ekosistem 3-Tier Skills (`.skill.md` Format)

Setiap berkas `.skill.md` wajib mematuhi struktur *frontmatter* YAML berikut agar *Sub-Agent* dapat melakukan **Progressive Disclosure** (memuat hanya metadata berukuran \~150 byte saat inisialisasi, dan baru memanggil isi lengkapnya saat dibutuhkan):

```markdown
---
skill_id: "owasp-sql-injection-hardening-v2"
name: "SQL & ORM Injection Triage and Auto-Hardening"
tier: "default" # Nilai valid: default | user-custom | orchestrator-synthesized
target_languages: ["typescript", "javascript", "python", "go", "java", "php"]
trigger_conditions:
  ast_edge_types: ["TAINT_SOURCE_TO_SINK"]
  sink_patterns: ["query", "raw", "execute", "exec", "createQuery"]
required_mcp_tools: ["trace_taint_flow", "read_file_scoped", "run_sandbox_unit_test"]
---

## 1. Panduan Triage & Eliminasi False Positive
1. Periksa apakah variabel input telah melewati fungsi parameterisasi atau *prepared statement*.
2. Periksa berkas `SECURITY.md` proyek untuk melihat apakah terdapat *middleware* validasi skema (seperti `zod`, `pydantic`, atau validator internal) di hulu *call path*.

## 2. Prosedur Pembuatan Security Unit-Test Lokal
Buat pengujian unit terisolasi di dalam Git Worktree yang mengirimkan *payload* uji ketahanan karakter kutip dan operator logika tanpa memodifikasi database utama (gunakan *mock/in-memory driver*).

## 3. Pola Auto-Hardening Kontekstual
Ubah penyambungan string (*string interpolation/concatenation*) menjadi *parameterized query* sesuai pustaka database yang sudah dipakai di proyek tersebut.
```

***

## 7. Desain Arsitektur Full-TUI & Interactive Whiteboard Canvas

### 7.1 Arsitektur Rendering Tanpa Lag (*Event Drain & 60 FPS Render Loop*)

Untuk memastikan kanvas *Whiteboard* di terminal berjalan semulus aplikasi grafis *native*, modul `sentinel-tui` menerapkan tiga mekanisme wajib:

1. **Aggressive Mouse & Key Event Draining:**
   Saat pengguna menggeser kanvas (*drag*) dengan *mouse* di terminal, terminal membombardir aplikasi dengan ratusan *event* `MouseEventKind::Moved` per detik. *Loop* utama TUI **wajib menguras habis seluruh antrean&#x20;*****event*****&#x20;****`crossterm::event::poll(Duration::ZERO)`****&#x20;terlebih dahulu**, menggabungkan delta pergeseran koordinat $(dx, dy)$, dan baru memanggil `terminal.draw()` satu kali per siklus *frame* (16,6 milidetik).
2. **Spatial Grid Culling & Scratch Buffers (****`rataflow`****):**
   Kanvas menggunakan koordinat dunia virtual tanpa batas $(-\infty \dots +\infty)$. Sebelum menggambar ke layar terminal, *viewport camera* menghitung kotak pembatas (*bounding box*) area yang terlihat dan hanya merender *node* Sub-Agent serta *edge* panah yang berpotongan dengan layar aktif.
3. **Tata Letak Hirarki Otomatis (*****Sugiyama Layered Graph Layout*****):**
   Ketika *Orchestrator* melahirkan beberapa *Sub-Agent* secara organik, algoritma *Sugiyama* secara otomatis menghitung posisi koordinat $(X, Y)$ setiap *node* baru agar panah hubungan antar-agen tidak saling bertumpuk.

### 7.2 Tata Letak Layar & Peta Navigasi TUI (*Keybindings & Mouse Controls*)

| Tombol / Aksi Mouse                                          | Konteks Panel              | Aksi Sistem                                                                                                      |
| ------------------------------------------------------------ | -------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| **`Mouse Drag`****&#x20;/&#x20;****`h, j, k, l`**            | Panel 1: Whiteboard Canvas | Menggeser kamera (*panning*) melintasi kanvas tanpa batas.                                                       |
| **`Mouse Scroll`****&#x20;/&#x20;****`+`****,&#x20;****`-`** | Panel 1: Whiteboard Canvas | Memperbesar atau memperkecil tampilan detail *node* di kanvas (*Zoom Level*).                                    |
| **`Klik Kiri`****&#x20;/&#x20;****`Tab`**                    | Panel 1: Whiteboard Canvas | Memilih *node* Sub-Agent atau simpul fungsi kode dan menampilkan detailnya di Panel 2 (*Inspector*).             |
| **`Space`**                                                  | Pada *Node* Agen Terpilih  | Menjeda (*Pause*) atau melanjutkan (*Resume*) eksekusi *Sub-Agent* tersebut secara instan.                       |
| **`s`**                                                      | Pada *Node* Agen Terpilih  | Membuka kotak dialog *Steer* untuk menyuntikkan petunjuk atau fakta baru ke dalam memori *Sub-Agent*.            |
| **`Enter`**                                                  | Pada *Node* Patch Hijau    | Membuka jendela konfirmasi untuk menerapkan (*merge*) kode tambalan dari *Git Worktree* ke proyek utama.         |
| **`Esc`****&#x20;+&#x20;****`Esc`****&#x20;(2x Cepat)**      | Global TUI                 | **Reversible Checkpoint Rewind:** Membatalkan perubahan terakhir dan mengembalikan *working tree* ke titik aman. |
| **`/`**                                                      | Global TUI                 | Memfokuskan kursor langsung ke Panel 3 (*Slash Command REPL*) dengan menu *autocompletion*.                      |

***

## 8. Kebutuhan Non-Fungsional (NFR): Keamanan, Performa & Skalabilitas

### 8.1 Standar Keamanan Internal (*Hardened Harness Security*)

1. **Kepatuhan Mutlak Pipa Izin (****`Deny`****&#x20;****$\to$****&#x20;****`Ask`****&#x20;****$\to$****&#x20;****`Allow`****):**
   Setiap pemanggilan fungsi MCP melewati validator `PolicyGate::evaluate(&ToolCall)`. Aturan `Deny` (seperti larangan memodifikasi berkas di luar direktori proyek, larangan mengeksekusi biner sistem berbahaya, atau larangan membuka soket jaringan keluar saat uji unit lokal) bersifat *hardcoded* di dalam Rust dan **fail-closed**.
2. **Kanonikalisasi Jalur Berkas (*****Path Traversal Prevention*****):**
   Seluruh alat baca/tulis berkas wajib memanggil `std::fs::canonicalize(target_path)` dan memverifikasi `canonical_path.starts_with(&project_root_canonical)`. Serangan *symlink* atau `../` yang mengarah ke luar folder proyek otomatis ditolak sebelum menyentuh diska.
3. **Isolasi Konteks dari&#x20;*****Indirect Prompt Injection*****:**
   Komentar atau string di dalam *source code* proyek target diperlakukan sebagai **Untrusted Data**. *Background Security Classifier* memeriksa validitas rencana pemanggilan alat hanya dengan mencocokkan perintah asli pengguna dan skema parameter alat, tanpa membaca teks alasan (*chain-of-thought*) dari *Sub-Agent* yang berpotensi tercemar.

### 8.2 Target Performa & Anggaran Sumber Daya (*Performance Budgets*)

* **Waktu Mulai Dingin (*****Cold Start Time*****):** $\le 50 \text{ ms}$ hingga antarmuka TUI tampil penuh di layar terminal.
* **Konsumsi Memori (RAM):** $\le 65 \text{ MB}$ saat *idle*; $\le 250 \text{ MB}$ saat memproses proyek skala menengah (100.000 baris kode).
* **Kecepatan Pemetaan&#x20;****`GraphCore`****&#x20;Awal (****`/init-sec`****):** $\ge 15.000 \text{ baris kode/detik}$ dengan pemindaian multi-inti `rayon`.
* **Latensi Audit Inkremental (****`/audit --diff-scope=local`****):** $\le 12 \text{ detik}$ dari perintah dijalankan hingga hasil *Triage* tampil di kanvas TUI.
* **Batas Kompresi Konteks Otomatis:** Middleware router otomatis memicu peringkasan konteks (*Context Compaction*) ketika pemakaian token *Sub-Agent* menyentuh **75% kapasitas jendela konteks model**, menjaga agar agen tidak pernah mengalami degradasi penalaran (*context rot*).

***

## 9. Struktur Repositori (Cargo Workspace) & Strategi Deployment

### 9.1 Tata Letak Cargo Workspace (`Cargo.toml`)

```
sentinel-harness/
├── Cargo.toml                         # Konfigurasi Workspace & profil rilis LTO
├── Cargo.lock
├── SECURITY.md                        # Dogfooding: Aturan keamanan internal SentinelHarness
├── assets/
│   └── builtin_skills/                # Tier-1 Default Skills (.skill.md) yang di-embed ke binary
│       ├── owasp-sast-triage.skill.md
│       ├── sca-reachability-triage.skill.md
│       ├── apk-manifest-guard.skill.md
│       ├── malicious-package-heuristics.skill.md
│       ├── secret-validation-triage.skill.md
│       ├── container-code-reachability.skill.md
│       ├── contextual-code-hardening.skill.md
│       └── vendor-hotfix-backport.skill.md
└── crates/
    ├── sentinel-cli/                  # Crate Binary Utama (Entrypoint CLI & inisialisasi sistem)
    │   └── src/main.rs
    ├── sentinel-tui/                  # Lapisan 3: Antarmuka Full-TUI & Rataflow Whiteboard
    │   └── src/
    │       ├── lib.rs
    │       ├── app.rs                 # Loop utama 60 FPS, Mouse Drain, & Split-Pane Manager
    │       ├── whiteboard_canvas.rs   # Widget Rataflow, Sugiyama Auto-Layout, & Braille Edges
    │       ├── inspector_modal.rs     # Panel Diff Viewer, Triage Reasoning, & Unit-Test Log
    │       └── slash_repl.rs          # Parser & Autocomplete untuk /init-sec, /audit, /patch, dll.
    ├── sentinel-core/                 # Lapisan 2: Kernel Harness, Policy Gate, SQLite & Worktree
    │   └── src/
    │       ├── lib.rs
    │       ├── policy_gate.rs         # Evaluasi Deny -> Ask -> Allow & Path Canonicalization
    │       ├── bg_classifier.rs       # Background Security Classifier (Anti-Prompt Injection)
    │       ├── worktree_sandbox.rs    # Manajemen Git Worktree & Checkpoint Rewind (git2)
    │       ├── mailbox.rs             # Asynchronous JSONL Mailbox Router
    │       └── storage.rs             # Koneksi SQLite WAL & OpenTelemetry Audit Exporter
    ├── sentinel-graph/                # Modul Mesin 1 & 3: AST Parser, Call Graph & Reachability
    │   └── src/
    │       ├── lib.rs
    │       ├── ast_parser.rs          # Multi-language tree-sitter + rayon parallel scanner
    │       ├── call_graph.rs          # Konstruksi DiGraph petgraph & Taint Flow Tracker
    │       └── reachability.rs        # Function-level CVE Reachability & Phantom Dep Detector
    ├── sentinel-scanners/             # Modul Mesin 4, 5 & 6: Malware, Secret, APK & Hotfix
    │   └── src/
    │       ├── lib.rs
    │       ├── malware_shield.rs      # Typosquatting & Pre-install Script Heuristic Analyzer
    │       ├── git_secrets.rs         # Git Revwalk (--git-logs) Secret & Entropy Scanner
    │       ├── apk_container.rs       # AndroidManifest.xml & Dockerfile Reachability Guard
    │       └── hotfix_patcher.rs      # Generator .patch untuk Local Dependency Backport
    └── sentinel-agents/               # Lapisan 1: Orchestrator, Organic Spawner, Skills & Router
        └── src/
            ├── lib.rs
            ├── orchestrator.rs        # Threat Modeling, Task Dependency Graph & Skill Synthesizer
            ├── spawner.rs             # Dynamic Sub-Agent Actor Spawner (Clean Context Window)
            ├── skill_registry.rs      # Pengelola 3-Tier Skills & Progressive YAML Loader
            ├── smart_router.rs        # Konektor Variatif Providers (Ollama, LM Studio, Cloud API)
            └── mcp_server.rs          # Eksposur seluruh modul mesin via makro #[mcp_tool]
```

### 9.2 Konfigurasi Optimasi Kompilasi Rilis (`Cargo.toml` Root)

Agar menghasilkan satu berkas biner yang sangat kecil, cepat, dan siap didistribusikan ke berbagai sistem operasi (*Linux, macOS, Windows*), gunakan konfigurasi profil rilis berikut:

```toml
[workspace]
resolver = "2"
members = [
    "crates/sentinel-cli",
    "crates/sentinel-tui",
    "crates/sentinel-core",
    "crates/sentinel-graph",
    "crates/sentinel-scanners",
    "crates/sentinel-agents",
]

[profile.release]
opt-level = 3
lto = "thin"              # Link-Time Optimization lintas crate untuk performa maksimal
codegen-units = 1         # Memaksimalkan optimasi instruksi CPU
panic = "abort"           # Menghilangkan overhead unwinding stack
strip = "symbols"         # Memangkas ukuran biner hingga < 20 MB
```

### 9.3 Urutan Fase Implementasi Tim (*Engineering Roadmap / Sprint Plan*)

1. **Fase 1 (Pondasi Kernel & Storage):** Mengimplementasikan `sentinel-core` (skema SQLite WAL, `PolicyGate`, pembatasan direktori proyek, dan manajemen `git2` Worktree).
2. **Fase 2 (Mesin Deterministik&#x20;****`GraphCore`****&#x20;& Scanners):** Mengimplementasikan `sentinel-graph` (`tree-sitter` + `petgraph` untuk *Call Graph*, *Taint Flow*, dan *Phantom Dependency*) serta `sentinel-scanners`.
3. **Fase 3 (Orkestrasi Agen, MCP & 3-Tier Skills):** Mengimplementasikan `sentinel-agents` (konektor `SmartRouter` ke Ollama/Cloud, pemuat YAML `.skill.md` *on-demand*, serta siklus *Detection&#x20;**$\to$**&#x20;Triage&#x20;**$\to$**&#x20;Auto-Hardening*).
4. **Fase 4 (Antarmuka Full-TUI & Whiteboard&#x20;****`rataflow`****):** Mengimplementasikan `sentinel-tui` (menghubungkan saluran telemetri ke kanvas interaktif `rataflow`, panel *Git Diff*, dan parser perintah `/slash commands`).
