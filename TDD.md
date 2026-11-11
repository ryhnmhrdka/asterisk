# TDD

# TECHNICAL DESIGN DOCUMENT (TDD)

## Sistem: Arterisk

**Subjudul:** *Autonomous Pre-Production Code Defense, Supply-Chain Reachability & Security Audit Harness***Versi Dokumen:** 2.0 (Final Architecture Release)**Target Kategori:** Penangkalan Siber (Deteksi Dini, Pencegahan, dan Respons Otomatis Pra-Produksi)**Bahasa & Ekosistem Utama:** 100% Rust (*Single Static Binary Architecture*)**Antarmuka Pengguna:** Full Native TUI (*Split-Pane Command Center + Interactive Node-Graph Whiteboard Canvas*)

***

## 1. Tinjauan Arsitektur & Prinsip Rekayasa

### 1.1 Tujuan Dokumen

Dokumen ini menjadi acuan teknis tunggal bagi tim *engineer* dalam mengimplementasikan **Asterisk**—sebuah *AI Agent Execution Harness* yang bekerja di lingkungan pengembangan lokal (*developer workstation*) untuk mengaudit *source code*, memverifikasi keterjangkauan kerentanan (*function-level reachability*), mencegah penyusupan *malware* paket pihak ketiga, serta melakukan penambalan kode otomatis (*auto-hardening* & *vendor hotfix*) sebelum aplikasi dikompilasi menjadi APK atau di-*deploy* ke server produksi.

### 1.2 Persamaan Dasar Arsitektur Sistem

Sistem dirancang mengikuti prinsip pemisahan antara mesin penalaran probabilistik (LLM) dan infrastruktur eksekusi deterministik (*Harness*):

$\text{Asterisk} = \text{Multi-Model Router} + \underbrace{(\text{GraphCore} + \text{MCP Tools} + \text{3-Tier Skills} + \text{Worktree Sandbox} + \text{Policy Gate} + \text{TUI Canvas})}_{\text{Deterministic Rust Execution Harness}}$

### 1.3 Keputusan Arsitektur Kunci (*Key Architectural Decisions*)

1. **Modular Monolith dalam Satu Biner Tunggal (*****Single Static Binary*****):** Menghindari penggunaan *microservices* yang rumit diinstal oleh *developer*. Seluruh komponen (TUI, Kernel Orkestrator, Mesin AST, dan Database SQLite) dikompilasi menjadi satu berkas eksekusi mandiri.
2. **Komunikasi Internal Berbasis Actor & Channel Asinkron:** Setiap komponen berjalan sebagai *task* independen di atas *runtime* `tokio` dan berkomunikasi melalui saluran pesan *non-blocking* (`mpsc` dan `broadcast`), menjamin antarmuka TUI tetap responsif pada 60 FPS meskipun agen sedang memindai ribuan berkas di latar belakang.
3. **Deterministic-First, AI-Second:** Agen AI tidak diizinkan membaca seluruh repositori secara mentah. Mesin deterministik (`GraphCore`) membangun peta hubungan fungsi dan alur data terlebih dahulu, lalu menyuapkan konteks yang sudah terfokus kepada *Sub-Agent*.

***

## 2. Spesifikasi Tech Stack (Ekosistem Rust)

Seluruh kode sumber sistem ditulis dalam bahasa **Rust (Edition 2024, MSRV 1.82+)** dengan arsitektur **Single-Crate Modular Monolith** dan rincian pustaka (*crates*) sebagai berikut:

| Kategori Komponen               | Crate Utama                           | Versi / Fitur Kunci                               | Alasan Pemilihan & Peran Teknis                                                                                                          |
| ------------------------------- | ------------------------------------- | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **TUI Rendering Engine**        | `ratatui` + `crossterm`               | `ratatui >= 0.30`, `crossterm >= 0.29`            | *Immediate-mode terminal rendering* dengan *double-buffering diff* yang sangat hemat CPU dan memori.                                     |
| **TUI Infinite Whiteboard**     | `rataflow`                            | *Sugiyama Layout, Step/Braille Edges*             | Menyediakan kanvas *node-graph* DAG interaktif di terminal (mendukung *pan*, *zoom*, dan pembaruan status *live*).                       |
| **Rich Terminal Markdown & Math** | `pulldown-cmark` + Custom LaTeX     | `pulldown-cmark >= 0.13`                          | Merender penjelasan agen, laporan keamanan Markdown, dan formula matematika LaTeX langsung di panel TUI.                                 |
| **Capability Jail & Policy Gate** | `cap-std` + `cedar-policy`          | `cap-std >= 4.0`, `cedar-policy >= 4.14`          | `cap-std` mengisolasi akses berkas berbasis kapabilitas OS (`ProjectJail`); `cedar-policy` mengevaluasi izin formal (`PolicyGate`).      |
| **Async Runtime & Concurrency** | `tokio`                               | `tokio >= 1.54 (full)`, `mpsc` channels           | Mengelola I/O jaringan LLM, komunikasi asinkron antar-komponen, dan *event loop* TUI 60 FPS tanpa pemblokiran.                           |
| **Code Context Graph & AST**    | `ast-grep-core` + `tree-sitter` + `petgraph` | Multi-language AST & `DiGraph`             | Membedah kode sumber menjadi *Abstract Syntax Tree* (AST) dan membangun graf berarah (*Call Graph* & *Taint Flow*) di memori.            |
| **File, Git & Secret Entropy**  | `walkdir` + `git2` + `similar` + `entropy` | *libgit2*, *unified diff*, *Shannon entropy* | Menyapu pohon direktori, membuat **Git Worktree** terisolasi, menyapu riwayat `--git-logs` dengan entropi Shannon, dan merender *diff*.  |
| **Multi-Model AI & Tool Harness** | `rig-core` (`rig`)                  | `rig-core >= 0.44 (reqwest)`, `PortableTool`      | Menghubungkan `SecurityAgentHub` ke penyedia lokal (**Ollama**) maupun API Cloud (**Claude, OpenAI, Gemini, DeepSeek, Custom URL**).     |
| **Embedded Storage**            | `rusqlite` (bundled) + `blake3`       | Mode `WAL`, Incremental Hash                      | Menyimpan graf kode, status sesi, dan hasil audit dalam satu berkas `.asterisk/state.sqlite` tanpa instalasi server DB eksternal.        |
| **Serialization & Config**      | `serde` + `serde_json` + `serde_yaml` | Derive macros                                     | Mem-parsing *frontmatter* YAML pada `.skill.md`, membaca `SECURITY.md`, dan menyimpan konfigurasi serta log JSONL (`audit_trail.jsonl`). |

***

## 3. Arsitektur Sistem & Diagram Alir

### 3.1 Diagram Arsitektur Tingkat Tinggi (*Single-Crate Modular Monolith Architecture*)

```markdown
+===================================================================================================+
|                        ASTERISK SINGLE STATIC BINARY (MODULAR MONOLITH)                           |
|                                                                                                   |
|  +---------------------------------------------------------------------------------------------+  |
|  | [LAPISAN 3: PRESENTATION & STEERING LAYER] (mod: src/ui | Thread Utama @ 60 FPS)            |  |
|  |                                                                                             |  |
|  |  +---------------------------------------+   +-------------------------------------------+  |  |
|  |  | Panel Kiri (50%): AI Assistant & REPL |   | Panel Kanan (50%): 5-Tab Defense Workspace|  |  |
|  |  | • Rich Markdown & LaTeX Renderer      |   | • [1 Graph] Rataflow DAG Whiteboard Canvas|  |  |
|  |  | • Slash-Command Autocomplete Popup    |   | • [2 Findings] Vulnerability Matrix Table |  |  |
|  |  | • Interactive Provider/Model/Key Modal|   | • [3 Patches] Unified Diff ([a]pply/[r]ev)|  |  |
|  |  | • Live Agent Thinking & Tool Stream   |   | • [4 Execution] Logs  • [5 Skills] Status |  |  |
|  |  +---------------------------------------+   +-------------------------------------------+  |  |
|  +----------------------------------------------+----------------------------------------------+  |
|                                                 |                                                 |
|                      EngineCommand (mpsc)       |      EngineMessage (mpsc)                       |
|                                                 v                                                 |
|  +---------------------------------------------------------------------------------------------+  |
|  | [LAPISAN 2: HARNESS GOVERNANCE & ISOLATION KERNEL] (mod: src/core & src/execution)          |  |
|  |                                                                                             |  |
|  |  +-----------------------------+  +-----------------------------+  +---------------------+  |  |
|  |  | Cedar PolicyGate            |  | Capability ProjectJail      |  | WorktreeSandbox     |  |  |
|  |  | • AWS cedar-policy Engine   |  | • cap-std Ambient Authority |  | • git2 Worktree Pool|  |  |
|  |  | • Allow / AskUser / Deny    |  | • Strict Path Confinement   |  | • Checkpoint Rewind |  |  |
|  |  +-----------------------------+  +-----------------------------+  +---------------------+  |  |
|  |  +-----------------------------------------------+  +------------------------------------+  |  |
|  |  | ExecutionEngine & Async Event Bus             |  | SQLite WAL Store & Audit JSONL     |  |  |
|  |  +-----------------------------------------------+  +------------------------------------+  |  |
|  +----------------------------------------------+----------------------------------------------+  |
|                                                 |                                                 |
|                                                 v                                                 |
|  +---------------------------------------------------------------------------------------------+  |
|  | [LAPISAN 1: CORE INTELLIGENCE & DETERMINISTIC ENGINES] (mod: orchestrator, subagents, core) |  |
|  |                                                                                             |  |
|  |  +---------------------------------------+   +-------------------------------------------+  |  |
|  |  | Orchestrator & StrategyPlanner        |   | SecurityAgentHub (rig-core AI Gateway)    |  |  |
|  |  | • WorkspaceScanner & Threat Modeler   |   | • Local Offline: Ollama / Custom Endpoint |  |  |
|  |  | • Dynamic Rataflow AgentGraphBuilder  |   | • Cloud API: Claude / OpenAI / Gemini / DS|  |  |
|  |  | • 3-Tier SkillRegistry (.skill.md)    |   | • PortableTool Bridge (rig_tools.rs)      |  |  |
|  |  +---------------------------------------+   +-------------------------------------------+  |  |
|  |                                                                                             |  |
|  |  +---------------------------------------------------------------------------------------+  |  |
|  |  | Deterministic Security Engines & Specialist Sub-Agents                                |  |  |
|  |  |  [1. CodeContextGraph AST]  [2. SastAnalyzer]  [3. ScaDependencyAuditor (Phantom Dep)]|  |  |
|  |  |  [4. GitHistorySecretMiner & SecretHunter]  [5. Network/APK/Malware]  [6. Patcher/Ver]|  |  |
|  |  +---------------------------------------------------------------------------------------+  |  |
|  +----------------------------------------------+----------------------------------------------+  |
+=================================================|=================================================+
                                                  |
                                                  v
  +---------------------------------------------------------------------------------------------+
  | [LOCAL WORKSPACE STORAGE & SANDBOX] (Direktori Proyek Lokal: ./.asterisk/ & ./SECURITY.md)   |
  |  ├─ state.sqlite (WAL Mode)     ├─ mailbox.jsonl & audit_trail.jsonl     ├─ worktrees/wt-*   |
  |  └─ skills/ (Tier-1 Built-in, Tier-2 User Import/Export, Tier-3 Orchestrator Synthesized)    |
  +---------------------------------------------------------------------------------------------+
```

***

### 3.2 Diagram Urutan Eksekusi End-to-End (*Sequence Diagram: Siklus Audit, Triage & Auto-Hardening*)

Diagram berikut menggambarkan interaksi antar-komponen saat pengguna mengeksekusi perintah `/audit --diff-scope=local` hingga penambalan otomatis (`/patch`):

```markdown
Developer (TUI)       asterisk-TUI        asterisk-Core       GraphCore & MCP      Orchestrator      Sub-Agents (Isolated)
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

### 4.1 Struktur Direktori Penyimpanan Lokal (`.asterisk/`)

Saat pengguna menjalankan `/init-sec` pada suatu repositori proyek lokal, sistem membuat struktur direktori tersembunyi berikut:

```markdown
<project-root>/
├── SECURITY.md                        # Memori konteks arsitektur & AI Context Rules (Ground Truth)
├── patches/                           # Berkas .patch untuk Local Dependency Hotfix (tanpa upgrade)
└── .asterisk/
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

### 4.3 Skema DDL SQLite (`crates/asterisk-core/migrations/001_init.sql`)

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

Enam modul berikut diimplementasikan di dalam *crate* `asterisk-graph` dan `asterisk-scanners` untuk menyuplai data deterministik berakurasi tinggi kepada *Sub-Agent*:

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

* **Auto-Hardening pada Source Code Sendiri:** Membuat *Git Worktree* baru di `.asterisk/worktrees/`, menulis skrip **Security Unit Test** yang menyimulasikan input berbahaya pada fungsi rentan, menulis kode perbaikan pada *source code*, dan mengeksekusi *test runner* lokal hingga lulus.
* **Vendor Hotfix Backport (Tanpa Upgrade Versi):** Apabila celah berada di dalam fungsi *library* pihak ketiga dan *upgrade* versi berisiko merusak kompilasi (*breaking changes*), agen memodifikasi fungsi *library* lokal secara terisolasi dan menghasilkan berkas tambalan standar di direktori `./patches/<nama-paket>+<versi>.patch` yang otomatis diterapkan saat proses *build*.

***

## 6. Desain Antarmuka Internal, Kontrak Event & Protokol MCP

### 6.1 Definisi Tipe Data Komunikasi Asinkron (`crates/asterisk-core/src/events.rs`)

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

Untuk memastikan kanvas *Whiteboard* di terminal berjalan semulus aplikasi grafis *native*, modul `asterisk-tui` menerapkan tiga mekanisme wajib:

1. **Aggressive Mouse & Key Event Draining:**
   Saat pengguna menggeser kanvas (*drag*) dengan *mouse* di terminal, terminal membombardir aplikasi dengan ratusan *event* `MouseEventKind::Moved` per detik. *Loop* utama TUI **wajib menguras habis seluruh antrean&#x20;*****event*****&#x20;****`crossterm::event::poll(Duration::ZERO)`****&#x20;terlebih dahulu**, menggabungkan delta pergeseran koordinat $(dx, dy)$, dan baru memanggil `terminal.draw()` satu kali per siklus *frame* (16,6 milidetik).
2. **Spatial Grid Culling & Scratch Buffers (****`rataflow`****):**
   Kanvas menggunakan koordinat dunia virtual tanpa batas $(-\infty \dots +\infty)$. Sebelum menggambar ke layar terminal, *viewport camera* menghitung kotak pembatas (*bounding box*) area yang terlihat dan hanya merender *node* Sub-Agent serta *edge* panah yang berpotongan dengan layar aktif.
3. **Tata Letak Hirarki Otomatis (*****Sugiyama Layered Graph Layout*****):**
   Ketika *Orchestrator* melahirkan beberapa *Sub-Agent* secara organik, algoritma *Sugiyama* secara otomatis menghitung posisi koordinat $(X, Y)$ setiap *node* baru agar panah hubungan antar-agen tidak saling bertumpuk.

### 7.2 Tata Letak Layar 50/50 Dual-Pane & Peta Navigasi TUI (*Keybindings & Mouse Controls*)

Antarmuka dibagi menjadi **Panel Kiri (50% — AI Assistant & Slash REPL)** dan **Panel Kanan (50% — 5-Tab Defense Workspace: `1:Graph`, `2:Findings`, `3:Patches`, `4:Execution`, `5:Skills`)**:

| Tombol / Aksi Mouse                                          | Konteks Panel                    | Aksi Sistem                                                                                                      |
| ------------------------------------------------------------ | -------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| **`Tab`****&#x20;/&#x20;****`1`–`5`****&#x20;/&#x20;****`F1`–`F5`** | Panel Kanan: 5-Tab Workspace     | Berpindah antar-tab tampilan kerja (`1:Graph`, `2:Findings`, `3:Patches`, `4:Execution`, `5:Skills`).            |
| **`Mouse Drag`****&#x20;/&#x20;****`h, j, k, l`**            | Tab 1: Rataflow Graph Canvas     | Menggeser kamera (*panning*) melintasi kanvas *node-graph* atau menavigasi baris pada tabel *Findings/Patches*.  |
| **`Mouse Scroll`****&#x20;/&#x20;****`+`****,&#x20;****`-`** | Tab 1 / Panel Kiri Chat          | Memperbesar/memperkecil tampilan kanvas (*Zoom*) atau menggulir riwayat percakapan secara independen.            |
| **`Space`**                                                  | Global Workspace / Node Terpilih | Memicu siklus audit otonom baru atau menjeda (*Pause*) / melanjutkan (*Resume*) eksekusi *Sub-Agent*.            |
| **`a`**                                                      | Tab 3: Patches Inspector         | **Apply Hardening Patch:** Menerapkan kode tambalan yang sudah diverifikasi langsung ke berkas sumber.           |
| **`r`**                                                      | Tab 3: Patches Inspector         | **Rollback Patch:** Mengembalikan berkas sumber ke kondisi semula sebelum tambalan diterapkan.                   |
| **`e`**                                                      | Global Workspace                 | **Export Report:** Mengekspor laporan pertahanan keamanan ke format Markdown/HTML/JSON.                          |
| **`Esc`****&#x20;+&#x20;****`Esc`****&#x20;(2x Cepat)**      | Global TUI                       | **Reversible Checkpoint Rewind:** Membatalkan perubahan terakhir dan mengembalikan *working tree* ke titik aman. |
| **`/`**                                                      | Panel Kiri: Slash-Command REPL   | Memunculkan *popup autocompletion* untuk `/scan`, `/init-sec`, `/config`, `/provider`, `/model`, `/key`, dll.    |

***

## 8. Kebutuhan Non-Fungsional (NFR): Keamanan, Performa & Skalabilitas

### 8.1 Standar Keamanan Internal (*Hardened Harness Security*)

1. **Otorisasi Kebijakan Formal Berbasis AWS Cedar (`PolicyGate` — `Deny` $\to$ `AskUser` $\to$ `Allow`):**
   Setiap pemanggilan alat melewati validator `PolicyGate::evaluate(agent_role, action, resource_path)` (`src/core/policy.rs`) yang ditenagai oleh mesin kebijakan formal **`cedar-policy`**. Aturan `permit` dan `forbid` dievaluasi secara deterministik (*fail-closed*): agen pembaca hanya diizinkan membaca di dalam *workspace*, penulisan tambalan dikunci hanya untuk `PatcherAgent` di dalam *sandbox*, dan eksekusi perintah *shell* atau modifikasi kode produksi memicu gerbang konfirmasi `GateDecision::AskUser` atau `GateDecision::Deny`.
2. **Isolasi Sistem Berkas Berbasis Kapabilitas OS (`ProjectJail` via `cap-std`):**
   Seluruh operasi baca/tulis berkas oleh agen dibungkus di dalam `ProjectJail` (`src/core/jail.rs`) menggunakan pustaka **`cap-std`** (`Dir::open_ambient_dir`). Otoritas akses berkas global dicabut pada tingkat *handle* sistem operasi dan dikombinasikan dengan kanonikalisasi jalur (`std::fs::canonicalize`) serta pemblokiran komponen `ParentDir` (`..`), sehingga upaya *path traversal* atau *symlink escape* ke luar direktori proyek gagal secara mutlak.
3. **Isolasi Konteks dari *Indirect Prompt Injection*:**
   Komentar atau string di dalam *source code* proyek target diperlakukan sebagai **Untrusted Data**. Rencana pemanggilan alat divalidasi terhadap skema `PortableTool` (`src/core/rig_tools.rs`) dan kebijakan Cedar sebelum dieksekusi.

### 8.2 Target Performa & Anggaran Sumber Daya (*Performance Budgets*)

* **Waktu Mulai Dingin (*****Cold Start Time*****):** $\le 50 \text{ ms}$ hingga antarmuka TUI tampil penuh di layar terminal.
* **Konsumsi Memori (RAM):** $\le 65 \text{ MB}$ saat *idle*; $\le 250 \text{ MB}$ saat memproses proyek skala menengah (100.000 baris kode).
* **Kecepatan Pemetaan&#x20;****`GraphCore`****&#x20;Awal (****`/init-sec`****):** $\ge 15.000 \text{ baris kode/detik}$ dengan pemindaian AST terindeks.
* **Latensi Audit Inkremental (****`/audit --diff-scope=local`****):** $\le 12 \text{ detik}$ dari perintah dijalankan hingga hasil *Triage* tampil di kanvas TUI.
* **Batas Kompresi Konteks Otomatis:** Middleware router otomatis memicu peringkasan konteks (*Context Compaction*) ketika pemakaian token *Sub-Agent* menyentuh **75% kapasitas jendela konteks model**, menjaga agar agen tidak pernah mengalami degradasi penalaran (*context rot*).

***

## 9. Struktur Repositori (Single-Crate Modular Monolith) & Strategi Deployment

### 9.1 Tata Letak Modular Monolith (`src/`)

Untuk meminimalkan *overhead* waktu kompilasi antar-crate dan menghasilkan satu berkas biner statis secara efisien, seluruh modul diorganisasikan ke dalam arsitektur **Single-Crate Modular Monolith** dengan pemisahan lapisan tanggung jawab yang tegas:

```
asterisk/
├── Cargo.toml                         # Konfigurasi paket tunggal & profil rilis LTO
├── Cargo.lock
├── SECURITY.md                        # Dogfooding: Aturan konteks keamanan internal Asterisk
├── assets/
│   └── builtin_skills/                # Tier-1 Default Skills (.skill.md) dengan YAML frontmatter
│       ├── owasp-sast-triage.skill.md
│       ├── sca-reachability-triage.skill.md
│       ├── apk-manifest-guard.skill.md
│       ├── malicious-package-heuristics.skill.md
│       ├── secret-validation-triage.skill.md
│       ├── container-code-reachability.skill.md
│       ├── contextual-code-hardening.skill.md
│       └── vendor-hotfix-backport.skill.md
├── tests/
│   ├── integration_tests.rs           # Pengujian integrasi pipeline End-to-End & UI
│   └── fixtures/vulnerable_repo/      # Repositori uji berisi sampel celah keamanan
└── src/
    ├── main.rs                        # Entrypoint CLI (--ci, --install-hook, --diff-scope) & TUI loop
    ├── lib.rs                         # Ekspor modul publik untuk pengujian integrasi
    ├── types.rs                       # Kontrak tipe data lintas modul (Finding, Patch, Provider, Cmd)
    ├── core/                          # Lapisan Kernel Harness, Isolasi, Storage & Mesin Inti
    │   ├── mod.rs
    │   ├── agent.rs                   # SecurityAgentHub: Konektor Multi-Model LLM berbasis rig-core
    │   ├── config.rs                  # Manajemen konfigurasi provider & kredensial (.asterisk/)
    │   ├── git_secrets.rs             # GitHistorySecretMiner: git2::Revwalk & Shannon Entropy
    │   ├── graph.rs                   # CodeContextGraph: AST parser, Call Graph & BFS Reachability
    │   ├── jail.rs                    # ProjectJail: Isolasi filesystem berbasis kapabilitas cap-std
    │   ├── policy.rs                  # PolicyGate: Mesin otorisasi formal berbasis cedar-policy
    │   ├── rig_tools.rs               # Implementasi PortableTool untuk pemanggilan alat terisolasi
    │   ├── sandbox.rs                 # WorktreeSandbox: Manajemen Git Worktree (.asterisk/worktrees)
    │   ├── sca.rs                     # ScaDependencyAuditor: Deteksi Phantom Dep & audit manifest
    │   ├── security_md.rs             # Parser aturan konteks arsitektur dari berkas SECURITY.md
    │   └── storage.rs                 # StateStore SQLite WAL (.asterisk/state.sqlite) & Audit JSONL
    ├── orchestrator/                  # Pemetaan Workspace, Perencanaan Strategi & Graf Agen
    │   ├── mod.rs
    │   ├── graph.rs                   # AgentGraphBuilder: Konstruksi node & edge DAG Rataflow
    │   ├── planner.rs                 # StrategyPlanner: Penyusun fase matriks pertahanan
    │   └── workspace.rs               # WorkspaceScanner: Deteksi bahasa, framework, Docker & APK
    ├── subagents/                     # Koloni Sub-Agent Spesialis Deteksi, Remediasi & Verifikasi
    │   ├── mod.rs
    │   ├── sast.rs                    # SastAnalyzerAgent: Deteksi celah injeksi & alur data
    │   ├── secrets.rs                 # SecretHunterAgent: Pemindai kredensial working-tree
    │   ├── network.rs                 # NetworkProberAgent: Linter permukaan jaringan & TLS/CORS
    │   ├── malware_shield.rs          # MalwareShieldAgent: Deteksi typosquatting & preinstall script
    │   ├── apk_guard.rs               # ApkAndContainerGuardAgent: Audit AndroidManifest & Dockerfile
    │   ├── patcher.rs                 # AutoHardeningAgent: Generator unified diff & vendor hotfix
    │   └── verifier.rs                # VerificationAgent: Eksekutor Security Unit-Test & Safe Outputs
    ├── execution/                     # Mesin Eksekusi Alur Kerja Asinkron
    │   ├── mod.rs
    │   └── engine.rs                  # ExecutionEngine: Orkestrasi pipeline Tri-Stage Audit
    ├── skills/                        # Pengelola Ekosistem 3-Tier Interactive Skills
    │   └── mod.rs                     # SkillRegistry: Progressive YAML loader, Import/Export & Synth
    └── ui/                            # Lapisan Presentasi Full-TUI (50/50 Split & 5-Tab Workspace)
        ├── mod.rs
        ├── app.rs                     # Loop 60 FPS, Mouse/Key Event Drain & State Controller
        ├── markdown.rs                # Perender Markdown terminal (pulldown-cmark)
        ├── latex.rs                   # Perender formula matematika LaTeX
        └── views/                     # Komponen tampilan modular
            ├── mod.rs
            ├── sidebar_view.rs        # Panel Kiri: AI Assistant Chat, Slash REPL & Autocomplete
            ├── graph_view.rs          # Tab 1: Rataflow DAG Whiteboard Canvas
            ├── matrix_view.rs         # Tab 2: Tabel Matriks Kerentanan (Findings)
            ├── patch_view.rs          # Tab 3: Unified Diff Inspector & Apply/Rollback Controls
            ├── logs_view.rs           # Tab 4: Live Execution & Improvisation Log Stream
            ├── skills_view.rs         # Tab 5: 3-Tier Skills Registry & Invocation Telemetry
            ├── modal_view.rs          # Overlay Modal pemilihan Provider, Model, API Key & URL
            └── welcome_view.rs        # Tampilan inisialisasi awal
```

### 9.2 Konfigurasi Optimasi Kompilasi Rilis (`Cargo.toml`)

Agar menghasilkan satu berkas biner mandiri yang cepat dan siap didistribusikan lintas sistem operasi (*Linux, macOS, Windows*):

```toml
[package]
name = "asterisk"
version = "0.1.0"
edition = "2024"

[profile.release]
opt-level = 3
lto = "thin"              # Link-Time Optimization untuk performa maksimal
codegen-units = 1         # Memaksimalkan optimasi instruksi CPU
panic = "abort"           # Menghilangkan overhead unwinding stack
strip = "symbols"         # Memangkas ukuran biner
```

### 9.3 Urutan Gelombang Implementasi Tim (*Parallel & Linear Wave Execution Plan*)

1. **Gelombang 0 (Pondasi Linear):** Standarisasi identitas paket `asterisk`, direktori `.asterisk/`, serta pendaftaran dependensi utama di `Cargo.toml`.
2. **Gelombang 1 (Pengembangan Modul Inti Secara Paralel — Bebas Bentrok):**
   * *Track A (`src/core/storage.rs`):* Implementasi SQLite WAL (`state.sqlite`) & log `audit_trail.jsonl`.
   * *Track B (`src/core/graph.rs`):* Upgrade mesin AST `CodeContextGraph` (`ast-grep-core`/`tree-sitter`) & `--diff-scope=local`.
   * *Track C (`src/skills/mod.rs` & `src/core/security_md.rs`):* Ekosistem 3-Tier `.skill.md` (*Progressive Disclosure*) & parser `SECURITY.md`.
   * *Track D (`src/subagents/`):* Implementasi `malware_shield.rs`, `apk_guard.rs`, dan *Vendor Hotfix Backport* di `patcher.rs`.
   * *Track E (`src/subagents/verifier.rs` & `src/core/sandbox.rs`):* Eksekusi dinamis *Security Unit Test* di Git Worktree, *Safe Outputs Gate*, & *Checkpoint Rewind*.
3. **Gelombang 2 (Konvergensi & Integrasi Akhir):** Merangkai seluruh modul Gelombang 1 ke dalam pipeline *Tri-Stage AI Triage* di `src/execution/engine.rs` serta menambahkan perintah `/slash` baru di `src/ui/app.rs`.
