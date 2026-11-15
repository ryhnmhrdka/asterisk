![logo](https://res.cloudinary.com/erwj1yyu/image/upload/v1794731959/logo_2_l4k5e6.png)

[![Rust](https://img.shields.io/badge/rust-2024_edition-orange.svg)](https://www.rust-lang.org/)
[![Ratatui](https://img.shields.io/badge/tui-ratatui_v0.30-blue.svg)](https://ratatui.rs/)
[![Storage](https://img.shields.io/badge/storage-SQLite_WAL-informational.svg)](https://www.sqlite.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)


**Asterisk** is a terminal-native, autonomous security harness that inspects, triages, and hardens codebases directly on local developer machines before code is committed, built, or deployed.

Powered by **Ratatui** and **Rataflow**, Asterisk combines static AST taint analysis with multi-agent orchestration, interactive DAG visualization, automated patch synthesis, and conversational security architecture reviews.

---

## Key Capabilities

- **Strict 1-to-1 AST Dataflow Canvas**: Visualizes triage as a clean, non-branching pipeline in Rataflow. Row 1 executes discovery and taint scanning; Row 2 automatically sprouts fixing, patch generation, and regression verification workflows.
- **Autonomous Multi-Agent Subsystems**:
  - `SecretHunter`: High-entropy credential, private key, and API token detection.
  - `SAST Analyzer`: AST taint analysis tracking sources to sensitive execution sinks (CWE-89, CWE-78, CWE-22, CWE-94).
  - `MalwareShield`: Pre-install manifest analysis checking for typosquatting and malicious lifecycle hooks.
  - `ApkAndContainerGuard`: Audits AndroidManifest.xml, mobile APK configurations, Dockerfiles, and container privileges.
  - `AutoHardeningAgent`: Generates minimal, non-breaking unified diff patches with accompanying unit tests.
  - `SafeOutputsVerifier`: Regression gate verifying that security fixes preserve intended system functionality.
- **Interactive Security Architect (`/grill-me`)**: An adversarial interview mode that relentlessly probes your threat model, trust boundaries, and sanitization assumptions, then synthesizes a comprehensive Hardened Security Architecture Plan.
- **Persistent Sessions (`/sessions` & `/new`)**: Full session state, chat logs, findings, and patches are backed by SQLite WAL storage (`.asterisk/state.sqlite`). Switch between sessions or start fresh at any time.
- **Zero-Friction Rollback (`Esc+Esc`)**: Automatic worktree checkpointing allows instantly reverting workspace filesystem changes with a double-Escape shortcut.
- **Customizable Appearance**: 7 built-in themes (`asterisk`, `tokyo_night`, `catppuccin`, `nord`, `gruvbox`, `solarized`, `terminal`) with smooth wall-clock animated spinners.

---

## Installation

### Automated Install (Recommended)

Asterisk includes an automated installer that detects your OS, installs required compilation tools, builds the release binary, and configures symlinks:

```bash
git clone https://github.com/ryhnmhrdkaa/asterisk.git
cd asterisk
./install.sh
```

Supported operating systems:
- **Linux**: Arch / Manjaro, Ubuntu / Debian / Kali / Mint / Pop!_OS, Fedora / RHEL / CentOS / Rocky, openSUSE, Alpine.
- **macOS**: Apple Silicon and Intel via Xcode Command Line Tools.

The installer creates symlinks at `~/.local/bin/asterisk` (and `/usr/local/bin/asterisk` when privileges permit) and configures your shell `$PATH`.

### Manual Build

Ensure you have the Rust toolchain installed:

```bash
cargo build --release
sudo ln -sf "$(pwd)/target/release/asterisk" /usr/local/bin/asterisk
```

---

## Quick Start

Launch Asterisk inside your current project:

```bash
asterisk
```

Target a specific repository:

```bash
asterisk /path/to/project
```

Scope audit strictly to uncommitted local git changes:

```bash
asterisk --diff-scope=local
```

Run in headless CI/CD mode (returns non-zero exit code on blocking vulnerabilities):

```bash
asterisk --ci /path/to/project
```

Install the automated git pre-commit defense hook:

```bash
asterisk --install-hook
```

---

## Interface Layout & Navigation

Asterisk utilizes an adaptive **Master-Detail Layout**:

- **Left Pane (45% Chatbot)**: Real-time conversational interface with streaming AI reasoning, command autocompletion, and status indicators.
- **Right Pane (55% Workspace)**: Tabbed workspace featuring interactive canvases, triage tables, diff inspectors, and logs.

### Workspace Tabs

| Tab | Name | Purpose |
| :---: | :--- | :--- |
| `[1]` | **Flow** | Interactive Rataflow canvas with pan (`h/j/k/l`), zoom (`+`/`-`), minimap, and live node status pills. |
| `[2]` | **Findings** | Vulnerability triage matrix with reachability filtering (`[f]`), CWE ratings, and AST taint paths. |
| `[3]` | **Patches** | Side-by-side unified diff inspector with automated security unit tests, instant apply (`[a]`), and rollback (`[r]`). |
| `[4]` | **Execution** | Granular multi-agent trace logs, subagent dispatches, and tool execution timelines. |
| `[5]` | **Skills** | Extensible 3-tier `.skill.md` registry with progressive disclosure. |

---

## Command Reference

Type `/` in the prompt to open the interactive autocomplete popup:

| Command | Arguments | Description |
| :--- | :--- | :--- |
| `/scan` | `[prompt]` | Synthesize AST DAG and start autonomous security scan (with optional directive prompt) |
| `/sessions` | `[id / list]` | List past sessions or switch to a previous session and restore chat & findings |
| `/new` | — | Archive current session and initialize a fresh security audit workspace |
| `/grill-me` | — | Launch interactive adversarial security architecture review with Principal Security Architect |
| `/done` | — | Conclude `/grill-me` interview and synthesize finalized Hardened Security Architecture Plan |
| `/apply` | — | Apply selected code hardening patch to disk (`[Ctrl+A]`) |
| `/rollback` | — | Rollback applied hardening patch from disk (`[Ctrl+R]`) |
| `/secrets` | — | Scan workspace for high-entropy tokens and embedded credentials |
| `/shield` | — | Run Pre-Install Malware Shield audit for typosquatting packages |
| `/apk` | `[path]` | Audit AndroidManifest.xml, mobile APK flags, and container privileges |
| `/reachability`| — | Display function reachability and phantom dependency analysis |
| `/init-sec` | — | Initialize CodeContextGraph rules and draft template `SECURITY.md` |
| `/hotfix` | `[pkg]` | Generate local vendor library patch without upgrading package dependencies |
| `/skills` | `[action]` | Manage, import (`/skills import <path>`), or synthesize (`/skills synth`) skills |
| `/model` | `[name]` | Select active reasoning model or open model selector |
| `/provider` | `[name]` | Switch AI provider (OpenAI, Anthropic, Gemini, DeepSeek, Groq, Ollama, Custom, etc.) |
| `/custom` | `[url]` | Configure custom OpenAI-compatible endpoint and credentials |
| `/key` | `[api_key]` | Set or update API credentials for current provider |
| `/theme` | `[name]` | Open theme picker or switch theme live (`[Ctrl+T]` cycles) |
| `/pause` | — | Pause or resume agent workflow execution (`[Space]` / `[Esc]`) |
| `/export` | — | Export defense audit report to JSON and Markdown (`[Ctrl+E]`) |
| `/clear` | — | Clear chat history in active session |
| `/help` | — | Display comprehensive command and keyboard shortcut reference |
| `/exit` | — | Exit Asterisk cleanly |

---

## Keyboard Shortcuts

| Shortcut | Context | Action |
| :--- | :--- | :--- |
| `[Tab]` | Any | Cycle through workspace tabs (`[1]` to `[5]`) / autocomplete command |
| `[Shift+Tab]` | Any | Toggle focus between Chatbot pane and Workspace pane |
| `[Alt+1]`..`[Alt+5]` | Any | Direct jump to tab: Flow, Findings, Patches, Execution, Skills |
| `[Space]` | Empty prompt | Trigger / re-run security audit |
| `[Space]` | Running flow | Pause / resume entire workflow execution |
| `[Esc]` | Running query | Cancel ongoing AI reasoning query |
| `[Esc]` | Running flow | Pause workflow execution |
| `[Esc+Esc]` | Any | Instant checkpoint rewind (revert workspace to pre-session state) |
| `[Ctrl+A]` | Workspace | Apply highlighted hardening patch to file |
| `[Ctrl+R]` | Workspace | Rollback highlighted hardening patch from file |
| `[Ctrl+T]` | Any | Cycle theme (Asterisk, Tokyo Night, Catppuccin, Nord, Gruvbox, etc.) |
| `[Ctrl+E]` | Any | Export security report to `./asterisk_report.json` |
| `[f]` | Tab [2] | Toggle reachability filter (show only reachable taint flows) |
| `[h / j / k / l]` | Tab [1] | Pan Rataflow canvas |
| `[+ / - / 0]` | Tab [1] | Zoom in / zoom out / fit canvas to view |
| `[?]` | Any | Open interactive keyboard cheatsheet |

---

## Supported AI Providers

Asterisk integrates with all major AI model providers through unified HTTP adapters:

- **Anthropic Claude** (Claude 3.7 Sonnet, Claude 3.5 Sonnet, Claude 3.5 Haiku)
- **OpenAI** (GPT-4o, GPT-4o-mini, o1, o3-mini)
- **Google Gemini** (Gemini 2.5 Pro, Gemini 2.0 Flash, Gemini 1.5 Pro)
- **DeepSeek** (DeepSeek-V3, DeepSeek-R1)
- **Groq** (Llama-3.3-70B, DeepSeek-R1-Distill)
- **OpenRouter** (Multi-provider aggregator)
- **Mistral AI** (Mistral Large, Codestral)
- **Together AI** & **xAI** (Grok 2)
- **Ollama** (Local models: `qwen2.5-coder`, `deepseek-r1`, `llama3.3`)
- **Custom / Self-Hosted Endpoints** (Any OpenAI-compatible REST API)

Switch providers instantly using `/provider <name>` or `/custom <url>`.

---

## Project Structure

```
asterisk/
├── install.sh                  # Automated cross-platform installer
├── Cargo.toml                  # Workspace dependencies & release profile
├── ascii.txt                   # ASCII emblem
├── src/
│   ├── main.rs                 # CLI entry point, argument parsing & hook installer
│   ├── types.rs                # Shared types, AST findings, patches & chat messages
│   ├── core/                   # Core engines (agent hub, AST graph, sandbox, policy, storage)
│   │   ├── agent.rs            # Multi-provider AI orchestration & reasoning parser
│   │   ├── graph.rs            # AST code context & taint reachability analyzer
│   │   ├── storage.rs          # SQLite WAL state store & session history
│   │   ├── policy.rs           # Cedar policy evaluation & gatekeeper
│   │   └── sandbox.rs          # Worktree isolation & checkpoint rewind engine
│   ├── orchestrator/           # Workflow orchestration & Rataflow graph generation
│   │   ├── graph.rs            # 1-to-1 arrow graph layout (Scan & Fixing pipelines)
│   │   ├── planner.rs          # AST task planner & subagent synthesizer
│   │   └── scanner.rs          # Project tech stack profiler
│   ├── execution/              # Background worker thread & message dispatch engine
│   ├── subagents/              # Specialized security subagents (SAST, Secrets, Shield, etc.)
│   ├── skills/                 # Dynamic .skill.md registry & progressive disclosure
│   └── ui/                     # Terminal user interface (Ratatui & Rataflow)
│       ├── app.rs              # App state, event loop, slash commands, modal handlers
│       ├── theme.rs            # Color palettes & adaptive styling
│       └── views/              # Views (graph, matrix, patch, logs, skills, sidebar, modals)
└── tests/
    └── integration_tests.rs    # Comprehensive integration test suite (34+ test cases)
```

---

## Security & Privacy Guarantee

- **Local Execution**: All AST parsing, taint analysis, secret detection, and git worktree isolation run completely on your local machine.
- **Controlled Outbound Calls**: Code snippets and reasoning context are sent only to the AI provider endpoint you explicitly configure.
- **Git Safety**: Asterisk never commits or pushes to remote repositories automatically. All patches are staged locally for interactive developer approval.

---

## License

This project is licensed under the [MIT License](LICENSE).
