# kartikacyber

an autonomous pre-production code defense & security audit harness in Rust (TUI).

built with **ratatui** and **rataflow** for visual interactive task dependency graphs, running directly inside local developer source repositories before build and deploy.

---

## visual design philosophy

designed with a sleek, classic monochrome aesthetic (opencode style: black, white, gray):
* no distracting neon or flashing colors
* clean high-contrast white active elements and crisp dark gray borders
* subtle indicators: `[crit]`, `[high]`, `[med]`, `[low]`
* minimal terminal glyphs: `->`, `│`, `>`

---

## architecture

```
               [ orchestrator ]
                      │
   ┌───────────┬──────┴──────┬───────────┐
   ▼           ▼             ▼           ▼
[ recon ]  [ secrets ]    [ sast ]   [ network ]
   │           │             │           │
   └───────────┼─────────────┼───────────┘
               ▼             ▼
          [ auto-hardening patcher ]
                      │
                      ▼
            [ test verifier ]
                      │
                      ▼
         [ pre-prod defense gate ]
```

* **orchestrator**: inspects workspace, tech stacks (Rust, Go, Python, Node, Mobile, Docker), and builds dynamic dependency graph.
* **secret hunter**: hunts leaked credentials, AWS keys, private certificates, JWT tokens, and high-entropy secrets.
* **sast analyzer**: scans for SQL injection (CWE-89), Command injection (CWE-78), Path traversal (CWE-22), and insecure eval/deserialization.
* **network prober**: detects `0.0.0.0` wildcard binds (CWE-1327), CORS wildcard `*` (CWE-942), disabled TLS verification (CWE-295), and cleartext transport.
* **auto-hardening patcher**: synthesizes non-breaking unified diff patches; apply with `[a]` or rollback with `[r]`.
* **test verifier**: synthesizes automated security unit tests to verify exploit resistance before build.
* **interactive skills**: dynamic skills registry (`entropy`, `ast-sast`, `net-audit`, `patcher`, `test-synth`, `self-heal`).

---

## views & controls

| view | description |
|---|---|
| `1 graph` | interactive rataflow DAG canvas with nodes, pan/zoom, and live agent status |
| `2 findings` | clean table of detected vulnerabilities and remediation recommendations |
| `3 patches` | unified diff review, automated unit tests, with instant apply and rollback |
| `4 execution` | real-time agent log stream, terminal executions, and self-healing events |
| `5 skills` | registry of active skills and sub-agent invocation metrics |

### keybindings

* `tab` : cycle views (1 to 5)
* `1` - `5` : direct jump to view
* `space` / `s` : trigger / re-run audit
* `↑` / `↓` or `k` / `j` : navigate items
* `a` : **apply selected auto-hardening patch to file**
* `r` : **rollback patch from file**
* `e` : **export security audit report to JSON**
* `q` / `esc` : exit

---

## quick start

```bash
# run on current directory
./target/release/constellation

# run on specified project repository
./target/release/constellation /path/to/project

# run in headless CI/CD mode
./target/release/constellation --ci /path/to/project
```
