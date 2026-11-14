mod core;
mod execution;
mod orchestrator;
mod skills;
mod subagents;
mod types;
mod ui;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::env;
use std::fs;
use std::io::stdout;
use std::path::PathBuf;
use std::process::exit;
use std::time::Duration;
use ui::App;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    // 1. Help flag
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("asterisk :: autonomous pre-production code defense harness");
        println!("\nusage:");
        println!("  asterisk                            launch interactive workspace");
        println!("  asterisk [path]                     run directly on specified directory");
        println!("  asterisk --ci [path]                run in headless CI/CD mode");
        println!("  asterisk --diff-scope=local [path]  scope audit strictly to uncommitted local git changes");
        println!("  asterisk --apk [path]               include Android APK & container manifest security guard");
        println!("  asterisk --install-hook             install automated .git/hooks/pre-commit defense guard");
        println!("  asterisk --help                     show this help message\n");
        return Ok(());
    }

    // 2. Install Git Pre-Commit Hook flag
    if args.iter().any(|a| a == "--install-hook") {
        let hook_path = PathBuf::from(".git/hooks/pre-commit");
        if !PathBuf::from(".git").exists() {
            eprintln!("error: .git directory not found. run this inside a git repository.");
            exit(1);
        }
        let hook_script = r#"#!/usr/bin/env bash
# asterisk automated pre-commit defense hook
echo "[asterisk] verifying pre-production code defense..."
asterisk --ci .
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo "[asterisk] commit blocked due to unresolved security vulnerabilities!"
    echo "[asterisk] run 'asterisk' to review and apply auto-hardening patches."
    exit 1
fi
"#;
        fs::write(&hook_path, hook_script)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&hook_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&hook_path, perms)?;
        }
        println!("successfully installed pre-commit defense guard -> {}", hook_path.display());
        return Ok(());
    }

    // 3. Headless / CI Mode & Scoping Flags
    let is_ci_mode = args.iter().any(|a| a == "--ci" || a == "--headless");
    let is_diff_scope_local = args.iter().any(|a| a == "--diff-scope=local" || a == "--diff-scope");
    let is_apk_mode = args.iter().any(|a| a == "--apk");
    let explicit_target = args.iter().skip(1).find(|a| !a.starts_with("--")).cloned();

    let target_dir = explicit_target
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    if is_ci_mode {
        println!("asterisk :: headless ci defense audit running on: {}", target_dir.display());
        if is_diff_scope_local {
            println!("  [diff-scope] scoped analysis strictly to uncommitted local git changes");
        }
        let profile = orchestrator::WorkspaceScanner::scan(&target_dir);
        let secrets = subagents::SecretHunterAgent::scan(&target_dir);
        let sast = subagents::SastAnalyzerAgent::scan(&target_dir);
        let net = subagents::NetworkProberAgent::scan(&target_dir);
        let git_secrets = core::GitHistorySecretMiner::scan_commit_history(&target_dir);
        let sca = core::ScaDependencyAuditor::audit(&target_dir);
        let malware = subagents::MalwareShieldAgent::scan(&target_dir);

        let mut findings = Vec::new();
        findings.extend(secrets);
        findings.extend(sast);
        findings.extend(net);
        findings.extend(git_secrets);
        findings.extend(sca);
        findings.extend(malware);

        if is_apk_mode {
            let apk = subagents::ApkAndContainerGuardAgent::scan(&target_dir);
            findings.extend(apk);
        }

        let patches = subagents::AutoHardeningAgent::generate_patches(&target_dir, &findings);

        println!("scanned {} files. stack: {}", profile.total_files, profile.languages.join(", "));
        println!("findings: {}  │  patches available: {}", findings.len(), patches.len());

        for finding in &findings {
            println!("  [{}] {}:{} -> {}", finding.cwe, finding.file_path.display(), finding.line_number, finding.title);
        }

        if !findings.is_empty() {
            eprintln!("\n[blocked] pre-production defense check failed with {} vulnerabilities.", findings.len());
            exit(1);
        } else {
            println!("\n[passed] pre-production defense check clean.");
            exit(0);
        }
    }

    // 4. Interactive TUI Mode (Directly into Flow & Chatbot Workspace)
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
        eprintln!("asterisk: stdout is not a terminal. Use --ci or run in an interactive terminal.");
        exit(1);
    }

    // Install panic hook to always cleanly restore terminal on unhandled panic
    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = execute!(
            std::io::stdout(),
            LeaveAlternateScreen,
            DisableMouseCapture,
            crossterm::cursor::Show
        );
        default_panic(panic_info);
    }));

    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(target_dir, false);
    if is_diff_scope_local {
        app.diff_scope = "LOCAL_DIFF".to_string();
    }

    'main: loop {
        app.update();

        terminal.draw(|f| {
            app.render(f);
        })?;

        if event::poll(Duration::from_millis(16))? {
            loop {
                match event::read()? {
                    Event::Key(key) => {
                        if app.handle_key(key) || app.should_quit {
                            break 'main;
                        }
                    }
                    Event::Mouse(mouse) => {
                        app.handle_mouse(mouse);
                        if app.should_quit {
                            break 'main;
                        }
                    }
                    _ => {}
                }
                if !event::poll(Duration::ZERO)? {
                    break;
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    println!("asterisk defense harness terminated cleanly.");
    Ok(())
}
