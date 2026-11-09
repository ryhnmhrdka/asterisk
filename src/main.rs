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
        println!("constellation :: autonomous pre-production code defense harness");
        println!("\nusage:");
        println!("  constellation                   launch interactive launcher (ascii + target prompt)");
        println!("  constellation [path]            run directly on specified local directory");
        println!("  constellation --ci [path]       run in headless CI/CD mode (exit code 1 if unpatched issues)");
        println!("  constellation --install-hook    install automated .git/hooks/pre-commit defense guard");
        println!("  constellation --help            show this help message\n");
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
# constellation automated pre-commit defense hook
echo "[constellation] verifying pre-production code defense..."
constellation --ci .
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo "[constellation] commit blocked due to unresolved security vulnerabilities!"
    echo "[constellation] run 'constellation' to review and apply auto-hardening patches."
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

    // 3. Headless / CI Mode
    let is_ci_mode = args.iter().any(|a| a == "--ci" || a == "--headless");
    let explicit_target = args.iter().skip(1).find(|a| !a.starts_with("--")).cloned();

    let target_dir = explicit_target
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    if is_ci_mode {
        println!("constellation :: headless ci defense audit running on: {}", target_dir.display());
        let profile = orchestrator::WorkspaceScanner::scan(&target_dir);
        let secrets = subagents::SecretHunterAgent::scan(&target_dir);
        let sast = subagents::SastAnalyzerAgent::scan(&target_dir);
        let net = subagents::NetworkProberAgent::scan(&target_dir);

        let mut findings = Vec::new();
        findings.extend(secrets);
        findings.extend(sast);
        findings.extend(net);

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

    // 4. Interactive TUI Mode
    // If no path was explicitly provided in CLI args, start in Welcome mode (ASCII logo + prompt)
    let start_in_welcome = explicit_target.is_none();

    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(target_dir, start_in_welcome);
    if !start_in_welcome {
        app.trigger_audit();
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
                        if app.handle_key(key) {
                            break 'main;
                        }
                    }
                    Event::Mouse(mouse) => {
                        app.handle_mouse(mouse);
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

    println!("kartikacyber defense harness terminated cleanly.");
    Ok(())
}
