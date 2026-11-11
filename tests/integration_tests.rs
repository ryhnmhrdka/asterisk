use asterisk::orchestrator::{AgentGraphBuilder, StrategyPlanner, WorkspaceScanner};
use asterisk::skills::SkillRegistry;
use asterisk::subagents::{
    AutoHardeningAgent, NetworkProberAgent, SastAnalyzerAgent, SecretHunterAgent, VerificationAgent,
};
use std::fs;
use std::path::PathBuf;

#[test]
fn test_harness_full_pipeline() {
    let target = PathBuf::from("./tests/fixtures/vulnerable_repo");
    assert!(target.exists(), "Target fixture folder must exist");

    // 1. Test Workspace Reconnaissance
    let profile = WorkspaceScanner::scan(&target);
    assert!(profile.total_files > 0);
    assert!(profile.languages.contains(&"Python".to_string()));

    // 2. Test Defense Strategy Planner
    let plan = StrategyPlanner::create_plan(&profile);
    assert!(!plan.rules_applied.is_empty());
    assert_eq!(plan.phases.len(), 6);

    // 3. Test Rataflow Sprouted Horizontal Graph Builder
    let nodes_map = AgentGraphBuilder::default_nodes_map();
    let flow = AgentGraphBuilder::build_sprouted_graph(&nodes_map);
    assert!(flow.is_ok(), "Rataflow sprouted horizontal graph must build successfully");

    // 4. Test Secret Hunter Sub-Agent
    let secrets = SecretHunterAgent::scan(&target);
    assert!(!secrets.is_empty(), "Must detect secrets");

    // 5. Test SAST Analyzer Sub-Agent
    let sast = SastAnalyzerAgent::scan(&target);
    assert!(!sast.is_empty(), "Must detect SQLi / Command injection");

    // 6. Test Network Surface Prober Sub-Agent
    let net = NetworkProberAgent::scan(&target);
    assert!(!net.is_empty(), "Must detect 0.0.0.0 bind / CORS wildcard");

    // 7. Test Auto-Hardening Patch Generation
    let mut all_findings = Vec::new();
    all_findings.extend(secrets);
    all_findings.extend(sast);
    all_findings.extend(net);

    let mut patches = AutoHardeningAgent::generate_patches(&target, &all_findings);
    assert!(!patches.is_empty(), "Must generate hardening patches");

    // 8. Test Automated Unit Test Synthesizer
    let test_suite = VerificationAgent::synthesize_test_suite(&patches);
    assert!(test_suite.contains("Verification test for: PATCH-"));

    // 9. Test Interactive Skills Registry
    let mut skills = SkillRegistry::new();
    assert!(skills.skills.len() >= 6);
    let first_skill_id = skills.skills[0].id.clone();
    skills.record_invocation(&first_skill_id);
    assert_eq!(skills.skills[0].invocations, 1);

    // 10. Test Patch Apply & Rollback
    if let Some(patch) = patches.first_mut() {
        let original_file_content = fs::read_to_string(&patch.target_file).unwrap();
        if original_file_content.contains(&patch.original_snippet) {
            let apply_res = AutoHardeningAgent::apply_patch(patch);
            assert!(apply_res.is_ok(), "Applying patch must succeed");
            assert!(patch.applied);

            let revert_res = AutoHardeningAgent::rollback_patch(patch);
            assert!(revert_res.is_ok(), "Rolling back patch must succeed");
            assert!(!patch.applied);
        }
    }
}

#[test]
fn test_app_empty_state_and_auth_modal_gate() {
    use asterisk::ui::App;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    // App must start with 0 findings, 0 patches, empty plan, empty graph (no dummy data)
    let mut app = App::new(PathBuf::from("."), true);
    assert_eq!(app.findings.len(), 0);
    assert_eq!(app.patches.len(), 0);
    assert!(app.nodes_info.is_empty(), "Flow nodes must be empty before audit is initiated");
    assert!(app.selected_node_id.is_none());
    assert!(app.plan.is_none());
    assert!(!app.is_running);
    assert!(!app.show_key_modal);

    // If API key is not configured, trigger_audit must block and display the auth modal
    app.config.api_key = None;
    app.config.provider = asterisk::types::AiProvider::AnthropicClaude;

    // Triggering audit without key
    app.trigger_audit();
    assert!(!app.is_running, "Audit must NOT run without configured API key");
    assert!(app.show_key_modal, "Auth modal must pop up when API key is missing");

    // Typing into modal and authenticating
    app.handle_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::empty()));
    app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::empty()));
    app.handle_key(KeyEvent::new(KeyCode::Char('-'), KeyModifiers::empty()));
    app.handle_key(KeyEvent::new(KeyCode::Char('1'), KeyModifiers::empty()));
    assert_eq!(app.key_modal_input, "sk-1");

    // Press Enter to save & authenticate
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert!(!app.show_key_modal, "Modal must close upon valid key submission");
    assert_eq!(app.config.get_api_key().as_deref(), Some("sk-1"));
}

#[test]
fn test_command_suggestions_and_execution() {
    use asterisk::types::{get_matching_commands, ChatMessage};
    use asterisk::ui::App;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    // 1. Test get_matching_commands helper
    let all = get_matching_commands("/");
    assert!(all.len() >= 10);
    assert!(all.iter().any(|c| c.name == "/model"));
    assert!(all.iter().any(|c| c.name == "/exit"));
    assert!(all.iter().any(|c| c.name == "/help"));
    assert!(all.iter().any(|c| c.name == "/scan"));

    let model_matches = get_matching_commands("/m");
    assert_eq!(model_matches.len(), 1);
    assert_eq!(model_matches[0].name, "/model");

    let ex_matches = get_matching_commands("/ex");
    assert!(ex_matches.iter().any(|c| c.name == "/exit"));
    assert!(ex_matches.iter().any(|c| c.name == "/export"));

    assert!(get_matching_commands("regular text").is_empty());
    assert!(get_matching_commands("/model gpt-4o").is_empty());

    // 2. Test Autocomplete via Tab in App
    let mut app = App::new(PathBuf::from("."), false);
    app.config.api_key = None;
    app.prompt_input = "/m".to_string();

    // Press Tab to autocomplete /model
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()));
    assert_eq!(app.prompt_input, "/model ");

    // 3. Test /help command execution
    app.prompt_input = "/help".to_string();
    let quit = app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert!(!quit);
    assert!(!app.chat_messages.is_empty());
    if let Some(ChatMessage::Agent { text, .. }) = app.chat_messages.last() {
        assert!(text.contains("Command Reference"));
        assert!(text.contains("/model"));
        assert!(text.contains("/exit"));
    } else {
        panic!("Expected Agent message with command reference table");
    }

    // 4. Test /model command opens configuration popup modal (not inline in orchestrator chat)
    app.prompt_input = "/model".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert!(app.show_key_modal, "/model must open the popup modal");
    assert_eq!(app.modal_field, 1, "modal must focus on model field (1)");

    // Press Esc to dismiss the modal
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert!(!app.show_key_modal, "Esc must close the modal");

    // 5. Test /exit command execution
    app.prompt_input = "/exit".to_string();
    let quit = app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert!(quit || app.should_quit, "/exit must signal application termination");
}

#[test]
fn test_provider_model_selector_and_custom_provider_setup_flow() {
    use asterisk::types::AiProvider;
    use asterisk::ui::app::ActiveModal;
    use asterisk::ui::App;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = App::new(PathBuf::from("."), false);
    app.config.api_key = None;

    // 1. /provider opens the clean SelectProvider modal
    app.prompt_input = "/provider".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert!(app.show_key_modal);
    assert_eq!(app.active_modal, ActiveModal::SelectProvider);

    // Selecting provider 2 (OpenAI) via keypress
    app.handle_key(KeyEvent::new(KeyCode::Char('2'), KeyModifiers::empty()));
    assert_eq!(app.active_provider, AiProvider::OpenAiGpt4o);

    // Pressing Enter advances to SelectModel for OpenAI
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::SelectModel);

    // Navigating models and pressing Enter advances to ApiKeyInput (since OpenAI requires key and none is configured)
    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::empty()));
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::ApiKeyInput);
    assert_eq!(app.config.provider, AiProvider::OpenAiGpt4o);

    // Entering key and saving
    app.handle_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::empty()));
    app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::empty()));
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert!(!app.show_key_modal);
    assert_eq!(app.active_modal, ActiveModal::None);
    assert_eq!(app.config.get_api_key().as_deref(), Some("sk"));

    // 2. /custom command opens the 1-input URL setup modal
    app.config.api_key = None;
    app.prompt_input = "/custom".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert!(app.show_key_modal);
    assert_eq!(app.active_modal, ActiveModal::BaseUrlInput);
    assert_eq!(app.active_provider, AiProvider::Custom);

    // Setting custom endpoint URL
    app.handle_key(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::empty()));
    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::empty()));
    app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::empty()));
    app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::empty()));
    assert!(app.url_modal_input.contains("http"));

    // Enter advances to API key setup for custom provider
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::ApiKeyInput);

    // Setting API key and saving
    app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::empty()));
    app.handle_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::empty()));
    app.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::empty()));
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert!(!app.show_key_modal);
    assert_eq!(app.config.provider, AiProvider::Custom);
}

#[test]
fn test_slash_command_isolation_and_tab_click_accuracy() {
    use asterisk::types::ChatMessage;
    use asterisk::ui::app::FocusedPane;
    use asterisk::ui::App;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let mut app = App::new(PathBuf::from("."), false);
    app.config.api_key = Some("test-key".to_string());

    // 1. Typing slash commands must execute without creating user chat bubbles in chat_messages
    app.prompt_input = "/clear".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.chat_messages.len(), 0, "Slash command /clear must not add user message");

    app.prompt_input = "/model".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert!(app.show_key_modal);
    assert!(
        !app.chat_messages.iter().any(|m| matches!(m, ChatMessage::User(u) if u == "/model")),
        "Slash command /model must not appear in chat messages"
    );
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert!(!app.show_key_modal);

    // 2. Render frame to populate exact 50/50 split and tab click targets
    let backend = TestBackend::new(120, 40);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| app.render(f)).unwrap();

    let sidebar_rect = app.click_targets.sidebar_rect.expect("Sidebar rect must be set");
    let workspace_rect = app.click_targets.workspace_rect.expect("Workspace rect must be set");

    // 50/50 split verification
    assert_eq!(sidebar_rect.width, 60);
    assert_eq!(workspace_rect.width, 60);

    // 3. Tab click exact boundaries
    assert_eq!(app.click_targets.tab_rects.len(), 5);
    let tab0_rect = app.click_targets.tab_rects[0].1;
    let tab1_rect = app.click_targets.tab_rects[1].1;
    let tab2_rect = app.click_targets.tab_rects[2].1;

    // Clicking directly on Tab 1 ([2] Findings)
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: tab1_rect.x + 2,
        row: tab1_rect.y + 1,
        modifiers: KeyModifiers::empty(),
    });
    assert_eq!(app.current_tab, 1, "Clicking exact Tab 1 area must switch to Findings");
    assert_eq!(app.focused_pane, FocusedPane::Workflow);

    // Clicking directly on Tab 2 ([3] Patches)
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: tab2_rect.x + 2,
        row: tab2_rect.y + 1,
        modifiers: KeyModifiers::empty(),
    });
    assert_eq!(app.current_tab, 2, "Clicking exact Tab 2 area must switch to Patches");

    // Clicking directly on Tab 0 ([1] Flow)
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: tab0_rect.x + 2,
        row: tab0_rect.y + 1,
        modifiers: KeyModifiers::empty(),
    });
    assert_eq!(app.current_tab, 0, "Clicking exact Tab 0 area must switch to Flow");

    // 4. Clicking left sidebar switches focus to Chatbot
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: sidebar_rect.x + 10,
        row: sidebar_rect.y + 10,
        modifiers: KeyModifiers::empty(),
    });
    assert_eq!(app.focused_pane, FocusedPane::Chatbot);

    // 5. Independent scrolling
    let initial_scroll = app.chat_scroll;
    // Scroll while over sidebar
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::ScrollUp,
        column: sidebar_rect.x + 5,
        row: sidebar_rect.y + 5,
        modifiers: KeyModifiers::empty(),
    });
    assert_eq!(app.chat_scroll, initial_scroll + 1, "Scrolling over sidebar must scroll chat");

    // Scroll while over workflow (Tab 0) does not change chat_scroll
    let cur_chat_scroll = app.chat_scroll;
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::ScrollUp,
        column: workspace_rect.x + 5,
        row: workspace_rect.y + 10,
        modifiers: KeyModifiers::empty(),
    });
    assert_eq!(app.chat_scroll, cur_chat_scroll, "Scrolling over workflow must not alter chat_scroll");
}

#[tokio::test]
async fn test_tri_stage_pipeline_sqlite_persistence_and_commands() {
    use asterisk::core::{StateStore, SecurityContextRules};
    use asterisk::execution::{EngineMessage, ExecutionEngine};
    use asterisk::types::ChatMessage;
    use asterisk::ui::App;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use tokio::sync::mpsc::unbounded_channel;

    let target = PathBuf::from("./tests/fixtures/vulnerable_repo");
    assert!(target.exists());

    // 1. Run ExecutionEngine autonomous audit
    let (tx, mut rx) = unbounded_channel();
    let (_cmd_tx, cmd_rx) = unbounded_channel();

    let engine = ExecutionEngine::new(target.clone(), tx, cmd_rx)
        .with_diff_scope("FULL")
        .with_active_provider("AnthropicClaude");

    engine.run_autonomous_audit().await;

    // Collect engine messages
    let mut received_findings = Vec::new();
    let mut received_patches = Vec::new();
    let mut scan_finished = false;

    while let Ok(msg) = rx.try_recv() {
        match msg {
            EngineMessage::FindingsUpdated(f) => {
                received_findings = f;
            }
            EngineMessage::PatchesUpdated(p) => {
                received_patches = p;
            }
            EngineMessage::ScanFinished => {
                scan_finished = true;
            }
            _ => {}
        }
    }

    assert!(scan_finished, "ExecutionEngine audit must finish cleanly");
    assert!(!received_findings.is_empty(), "Stage 1 & 2 must produce findings");

    // Verify tri-stage fields on findings
    for f in &received_findings {
        assert!(!f.reachability.is_empty(), "Reachability must be populated");
        assert!(!f.triage_verdict.is_empty(), "Triage verdict must be populated");
        assert!(!f.triage_reasoning.is_empty(), "Triage reasoning must be auditable");
    }

    // Verify SQLite WAL persistence (.asterisk/state.sqlite)
    let store = StateStore::for_project(&target).expect("StateStore open");
    let loaded_findings = store.load_latest_findings("project_default").expect("load findings");
    assert!(!loaded_findings.is_empty(), "Findings must be persisted in SQLite");

    // Verify audit trail (.asterisk/audit_trail.jsonl)
    let audit_trail_path = target.join(".asterisk").join("audit_trail.jsonl");
    assert!(audit_trail_path.exists(), "Audit trail must exist");
    let trail_content = fs::read_to_string(&audit_trail_path).unwrap();
    assert!(trail_content.contains("SESSION_INITIALIZE"));
    assert!(trail_content.contains("STAGE_1_DETECTION_FINISHED"));
    assert!(trail_content.contains("STAGE_2_TRIAGE_FINISHED"));

    // 2. Test Slash Commands in App
    let mut app = App::new(target.clone(), false);
    app.config.api_key = Some("test-key".to_string());
    app.findings = received_findings.clone();
    app.patches = received_patches.clone();

    // Test /init-sec command
    app.prompt_input = "/init-sec".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert!(target.join("SECURITY.md").exists(), "SECURITY.md must be generated");
    let sec_rules = SecurityContextRules::load_from_workspace(&target);
    assert!(sec_rules.is_some(), "SECURITY.md must be parseable");

    // Test /reachability command
    app.prompt_input = "/reachability".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    if let Some(ChatMessage::Agent { text, .. }) = app.chat_messages.last() {
        assert!(text.contains("AST CodeContextGraph & Reachability Triage"));
    } else {
        panic!("Expected reachability analysis chat output");
    }

    // Test /shield command
    app.prompt_input = "/shield".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    if let Some(ChatMessage::Agent { text, .. }) = app.chat_messages.last() {
        assert!(text.contains("Pre-Install Malware Shield Audit"));
    } else {
        panic!("Expected malware shield chat output");
    }

    // Test /hotfix command
    app.prompt_input = "/hotfix requests".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    if let Some(ChatMessage::Agent { text, .. }) = app.chat_messages.last() {
        assert!(text.contains("Vendor Hotfix Synthesized") || text.contains("hotfix"));
    } else {
        panic!("Expected hotfix chat output");
    }

    // Test /skills command
    app.prompt_input = "/skills".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.current_tab, 4, "Must switch to skills tab [5]");

    // Test double Esc for checkpoint rewind
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert!(app.action_msg.as_deref().unwrap_or("").contains("rewound") || app.action_msg.as_deref().unwrap_or("").contains("checkpoint"));
}
