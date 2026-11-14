use asterisk::orchestrator::{AgentGraphBuilder, StrategyPlanner, WorkspaceScanner};
use asterisk::skills::SkillRegistry;
use asterisk::subagents::{
    AutoHardeningAgent, NetworkProberAgent, SastAnalyzerAgent, SecretHunterAgent, VerificationAgent,
};
use std::fs;
use std::path::PathBuf;

#[test]
fn test_harness_full_pipeline() {
    isolate_home();
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
    isolate_home();
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
    isolate_home();
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
    isolate_home();
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

    // Pressing Enter on provider opens independent ProviderDetail hub
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::ProviderDetail);
    assert_eq!(app.active_provider, AiProvider::OpenAiGpt4o);

    // Pressing 1 in ProviderDetail hub opens ApiKeyInput for this provider
    app.handle_key(KeyEvent::new(KeyCode::Char('1'), KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::ApiKeyInput);

    // Entering key and saving (returns to previous ProviderDetail hub)
    app.handle_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::empty()));
    app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::empty()));
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::ProviderDetail);
    assert_eq!(app.config.get_api_key_for_provider(AiProvider::OpenAiGpt4o).as_deref(), Some("sk"));

    // Pressing Esc in ProviderDetail hub returns to SelectProvider list
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::SelectProvider);

    // Pressing Esc in SelectProvider closes modal
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert!(!app.show_key_modal);
    assert_eq!(app.active_modal, ActiveModal::None);

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
    isolate_home();
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

#[test]
fn test_remove_send_button_and_unauthenticated_model_scan_gate() {
    isolate_home();
    use asterisk::types::{AiProvider, ChatMessage};
    use asterisk::ui::app::ActiveModal;
    use asterisk::ui::App;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let mut app = App::new(PathBuf::from("."), false);
    app.config.api_key = None;
    app.config.provider_keys.clear();
    app.config.provider = AiProvider::AnthropicClaude;
    app.active_provider = AiProvider::AnthropicClaude;

    // 1. Verify prompt bar rendering without Send button (renders full width)
    let backend = TestBackend::new(120, 40);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| app.render(f)).unwrap();

    // 2. /scan without key must not execute dummy scan; findings and flow stay empty!
    assert!(app.findings.is_empty(), "Findings must start empty");
    assert!(app.patches.is_empty(), "Patches must start empty");
    assert!(app.nodes_info.is_empty(), "Nodes must start empty");
    assert!(!app.is_running);

    app.prompt_input = "/scan".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));

    assert!(!app.is_running, "Scan must not run without configured API key");
    assert!(app.show_key_modal, "Must open key modal");
    assert_eq!(app.active_modal, ActiveModal::ApiKeyInput);
    assert!(app.findings.is_empty(), "Findings must remain empty without key");
    assert!(app.patches.is_empty(), "Patches must remain empty without key");
    assert!(app.nodes_info.is_empty(), "Graph nodes must remain empty without key");

    // Chat message explains blocking reason
    if let Some(ChatMessage::Agent { text, .. }) = app.chat_messages.last() {
        assert!(text.contains("Defense scan blocked") && text.contains("No API key configured"));
    } else {
        panic!("Expected blocking chat message for unauthenticated /scan");
    }

    // Dismiss key modal
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert!(!app.show_key_modal);

    // 3. /model <name> without key must block setting model
    app.prompt_input = "/model claude-3-7-sonnet".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert!(app.show_key_modal);
    assert_eq!(app.active_modal, ActiveModal::ApiKeyInput);
    assert_ne!(app.config.model.as_deref(), Some("claude-3-7-sonnet"), "Model must NOT be set without key");

    // Dismiss key modal
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert!(!app.show_key_modal);

    // 4. /model opens grouped model catalog; all models displayed grouped by provider
    app.prompt_input = "/model".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert!(app.show_key_modal);
    assert_eq!(app.active_modal, ActiveModal::SelectModel);
    assert!(!app.model_filtered_items.is_empty(), "Model catalog must contain all models");

    // Setting key via /key
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    app.prompt_input = "/key my-k".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert!(app.config.is_api_key_configured());

    // Now /model opens model selector with populated items
    app.prompt_input = "/model".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::SelectModel);
    assert!(!app.model_filtered_items.is_empty(), "Model catalog must be populated once authenticated");
}

#[test]
fn test_provider_hub_dynamic_synchronization_and_per_provider_storage() {
    isolate_home();
    use asterisk::types::AiProvider;
    use asterisk::ui::app::ActiveModal;
    use asterisk::ui::App;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let mut app = App::new(PathBuf::from("."), false);
    app.config.api_key = None;
    app.config.provider_keys.clear();
    app.config.provider_base_urls.clear();

    // 1. Initial State: DeepSeek is not configured, Ollama is local ready
    assert!(!app.config.is_provider_configured(AiProvider::DeepSeek));
    assert_eq!(app.config.mask_key_for_provider(AiProvider::DeepSeek), "None (Unset)");
    assert!(app.config.is_provider_configured(AiProvider::OllamaLocal));
    assert_eq!(app.config.mask_key_for_provider(AiProvider::OllamaLocal), "Not Required (Offline Local)");

    // 2. Open /provider modal
    app.prompt_input = "/provider".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::SelectProvider);

    // Navigate to DeepSeek (index 3 or press '4')
    app.handle_key(KeyEvent::new(KeyCode::Char('4'), KeyModifiers::empty()));
    assert_eq!(app.active_provider, AiProvider::DeepSeek);

    // Press Enter to open dedicated Provider Hub for DeepSeek
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::ProviderDetail);
    assert_eq!(app.active_provider, AiProvider::DeepSeek);

    // 3. Test rendering Provider Hub under standard and constrained terminals (no panic, no overflow)
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| app.render(f)).unwrap();

    let backend_small = TestBackend::new(60, 20);
    let mut terminal_small = Terminal::new(backend_small).unwrap();
    terminal_small.draw(|f| app.render(f)).unwrap();

    // 4. Press '1' to input API Key for DeepSeek
    app.handle_key(KeyEvent::new(KeyCode::Char('1'), KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::ApiKeyInput);
    app.key_modal_input = "sk-deepseek-test123456".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));

    // Must return to ProviderDetail for DeepSeek
    assert_eq!(app.active_modal, ActiveModal::ProviderDetail);
    assert!(app.config.is_provider_configured(AiProvider::DeepSeek));
    assert_eq!(
        app.config.mask_key_for_provider(AiProvider::DeepSeek),
        "sk-d••••••••3456"
    );

    // 5. Press '2' to input Base URL for DeepSeek
    app.handle_key(KeyEvent::new(KeyCode::Char('2'), KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::BaseUrlInput);
    app.url_modal_input = "https://custom.deepseek.local/v1".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));

    // Must return to ProviderDetail
    assert_eq!(app.active_modal, ActiveModal::ProviderDetail);
    assert_eq!(
        app.config.get_base_url_for_provider(AiProvider::DeepSeek).as_deref(),
        Some("https://custom.deepseek.local/v1")
    );

    // 6. Verify other providers remain unpolluted and dynamically consistent
    assert_eq!(
        app.config.get_base_url_for_provider(AiProvider::OllamaLocal).as_deref(),
        Some("http://localhost:11434")
    );

    // 7. Press Esc to return to SelectProvider list
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::SelectProvider);

    // Press Esc again to return to workspace
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::None);
    assert!(!app.show_key_modal);
}

#[test]
fn test_fit_helpers_never_exceed_width() {
    isolate_home();
    use asterisk::ui::fit::{ellipsize, ellipsize_start, hint_line, tab_widths, text_width};
    use ratatui::style::Style;

    for w in 0..40usize {
        assert!(text_width(&ellipsize("claude-3-7-sonnet-20250219 ✓ 日本語", w)) <= w);
        assert!(text_width(&ellipsize_start("/home/frigg/Projects/asterisk/src", w)) <= w);
        let line = hint_line(
            &[("[1-6/↑↓]", "Select"), ("[Enter]", "Open Hub"), ("[k]", "API Key"), ("[u]", "Endpoint URL"), ("[Esc]", "Back")],
            w,
            Style::default(),
            Style::default(),
            "  ",
        );
        if w >= 6 {
            assert!(line.width() <= w, "hint overflow at width {w}: {}", line.width());
        }
    }
    let natural = [8usize, 17, 17, 8, 9];
    for avail in [20usize, 30, 40, 60, 80] {
        for active in 0..5 {
            let ws = tab_widths(&natural, active, avail, 1);
            assert_eq!(ws[active], natural[active].min(ws[active]));
            if avail >= 5 * 5 + 4 + 12 {
                assert!(ws.iter().sum::<usize>() + 4 <= avail, "tabs overflow avail={avail} {ws:?}");
            }
        }
    }
}

#[test]
fn test_render_all_screens_at_multiple_terminal_sizes() {
    isolate_home();
    use asterisk::types::AiProvider;
    use asterisk::ui::App;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    for (w, h) in [(60u16, 20u16), (80, 24), (100, 30), (140, 40)] {
        let mut app = App::new(PathBuf::from("/home/frigg/Projects/a-very-long-project-directory-name/subdir"), false);
        app.config.provider = AiProvider::DeepSeek;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        for tab in 0..5usize {
            app.current_tab = tab;
            term.draw(|f| app.render(f)).unwrap();
        }
        for cmd in ["/", "/provider", "/model", "/config"] {
            app.prompt_input = cmd.to_string();
            term.draw(|f| app.render(f)).unwrap();
            if cmd != "/" {
                app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
                term.draw(|f| app.render(f)).unwrap();
                app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
            }
            app.prompt_input.clear();
        }
    }
}

/// Tests must never read or write the developer's real ~/.config/asterisk/config.json.
fn isolate_home() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let dir = std::env::temp_dir().join(format!("asterisk-test-home-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        // SAFETY: runs once, before any test touches config; all tests call this first.
        unsafe { std::env::set_var("HOME", &dir) };
    });
}

#[test]
fn test_hotkeys_do_not_collide_with_typing_or_open_wrong_modal() {
    isolate_home();
    use asterisk::types::AiProvider;
    use asterisk::ui::app::ActiveModal;
    use asterisk::ui::App;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = App::new(PathBuf::from("."), false);
    app.config.api_key = None;
    app.config.provider_keys.clear();
    app.config.provider = AiProvider::DeepSeek;

    // Plain letters must always type into the prompt (not trigger actions)
    for c in "apply run export".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::empty()));
    }
    assert_eq!(app.prompt_input, "apply run export");
    app.prompt_input.clear();

    // Space / Enter without key -> NO popup, only a hint; typed text is kept
    app.handle_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::None);
    assert!(!app.show_key_modal);
    assert!(app.action_msg.as_deref().unwrap_or("").contains("/provider"));
    app.prompt_input = "hello".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::None);
    assert!(!app.show_key_modal);
    assert_eq!(app.prompt_input, "hello");
    app.prompt_input.clear();

    // Alt+3 switches tab; plain 3 types
    app.handle_key(KeyEvent::new(KeyCode::Char('3'), KeyModifiers::ALT));
    assert_eq!(app.current_tab, 2);
    app.handle_key(KeyEvent::new(KeyCode::Char('3'), KeyModifiers::empty()));
    assert_eq!(app.prompt_input, "3");
}

#[test]
fn test_live_model_discovery_and_provider_sync() {
    isolate_home();
    use asterisk::execution::EngineMessage;
    use asterisk::types::AiProvider;
    use asterisk::ui::app::ActiveModal;
    use asterisk::ui::App;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = App::new(PathBuf::from("."), false);
    app.config.api_key = None;
    app.config.provider = AiProvider::DeepSeek;

    // 1. Initial State: No discovered models, uses defaults
    assert!(!app.config.has_discovered_models(AiProvider::DeepSeek));
    let initial_models = app.config.get_models_for_provider(AiProvider::DeepSeek);
    assert_eq!(initial_models, AiProvider::DeepSeek.preset_models());

    // 2. Open /provider -> DeepSeek -> ProviderDetail
    app.prompt_input = "/provider".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::SelectProvider);

    app.handle_key(KeyEvent::new(KeyCode::Char('4'), KeyModifiers::empty()));
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::ProviderDetail);

    // 3. Trigger live sync via shortcut '4'
    app.handle_key(KeyEvent::new(KeyCode::Char('4'), KeyModifiers::empty()));
    assert!(app.action_msg.as_deref().unwrap_or("").contains("API"));

    // 4. Simulate API returned models message
    let mock_models = vec![
        "deepseek-chat".to_string(),
        "deepseek-coder-v2".to_string(),
        "deepseek-reasoner-r1".to_string(),
    ];
    let _ = app.engine_tx.send(EngineMessage::ModelsDiscovered {
        provider: AiProvider::DeepSeek,
        models: mock_models.clone(),
    });

    // Update app loop to process engine message
    app.update();

    // 5. Verify models are stored, live flag is active, and /model reflects discovered list
    assert!(app.config.has_discovered_models(AiProvider::DeepSeek));
    assert_eq!(
        app.config.get_models_for_provider(AiProvider::DeepSeek),
        mock_models
    );

    // Open /model and verify discovered items are present
    app.handle_key(KeyEvent::new(KeyCode::Char('3'), KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::SelectModel);

    let has_coder_v2 = app
        .model_filtered_items
        .iter()
        .any(|(prov, name, _)| *prov == AiProvider::DeepSeek && name == "deepseek-coder-v2");
    assert!(has_coder_v2, "Newly discovered live model must be present in model catalog");
}

#[test]
fn test_sequential_provider_wizard_custom_and_predefined() {
    isolate_home();
    use asterisk::types::AiProvider;
    use asterisk::ui::app::ActiveModal;
    use asterisk::ui::App;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = App::new(PathBuf::from("."), false);

    // =========================================================================
    // 1. CUSTOM PROVIDER: Complete 3-Step Wizard Flow (Name -> URL -> Key -> Model)
    // =========================================================================
    app.start_provider_setup_flow(AiProvider::Custom);
    assert!(app.show_key_modal);
    assert_eq!(app.active_modal, ActiveModal::CustomProviderNameInput);

    // Step 1: Type custom provider name
    app.custom_provider_name_input.clear();
    for c in "OpenRouter AI".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::empty()));
    }
    assert_eq!(app.custom_provider_name_input, "OpenRouter AI");

    // Press Enter -> advances to Step 2 (Base URL)
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::BaseUrlInput);

    // Test Esc step-back: URL -> Name
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::CustomProviderNameInput);

    // Re-advance to Step 2
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::BaseUrlInput);

    // Step 2: Enter Base URL
    app.url_modal_input.clear();
    for c in "https://openrouter.ai/api/v1".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::empty()));
    }

    // Press Enter -> advances to Step 3 (API Key)
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::ApiKeyInput);

    // Test Esc step-back: Key -> URL
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::BaseUrlInput);

    // Re-advance to Step 3
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::ApiKeyInput);

    // Step 3: Enter API Key
    app.key_modal_input.clear();
    for c in "sk-or-v1-custom-secret".chars() {
        app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::empty()));
    }

    // Press Enter -> completes credentials and advances automatically to Model Catalog
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::SelectModel);
    assert_eq!(
        app.config.get_provider_display_name(AiProvider::Custom),
        "Custom (OpenRouter AI)"
    );
    assert_eq!(
        app.config.get_base_url_for_provider(AiProvider::Custom).as_deref(),
        Some("https://openrouter.ai/api/v1")
    );
    assert_eq!(
        app.config.get_api_key_for_provider(AiProvider::Custom).as_deref(),
        Some("sk-or-v1-custom-secret")
    );

    // Close model modal
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    // =========================================================================
    // 2. PREDEFINED PROVIDER (e.g. Claude): 2-Step Flow (URL -> Key -> Model)
    // Omit provider name step automatically!
    // =========================================================================
    app.start_provider_setup_flow(AiProvider::AnthropicClaude);
    assert!(app.show_key_modal);
    assert_eq!(app.active_modal, ActiveModal::BaseUrlInput); // Directly Step 1 of 2

    // Esc step-back from Step 1 returns to SelectProvider
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::SelectProvider);

    // Restart Claude setup wizard
    app.start_provider_setup_flow(AiProvider::AnthropicClaude);
    assert_eq!(app.active_modal, ActiveModal::BaseUrlInput);

    // Enter Base URL -> advances to Step 2 (API Key)
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::ApiKeyInput);

    // Esc step-back from Step 2 returns to Step 1 (Base URL)
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::BaseUrlInput);

    // Advance to Step 2 again and provide key
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::ApiKeyInput);
    app.key_modal_input = "sk-ant-api03-live-test".to_string();

    // Enter saves and advances to Model Catalog
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::SelectModel);
    assert_eq!(
        app.config.get_api_key_for_provider(AiProvider::AnthropicClaude).as_deref(),
        Some("sk-ant-api03-live-test")
    );

    // Close model modal
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    // =========================================================================
    // 3. OLLAMA LOCAL: 1-Step Flow (Base URL -> Model Catalog)
    // Skips Name step AND skips API Key authentication entirely!
    // =========================================================================
    app.start_provider_setup_flow(AiProvider::OllamaLocal);
    assert!(app.show_key_modal);
    assert_eq!(app.active_modal, ActiveModal::BaseUrlInput); // Directly Step 1 of 1

    // Enter completes endpoint and advances directly to Model Catalog without asking for API Key
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
    assert_eq!(app.active_modal, ActiveModal::SelectModel);
}

#[test]
fn test_expanded_providers_and_reasoning_models() {
    isolate_home();
    use asterisk::types::AiProvider;
    use asterisk::core::agent::parse_ai_thinking_content;
    use asterisk::ui::markdown::preprocess_reasoning_tags;

    // 1. Verify 11 providers in AiProvider::ALL
    assert_eq!(AiProvider::ALL.len(), 11);
    let expected_names = [
        "Anthropic Claude", "OpenAI", "Google Gemini", "DeepSeek",
        "Groq", "OpenRouter", "Mistral AI", "Together AI", "xAI (Grok)",
        "Ollama Local", "Custom Provider"
    ];
    for (i, p) in AiProvider::ALL.iter().enumerate() {
        assert_eq!(p.name(), expected_names[i]);
        assert!(!p.preset_models().is_empty());
        assert!(!p.default_model().is_empty());
    }

    // 2. Verify default base URLs for cloud OpenAI-compatible providers
    assert_eq!(AiProvider::Groq.default_base_url(), Some("https://api.groq.com/openai/v1"));
    assert_eq!(AiProvider::OpenRouter.default_base_url(), Some("https://openrouter.ai/api/v1"));
    assert_eq!(AiProvider::Mistral.default_base_url(), Some("https://api.mistral.ai/v1"));
    assert_eq!(AiProvider::TogetherAi.default_base_url(), Some("https://api.together.xyz/v1"));
    assert_eq!(AiProvider::XAi.default_base_url(), Some("https://api.x.ai/v1"));

    // 3. Test reasoning / <think> extraction
    let raw_ai_output = "<think>\nAnalyzing AST nodes for SQL injection vulnerabilities...\nChecking input sanitization.\n</think>\n\n# Audit Verdict\nNo vulnerabilities detected.";
    let (thinking, content) = parse_ai_thinking_content(raw_ai_output);
    assert!(thinking.is_some());
    let t = thinking.unwrap();
    assert!(t.contains("Analyzing AST nodes"));
    assert_eq!(content.trim(), "# Audit Verdict\nNo vulnerabilities detected.");

    // 4. Test Markdown preprocessor for thinking tags
    let preprocessed = preprocess_reasoning_tags(raw_ai_output);
    assert!(!preprocessed.contains("<think>"));
    assert!(preprocessed.contains("Thinking Process"));
    assert!(preprocessed.contains("Analyzing AST nodes"));
    assert!(preprocessed.contains("# Audit Verdict"));
}

#[test]
fn test_user_skills_directory_discovery() {
    isolate_home();
    let temp_skills_dir = std::env::temp_dir().join(format!("asterisk-test-skills-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_skills_dir);

    // Create a custom skill file
    let custom_skill_content = r#"---
name: zero-day-recon
description: Autonomous zero-day vulnerability discovery heuristic
tier: Tier3Expert
commands: ["/zeroday"]
---
# Zero-Day Reconnaissance Procedure
Search for unknown memory corruption and unvalidated deserialization vectors.
"#;
    let skill_path = temp_skills_dir.join("zero_day.skill.md");
    std::fs::write(&skill_path, custom_skill_content).expect("write skill");

    // Override ASTERISK_SKILLS_DIR
    unsafe { std::env::set_var("ASTERISK_SKILLS_DIR", &temp_skills_dir) };

    let registry = SkillRegistry::new();
    let found = registry.skills.iter().any(|s| s.id == "zero-day-recon" || s.name == "zero-day-recon");
    assert!(found, "User skill from ~/.asterisk/skills/ must be discovered and registered");

    let _ = std::fs::remove_dir_all(&temp_skills_dir);
}

#[test]
fn test_unauthenticated_scan_strictly_empty() {
    isolate_home();
    use asterisk::ui::app::App;
    use asterisk::core::config::AppConfig;
    use asterisk::types::AiProvider;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    // Isolated config with empty key
    let temp_cfg = std::env::temp_dir().join(format!("asterisk-unauth-test-{}.json", std::process::id()));
    let mut config = AppConfig::default();
    config.api_key = None;
    config.provider_keys.clear();
    let _ = std::fs::write(&temp_cfg, serde_json::to_string_pretty(&config).unwrap());
    unsafe { std::env::set_var("ASTERISK_CONFIG_PATH", &temp_cfg) };

    let mut app = App::new(PathBuf::from("./tests/fixtures/vulnerable_repo"), false);
    app.config.api_key = None;
    app.config.provider_keys.clear();
    app.config.provider = AiProvider::AnthropicClaude;
    assert!(!app.config.is_api_key_configured());
    assert!(app.nodes_info.is_empty());
    assert!(app.findings.is_empty());
    assert!(app.patches.is_empty());

    // User types /scan and presses Enter
    app.prompt_input = "/scan".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));

    // Strict invariant: Scan must be blocked, workflow/findings/patches MUST remain completely empty
    assert!(!app.is_running, "Audit must not start without authentication");
    assert!(app.nodes_info.is_empty(), "Nodes must not be populated when unauthenticated");
    assert!(app.findings.is_empty(), "Findings must remain empty");
    assert!(app.patches.is_empty(), "Patches must remain empty");
    assert!(app.show_key_modal, "Auth/Key modal must be shown to prompt the user");

    let _ = std::fs::remove_file(&temp_cfg);
}
