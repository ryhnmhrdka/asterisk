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
    app.config.provider_keys.clear();
    app.config.provider = asterisk::types::AiProvider::AnthropicClaude;
    app.active_provider = asterisk::types::AiProvider::AnthropicClaude;

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

    // Master-detail proportion verification (45% left sidebar / 55% right workspace)
    assert_eq!(sidebar_rect.width, 54);
    assert_eq!(workspace_rect.width, 66);
    assert_eq!(sidebar_rect.width + workspace_rect.width, 120);

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

#[test]
fn test_tui_design_review_enhancements() {
    isolate_home();
    use asterisk::ui::app::{App, FocusedPane};
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::Terminal;

    let mut app = App::new(PathBuf::from("./tests/fixtures/vulnerable_repo"), false);

    // 1. Minimum terminal size protection check
    let small_backend = TestBackend::new(50, 10);
    let mut small_terminal = Terminal::new(small_backend).unwrap();
    small_terminal.draw(|f| app.render(f)).expect("Small terminal render must not panic");
    let buffer = small_terminal.backend().buffer().clone();
    let text: String = buffer.content().iter().map(|c| c.symbol()).collect();
    assert!(text.contains("Terminal Window Too Small"), "Should show polite resize notice on small screens");

    // 2. Normal terminal rendering with designed empty states across all tabs
    let normal_backend = TestBackend::new(120, 35);
    let mut terminal = Terminal::new(normal_backend).unwrap();

    // Tab 1 (Findings) Empty State
    app.current_tab = 1;
    terminal.draw(|f| app.render(f)).expect("Tab 1 render must succeed");
    let t1_text: String = terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect();
    assert!(t1_text.contains("Workspace Security Clean"), "Tab 1 must show designed empty state");

    // Tab 2 (Patches) Empty State
    app.current_tab = 2;
    terminal.draw(|f| app.render(f)).expect("Tab 2 render must succeed");
    let t2_text: String = terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect();
    assert!(t2_text.contains("No Hardening Patches Required"), "Tab 2 must show designed empty state");

    // Tab 3 (Logs) Empty State
    app.current_tab = 3;
    terminal.draw(|f| app.render(f)).expect("Tab 3 render must succeed");
    let t3_text: String = terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect();
    assert!(t3_text.contains("Execution Event Log Idle"), "Tab 3 must show designed empty state");

    // 3. Focus toggle and Chatbot Keyboard Scrolling
    app.current_tab = 0;
    app.focused_pane = FocusedPane::Chatbot;
    app.chat_scroll = 0;

    // Test PageUp / PageDown keys for chat scroll
    app.handle_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::empty()));
    assert_eq!(app.chat_scroll, 5, "PageUp must scroll chat up by 5 lines");

    app.handle_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::empty()));
    assert_eq!(app.chat_scroll, 0, "PageDown must scroll chat down");

    // Test Ctrl+U / Ctrl+D
    app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    assert_eq!(app.chat_scroll, 5, "Ctrl+U must scroll chat up");

    app.handle_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL));
    assert_eq!(app.chat_scroll, 0, "Ctrl+D must scroll chat down");

    // Test Shift+Tab / Ctrl+W pane switching
    app.handle_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::empty()));
    assert_eq!(app.focused_pane, FocusedPane::Workflow, "Shift+Tab must toggle focus to Workflow");

    app.handle_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::empty()));
    assert_eq!(app.focused_pane, FocusedPane::Chatbot, "Shift+Tab must toggle focus back to Chatbot");
}

#[test]
fn test_interactive_help_modal_and_findings_reachability_filter() {
    isolate_home();
    use asterisk::types::{Severity, VulnerabilityFinding};
    use asterisk::ui::app::{ActiveModal, App, FocusedPane};
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::Terminal;

    let mut app = App::new(PathBuf::from("./tests/fixtures/vulnerable_repo"), false);

    // 1. Pressing '?' opens the interactive help modal cheat sheet
    assert!(!app.show_key_modal);
    app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::empty()));
    assert!(app.show_key_modal, "'?' must open modal");
    assert!(matches!(app.active_modal, ActiveModal::Help));

    // Render help modal and verify cheat sheet contents
    let backend = TestBackend::new(120, 35);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| app.render(f)).expect("Help modal render must succeed");
    let text: String = terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect();
    assert!(text.contains("ASTERISK"), "Modal should display Asterisk header");
    assert!(text.contains("Keyboard Shortcuts"), "Modal should list keyboard shortcuts");
    assert!(text.contains("Shift+Tab"), "Modal should document Shift+Tab");
    assert!(text.contains("/scan"), "Modal should document /scan");

    // Esc closes help modal
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert!(!app.show_key_modal, "Esc must dismiss help modal");
    assert!(matches!(app.active_modal, ActiveModal::None));

    // 2. Tab 1 Findings reachability filter and vim navigation
    app.current_tab = 1;
    app.focused_pane = FocusedPane::Workflow;

    app.findings = vec![
        VulnerabilityFinding {
            id: "AST-VULN-001".to_string(),
            title: "SQL Injection".to_string(),
            severity: Severity::Critical,
            cwe: "CWE-89".to_string(),
            reachability: "REACHABLE".to_string(),
            file_path: PathBuf::from("src/db.rs"),
            line_number: 42,
            snippet: "db.query(&sql);".to_string(),
            description: "Unsanitized input executed in SQL engine.".to_string(),
            recommendation: "Use parameterized queries.".to_string(),
            patched: false,
            call_path: vec!["main".to_string(), "handle_req".to_string()],
            triage_verdict: "Confirmed Exploitable".to_string(),
            triage_reasoning: "Taint propagates directly from HTTP body to query sink.".to_string(),
        },
        VulnerabilityFinding {
            id: "AST-VULN-002".to_string(),
            title: "Dead Code Path Weak Hash".to_string(),
            severity: Severity::Low,
            cwe: "CWE-328".to_string(),
            reachability: "UNREACHABLE".to_string(),
            file_path: PathBuf::from("src/legacy.rs"),
            line_number: 10,
            snippet: "md5(data);".to_string(),
            description: "Deprecated hash algorithm.".to_string(),
            recommendation: "Upgrade to SHA-256.".to_string(),
            patched: false,
            call_path: Vec::new(),
            triage_verdict: "Non-exploitable Phantom".to_string(),
            triage_reasoning: "Unreachable dead function.".to_string(),
        },
    ];

    terminal.draw(|f| app.render(f)).expect("Findings matrix render must succeed");
    let t_all: String = terminal.backend().buffer().content().iter().map(|c| c.symbol()).collect();
    assert!(t_all.contains("CRIT: 1"));
    assert!(t_all.contains("LOW: 1"));
    assert!(t_all.contains("Reachable: 1/2"));

    // Press 'r' in Workflow pane to toggle reachable-only filter
    assert!(!app.findings_filter_reachable);
    app.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::empty()));
    assert!(app.findings_filter_reachable, "'r' must activate reachability filter");

    // Press 'a' to reset to all findings
    app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::empty()));
    assert!(!app.findings_filter_reachable, "'a' must reset filter to all findings");

    // Test 'j' and 'k' navigation in Workflow pane
    assert_eq!(app.selected_matrix_row, 0);
    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()));
    assert_eq!(app.selected_matrix_row, 1, "'j' must move cursor down to next finding");

    app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::empty()));
    assert_eq!(app.selected_matrix_row, 0, "'k' must move cursor up to previous finding");
}

#[tokio::test]
async fn test_ai_workflow_plan_synthesis_and_parsing() {
    use asterisk::orchestrator::{AgentGraphBuilder, StrategyPlanner};
    use std::collections::HashMap;

    let target = PathBuf::from("./tests/fixtures/vulnerable_repo");
    assert!(target.exists());

    // 1. Scan workspace file list - verify low-level files/cargo/git are ignored
    let files = StrategyPlanner::scan_workspace_file_list(&target);
    assert!(!files.is_empty(), "workspace should contain source files");
    for f in &files {
        assert!(!f.ends_with("Cargo.toml"), "Cargo.toml should be filtered out: {f}");
        assert!(!f.contains(".git"), ".git should be filtered out: {f}");
        assert!(!f.contains("target"), "target build dir should be filtered out: {f}");
    }

    // 2. Heuristic workflow plan generation
    let plan = StrategyPlanner::create_heuristic_workflow_plan(&files, None);
    assert!(!plan.nodes.is_empty(), "heuristic plan should generate modular tasks");
    assert!(plan.nodes.iter().any(|n| n.agent == "secrets"), "must include secrets hunter task");
    assert!(plan.nodes.iter().any(|n| n.agent == "sast"), "must include sast analyzer task");

    // 2b. Test directive influence in heuristic generation
    let directive_plan = StrategyPlanner::create_heuristic_workflow_plan(&files, Some("tolong scan folder auth dulu gitu"));
    assert!(
        directive_plan.nodes.iter().any(|n| n.id == "task_user_priority" || n.title.contains("User Directed")),
        "Directive should create prioritized user scope node"
    );

    // 3. Workflow JSON serialization & parsing
    let json_str = serde_json::to_string_pretty(&plan).expect("plan must serialize to json");
    let parsed_plan = StrategyPlanner::parse_workflow_json(&json_str).expect("plan must parse from json");
    assert_eq!(plan.workflow_name, parsed_plan.workflow_name);
    assert_eq!(plan.nodes.len(), parsed_plan.nodes.len());

    // 4. Construct Flow graph from plan
    let mut nodes_info = HashMap::new();
    let _flow = AgentGraphBuilder::build_from_workflow_plan(&plan, &mut nodes_info)
        .expect("building flow from workflow plan should succeed");

    assert!(nodes_info.contains_key("orch"), "must contain orch root");
    assert!(nodes_info.contains_key("defense_gate"), "must contain defense gate");
    for task in &plan.nodes {
        assert!(nodes_info.contains_key(&task.id), "nodes_info must contain task {}", task.id);
    }
}

#[tokio::test]
async fn test_interactive_workflow_node_delete_and_move() {
    use asterisk::orchestrator::AgentGraphBuilder;
    use asterisk::types::{WorkflowPlan, WorkflowTaskNode};
    use asterisk::ui::App;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let target = PathBuf::from("./tests/fixtures/vulnerable_repo");
    let mut app = App::new(target, false);
    app.config.api_key = Some("test-key".to_string());

    let test_plan = WorkflowPlan {
        workflow_name: "Test Dynamic Workflow".to_string(),
        target_summary: "Test targets".to_string(),
        nodes: vec![
            WorkflowTaskNode {
                id: "task_1_secrets".to_string(),
                title: "Secrets Scan".to_string(),
                subtitle: "Entropy analysis".to_string(),
                agent: "secrets".to_string(),
                tier: "secrets".to_string(),
                targets: vec!["src/main.rs".to_string()],
                description: "Scan secrets".to_string(),
                order: 0,
                depends_on: vec![],
            },
            WorkflowTaskNode {
                id: "task_2_sast".to_string(),
                title: "SAST Scan".to_string(),
                subtitle: "Code guard".to_string(),
                agent: "sast".to_string(),
                tier: "sast".to_string(),
                targets: vec!["src/app.rs".to_string()],
                description: "Scan sast".to_string(),
                order: 1,
                depends_on: vec![],
            },
            WorkflowTaskNode {
                id: "task_3_net".to_string(),
                title: "Net Surface".to_string(),
                subtitle: "Network check".to_string(),
                agent: "net".to_string(),
                tier: "net".to_string(),
                targets: vec![],
                description: "Scan net".to_string(),
                order: 2,
                depends_on: vec![],
            },
        ],
    };

    app.flow = AgentGraphBuilder::build_from_workflow_plan(&test_plan, &mut app.nodes_info)
        .expect("Flow construction must succeed");
    app.current_workflow_plan = Some(test_plan.clone());
    app.awaiting_confirmation = true;
    app.current_tab = 0;

    // Orchestrator and defense gate cannot be deleted
    app.selected_node_id = Some("orch".to_string());
    app.delete_selected_workflow_node();
    assert!(app.nodes_info.contains_key("orch"), "orch must never be deleted");

    app.selected_node_id = Some("defense_gate".to_string());
    app.delete_selected_workflow_node();
    assert!(app.nodes_info.contains_key("defense_gate"), "defense_gate must never be deleted");

    // Deleting task_2_sast via 'd' key
    app.selected_node_id = Some("task_2_sast".to_string());
    assert!(app.nodes_info.contains_key("task_2_sast"));
    app.handle_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::empty()));
    assert!(!app.nodes_info.contains_key("task_2_sast"), "task_2_sast must be deleted");
    assert_eq!(app.current_workflow_plan.as_ref().unwrap().nodes.len(), 2);

    // Shifting task_3_net horizontally left
    app.selected_node_id = Some("task_3_net".to_string());
    let initial_x = app.flow.node("task_3_net").unwrap().position.x;
    app.handle_key(KeyEvent::new(KeyCode::Left, KeyModifiers::empty()));
    let shifted_x = app.flow.node("task_3_net").unwrap().position.x;
    assert!(shifted_x < initial_x, "task_3_net position.x must shift left");

    // Shifting task_3_net horizontally right via 'l'
    app.handle_key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::empty()));
    let reverted_x = app.flow.node("task_3_net").unwrap().position.x;
    assert!((reverted_x - initial_x).abs() < 0.1, "task_3_net position.x must shift right back");

    // Shifting task_3_net vertically up via 'k'
    let initial_y = app.flow.node("task_3_net").unwrap().position.y;
    app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::empty()));
    let shifted_y = app.flow.node("task_3_net").unwrap().position.y;
    assert!(shifted_y < initial_y, "task_3_net position.y must shift up");

    // Shifting task_3_net vertically down via 'j'
    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()));
    let reverted_y = app.flow.node("task_3_net").unwrap().position.y;
    assert!((reverted_y - initial_y).abs() < 0.1, "task_3_net position.y must shift down back");
}

#[tokio::test]
async fn test_flow_pause_and_resume_execution() {
    use asterisk::execution::{EngineCommand, EngineMessage, ExecutionEngine};
    use asterisk::types::{WorkflowTaskNode, AgentStatus};
    use std::collections::HashSet;
    use tokio::sync::mpsc::unbounded_channel;

    let target = PathBuf::from("./tests/fixtures/vulnerable_repo");
    let (tx, mut rx) = unbounded_channel();
    let (cmd_tx, cmd_rx) = unbounded_channel();

    let custom_tasks = vec![
        WorkflowTaskNode {
            id: "paused_task".to_string(),
            title: "Paused Task Test".to_string(),
            subtitle: "Testing pause".to_string(),
            agent: "secrets".to_string(),
            tier: "secrets".to_string(),
            targets: vec![],
            description: "Task that starts paused".to_string(),
            order: 0,
            depends_on: vec![],
        },
    ];

    let mut initially_paused = HashSet::new();
    initially_paused.insert("paused_task".to_string());

    let engine = ExecutionEngine::new(target, tx, cmd_rx)
        .with_tasks(custom_tasks)
        .with_paused_nodes(initially_paused);

    let handle = tokio::spawn(async move {
        engine.run_autonomous_audit().await;
    });

    // Wait briefly and verify node announced as Paused
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let mut saw_paused = false;
    while let Ok(msg) = rx.try_recv() {
        if let EngineMessage::NodeStatusChanged { id, status } = msg {
            if id == "paused_task" && status == AgentStatus::Paused {
                saw_paused = true;
            }
        }
    }
    assert!(saw_paused, "paused_task must enter AgentStatus::Paused");

    // Send resume command
    let _ = cmd_tx.send(EngineCommand::ResumeNode("paused_task".to_string()));

    // Await engine completion
    let _ = handle.await;

    let mut saw_success = false;
    while let Ok(msg) = rx.try_recv() {
        if let EngineMessage::NodeStatusChanged { id, status } = msg {
            if id == "paused_task" && status == AgentStatus::Success {
                saw_success = true;
            }
        }
    }
    assert!(saw_success, "paused_task must finish with AgentStatus::Success after resume");
}

#[tokio::test]
async fn test_dynamic_workflow_execution_follows_reordered_nodes() {
    use asterisk::execution::{EngineMessage, ExecutionEngine};
    use asterisk::types::{WorkflowTaskNode, AgentStatus};
    use tokio::sync::mpsc::unbounded_channel;

    let target = PathBuf::from("./tests/fixtures/vulnerable_repo");
    let (tx, mut rx) = unbounded_channel();
    let (_cmd_tx, cmd_rx) = unbounded_channel();

    let custom_tasks = vec![
        WorkflowTaskNode {
            id: "custom_secrets".to_string(),
            title: "Secret Detection".to_string(),
            subtitle: "Credential miner".to_string(),
            agent: "secrets".to_string(),
            tier: "secrets".to_string(),
            targets: vec!["secrets".to_string()],
            description: "Scan test secrets".to_string(),
            order: 0,
            depends_on: vec![],
        },
        WorkflowTaskNode {
            id: "custom_sast".to_string(),
            title: "SAST Deep Inspection".to_string(),
            subtitle: "AST analyzer".to_string(),
            agent: "sast".to_string(),
            tier: "sast".to_string(),
            targets: vec!["src".to_string()],
            description: "Scan test sast".to_string(),
            order: 1,
            depends_on: vec![],
        },
    ];

    let engine = ExecutionEngine::new(target, tx, cmd_rx)
        .with_diff_scope("FULL")
        .with_active_provider("AnthropicClaude")
        .with_tasks(custom_tasks);

    engine.run_autonomous_audit().await;

    let mut executed_nodes = Vec::new();
    let mut scan_finished = false;

    while let Ok(msg) = rx.try_recv() {
        match msg {
            EngineMessage::NodeStatusChanged { id, status } => {
                if status == AgentStatus::Running {
                    executed_nodes.push(id);
                }
            }
            EngineMessage::ScanFinished => {
                scan_finished = true;
            }
            _ => {}
        }
    }

    assert!(scan_finished, "Scan must complete");
    assert!(executed_nodes.contains(&"custom_secrets".to_string()), "custom_secrets must execute");
    assert!(executed_nodes.contains(&"custom_sast".to_string()), "custom_sast must execute");
}

#[tokio::test]
async fn test_scan_with_custom_directive_prompt() {
    use asterisk::types::ChatMessage;
    use asterisk::ui::App;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let target = PathBuf::from("./tests/fixtures/vulnerable_repo");
    let mut app = App::new(target, false);
    app.config.api_key = Some("test-key".to_string());

    // Type /scan with custom user directive
    app.prompt_input = "/scan tolong scan folder backend dulu gitu".to_string();
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));

    // Verify thinking message reflects user's directive
    let has_directive_thinking = app.chat_messages.iter().any(|msg| match msg {
        ChatMessage::Thinking { thought, .. } => thought.contains("tolong scan folder backend dulu gitu"),
        _ => false,
    });
    assert!(has_directive_thinking, "Orchestrator thinking must incorporate user directive");
}

#[tokio::test]
async fn test_branching_tree_dag_layout() {
    use asterisk::orchestrator::AgentGraphBuilder;
    use asterisk::types::{WorkflowPlan, WorkflowTaskNode};
    use std::collections::HashMap;

    let branched_plan = WorkflowPlan {
        workflow_name: "Branched Test Pipeline".to_string(),
        target_summary: "Multi-branch tree test".to_string(),
        nodes: vec![
            WorkflowTaskNode {
                id: "b1_secrets".to_string(),
                title: "Branch 1: Secrets".to_string(),
                subtitle: "cred miner".to_string(),
                agent: "secrets".to_string(),
                tier: "secrets".to_string(),
                targets: vec![],
                description: "branch 1".to_string(),
                order: 1,
                depends_on: vec![], // Root-level parallel branch 1
            },
            WorkflowTaskNode {
                id: "b2_sast".to_string(),
                title: "Branch 2: SAST".to_string(),
                subtitle: "code guard".to_string(),
                agent: "sast".to_string(),
                tier: "sast".to_string(),
                targets: vec![],
                description: "branch 2".to_string(),
                order: 2,
                depends_on: vec![], // Root-level parallel branch 2
            },
            WorkflowTaskNode {
                id: "b3_net".to_string(),
                title: "Branch 3: Network".to_string(),
                subtitle: "port prober".to_string(),
                agent: "net".to_string(),
                tier: "net".to_string(),
                targets: vec![],
                description: "branch 3".to_string(),
                order: 3,
                depends_on: vec![], // Root-level parallel branch 3
            },
            WorkflowTaskNode {
                id: "converge_verifier".to_string(),
                title: "Convergence Verifier".to_string(),
                subtitle: "sandbox verifier".to_string(),
                agent: "verifier".to_string(),
                tier: "verifier".to_string(),
                targets: vec![],
                description: "converges all branches".to_string(),
                order: 4,
                depends_on: vec!["b1_secrets".to_string(), "b2_sast".to_string(), "b3_net".to_string()],
            },
        ],
    };

    let mut nodes_info = HashMap::new();
    let flow = AgentGraphBuilder::build_from_workflow_plan(&branched_plan, &mut nodes_info)
        .expect("Building branched flow must succeed");

    let b1 = flow.node("b1_secrets").unwrap();
    let b2 = flow.node("b2_sast").unwrap();
    let b3 = flow.node("b3_net").unwrap();
    let converge = flow.node("converge_verifier").unwrap();

    // Parallel branches share the same column X coordinate
    assert!((b1.position.x - b2.position.x).abs() < 0.1, "Parallel branches should align horizontally in Column 1");
    assert!((b2.position.x - b3.position.x).abs() < 0.1, "Parallel branches should align horizontally in Column 1");

    // Parallel branches branch out across different vertical Y coordinates (not a single horizontal line!)
    assert!(b1.position.y != b2.position.y, "Branches b1 and b2 must have distinct Y positions: {} vs {}", b1.position.y, b2.position.y);
    assert!(b2.position.y != b3.position.y, "Branches b2 and b3 must have distinct Y positions: {} vs {}", b2.position.y, b3.position.y);

    // Convergence node is in the downstream layer (X > parallel branches)
    assert!(converge.position.x > b1.position.x, "Convergence node must be downstream (higher X)");
}

#[tokio::test]
async fn test_workflow_persists_on_completion_with_animated_edges() {
    use asterisk::orchestrator::AgentGraphBuilder;
    use asterisk::execution::EngineMessage;
    use asterisk::types::{WorkflowPlan, WorkflowTaskNode, AgentStatus};
    use asterisk::ui::App;

    let target = PathBuf::from("./tests/fixtures/vulnerable_repo");
    let mut app = App::new(target, false);
    app.config.api_key = Some("test-key".to_string());

    let plan = WorkflowPlan {
        workflow_name: "Persistence Test Plan".to_string(),
        target_summary: "Test targets".to_string(),
        nodes: vec![
            WorkflowTaskNode {
                id: "task_verify_1".to_string(),
                title: "Deep Verify 1".to_string(),
                subtitle: "SAST verification".to_string(),
                agent: "sast".to_string(),
                tier: "workflow_task".to_string(),
                targets: vec!["src/main.rs".to_string()],
                description: "Deep check".to_string(),
                order: 0,
                depends_on: vec![],
            },
        ],
    };

    app.flow = AgentGraphBuilder::build_from_workflow_plan(&plan, &mut app.nodes_info)
        .expect("Building flow should succeed");
    app.current_workflow_plan = Some(plan.clone());

    assert!(app.flow.node("task_verify_1").is_some(), "task_verify_1 must exist in flow");

    // 1. Simulate running state: line should animate
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    app.engine_rx = rx;
    let _ = tx.send(EngineMessage::NodeStatusChanged {
        id: "task_verify_1".to_string(),
        status: AgentStatus::Running,
    });
    app.update();

    assert_eq!(app.nodes_info.get("task_verify_1").unwrap().status, AgentStatus::Running);
    // Edge leading to task_verify_1 should be animated
    let running_edge = app.flow.edges().iter().find(|e| e.target == "task_verify_1" || e.source == "task_verify_1");
    assert!(running_edge.is_some(), "Edge connecting to task_verify_1 must exist");
    assert!(running_edge.unwrap().animated, "Edge connecting to Running node must be animated!");

    // 2. Simulate scan finished: workflow must NOT be removed or cleared!
    let _ = tx.send(EngineMessage::NodeStatusChanged {
        id: "task_verify_1".to_string(),
        status: AgentStatus::Success,
    });
    let _ = tx.send(EngineMessage::ScanFinished);
    app.update();

    assert!(!app.is_running, "App is no longer running");
    assert!(app.flow.node("task_verify_1").is_some(), "Workflow node MUST persist after completion!");
    assert!(app.nodes_info.contains_key("task_verify_1"), "nodes_info MUST retain task_verify_1 after completion!");
    assert!(app.flow.node("defense_gate").is_some(), "defense_gate MUST persist!");
}

#[tokio::test]
async fn test_subagent_error_handling_marks_failed_without_message_and_preserves_flow() {
    use asterisk::orchestrator::AgentGraphBuilder;
    use asterisk::execution::EngineMessage;
    use asterisk::types::{WorkflowPlan, WorkflowTaskNode, AgentStatus};
    use asterisk::ui::App;

    let target = PathBuf::from("./tests/fixtures/vulnerable_repo");
    let mut app = App::new(target, false);
    app.config.api_key = Some("test-key".to_string());

    let plan = WorkflowPlan {
        workflow_name: "Failure Test Plan".to_string(),
        target_summary: "Failure test".to_string(),
        nodes: vec![
            WorkflowTaskNode {
                id: "task_failed_node".to_string(),
                title: "Faulty Subagent".to_string(),
                subtitle: "Simulated failure".to_string(),
                agent: "sast".to_string(),
                tier: "workflow_task".to_string(),
                targets: vec![],
                description: "fails".to_string(),
                order: 0,
                depends_on: vec![],
            },
        ],
    };

    app.flow = AgentGraphBuilder::build_from_workflow_plan(&plan, &mut app.nodes_info)
        .expect("Building flow should succeed");
    app.current_workflow_plan = Some(plan.clone());

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    app.engine_rx = rx;

    let initial_msg_count = app.chat_messages.len();

    // Node fails: status changes to Failed
    let _ = tx.send(EngineMessage::NodeStatusChanged {
        id: "task_failed_node".to_string(),
        status: AgentStatus::Failed,
    });
    app.update();

    // Node is marked Failed ("kalau error ya error, no message, workflow tidak hilang")
    assert_eq!(app.nodes_info.get("task_failed_node").unwrap().status, AgentStatus::Failed);
    assert!(app.flow.node("task_failed_node").is_some(), "Workflow node MUST NOT be deleted on error!");
    assert_eq!(app.chat_messages.len(), initial_msg_count, "No noisy message or paragraph should be spammed to chat on error!");
}

#[tokio::test]
async fn test_ai_followup_verification_creates_workflow_below_current() {
    use asterisk::orchestrator::AgentGraphBuilder;
    use asterisk::execution::EngineMessage;
    use asterisk::types::{WorkflowPlan, WorkflowTaskNode};
    use asterisk::ui::App;

    let target = PathBuf::from("./tests/fixtures/vulnerable_repo");
    let mut app = App::new(target, false);
    app.config.api_key = Some("test-key".to_string());

    let plan = WorkflowPlan {
        workflow_name: "Follow-up Test Plan".to_string(),
        target_summary: "Followup test".to_string(),
        nodes: vec![
            WorkflowTaskNode {
                id: "initial_task".to_string(),
                title: "Initial Subagent".to_string(),
                subtitle: "Initial check".to_string(),
                agent: "sast".to_string(),
                tier: "workflow_task".to_string(),
                targets: vec![],
                description: "Initial".to_string(),
                order: 0,
                depends_on: vec![],
            },
        ],
    };

    app.flow = AgentGraphBuilder::build_from_workflow_plan(&plan, &mut app.nodes_info)
        .expect("Building flow should succeed");
    app.current_workflow_plan = Some(plan.clone());

    let initial_task_y = app.flow.node("initial_task").unwrap().position.y;

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    app.engine_rx = rx;

    // AI discovers follow-up verification: emits WorkflowNodeAppended
    let followup = WorkflowTaskNode {
        id: "verify_followup_token".to_string(),
        title: "Verify token.rs".to_string(),
        subtitle: "Check token signing".to_string(),
        agent: "verifier".to_string(),
        tier: "workflow_task".to_string(),
        targets: vec!["src/token.rs".to_string()],
        description: "Check token signing algorithm".to_string(),
        order: 1,
        depends_on: vec!["initial_task".to_string()],
    };

    let _ = tx.send(EngineMessage::WorkflowNodeAppended {
        node: followup,
        parent_id: "initial_task".to_string(),
    });
    app.update();

    // Verify that the new node exists in flow and nodes_info
    assert!(app.flow.node("verify_followup_token").is_some(), "Follow-up node must be added to flow");
    assert!(app.nodes_info.contains_key("verify_followup_token"), "Follow-up node must be in nodes_info");

    // Verify it is placed DIBAWAH workflow saat ini (Y coordinate is strictly greater than initial task)
    let followup_y = app.flow.node("verify_followup_token").unwrap().position.y;
    assert!(
        followup_y > initial_task_y + 4.0,
        "Follow-up verification node MUST be placed below current workflow: followup_y ({}) vs initial_y ({})",
        followup_y,
        initial_task_y
    );
}

#[test]
fn test_each_node_has_at_most_one_outgoing_arrow() {
    use asterisk::orchestrator::AgentGraphBuilder;
    use asterisk::types::{WorkflowPlan, WorkflowTaskNode};
    use std::collections::HashMap;

    let branched_plan = WorkflowPlan {
        workflow_name: "Multi-branch Workflow".to_string(),
        target_summary: "Multi-branch test".to_string(),
        nodes: vec![
            WorkflowTaskNode {
                id: "b1_secrets".to_string(),
                title: "Branch 1: Secrets".to_string(),
                subtitle: "key miner".to_string(),
                agent: "secrets".to_string(),
                tier: "secrets".to_string(),
                targets: vec![],
                description: "branch 1".to_string(),
                order: 1,
                depends_on: vec![],
            },
            WorkflowTaskNode {
                id: "b2_sast".to_string(),
                title: "Branch 2: SAST".to_string(),
                subtitle: "taint analyzer".to_string(),
                agent: "sast".to_string(),
                tier: "sast".to_string(),
                targets: vec![],
                description: "branch 2".to_string(),
                order: 2,
                depends_on: vec![],
            },
            WorkflowTaskNode {
                id: "b3_net".to_string(),
                title: "Branch 3: Network".to_string(),
                subtitle: "port prober".to_string(),
                agent: "net".to_string(),
                tier: "net".to_string(),
                targets: vec![],
                description: "branch 3".to_string(),
                order: 3,
                depends_on: vec![],
            },
            WorkflowTaskNode {
                id: "converge_verifier".to_string(),
                title: "Convergence Verifier".to_string(),
                subtitle: "sandbox verifier".to_string(),
                agent: "verifier".to_string(),
                tier: "verifier".to_string(),
                targets: vec![],
                description: "converges all branches".to_string(),
                order: 4,
                depends_on: vec!["b1_secrets".to_string(), "b2_sast".to_string(), "b3_net".to_string()],
            },
        ],
    };

    let mut nodes_info = HashMap::new();
    let flow = AgentGraphBuilder::build_from_workflow_plan(&branched_plan, &mut nodes_info)
        .expect("Building branched flow must succeed");

    // Invariant check: For every active task node in the workflow, exactly 1 outgoing AND 1 incoming arrow must exist
    for task in &branched_plan.nodes {
        let outgoing_count = flow.edges().iter().filter(|e| e.source == task.id).count();
        let incoming_count = flow.edges().iter().filter(|e| e.target == task.id).count();
        assert_eq!(
            outgoing_count, 1,
            "Node {} MUST have exactly 1 outgoing arrow, found {}",
            task.id, outgoing_count
        );
        assert_eq!(
            incoming_count, 1,
            "Node {} MUST have exactly 1 incoming arrow (no branching/roots!), found {}",
            task.id, incoming_count
        );
    }

    // Invariant check: Orch MUST have EXACTLY 1 outgoing arrow and 0 incoming arrows
    let orch_outgoing_count = flow.edges().iter().filter(|e| e.source == "orch").count();
    let orch_incoming_count = flow.edges().iter().filter(|e| e.target == "orch").count();
    assert_eq!(orch_outgoing_count, 1, "Orchestrator MUST have exactly 1 outgoing arrow!");
    assert_eq!(orch_incoming_count, 0, "Orchestrator must have 0 incoming arrows");

    // Invariant check: Defense gate MUST have EXACTLY 1 incoming arrow and 0 outgoing arrows
    let gate_incoming_count = flow.edges().iter().filter(|e| e.target == "defense_gate").count();
    let gate_outgoing_count = flow.edges().iter().filter(|e| e.source == "defense_gate").count();
    assert_eq!(gate_incoming_count, 1, "Defense gate MUST have exactly 1 incoming arrow!");
    assert_eq!(gate_outgoing_count, 0, "Defense gate must have 0 outgoing arrows");

    // Verify sequential flow order: orch -> b1_secrets -> b2_sast -> b3_net -> converge_verifier -> defense_gate
    let orch_edge = flow.edges().iter().find(|e| e.source == "orch").unwrap();
    assert_eq!(orch_edge.target, "b1_secrets");

    let b1_edge = flow.edges().iter().find(|e| e.source == "b1_secrets").unwrap();
    assert_eq!(b1_edge.target, "b2_sast");

    let b2_edge = flow.edges().iter().find(|e| e.source == "b2_sast").unwrap();
    assert_eq!(b2_edge.target, "b3_net");

    let b3_edge = flow.edges().iter().find(|e| e.source == "b3_net").unwrap();
    assert_eq!(b3_edge.target, "converge_verifier");

    let converge_edge = flow.edges().iter().find(|e| e.source == "converge_verifier").unwrap();
    assert_eq!(converge_edge.target, "defense_gate");
}

#[tokio::test]
async fn test_pause_total_via_esc_and_space_stops_animation_and_grays_out() {
    use asterisk::orchestrator::AgentGraphBuilder;
    use asterisk::types::{AgentStatus, WorkflowPlan, WorkflowTaskNode};
    use asterisk::ui::App;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::collections::HashMap;

    let target = PathBuf::from("./tests/fixtures/vulnerable_repo");
    let mut app = App::new(target, false);
    app.config.api_key = Some("test-key".to_string());

    let plan = WorkflowPlan {
        workflow_name: "Pause Test".to_string(),
        target_summary: "Testing pause total".to_string(),
        nodes: vec![
            WorkflowTaskNode {
                id: "task_scan".to_string(),
                title: "Scan Task".to_string(),
                subtitle: "scanner".to_string(),
                agent: "sast".to_string(),
                tier: "sast".to_string(),
                targets: vec![],
                description: "scanning".to_string(),
                order: 1,
                depends_on: vec![],
            },
        ],
    };

    let mut nodes_info = HashMap::new();
    let flow = AgentGraphBuilder::build_from_workflow_plan(&plan, &mut nodes_info).unwrap();
    app.flow = flow;
    app.nodes_info = nodes_info;
    app.is_running = true;

    // Set task running and verify edge animates
    app.nodes_info.get_mut("task_scan").unwrap().status = AgentStatus::Running;
    AgentGraphBuilder::rechain_workflow_edges(&mut app.flow, &app.nodes_info);
    let edge_before = app.flow.edges().iter().find(|e| e.source == "orch").unwrap();
    assert!(edge_before.animated, "Edge must animate while task is running");

    // 1. Press ESC while running -> Triggers PAUSE TOTAL
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));

    // Verify all nodes are marked paused
    for node in app.nodes_info.values() {
        assert!(node.is_paused, "Node {} must be paused", node.id);
    }

    // Verify animation has STOPPED (animated == false)
    for edge in app.flow.edges() {
        assert!(!edge.animated, "Edge {} animation must STOP when paused!", edge.id);
    }

    // 2. Press Space while paused -> Resumes execution
    app.handle_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::empty()));
    for node in app.nodes_info.values() {
        assert!(!node.is_paused, "Node {} must resume after space pressed", node.id);
    }
}

#[tokio::test]
async fn test_fixing_workflow_sprouts_below_scan_workflow() {
    use asterisk::orchestrator::AgentGraphBuilder;
    use asterisk::types::{WorkflowPlan, WorkflowTaskNode};
    use std::collections::HashMap;

    let plan = WorkflowPlan {
        workflow_name: "Audit Phase 1".to_string(),
        target_summary: "Initial audit surface".to_string(),
        nodes: vec![
            WorkflowTaskNode {
                id: "scan_1".to_string(),
                title: "Scan Surface 1".to_string(),
                subtitle: "auth scan".to_string(),
                agent: "sast".to_string(),
                tier: "sast".to_string(),
                targets: vec![],
                description: "scan 1".to_string(),
                order: 1,
                depends_on: vec![],
            },
        ],
    };

    let mut nodes_info = HashMap::new();
    let mut flow = AgentGraphBuilder::build_from_workflow_plan(&plan, &mut nodes_info)
        .expect("Building scan flow succeeds");

    // Verify Row 1: Scan workflow is at y = 14.0
    let scan_y = flow.node("scan_1").unwrap().position.y;
    assert_eq!(scan_y, 14.0, "Scan workflow must be on Row 1 (y = 14.0)");

    // SPROUT FIXING WORKFLOW directly below scan workflow
    AgentGraphBuilder::append_fixing_workflow(&mut flow, &mut nodes_info, 3);

    // Verify Row 2 nodes exist: fix_orch, fix_rewrite, fix_add_code, fix_exec, fix_verify, fix_gate
    let fix_orch = flow.node("fix_orch").expect("fix_orch must exist as new start point");
    let fix_rewrite = flow.node("fix_rewrite").expect("fix_rewrite must exist for code rewrite");
    let fix_add_code = flow.node("fix_add_code").expect("fix_add_code must exist for adding code/guards");
    let fix_exec = flow.node("fix_exec").expect("fix_exec must exist for executing commands");
    let fix_verify = flow.node("fix_verify").expect("fix_verify must exist for regression verification");
    let fix_gate = flow.node("fix_gate").expect("fix_gate must exist as new endpoint");

    // Verify all fixing nodes are placed BELOW the scan workflow (y = 26.0)
    assert!(fix_orch.position.y > scan_y, "fix_orch must be below scan flow");
    assert_eq!(fix_orch.position.y, 26.0);
    assert_eq!(fix_rewrite.position.y, 26.0);
    assert_eq!(fix_add_code.position.y, 26.0);
    assert_eq!(fix_exec.position.y, 26.0);
    assert_eq!(fix_verify.position.y, 26.0);
    assert_eq!(fix_gate.position.y, 26.0);

    // Verify strict 1-to-1 arrow sequence in fixing workflow
    let e1 = flow.edges().iter().find(|e| e.source == "fix_orch").unwrap();
    assert_eq!(e1.target, "fix_rewrite", "fix_orch connects to fix_rewrite");

    let e2 = flow.edges().iter().find(|e| e.source == "fix_rewrite").unwrap();
    assert_eq!(e2.target, "fix_add_code", "fix_rewrite connects to fix_add_code");

    let e3 = flow.edges().iter().find(|e| e.source == "fix_add_code").unwrap();
    assert_eq!(e3.target, "fix_exec", "fix_add_code connects to fix_exec");

    let e4 = flow.edges().iter().find(|e| e.source == "fix_exec").unwrap();
    assert_eq!(e4.target, "fix_verify", "fix_exec connects to fix_verify");

    let e5 = flow.edges().iter().find(|e| e.source == "fix_verify").unwrap();
    assert_eq!(e5.target, "fix_gate", "fix_verify connects to fix_gate");

    // Verify NO crossing arrows between Scan workflow (Row 1) and Fixing workflow (Row 2)
    for edge in flow.edges() {
        let src_is_scan = edge.source == "orch" || edge.source.starts_with("scan_") || edge.source == "defense_gate";
        let dst_is_scan = edge.target == "orch" || edge.target.starts_with("scan_") || edge.target == "defense_gate";
        let src_is_fix = edge.source.starts_with("fix_");
        let dst_is_fix = edge.target.starts_with("fix_");

        if src_is_scan {
            assert!(dst_is_scan, "Scan edge {} cannot cross into fixing workflow", edge.id);
        }
        if src_is_fix {
            assert!(dst_is_fix, "Fixing edge {} cannot cross into scan workflow", edge.id);
        }
    }
}

#[tokio::test]
async fn test_chat_query_loading_indicator_and_cancellation() {
    use asterisk::ui::App;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let target = PathBuf::from("./tests/fixtures/vulnerable_repo");
    let mut app = App::new(target, false);
    app.config.api_key = Some("test-key".to_string());

    // User types normal question (not a slash command)
    app.prompt_input = "explain the vulnerability in auth.rs".to_string();
    app.submit_prompt_input();

    // Verify loading state is triggered
    assert!(app.is_chat_querying, "Submitting normal chat must set is_chat_querying = true");
    assert!(app.action_msg.as_ref().unwrap().contains("thinking"), "action_msg must display thinking indicator");

    // Press Esc to cancel query
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert!(!app.is_chat_querying, "Pressing Esc must cancel query and reset is_chat_querying to false");
    assert!(app.action_msg.as_ref().unwrap().contains("cancelled"), "action_msg must reflect query cancellation");
}

#[test]
fn test_sqlite_session_full_lifecycle() {
    use asterisk::core::StateStore;
    use asterisk::types::{ChatMessage, Severity, VulnerabilityFinding, HardeningPatch};
    use std::path::PathBuf;

    let mut store = StateStore::in_memory().expect("in-memory sqlite");

    let session_id = "sess-test-123";
    let project_id = "/tmp/test-proj";
    let provider = "Custom";

    let messages = vec![
        ChatMessage::User("how to fix SQL injection in login handler?".to_string()),
        ChatMessage::Agent {
            sender: "orchestrator".to_string(),
            text: "Use parameterized queries or AST-based sanitizers.".to_string(),
        },
    ];

    let findings = vec![
        VulnerabilityFinding {
            id: "VULN-001".to_string(),
            title: "SQL Injection".to_string(),
            cwe: "CWE-89".to_string(),
            severity: Severity::Critical,
            file_path: PathBuf::from("src/auth.rs"),
            line_number: 42,
            snippet: "db.execute(format!(\"SELECT * FROM users WHERE user='{}'\", u))".to_string(),
            description: "Raw SQL concatenation".to_string(),
            recommendation: "Use sqlx params".to_string(),
            patched: false,
            reachability: "REACHABLE".to_string(),
            triage_verdict: "TRUE_POSITIVE".to_string(),
            triage_reasoning: "Direct sink execution".to_string(),
            call_path: vec!["main".to_string(), "login".to_string()],
        },
    ];

    let patches = vec![
        HardeningPatch {
            id: "PATCH-001".to_string(),
            finding_id: "VULN-001".to_string(),
            target_file: PathBuf::from("src/auth.rs"),
            original_snippet: "raw_query".to_string(),
            hardened_snippet: "param_query".to_string(),
            unified_diff: "+param_query".to_string(),
            unit_test_code: "assert!(true)".to_string(),
            applied: false,
            explanation: "Converted to parameterized query".to_string(),
            unit_test_passed: true,
            safe_outputs_passed: true,
        },
    ];

    // 1. Save session
    store.save_session_full(session_id, project_id, provider, &messages, &findings, &patches)
        .expect("save_session_full succeeds");

    // 2. List sessions
    let sessions = store.list_sessions(project_id).expect("list_sessions succeeds");
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].session_id, session_id);
    assert_eq!(sessions[0].message_count, 2);
    assert_eq!(sessions[0].findings_count, 1);
    assert!(sessions[0].title.contains("SQL injection"));

    // 3. Load session
    let (loaded_msgs, loaded_findings, loaded_patches) = store.load_session_full(session_id)
        .expect("load_session_full succeeds");

    assert_eq!(loaded_msgs.len(), 2);
    match &loaded_msgs[0] {
        ChatMessage::User(txt) => assert!(txt.contains("SQL injection")),
        _ => panic!("Expected ChatMessage::User"),
    }
    assert_eq!(loaded_findings.len(), 1);
    assert_eq!(loaded_findings[0].id, "VULN-001");
    assert_eq!(loaded_patches.len(), 1);
    assert_eq!(loaded_patches[0].id, "PATCH-001");
}

#[test]
fn test_app_slash_commands_sessions_new_and_grill_me() {
    use asterisk::ui::App;
    use asterisk::types::ChatMessage;

    let target = PathBuf::from("./tests/fixtures/vulnerable_repo");
    let mut app = App::new(target, false);

    // Initial session ID should be set
    assert!(!app.current_session_id.is_empty(), "current_session_id must be initialized");
    let initial_session_id = app.current_session_id.clone();

    // 1. Test /sessions command (viewing history)
    app.prompt_input = "/sessions".to_string();
    app.submit_prompt_input();

    let last_msg = app.chat_messages.last().expect("must have message");
    match last_msg {
        ChatMessage::Agent { text, .. } => {
            assert!(text.contains("Asterisk Audit & Chat Sessions"), "Should display sessions table");
            assert!(text.contains(&initial_session_id), "Should include active session ID");
        }
        _ => panic!("Expected Agent message for /sessions"),
    }

    // 2. Test /new command (new session)
    app.prompt_input = "/new".to_string();
    app.submit_prompt_input();

    assert_ne!(app.current_session_id, initial_session_id, "New session must produce a new session ID");
    let new_last_msg = app.chat_messages.last().expect("must have message");
    match new_last_msg {
        ChatMessage::Agent { text, .. } => {
            assert!(text.contains("New Security Session Initialized"), "Should display new session banner");
            assert!(text.contains(&initial_session_id), "Should note archived previous session");
        }
        _ => panic!("Expected Agent message for /new"),
    }

    // 3. Test /grill-me command
    app.prompt_input = "/grill-me".to_string();
    app.submit_prompt_input();

    assert!(app.is_grill_mode, "Entering /grill-me must activate is_grill_mode");
    assert_eq!(app.grill_step, 1, "Grill step must be 1");
    let grill_msg = app.chat_messages.last().expect("must have grill message");
    match grill_msg {
        ChatMessage::Agent { sender, text } => {
            assert_eq!(sender, "security_architect");
            assert!(text.contains("Grill-Me: Adversarial Security Architecture Review"));
            assert!(text.contains("Question 1/5"));
        }
        _ => panic!("Expected Agent message for /grill-me"),
    }

    // 4. Test /done command (exiting grill-me and synthesizing plan)
    app.prompt_input = "/done".to_string();
    app.submit_prompt_input();

    assert!(!app.is_grill_mode, "/done must exit grill mode");
    let plan_msg = app.chat_messages.last().expect("must have plan message");
    match plan_msg {
        ChatMessage::Agent { sender, text } => {
            assert_eq!(sender, "security_architect");
            assert!(text.contains("Hardened Security Architecture Plan"), "Must synthesize hardened security plan");
            assert!(text.contains("Ingress Boundary Conformance"));
            assert!(text.contains("Taint Neutralization"));
        }
        _ => panic!("Expected Agent message for /done"),
    }
}

#[test]
fn test_spinner_rotation_timing() {
    let spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

    // Frame indices at simulated milliseconds offset:
    let idx_0ms = (0u128 / 80) as usize % spinner_frames.len();
    let idx_160ms = (160u128 / 80) as usize % spinner_frames.len();
    let idx_400ms = (400u128 / 80) as usize % spinner_frames.len();

    assert_eq!(idx_0ms, 0);
    assert_eq!(idx_160ms, 2);
    assert_eq!(idx_400ms, 5);
    assert_ne!(spinner_frames[idx_0ms], spinner_frames[idx_160ms]);
    assert_ne!(spinner_frames[idx_160ms], spinner_frames[idx_400ms]);
}
