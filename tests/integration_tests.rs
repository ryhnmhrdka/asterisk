use constellation::orchestrator::{AgentGraphBuilder, StrategyPlanner, WorkspaceScanner};
use constellation::skills::SkillRegistry;
use constellation::subagents::{
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
    assert!(test_suite.contains("AUTONOMOUS DEFENSE HARNESS: SECURITY VERIFICATION TEST SUITE"));

    // 9. Test Interactive Skills Registry
    let mut skills = SkillRegistry::new();
    assert_eq!(skills.skills.len(), 6);
    skills.record_invocation("skill-entropy");
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
