pub mod agent;
pub mod config;
pub mod git_secrets;
pub mod graph;
pub mod jail;
pub mod policy;
pub mod rig_tools;
pub mod sandbox;
pub mod sca;

pub use agent::SecurityAgentHub;
pub use config::AppConfig;
pub use git_secrets::GitHistorySecretMiner;
pub use graph::{CodeContextGraph, CodeNode, EdgeKind, NodeKind, ReachabilityVerdict};
pub use jail::ProjectJail;
pub use policy::{GateDecision, PolicyGate};
pub use sandbox::WorktreeSandbox;
pub use sca::ScaDependencyAuditor;
