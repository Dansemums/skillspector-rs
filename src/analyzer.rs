//! The detectors: whole-skill analyzers and static pattern modules.

use crate::finding::RawFinding;
use crate::modules::agent_snooping::AgentSnoopingAnalyzer;
use crate::modules::anti_refusal::AntiRefusal;
use crate::modules::behavioral_ast::BehavioralAst;
use crate::modules::concealed_executable::ConcealedExecutable;
use crate::modules::data_exfiltration::DataExfiltration;
use crate::modules::memory_poisoning::MemoryPoisoning;
use crate::modules::output_handling::OutputHandling;
use crate::modules::privilege_escalation::PrivilegeEscalation;
use crate::modules::prompt_injection::PromptInjection;
use crate::modules::rogue_agent::RogueAgent;
use crate::modules::rug_pull::RugPull;
use crate::modules::ssrf::Ssrf;
use crate::modules::supply_chain::SupplyChain;
use crate::modules::system_prompt_leakage::SystemPromptLeakage;
use crate::runner::StaticModule;
use crate::skill::Skill;

/// A detector that sees the whole skill (manifest included) and returns raw findings.
pub trait Analyzer: Sync {
    /// SkillSpector's `ANALYZER_ID`, e.g. `mcp_rug_pull`.
    #[allow(dead_code)] // part of the trait for parity with SkillSpector's ANALYZER_ID
    fn id(&self) -> &'static str;

    /// Findings for `skill`, in any order.
    fn run(&self, skill: &Skill) -> Vec<RawFinding>;
}

/// Whole-skill analyzers ported so far.
#[must_use]
pub fn registry() -> Vec<Box<dyn Analyzer>> {
    // AgentSnooping needs the skill identity, so it is a whole-skill analyzer that runs the static runner.
    vec![
        Box::new(RugPull),
        Box::new(AgentSnoopingAnalyzer),
        Box::new(ConcealedExecutable),
        Box::new(crate::modules::coverage::ReferenceCoverage),
        Box::new(crate::modules::artifact_integrity::ArtifactIntegrity),
        Box::new(crate::modules::least_privilege::LeastPrivilege),
        #[cfg(feature = "yara")]
        Box::new(crate::modules::yara::Yara),
    ]
}

/// Static pattern modules ported so far; they run through [`crate::runner::run_static`].
#[must_use]
pub fn static_modules() -> Vec<Box<dyn StaticModule>> {
    vec![
        Box::new(crate::modules::excessive_agency::ExcessiveAgency),
        Box::new(RogueAgent),
        Box::new(AntiRefusal),
        Box::new(PrivilegeEscalation),
        Box::new(PromptInjection),
        Box::new(MemoryPoisoning),
        Box::new(SystemPromptLeakage),
        Box::new(Ssrf),
        Box::new(DataExfiltration),
        Box::new(BehavioralAst),
        Box::new(crate::modules::taint::Taint),
        Box::new(OutputHandling),
        Box::new(SupplyChain),
        Box::new(crate::modules::tool_misuse::ToolMisuse),
        Box::new(crate::modules::tool_misuse::ShellTruthiness),
    ]
}
