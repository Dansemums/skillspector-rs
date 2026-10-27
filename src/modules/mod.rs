//! Ported detector modules, one per SkillSpector analyzer.

pub mod agent_snooping;
pub mod anti_refusal;
pub mod artifact_integrity;
pub mod behavioral_ast;
mod common;
pub mod concealed_executable;
pub mod coverage;
mod coverage_refs;
pub mod data_exfiltration;
pub mod declared_marker;
mod declared_marker_re;
pub mod excessive_agency;
pub mod least_privilege;
pub mod memory_guards;
pub mod memory_poisoning;
pub mod model_selection;
pub mod oh_js;
pub mod output_handling;
pub mod pe_context;
#[cfg(test)]
mod pe_tests;
pub mod pe_token;
pub mod privilege_escalation;
pub mod prompt_hidden;
pub mod prompt_injection;
mod py_shlex;
mod python_comments;
pub mod rogue_agent;
mod rogue_agent_ctx;
pub mod rug_pull;
pub mod ssrf;
pub mod supply_chain;
mod supply_chain_sc2;
mod supply_chain_sc3;
#[cfg(test)]
mod supply_chain_tests;
pub mod support;
pub mod system_prompt_leakage;
pub mod taint;
pub mod tool_misuse;
#[cfg(feature = "yara")]
pub mod yara;
