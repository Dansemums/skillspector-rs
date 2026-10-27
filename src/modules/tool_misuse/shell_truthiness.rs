//! `static_python_shell_truthiness.py` (AST). Placeholder until pyast lands.
use crate::finding::RawFinding;
use crate::pyast::PyFile;
use crate::runner::StaticModule;
use crate::skill::FileType;

/// The shell-truthiness AST module.
pub struct ShellTruthiness;

impl StaticModule for ShellTruthiness {
    fn id(&self) -> &'static str {
        "static_python_shell_truthiness"
    }
    fn uses_python_ast(&self) -> bool {
        true
    }
    fn analyze(&self, _t: &str, _p: &str, _ft: FileType, _py: Option<&PyFile>) -> Vec<RawFinding> {
        // TODO(pyast)
        Vec::new()
    }
}
