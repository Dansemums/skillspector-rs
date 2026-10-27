//! Lexical half of the variable `shell=<name>` rule: `_variable_shell_matches` and its helpers.
//!
//! The AST reconciliation of these windows (`_build_variable_shell_ast_index`,
//! `_reconcile_variable_shell_findings`, `_lexical_shell_has_counterevidence`) needs the Python
//! AST layer and lives behind [`reconcile_with_ast`].

use super::patterns::{
    SHELL_NAME_ARGUMENT_RE, VARIABLE_ASSIGNMENT_RE, VARIABLE_FLAG_RE, VARIABLE_FLAG_TAIL_RE,
};
use crate::finding::RawFinding;
use crate::matcher::{Hit, Pat};
use crate::pyast::PyFile;
use std::collections::BTreeMap;
use std::sync::LazyLock;

/// One bounded window: an assignment of `True` to `name`, then a call using `shell=name`.
#[derive(Debug, Clone)]
pub struct VariableWindow {
    pub start: usize,
    pub end: usize,
    pub name: String,
    pub text: String,
}

static CALLEE: LazyLock<Pat> = LazyLock::new(|| Pat::new(r"(?:subprocess\.\w+|Popen)\s*\(", "i"));

/// `_is_true_prefixed_name`.
pub fn is_true_prefixed_name(name: &str) -> bool {
    crate::unicode::casefold(name).starts_with("true")
}

/// `_variable_shell_call_start`: the final call the window reaches.
pub fn call_start(window: &VariableWindow) -> Option<usize> {
    CALLEE
        .find_iter(&window.text)
        .last()
        .map(|h| window.start + h.start)
}

fn window(content: &str, hit: &Hit) -> VariableWindow {
    VariableWindow {
        start: hit.start,
        end: hit.end,
        name: hit.group(content, 1).unwrap_or_default().to_owned(),
        text: hit.text(content).to_owned(),
    }
}

/// `_variable_shell_matches`: one window per call, nearest assignment wins.
pub fn variable_shell_matches(content: &str) -> Vec<VariableWindow> {
    let mut windows: BTreeMap<usize, VariableWindow> = BTreeMap::new();
    let mut keep = |w: VariableWindow| {
        let better = windows.get(&w.end).is_none_or(|p| w.start > p.start);
        if better {
            windows.insert(w.end, w);
        }
    };
    for hit in VARIABLE_FLAG_RE.find_iter(content) {
        keep(window(content, &hit));
    }
    for assignment in VARIABLE_ASSIGNMENT_RE.find_iter(content) {
        let name = assignment.group(content, 1).unwrap_or_default();
        if !is_true_prefixed_name(name) {
            continue;
        }
        let mut search_end = assignment.end - 1;
        for _ in 0..5 {
            match content[(search_end + 1).min(content.len())..].find('\n') {
                Some(i) => search_end = search_end + 1 + i,
                None => {
                    search_end = content.len();
                    break;
                }
            }
        }
        for argument in SHELL_NAME_ARGUMENT_RE.find_in(content, assignment.end, search_end) {
            let tail = VARIABLE_FLAG_TAIL_RE.find_in(content, assignment.start, argument.end);
            if let Some(full) = tail
                .first()
                .filter(|h| h.start == assignment.start && h.end == argument.end)
            {
                keep(window(content, full));
            }
        }
    }
    let mut out: Vec<VariableWindow> = windows.into_values().collect();
    out.sort_by_key(|w| (w.start, w.end));
    out
}

/// TODO(pyast): `_reconcile_variable_shell_findings` + the `invisible_variable_matches` filter of
/// `analyze`. They resolve each window to its assignment/call through the Python AST, drop windows
/// whose binding is not visible or was replaced, and swap in the shell-truthiness owner's finding.
/// Without a parse tree Python keeps the lexical findings unchanged, which is what this does.
#[must_use]
pub fn reconcile_with_ast(findings: Vec<RawFinding>, _py: Option<&PyFile>) -> Vec<RawFinding> {
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_window() {
        let src = "flag = True\nsubprocess.run(cmd, shell=flag)\n";
        let w = variable_shell_matches(src);
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].name, "flag");
        assert_eq!(call_start(&w[0]), Some(12));
    }

    #[test]
    fn true_prefixed_names_pair_each_call() {
        let src =
            "true_x = True\nsubprocess.run(a, shell=true_x)\nsubprocess.run(b, shell=true_x)\n";
        assert_eq!(variable_shell_matches(src).len(), 2);
    }

    #[test]
    fn unrelated_assignment_is_ignored() {
        assert!(variable_shell_matches("x = False\nsubprocess.run(c, shell=x)\n").is_empty());
    }
}
