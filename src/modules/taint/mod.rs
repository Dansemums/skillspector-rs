//! TT1-TT6 from `nodes/analyzers/behavioral_taint_tracking.py`: sources -> sinks data flow over
//! Python's lexical scopes, crossing direct calls to functions and methods defined in the file.
//!
//! The budget, ledger and runtime-limit machinery of the Python node is not ported.

mod graph;
mod nodes;
mod rules;
mod scope;
mod scope_build;
#[cfg(test)]
mod tests;

use crate::finding::RawFinding;
use crate::pyast::ast::{Expr, ExprCall};
use crate::pyast::names::{build_type_map, get_complete_source_segment, resolve_call_name_typed};
use crate::pyast::{Node, PyFile};
use crate::runner::StaticModule;
use crate::skill::FileType;
use graph::{TaintGraph, TaintedVar};
use nodes::{eid, walk_from};
use rules::{
    TAG, is_open_for_write, is_sink, pick_rule, resolve_sink_name, rule_confidence, rule_severity,
    shorten, sink_category, source_category, source_name,
};
use scope::{CallRef, attr_ref, call_ref, nm};
use scope_build::build_scope_index;
use std::collections::{HashMap, HashSet};

pub struct Taint;

impl StaticModule for Taint {
    fn id(&self) -> &'static str {
        "behavioral_taint_tracking"
    }

    fn uses_python_ast(&self) -> bool {
        true
    }

    fn analyze(
        &self,
        _text: &str,
        path: &str,
        _ft: FileType,
        py: Option<&PyFile>,
    ) -> Vec<RawFinding> {
        py.map(|p| analyze_python(p, path)).unwrap_or_default()
    }
}

/// `_find_nested_sources`: source calls nested inside a sink call.
fn find_nested_sources<'a>(
    node: &'a Expr,
    type_map: &HashMap<String, String>,
    aliases: &crate::pyast::names::Aliases,
) -> Vec<(String, &'a ExprCall)> {
    let mut results = Vec::new();
    walk_from(Node::Expr(node), |child| {
        if let Node::Expr(e) = child
            && eid(e) != eid(node)
            && let Expr::Call(c) = e
            && let Some(name) = resolve_call_name_typed(c, Some(type_map), Some(aliases))
            && rules::is_source(&name)
        {
            results.push((name, c));
        }
    });
    results
}

/// `_spelling`: how a sink spells what it reads.
fn spelling(node: &Expr) -> String {
    let id = |e: &Expr| match e {
        Expr::Name(n) => Some(shorten(&nm(n.id.as_str()))),
        _ => None,
    };
    match node {
        Expr::Name(_) => id(node).unwrap_or_default(),
        Expr::Attribute(a) => match id(&a.value) {
            Some(v) => shorten(&format!("{v}.{}", shorten(&nm(a.attr.as_str())))),
            None => "<lambda>()".to_owned(),
        },
        Expr::Call(c) => match &*c.func {
            f @ Expr::Name(_) => shorten(&format!("{}()", id(f).unwrap_or_default())),
            Expr::Attribute(a) => match &*a.value {
                v @ Expr::Name(_) => shorten(&format!(
                    "{}.{}()",
                    id(v).unwrap_or_default(),
                    shorten(&nm(a.attr.as_str()))
                )),
                Expr::Call(inner) => match &*inner.func {
                    f @ Expr::Name(_) => shorten(&format!(
                        "{}().{}()",
                        id(f).unwrap_or_default(),
                        shorten(&nm(a.attr.as_str()))
                    )),
                    _ => "<lambda>()".to_owned(),
                },
                _ => "<lambda>()".to_owned(),
            },
            _ => "<lambda>()".to_owned(),
        },
        _ => "<lambda>()".to_owned(),
    }
}

/// `_find_tainted_names_in_args`: tainted variables, `self.x` attributes and helper results a sink reads.
fn find_tainted_names_in_args<'a>(
    node: &'a Expr,
    graph: &mut TaintGraph<'a>,
    sink_name: &str,
) -> Vec<TaintedVar> {
    let lane = TaintGraph::sink_lane(sink_name);
    let mut seen: HashSet<usize> = HashSet::new();
    let (mut names, mut new_names, mut others) = (Vec::new(), Vec::new(), Vec::new());
    let mut children: Vec<&'a Expr> = Vec::new();
    walk_from(Node::Expr(node), |c| {
        if let Node::Expr(e) = c
            && eid(e) != eid(node)
        {
            children.push(e);
        }
    });
    for child in children {
        // (key, spelled node, bucket: 0 names, 1 new names, 2 others)
        let mut reads: Vec<(Option<usize>, &Expr, u8)> = Vec::new();
        let read = match child {
            Expr::Name(_) => Some(child),
            Expr::Subscript(s) if matches!(&*s.value, Expr::Name(_)) => Some(&*s.value),
            _ => None,
        };
        if let Some(read) = read {
            let key = graph
                .index
                .class_read_views
                .get(&eid(read))
                .or_else(|| graph.index.name_key.get(&eid(read)))
                .copied();
            let bucket = if key.is_some_and(|k| graph.phase_a_keys.contains(&k)) {
                0
            } else {
                1
            };
            reads.push((key, read, bucket));
        } else if let Some(a) = attr_ref(child) {
            reads.push((graph.index.views.get(&a.id).copied(), child, 2));
        } else if let Some(cr) = call_ref(child) {
            let targets = graph.index.call_targets(cr);
            for g in &targets.results {
                reads.push((graph.returns.get(g).copied(), child, 2));
            }
        }
        for (key, spelled, bucket) in reads {
            let Some(key) = key else { continue };
            if seen.contains(&key) {
                continue;
            }
            let Some((source, line)) = graph.cited(key, sink_name, lane) else {
                continue;
            };
            seen.insert(key);
            let var = TaintedVar {
                name: spelling(spelled),
                source_call: source_name(source),
                lineno: line,
            };
            match bucket {
                0 => names.push(var),
                1 => new_names.push(var),
                _ => others.push(var),
            }
        }
    }
    names.extend(new_names);
    names.extend(others);
    names
}

struct Emitter<'a> {
    pf: &'a PyFile,
    path: &'a str,
    seen: HashSet<(&'static str, usize)>,
    findings: Vec<RawFinding>,
    node_index: usize,
}

impl Emitter<'_> {
    /// `_emit`: one finding per (rule, sink call).
    fn emit(&mut self, rule: &'static str, call: CallRef<'_>, message: String) {
        if !self.seen.insert((rule, call.id)) {
            return;
        }
        use crate::pyast::ast::Ranged;
        let pos = self.pf.char_pos(call.call.range());
        let complete = match self.pf.node_segment(call.call) {
            Some(s) => s.to_owned(),
            None => get_complete_source_segment(&self.pf.lines, pos.line, Some(pos.end_line)),
        };
        let mut f = RawFinding::new(
            rule,
            message,
            rule_severity(rule),
            rule_confidence(rule),
            self.path,
            pos.line,
        );
        f.end_line = Some(pos.end_line);
        f.start_column = pos.col;
        f.end_column = pos.end_col;
        f.tags = vec![TAG.to_owned()];
        f.matched_text = Some(complete.chars().take(200).collect());
        f.fingerprint_text = Some(complete);
        if pos.col.is_none() || pos.end_col.is_none() {
            f.evidence.insert(
                "python_ast_node_index".to_owned(),
                self.node_index.to_string(),
            );
        }
        self.findings.push(f);
    }
}

/// `_analyze_python`.
fn analyze_python(pf: &PyFile, path: &str) -> Vec<RawFinding> {
    let Some(tree) = pf.tree.as_deref() else {
        return Vec::new();
    };
    let aliases = &pf.import_aliases;
    let type_map = build_type_map(tree, Some(aliases));
    let mut graph = TaintGraph::new(build_scope_index(tree), &type_map, aliases, pf);
    graph.run();
    let mut out = Emitter {
        pf,
        path,
        seen: HashSet::new(),
        findings: Vec::new(),
        node_index: 0,
    };
    let mut calls: Vec<&Expr> = Vec::new();
    crate::pyast::walk(tree, |n| {
        if let Node::Expr(e @ Expr::Call(_)) = n {
            calls.push(e);
        }
    });
    for e in calls {
        let Some(cr) = call_ref(e) else { continue };
        let Some(sink) = resolve_sink_name(cr.call, &type_map, aliases) else {
            continue;
        };
        if !is_sink(&sink) || (sink == "open" && !is_open_for_write(cr.call)) {
            continue;
        }
        for (src, src_call) in find_nested_sources(e, &type_map, aliases) {
            if src == "open" && is_open_for_write(src_call) {
                continue;
            }
            let rule = pick_rule(&src, &sink, true);
            let msg = format!(
                "Direct flow: {src} ({}) \u{2192} {sink} ({})",
                source_category(&src),
                sink_category(&sink)
            );
            out.emit(rule, cr, msg);
        }
        for tv in find_tainted_names_in_args(e, &mut graph, &sink) {
            let rule = pick_rule(tv.source_call, &sink, false);
            let msg = format!(
                "Tainted flow: '{}' from {} (line {}, {}) \u{2192} {sink} ({})",
                tv.name,
                tv.source_call,
                tv.lineno,
                source_category(tv.source_call),
                sink_category(&sink)
            );
            out.emit(rule, cr, msg);
        }
    }
    out.findings
}

/// Readable-name taint of a whole file, for tests (`_collect_tainted`).
#[cfg(test)]
pub(crate) fn collect_tainted(pf: &PyFile) -> Vec<(String, TaintedVar)> {
    let Some(tree) = pf.tree.as_deref() else {
        return Vec::new();
    };
    let type_map = build_type_map(tree, Some(&pf.import_aliases));
    let mut graph = TaintGraph::new(build_scope_index(tree), &type_map, &pf.import_aliases, pf);
    graph.run();
    graph.tainted_names()
}
