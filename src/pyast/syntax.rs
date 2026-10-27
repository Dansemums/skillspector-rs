//! Syntax errors CPython's parser reports that rustpython-parser 0.4 accepts. Each check is a
//! post-parse walk; add one only when the differential test (`tests/pyast_diff.rs`) finds a gap.

use super::walk::{Node, walk};
use rustpython_parser::ast::{Expr, Pattern, Ranged, Stmt};

/// Valid assignment target (`for` / `with` / comprehension / `=`): names, attributes, subscripts,
/// and (starred) tuples or lists of those.
fn store_target(e: &Expr) -> bool {
    match e {
        Expr::Name(_) | Expr::Attribute(_) | Expr::Subscript(_) => true,
        Expr::Starred(s) => store_target(&s.value),
        Expr::Tuple(t) => t.elts.iter().all(store_target),
        Expr::List(l) => l.elts.iter().all(store_target),
        _ => false,
    }
}

fn del_target(e: &Expr) -> bool {
    match e {
        Expr::Name(_) | Expr::Attribute(_) | Expr::Subscript(_) => true,
        Expr::Tuple(t) => t.elts.iter().all(del_target),
        Expr::List(l) => l.elts.iter().all(del_target),
        _ => false,
    }
}

/// Targets of augmented and annotated assignment: a single name, attribute or subscript.
fn simple_target(e: &Expr) -> bool {
    matches!(e, Expr::Name(_) | Expr::Attribute(_) | Expr::Subscript(_))
}

fn is_star(p: &Pattern) -> bool {
    matches!(p, Pattern::MatchStar(_))
}

/// `*name` is only valid directly inside a sequence pattern.
fn misplaced_star(p: &Pattern) -> bool {
    match p {
        Pattern::MatchAs(a) => a.pattern.as_deref().is_some_and(is_star),
        Pattern::MatchOr(o) => o.patterns.iter().any(is_star),
        Pattern::MatchClass(c) => c.patterns.iter().chain(&c.kwd_patterns).any(is_star),
        Pattern::MatchMapping(m) => m.patterns.iter().any(is_star),
        _ => false,
    }
}

/// An unparenthesized generator expression next to other arguments, or among class bases.
fn bare_genexp(content: &str, e: &Expr, alone: bool) -> bool {
    matches!(e, Expr::GeneratorExp(_))
        && !alone
        && !content
            .get(usize::from(e.range().start())..)
            .is_some_and(|rest| rest.starts_with('('))
}

/// True when the tree contains something CPython's parser rejects but rustpython accepts: an invalid
/// assignment, `del`, `for`, `with` or `:=` target, a misplaced `*` pattern, or an unparenthesized
/// generator expression argument.
#[must_use]
pub fn has_invalid_target(body: &[Stmt], content: &str) -> bool {
    let mut bad = false;
    walk(body, |node| {
        bad = bad
            || match node {
                Node::Stmt(Stmt::Assign(a)) => !a.targets.iter().all(store_target),
                Node::Stmt(Stmt::AugAssign(a)) => !simple_target(&a.target),
                Node::Stmt(Stmt::AnnAssign(a)) => !simple_target(&a.target),
                Node::Stmt(Stmt::Delete(d)) => !d.targets.iter().all(del_target),
                Node::Stmt(Stmt::For(f)) => !store_target(&f.target),
                Node::Stmt(Stmt::AsyncFor(f)) => !store_target(&f.target),
                Node::Stmt(Stmt::ClassDef(c)) => {
                    c.bases.iter().any(|b| bare_genexp(content, b, false))
                }
                Node::WithItem(w) => w.optional_vars.as_deref().is_some_and(|v| !store_target(v)),
                Node::Comprehension(c) => !store_target(&c.target),
                Node::MatchCase(m) => is_star(&m.pattern),
                Node::Pattern(p) => misplaced_star(p),
                Node::Expr(Expr::NamedExpr(n)) => !matches!(&*n.target, Expr::Name(_)),
                Node::Expr(Expr::Call(c)) => {
                    let alone = c.args.len() + c.keywords.len() == 1;
                    c.args.iter().any(|a| bare_genexp(content, a, alone))
                }
                _ => false,
            };
    });
    bad
}
