//! Child enumeration (`ast.iter_child_nodes`) for one node, and node identity.
//!
//! The child-order table is a copy of `pyast/walk.rs`'s private `children` (CPython field order);
//! the shared file only exposes whole-tree walks, and the taint scope builder needs per-node
//! children (patch idea: make `walk::children` public and delete this copy).

use crate::pyast::Node;
use rustpython_parser::ast::{
    Arguments, Comprehension, ExceptHandler, Expr, Pattern, Stmt, TypeParam,
};
use std::collections::VecDeque;

type Q<'a> = VecDeque<Node<'a>>;

fn exprs<'a>(q: &mut Q<'a>, v: &'a [Expr]) {
    q.extend(v.iter().map(Node::Expr));
}
fn stmts<'a>(q: &mut Q<'a>, v: &'a [Stmt]) {
    q.extend(v.iter().map(Node::Stmt));
}
fn opt<'a>(q: &mut Q<'a>, e: Option<&'a Expr>) {
    q.extend(e.map(Node::Expr));
}
fn pats<'a>(q: &mut Q<'a>, v: &'a [Pattern]) {
    q.extend(v.iter().map(Node::Pattern));
}
fn one<'a>(q: &mut Q<'a>, e: &'a Expr) {
    q.push_back(Node::Expr(e));
}

fn stmt_children<'a>(q: &mut Q<'a>, s: &'a Stmt) {
    match s {
        Stmt::FunctionDef(n) => {
            q.push_back(Node::Arguments(&n.args));
            stmts(q, &n.body);
            exprs(q, &n.decorator_list);
            opt(q, n.returns.as_deref());
            q.extend(n.type_params.iter().map(Node::TypeParam));
        }
        Stmt::AsyncFunctionDef(n) => {
            q.push_back(Node::Arguments(&n.args));
            stmts(q, &n.body);
            exprs(q, &n.decorator_list);
            opt(q, n.returns.as_deref());
            q.extend(n.type_params.iter().map(Node::TypeParam));
        }
        Stmt::ClassDef(n) => {
            exprs(q, &n.bases);
            q.extend(n.keywords.iter().map(Node::Keyword));
            stmts(q, &n.body);
            exprs(q, &n.decorator_list);
            q.extend(n.type_params.iter().map(Node::TypeParam));
        }
        Stmt::Return(n) => opt(q, n.value.as_deref()),
        Stmt::Delete(n) => exprs(q, &n.targets),
        Stmt::Assign(n) => {
            exprs(q, &n.targets);
            one(q, &n.value);
        }
        Stmt::TypeAlias(n) => {
            one(q, &n.name);
            q.extend(n.type_params.iter().map(Node::TypeParam));
            one(q, &n.value);
        }
        Stmt::AugAssign(n) => {
            one(q, &n.target);
            one(q, &n.value);
        }
        Stmt::AnnAssign(n) => {
            one(q, &n.target);
            one(q, &n.annotation);
            opt(q, n.value.as_deref());
        }
        Stmt::For(n) => {
            one(q, &n.target);
            one(q, &n.iter);
            stmts(q, &n.body);
            stmts(q, &n.orelse);
        }
        Stmt::AsyncFor(n) => {
            one(q, &n.target);
            one(q, &n.iter);
            stmts(q, &n.body);
            stmts(q, &n.orelse);
        }
        Stmt::While(n) => {
            one(q, &n.test);
            stmts(q, &n.body);
            stmts(q, &n.orelse);
        }
        Stmt::If(n) => {
            one(q, &n.test);
            stmts(q, &n.body);
            stmts(q, &n.orelse);
        }
        Stmt::With(n) => {
            q.extend(n.items.iter().map(Node::WithItem));
            stmts(q, &n.body);
        }
        Stmt::AsyncWith(n) => {
            q.extend(n.items.iter().map(Node::WithItem));
            stmts(q, &n.body);
        }
        Stmt::Match(n) => {
            one(q, &n.subject);
            q.extend(n.cases.iter().map(Node::MatchCase));
        }
        Stmt::Raise(n) => {
            opt(q, n.exc.as_deref());
            opt(q, n.cause.as_deref());
        }
        Stmt::Try(n) => {
            stmts(q, &n.body);
            q.extend(n.handlers.iter().map(Node::Handler));
            stmts(q, &n.orelse);
            stmts(q, &n.finalbody);
        }
        Stmt::TryStar(n) => {
            stmts(q, &n.body);
            q.extend(n.handlers.iter().map(Node::Handler));
            stmts(q, &n.orelse);
            stmts(q, &n.finalbody);
        }
        Stmt::Assert(n) => {
            one(q, &n.test);
            opt(q, n.msg.as_deref());
        }
        Stmt::Import(n) => q.extend(n.names.iter().map(Node::Alias)),
        Stmt::ImportFrom(n) => q.extend(n.names.iter().map(Node::Alias)),
        Stmt::Expr(n) => one(q, &n.value),
        Stmt::Global(_)
        | Stmt::Nonlocal(_)
        | Stmt::Pass(_)
        | Stmt::Break(_)
        | Stmt::Continue(_) => {}
    }
}

fn generators<'a>(q: &mut Q<'a>, g: &'a [Comprehension]) {
    q.extend(g.iter().map(Node::Comprehension));
}

fn expr_children<'a>(q: &mut Q<'a>, e: &'a Expr) {
    match e {
        Expr::BoolOp(n) => exprs(q, &n.values),
        Expr::NamedExpr(n) => {
            one(q, &n.target);
            one(q, &n.value);
        }
        Expr::BinOp(n) => {
            one(q, &n.left);
            one(q, &n.right);
        }
        Expr::UnaryOp(n) => one(q, &n.operand),
        Expr::Lambda(n) => {
            q.push_back(Node::Arguments(&n.args));
            one(q, &n.body);
        }
        Expr::IfExp(n) => {
            one(q, &n.test);
            one(q, &n.body);
            one(q, &n.orelse);
        }
        Expr::Dict(n) => {
            q.extend(n.keys.iter().flatten().map(Node::Expr));
            exprs(q, &n.values);
        }
        Expr::Set(n) => exprs(q, &n.elts),
        Expr::ListComp(n) => {
            one(q, &n.elt);
            generators(q, &n.generators);
        }
        Expr::SetComp(n) => {
            one(q, &n.elt);
            generators(q, &n.generators);
        }
        Expr::DictComp(n) => {
            one(q, &n.key);
            one(q, &n.value);
            generators(q, &n.generators);
        }
        Expr::GeneratorExp(n) => {
            one(q, &n.elt);
            generators(q, &n.generators);
        }
        Expr::Await(n) => one(q, &n.value),
        Expr::Yield(n) => opt(q, n.value.as_deref()),
        Expr::YieldFrom(n) => one(q, &n.value),
        Expr::Compare(n) => {
            one(q, &n.left);
            exprs(q, &n.comparators);
        }
        Expr::Call(n) => {
            one(q, &n.func);
            exprs(q, &n.args);
            q.extend(n.keywords.iter().map(Node::Keyword));
        }
        Expr::FormattedValue(n) => {
            one(q, &n.value);
            opt(q, n.format_spec.as_deref());
        }
        Expr::JoinedStr(n) => exprs(q, &n.values),
        Expr::Attribute(n) => one(q, &n.value),
        Expr::Subscript(n) => {
            one(q, &n.value);
            one(q, &n.slice);
        }
        Expr::Starred(n) => one(q, &n.value),
        Expr::List(n) => exprs(q, &n.elts),
        Expr::Tuple(n) => exprs(q, &n.elts),
        Expr::Slice(n) => {
            opt(q, n.lower.as_deref());
            opt(q, n.upper.as_deref());
            opt(q, n.step.as_deref());
        }
        Expr::Constant(_) | Expr::Name(_) => {}
    }
}

fn arguments_children<'a>(q: &mut Q<'a>, a: &'a Arguments) {
    q.extend(a.posonlyargs.iter().map(|x| Node::Arg(&x.def)));
    q.extend(a.args.iter().map(|x| Node::Arg(&x.def)));
    q.extend(a.vararg.as_deref().map(Node::Arg));
    q.extend(a.kwonlyargs.iter().map(|x| Node::Arg(&x.def)));
    q.extend(
        a.kwonlyargs
            .iter()
            .filter_map(|x| x.default.as_deref())
            .map(Node::Expr),
    );
    q.extend(a.kwarg.as_deref().map(Node::Arg));
    let defaults = a
        .posonlyargs
        .iter()
        .chain(&a.args)
        .filter_map(|x| x.default.as_deref());
    q.extend(defaults.map(Node::Expr));
}

fn pattern_children<'a>(q: &mut Q<'a>, p: &'a Pattern) {
    match p {
        Pattern::MatchValue(n) => one(q, &n.value),
        Pattern::MatchSequence(n) => pats(q, &n.patterns),
        Pattern::MatchMapping(n) => {
            exprs(q, &n.keys);
            pats(q, &n.patterns);
        }
        Pattern::MatchClass(n) => {
            one(q, &n.cls);
            pats(q, &n.patterns);
            pats(q, &n.kwd_patterns);
        }
        Pattern::MatchAs(n) => q.extend(n.pattern.as_deref().map(Node::Pattern)),
        Pattern::MatchOr(n) => pats(q, &n.patterns),
        Pattern::MatchSingleton(_) | Pattern::MatchStar(_) => {}
    }
}

fn children<'a>(q: &mut Q<'a>, node: Node<'a>) {
    match node {
        Node::Stmt(s) => stmt_children(q, s),
        Node::Expr(e) => expr_children(q, e),
        Node::Comprehension(c) => {
            one(q, &c.target);
            one(q, &c.iter);
            exprs(q, &c.ifs);
        }
        Node::Handler(ExceptHandler::ExceptHandler(h)) => {
            opt(q, h.type_.as_deref());
            stmts(q, &h.body);
        }
        Node::Arguments(a) => arguments_children(q, a),
        Node::Arg(a) => opt(q, a.annotation.as_deref()),
        Node::Keyword(k) => one(q, &k.value),
        Node::WithItem(w) => {
            one(q, &w.context_expr);
            opt(q, w.optional_vars.as_deref());
        }
        Node::MatchCase(m) => {
            q.push_back(Node::Pattern(&m.pattern));
            opt(q, m.guard.as_deref());
            stmts(q, &m.body);
        }
        Node::Pattern(p) => pattern_children(q, p),
        Node::TypeParam(TypeParam::TypeVar(t)) => opt(q, t.bound.as_deref()),
        Node::TypeParam(_) | Node::Alias(_) => {}
    }
}

/// `ast.iter_child_nodes(node)` (contexts and operators are not nodes here).
#[must_use]
pub fn child_nodes<'a>(node: Node<'a>) -> Vec<Node<'a>> {
    let mut q: Q<'a> = VecDeque::new();
    children(&mut q, node);
    q.into()
}

/// Identity of a node: variant tag plus address, so a node and its first inline field never collide.
pub type NodeKey = (u8, usize);

#[must_use]
pub fn node_key(node: Node<'_>) -> NodeKey {
    match node {
        Node::Stmt(n) => (0, std::ptr::from_ref(n) as usize),
        Node::Expr(n) => (1, std::ptr::from_ref(n) as usize),
        Node::Comprehension(n) => (2, std::ptr::from_ref(n) as usize),
        Node::Handler(n) => (3, std::ptr::from_ref(n) as usize),
        Node::Arguments(n) => (4, std::ptr::from_ref(n) as usize),
        Node::Arg(n) => (5, std::ptr::from_ref(n) as usize),
        Node::Keyword(n) => (6, std::ptr::from_ref(n) as usize),
        Node::Alias(n) => (7, std::ptr::from_ref(n) as usize),
        Node::WithItem(n) => (8, std::ptr::from_ref(n) as usize),
        Node::MatchCase(n) => (9, std::ptr::from_ref(n) as usize),
        Node::Pattern(n) => (10, std::ptr::from_ref(n) as usize),
        Node::TypeParam(n) => (11, std::ptr::from_ref(n) as usize),
    }
}

/// Identity of an expression (address of the `Expr`; only compared with other expression ids).
#[must_use]
pub fn eid(e: &Expr) -> usize {
    std::ptr::from_ref(e) as usize
}

/// `ast.walk(root)`: breadth-first, the root included.
pub fn walk_from<'a>(root: Node<'a>, mut visit: impl FnMut(Node<'a>)) {
    let mut q: Q<'a> = VecDeque::from([root]);
    while let Some(node) = q.pop_front() {
        visit(node);
        children(&mut q, node);
    }
}
