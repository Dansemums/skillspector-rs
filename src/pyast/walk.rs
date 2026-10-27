//! `ast.walk` over rustpython's tree: breadth-first, children in CPython's field order, so that
//! order-sensitive consumers (the import-alias dict, where a later import wins) match CPython.
//! Operator and context singletons (`ast.Load`, `ast.Add`, ...) are not visited.

use rustpython_parser::ast::{
    Alias, Arg, Arguments, Comprehension, ExceptHandler, Expr, ExprCall, Keyword, MatchCase,
    Pattern, Ranged, Stmt, TypeParam, WithItem,
};
use rustpython_parser::text_size::TextRange;
use std::collections::VecDeque;

/// Any node `ast.walk` yields that carries structure (everything but operators and contexts).
#[derive(Clone, Copy, Debug)]
pub enum Node<'a> {
    Stmt(&'a Stmt),
    Expr(&'a Expr),
    Comprehension(&'a Comprehension),
    Handler(&'a ExceptHandler),
    Arguments(&'a Arguments),
    Arg(&'a Arg),
    Keyword(&'a Keyword),
    Alias(&'a Alias),
    WithItem(&'a WithItem),
    MatchCase(&'a MatchCase),
    Pattern(&'a Pattern),
    TypeParam(&'a TypeParam),
}

impl Node<'_> {
    /// Source range for nodes CPython gives `lineno`/`col_offset` (not comprehension, arguments,
    /// withitem or match_case).
    #[must_use]
    pub fn range(&self) -> Option<TextRange> {
        Some(match self {
            Node::Stmt(n) => n.range(),
            Node::Expr(n) => n.range(),
            Node::Handler(n) => n.range(),
            Node::Arg(n) => n.range(),
            Node::Keyword(n) => n.range(),
            Node::Alias(n) => n.range(),
            Node::Pattern(n) => n.range(),
            Node::TypeParam(n) => n.range(),
            Node::Comprehension(_)
            | Node::Arguments(_)
            | Node::WithItem(_)
            | Node::MatchCase(_) => return None,
        })
    }
}

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

/// Visits every node under `body` breadth-first, like `ast.walk(module)` minus the module itself.
pub fn walk<'a>(body: &'a [Stmt], mut visit: impl FnMut(Node<'a>)) {
    let mut q: Q<'a> = VecDeque::new();
    stmts(&mut q, body);
    while let Some(node) = q.pop_front() {
        visit(node);
        children(&mut q, node);
    }
}

/// Every `ast.Call` under `body`, in walk order.
#[must_use]
pub fn calls(body: &[Stmt]) -> Vec<&ExprCall> {
    let mut out = Vec::new();
    walk(body, |n| {
        if let Node::Expr(Expr::Call(c)) = n {
            out.push(c);
        }
    });
    out
}

/// Depth of the deepest node under `body` (a statement directly in the module is depth 1).
#[must_use]
pub fn max_depth(body: &[Stmt]) -> usize {
    let mut q: VecDeque<(Node, usize)> = body.iter().map(|s| (Node::Stmt(s), 1)).collect();
    let mut deepest = 0;
    let mut kids: Q = VecDeque::new();
    while let Some((node, depth)) = q.pop_front() {
        deepest = deepest.max(depth);
        children(&mut kids, node);
        q.extend(kids.drain(..).map(|k| (k, depth + 1)));
    }
    deepest
}
