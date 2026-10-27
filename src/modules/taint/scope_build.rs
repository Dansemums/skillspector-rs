//! `_build_scope_index`, `_resolve_names` and `_index_definitions` (lines 1130-1400).

use super::nodes::{NodeKey, child_nodes, eid, node_key};
use super::scope::{
    CLASS, COMPREHENSION, Class, ClassDef, Def, FUNCTION, FnNode, Function, IdKey, Kind, LAMBDA,
    MODULE, NameRef, ScopeIndex, StmtRef, call_ref, is_load, method_kind, name_ref, nm, parameters,
};
use crate::pyast::Node;
use crate::pyast::ast::{Comprehension, ExceptHandler, Expr, ExprContext, Pattern, Stmt};
use std::collections::{HashMap, HashSet, VecDeque};

type Switch = HashMap<NodeKey, usize>;

fn sw(switch: &mut Switch, e: &Expr, scope: usize) {
    switch.insert(node_key(Node::Expr(e)), scope);
}

fn switch_comprehension(switch: &mut Switch, generators: &[Comprehension], inner: usize) {
    for (position, generator) in generators.iter().enumerate() {
        sw(switch, &generator.target, inner);
        for cond in &generator.ifs {
            sw(switch, cond, inner);
        }
        if position > 0 {
            sw(switch, &generator.iter, inner);
        }
    }
}

struct Pending<'a> {
    switch: Switch,
    /// Walrus targets bind in the nearest enclosing non-comprehension scope.
    walrus: HashMap<usize, usize>,
    annotation_only: HashSet<usize>,
    queue: VecDeque<(Node<'a>, usize)>,
}

fn bind_all<'a>(index: &mut ScopeIndex<'a>, scope: usize, params: impl Iterator<Item = &'a str>) {
    for p in params {
        index.scopes[scope].bound.insert(nm(p));
    }
}

fn visit_name<'a>(index: &mut ScopeIndex<'a>, st: &mut Pending<'a>, e: &'a Expr, scope: usize) {
    let Some(n) = name_ref(e) else { return };
    if is_load(n.name.ctx) {
        index.scopes[scope].names.push(n);
    } else if !st.annotation_only.contains(&n.id) {
        let binding = st.walrus.remove(&n.id).unwrap_or(scope);
        index.scopes[binding].bound.insert(nm(n.name.id.as_str()));
        index.scopes[binding].names.push(n);
    }
}

fn visit_expr<'a>(index: &mut ScopeIndex<'a>, st: &mut Pending<'a>, e: &'a Expr, scope: usize) {
    match e {
        Expr::Lambda(l) => {
            let inner = index.new_scope(LAMBDA, Some(scope), "<lambda>");
            let function = index.functions.len();
            index.functions.push(Function {
                node: FnNode::Lambda(l),
                scope: inner,
                kind: Kind::Function,
                key: None,
                group: None,
            });
            index.scopes[inner].function = Some(function);
            index.lambdas.insert(eid(e), function);
            bind_all(
                index,
                inner,
                parameters(&l.args).into_iter().map(|a| a.arg.as_str()),
            );
            sw(&mut st.switch, &l.body, inner);
        }
        Expr::ListComp(n) => {
            let inner = index.new_scope(COMPREHENSION, Some(scope), "<listcomp>");
            sw(&mut st.switch, &n.elt, inner);
            switch_comprehension(&mut st.switch, &n.generators, inner);
        }
        Expr::SetComp(n) => {
            let inner = index.new_scope(COMPREHENSION, Some(scope), "<setcomp>");
            sw(&mut st.switch, &n.elt, inner);
            switch_comprehension(&mut st.switch, &n.generators, inner);
        }
        Expr::GeneratorExp(n) => {
            let inner = index.new_scope(COMPREHENSION, Some(scope), "<generatorexp>");
            sw(&mut st.switch, &n.elt, inner);
            switch_comprehension(&mut st.switch, &n.generators, inner);
        }
        Expr::DictComp(n) => {
            let inner = index.new_scope(COMPREHENSION, Some(scope), "<dictcomp>");
            sw(&mut st.switch, &n.key, inner);
            sw(&mut st.switch, &n.value, inner);
            switch_comprehension(&mut st.switch, &n.generators, inner);
        }
        Expr::NamedExpr(n) => {
            let mut binding = scope;
            while index.scopes[binding].kind == COMPREHENSION {
                let Some(p) = index.scopes[binding].parent else {
                    break;
                };
                binding = p;
            }
            if let Expr::Name(_) = &*n.target {
                st.walrus.insert(eid(&n.target), binding);
            }
        }
        Expr::Call(c) => {
            if let Some(cr) = call_ref(e) {
                index.statements.push((StmtRef::Call(cr), scope));
                if let Expr::Name(f) = &*c.func
                    && f.id.as_str() == "super"
                {
                    index.super_scopes.insert(cr.id, scope);
                }
            }
        }
        Expr::Attribute(_) => {
            if let Some(a) = super::scope::attr_ref(e)
                && matches!(&*a.attr.value, Expr::Name(_))
            {
                index.attributes.push(a);
            }
        }
        _ => {}
    }
}

fn define<'a>(index: &mut ScopeIndex<'a>, scope: usize, name: &str, def: Def) {
    index.scopes[scope].bound.insert(name.to_owned());
    index.scopes[scope].definitions.push((name.to_owned(), def));
}

fn visit_function<'a>(
    index: &mut ScopeIndex<'a>,
    st: &mut Pending<'a>,
    scope: usize,
    node: FnNode<'a>,
    body: &'a [Stmt],
) {
    let name = node.name().unwrap_or_default();
    let inner = index.new_scope(FUNCTION, Some(scope), &name);
    let function = index.functions.len();
    index.functions.push(Function {
        node,
        scope: inner,
        kind: Kind::Function,
        key: None,
        group: None,
    });
    index.scopes[inner].function = Some(function);
    define(index, scope, &name, Def::Function(function));
    bind_all(
        index,
        inner,
        parameters(node.args()).into_iter().map(|a| a.arg.as_str()),
    );
    // Only the body runs in the new scope; decorators, defaults and annotations stay outside.
    for s in body {
        st.switch.insert(node_key(Node::Stmt(s)), inner);
    }
}

fn visit_stmt<'a>(index: &mut ScopeIndex<'a>, st: &mut Pending<'a>, s: &'a Stmt, scope: usize) {
    match s {
        Stmt::FunctionDef(f) => visit_function(index, st, scope, FnNode::Def(f), &f.body),
        Stmt::AsyncFunctionDef(f) => visit_function(index, st, scope, FnNode::Async(f), &f.body),
        Stmt::ClassDef(c) => {
            let name = nm(c.name.as_str());
            let inner = index.new_scope(CLASS, Some(scope), &name);
            let id = index.class_defs.len();
            index.class_defs.push(ClassDef {
                node: c,
                scope: inner,
                key: None,
                cls: None,
            });
            index.scopes[inner].class_def = Some(id);
            define(index, scope, &name, Def::Class(id));
            for b in &c.body {
                st.switch.insert(node_key(Node::Stmt(b)), inner);
            }
        }
        Stmt::Global(g) => index.scopes[scope]
            .declared_global
            .extend(g.names.iter().map(|n| nm(n.as_str()))),
        Stmt::Nonlocal(g) => index.scopes[scope]
            .declared_nonlocal
            .extend(g.names.iter().map(|n| nm(n.as_str()))),
        Stmt::Import(i) => bind_aliases(index, scope, &i.names),
        Stmt::ImportFrom(i) => bind_aliases(index, scope, &i.names),
        Stmt::AnnAssign(a) => {
            if a.value.is_none()
                && index.scopes[scope].kind == CLASS
                && let Some(n) = name_ref(&a.target)
            {
                st.annotation_only.insert(n.id);
            }
        }
        Stmt::Assign(a) => {
            index.statements.push((StmtRef::Assign(a), scope));
            if let Expr::Lambda(_) = &*a.value {
                for t in &a.targets {
                    if let Some(n) = name_ref(t) {
                        index.lambda_bindings.push((n, eid(&a.value)));
                    }
                }
            }
        }
        Stmt::Return(r) => index.statements.push((StmtRef::Return(r), scope)),
        _ => {}
    }
}

fn bind_aliases<'a>(
    index: &mut ScopeIndex<'a>,
    scope: usize,
    names: &'a [crate::pyast::ast::Alias],
) {
    for alias in names {
        let name = nm(alias.name.as_str());
        if name != "*" {
            let bound = match &alias.asname {
                Some(a) => nm(a.as_str()),
                None => name.split('.').next().unwrap_or_default().to_owned(),
            };
            index.scopes[scope].bound.insert(bound);
        }
    }
}

fn visit_other<'a>(index: &mut ScopeIndex<'a>, node: Node<'a>, scope: usize) {
    let bind = |index: &mut ScopeIndex<'a>, n: &Option<crate::pyast::ast::Identifier>| {
        if let Some(n) = n
            && !n.as_str().is_empty()
        {
            index.scopes[scope].bound.insert(nm(n.as_str()));
        }
    };
    match node {
        Node::Handler(ExceptHandler::ExceptHandler(h)) => bind(index, &h.name),
        Node::Pattern(Pattern::MatchAs(p)) => bind(index, &p.name),
        Node::Pattern(Pattern::MatchStar(p)) => bind(index, &p.name),
        Node::Pattern(Pattern::MatchMapping(p)) => bind(index, &p.rest),
        _ => {}
    }
}

/// `_build_scope_index`.
#[must_use]
pub fn build_scope_index(body: &[Stmt]) -> ScopeIndex<'_> {
    let mut index = ScopeIndex::new();
    let module = index.new_scope(MODULE, None, "");
    let mut st = Pending {
        switch: Switch::new(),
        walrus: HashMap::new(),
        annotation_only: HashSet::new(),
        queue: body.iter().map(|s| (Node::Stmt(s), module)).collect(),
    };
    while let Some((node, scope)) = st.queue.pop_front() {
        match node {
            Node::Expr(e) => {
                if let Expr::Name(_) = e {
                    visit_name(&mut index, &mut st, e, scope);
                    continue;
                }
                visit_expr(&mut index, &mut st, e, scope);
            }
            Node::Stmt(s) => visit_stmt(&mut index, &mut st, s, scope),
            other => visit_other(&mut index, other, scope),
        }
        for child in child_nodes(node) {
            let inner = st.switch.remove(&node_key(child)).unwrap_or(scope);
            st.queue.push_back((child, inner));
        }
    }
    resolve_names(&mut index);
    index_definitions(&mut index);
    index
}

fn binding_scope(
    index: &ScopeIndex<'_>,
    scope: usize,
    name: &str,
    stacks: &HashMap<String, Vec<usize>>,
) -> usize {
    let s = &index.scopes[scope];
    if s.declared_global.contains(name) || s.kind == MODULE {
        return ScopeIndex::MODULE_SCOPE;
    }
    if s.kind == CLASS && s.bound.contains(name) && !s.declared_nonlocal.contains(name) {
        return scope;
    }
    stacks
        .get(name)
        .and_then(|st| st.last())
        .copied()
        .unwrap_or(ScopeIndex::MODULE_SCOPE)
}

/// `_resolve_names`: every recorded name resolved by Python's rules, O(1) per name.
fn resolve_names(index: &mut ScopeIndex<'_>) {
    let module = ScopeIndex::MODULE_SCOPE;
    let mut stacks: HashMap<String, Vec<usize>> = HashMap::new();
    let mut work: Vec<(usize, Option<Vec<String>>)> = vec![(module, None)];
    while let Some((scope, pushed)) = work.pop() {
        if let Some(pushed) = pushed {
            for name in pushed {
                if let Some(st) = stacks.get_mut(&name) {
                    st.pop();
                }
            }
            continue;
        }
        let mut names: Vec<String> = Vec::new();
        let kind = index.scopes[scope].kind;
        if kind != MODULE && kind != CLASS {
            let globals: Vec<String> = index.scopes[scope]
                .declared_global
                .iter()
                .cloned()
                .collect();
            for name in globals {
                stacks.entry(name.clone()).or_default().push(module);
                names.push(name);
            }
            let bound: Vec<String> = index.scopes[scope].bound.iter().cloned().collect();
            for name in bound {
                let s = &index.scopes[scope];
                if !s.declared_global.contains(&name) && !s.declared_nonlocal.contains(&name) {
                    stacks.entry(name.clone()).or_default().push(scope);
                    names.push(name);
                }
            }
        }
        let requested: Vec<NameRef<'_>> = index.scopes[scope].names.clone();
        for node in requested {
            let id = nm(node.name.id.as_str());
            let binder = binding_scope(index, scope, &id, &stacks);
            let key = index.key(binder, &id);
            index.name_key.insert(node.id, key);
            if binder == scope && kind == CLASS && matches!(node.name.ctx, ExprContext::Load) {
                let view = index.synthetic(IdKey::ClassRead(scope, id.clone()), false, &id);
                index.class_read_views.insert(node.id, view);
                let module_key = index.key(module, &id);
                index.add_class_read(view, key, module_key);
            }
        }
        let definitions: Vec<(String, Def)> = index.scopes[scope].definitions.clone();
        for (name, def) in definitions {
            let key = index.key(binding_scope(index, scope, &name, &stacks), &name);
            match def {
                Def::Function(f) => index.functions[f].key = Some(key),
                Def::Class(c) => index.class_defs[c].key = Some(key),
            }
        }
        work.push((scope, Some(names)));
        let children: Vec<usize> = index.scopes[scope].children.clone();
        work.extend(children.into_iter().rev().map(|c| (c, None)));
    }
}

/// `_index_definitions`: merge class redefinitions, link in-file bases, group callees.
fn index_definitions(index: &mut ScopeIndex<'_>) {
    for cd in 0..index.class_defs.len() {
        let Some(key) = index.class_defs[cd].key else {
            continue;
        };
        let cls = match index.class_of_key.get(&key) {
            Some(&c) => c,
            None => {
                let c = index.classes.len();
                index.classes.push(Class {
                    defs: Vec::new(),
                    bases: Vec::new(),
                    methods: HashMap::new(),
                    ancestors: None,
                });
                index.class_of_key.insert(key, c);
                c
            }
        };
        index.classes[cls].defs.push(cd);
        index.class_defs[cd].cls = Some(cls);
    }
    for cls in 0..index.classes.len() {
        let mut linked: HashSet<usize> = HashSet::from([cls]);
        let defs = index.classes[cls].defs.clone();
        for cd in defs {
            for base in &index.class_defs[cd].node.bases {
                let base = match base {
                    Expr::Subscript(s) => &*s.value,
                    other => other,
                };
                if !matches!(base, Expr::Name(_)) {
                    continue;
                }
                let parent = index
                    .name_key
                    .get(&eid(base))
                    .and_then(|k| index.class_of_key.get(k))
                    .copied();
                if let Some(p) = parent
                    && linked.insert(p)
                {
                    index.classes[cls].bases.push(p);
                }
            }
        }
    }
    for f in 0..index.functions.len() {
        let node = index.functions[f].node;
        let scope = index.functions[f].scope;
        if let Some(kwarg) = &node.args().kwarg {
            let key = index.key(scope, &nm(kwarg.arg.as_str()));
            index.kwarg_params.insert(key);
        }
        if matches!(node, FnNode::Lambda(_)) {
            continue;
        }
        let owner = index.scopes[scope]
            .parent
            .and_then(|p| index.scopes[p].class_def)
            .and_then(|cd| index.class_defs[cd].cls);
        let Some(cls) = owner else {
            if let Some(key) = index.functions[f].key {
                let g = index.function_group(key);
                index.add_function(g, f);
            }
            continue;
        };
        let kind = method_kind(node);
        index.functions[f].kind = kind;
        let g = index.method_group(cls, &node.name().unwrap_or_default(), kind);
        index.add_function(g, f);
        let args = node.args();
        let first = args.posonlyargs.iter().chain(&args.args).next();
        if kind != Kind::Static
            && let Some(first) = first
        {
            let rk = index.key(scope, &nm(first.def.arg.as_str()));
            index.receivers.insert(rk, (cls, kind == Kind::Class));
        }
    }
    let bindings: Vec<_> = index
        .lambda_bindings
        .iter()
        .map(|(t, l)| (*t, *l))
        .collect();
    for (target, lam) in bindings {
        let function = index.lambdas.get(&lam).copied();
        let key = index.name_key.get(&target.id).copied();
        if let (Some(function), Some(key)) = (function, key) {
            let g = index.lambda_group(lam, function);
            index.bind_name(key, g);
        }
    }
    index.finish_groups();
}
