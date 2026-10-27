//! Lexical scopes and in-file callees (`_Scope` ... `_ScopeIndex`, lines 450-1130). Python's
//! object references are indices into the arenas of [`ScopeIndex`]; AST nodes are identified by
//! the address of their `Expr` ([`super::nodes::eid`]).

use super::nodes::eid;
use crate::pyast::ast::{
    Arguments, Expr, ExprAttribute, ExprCall, ExprContext, ExprLambda, ExprName,
    StmtAsyncFunctionDef, StmtClassDef, StmtFunctionDef,
};
use crate::pyast::names::ident;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

pub const MODULE: u8 = 0;
pub const FUNCTION: u8 = 1;
pub const LAMBDA: u8 = 2;
pub const COMPREHENSION: u8 = 3;
pub const CLASS: u8 = 4;

/// Call-site positional arguments at or beyond this index share one wildcard slot.
pub const MAX_POSITIONAL_SLOTS: usize = 16;
/// The in-file base lookup visits at most this many classes (the class itself included).
const MAX_ANCESTORS: usize = 8;

/// An identifier as CPython stores it (NFKC-normalised).
#[must_use]
pub fn nm(s: &str) -> String {
    ident(s).into_owned()
}

#[derive(Clone, Copy)]
pub struct NameRef<'a> {
    pub id: usize,
    pub name: &'a ExprName,
}
#[derive(Clone, Copy)]
pub struct CallRef<'a> {
    pub id: usize,
    pub call: &'a ExprCall,
}
#[derive(Clone, Copy)]
pub struct AttrRef<'a> {
    pub id: usize,
    pub attr: &'a ExprAttribute,
}

#[must_use]
pub fn name_ref(e: &Expr) -> Option<NameRef<'_>> {
    match e {
        Expr::Name(name) => Some(NameRef { id: eid(e), name }),
        _ => None,
    }
}
#[must_use]
pub fn call_ref(e: &Expr) -> Option<CallRef<'_>> {
    match e {
        Expr::Call(call) => Some(CallRef { id: eid(e), call }),
        _ => None,
    }
}
#[must_use]
pub fn attr_ref(e: &Expr) -> Option<AttrRef<'_>> {
    match e {
        Expr::Attribute(attr) => Some(AttrRef { id: eid(e), attr }),
        _ => None,
    }
}

#[must_use]
pub fn is_load(ctx: ExprContext) -> bool {
    matches!(ctx, ExprContext::Load)
}

#[derive(Clone, Copy)]
pub enum FnNode<'a> {
    Def(&'a StmtFunctionDef),
    Async(&'a StmtAsyncFunctionDef),
    Lambda(&'a ExprLambda),
}

impl<'a> FnNode<'a> {
    #[must_use]
    pub fn args(&self) -> &'a Arguments {
        match self {
            FnNode::Def(n) => &n.args,
            FnNode::Async(n) => &n.args,
            FnNode::Lambda(n) => &n.args,
        }
    }
    #[must_use]
    pub fn name(&self) -> Option<String> {
        match self {
            FnNode::Def(n) => Some(nm(n.name.as_str())),
            FnNode::Async(n) => Some(nm(n.name.as_str())),
            FnNode::Lambda(_) => None,
        }
    }
    #[must_use]
    pub fn decorators(&self) -> &'a [Expr] {
        match self {
            FnNode::Def(n) => &n.decorator_list,
            FnNode::Async(n) => &n.decorator_list,
            FnNode::Lambda(_) => &[],
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Function,
    Instance,
    Class,
    Static,
}

#[derive(Clone, Copy)]
pub enum Def {
    Function(usize),
    Class(usize),
}

pub struct Scope<'a> {
    pub kind: u8,
    pub parent: Option<usize>,
    #[cfg_attr(not(test), allow(dead_code))]
    pub name: String,
    pub in_function: bool,
    pub bound: HashSet<String>,
    pub declared_global: HashSet<String>,
    pub declared_nonlocal: HashSet<String>,
    pub children: Vec<usize>,
    pub names: Vec<NameRef<'a>>,
    pub definitions: Vec<(String, Def)>,
    pub function: Option<usize>,
    pub class_def: Option<usize>,
}

pub struct Function<'a> {
    pub node: FnNode<'a>,
    pub scope: usize,
    pub kind: Kind,
    pub key: Option<usize>,
    pub group: Option<usize>,
}

pub struct ClassDef<'a> {
    pub node: &'a StmtClassDef,
    pub scope: usize,
    pub key: Option<usize>,
    pub cls: Option<usize>,
}

pub struct Class {
    pub defs: Vec<usize>,
    pub bases: Vec<usize>,
    pub methods: HashMap<String, Vec<(Kind, usize)>>,
    pub ancestors: Option<Vec<usize>>,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum SlotKey {
    Pos(usize),
    Star(usize),
    Map(usize),
    Kw(String),
    KwRest,
}

pub struct Group {
    pub kind: Kind,
    pub functions: Vec<usize>,
    pub merged: Option<usize>,
    pub slots: HashMap<SlotKey, usize>,
    /// `signature()`: names a keyword can bind, and names every `**kwargs` definition takes.
    pub named: Option<HashSet<String>>,
    pub kwarg_named: Option<HashSet<String>>,
}

#[derive(Default)]
pub struct CallTargets {
    /// (callee group, receiver offset) pairs the call binds its arguments into.
    pub members: Vec<(usize, usize)>,
    /// Callees whose return summary the call's value reads.
    pub results: Vec<usize>,
}

/// A key of the `_ids` table: one id per scope-bound name or synthetic descriptor.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum IdKey {
    Scope(usize, String),
    Store(usize, String),
    Class(usize, String),
    View(usize, String),
    ClassRead(usize, String),
    Return(usize),
    Value(usize),
    Slot(usize, SlotKey),
}

#[derive(Clone, Copy)]
pub enum StmtRef<'a> {
    Assign(&'a crate::pyast::ast::StmtAssign),
    Return(&'a crate::pyast::ast::StmtReturn),
    Call(CallRef<'a>),
}

pub struct ScopeIndex<'a> {
    pub scopes: Vec<Scope<'a>>,
    pub statements: Vec<(StmtRef<'a>, usize)>,
    pub functions: Vec<Function<'a>>,
    pub lambdas: HashMap<usize, usize>,
    pub lambda_bindings: Vec<(NameRef<'a>, usize)>,
    pub class_defs: Vec<ClassDef<'a>>,
    pub classes: Vec<Class>,
    pub attributes: Vec<AttrRef<'a>>,
    pub super_scopes: HashMap<usize, usize>,
    pub ids: HashMap<IdKey, usize>,
    pub key_scope: Vec<Option<usize>>,
    pub key_name: Vec<String>,
    pub local: Vec<bool>,
    pub name_key: HashMap<usize, usize>,
    pub class_reads: Vec<(usize, usize, usize)>,
    class_reads_seen: HashSet<(usize, usize, usize)>,
    pub class_read_views: HashMap<usize, usize>,
    pub kwarg_params: HashSet<usize>,
    pub class_of_key: HashMap<usize, usize>,
    pub function_groups: HashMap<usize, usize>,
    pub groups: Vec<Group>,
    pub receivers: HashMap<usize, (usize, bool)>,
    pub views: HashMap<usize, usize>,
    pub view_list: Vec<(usize, String, usize)>,
    calls: HashMap<usize, Rc<CallTargets>>,
    lookups: HashMap<(usize, String, usize), Vec<usize>>,
    lambda_groups: HashMap<usize, usize>,
}

impl<'a> ScopeIndex<'a> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            scopes: Vec::new(),
            statements: Vec::new(),
            functions: Vec::new(),
            lambdas: HashMap::new(),
            lambda_bindings: Vec::new(),
            class_defs: Vec::new(),
            classes: Vec::new(),
            attributes: Vec::new(),
            super_scopes: HashMap::new(),
            ids: HashMap::new(),
            key_scope: Vec::new(),
            key_name: Vec::new(),
            local: Vec::new(),
            name_key: HashMap::new(),
            class_reads: Vec::new(),
            class_reads_seen: HashSet::new(),
            class_read_views: HashMap::new(),
            kwarg_params: HashSet::new(),
            class_of_key: HashMap::new(),
            function_groups: HashMap::new(),
            groups: Vec::new(),
            receivers: HashMap::new(),
            views: HashMap::new(),
            view_list: Vec::new(),
            calls: HashMap::new(),
            lookups: HashMap::new(),
            lambda_groups: HashMap::new(),
        }
    }

    /// The module scope (always scope 0).
    pub const MODULE_SCOPE: usize = 0;

    pub fn new_scope(&mut self, kind: u8, parent: Option<usize>, name: &str) -> usize {
        let id = self.scopes.len();
        let in_function = kind == FUNCTION
            || kind == LAMBDA
            || (kind == COMPREHENSION && parent.is_some_and(|p| self.scopes[p].in_function));
        self.scopes.push(Scope {
            kind,
            parent,
            name: name.to_owned(),
            in_function,
            bound: HashSet::new(),
            declared_global: HashSet::new(),
            declared_nonlocal: HashSet::new(),
            children: Vec::new(),
            names: Vec::new(),
            definitions: Vec::new(),
            function: None,
            class_def: None,
        });
        if let Some(p) = parent {
            self.scopes[p].children.push(id);
        }
        id
    }

    pub fn add_class_read(&mut self, view: usize, key: usize, module_key: usize) {
        if self.class_reads_seen.insert((view, key, module_key)) {
            self.class_reads.push((view, key, module_key));
        }
    }

    // ── keys ──

    fn new_key(&mut self, scope: Option<usize>, name: &str, local: bool) -> usize {
        let key = self.key_scope.len();
        self.key_scope.push(scope);
        self.key_name.push(name.to_owned());
        self.local.push(local);
        key
    }

    /// Key of `name` bound in `scope` itself.
    pub fn key(&mut self, scope: usize, name: &str) -> usize {
        let ident = IdKey::Scope(scope, name.to_owned());
        if let Some(&k) = self.ids.get(&ident) {
            return k;
        }
        let local = self.scopes[scope].in_function;
        let k = self.new_key(Some(scope), name, local);
        self.ids.insert(ident, k);
        k
    }

    pub fn synthetic(&mut self, ident: IdKey, local: bool, name: &str) -> usize {
        if let Some(&k) = self.ids.get(&ident) {
            return k;
        }
        let k = self.new_key(None, name, local);
        self.ids.insert(ident, k);
        k
    }

    /// Whether a read evaluated from `root` carries `key`'s data.
    #[must_use]
    pub fn visible(&self, key: usize, root: usize) -> bool {
        match self.key_scope[key] {
            None => true,
            Some(owner) => {
                owner == root || !matches!(self.scopes[owner].kind, LAMBDA | COMPREHENSION)
            }
        }
    }

    // ── callees ──

    fn new_group(&mut self, kind: Kind) -> usize {
        let id = self.groups.len();
        self.groups.push(Group {
            kind,
            functions: Vec::new(),
            merged: None,
            slots: HashMap::new(),
            named: None,
            kwarg_named: None,
        });
        id
    }

    pub fn function_group(&mut self, key: usize) -> usize {
        if let Some(&g) = self.function_groups.get(&key) {
            return g;
        }
        let g = self.new_group(Kind::Function);
        self.function_groups.insert(key, g);
        g
    }

    pub fn method_group(&mut self, cls: usize, name: &str, kind: Kind) -> usize {
        let existing = self.classes[cls]
            .methods
            .get(name)
            .and_then(|kinds| kinds.iter().find(|(k, _)| *k == kind))
            .map(|&(_, g)| g);
        if let Some(g) = existing {
            return g;
        }
        let g = self.new_group(kind);
        self.classes[cls]
            .methods
            .entry(name.to_owned())
            .or_default()
            .push((kind, g));
        g
    }

    pub fn add_function(&mut self, group: usize, function: usize) {
        self.groups[group].functions.push(function);
        self.functions[function].group = Some(group);
    }

    pub fn root(&mut self, g: usize) -> usize {
        let mut group = g;
        while let Some(m) = self.groups[group].merged {
            group = m;
        }
        let mut node = g;
        while let Some(m) = self.groups[node].merged {
            if m == group {
                break;
            }
            self.groups[node].merged = Some(group);
            node = m;
        }
        group
    }

    /// The one callee of a lambda, shared by every name it is bound to.
    pub fn lambda_group(&mut self, lambda: usize, function: usize) -> usize {
        let group = match self.lambda_groups.get(&lambda) {
            Some(&g) => g,
            None => {
                let g = self.new_group(Kind::Function);
                self.add_function(g, function);
                self.lambda_groups.insert(lambda, g);
                g
            }
        };
        self.root(group)
    }

    /// Makes `group` (a lambda's) a callee of the name `key`.
    pub fn bind_name(&mut self, key: usize, group: usize) {
        let Some(&current) = self.function_groups.get(&key) else {
            self.function_groups.insert(key, group);
            return;
        };
        let (mut current, mut group) = (self.root(current), self.root(group));
        if current == group {
            return;
        }
        if self.groups[current].functions.len() < self.groups[group].functions.len() {
            std::mem::swap(&mut current, &mut group);
        }
        self.groups[group].merged = Some(current);
        let moved = std::mem::take(&mut self.groups[group].functions);
        for &f in &moved {
            self.functions[f].group = Some(current);
        }
        self.groups[current].functions.extend(moved);
    }

    pub fn finish_groups(&mut self) {
        let keys: Vec<usize> = self.function_groups.keys().copied().collect();
        for key in keys {
            let g = self.function_groups[&key];
            if self.groups[g].merged.is_some() {
                let r = self.root(g);
                self.function_groups.insert(key, r);
            }
        }
    }

    /// `_Group.signature`: computed once, on the first call bound into the group.
    pub fn signature(&mut self, group: usize) {
        if self.groups[group].named.is_some() {
            return;
        }
        let mut named = HashSet::new();
        let mut kwarg_named: Option<HashSet<String>> = None;
        for &f in &self.groups[group].functions {
            let args = self.functions[f].node.args();
            // CPython's `args.args` excludes positional-only names.
            let names: HashSet<String> = args
                .args
                .iter()
                .chain(&args.kwonlyargs)
                .map(|a| nm(a.def.arg.as_str()))
                .collect();
            named.extend(names.iter().cloned());
            if args.kwarg.is_some() {
                kwarg_named = Some(match kwarg_named {
                    None => names,
                    Some(prev) => prev.intersection(&names).cloned().collect(),
                });
            }
        }
        self.groups[group].named = Some(named);
        self.groups[group].kwarg_named = kwarg_named;
    }

    // ── classes ──

    /// `_c3`: linearisation of `cls` from its bases', cut at `MAX_ANCESTORS`.
    fn c3(&self, cls: usize, bases: &[usize]) -> Vec<usize> {
        let mut result = vec![cls];
        if bases.is_empty() {
            return result;
        }
        let mut sequences: Vec<Vec<usize>> = bases
            .iter()
            .map(|&b| {
                let seq = self.classes[b].ancestors.clone().unwrap_or_else(|| vec![b]);
                seq.into_iter().filter(|&c| c != cls).collect()
            })
            .collect();
        if sequences.len() == 1 {
            result.extend(sequences[0].iter().take(MAX_ANCESTORS - 1));
            return result;
        }
        sequences.push(bases.iter().copied().filter(|&b| b != cls).collect());
        let mut tails: HashMap<usize, i64> = HashMap::new();
        for seq in &sequences {
            for &c in seq.iter().skip(1) {
                *tails.entry(c).or_insert(0) += 1;
            }
        }
        let mut positions = vec![0usize; sequences.len()];
        let mut placed: HashSet<usize> = HashSet::from([cls]);
        while result.len() < MAX_ANCESTORS {
            let mut candidate = None;
            let mut leftmost = None;
            for (seq, &pos) in sequences.iter().zip(&positions) {
                if pos < seq.len() {
                    let head = seq[pos];
                    if leftmost.is_none() {
                        leftmost = Some(head);
                    }
                    if tails.get(&head).copied().unwrap_or(0) == 0 {
                        candidate = Some(head);
                        break;
                    }
                }
            }
            let Some(candidate) = candidate.or(leftmost) else {
                break;
            };
            if placed.insert(candidate) {
                result.push(candidate);
            }
            for (i, seq) in sequences.iter().enumerate() {
                let pos = positions[i];
                if pos < seq.len() && seq[pos] == candidate {
                    positions[i] = pos + 1;
                    if pos + 1 < seq.len() {
                        *tails.entry(seq[pos + 1]).or_insert(0) -= 1;
                    }
                }
            }
        }
        result
    }

    /// `cls` then its in-file bases in C3 order, bounded.
    pub fn ancestors(&mut self, cls: usize) -> Vec<usize> {
        if let Some(a) = &self.classes[cls].ancestors {
            return a.clone();
        }
        let mut visiting: HashSet<usize> = HashSet::new();
        let mut stack = vec![cls];
        while let Some(&current) = stack.last() {
            if self.classes[current].ancestors.is_some() {
                stack.pop();
                continue;
            }
            let bases = self.classes[current].bases.clone();
            if !visiting.contains(&current) {
                visiting.insert(current);
                let pending: Vec<usize> = bases
                    .iter()
                    .copied()
                    .filter(|b| self.classes[*b].ancestors.is_none() && !visiting.contains(b))
                    .collect();
                if !pending.is_empty() {
                    stack.extend(pending.into_iter().rev());
                    continue;
                }
            }
            stack.pop();
            let order = self.c3(current, &bases);
            self.classes[current].ancestors = Some(order);
        }
        self.classes[cls].ancestors.clone().unwrap_or_default()
    }

    /// Method groups named `name` on the nearest class in `cls`'s lookup chain.
    pub fn lookup(&mut self, cls: usize, name: &str, skip: usize) -> Vec<usize> {
        let memo = (cls, name.to_owned(), skip);
        if let Some(found) = self.lookups.get(&memo) {
            return found.clone();
        }
        let mut found = Vec::new();
        for candidate in self.ancestors(cls).into_iter().skip(skip) {
            if let Some(kinds) = self.classes[candidate].methods.get(name)
                && !kinds.is_empty()
            {
                found = kinds.iter().map(|&(_, g)| g).collect();
                break;
            }
        }
        self.lookups.insert(memo, found.clone());
        found
    }

    /// The class whose bases `super()` / `super(C, obj)` starts from.
    fn super_class(&self, call: CallRef<'_>) -> Option<usize> {
        let Expr::Name(func) = &*call.call.func else {
            return None;
        };
        let key = *self.name_key.get(&eid(&call.call.func))?;
        if func.id.as_str() != "super"
            || self.key_scope[key] != Some(Self::MODULE_SCOPE)
            || self.scopes[Self::MODULE_SCOPE].bound.contains("super")
        {
            return None;
        }
        if let Some(first) = call.call.args.first() {
            return match first {
                Expr::Name(_) => self
                    .name_key
                    .get(&eid(first))
                    .and_then(|k| self.class_of_key.get(k))
                    .copied(),
                _ => None,
            };
        }
        let mut scope = self.super_scopes.get(&call.id).copied();
        while let Some(s) = scope {
            if matches!(self.scopes[s].kind, LAMBDA | COMPREHENSION) {
                scope = self.scopes[s].parent;
            } else {
                break;
            }
        }
        let scope = scope?;
        if self.scopes[scope].kind != FUNCTION {
            return None;
        }
        let parent = self.scopes[scope].parent?;
        let class_def = self.scopes[parent].class_def?;
        self.class_defs[class_def].cls
    }

    /// The class `Name(...)` constructs: an in-file class name, or `cls`.
    fn constructed_class(&self, key: Option<usize>) -> Option<usize> {
        let key = key?;
        if let Some(&(cls, is_cls)) = self.receivers.get(&key) {
            return is_cls.then_some(cls);
        }
        self.class_of_key.get(&key).copied()
    }

    /// The in-file callees a call reaches, resolved from syntax alone.
    pub fn call_targets(&mut self, call: CallRef<'a>) -> Rc<CallTargets> {
        if let Some(c) = self.calls.get(&call.id) {
            return Rc::clone(c);
        }
        let mut members: Vec<(usize, usize)> = Vec::new();
        let mut results: Vec<usize> = Vec::new();
        let func: &'a Expr = &call.call.func;
        match func {
            Expr::Name(_) => {
                let key = self.name_key.get(&eid(func)).copied();
                if let Some(&group) = key.and_then(|k| self.function_groups.get(&k)) {
                    members.push((group, 0));
                    results.push(group);
                }
                if let Some(constructed) = self.constructed_class(key) {
                    for group in self.lookup(constructed, "__init__", 0) {
                        members.push((group, usize::from(self.groups[group].kind != Kind::Static)));
                    }
                    for group in self.lookup(constructed, "__new__", 0) {
                        members.push((group, 1));
                    }
                }
            }
            Expr::Lambda(_) => {
                if let Some(&function) = self.lambdas.get(&eid(func)) {
                    let g = self.lambda_group(eid(func), function);
                    members.push((g, 0));
                }
            }
            Expr::Attribute(attr) => {
                let value: &'a Expr = &attr.value;
                let mut cls: Option<usize> = None;
                let mut class_object = false;
                let mut skip = 0;
                match value {
                    Expr::Name(_) => {
                        let key = self.name_key.get(&eid(value)).copied();
                        if let Some(&(c, o)) = key.and_then(|k| self.receivers.get(&k)) {
                            cls = Some(c);
                            class_object = o;
                        } else {
                            cls = key.and_then(|k| self.class_of_key.get(&k)).copied();
                            class_object = true;
                        }
                    }
                    Expr::Call(inner) => {
                        let inner_ref = CallRef {
                            id: eid(value),
                            call: inner,
                        };
                        cls = self.super_class(inner_ref);
                        if cls.is_some() {
                            skip = 1;
                        } else if let Expr::Name(_) = &*inner.func {
                            let key = self.name_key.get(&eid(&inner.func)).copied();
                            cls = self.constructed_class(key);
                        }
                    }
                    _ => {}
                }
                if let Some(cls) = cls {
                    for group in self.lookup(cls, &nm(attr.attr.as_str()), skip) {
                        members.push((
                            group,
                            receiver_offset(self.groups[group].kind, class_object),
                        ));
                        results.push(group);
                    }
                }
            }
            _ => {}
        }
        let found = Rc::new(CallTargets { members, results });
        self.calls.insert(call.id, Rc::clone(&found));
        found
    }

    // ── attributes ──

    /// The class of `self` / `cls` in `self.x` / `cls.x`, if it is one.
    fn receiver_class(&self, node: AttrRef<'_>) -> Option<usize> {
        if !matches!(&*node.attr.value, Expr::Name(_)) {
            return None;
        }
        let key = self.name_key.get(&eid(&node.attr.value))?;
        self.receivers.get(key).map(|r| r.0)
    }

    pub fn attribute_store(&mut self, node: AttrRef<'_>) -> Option<usize> {
        let cls = self.receiver_class(node)?;
        Some(self.synthetic(IdKey::Store(cls, nm(node.attr.attr.as_str())), false, ""))
    }

    pub fn class_body_store(&mut self, cls: usize, name: &str) -> usize {
        self.synthetic(IdKey::Class(cls, name.to_owned()), false, "")
    }

    /// Key read by `self.x` / `cls.x`: stores in the class and its bases.
    pub fn attribute_view(&mut self, node: AttrRef<'_>) -> Option<usize> {
        if let Some(&k) = self.views.get(&node.id) {
            return Some(k);
        }
        if !is_load(node.attr.ctx) {
            return None;
        }
        let cls = self.receiver_class(node)?;
        let attr = nm(node.attr.attr.as_str());
        let ident = IdKey::View(cls, attr.clone());
        let key = match self.ids.get(&ident) {
            Some(&k) => k,
            None => {
                let k = self.synthetic(ident, false, "");
                self.view_list.push((cls, attr, k));
                k
            }
        };
        self.views.insert(node.id, key);
        Some(key)
    }

    /// `_ScopeIndex.qualname`.
    #[cfg(test)]
    #[must_use]
    pub fn qualname(&self, scope: usize) -> String {
        let mut parts: Vec<String> = Vec::new();
        let mut current = Some(scope);
        while let Some(c) = current {
            if self.scopes[c].kind == MODULE {
                break;
            }
            let parent = self.scopes[c].parent;
            if parent
                .is_some_and(|p| matches!(self.scopes[p].kind, FUNCTION | LAMBDA | COMPREHENSION))
            {
                parts.push(format!("<locals>.{}", self.scopes[c].name));
            } else {
                parts.push(self.scopes[c].name.clone());
            }
            current = parent;
        }
        parts.reverse();
        parts.join(".")
    }
}

impl Default for ScopeIndex<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// `_receiver_offset`: leading parameters a call binds implicitly (`self` / `cls`).
#[must_use]
pub fn receiver_offset(kind: Kind, class_object: bool) -> usize {
    match kind {
        Kind::Class => 1,
        Kind::Instance => usize::from(!class_object),
        _ => 0,
    }
}

/// `_decorator_name`.
fn decorator_name(d: &Expr) -> Option<String> {
    let d = match d {
        Expr::Call(c) => &*c.func,
        other => other,
    };
    match d {
        Expr::Name(n) => Some(nm(n.id.as_str())),
        Expr::Attribute(a) => Some(nm(a.attr.as_str())),
        _ => None,
    }
}

/// `_method_kind`.
#[must_use]
pub fn method_kind(node: FnNode<'_>) -> Kind {
    let names: Vec<Option<String>> = node.decorators().iter().map(decorator_name).collect();
    let has = |n: &str| names.iter().any(|d| d.as_deref() == Some(n));
    let name = node.name().unwrap_or_default();
    if has("staticmethod") || name == "__new__" {
        Kind::Static
    } else if has("classmethod") || name == "__init_subclass__" || name == "__class_getitem__" {
        Kind::Class
    } else {
        Kind::Instance
    }
}

/// `_parameters`: every parameter a function binds, in signature order.
#[must_use]
pub fn parameters(args: &Arguments) -> Vec<&crate::pyast::ast::Arg> {
    let mut params: Vec<&crate::pyast::ast::Arg> = args
        .posonlyargs
        .iter()
        .chain(&args.args)
        .map(|a| &a.def)
        .collect();
    params.extend(args.vararg.as_deref());
    params.extend(args.kwonlyargs.iter().map(|a| &a.def));
    params.extend(args.kwarg.as_deref());
    params
}
