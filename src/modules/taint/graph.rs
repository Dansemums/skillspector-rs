//! `_mark_targets` and `_TaintGraph` (lines 1400-2010): scope-aware taint as reachability in a
//! flow graph over keys, computed with a monotone worklist.
//!
//! Facts are arena entries compared by id, as Python compares tuples with `is`.

use super::nodes::{child_nodes, eid};
use super::rules::{
    call_source, credential_subscript, is_deserialization_sink, is_exec_sink, lane_ranks,
    pick_rule, source_name,
};
use super::scope::{
    CLASS, CallRef, IdKey, MAX_POSITIONAL_SLOTS, ScopeIndex, SlotKey, StmtRef, attr_ref, name_ref,
    nm,
};
use crate::pyast::ast::{Expr, Ranged, StmtAssign};
use crate::pyast::names::Aliases;
use crate::pyast::{Node, PyFile};
use std::collections::{HashMap, HashSet, VecDeque};

pub const ASSIGN: u8 = 0;
pub const PASS: u8 = 1;
pub const RETURN: u8 = 2;
pub const BIND: u8 = 3;

const FIRST_LANE: usize = 2;
const ALL_LANES: u8 = 7;
const NO_FACT: u32 = u32::MAX;

/// A fact is (source index, line).
pub type Fact = (usize, u32);
type Work = (usize, usize, u8);

/// One reported taint fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaintedVar {
    pub name: String,
    pub source_call: &'static str,
    pub lineno: u32,
}

struct Flow {
    targets: Vec<usize>,
    kind: u8,
    line: u32,
}

struct Seed {
    targets: Vec<usize>,
    kind: u8,
    line: u32,
    fact: Fact,
    lanes: u8,
}

/// The names, other keys and sources an expression reads.
pub struct Scan {
    pub names: Vec<usize>,
    pub others: Vec<usize>,
    pub sources: Vec<(usize, u8)>,
}

#[derive(Default)]
struct OrderedKeys {
    keys: Vec<usize>,
    seen: HashSet<usize>,
}

impl OrderedKeys {
    fn insert(&mut self, k: usize) {
        if self.seen.insert(k) {
            self.keys.push(k);
        }
    }
}

/// `facts[slot][lane]`: key -> fact id, with the insertion order a Python dict would keep.
#[derive(Default)]
struct FactTable {
    arena: Vec<Fact>,
    held: [[Vec<u32>; 3]; 2],
    order: [[Vec<usize>; 3]; 2],
}

impl FactTable {
    fn get(&self, slot: usize, lane: usize, key: usize) -> Option<u32> {
        self.held[slot][lane]
            .get(key)
            .copied()
            .filter(|&f| f != NO_FACT)
    }
    fn set(&mut self, slot: usize, lane: usize, key: usize, fact: u32) {
        let v = &mut self.held[slot][lane];
        if v.len() <= key {
            v.resize(key + 1, NO_FACT);
        }
        if v[key] == NO_FACT {
            self.order[slot][lane].push(key);
        }
        v[key] = fact;
    }
    fn content(&self, id: u32) -> Fact {
        self.arena[id as usize]
    }
}

pub struct TaintGraph<'a> {
    pub index: ScopeIndex<'a>,
    type_map: &'a HashMap<String, String>,
    aliases: &'a Aliases,
    pf: &'a PyFile,
    facts: FactTable,
    flows: Vec<Flow>,
    prop_a: HashMap<usize, Vec<usize>>,
    prop_b: HashMap<usize, Vec<usize>>,
    worklist: VecDeque<Work>,
    seeds: Vec<Seed>,
    fired: Vec<u32>,
    pub returns: HashMap<usize, usize>,
    pub phase_a_keys: HashSet<usize>,
    values: HashMap<usize, usize>,
    class_links: HashSet<(usize, String)>,
}

impl<'a> TaintGraph<'a> {
    pub fn new(
        index: ScopeIndex<'a>,
        type_map: &'a HashMap<String, String>,
        aliases: &'a Aliases,
        pf: &'a PyFile,
    ) -> Self {
        Self {
            index,
            type_map,
            aliases,
            pf,
            facts: FactTable::default(),
            flows: Vec::new(),
            prop_a: HashMap::new(),
            prop_b: HashMap::new(),
            worklist: VecDeque::new(),
            seeds: Vec::new(),
            fired: Vec::new(),
            returns: HashMap::new(),
            phase_a_keys: HashSet::new(),
            values: HashMap::new(),
            class_links: HashSet::new(),
        }
    }

    fn line_of(&self, node: &impl Ranged) -> u32 {
        self.pf.pos(node.range()).line
    }

    /// `_mark_targets`: gives each target `fact`, in each of `lanes`, where it outranks what it holds.
    fn mark_targets(
        &mut self,
        targets: &[usize],
        kind: u8,
        line: u32,
        fact: Fact,
        bound: bool,
        lanes: u8,
    ) -> Vec<Work> {
        let (source, mut fact_line) = fact;
        if kind != PASS {
            fact_line = line;
        }
        let bound = bound || kind == BIND;
        let ranks = lane_ranks(source);
        let mut new_id: Option<u32> = None;
        let mut changed = Vec::new();
        for &target in targets {
            let slot = usize::from(bound && self.index.local.get(target).copied().unwrap_or(false));
            let mut mask = 0u8;
            for (lane, &rank) in ranks.iter().enumerate() {
                if lanes >> lane & 1 == 0 {
                    continue;
                }
                let outranked = |t: &FactTable, s: usize| {
                    t.get(s, lane, target)
                        .is_some_and(|cur| lane_ranks(t.content(cur).0)[lane] >= rank)
                };
                if outranked(&self.facts, 0) || (slot == 1 && outranked(&self.facts, 1)) {
                    continue;
                }
                let id = *new_id.get_or_insert_with(|| {
                    self.facts.arena.push((source, fact_line));
                    u32::try_from(self.facts.arena.len() - 1).unwrap_or(0)
                });
                self.facts.set(slot, lane, target, id);
                mask |= 1 << lane;
            }
            if mask != 0 {
                changed.push((target, slot, mask));
            }
        }
        changed
    }

    // ── building ──

    fn add_flow(&mut self, reads: &[usize], targets: &[usize], kind: u8, line: u32, phase_a: bool) {
        if targets.is_empty() {
            return;
        }
        let mut keys = OrderedKeys::default();
        for &k in reads {
            keys.insert(k);
        }
        if keys.keys.is_empty() {
            return;
        }
        let flow_id = self.flows.len();
        self.flows.push(Flow {
            targets: targets.to_vec(),
            kind,
            line,
        });
        let table = if phase_a {
            &mut self.prop_a
        } else {
            &mut self.prop_b
        };
        for key in keys.keys {
            table.entry(key).or_default().push(flow_id);
        }
    }

    /// Queues phase B sources for `targets` (applied after phase A).
    fn seed(&mut self, targets: &[usize], kind: u8, line: u32, sources: &[(usize, u8)]) {
        if targets.is_empty() {
            return;
        }
        for &(source, lanes) in sources {
            self.seeds.push(Seed {
                targets: targets.to_vec(),
                kind,
                line,
                fact: (source, line),
                lanes,
            });
        }
    }

    pub fn ret_key(&mut self, group: usize) -> usize {
        if let Some(&k) = self.returns.get(&group) {
            return k;
        }
        let k = self.index.synthetic(IdKey::Return(group), false, "");
        self.returns.insert(group, k);
        k
    }

    /// Key of an in-file call's value, for an enclosing call's arguments.
    fn value_key(&mut self, call: CallRef<'a>, root: usize) -> Option<usize> {
        if self.index.call_targets(call).members.is_empty() {
            return None;
        }
        if let Some(&k) = self.values.get(&call.id) {
            return Some(k);
        }
        let local = self.index.scopes[root].in_function;
        let k = self.index.synthetic(IdKey::Value(call.id), local, "");
        self.values.insert(call.id, k);
        Some(k)
    }

    /// Walks an expression once: (names read, other keys read, sources).
    pub fn scan(
        &mut self,
        node: &'a Expr,
        root: usize,
        nested_values: bool,
        opaque_lambdas: bool,
    ) -> Scan {
        let mut names = OrderedKeys::default();
        let mut others = OrderedKeys::default();
        let mut best: [Option<usize>; 3] = [None; 3];
        let mut best_rank = [-1i32; 3];
        let mut queue: VecDeque<Node<'a>> = VecDeque::from([Node::Expr(node)]);
        while let Some(child) = queue.pop_front() {
            if let Node::Expr(e) = child {
                match e {
                    Expr::Name(_) => {
                        let id = eid(e);
                        let key = self
                            .index
                            .class_read_views
                            .get(&id)
                            .or_else(|| self.index.name_key.get(&id))
                            .copied();
                        if let Some(key) = key
                            && self.index.visible(key, root)
                        {
                            names.insert(key);
                        }
                        continue;
                    }
                    Expr::Call(c) => {
                        let cr = CallRef {
                            id: eid(e),
                            call: c,
                        };
                        if nested_values && let Some(v) = self.value_key(cr, root) {
                            others.insert(v);
                            continue;
                        }
                        if let Some(source) = call_source(c, self.type_map, self.aliases) {
                            let ranks = lane_ranks(source);
                            for lane in 0..3 {
                                if i32::from(ranks[lane]) > best_rank[lane] {
                                    best[lane] = Some(source);
                                    best_rank[lane] = i32::from(ranks[lane]);
                                }
                            }
                            continue;
                        }
                        let targets = self.index.call_targets(cr);
                        for &g in &targets.results {
                            let k = self.ret_key(g);
                            others.insert(k);
                        }
                        if opaque_lambdas && let Expr::Lambda(l) = &*c.func {
                            queue.push_back(Node::Expr(&l.body));
                        }
                    }
                    Expr::Attribute(_) => {
                        if let Some(a) = attr_ref(e)
                            && let Some(view) = self.index.attribute_view(a)
                        {
                            others.insert(view);
                        }
                    }
                    Expr::Lambda(_) if opaque_lambdas => continue,
                    _ => {}
                }
            }
            queue.extend(child_nodes(child));
        }
        if best[0].is_none() {
            let sub = credential_subscript(node, self.aliases);
            best = [sub; 3];
        }
        let mut lanes_of: Vec<(usize, u8)> = Vec::new();
        for (lane, source) in best.iter().enumerate() {
            let Some(source) = source else { continue };
            match lanes_of.iter_mut().find(|(s, _)| s == source) {
                Some(entry) => entry.1 |= 1 << lane,
                None => lanes_of.push((*source, 1 << lane)),
            }
        }
        Scan {
            names: names.keys,
            others: others.keys,
            sources: lanes_of,
        }
    }

    fn assign(&mut self, node: &'a StmtAssign, scope: usize) {
        let Scan {
            names,
            others,
            sources,
        } = self.scan(&node.value, scope, false, false);
        let mut plain: Vec<usize> = Vec::new();
        let mut attributes: Vec<usize> = Vec::new();
        for target in &node.targets {
            let elements: Vec<&'a Expr> = match target {
                Expr::Tuple(t) => t.elts.iter().collect(),
                other => vec![other],
            };
            for element in elements {
                if let Some(n) = name_ref(element) {
                    if let Some(&key) = self.index.name_key.get(&n.id) {
                        plain.push(key);
                        if self.index.scopes[scope].kind == CLASS {
                            self.class_attribute(scope, &nm(n.name.id.as_str()), key);
                        }
                    }
                } else if let Some(a) = attr_ref(element)
                    && let Some(store) = self.index.attribute_store(a)
                {
                    attributes.push(store);
                }
            }
        }
        let line = self.line_of(node);
        let all_reads: Vec<usize> = names.iter().chain(&others).copied().collect();
        if !sources.is_empty() {
            for &(source, lanes) in &sources {
                let work = self.mark_targets(&plain, ASSIGN, line, (source, line), false, lanes);
                self.worklist.extend(work);
            }
            self.seed(&attributes, ASSIGN, line, &sources);
            let targets: Vec<usize> = plain.iter().chain(&attributes).copied().collect();
            self.add_flow(&all_reads, &targets, ASSIGN, line, false);
        } else {
            self.add_flow(&names, &plain, ASSIGN, line, true);
            self.add_flow(&others, &plain, ASSIGN, line, false);
            self.add_flow(&all_reads, &attributes, ASSIGN, line, false);
        }
    }

    /// A name assigned in a class body is also the class's attribute.
    fn class_attribute(&mut self, scope: usize, name: &str, key: usize) {
        let Some(class_def) = self.index.scopes[scope].class_def else {
            return;
        };
        let Some(cls) = self.index.class_defs[class_def].cls else {
            return;
        };
        if !self.class_links.insert((scope, name.to_owned())) {
            return;
        }
        let store = self.index.class_body_store(cls, name);
        self.add_flow(&[key], &[store], PASS, 0, false);
    }

    fn returned(&mut self, value: &'a Expr, scope: usize, line: u32) {
        let Some(function) = self.index.scopes[scope].function else {
            return;
        };
        let Some(group) = self.index.functions[function].group else {
            return;
        };
        let target = self.ret_key(group);
        let Scan {
            names,
            others,
            sources,
        } = self.scan(value, scope, false, false);
        self.seed(&[target], RETURN, line, &sources);
        let reads: Vec<usize> = names.iter().chain(&others).copied().collect();
        self.add_flow(&reads, &[target], RETURN, line, false);
    }

    fn call(&mut self, node: CallRef<'a>, scope: usize) {
        let targets = self.index.call_targets(node);
        let value = self.values.get(&node.id).copied();
        if targets.members.is_empty() && value.is_none() {
            return;
        }
        let mut parts: Vec<&'a Expr> = node
            .call
            .args
            .iter()
            .map(|a| match a {
                Expr::Starred(s) => &*s.value,
                other => other,
            })
            .collect();
        parts.extend(node.call.keywords.iter().map(|k| &k.value));
        let scans: Vec<Scan> = parts
            .into_iter()
            .map(|p| self.scan(p, scope, true, false))
            .collect();
        let line = self.line_of(node.call);
        if let Some(value) = value {
            let mut reads: Vec<usize> = Vec::new();
            for s in &scans {
                reads.extend(&s.names);
                reads.extend(&s.others);
                self.seed(&[value], ASSIGN, line, &s.sources);
            }
            for &g in &targets.results {
                let k = self.ret_key(g);
                reads.push(k);
            }
            self.add_flow(&reads, &[value], ASSIGN, line, false);
        }
        if !targets.members.is_empty() {
            self.bind_arguments(node, &targets.members, &scans, line);
        }
    }

    /// Binds a call's arguments into each callee's slots.
    fn bind_arguments(
        &mut self,
        node: CallRef<'a>,
        members: &[(usize, usize)],
        scans: &[Scan],
        line: u32,
    ) {
        let mut slots: Vec<Vec<usize>> = Vec::new();
        let mut starred_at: Option<usize> = None;
        for (position, arg) in node.call.args.iter().enumerate() {
            if starred_at.is_none() && matches!(arg, Expr::Starred(_)) {
                starred_at = Some(position);
            }
            let mut keys = Vec::new();
            for &(group, offset) in members {
                let slot = match starred_at {
                    Some(at) => SlotKey::Star((at + offset).min(MAX_POSITIONAL_SLOTS)),
                    None if position + offset >= MAX_POSITIONAL_SLOTS => {
                        SlotKey::Star(MAX_POSITIONAL_SLOTS)
                    }
                    None => SlotKey::Pos(position + offset),
                };
                keys.push(self.slot(group, slot));
            }
            slots.push(keys);
        }
        for keyword in &node.call.keywords {
            let mut keys = Vec::new();
            if keyword.arg.is_none() && self.forwards_kwargs(&keyword.value) {
                slots.push(keys);
                continue;
            }
            for &(group, offset) in members {
                match &keyword.arg {
                    None => keys.push(self.slot(group, SlotKey::Map(offset))),
                    Some(arg) => {
                        let arg = nm(arg.as_str());
                        self.index.signature(group);
                        let g = &self.index.groups[group];
                        let named = g.named.as_ref().is_some_and(|n| n.contains(&arg));
                        let kw_rest = g.kwarg_named.as_ref().is_some_and(|k| !k.contains(&arg));
                        if named {
                            keys.push(self.slot(group, SlotKey::Kw(arg)));
                        }
                        if kw_rest {
                            keys.push(self.slot(group, SlotKey::KwRest));
                        }
                    }
                }
            }
            slots.push(keys);
        }
        for (keys, scan) in slots.iter().zip(scans) {
            self.seed(keys, BIND, line, &scan.sources);
            let reads: Vec<usize> = scan.names.iter().chain(&scan.others).copied().collect();
            self.add_flow(&reads, keys, BIND, line, false);
        }
    }

    /// Whether `**value` forwards a function's own `**kwargs` parameter.
    fn forwards_kwargs(&self, value: &Expr) -> bool {
        matches!(value, Expr::Name(_))
            && self
                .index
                .name_key
                .get(&eid(value))
                .is_some_and(|k| self.index.kwarg_params.contains(k))
    }

    fn slot(&mut self, group: usize, slot: SlotKey) -> usize {
        if let Some(&k) = self.index.groups[group].slots.get(&slot) {
            return k;
        }
        let k = self
            .index
            .synthetic(IdKey::Slot(group, slot.clone()), true, "");
        self.index.groups[group].slots.insert(slot, k);
        k
    }

    fn defaults(&mut self, function: usize) {
        let node = self.index.functions[function].node;
        let args = node.args();
        let scope = self.index.functions[function].scope;
        let defining = self.index.scopes[scope]
            .parent
            .unwrap_or(ScopeIndex::MODULE_SCOPE);
        let pairs: Vec<(&'a str, &'a Expr)> = args
            .posonlyargs
            .iter()
            .chain(&args.args)
            .chain(&args.kwonlyargs)
            .filter_map(|a| a.default.as_deref().map(|d| (a.def.arg.as_str(), d)))
            .collect();
        for (arg, default) in pairs {
            let target = self.index.key(scope, &nm(arg));
            let Scan {
                names,
                others,
                sources,
            } = self.scan(default, defining, false, true);
            let line = self.line_of(default);
            self.seed(&[target], ASSIGN, line, &sources);
            let reads: Vec<usize> = names.iter().chain(&others).copied().collect();
            self.add_flow(&reads, &[target], ASSIGN, line, false);
        }
    }

    /// Flows each callee's argument slots into the parameters they bind.
    fn link_callees(&mut self) {
        for g in 0..self.index.groups.len() {
            if self.index.groups[g].slots.is_empty() {
                continue;
            }
            let slots = self.index.groups[g].slots.clone();
            let stars: Vec<(usize, usize)> = (0..=MAX_POSITIONAL_SLOTS)
                .filter_map(|s| slots.get(&SlotKey::Star(s)).map(|&k| (s, k)))
                .collect();
            let mappings: Vec<(usize, usize)> = (0..=1)
                .filter_map(|o| slots.get(&SlotKey::Map(o)).map(|&k| (o, k)))
                .collect();
            let rest = slots.get(&SlotKey::KwRest).copied();
            for f in self.index.groups[g].functions.clone() {
                let args = self.index.functions[f].node.args();
                let scope = self.index.functions[f].scope;
                let positional: Vec<&'a str> = args
                    .posonlyargs
                    .iter()
                    .chain(&args.args)
                    .map(|a| a.def.arg.as_str())
                    .collect();
                let posonly = args.posonlyargs.len();
                for (position, arg) in positional.iter().enumerate() {
                    let mut reads: Vec<usize> = slots
                        .get(&SlotKey::Pos(position))
                        .copied()
                        .into_iter()
                        .collect();
                    reads.extend(
                        stars
                            .iter()
                            .filter(|(s, _)| *s <= position)
                            .map(|&(_, k)| k),
                    );
                    if position >= posonly {
                        reads.extend(slots.get(&SlotKey::Kw(nm(arg))).copied());
                        reads.extend(
                            mappings
                                .iter()
                                .filter(|(o, _)| *o <= position)
                                .map(|&(_, k)| k),
                        );
                    }
                    let target = self.index.key(scope, &nm(arg));
                    self.add_flow(&reads, &[target], PASS, 0, false);
                }
                for arg in &args.kwonlyargs {
                    let name = nm(arg.def.arg.as_str());
                    let mut reads: Vec<usize> = slots
                        .get(&SlotKey::Kw(name.clone()))
                        .copied()
                        .into_iter()
                        .collect();
                    reads.extend(mappings.iter().map(|&(_, k)| k));
                    let target = self.index.key(scope, &name);
                    self.add_flow(&reads, &[target], PASS, 0, false);
                }
                if let Some(vararg) = &args.vararg {
                    let mut reads: Vec<usize> = stars.iter().map(|&(_, k)| k).collect();
                    reads.extend(
                        (positional.len()..MAX_POSITIONAL_SLOTS)
                            .filter_map(|i| slots.get(&SlotKey::Pos(i)).copied()),
                    );
                    let target = self.index.key(scope, &nm(vararg.arg.as_str()));
                    self.add_flow(&reads, &[target], PASS, 0, false);
                }
                if let Some(kwarg) = &args.kwarg {
                    let mut reads: Vec<usize> = rest.into_iter().collect();
                    reads.extend(mappings.iter().map(|&(_, k)| k));
                    let target = self.index.key(scope, &nm(kwarg.arg.as_str()));
                    self.add_flow(&reads, &[target], PASS, 0, false);
                }
            }
        }
    }

    /// `self.x` reads see `self.x` stores in the class and its in-file bases, and the class-body
    /// `x` of the nearest of them whose body binds `x` in any way.
    fn link_attributes(&mut self) {
        for i in 0..self.index.attributes.len() {
            let a = self.index.attributes[i];
            self.index.attribute_view(a);
        }
        for i in 0..self.index.view_list.len() {
            let (cls, attr, view) = self.index.view_list[i].clone();
            let mut reads = Vec::new();
            let mut shadowed = false;
            for owner in self.index.ancestors(cls) {
                if let Some(&store) = self.index.ids.get(&IdKey::Store(owner, attr.clone())) {
                    reads.push(store);
                }
                if !shadowed {
                    if let Some(&body) = self.index.ids.get(&IdKey::Class(owner, attr.clone())) {
                        reads.push(body);
                        shadowed = true;
                    } else if self.index.classes[owner].defs.iter().any(|&d| {
                        self.index.scopes[self.index.class_defs[d].scope]
                            .bound
                            .contains(&attr)
                    }) {
                        shadowed = true;
                    }
                }
            }
            self.add_flow(&reads, &[view], PASS, 0, false);
        }
    }

    fn build(&mut self) {
        for (view, class_key, module_key) in self.index.class_reads.clone() {
            self.add_flow(&[module_key], &[view], PASS, 0, true);
            self.add_flow(&[class_key], &[view], PASS, 0, true);
        }
        for i in 0..self.index.statements.len() {
            let (stmt, scope) = self.index.statements[i];
            match stmt {
                StmtRef::Assign(a) => self.assign(a, scope),
                StmtRef::Return(r) => {
                    if let Some(v) = &r.value {
                        let line = self.line_of(r);
                        self.returned(v, scope, line);
                    }
                }
                StmtRef::Call(c) => self.call(c, scope),
            }
        }
        for f in 0..self.index.functions.len() {
            self.defaults(f);
        }
        self.link_attributes();
        self.link_callees();
    }

    pub fn run(&mut self) {
        self.build();
        self.propagate();
    }

    fn propagate(&mut self) {
        let mut a = std::mem::take(&mut self.worklist);
        self.drain(&mut a, false);
        self.phase_a_keys = self.facts.order[0][FIRST_LANE].iter().copied().collect();
        let mut worklist: VecDeque<Work> = self.facts.order[0][FIRST_LANE]
            .iter()
            .map(|&k| (k, 0, ALL_LANES))
            .collect();
        for i in 0..self.seeds.len() {
            let (targets, kind, line, fact, lanes) = {
                let s = &self.seeds[i];
                (s.targets.clone(), s.kind, s.line, s.fact, s.lanes)
            };
            let work = self.mark_targets(&targets, kind, line, fact, false, lanes);
            worklist.extend(work);
        }
        self.drain(&mut worklist, true);
    }

    fn drain(&mut self, worklist: &mut VecDeque<Work>, with_b: bool) {
        if self.fired.len() < self.flows.len() {
            self.fired.resize(self.flows.len(), 0);
        }
        while let Some((key, slot, lanes)) = worklist.pop_front() {
            let mut carried: Vec<(u32, u8)> = Vec::new();
            for lane in 0..3 {
                if lanes >> lane & 1 == 0 {
                    continue;
                }
                let Some(fact) = self.facts.get(slot, lane, key) else {
                    continue;
                };
                match carried.iter_mut().find(|(f, _)| *f == fact) {
                    Some(entry) => entry.1 |= 1 << lane,
                    None => carried.push((fact, 1 << lane)),
                }
            }
            for (fact_id, fact_lanes) in carried {
                let fact = self.facts.content(fact_id);
                let ranks = lane_ranks(fact.0);
                let mut want = 0u32;
                for (lane, &rank) in ranks.iter().enumerate() {
                    if fact_lanes >> lane & 1 == 1 {
                        want |= 1 << (6 * lane + 2 * usize::from(rank) + slot);
                    }
                }
                let mut ids: Vec<usize> = self.prop_a.get(&key).cloned().unwrap_or_default();
                if with_b {
                    ids.extend(self.prop_b.get(&key).into_iter().flatten());
                }
                for flow_id in ids {
                    let mark = self.fired[flow_id];
                    let todo_bits = want & !mark;
                    if todo_bits == 0 {
                        continue;
                    }
                    let (kind, line) = (self.flows[flow_id].kind, self.flows[flow_id].line);
                    if slot == 1 && kind == RETURN {
                        continue;
                    }
                    self.fired[flow_id] = mark | todo_bits;
                    let todo = u8::from(todo_bits & 0x3F != 0)
                        | (u8::from(todo_bits & 0xFC0 != 0) << 1)
                        | (u8::from(todo_bits & 0x3000 != 0) << 2);
                    let targets = std::mem::take(&mut self.flows[flow_id].targets);
                    let work = self.mark_targets(&targets, kind, line, fact, slot == 1, todo);
                    self.flows[flow_id].targets = targets;
                    worklist.extend(work);
                }
            }
        }
    }

    // ── results ──

    /// The most severe fact at `key` for `lane` (an ordinary one on ties).
    fn fact(&self, key: usize, lane: usize) -> Option<u32> {
        let ordinary = self.facts.get(0, lane, key);
        let bound = self.facts.get(1, lane, key);
        match (ordinary, bound) {
            (Some(o), Some(b)) => {
                let rank = |f: u32| lane_ranks(self.facts.content(f).0)[lane];
                if rank(b) > rank(o) { Some(b) } else { Some(o) }
            }
            (None, b) => b,
            (o, None) => o,
        }
    }

    /// The fact a sink of `lane` reports for `key`.
    #[must_use]
    pub fn cited(&self, key: usize, sink_name: &str, lane: usize) -> Option<Fact> {
        let ranked = self.fact(key, lane)?;
        if let Some(first) = self.fact(key, FIRST_LANE)
            && first != ranked
        {
            let rule = |f: u32| pick_rule(source_name(self.facts.content(f).0), sink_name, false);
            if rule(ranked) == rule(first) {
                return Some(self.facts.content(first));
            }
        }
        Some(self.facts.content(ranked))
    }

    /// Tainted variables by readable name (module globals keep their bare name).
    #[cfg(test)]
    #[must_use]
    pub fn tainted_names(&self) -> Vec<(String, TaintedVar)> {
        let mut result: Vec<(String, TaintedVar)> = Vec::new();
        let keys = self.facts.order[0][0].iter().chain(&self.facts.order[1][0]);
        for &key in keys {
            let Some(scope) = self.index.key_scope[key] else {
                continue;
            };
            let Some(fact) = self.fact(key, 0) else {
                continue;
            };
            let name = &self.index.key_name[key];
            let label = match self.index.scopes[scope].kind {
                super::scope::MODULE => name.clone(),
                CLASS => format!("{}.{name}", self.index.qualname(scope)),
                _ => format!("{}.<locals>.{name}", self.index.qualname(scope)),
            };
            if result.iter().any(|(l, _)| *l == label) {
                continue;
            }
            let (source, lineno) = self.facts.content(fact);
            result.push((
                label,
                TaintedVar {
                    name: name.clone(),
                    source_call: source_name(source),
                    lineno,
                },
            ));
        }
        result
    }

    /// The lane a sink reads (`1` for code execution and deserialization).
    #[must_use]
    pub fn sink_lane(sink_name: &str) -> usize {
        usize::from(is_exec_sink(sink_name) || is_deserialization_sink(sink_name))
    }
}
