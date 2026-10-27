//! Name resolution over the AST (`analyzers/common.py`: `resolve_dotted_name`, `resolve_call_name`
//! and the import-alias helpers, plus `python_ast.build_import_aliases`).

use super::walk::{Node, walk};
use crate::unicode::nfkc;
use rustpython_parser::ast::{Constant, Expr, ExprCall, Stmt};
use std::borrow::Cow;
use std::collections::HashMap;

/// `{local name: fully-qualified import path}`.
pub type Aliases = HashMap<String, String>;

/// CPython NFKC-normalizes identifiers; rustpython does not. Single-code-point NFKC only
/// (sequences that compose across characters, e.g. base + combining mark, are left as written).
#[must_use]
pub fn ident(s: &str) -> Cow<'_, str> {
    if s.is_ascii() {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match nfkc(c) {
            Some(r) => out.push_str(r),
            None => out.push(c),
        }
    }
    Cow::Owned(out)
}

/// `build_import_aliases`: every `import` / `from ... import` binding, later ones (in `ast.walk`
/// order) winning. Relative-import levels are ignored, as in SkillSpector.
#[must_use]
pub fn build_import_aliases(body: &[Stmt]) -> Aliases {
    let mut aliases = Aliases::new();
    walk(body, |node| {
        let Node::Stmt(stmt) = node else { return };
        match stmt {
            Stmt::Import(imp) => {
                for a in &imp.names {
                    let name = ident(a.name.as_str());
                    let local = a
                        .asname
                        .as_ref()
                        .map_or_else(|| name.clone(), |s| ident(s.as_str()));
                    aliases.insert(local.into_owned(), name.into_owned());
                }
            }
            Stmt::ImportFrom(imp) => {
                let module = imp
                    .module
                    .as_ref()
                    .map_or(Cow::Borrowed(""), |m| ident(m.as_str()));
                for a in &imp.names {
                    let name = ident(a.name.as_str());
                    let local = a
                        .asname
                        .as_ref()
                        .map_or_else(|| name.clone(), |s| ident(s.as_str()));
                    let full = if module.is_empty() {
                        name.into_owned()
                    } else {
                        format!("{module}.{name}")
                    };
                    aliases.insert(local.into_owned(), full);
                }
            }
            _ => {}
        }
    });
    aliases
}

/// `resolve_dotted_name`: `Name` or a chain of `Attribute`s ending in a `Name`.
#[must_use]
pub fn resolve_dotted_name(node: &Expr) -> Option<String> {
    match node {
        Expr::Name(n) => Some(ident(n.id.as_str()).into_owned()),
        Expr::Attribute(_) => {
            let mut parts: Vec<Cow<str>> = Vec::new();
            let mut cur = node;
            while let Expr::Attribute(a) = cur {
                parts.push(ident(a.attr.as_str()));
                cur = &a.value;
            }
            let Expr::Name(n) = cur else { return None };
            parts.push(ident(n.id.as_str()));
            parts.reverse();
            Some(parts.join("."))
        }
        _ => None,
    }
}

/// `_strip_builtins_prefix`: `builtins.exec` -> `exec`, deeper chains untouched.
fn strip_builtins_prefix(name: &str) -> String {
    match name.split_once('.') {
        Some(("builtins", rest)) if !rest.contains('.') => rest.to_owned(),
        _ => name.to_owned(),
    }
}

/// `apply_import_aliases`.
#[must_use]
pub fn apply_import_aliases(name: &str, aliases: &Aliases) -> String {
    if let Some(full) = aliases.get(name) {
        return strip_builtins_prefix(full);
    }
    if let Some((root, rest)) = name.split_once('.')
        && let Some(full) = aliases.get(root)
    {
        return strip_builtins_prefix(&format!("{full}.{rest}"));
    }
    strip_builtins_prefix(name)
}

/// `aliases` as Python's truthiness sees it: `None` and `{}` both skip alias rewriting.
fn effective(aliases: Option<&Aliases>) -> Option<&Aliases> {
    aliases.filter(|a| !a.is_empty())
}

/// `resolve_call_name`.
#[must_use]
pub fn resolve_call_name(call: &ExprCall, aliases: Option<&Aliases>) -> Option<String> {
    let name = resolve_dotted_name(&call.func)?;
    Some(match effective(aliases) {
        Some(a) => apply_import_aliases(&name, a),
        None => name,
    })
}

/// `_dynamic_import_target`: the literal module of `importlib.import_module("mod")`.
fn dynamic_import_target(node: &Expr, aliases: Option<&Aliases>) -> Option<String> {
    let Expr::Call(call) = node else { return None };
    let name = resolve_dotted_name(&call.func)?;
    let name = match effective(aliases) {
        Some(a) => apply_import_aliases(&name, a),
        None => name,
    };
    if name != "importlib.import_module" && name != "import_module" {
        return None;
    }
    match call.args.first()? {
        Expr::Constant(c) => match &c.value {
            Constant::Str(s) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// `resolve_dynamic_import_call`: `importlib.import_module("os").system(...)` -> `os.system`.
#[must_use]
pub fn resolve_dynamic_import_call(call: &ExprCall, aliases: Option<&Aliases>) -> Option<String> {
    let Expr::Attribute(attr) = &*call.func else {
        return None;
    };
    let module = dynamic_import_target(&attr.value, aliases)?;
    Some(format!("{module}.{}", ident(attr.attr.as_str())))
}

/// `build_type_map`: `var = Type(...)` and `with Type() as var` -> `{var: "qualified.Type"}`.
#[must_use]
pub fn build_type_map(body: &[Stmt], aliases: Option<&Aliases>) -> HashMap<String, String> {
    let built;
    let aliases = match aliases {
        Some(a) => a,
        None => {
            built = build_import_aliases(body);
            &built
        }
    };
    let ctor = |call: &ExprCall| -> Option<String> {
        let raw = resolve_dotted_name(&call.func)?;
        let (root, rest) = raw
            .split_once('.')
            .map_or((raw.as_str(), None), |(r, t)| (r, Some(t)));
        let root = aliases.get(root).map_or(root, String::as_str);
        let out = rest.map_or_else(|| root.to_owned(), |t| format!("{root}.{t}"));
        (!out.is_empty()).then_some(out)
    };
    let mut map = HashMap::new();
    walk(body, |node| {
        let Node::Stmt(stmt) = node else { return };
        match stmt {
            Stmt::Assign(a) => {
                let Expr::Call(call) = &*a.value else { return };
                let Some(c) = ctor(call) else { return };
                for t in &a.targets {
                    if let Expr::Name(n) = t {
                        map.insert(ident(n.id.as_str()).into_owned(), c.clone());
                    }
                }
            }
            Stmt::With(w) => {
                for item in &w.items {
                    let (Expr::Call(call), Some(vars)) = (&item.context_expr, &item.optional_vars)
                    else {
                        continue;
                    };
                    if let (Some(c), Expr::Name(n)) = (ctor(call), &**vars) {
                        map.insert(ident(n.id.as_str()).into_owned(), c);
                    }
                }
            }
            _ => {}
        }
    });
    map
}

/// `resolve_call_name_typed`: like [`resolve_call_name`] but maps instance variables to their type.
#[must_use]
pub fn resolve_call_name_typed(
    call: &ExprCall,
    type_map: Option<&HashMap<String, String>>,
    aliases: Option<&Aliases>,
) -> Option<String> {
    let mut plain = resolve_dotted_name(&call.func)?;
    if let Some(a) = effective(aliases) {
        plain = apply_import_aliases(&plain, a);
    }
    if let (Some(map), Some((root, rest))) = (type_map, plain.split_once('.'))
        && let Some(inferred) = map.get(root)
    {
        plain = format!("{inferred}.{rest}");
    }
    Some(plain)
}

/// `get_complete_source_segment`: the lines `lineno..=end_lineno` joined with `\n`.
#[must_use]
pub fn get_complete_source_segment<S: AsRef<str>>(
    lines: &[S],
    lineno: u32,
    end_lineno: Option<u32>,
) -> String {
    let start = (lineno as usize).saturating_sub(1).min(lines.len());
    let end = match end_lineno {
        Some(e) if e != 0 => e as usize,
        _ => lineno as usize,
    }
    .min(lines.len());
    let slice = lines.get(start..end.max(start)).unwrap_or_default();
    slice
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<_>>()
        .join("\n")
}

/// `get_source_segment`: the first 200 characters of [`get_complete_source_segment`].
#[must_use]
pub fn get_source_segment<S: AsRef<str>>(
    lines: &[S],
    lineno: u32,
    end_lineno: Option<u32>,
) -> String {
    get_complete_source_segment(lines, lineno, end_lineno)
        .chars()
        .take(200)
        .collect()
}
