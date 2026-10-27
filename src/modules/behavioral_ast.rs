//! AST1-AST10 from `behavioral_ast.py` (`_analyze_python`): dangerous execution patterns found by
//! walking the Python tree. One finding per call or subscript node, with character columns.

use crate::finding::RawFinding;
use crate::issue::Severity;
use crate::pyast::names::ident;
use crate::pyast::{
    Aliases, Node, PyFile, ast, get_complete_source_segment, resolve_call_name,
    resolve_dynamic_import_call, walk,
};
use crate::runner::StaticModule;
use crate::skill::FileType;
use ast::{Constant, Expr, ExprCall, Ranged};

const TAG: &str = "Dangerous Code Execution";
const DANGEROUS_GETATTR: [&str; 5] = ["exec", "eval", "system", "popen", "__import__"];
const MAX_NAME_LEN: usize = 10; // len("__import__")
const DICT_READS: [&str; 3] = ["get", "setdefault", "pop"];
const SUBPROCESS: [&str; 7] = [
    "call",
    "run",
    "Popen",
    "check_output",
    "check_call",
    "getoutput",
    "getstatusoutput",
];
const OS_EXEC: [&str; 20] = [
    "system",
    "popen",
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "posix_spawn",
    "posix_spawnp",
];
const DESERIALIZERS: [&str; 14] = [
    "pickle.load",
    "pickle.loads",
    "cPickle.load",
    "cPickle.loads",
    "_pickle.load",
    "_pickle.loads",
    "marshal.load",
    "marshal.loads",
    "dill.load",
    "dill.loads",
    "jsonpickle.decode",
    "pandas.read_pickle",
    "joblib.load",
    "yaml.unsafe_load",
];
const SAFE_LOADERS: [&str; 3] = ["SafeLoader", "CSafeLoader", "BaseLoader"];

/// (message, severity, confidence).
fn rule(id: &str) -> (&'static str, Severity, f32) {
    match id {
        "AST1" => ("exec() call detected", Severity::High, 0.85),
        "AST2" => ("eval() call detected", Severity::High, 0.85),
        "AST3" => ("Dynamic import via __import__()", Severity::Medium, 0.75),
        "AST4" => ("subprocess module call", Severity::Medium, 0.70),
        "AST5" => ("os.system() or os exec-family call", Severity::High, 0.85),
        "AST6" => ("compile() call detected", Severity::Medium, 0.65),
        "AST7" => (
            "Dynamic attribute access via getattr()",
            Severity::Low,
            0.50,
        ),
        "AST8" => ("Dangerous execution chain", Severity::Critical, 0.95),
        "AST9" => (
            "Reflective dangerous call via getattr() with a literal sink name",
            Severity::High,
            0.85,
        ),
        _ => (
            "Insecure deserialization of untrusted data",
            Severity::Medium,
            0.70,
        ),
    }
}

fn str_const(e: &Expr) -> Option<&str> {
    match e {
        Expr::Constant(c) => match &c.value {
            Constant::Str(s) => Some(s),
            _ => None,
        },
        _ => None,
    }
}

/// `_constant_string`: a string literal or a short `"sep".join([literals])`.
fn constant_string(e: &Expr) -> Option<String> {
    if let Some(s) = str_const(e) {
        return Some(s.to_owned());
    }
    let Expr::Call(call) = e else { return None };
    let Expr::Attribute(attr) = &*call.func else {
        return None;
    };
    let sep = str_const(&attr.value).filter(|_| attr.attr.as_str() == "join")?;
    let [arg] = call.args.as_slice() else {
        return None;
    };
    let (Expr::List(ast::ExprList { elts, .. }) | Expr::Tuple(ast::ExprTuple { elts, .. })) = arg
    else {
        return None;
    };
    let parts: Vec<String> = elts.iter().map(constant_string).collect::<Option<_>>()?;
    let total: usize = parts.iter().map(|p| p.chars().count()).sum::<usize>()
        + sep.chars().count() * parts.len().saturating_sub(1);
    (total <= MAX_NAME_LEN).then(|| parts.join(sep))
}

/// `_contains_dangerous_source`: the first nested call (walk order) that forms a chain.
fn dangerous_source(arg: &Expr, aliases: &Aliases) -> Option<String> {
    // `walk` takes statements: wrap a clone of the operand.
    let wrapper = ast::Stmt::Expr(ast::StmtExpr {
        range: arg.range(),
        value: Box::new(arg.clone()),
    });
    let mut found = None;
    walk(std::slice::from_ref(&wrapper), |n| {
        if found.is_some() {
            return;
        }
        let Node::Expr(Expr::Call(c)) = n else { return };
        let Some(name) = resolve_call_name(c, Some(aliases)) else {
            return;
        };
        let hit = matches!(name.as_str(), "compile" | "__import__")
            || name.starts_with("subprocess.")
            || name.starts_with("os.")
            || ["base64", "codecs", "marshal", "urllib", "requests", "httpx"]
                .iter()
                .any(|p| name.contains(p));
        if hit {
            found = Some(name);
        }
    });
    found
}

fn loader_name(e: &Expr) -> Option<String> {
    match e {
        Expr::Attribute(a) => Some(ident(a.attr.as_str()).into_owned()),
        Expr::Name(n) => Some(ident(n.id.as_str()).into_owned()),
        _ => None,
    }
}

fn is_safe_loader(e: &Expr) -> bool {
    loader_name(e).is_some_and(|n| SAFE_LOADERS.contains(&n.as_str()))
}

fn is_true(e: &Expr) -> bool {
    matches!(e, Expr::Constant(c) if matches!(c.value, Constant::Bool(true)))
}

fn kwarg<'a>(call: &'a ExprCall, name: &str) -> Option<&'a Expr> {
    call.keywords
        .iter()
        .find(|k| k.arg.as_ref().is_some_and(|a| ident(a.as_str()) == name))
        .map(|k| &k.value)
}

/// `_deserialization_message`.
fn deserialization_message(name: &str, call: &ExprCall) -> Option<String> {
    if DESERIALIZERS.contains(&name) {
        return Some(format!("Insecure deserialization: {name}()"));
    }
    match name {
        "yaml.load" => {
            if let Some(l) = kwarg(call, "Loader") {
                return if is_safe_loader(l) {
                    None
                } else {
                    Some("Insecure deserialization: yaml.load() with an unsafe Loader".into())
                };
            }
            if call.args.get(1).is_some_and(is_safe_loader) {
                return None;
            }
            Some("Insecure deserialization: yaml.load() without SafeLoader".into())
        }
        "torch.load" => (!kwarg(call, "weights_only").is_some_and(is_true))
            .then(|| "Insecure deserialization: torch.load() without weights_only=True".into()),
        "numpy.load" => (kwarg(call, "allow_pickle").is_some_and(is_true)
            || call.args.get(2).is_some_and(is_true))
        .then(|| "Insecure deserialization: numpy.load(allow_pickle=True)".into()),
        _ => None,
    }
}

/// `_reflective_module_dict_container`: `mod.__dict__` / `vars(mod)` of an imported plain module.
fn module_dict_container(container: &Expr, aliases: &Aliases) -> Option<String> {
    let base = match container {
        Expr::Attribute(a) if a.attr.as_str() == "__dict__" => &*a.value,
        Expr::Call(c)
            if c.args.len() == 1
                && matches!(&*c.func, Expr::Name(n) if ident(n.id.as_str()) == "vars") =>
        {
            &c.args[0]
        }
        _ => return None,
    };
    let Expr::Name(n) = base else { return None };
    let resolved = aliases.get(ident(n.id.as_str()).as_ref())?;
    (!resolved.contains('.')).then(|| resolved.clone())
}

struct Emitter<'a> {
    py: &'a PyFile,
    path: &'a str,
    out: Vec<RawFinding>,
}

impl Emitter<'_> {
    fn emit(&mut self, index: usize, id: &'static str, node: &impl Ranged, msg: Option<String>) {
        let (default_msg, severity, confidence) = rule(id);
        let p = self.py.char_pos(node.range());
        let segment = self.py.node_segment(node).map_or_else(
            || get_complete_source_segment(&self.py.lines, p.line, Some(p.end_line)),
            str::to_owned,
        );
        let mut f = RawFinding::new(
            id,
            msg.unwrap_or_else(|| default_msg.to_owned()),
            severity,
            confidence,
            self.path,
            p.line,
        );
        f.end_line = Some(p.end_line);
        f.start_column = p.col;
        f.end_column = p.end_col;
        f.tags = vec![TAG.to_owned()];
        f.matched_text = Some(segment.chars().take(200).collect());
        f.fingerprint_text = Some(segment);
        if p.col.is_none() || p.end_col.is_none() {
            f.evidence
                .insert("python_ast_node_index".into(), index.to_string());
        }
        self.out.push(f);
    }

    fn dict_access(
        &mut self,
        index: usize,
        node: &impl Ranged,
        key: &Expr,
        module: &str,
        how: &str,
    ) {
        match key {
            Expr::Constant(c) => {
                if matches!(&c.value, Constant::Str(s) if DANGEROUS_GETATTR.contains(&s.as_str())) {
                    let m = format!(
                        "Reflective dangerous access via {module}.__dict__{how} with a literal sink name"
                    );
                    self.emit(index, "AST9", node, Some(m));
                }
            }
            _ => {
                let m = format!("Dynamic attribute access via {module}.__dict__{how}");
                self.emit(index, "AST7", node, Some(m));
            }
        }
    }

    fn call(&mut self, index: usize, call: &ExprCall, aliases: &Aliases) {
        if let Expr::Attribute(a) = &*call.func
            && DICT_READS.contains(&a.attr.as_str())
            && let Some(key) = call.args.first()
            && let Some(module) = module_dict_container(&a.value, aliases)
        {
            let how = format!(".{}()", a.attr);
            self.dict_access(index, call, key, &module, &how);
            return;
        }
        let name = resolve_call_name(call, Some(aliases))
            .or_else(|| resolve_dynamic_import_call(call, Some(aliases)));
        let Some(name) = name else { return };
        match name.as_str() {
            "exec" | "eval" => {
                if let Some(arg) = call.args.first()
                    && let Some(source) = dangerous_source(arg, aliases)
                {
                    let m = format!("Dangerous chain: {name}() wrapping {source}");
                    self.emit(index, "AST8", call, Some(m));
                }
                self.emit(
                    index,
                    if name == "exec" { "AST1" } else { "AST2" },
                    call,
                    None,
                );
            }
            "__import__" => self.emit(index, "AST3", call, None),
            "compile" => self.emit(index, "AST6", call, None),
            n if n.starts_with("subprocess.") => {
                if SUBPROCESS.contains(&&n["subprocess.".len()..]) {
                    self.emit(index, "AST4", call, None);
                }
            }
            n if n.starts_with("os.") => {
                if OS_EXEC.contains(&&n["os.".len()..]) {
                    self.emit(index, "AST5", call, None);
                }
            }
            n => {
                if let Some(m) = deserialization_message(n, call) {
                    self.emit(index, "AST10", call, Some(m));
                } else if n == "getattr" && call.args.len() >= 2 {
                    self.getattr(index, call);
                }
            }
        }
    }

    fn getattr(&mut self, index: usize, call: &ExprCall) {
        let second = &call.args[1];
        if matches!(second, Expr::Constant(c) if !matches!(c.value, Constant::Str(_))) {
            return;
        }
        match constant_string(second) {
            Some(s) if DANGEROUS_GETATTR.contains(&s.as_str()) => {
                self.emit(index, "AST9", call, None);
            }
            r if r.is_none() || !matches!(second, Expr::Constant(_)) => {
                self.emit(index, "AST7", call, None);
            }
            _ => {}
        }
    }
}

/// `_analyze_python`.
fn analyze_python(py: &PyFile, path: &str) -> Vec<RawFinding> {
    let Some(tree) = py.tree.as_deref() else {
        return Vec::new();
    };
    let aliases = &py.import_aliases;
    let mut em = Emitter {
        py,
        path,
        out: Vec::new(),
    };
    let mut index = 0usize;
    walk(tree, |node| {
        let i = index;
        index += 1;
        match node {
            Node::Expr(Expr::Subscript(s)) => {
                if let Some(module) = module_dict_container(&s.value, aliases) {
                    em.dict_access(i, s, &s.slice, &module, " subscript");
                }
            }
            Node::Expr(Expr::Call(c)) => em.call(i, c, aliases),
            _ => {}
        }
    });
    em.out
}

/// AST1-AST10.
pub struct BehavioralAst;

impl StaticModule for BehavioralAst {
    fn id(&self) -> &'static str {
        "behavioral_ast"
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

#[cfg(test)]
mod tests;
