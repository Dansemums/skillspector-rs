//! Source and sink name sets, rule choice and the leaf helpers of `behavioral_taint_tracking.py`
//! (lines 75-420).

use crate::issue::Severity;
use crate::pyast::ast::{Constant, Expr, ExprCall};
use crate::pyast::names::{
    Aliases, apply_import_aliases, ident, resolve_call_name_typed, resolve_dotted_name,
    resolve_dynamic_import_call,
};
use std::collections::HashMap;
use std::sync::LazyLock;

pub const CREDENTIAL_SOURCES: &[&str] = &["os.environ.get", "os.environ", "os.getenv"];
pub const FILE_READ_SOURCES: &[&str] =
    &["open", "pathlib.Path.read_text", "pathlib.Path.read_bytes"];
pub const NETWORK_INPUT_SOURCES: &[&str] = &[
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.patch",
    "httpx.delete",
    "urllib.request.urlopen",
    "urllib.request.urlretrieve",
    "socket.socket.recv",
    "socket.socket.recvfrom",
];
pub const USER_INPUT_SOURCES: &[&str] = &["input", "sys.stdin.read", "sys.stdin.readline"];

pub const NETWORK_OUTPUT_SINKS: &[&str] = &[
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.get",
    "httpx.post",
    "httpx.put",
    "httpx.patch",
    "httpx.get",
    "urllib.request.urlopen",
    "urllib.request.build_opener.open",
    "socket.socket.send",
    "socket.socket.sendall",
    "socket.socket.sendto",
];
pub const EXEC_SINKS: &[&str] = &[
    "exec",
    "eval",
    "compile",
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_output",
    "subprocess.check_call",
    "subprocess.Popen",
];
pub const FILE_WRITE_SINKS: &[&str] = &[
    "open",
    "pathlib.Path.write_text",
    "pathlib.Path.write_bytes",
    "shutil.copy",
    "shutil.copy2",
    "shutil.copyfile",
];
pub const DESERIALIZATION_SINKS: &[&str] = &[
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

pub const TAG: &str = "Data Flow";
pub const MAX_NAME_CHARS: usize = 120;

#[must_use]
pub fn rule_severity(rule: &str) -> Severity {
    match rule {
        "TT2" => Severity::Medium,
        "TT3" | "TT5" => Severity::Critical,
        _ => Severity::High,
    }
}

#[must_use]
pub fn rule_confidence(rule: &str) -> f32 {
    match rule {
        "TT1" | "TT4" => 0.80,
        "TT2" => 0.65,
        "TT3" | "TT5" => 0.90,
        "TT6" => 0.85,
        _ => 0.0,
    }
}

fn in_set(set: &[&str], name: &str) -> bool {
    set.contains(&name)
}

#[must_use]
pub fn is_credential(name: &str) -> bool {
    in_set(CREDENTIAL_SOURCES, name)
}
#[must_use]
pub fn is_file_read(name: &str) -> bool {
    in_set(FILE_READ_SOURCES, name)
}
#[must_use]
pub fn is_external_input(name: &str) -> bool {
    in_set(NETWORK_INPUT_SOURCES, name) || in_set(USER_INPUT_SOURCES, name)
}
#[must_use]
pub fn is_source(name: &str) -> bool {
    is_credential(name) || is_file_read(name) || is_external_input(name)
}
#[must_use]
pub fn is_network_sink(name: &str) -> bool {
    in_set(NETWORK_OUTPUT_SINKS, name)
}
#[must_use]
pub fn is_exec_sink(name: &str) -> bool {
    in_set(EXEC_SINKS, name)
}
#[must_use]
pub fn is_deserialization_sink(name: &str) -> bool {
    in_set(DESERIALIZATION_SINKS, name)
}
#[must_use]
pub fn is_sink(name: &str) -> bool {
    is_network_sink(name)
        || is_exec_sink(name)
        || in_set(FILE_WRITE_SINKS, name)
        || is_deserialization_sink(name)
}

#[must_use]
pub fn source_category(name: &str) -> &'static str {
    if is_credential(name) {
        "credential/environment"
    } else if is_file_read(name) {
        "file read"
    } else if in_set(NETWORK_INPUT_SOURCES, name) {
        "network input"
    } else if in_set(USER_INPUT_SOURCES, name) {
        "user input"
    } else {
        "data source"
    }
}

#[must_use]
pub fn sink_category(name: &str) -> &'static str {
    if is_network_sink(name) {
        "network output"
    } else if is_exec_sink(name) {
        "code execution"
    } else if in_set(FILE_WRITE_SINKS, name) {
        "file write"
    } else if is_deserialization_sink(name) {
        "deserialization"
    } else {
        "data sink"
    }
}

/// `_pick_rule`.
#[must_use]
pub fn pick_rule(source: &str, sink: &str, is_direct: bool) -> &'static str {
    if is_credential(source) && is_network_sink(sink) {
        "TT3"
    } else if is_file_read(source) && is_network_sink(sink) {
        "TT4"
    } else if is_external_input(source) && is_exec_sink(sink) {
        "TT5"
    } else if is_deserialization_sink(sink) && (is_external_input(source) || is_file_read(source)) {
        "TT6"
    } else if is_direct {
        "TT1"
    } else {
        "TT2"
    }
}

/// `_SOURCE_NAMES`: every source, sorted; a source is its index here.
pub static SOURCE_NAMES: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    let mut all: Vec<&'static str> = [
        CREDENTIAL_SOURCES,
        FILE_READ_SOURCES,
        NETWORK_INPUT_SOURCES,
        USER_INPUT_SOURCES,
    ]
    .concat();
    all.sort_unstable();
    all.dedup();
    all
});

/// `_LANE_RANKS` per source index.
static LANE_RANKS: LazyLock<Vec<[u8; 3]>> = LazyLock::new(|| {
    SOURCE_NAMES
        .iter()
        .map(|n| {
            if is_credential(n) {
                [2, 0, 0]
            } else if is_external_input(n) {
                [0, 2, 0]
            } else {
                [1, 1, 0]
            }
        })
        .collect()
});

#[must_use]
pub fn source_index(name: &str) -> Option<usize> {
    SOURCE_NAMES.binary_search(&name).ok()
}

#[must_use]
pub fn lane_ranks(source: usize) -> [u8; 3] {
    LANE_RANKS.get(source).copied().unwrap_or([0; 3])
}

#[must_use]
pub fn source_name(source: usize) -> &'static str {
    SOURCE_NAMES.get(source).copied().unwrap_or("")
}

/// `str(bytes)` as far as `"w"` / `"a"` membership can tell.
fn bytes_repr(b: &[u8]) -> String {
    let quote = if b.contains(&b'\'') && !b.contains(&b'"') {
        '"'
    } else {
        '\''
    };
    let mut out = format!("b{quote}");
    for &c in b {
        match c {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            c if char::from(c) == quote => {
                out.push('\\');
                out.push(char::from(c));
            }
            0x20..=0x7e => out.push(char::from(c)),
            c => out.push_str(&format!("\\x{c:02x}")),
        }
    }
    out.push(quote);
    out
}

/// `str(constant.value)`, only where it can contain `w` or `a`.
fn constant_str(c: &Constant) -> String {
    match c {
        Constant::Str(s) => s.clone(),
        Constant::Bytes(b) => bytes_repr(b),
        Constant::Bool(b) => if *b { "True" } else { "False" }.to_owned(),
        Constant::None => "None".to_owned(),
        Constant::Ellipsis => "Ellipsis".to_owned(),
        _ => String::new(),
    }
}

/// `_is_open_for_write`: the mode argument mentions `w` or `a`.
#[must_use]
pub fn is_open_for_write(call: &ExprCall) -> bool {
    let writes = |c: &Constant| constant_str(c).chars().any(|ch| ch == 'w' || ch == 'a');
    if call.args.len() >= 2
        && let Expr::Constant(c) = &call.args[1]
    {
        return writes(&c.value);
    }
    for kw in &call.keywords {
        if kw.arg.as_ref().is_some_and(|a| ident(a.as_str()) == "mode")
            && let Expr::Constant(c) = &kw.value
        {
            return writes(&c.value);
        }
    }
    false
}

/// `_call_source`: the source name a call reads, as an index into [`SOURCE_NAMES`].
#[must_use]
pub fn call_source(
    call: &ExprCall,
    type_map: &HashMap<String, String>,
    aliases: &Aliases,
) -> Option<usize> {
    let name = resolve_call_name_typed(call, Some(type_map), Some(aliases))?;
    let index = source_index(&name)?;
    if name == "open" && is_open_for_write(call) {
        return None;
    }
    Some(index)
}

/// `_credential_subscript`: `os.environ["K"]` (aliases applied) as a whole value.
#[must_use]
pub fn credential_subscript(node: &Expr, aliases: &Aliases) -> Option<usize> {
    let Expr::Subscript(sub) = node else {
        return None;
    };
    let base = apply_import_aliases(&resolve_dotted_name(&sub.value)?, aliases);
    if is_credential(&base) {
        source_index(&base)
    } else {
        None
    }
}

/// `_resolve_sink_name`: a call's canonical sink name, dynamic imports and inline openers included.
#[must_use]
pub fn resolve_sink_name(
    call: &ExprCall,
    type_map: &HashMap<String, String>,
    aliases: &Aliases,
) -> Option<String> {
    if let Expr::Attribute(attr) = &*call.func
        && ident(attr.attr.as_str()) == "open"
        && let Expr::Call(inner) = &*attr.value
        && resolve_call_name_typed(inner, Some(type_map), Some(aliases)).as_deref()
            == Some("urllib.request.build_opener")
    {
        return Some("urllib.request.build_opener.open".to_owned());
    }
    resolve_call_name_typed(call, Some(type_map), Some(aliases))
        .or_else(|| resolve_dynamic_import_call(call, Some(aliases)))
}

/// `_shorten`.
#[must_use]
pub fn shorten(name: &str) -> String {
    if name.chars().count() <= MAX_NAME_CHARS {
        return name.to_owned();
    }
    let head: String = name.chars().take(MAX_NAME_CHARS - 3).collect();
    format!("{head}...")
}
