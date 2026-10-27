//! `SKILL.md` frontmatter manifest, projected like `build_context._parse_manifest`.
//!
//! SkillSpector keeps a fixed-shape dict (`name`, `description`, `version`, `triggers`,
//! `permissions`, `allowed-tools`, `parameters`); RP1/RP2 scan `str(manifest)`, so this module
//! also renders that dict the way Python's `repr` does.
//! Gaps: PyYAML's YAML 1.1 scalars (`yes`, dates, octals), duplicate keys and the 10k-node /
//! depth-64 parser ceilings are not modelled; such manifests may differ.

use crate::matcher::Pat;
use crate::skill::SourceFile;
use crate::unicode::{is_printable, is_space};
use serde_yaml::Value;
use std::fmt::Write as _;
use std::sync::LazyLock;

const MAX_FRONTMATTER_BYTES: usize = 256 * 1024;
const MAX_OUTPUT_RECORDS: usize = 1_024;
const MAX_OUTPUT_CHARS: usize = 256 * 1024;

static FRONTMATTER_END: LazyLock<Pat> = LazyLock::new(|| Pat::new(r"\n---\s*\n", ""));

/// A Python value as far as the manifest needs it.
#[derive(Clone, Debug, PartialEq)]
pub enum PyVal {
    None,
    Bool(bool),
    Int(String),
    Float(f64),
    Str(String),
    List(Vec<PyVal>),
    Dict(Vec<(String, PyVal)>),
}

/// The projected manifest.
#[derive(Clone, Debug, PartialEq)]
pub struct Manifest {
    pub name: Option<String>,
    /// `version`, always text (`_scalar_text`).
    pub version: Option<String>,
    /// The projected `permissions` list.
    pub permissions: Vec<String>,
    /// The projected `allowed-tools` list.
    pub allowed_tools: Vec<String>,
    /// `str(manifest)`.
    pub text: String,
}

/// Python's `repr(str)`.
#[must_use]
pub fn py_str_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if is_printable(c) => out.push(c),
            c if u32::from(c) < 0x100 => {
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            }
            c if u32::from(c) < 0x10000 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => {
                let _ = write!(out, "\\U{:08x}", u32::from(c));
            }
        }
    }
    out.push(quote);
    out
}

/// Python's `repr(float)` / `str(float)`.
#[must_use]
pub fn py_float_repr(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf" } else { "-inf" }.into();
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0.0" } else { "0.0" }.into();
    }
    let sci = format!("{:e}", f.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let sign = if f < 0.0 { "-" } else { "" };
    if (-4..16).contains(&exp) {
        if exp >= 0 {
            let int_len = usize::try_from(exp).unwrap_or(0) + 1;
            let padded = format!("{digits:0<int_len$}");
            let (int, frac) = padded.split_at(int_len);
            format!("{sign}{int}.{}", if frac.is_empty() { "0" } else { frac })
        } else {
            format!(
                "{sign}0.{}{digits}",
                "0".repeat(usize::try_from(-exp - 1).unwrap_or(0))
            )
        }
    } else {
        let frac = if digits.len() > 1 {
            format!(".{}", &digits[1..])
        } else {
            String::new()
        };
        format!(
            "{sign}{}{frac}e{}{:02}",
            &digits[..1],
            if exp < 0 { '-' } else { '+' },
            exp.abs()
        )
    }
}

impl PyVal {
    /// Python's `repr`.
    #[must_use]
    pub fn repr(&self) -> String {
        match self {
            Self::None => "None".into(),
            Self::Bool(b) => if *b { "True" } else { "False" }.into(),
            Self::Int(i) => i.clone(),
            Self::Float(f) => py_float_repr(*f),
            Self::Str(s) => py_str_repr(s),
            Self::List(v) => format!(
                "[{}]",
                v.iter().map(Self::repr).collect::<Vec<_>>().join(", ")
            ),
            Self::Dict(d) => format!(
                "{{{}}}",
                d.iter()
                    .map(|(k, v)| format!("{}: {}", py_str_repr(k), v.repr()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    /// Python's `str` for scalars.
    fn scalar_text(&self) -> Option<String> {
        match self {
            Self::Str(s) => Some(s.clone()),
            Self::Int(i) => Some(i.clone()),
            Self::Float(f) => Some(py_float_repr(*f)),
            Self::Bool(b) => Some(if *b { "True" } else { "False" }.into()),
            _ => None,
        }
    }
}

fn convert(v: &Value) -> Option<PyVal> {
    Some(match v {
        Value::Null => PyVal::None,
        Value::Bool(b) => PyVal::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                PyVal::Int(i.to_string())
            } else if let Some(u) = n.as_u64() {
                PyVal::Int(u.to_string())
            } else {
                PyVal::Float(n.as_f64()?)
            }
        }
        Value::String(s) => PyVal::Str(s.clone()),
        Value::Sequence(s) => PyVal::List(s.iter().map(convert).collect::<Option<_>>()?),
        Value::Mapping(m) => PyVal::Dict(
            m.iter()
                .map(|(k, v)| Some((k.as_str()?.to_owned(), convert(v)?)))
                .collect::<Option<_>>()?,
        ),
        Value::Tagged(_) => return None,
    })
}

/// Output-size accounting of `_project_manifest._consume`.
#[derive(Default)]
struct Budget {
    records: usize,
    chars: usize,
}

impl Budget {
    fn consume(&mut self, text: &str) -> Option<()> {
        self.records += 1;
        self.chars += text.chars().count();
        (self.records <= MAX_OUTPUT_RECORDS && self.chars <= MAX_OUTPUT_CHARS).then_some(())
    }

    fn charge(&mut self, v: &PyVal) -> Option<()> {
        match v {
            PyVal::None => self.consume(""),
            PyVal::List(items) => {
                self.consume("")?;
                items.iter().try_for_each(|i| self.charge(i))
            }
            PyVal::Dict(items) => {
                self.consume("")?;
                items.iter().try_for_each(|(k, v)| {
                    self.consume(k)?;
                    self.charge(v)
                })
            }
            scalar => self.consume(&scalar.scalar_text().unwrap_or_default()),
        }
    }
}

fn string_list(v: Option<&PyVal>, budget: &mut Budget) -> Option<Vec<PyVal>> {
    match v {
        None | Some(PyVal::None) => Some(Vec::new()),
        Some(PyVal::List(items)) => items
            .iter()
            .map(|i| {
                let t = i.scalar_text()?;
                budget.consume(&t)?;
                Some(PyVal::Str(t))
            })
            .collect(),
        Some(_) => None,
    }
}

fn is_ws(c: char) -> bool {
    is_space(c)
}

/// `allowed_tools.iter_allowed_tools_entries`.
fn allowed_tools_entries(value: &str) -> Vec<String> {
    let mut seps: Vec<(usize, usize, bool)> = Vec::new(); // start, end, is_comma
    let mut in_spec = false;
    let mut iter = value.char_indices().peekable();
    while let Some((i, c)) = iter.next() {
        if is_ws(c) {
            let mut end = i + c.len_utf8();
            while let Some(&(j, d)) = iter.peek() {
                if !is_ws(d) {
                    break;
                }
                end = j + d.len_utf8();
                iter.next();
            }
            if !in_spec {
                seps.push((i, end, false));
            }
            continue;
        }
        let end = i + c.len_utf8();
        match c {
            ')' if in_spec => {
                let next = value[end..].chars().next();
                if next.is_none_or(|n| n == ',' || is_ws(n)) {
                    in_spec = false;
                }
            }
            '(' if !in_spec => in_spec = true,
            ',' if !in_spec => seps.push((i, end, true)),
            _ => {}
        }
    }
    let comma_form = seps.iter().any(|s| s.2);
    let mut out = Vec::new();
    let mut start = 0;
    for &(s, e, is_comma) in &seps {
        if comma_form && !is_comma {
            continue;
        }
        let entry = value[start..s].trim_matches(is_ws);
        if !entry.is_empty() || comma_form {
            out.push(entry.to_owned());
        }
        start = e;
    }
    let entry = value[start..].trim_matches(is_ws);
    if !entry.is_empty() || comma_form {
        out.push(entry.to_owned());
    }
    out
}

fn project(data: &[(String, PyVal)]) -> Option<Manifest> {
    let get = |k: &str| data.iter().find(|(key, _)| key == k).map(|(_, v)| v);
    let mut budget = Budget::default();
    let mut out: Vec<(String, PyVal)> = Vec::new();
    let mut name = None;
    for key in ["name", "description"] {
        match get(key) {
            None | Some(PyVal::None) => {}
            Some(PyVal::Str(s)) => {
                budget.consume(s)?;
                if key == "name" {
                    name = Some(s.clone());
                }
                out.push((key.into(), PyVal::Str(s.clone())));
            }
            Some(_) => return None,
        }
    }
    let mut version = None;
    if let Some(v) = get("version").filter(|v| **v != PyVal::None) {
        let t = v.scalar_text()?;
        budget.consume(&t)?;
        version = Some(t.clone());
        out.push(("version".into(), PyVal::Str(t)));
    }
    out.push((
        "triggers".into(),
        PyVal::List(string_list(get("triggers"), &mut budget)?),
    ));
    out.push((
        "permissions".into(),
        PyVal::List(string_list(get("permissions"), &mut budget)?),
    ));
    let tools = match get("allowed-tools") {
        Some(PyVal::Str(s)) => {
            let mut v = Vec::new();
            for item in allowed_tools_entries(s)
                .into_iter()
                .filter(|i| !i.is_empty())
            {
                budget.consume(&item)?;
                v.push(PyVal::Str(item));
            }
            v
        }
        Some(l @ PyVal::List(_)) => string_list(Some(l), &mut budget)?
            .into_iter()
            .filter_map(|i| match i {
                PyVal::Str(s) => Some(s.trim_matches(is_ws).to_owned()),
                _ => None,
            })
            .filter(|s| !s.is_empty())
            .map(PyVal::Str)
            .collect(),
        _ => Vec::new(),
    };
    out.push(("allowed-tools".into(), PyVal::List(tools)));
    let mut params = Vec::new();
    if let Some(PyVal::List(items)) = get("parameters") {
        for item in items {
            if matches!(item, PyVal::Dict(_)) {
                budget.charge(item)?;
                params.push(item.clone());
            }
        }
    }
    out.push(("parameters".into(), PyVal::List(params)));
    let list_of = |key: &str| -> Vec<String> {
        match out.iter().find(|(k, _)| k == key) {
            Some((_, PyVal::List(items))) => items.iter().filter_map(PyVal::scalar_text).collect(),
            _ => Vec::new(),
        }
    };
    Some(Manifest {
        name,
        version,
        permissions: list_of("permissions"),
        allowed_tools: list_of("allowed-tools"),
        text: PyVal::Dict(out).repr(),
    })
}

/// `_parse_manifest`: `None` when SkillSpector would return `{}`.
#[must_use]
pub fn parse_manifest(files: &[SourceFile]) -> Option<Manifest> {
    let file = ["SKILL.md", "skill.md"]
        .iter()
        .find_map(|n| files.iter().find(|f| f.rel == *n))?;
    let cut = &file.bytes[..file.bytes.len().min(MAX_FRONTMATTER_BYTES)];
    let content = String::from_utf8_lossy(cut);
    let content = content.trim_start_matches('\u{feff}');
    let body = content.strip_prefix("---")?;
    let end = FRONTMATTER_END.find_iter(body).into_iter().next()?;
    let value: Value = serde_yaml::from_str(&body[..end.start]).ok()?;
    let Value::Mapping(map) = &value else {
        return None;
    };
    const USED: [&str; 7] = [
        "name",
        "description",
        "version",
        "triggers",
        "permissions",
        "allowed-tools",
        "parameters",
    ];
    let mut data: Vec<(String, PyVal)> = Vec::new();
    for (k, v) in map {
        let Some(key) = k.as_str() else { continue };
        match convert(v) {
            Some(p) => data.push((key.to_owned(), p)),
            None if USED.contains(&key) => return None,
            None => {}
        }
    }
    project(&data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skill::Skill;

    fn manifest(frontmatter: &str) -> Option<Manifest> {
        let text = format!("---\n{frontmatter}\n---\nbody\n");
        Skill::from_memory(vec![("SKILL.md".into(), text.into_bytes())]).manifest
    }

    #[test]
    fn str_repr_matches_python() {
        assert_eq!(py_str_repr("a'b"), "\"a'b\"");
        assert_eq!(py_str_repr("a'b\"c"), "'a\\'b\"c'");
        assert_eq!(py_str_repr("tab\there\n"), "'tab\\there\\n'");
        assert_eq!(py_str_repr("\u{200b}\u{e9}\x07"), "'\\u200b\u{e9}\\x07'");
        assert_eq!(py_str_repr("\u{1f600}"), "'\u{1f600}'");
        assert_eq!(py_str_repr("\u{e0001}"), "'\\U000e0001'");
    }

    #[test]
    fn float_repr_matches_python() {
        for (f, s) in [
            (1.0, "1.0"),
            (0.5, "0.5"),
            (1e16, "1e+16"),
            (1.5e-5, "1.5e-05"),
            (0.0001, "0.0001"),
            (123456.789, "123456.789"),
            (-2.5, "-2.5"),
            (1e15, "1000000000000000.0"),
        ] {
            assert_eq!(py_float_repr(f), s);
        }
    }

    #[test]
    fn manifest_repr_is_python_dict() {
        let m = manifest(
            "name: x\ndescription: it's\nversion: 1.0\nallowed-tools: Read, Bash(git status:*)",
        )
        .unwrap();
        assert_eq!(
            m.text,
            "{'name': 'x', 'description': \"it's\", 'version': '1.0', 'triggers': [], 'permissions': [], \
             'allowed-tools': ['Read', 'Bash(git status:*)'], 'parameters': []}"
        );
        assert_eq!(m.version.as_deref(), Some("1.0"));
    }

    #[test]
    fn manifest_rejects_bad_shapes() {
        assert!(manifest("name: [a]").is_none());
        assert!(manifest("triggers: foo").is_none());
        assert!(manifest("triggers: [a, [b]]").is_none());
        assert!(manifest("just text: [").is_none());
        assert!(
            Skill::from_memory(vec![("SKILL.md".into(), b"no frontmatter".to_vec())])
                .manifest
                .is_none()
        );
    }

    #[test]
    fn allowed_tools_split() {
        assert_eq!(
            allowed_tools_entries("Bash(git status:*) Read"),
            ["Bash(git status:*)", "Read"]
        );
        assert_eq!(allowed_tools_entries("a, b ,"), ["a", "b", ""]);
        assert_eq!(allowed_tools_entries("Read(./a, b)"), ["Read(./a, b)"]);
    }

    #[test]
    fn parameters_are_kept() {
        let m = manifest("parameters:\n  - name: p\n    default: 1\n    type: string\n  - skip")
            .unwrap();
        assert!(
            m.text
                .ends_with("'parameters': [{'name': 'p', 'default': 1, 'type': 'string'}]}")
        );
    }
}
