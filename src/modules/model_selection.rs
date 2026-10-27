//! EA5 (external model or provider selection) from `static_patterns_excessive_agency._ea5_findings`:
//! frontmatter `model:`/`provider:` pins and actionable coding-CLI model switches in prose and shell
//! fences. Findings carry exact columns and `selection_surface`/`selection_key` evidence.

use crate::finding::RawFinding;
use crate::issue::Severity;
use crate::matcher::Pat;
use crate::text::{LineIndex, get_context, line_breaks};
use crate::unicode::{is_space, py_split};
use std::collections::HashSet;
use std::sync::LazyLock;

const CATEGORY_TAG: &str = "Excessive Agency";
const MESSAGE: &str = "External Model or Provider Selection";

/// (source, flags) of every EA5 pattern.
const PATTERNS: [(&str, &str); 7] = [
    (
        r#"^["']?(?P<key>model|provider|model_name|model_id)["']?[ \t]*:[ \t]*(?P<value>[^#\s][^#\r\n]*)"#,
        "im",
    ),
    (r"`(?P<command>[^`\r\n]+)`", ""),
    (
        r"^(?:run|execute|invoke|call)(?:[ \t]+the)?(?:[ \t]+command)?[ \t]*:?[ \t]+",
        "i",
    ),
    (
        r"^(?:(?:[-*+]|\d+[.)])[ \t]+)?(?:run|execute|invoke|call)(?:[ \t]+the)?(?:[ \t]+command)?[ \t]*:?[ \t]*$",
        "i",
    ),
    (
        r"^[ \t]*(?P<marker>`{3,}|~{3,})[ \t]*(?P<language>[\w+-]*)",
        "",
    ),
    // `$` of the Python pattern also matches before a final newline.
    (
        r"^(?:claude|gpt|gemini|deepseek|kimi|glm|minimax|mistral|llama)(?:\n?\z|[-_./:0-9])",
        "i",
    ),
    (r"\A\ufeff*---[ \t]*\r?\n", ""),
];

struct Re {
    key: Pat,
    inline: Pat,
    imperative: Pat,
    inline_directive: Pat,
    fence: Pat,
    model_value: Pat,
    opening: Pat,
    closing: Pat,
}

static RE: LazyLock<Re> = LazyLock::new(|| {
    let p = |i: usize| Pat::new(PATTERNS[i].0, PATTERNS[i].1);
    Re {
        key: p(0),
        inline: p(1),
        imperative: p(2),
        inline_directive: p(3),
        fence: p(4),
        model_value: p(5),
        opening: p(6),
        closing: Pat::new(r"^---[ \t]*$", "m"),
    }
});

fn cut_chars(s: &str, n: usize) -> &str {
    s.char_indices().nth(n).map_or(s, |(i, _)| &s[..i])
}

/// `_frontmatter_bounds`: byte offsets of the YAML frontmatter body of a `SKILL.md`.
fn frontmatter_bounds(content: &str, path: &str) -> Option<(usize, usize)> {
    if path.rsplit('/').next()?.to_lowercase() != "skill.md" {
        return None;
    }
    let opening = RE.opening.find_iter(content).into_iter().next()?;
    let closing = RE
        .closing
        .find_iter(&content[opening.end..])
        .into_iter()
        .next()?;
    Some((opening.end, opening.end + closing.start))
}

/// `shlex.split(command, comments=False, posix=True)`; `None` on a quoting error.
fn shlex_split(s: &str) -> Option<Vec<String>> {
    #[derive(Clone, Copy, PartialEq)]
    enum St {
        Space,
        Word,
        Quote(char),
        Escape(Option<char>),
    }
    let ws = |c: char| matches!(c, ' ' | '\t' | '\r' | '\n');
    let mut tokens = Vec::new();
    let (mut token, mut quoted, mut state) = (String::new(), false, St::Space);
    for c in s.chars().map(Some).chain(std::iter::once(None)) {
        match (state, c) {
            (St::Space, None) | (St::Word, None) => {
                if !token.is_empty() || quoted {
                    tokens.push(std::mem::take(&mut token));
                }
                return Some(tokens);
            }
            (St::Quote(_) | St::Escape(_), None) => return None,
            (St::Space, Some(c)) => {
                if ws(c) {
                    if !token.is_empty() || quoted {
                        tokens.push(std::mem::take(&mut token));
                        quoted = false;
                    }
                } else if c == '\\' {
                    state = St::Escape(None);
                } else if c == '\'' || c == '"' {
                    state = St::Quote(c);
                } else {
                    token.push(c);
                    state = St::Word;
                }
            }
            (St::Word, Some(c)) => {
                if ws(c) {
                    state = St::Space;
                    if !token.is_empty() || quoted {
                        tokens.push(std::mem::take(&mut token));
                        quoted = false;
                    }
                } else if c == '\'' || c == '"' {
                    state = St::Quote(c);
                } else if c == '\\' {
                    state = St::Escape(None);
                } else {
                    token.push(c);
                }
            }
            (St::Quote(q), Some(c)) => {
                if c == q {
                    quoted = true;
                    state = St::Word;
                } else if c == '\\' && q == '"' {
                    state = St::Escape(Some(q));
                } else {
                    token.push(c);
                }
            }
            (St::Escape(from), Some(c)) => {
                if let Some(q) = from
                    && c != q
                    && c != '\\'
                {
                    token.push('\\');
                }
                token.push(c);
                state = from.map_or(St::Word, St::Quote);
            }
        }
    }
    Some(tokens)
}

/// `_is_model_switch_command`: whether a shell command selects another coding model/provider.
fn is_model_switch_command(command: &str) -> bool {
    let tokens =
        shlex_split(command).unwrap_or_else(|| py_split(command).map(str::to_owned).collect());
    let Some(first) = tokens.first() else {
        return false;
    };
    let executable = first.rsplit('/').next().unwrap_or("").to_lowercase();
    let rest = &tokens[1..];
    if executable == "claude"
        && rest
            .iter()
            .any(|t| t == "-p" || t == "--print" || t.starts_with("--print="))
    {
        return true;
    }
    if executable == "codex" && rest.first().is_some_and(|t| t.to_lowercase() == "exec") {
        return true;
    }
    if executable.starts_with("python") || matches!(executable.as_str(), "node" | "perl" | "ruby") {
        return false;
    }
    rest.iter().enumerate().any(|(i, token)| {
        let value = if token == "-m" || token == "--model" {
            rest.get(i + 1).map(String::as_str)
        } else if token.starts_with("-m=") || token.starts_with("--model=") {
            token.split_once('=').map(|(_, v)| v)
        } else {
            None
        };
        value.is_some_and(|v| !v.is_empty() && !RE.model_value.find_iter(v).is_empty())
    })
}

/// `_command_span`: byte span of the model-switch command in an actionable instruction line.
fn command_span(line: &str) -> Option<(usize, usize)> {
    if line.contains('`') {
        return None;
    }
    let mut leading = line.len() - line.trim_start_matches([' ', '\t']).len();
    let mut candidate = &line[leading..];
    if candidate.starts_with(['$', '>']) {
        let rest = &candidate[1..];
        let width = 1 + rest.len() - rest.trim_start_matches([' ', '\t']).len();
        leading += width;
        candidate = &candidate[width..];
    }
    let command = candidate.trim_matches(is_space).trim_matches('`');
    if is_model_switch_command(command) {
        let start = leading + line[leading..].find(command)?;
        return Some((start, start + command.len()));
    }
    let imperative = RE.imperative.find_iter(candidate).into_iter().next()?;
    let command = candidate[imperative.end..]
        .trim_matches(is_space)
        .trim_matches('`');
    if is_model_switch_command(command) {
        let from = leading + imperative.end;
        let start = from + line[from..].find(command)?;
        return Some((start, start + command.len()));
    }
    None
}

/// `_inline_command_span`: an inline command only when prose directs its execution.
fn inline_command_span(line: &str, command_span: (usize, usize)) -> Option<(usize, usize)> {
    let raw = &line[command_span.0..command_span.1];
    let command = raw.trim_matches(is_space);
    if RE
        .inline_directive
        .find_iter(&line[..command_span.0.saturating_sub(1)])
        .is_empty()
        || !is_model_switch_command(command)
    {
        return None;
    }
    let offset = command_span.0 + raw.len() - raw.trim_start_matches(is_space).len();
    Some((offset, offset + command.len()))
}

/// Lines with their terminators, like `str.splitlines(keepends=True)`.
fn split_keepends(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    for (_, e) in line_breaks(text) {
        out.push(&text[start..e]);
        start = e;
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

fn located(idx: &LineIndex, text: &str, (a, b): (usize, usize), severity: Severity) -> RawFinding {
    let mut f = RawFinding::new("EA5", MESSAGE, severity, 0.9, "", idx.line(a));
    f.end_line = Some(idx.line(b));
    f.start_column = Some(idx.col_chars(text, a));
    f.end_column = Some(idx.col_chars(text, b));
    f.tags = vec![CATEGORY_TAG.to_owned()];
    f.context = Some(get_context(text, a));
    let full = &text[a..b];
    f.matched_text = Some(cut_chars(full, 200).to_owned());
    f.fingerprint_text = Some(full.to_owned());
    f
}

const EMPTY_VALUES: [&str; 8] = [
    "\"\"", "''", "~", "null", "none", "default", "auto", "inherit",
];

/// `_ea5_findings`.
#[must_use]
pub fn ea5_findings(content: &str, path: &str) -> Vec<RawFinding> {
    let idx = LineIndex::new(content);
    let mut out = Vec::new();
    let bounds = frontmatter_bounds(content, path);
    let mut body_start = 0;
    if let Some((start, end)) = bounds {
        body_start = end;
        let fm = &content[start..end];
        for h in RE.key.find_iter(fm) {
            let value = h
                .group(fm, 2)
                .unwrap_or("")
                .trim_matches(is_space)
                .to_lowercase();
            if EMPTY_VALUES.contains(&value.as_str()) {
                continue;
            }
            let key = h.group(fm, 1).unwrap_or("").to_lowercase();
            let mut f = located(
                &idx,
                content,
                (start + h.start, start + h.end),
                Severity::Medium,
            );
            f.file = path.to_owned();
            f.evidence
                .insert("selection_surface".into(), "frontmatter".into());
            f.evidence.insert("selection_key".into(), key);
            out.push(f);
        }
    }
    let mut seen: HashSet<(usize, usize)> = HashSet::new();
    let mut cursor = body_start;
    let mut fence: Option<char> = None;
    let mut fence_language = String::new();
    for line in split_keepends(&content[body_start..]) {
        let line_text = line.trim_end_matches(['\r', '\n']);
        if let Some(h) = RE
            .fence
            .find_iter(line_text)
            .into_iter()
            .find(|h| h.start == 0)
        {
            let marker = h.group(line_text, 1).and_then(|m| m.chars().next());
            if fence.is_none() {
                fence = marker;
                fence_language = h.group(line_text, 2).unwrap_or("").to_lowercase();
            } else if marker == fence {
                fence = None;
                fence_language.clear();
            }
            cursor += line.len();
            continue;
        }
        let mut candidates = Vec::new();
        let shell = matches!(
            fence_language.as_str(),
            "bash" | "console" | "sh" | "shell" | "zsh"
        );
        if fence.is_none() || shell || fence_language.is_empty() {
            candidates.extend(command_span(line_text));
        }
        for inline in RE.inline.find_iter(line_text) {
            if let Some(g) = inline.groups.get(1).copied().flatten() {
                candidates.extend(inline_command_span(line_text, g));
            }
        }
        for (a, b) in candidates {
            let absolute = (cursor + a, cursor + b);
            if !seen.insert(absolute) {
                continue;
            }
            let mut f = located(&idx, content, absolute, Severity::High);
            f.file = path.to_owned();
            f.evidence
                .insert("selection_surface".into(), "command".into());
            out.push(f);
        }
        cursor += line.len();
    }
    out
}

#[cfg(test)]
/// Every EA5 pattern, for the compile test.
pub fn pattern_sources() -> Vec<(String, &'static str)> {
    let mut v: Vec<_> = PATTERNS
        .iter()
        .map(|(s, f)| ((*s).to_owned(), *f))
        .collect();
    v.push((r"^---[ \t]*$".to_owned(), "m"));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_regexes_compile() {
        for (src, flags) in pattern_sources() {
            Pat::try_new(&src, flags).unwrap_or_else(|e| panic!("{e}"));
        }
    }

    #[test]
    fn shlex_matches_python() {
        let split = |s| shlex_split(s).unwrap_or_default();
        assert_eq!(
            split(r#"a "b c" 'd e' f\ g "" x"#),
            ["a", "b c", "d e", "f g", "", "x"]
        );
        assert_eq!(split(r#"a "b\"c" "d\e""#), ["a", "b\"c", "d\\e"]);
        assert!(shlex_split("a 'b").is_none());
        assert!(shlex_split("a \\").is_none());
        assert_eq!(split("a#b"), ["a#b"]);
    }

    #[test]
    fn model_switch_commands() {
        for c in [
            "claude -p hello",
            "claude --print=x",
            "codex exec foo",
            "tool --model gpt-4o",
            "tool -m=claude-3",
            "/usr/bin/aider --model deepseek/chat",
        ] {
            assert!(is_model_switch_command(c), "{c}");
        }
        for c in [
            "python -m gpt-4",
            "tool --model foo",
            "ls",
            "",
            "tool --model",
        ] {
            assert!(!is_model_switch_command(c), "{c}");
        }
    }

    fn found(content: &str, path: &str) -> Vec<(u32, u32, Option<u32>, String)> {
        ea5_findings(content, path)
            .into_iter()
            .map(|f| {
                (
                    f.start_line,
                    f.start_column.unwrap_or(0),
                    f.end_column,
                    f.evidence["selection_surface"].clone(),
                )
            })
            .collect()
    }

    #[test]
    fn frontmatter_pins() {
        let md =
            "---\nname: x\nmodel: claude-3\nprovider: auto\nmodel_id: \"\"\n---\nbody model: x\n";
        assert_eq!(
            found(md, "SKILL.md"),
            [(3, 0, Some(15), "frontmatter".to_owned())]
        );
        assert!(found(md, "other.md").is_empty());
    }

    #[test]
    fn commands_in_fences_and_inline() {
        let md = "Run `claude -p hi`\n```bash\n$ codex exec x\n```\n```python\nclaude -p x\n```\nSee `claude -p hi`.\nrun: codex exec go\n";
        let got = found(md, "a.md");
        let lines: Vec<u32> = got.iter().map(|g| g.0).collect();
        assert_eq!(lines, [1, 3, 9]);
        assert!(got.iter().all(|g| g.3 == "command"));
    }
}
