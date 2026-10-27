//! Context checks of `static_patterns_rogue_agent.py`: negated safety constraints, signed companion
//! CLI updates and nearby skill-install context. All offsets are byte offsets into the text.

use crate::matcher::Pat;
use crate::unicode::is_space;
use std::sync::LazyLock;

const COMMAND_COMPOSITION: &str = r"(?:&&|\|\||[;&|#<>]|\$\(|<\(|>\()";
const LINE_BREAK_CLASS: &str = r"\r\n\x0b\x0c\x1c\x1d\x1e\x85  ";
const MAX_COMPANION_UPDATE_LINE_CHARS: usize = 4_096;
const MAX_SKILL_INSTALL_CONTEXT_CHARS: usize = 4_096;

const NON_COMPANION_UPDATE_SUBJECTS: [&str; 23] = [
    "agent",
    "assistant",
    "bash",
    "cli",
    "cmd",
    "command",
    "env",
    "exec",
    "fish",
    "itself",
    "node",
    "perl",
    "powershell",
    "pwsh",
    "python",
    "ruby",
    "self",
    "sh",
    "skill",
    "skillspector",
    "sudo",
    "tool",
    "zsh",
];
const CLI_EXECUTABLE_EXTENSIONS: [&str; 11] = [
    ".exe", ".cmd", ".bat", ".com", ".ps1", ".sh", ".py", ".pyw", ".js", ".mjs", ".cjs",
];
const CLI_ROLE_SUFFIXES: [&str; 8] = ["-cli", "_cli", ".cli", "cli", "-ctl", "_ctl", ".ctl", "ctl"];
const PROTECTED_UPDATE_SUBJECT_PARTS: [&str; 6] = [
    "agent",
    "assistant",
    "self",
    "skill",
    "skillspector",
    "tool",
];

/// Source of the hidden-directory write pattern (RA2), which the analyzer compares against.
pub fn hidden_directory_write_pattern() -> String {
    format!(
        r"(?:create|write|mkdir)(?:[ \t]|\\\r?\n)+(?:[^|&;{LINE_BREAK_CLASS}]|\\\r?\n)*(?:~/|/home/|/tmp/)\.(?!git|ssh|aws)[a-z_-]+"
    )
}

fn re(src: &str, flags: &str) -> Pat {
    Pat::new(src, flags)
}

static VERIFY_SIGNATURE_FLAG: LazyLock<Pat> =
    LazyLock::new(|| re(r"\A--verify-signature(?:=(?P<value>1|on|true|yes))?\z", "i"));
static DISABLE_SIGNATURE: LazyLock<Pat> = LazyLock::new(|| {
    re(
        r"(?<!\S)--no-verify-signature(?=\s|$)|(?<!\S)--verify-signature(?:=|\s+)(?:0|false|no|off)(?=\s|$)",
        "i",
    )
});
static SIGNED_RELEASE: LazyLock<Pat> =
    LazyLock::new(|| re(r"\bsigned\s+(?:cli\s+)?release\b", "i"));
static SIGNED_RELEASE_NEGATION: LazyLock<Pat> = LazyLock::new(|| {
    re(
        r"\b(?:not|without)\s+(?:an?\s+)?signed\s+(?:cli\s+)?release\b|\bexcept\s+(?:for\s+)?(?:an?\s+)?signed\s+(?:cli\s+)?release\b|\b(?:never|do\s+not|don't)\b[^\n]{0,40}\bsigned\s+(?:cli\s+)?release\b",
        "i",
    )
});
static COMPOSITION: LazyLock<Pat> = LazyLock::new(|| re(COMMAND_COMPOSITION, ""));
static COMPANION_CLI: LazyLock<Pat> =
    LazyLock::new(|| re(r"\A(?P<cli>[a-z0-9][\w.-]{1,63})\s+\z", "i"));
pub static STANDARD_SKILL_MKDIR: LazyLock<Pat> = LazyLock::new(|| {
    re(
        r#"\A[ \t]*mkdir[ \t]+(?:(?:-p|--parents)[ \t]+)?(?:--[ \t]+)?(?P<quote>['"]?)(?P<target>~/\.(?:claude|codex|gemini)/skills(?:/[a-zA-Z0-9][a-zA-Z0-9_.-]*)?)/?(?P=quote)[ \t]*\z"#,
        "",
    )
});
static SKILLS_ROOT: LazyLock<Pat> = LazyLock::new(|| {
    re(
        r"\.(?:claude|codex|gemini)\b|/skills\b|\bskills/|\$(?:\{|\(|[A-Za-z_@*])",
        "i",
    )
});
const SKILL_INSTALL_PATH_SRC: &str = r"(?:~/|\$(?:HOME|\{HOME\})/|/home/[^/\s]+/)(?P<relative>\.(?:claude|codex|gemini)/skills(?:/[a-zA-Z0-9][a-zA-Z0-9_.-]*)*)/?";
static SKILL_INSTALL_PATH: LazyLock<Pat> =
    LazyLock::new(|| re(&format!(r"\A{SKILL_INSTALL_PATH_SRC}\z"), ""));
static CLONE_URL: LazyLock<Pat> = LazyLock::new(|| {
    re(
        r"\A(?:(?:https?|git|ssh)://[a-zA-Z0-9._~:/%@+-]+|[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:[a-zA-Z0-9._~/-]+)\z",
        "",
    )
});
static NEGATION_PREFIX: &str = r"(?:must\s+not|do\s+not|don't|never|should\s+not)\s+(?:(?:ever|again|directly|intentionally|explicitly|attempt\s+to|try\s+to)\s+){0,2}";

/// Every pattern of this file with its flags, for the compile test.
#[cfg(test)]
pub fn all_patterns() -> Vec<(String, &'static str)> {
    vec![
        (hidden_directory_write_pattern(), "im"),
        (COMMAND_COMPOSITION.to_owned(), ""),
        (
            r"\A--verify-signature(?:=(?P<value>1|on|true|yes))?\z".into(),
            "i",
        ),
        (r"\A(?P<cli>[a-z0-9][\w.-]{1,63})\s+\z".into(), "i"),
        (format!(r"\A{SKILL_INSTALL_PATH_SRC}\z"), ""),
        (format!("{NEGATION_PREFIX}x$"), "i"),
    ]
}

/// Python `s[:n]` by characters.
fn take_chars(s: &str, n: usize) -> &str {
    super::common::cut_chars(s, n)
}

/// Logical line starts and ends (`_logical_line_metadata`).
pub struct Lines {
    pub starts: Vec<usize>,
    pub ends: Vec<usize>,
}

impl Lines {
    #[must_use]
    pub fn new(text: &str) -> Self {
        let mut starts = vec![0];
        let mut ends = Vec::new();
        for (s, e) in crate::text::line_breaks(text) {
            ends.push(s);
            starts.push(e);
        }
        ends.push(text.len());
        Self { starts, ends }
    }

    /// Zero-based line index holding `byte` (`bisect_right(starts, byte) - 1`).
    #[must_use]
    pub fn index_of(&self, byte: usize) -> usize {
        self.starts
            .partition_point(|&s| s <= byte)
            .saturating_sub(1)
    }

    /// Source-line bounds around `byte`.
    #[must_use]
    pub fn bounds(&self, byte: usize) -> (usize, usize) {
        let i = self.index_of(byte);
        (self.starts[i], self.ends[i])
    }
}

/// `_is_negated_safety_constraint`: the RA1 phrase is forbidden ("must not ...") in policy prose.
#[must_use]
pub fn is_negated_safety_constraint(text: &str, start: usize, end: usize, lines: &Lines) -> bool {
    let (line_start, line_end) = lines.bounds(start);
    let line = &text[line_start..line_end];
    let local_start = start - line_start;
    let phrase = take_chars(&line[local_start..], text[start..end].chars().count());
    let trimmed = phrase.trim_matches(is_space);
    if trimmed.is_empty() {
        return false;
    }
    let clause_start = line[..local_start].rfind(['.', ';', ':']).map(|p| p + 1);
    let prefix = &line[clause_start.unwrap_or(0)..local_start];
    let pattern = format!("{NEGATION_PREFIX}{}$", regex::escape(trimmed));
    let Ok(pat) = Pat::try_new(&pattern, "i") else {
        return false;
    };
    !pat.find_iter(&format!("{prefix}{phrase}")).is_empty()
}

/// `_strip_cli_subject_affixes`.
fn strip_cli_subject_affixes(subject: &str) -> String {
    let mut stem = subject.to_lowercase();
    let mut changed = true;
    while changed {
        changed = false;
        if let Some(ext) = CLI_EXECUTABLE_EXTENSIONS
            .iter()
            .find(|e| stem.ends_with(**e))
        {
            stem.truncate(stem.len() - ext.len());
            changed = true;
        }
        if let Some(sfx) = CLI_ROLE_SUFFIXES
            .iter()
            .find(|s| stem.len() > s.len() && stem.ends_with(**s))
        {
            stem.truncate(stem.len() - sfx.len());
            changed = true;
        }
    }
    stem
}

/// `_is_protected_update_subject`: fail closed when the subject may denote the skill or its agent.
fn is_protected_update_subject(subject: &str) -> bool {
    if !subject.is_ascii() {
        return true;
    }
    let stem = strip_cli_subject_affixes(subject);
    let collapsed: String = stem.chars().filter(|c| !"-_.".contains(*c)).collect();
    if NON_COMPANION_UPDATE_SUBJECTS.contains(&collapsed.as_str())
        || collapsed.starts_with("python")
    {
        return true;
    }
    stem.split(['-', '_', '.'])
        .any(|p| !p.is_empty() && PROTECTED_UPDATE_SUBJECT_PARTS.contains(&p))
}

/// `_enclosing_inline_code_span`: the simple backtick pair around `[start, end)`.
fn enclosing_inline_code_span(line: &str, start: usize, end: usize) -> Option<(usize, usize)> {
    let marks: Vec<usize> = line.match_indices('`').map(|(i, _)| i).collect();
    if marks.len() % 2 == 1 {
        return None;
    }
    marks
        .chunks(2)
        .find(|p| p[0] < start && end <= p[1])
        .map(|p| (p[0], p[1]))
}

/// `_is_signed_companion_cli_update` for a `self-update` match in Markdown or text.
#[must_use]
pub fn is_signed_companion_cli_update(text: &str, start: usize, end: usize, lines: &Lines) -> bool {
    if text[start..end].to_lowercase() != "self-update" {
        return false;
    }
    let (line_start, line_end) = lines.bounds(start);
    let line = &text[line_start..line_end];
    if line.chars().count() > MAX_COMPANION_UPDATE_LINE_CHARS {
        return false;
    }
    let (local_start, local_end) = (start - line_start, end - line_start);
    let Some((code_start, code_end)) = enclosing_inline_code_span(line, local_start, local_end)
    else {
        return false;
    };
    let command = &line[code_start + 1..code_end];
    if !COMPOSITION.find_iter(command).is_empty() {
        return false;
    }
    let (cmd_start, cmd_end) = (local_start - code_start - 1, local_end - code_start - 1);
    let Some(cli) = COMPANION_CLI
        .find_iter(&command[..cmd_start])
        .into_iter()
        .next()
        .and_then(|h| h.group(&command[..cmd_start], 1).map(str::to_lowercase))
    else {
        return false;
    };
    if is_protected_update_subject(&cli) || !DISABLE_SIGNATURE.find_iter(command).is_empty() {
        return false;
    }
    let tail = command[cmd_end..].trim_matches(is_space);
    let Some(flag) = VERIFY_SIGNATURE_FLAG.find_iter(tail).into_iter().next() else {
        return false;
    };
    let value = flag.group(tail, 1).unwrap_or("true").to_lowercase();
    let clause_start = line[..code_start]
        .rfind(['.', ';', '!', '?'])
        .map_or(0, |p| p + 1);
    let after = code_end + 1;
    let clause_end = line
        .get(after..)
        .and_then(|rest| rest.find(['.', ';', '!', '?']))
        .map_or(line.len(), |p| p + after);
    let next_code = line
        .get(after..)
        .and_then(|r| r.find('`'))
        .map(|p| p + after);
    let negation_end = next_code.unwrap_or(line.len());
    matches!(value.as_str(), "1" | "on" | "true" | "yes")
        && !SIGNED_RELEASE
            .find_iter(&line[clause_start..clause_end.max(clause_start)])
            .is_empty()
        && SIGNED_RELEASE_NEGATION
            .find_iter(&line[clause_start..negation_end.max(clause_start)])
            .is_empty()
}

/// Python `shlex.split(line, posix=True)`; `None` where it raises `ValueError`.
fn shlex_split(line: &str) -> Option<Vec<String>> {
    let chars: Vec<char> = line.chars().collect();
    let (mut out, mut token, mut started, mut i) = (Vec::new(), String::new(), false, 0);
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        match c {
            ' ' | '\t' | '\r' | '\n' => {
                if started {
                    out.push(std::mem::take(&mut token));
                    started = false;
                }
            }
            '\\' => {
                token.push(*chars.get(i)?);
                i += 1;
                started = true;
            }
            '\'' => {
                started = true;
                loop {
                    let ch = *chars.get(i)?;
                    i += 1;
                    if ch == '\'' {
                        break;
                    }
                    token.push(ch);
                }
            }
            '"' => {
                started = true;
                loop {
                    let ch = *chars.get(i)?;
                    i += 1;
                    match ch {
                        '"' => break,
                        '\\' => {
                            let next = *chars.get(i)?;
                            i += 1;
                            if next != '"' && next != '\\' {
                                token.push('\\');
                            }
                            token.push(next);
                        }
                        _ => token.push(ch),
                    }
                }
            }
            _ => {
                token.push(c);
                started = true;
            }
        }
    }
    if started {
        out.push(token);
    }
    Some(out)
}

fn install_relative(path: &str) -> Option<String> {
    let hit = SKILL_INSTALL_PATH.find_iter(path).into_iter().next()?;
    hit.group(path, 1).map(str::to_owned)
}

/// `_is_simple_skill_clone`: only `git clone <literal URL> <target or child>`.
fn is_simple_skill_clone(line: &str, target: &str) -> bool {
    if !COMPOSITION.find_iter(line).is_empty() || line.contains('`') {
        return false;
    }
    let Some(tokens) = shlex_split(line) else {
        return false;
    };
    if tokens.len() != 4 || tokens[0] != "git" || tokens[1] != "clone" {
        return false;
    }
    if CLONE_URL.find_iter(&tokens[2]).is_empty() {
        return false;
    }
    let (Some(dest), Some(created)) = (install_relative(&tokens[3]), install_relative(target))
    else {
        return false;
    };
    dest == created || dest.starts_with(&format!("{created}/"))
}

fn has_non_whitespace(s: &str) -> bool {
    s.chars().any(|c| !is_space(c))
}

/// `_unsafe_skill_install_context`: the span to report instead of a plain `mkdir`, or `None` when
/// every neighbouring line is independent of the skills root.
#[must_use]
pub fn unsafe_skill_install_context(
    text: &str,
    mkdir_line_start: usize,
    target: &str,
    lines: &Lines,
) -> Option<(usize, usize)> {
    let radius = MAX_SKILL_INSTALL_CONTEXT_CHARS / 2;
    let idx = lines.index_of(mkdir_line_start);
    let ctx_start = text[..mkdir_line_start]
        .char_indices()
        .rev()
        .nth(radius - 1)
        .map_or(0, |(i, _)| i);
    let ctx_end = text[mkdir_line_start..]
        .char_indices()
        .nth(radius)
        .map_or(text.len(), |(i, _)| mkdir_line_start + i);
    let evidence = Some((mkdir_line_start, lines.ends[idx])).filter(|(s, e)| s < e);
    for forward in [true, false] {
        let mut at = idx;
        loop {
            at = if forward {
                at + 1
            } else if at == 0 {
                break;
            } else {
                at - 1
            };
            if at >= lines.starts.len() {
                break;
            }
            let (s, e) = (lines.starts[at], lines.ends[at]);
            if s >= ctx_end || e <= ctx_start {
                let beyond = if forward {
                    has_non_whitespace(&text[ctx_end..])
                } else {
                    has_non_whitespace(&text[..ctx_start])
                };
                if beyond {
                    return evidence;
                }
                break;
            }
            if s < ctx_start || e > ctx_end {
                return evidence;
            }
            let line = &text[s..e];
            if !SKILLS_ROOT.find_iter(line).is_empty() && !is_simple_skill_clone(line, target) {
                return Some((s, e)).filter(|(a, b)| a < b);
            }
        }
    }
    None
}
