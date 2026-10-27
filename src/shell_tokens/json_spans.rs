//! `security_reconstruction.validated_json_string_spans`: the string literals of complete JSON
//! values (a whole file, a front-matter body or a fenced `json` block). Char indices.

use super::markdown::split_keepends;
use serde::de::IgnoredAny;

const MAX_CONTAINER_CHARS: usize = 65_536;

fn is_json(text: &str) -> bool {
    text.chars().count() <= MAX_CONTAINER_CHARS && serde_json::from_str::<IgnoredAny>(text).is_ok()
}

/// `_JsonContainerCursor`.
struct Cursor<'a> {
    line: &'a [char],
    index: usize,
    column: usize,
    pending: usize,
}

impl<'a> Cursor<'a> {
    fn new(line: &'a [char]) -> Self {
        Self {
            line,
            index: 0,
            column: 0,
            pending: 0,
        }
    }

    fn character(&self) -> Option<char> {
        if self.pending > 0 {
            Some(' ')
        } else {
            self.line.get(self.index).copied()
        }
    }

    fn advance(&mut self) {
        if self.pending > 0 {
            self.pending -= 1;
        } else {
            if self.line[self.index] == '\t' {
                self.pending = 3 - self.column % 4;
            }
            self.index += 1;
        }
        self.column += 1;
    }

    fn spaces(&mut self, limit: usize) -> usize {
        let start = self.column;
        while self.column - start < limit && matches!(self.character(), Some(' ' | '\t')) {
            self.advance();
        }
        self.column - start
    }

    fn quote(&mut self) -> bool {
        self.spaces(3);
        if self.character() != Some('>') {
            return false;
        }
        self.advance();
        self.spaces(1);
        true
    }

    fn remainder(&mut self) -> String {
        let start = self.column;
        self.spaces(4);
        let mut out = " ".repeat(self.column - start + self.pending);
        out.extend(&self.line[self.index.min(self.line.len())..]);
        out
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Quote,
    Indent(usize),
}

/// End of a list marker `(?:[-+*]|[0-9]{1,9}[.)])` at `pos`.
fn list_marker_end(s: &[char], pos: usize) -> Option<usize> {
    match s.get(pos)? {
        '-' | '+' | '*' => Some(pos + 1),
        c if c.is_ascii_digit() => {
            let mut i = pos;
            while i < s.len() && i < pos + 9 && s[i].is_ascii_digit() {
                i += 1;
            }
            matches!(s.get(i), Some('.' | ')')).then_some(i + 1)
        }
        _ => None,
    }
}

fn fence_prefix(line: &[char]) -> (String, Vec<Kind>) {
    let mut context = Vec::new();
    let mut c = Cursor::new(line);
    loop {
        let start = (c.index, c.column, c.pending);
        c.spaces(3);
        if c.character() == Some('>') {
            context.push(Kind::Quote);
            c.advance();
            c.spaces(1);
            continue;
        }
        let item = if c.pending > 0 {
            None
        } else {
            list_marker_end(line, c.index)
        };
        if let Some(end) = item {
            c.column += end - c.index;
            c.index = end;
            let padding = c.spaces(5);
            if (1..=4).contains(&padding) {
                context.push(Kind::Indent(c.column - start.1));
                continue;
            }
        }
        (c.index, c.column, c.pending) = start;
        return (c.remainder(), context);
    }
}

fn fence_body(line: &[char], context: &[Kind], last_quote: isize) -> Option<String> {
    let mut c = Cursor::new(line);
    for (index, kind) in context.iter().enumerate() {
        match kind {
            Kind::Quote => {
                if !c.quote() {
                    return None;
                }
            }
            Kind::Indent(width) => {
                if c.spaces(*width) != *width {
                    let blank = line[c.index.min(line.len())..]
                        .iter()
                        .all(|&ch| crate::unicode::is_space(ch));
                    return (isize::try_from(index).unwrap_or(0) > last_quote && blank)
                        .then(|| "\n".to_owned());
                }
            }
        }
    }
    Some(c.remainder())
}

/// `^[ ]{0,3}(`{3,}|~{3,})rest$` with group 1: `(marker, run length, info string)`.
fn fence_line(body: &str, closing: bool) -> Option<(char, usize, String)> {
    let chars: Vec<char> = body.chars().collect();
    let spaces = chars.iter().take_while(|&&c| c == ' ').count();
    if spaces > 3 {
        return None;
    }
    let marker = *chars.get(spaces)?;
    if marker != '`' && marker != '~' {
        return None;
    }
    let run = chars[spaces..].iter().take_while(|&&c| c == marker).count();
    if run < 3 {
        return None;
    }
    let rest: String = chars[spaces + run..].iter().collect();
    let ok = if closing {
        rest.chars().all(|c| c == ' ' || c == '\t')
    } else {
        !rest.contains(['\r', '\n'])
    };
    ok.then_some((marker, run, rest))
}

fn frontmatter_body(text: &[char]) -> Option<usize> {
    let prefix = &text[..text.len().min(MAX_CONTAINER_CHARS)];
    let mut offset = 0;
    if prefix.get(..3)? != ['-', '-', '-'] {
        return None;
    }
    offset += 3;
    while matches!(prefix.get(offset), Some(' ' | '\t')) {
        offset += 1;
    }
    if prefix.get(offset) == Some(&'\r') {
        offset += 1;
    }
    if prefix.get(offset) != Some(&'\n') {
        return None;
    }
    offset += 1;
    for (s, e) in split_keepends(&prefix[offset..]) {
        let line = &prefix[offset + s..offset + e];
        if line.last() == Some(&'\n') {
            let t: String = line.iter().collect();
            let t = t
                .trim_end_matches(['\r', '\n'])
                .trim_end_matches([' ', '\t']);
            if t == "---" || t == "..." {
                return Some(offset + e);
            }
        }
    }
    None
}

fn validated_ranges(text: &[char]) -> Vec<(usize, usize)> {
    let whole: String = text.iter().collect();
    if is_json(&whole) {
        return vec![(0, text.len())];
    }
    if let Some(b) = frontmatter_body(text)
        && is_json(&text[b..].iter().collect::<String>())
    {
        return vec![(b, text.len())];
    }
    let mut ranges = Vec::new();
    let mut fence: Option<(char, usize, Vec<Kind>, bool)> = None;
    let mut body_lines: Vec<String> = Vec::new();
    let mut last_quote: isize = -1;
    let (mut start, mut offset) = (0usize, 0usize);
    for (ls, le) in split_keepends(text) {
        let line = &text[ls..le];
        let mut body: Option<String> = None;
        if let Some(f) = &fence {
            body = fence_body(line, &f.2, last_quote);
            if body.is_none() {
                fence = None;
                body_lines.clear();
            }
        }
        if fence.is_none() {
            let trimmed: Vec<char> = {
                let mut v = line.to_vec();
                while matches!(v.last(), Some('\r' | '\n')) {
                    v.pop();
                }
                v
            };
            let (b, context) = fence_prefix(&trimmed);
            if let Some((marker, run, info)) = fence_line(&b, false)
                && !(marker == '`' && info.contains('`'))
            {
                let language = info.split_whitespace().next();
                last_quote = context
                    .iter()
                    .rposition(|k| *k == Kind::Quote)
                    .map_or(-1, |i| isize::try_from(i).unwrap_or(-1));
                fence = Some((
                    marker,
                    run,
                    context,
                    language.is_some_and(|l| l.to_lowercase() == "json"),
                ));
                start = offset + line.len();
                body_lines.clear();
            }
        } else if let (Some(f), Some(b)) = (&fence, body) {
            let closing = fence_line(b.trim_end_matches(['\r', '\n']), true);
            if closing.is_some_and(|(m, r, _)| m == f.0 && r >= f.1) {
                if f.3 && offset - start <= MAX_CONTAINER_CHARS && is_json(&body_lines.concat()) {
                    ranges.push((start, offset));
                }
                fence = None;
                body_lines.clear();
            } else if offset + line.len() - start <= MAX_CONTAINER_CHARS {
                if f.3 {
                    body_lines.push(b);
                }
            } else {
                body_lines.clear();
            }
        }
        offset += line.len();
    }
    ranges
}

/// Lexes every complete JSON string of `text`: one forward, escape-aware pass.
fn string_spans(text: &[char]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    let mut cursor = 0;
    while cursor < text.len() {
        let c = text[cursor];
        match start {
            None => {
                if c == '"' {
                    start = Some(cursor);
                }
            }
            Some(s) => {
                if c == '\\' {
                    cursor += 1;
                } else if c == '"' {
                    out.push((s, cursor + 1));
                    start = None;
                } else if c == '\r' || c == '\n' {
                    start = None;
                }
            }
        }
        cursor += 1;
    }
    out
}

/// Exact string spans (both quotes included) owned by complete JSON values.
#[must_use]
pub fn validated_json_string_spans(text: &[char]) -> Vec<(usize, usize)> {
    validated_ranges(text)
        .into_iter()
        .flat_map(|(s, e)| {
            string_spans(&text[s..e])
                .into_iter()
                .map(move |(a, b)| (s + a, s + b))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spans(s: &str) -> Vec<(usize, usize)> {
        validated_json_string_spans(&s.chars().collect::<Vec<_>>())
    }

    #[test]
    fn whole_document_and_fenced_json() {
        assert_eq!(spans(r#"{"a": "b"}"#), [(1, 4), (6, 9)]);
        let fenced = "text\n```json\n{\"k\": \"v\"}\n```\n";
        assert_eq!(spans(fenced).len(), 2);
        assert!(spans("```text\n{\"k\": \"v\"}\n```\n").is_empty());
        assert!(spans("{\"a\": ").is_empty());
    }

    #[test]
    fn list_prefix_is_ignored() {
        assert_eq!(spans("- ```json\n  {\"k\": 1}\n  ```\n").len(), 1);
    }
}
