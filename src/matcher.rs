//! Python `re` patterns on Rust engines.
//!
//! A pattern is rewritten (Python `\s` includes U+001C..U+001F, possessive quantifiers become atomic
//! groups, `\Z`, `\uXXXX`, `{,n}`, `(?P=n)`), then compiled with `regex` when it can be and with
//! `fancy_regex` otherwise (lookaround, atomic groups, backreferences).
//! Known gap: `$` without the `m` flag matches only at the very end (Python also before a final `\n`),
//! and `\S` inside a character class is left as is.

use crate::text::paragraph_ranges;

/// One match: byte span plus capture-group spans (index 0 is the whole match).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub start: usize,
    pub end: usize,
    pub groups: Vec<Option<(usize, usize)>>,
}

impl Hit {
    /// The matched text.
    #[must_use]
    pub fn text<'a>(&self, haystack: &'a str) -> &'a str {
        &haystack[self.start..self.end]
    }

    /// Text of capture group `i`, when it participated.
    #[must_use]
    pub fn group<'a>(&self, haystack: &'a str, i: usize) -> Option<&'a str> {
        self.groups
            .get(i)
            .copied()
            .flatten()
            .map(|(s, e)| &haystack[s..e])
    }
}

/// A compiled pattern on whichever engine accepts it.
#[derive(Debug)]
pub enum Pat {
    Fast(regex::Regex),
    Fancy(fancy_regex::Regex),
}

impl Pat {
    /// Compiles `src` (Python syntax) with Python-style `flags` (any of `imsx`).
    ///
    /// # Errors
    /// Fails when neither engine accepts the rewritten pattern.
    pub fn try_new(src: &str, flags: &str) -> Result<Self, String> {
        let rewritten = rewrite(src);
        let flags: String = flags.chars().filter(|c| "imsx".contains(*c)).collect();
        let full = if flags.is_empty() {
            rewritten
        } else {
            format!("(?{flags}){rewritten}")
        };
        match regex::Regex::new(&full) {
            Ok(re) => Ok(Self::Fast(re)),
            Err(_) => fancy_regex::Regex::new(&full)
                .map(Self::Fancy)
                .map_err(|e| format!("{src}: {e}")),
        }
    }

    /// Like [`Pat::try_new`] for patterns checked by tests; a bad pattern never matches.
    #[must_use]
    pub fn new(src: &str, flags: &str) -> Self {
        Self::try_new(src, flags).unwrap_or_else(|_| Self::Fast(never()))
    }

    /// Matches in the whole text, like `finditer(text)`.
    #[must_use]
    pub fn find_iter(&self, text: &str) -> Vec<Hit> {
        self.find_in(text, 0, text.len())
    }

    /// Matches in `text[start..end]` like `finditer(text, start, end)`: the left context stays
    /// visible to `\b` and lookbehind, the text after `end` does not exist.
    #[must_use]
    pub fn find_in(&self, text: &str, start: usize, end: usize) -> Vec<Hit> {
        let hay = &text[..end];
        let mut hits = Vec::new();
        let mut pos = start;
        while pos <= end {
            let Some(hit) = self.hit_at(hay, pos) else {
                break;
            };
            pos = if hit.end == hit.start {
                hay[hit.end..]
                    .chars()
                    .next()
                    .map_or(end + 1, |c| hit.end + c.len_utf8())
            } else {
                hit.end
            };
            hits.push(hit);
        }
        hits
    }

    fn hit_at(&self, hay: &str, pos: usize) -> Option<Hit> {
        match self {
            Self::Fast(re) => {
                let caps = re.captures_at(hay, pos)?;
                let m = caps.get(0)?;
                let groups = caps
                    .iter()
                    .map(|g| g.map(|m| (m.start(), m.end())))
                    .collect();
                Some(Hit {
                    start: m.start(),
                    end: m.end(),
                    groups,
                })
            }
            Self::Fancy(re) => {
                let caps = re.captures_from_pos(hay, pos).ok()??;
                let m = caps.get(0)?;
                let groups = caps
                    .iter()
                    .map(|g| g.map(|m| (m.start(), m.end())))
                    .collect();
                Some(Hit {
                    start: m.start(),
                    end: m.end(),
                    groups,
                })
            }
        }
    }
}

fn never() -> regex::Regex {
    // `[^\s\S]` is valid and matches nothing.
    regex::Regex::new(r"[^\s\S]").unwrap_or_else(|_| unreachable!("constant pattern"))
}

/// `static_runner.iter_paragraph_matches`: prose is matched inside paragraphs.
#[must_use]
pub fn paragraph_matches(p: &Pat, text: &str) -> Vec<Hit> {
    let ranges = paragraph_ranges(text);
    if ranges.is_empty() {
        return p.find_iter(text);
    }
    ranges
        .into_iter()
        .flat_map(|(s, e)| p.find_in(text, s, e))
        .collect()
}

fn valid_quantifier(rest: &str) -> Option<(usize, String)> {
    let close = rest.find('}')?;
    let body = &rest[1..close];
    let ok = !body.is_empty()
        && body.chars().all(|c| c.is_ascii_digit() || c == ',')
        && body.matches(',').count() <= 1
        && body != ",";
    if !ok {
        return None;
    }
    let body = if body.starts_with(',') {
        format!("0{body}")
    } else {
        body.to_owned()
    };
    Some((close + 1, format!("{{{body}}}")))
}

/// Rewrites Python regex syntax into the common subset of `regex` and `fancy_regex`.
fn rewrite(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len() + 16);
    let mut groups: Vec<usize> = Vec::new();
    let mut atom: Option<usize> = None;
    let mut in_class = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && i + 1 < chars.len() {
            let n = chars[i + 1];
            let start = out.len();
            i += 2;
            match n {
                's' if in_class => out.push_str(r"\s\x1c-\x1f"),
                's' => out.push_str(r"[\s\x1c-\x1f]"),
                'S' if !in_class => out.push_str(r"[^\s\x1c-\x1f]"),
                'Z' => out.push_str(r"\z"),
                'u' | 'U' => {
                    let len = if n == 'u' { 4 } else { 8 };
                    let hex: String = chars[i..(i + len).min(chars.len())].iter().collect();
                    out.push_str(&format!("\\x{{{hex}}}"));
                    i += hex.chars().count();
                }
                _ => {
                    out.push('\\');
                    out.push(n);
                }
            }
            if !in_class {
                atom = Some(start);
            }
            continue;
        }
        if in_class {
            match c {
                ']' => in_class = false,
                '[' => {
                    out.push_str(r"\[");
                    i += 1;
                    continue;
                }
                '&' | '~' if chars.get(i + 1) == Some(&c) => {
                    out.push('\\');
                }
                _ => {}
            }
            out.push(c);
            i += 1;
            continue;
        }
        match c {
            '[' => {
                atom = Some(out.len());
                in_class = true;
                out.push('[');
                i += 1;
                if chars.get(i) == Some(&'^') {
                    out.push('^');
                    i += 1;
                }
                if chars.get(i) == Some(&']') {
                    out.push_str(r"\]");
                    i += 1;
                }
            }
            '(' => {
                groups.push(out.len());
                atom = None;
                let rest: String = chars[i..].iter().take(4).collect();
                if rest.starts_with("(?P=") {
                    let end = chars[i..]
                        .iter()
                        .position(|&x| x == ')')
                        .map_or(chars.len(), |p| i + p);
                    let name: String = chars[i + 4..end].iter().collect();
                    out.push_str(&format!("\\k<{name}>"));
                    groups.pop();
                    atom = Some(out.len() - format!("\\k<{name}>").len());
                    i = end + 1;
                } else {
                    out.push('(');
                    i += 1;
                }
            }
            ')' => {
                out.push(')');
                atom = groups.pop();
                i += 1;
            }
            '*' | '+' | '?' | '{' => {
                let (quant, len) = if c == '{' {
                    let rest: String = chars[i..].iter().collect();
                    match valid_quantifier(&rest) {
                        Some((n, q)) => (q, rest[..n].chars().count()),
                        None => {
                            out.push_str(r"\{");
                            atom = Some(out.len() - 2);
                            i += 1;
                            continue;
                        }
                    }
                } else {
                    (c.to_string(), 1)
                };
                i += len;
                out.push_str(&quant);
                match chars.get(i) {
                    Some('+') if atom.is_some() => {
                        if let Some(a) = atom {
                            out.insert_str(a, "(?>");
                            out.push(')');
                            atom = Some(a);
                        }
                        i += 1;
                    }
                    Some('?') => {
                        out.push('?');
                        i += 1;
                    }
                    _ => {}
                }
            }
            '|' | '^' | '$' => {
                out.push(c);
                atom = None;
                i += 1;
            }
            _ => {
                atom = Some(out.len());
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(p: &Pat, s: &str) -> Vec<String> {
        p.find_iter(s)
            .iter()
            .map(|h| h.text(s).to_owned())
            .collect()
    }

    #[test]
    fn whitespace_includes_c0_separators() {
        let p = Pat::new(r"a\sb", "");
        assert_eq!(
            texts(&p, "a\x1cb a b a\u{85}b"),
            ["a\x1cb", "a b", "a\u{85}b"]
        );
        assert_eq!(rewrite(r"\s+\S"), r"[\s\x1c-\x1f]+[^\s\x1c-\x1f]");
        assert_eq!(rewrite(r"[\s,]"), r"[\s\x1c-\x1f,]");
    }

    #[test]
    fn possessive_becomes_atomic() {
        assert_eq!(rewrite(r"a*+b"), "(?>a*)b");
        assert_eq!(rewrite(r"[ab]++c"), "(?>[ab]+)c");
        assert_eq!(rewrite(r"(?:ab)?+c"), "(?>(?:ab)?)c");
        assert_eq!(rewrite(r"x{2,3}+"), "(?>x{2,3})");
        let p = Pat::new(r"a*+a", "");
        assert!(matches!(p, Pat::Fancy(_)));
        assert!(texts(&p, "aaaa").is_empty());
    }

    #[test]
    fn engine_choice() {
        assert!(matches!(Pat::new(r"npx\s+x", "i"), Pat::Fast(_)));
        assert!(matches!(Pat::new(r"(?<=a)b", ""), Pat::Fancy(_)));
        assert!(matches!(Pat::new(r"(?>ab)c", ""), Pat::Fancy(_)));
    }

    #[test]
    fn python_syntax_is_translated() {
        assert_eq!(texts(&Pat::new(r"x{,2}\Z", ""), "axx"), ["xx", ""]);
        assert_eq!(texts(&Pat::new(r"é{2}", ""), "éé"), ["éé"]);
        assert_eq!(texts(&Pat::new(r"[[]a", ""), "[a"), ["[a"]);
        assert_eq!(texts(&Pat::new(r"a{x", ""), "a{x"), ["a{x"]);
        assert_eq!(texts(&Pat::new(r"(?P<x>a)(?P=x)?", ""), "aa"), ["aa"]);
    }

    #[test]
    fn find_in_keeps_left_context_and_cuts_right() {
        let p = Pat::new(r"\bab\b", "");
        let s = "xab ab";
        assert_eq!(p.find_in(s, 1, 3).len(), 0);
        assert_eq!(p.find_in(s, 4, 6).len(), 1);
        let cut = Pat::new(r"ab\b", "");
        assert_eq!(cut.find_in("abc", 0, 2).len(), 1);
    }

    #[test]
    fn groups_and_unicode_offsets() {
        let p = Pat::new(r"(é+)(x)?", "");
        let s = "aéé";
        let h = &p.find_iter(s)[0];
        assert_eq!((h.start, h.end), (1, 5));
        assert_eq!(h.group(s, 1), Some("éé"));
        assert_eq!(h.group(s, 2), None);
    }

    #[test]
    fn paragraphs() {
        let p = Pat::new(r"a\s+b", "");
        assert_eq!(paragraph_matches(&p, "a\nb").len(), 1);
        assert_eq!(paragraph_matches(&p, "a\n\nb").len(), 0);
        assert_eq!(paragraph_matches(&p, "x a b\n \nq a b").len(), 2);
    }
}
