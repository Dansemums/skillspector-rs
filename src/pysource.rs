//! Python source identity and decoding, simplified from SkillSpector's `python_ast.py`.
//!
//! Gaps: `env -S` argument grammar and Linux truncated-shebang views are not modelled
//! (such scripts count as Python only for plain `python` / `env python` shebangs, `env -S` is
//! `Ambiguous`); PEP 263 cookies other than UTF-8, Latin-1 and ASCII are decoded as UTF-8.

use crate::matcher::Pat;
use crate::skill::PySource;
use std::sync::LazyLock;

static INTERPRETER: LazyLock<Pat> = LazyLock::new(|| {
    Pat::new(
        r"\A(?:python(?:[0-9]+(?:\.[0-9]+)*(?:d?m?u?|t?d?)(?:-(?:intel64|32|dbg))?)?|pypy(?:[0-9]+(?:\.[0-9]+)*)?)\Z",
        "",
    )
});
static COOKIE: LazyLock<Pat> =
    LazyLock::new(|| Pat::new(r"\A[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)", ""));

fn is_python_command(command: &str) -> bool {
    let base = command.rsplit('/').next().unwrap_or(command);
    !INTERPRETER.find_iter(base).is_empty()
}

/// `classify_python_source(path, content)`.
#[must_use]
pub fn classify_python_source(path: &str, bytes: &[u8]) -> PySource {
    let base = path.rsplit('/').next().unwrap_or(path);
    if let Some(dot) = base.rfind('.')
        && matches!(base[dot..].to_lowercase().as_str(), ".py" | ".pyw")
    {
        return PySource::Python;
    }
    let sample = &bytes[..bytes.len().min(513)];
    let end = sample.iter().position(|&b| b == b'\n' || b == 0);
    let line = match end {
        Some(e) if e <= 512 => &sample[..e],
        None if sample.len() <= 512 => sample,
        _ => {
            return if bytes.starts_with(b"#!") {
                PySource::Ambiguous
            } else {
                PySource::NonPython
            };
        }
    };
    let line = String::from_utf8_lossy(line);
    let Some(rest) = line.strip_prefix("#!") else {
        return PySource::NonPython;
    };
    let command_line = rest.trim_start_matches([' ', '\t']);
    if !command_line.starts_with('/') {
        return PySource::NonPython;
    }
    let mut tokens = command_line
        .trim_matches([' ', '\t'])
        .split([' ', '\t'])
        .filter(|t| !t.is_empty());
    let Some(first) = tokens.next() else {
        return PySource::NonPython;
    };
    if matches!(first, "/usr/bin/env" | "/bin/env") {
        for t in tokens {
            if t == "-S" || t.starts_with("-S") || t == "--split-string" {
                return PySource::Ambiguous;
            }
            if t.starts_with('-') || t.contains('=') {
                continue;
            }
            return if is_python_command(t) {
                PySource::Python
            } else {
                PySource::NonPython
            };
        }
        return PySource::NonPython;
    }
    if is_python_command(first) {
        PySource::Python
    } else {
        PySource::NonPython
    }
}

/// `decode_python_source`: universal newlines, then the PEP 263 encoding. `None` on failure.
#[must_use]
pub fn decode_python_source(bytes: &[u8]) -> Option<String> {
    if bytes.contains(&0) {
        return None;
    }
    let normalized: Vec<u8> = if bytes.contains(&b'\r') {
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\r' {
                out.push(b'\n');
                if bytes.get(i + 1) == Some(&b'\n') {
                    i += 1;
                }
            } else {
                out.push(bytes[i]);
            }
            i += 1;
        }
        out
    } else {
        bytes.to_vec()
    };
    let (bom, body) = match normalized.strip_prefix(b"\xef\xbb\xbf") {
        Some(b) => (true, b),
        None => (false, &normalized[..]),
    };
    let encoding = cookie_encoding(body);
    let text = match encoding.as_str() {
        "iso-8859-1" if !bom => body.iter().map(|&b| char::from(b)).collect(),
        "ascii" if !bom => {
            if !body.is_ascii() {
                return None;
            }
            String::from_utf8_lossy(body).into_owned()
        }
        _ => std::str::from_utf8(body).ok()?.to_owned(),
    };
    Some(text)
}

fn cookie_encoding(body: &[u8]) -> String {
    let mut lines = body.split(|&b| b == b'\n');
    for _ in 0..2 {
        let Some(line) = lines.next() else { break };
        let text = String::from_utf8_lossy(line);
        if let Some(h) = COOKIE.find_iter(&text).first()
            && let Some(name) = h.group(&text, 1)
        {
            let n = name
                .chars()
                .take(12)
                .collect::<String>()
                .to_lowercase()
                .replace('_', "-");
            return match n.as_str() {
                "latin-1" | "iso-8859-1" | "iso-latin-1" => "iso-8859-1".into(),
                "ascii" | "us-ascii" => "ascii".into(),
                _ => "utf-8".into(),
            };
        }
        let trimmed = text.trim_start_matches([' ', '\t', '\x0c']);
        if !(trimmed.is_empty() || trimmed.starts_with('#')) {
            break;
        }
    }
    "utf-8".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies() {
        assert_eq!(classify_python_source("a.PY", b""), PySource::Python);
        assert_eq!(
            classify_python_source("x", b"#!/usr/bin/env python3\n"),
            PySource::Python
        );
        assert_eq!(
            classify_python_source("x", b"#!/usr/bin/python3.11\n"),
            PySource::Python
        );
        assert_eq!(
            classify_python_source("x", b"#!/usr/bin/env -S uv run\n"),
            PySource::Ambiguous
        );
        assert_eq!(
            classify_python_source("x", b"#!/bin/bash\n"),
            PySource::NonPython
        );
        assert_eq!(classify_python_source("x", b"echo hi"), PySource::NonPython);
    }

    #[test]
    fn decodes() {
        assert_eq!(decode_python_source(b"a\r\nb").as_deref(), Some("a\nb"));
        assert_eq!(
            decode_python_source(b"# coding: latin-1\n\xe9").as_deref(),
            Some("# coding: latin-1\n\u{e9}")
        );
        assert_eq!(decode_python_source(b"a\0"), None);
        assert_eq!(decode_python_source(b"\xff"), None);
        assert_eq!(decode_python_source(b"\xef\xbb\xbfx").as_deref(), Some("x"));
    }
}
