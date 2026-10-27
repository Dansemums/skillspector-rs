//! SC3 patterns and the decoded-payload helpers of `static_patterns_supply_chain.py`:
//! `_decoded_literal_xor_calls`, `_decoded_shell_literal_payloads` and the shell decode-to-execute
//! regexes (lines 201-430).

use super::py_shlex::shell_tokens;
use crate::matcher::Pat;
use crate::text::LineIndex;
use crate::unicode::is_space;
use std::sync::LazyLock;

type Rule = (&'static str, f32);

const MAX_LITERAL_XOR_KEY_BYTES: usize = 256;
const MAX_LITERAL_XOR_VALUES: usize = 4_096;
const MAX_SHELL_LITERAL_CHARS: usize = 16_384;

pub const SC3_CODE: &[Rule] = &[
    (r"exec\s*\(\s*(?:base64\.)?b64decode\s*\(", 0.95),
    (r"eval\s*\(\s*(?:base64\.)?b64decode\s*\(", 0.95),
    (
        r##"exec\s*\(\s*codecs\.decode\s*\([^)]*['\"]hex['\"]\s*\)"##,
        0.95,
    ),
    (r"marshal\.loads\s*\(", 0.9),
    (r"exec\s*\(\s*marshal\.loads\s*\(", 0.95),
    (r"exec\s*\(\s*compile\s*\([^)]*base64", 0.9),
    (r"exec\s*\(\s*bytes\.fromhex\s*\(", 0.9),
    (r"exec\s*\(\s*bytearray\.fromhex\s*\(", 0.9),
    (r"exec\s*\(\s*(?:zlib|gzip)\.decompress\s*\(", 0.9),
    (r"eval\s*\(\s*atob\s*\(", 0.9),
    (r"new\s+Function\s*\(\s*atob\s*\(", 0.9),
    (r"_0x[a-f0-9]{4,}\s*\(", 0.8),
    (r##"['\"][A-Fa-f0-9]{200,}['\"]"##, 0.6),
    (r##"['\"][A-Za-z0-9+/=]{200,}['\"]"##, 0.5),
    (r"\(lambda\s+_:\s*exec\s*\(", 0.9),
    (r##"__import__\s*\(['\"]os['\"]\s*\)\.system"##, 0.85),
];
pub const SC3_PROSE: &[Rule] = &[(
    r"decode\s+(?:this|the)\s+(?:base64|hex)\s+(?:and\s+)?(?:run|execute)",
    0.8,
)];

const SHELL_DECODER: &str = concat!(
    r"(?>\bbase(?:64|32)(?:[ \t]{1,16}--?[A-Za-z][\w=-]{0,20}){0,3}?",
    r"[ \t]{1,16}(?:--decode|-[A-Za-z]{0,3}d[A-Za-z]{0,3})\b",
    r"|\bxxd(?:[ \t]{1,16}-[A-Za-z]{1,10}){0,3}?[ \t]{1,16}-(?:r|rp|pr|rps|psr|revert)\b",
    r"|\bopenssl[ \t]{1,16}(?:base64|enc)(?:[ \t]{1,16}-[A-Za-z0-9-]{1,16}){0,4}?[ \t]{1,16}-d\b)"
);
const PIPE_SEGMENT: &str =
    r##"[^|;&\n`\\]{0,256}+(?:(?:&[0-9>-]|\\['\"])[^|;&\n`\\]{0,64}+){0,2}+"##;
const PIPE_EXECUTOR: &str = concat!(
    r"\|(?!\|)&?[ \t]{0,16}",
    r"(?:sudo(?:[ \t]{1,16}+-[A-Za-z]{1,8}+(?:[ \t]{1,16}+[\w.][\w.-]{0,31}+)?){0,4}[ \t]{1,16}+)?",
    r"(?:(?:/[\w.-]{1,32}){0,4}/)?",
    r"(?:(?:ba|da|z|k|a)?sh(?![\w.-])",
    r"(?![ \t]{1,16}(?:-[A-Za-z]{1,8}[ \t]{1,16}){0,3}-[A-Za-z]{0,3}c)",
    r"(?![ \t]{1,16}(?!-|/dev/stdin\b|[0-9]{0,2}[<>])[^\s|;&)#])",
    r"|(?:python(?:[23](?:\.[0-9]{1,2})?)?|perl|ruby|node)(?:[ \t]{1,16}-[A-Za-z]{0,4}){0,2}",
    r##"(?=['\"]|[ \t]{0,16}(?:$|[\r;&|)`#]|[0-9]{0,2}>)))"##
);
const SUBSTITUTION_EXECUTOR: &str = concat!(
    r"(?:(?<![\w.-])(?:eval|(?:ba|da|z|k|a)?sh[ \t]{1,16}-[A-Za-z]{0,3}c",
    r"|python(?:[23](?:\.[0-9]{1,2})?)?[ \t]{1,16}-c|(?:perl|ruby|node)[ \t]{1,16}-e)",
    r##"[ \t]{1,16}\\?[\"']?(?:\$\(|`)"##,
    r"|(?:(?<![\w.-])(?:source|(?:ba|da|z|k|a)?sh|python(?:[23](?:\.[0-9]{1,2})?)?|perl|ruby|node)",
    r##"|(?:^|(?<=[;&|(`'\"{]))[ \t]{0,16}\.)"##,
    r"(?:[ \t]{1,16}-{1,2}[A-Za-z]{0,16}){0,2}(?:[ \t]{1,16}/dev/stdin)?",
    r##"[ \t]{1,16}(?:<<<[ \t]{0,16}\\?[\"']?(?:\$\(|`)|<(?:[ \t]{0,16}<)?\())"##
);
const HERE_STRING: &str = r"(?:[ \t]{1,16}-[A-Za-z0-9-]{1,16}){0,4}[ \t]{0,16}<<<[ \t]{0,16}";

fn shell_literal() -> String {
    format!(
        r##"(?P<quote>(?:\\?['\"])?)(?P<literal>[A-Za-z0-9+/=]{{8,{MAX_SHELL_LITERAL_CHARS}}})"##
    )
}

/// `SC3_SHELL_PATTERNS`, source text (flags `im`).
#[must_use]
pub fn shell_patterns() -> Vec<(String, f32)> {
    vec![
        (
            format!(
                r##"{SHELL_DECODER}(?:{HERE_STRING}\\?['\"]?[A-Za-z0-9+/=]{{0,{MAX_SHELL_LITERAL_CHARS}}}+)?+{PIPE_SEGMENT}(?:\|(?!\|)&?{PIPE_SEGMENT}){{0,3}}?{PIPE_EXECUTOR}"##
            ),
            0.9,
        ),
        (
            format!(
                "{SUBSTITUTION_EXECUTOR}[^()`\\n]{{0,{MAX_SHELL_LITERAL_CHARS}}}?{SHELL_DECODER}"
            ),
            0.9,
        ),
    ]
}

fn piped_literal_src() -> String {
    format!(
        r##"\b(?:echo(?:[ \t]{{1,16}}-[neE]{{1,3}})?|printf(?:[ \t]{{1,16}}(?P<format_quote>['\"]?)%s(?:\\n)?(?P=format_quote))?)[ \t]{{1,16}}{lit}(?P=quote)[ \t]{{0,16}}\|(?!\|)[ \t]{{0,16}}(?P<decoder>{SHELL_DECODER})"##,
        lit = shell_literal()
    )
}

fn here_string_literal_src() -> String {
    format!(
        r"(?P<decoder>{SHELL_DECODER}){HERE_STRING}{lit}(?![A-Za-z0-9+/=])(?P=quote)",
        lit = shell_literal()
    )
}

const DATA_SINK: &str = concat!(
    r"\A(?:[ \t]{1,16}-[A-Za-z0-9-]{1,16}){0,4}[ \t]{0,16}",
    r"\|(?!\|)&?[ \t]{0,16}sha256sum(?=$|[\s;&|)`])"
);

const XOR_SOURCES: [&str; 3] = [
    r"^def\s+(?P<name>[A-Za-z_]\w*)\(",
    r"(?:\n[ \t]+.*)+",
    r##"\b\w+\s*=\s*b(?P<q>['\"])(?P<key>(?:\\[\s\S]|[^'\"\\])*)(?P=q)"##,
];

pub struct Compiled {
    pub code: Vec<Pat>,
    pub prose: Vec<Pat>,
    pub shell: Vec<Pat>,
    pub decode_command: Pat,
    piped: Pat,
    here: Pat,
    sink: Pat,
    xor_function: Pat,
    xor_body: Pat,
    xor_key: Pat,
}

pub static COMPILED: LazyLock<Compiled> = LazyLock::new(|| Compiled {
    code: SC3_CODE.iter().map(|(s, _)| Pat::new(s, "im")).collect(),
    prose: SC3_PROSE.iter().map(|(s, _)| Pat::new(s, "im")).collect(),
    shell: shell_patterns()
        .iter()
        .map(|(s, _)| Pat::new(s, "im"))
        .collect(),
    decode_command: Pat::new(SHELL_DECODER, "i"),
    piped: Pat::new(&piped_literal_src(), "i"),
    here: Pat::new(&here_string_literal_src(), "i"),
    sink: Pat::new(DATA_SINK, ""),
    xor_function: Pat::new(XOR_SOURCES[0], "m"),
    xor_body: Pat::new(XOR_SOURCES[1], ""),
    xor_key: Pat::new(XOR_SOURCES[2], ""),
});

/// `bytes.decode("utf-8", errors="replace")`.
fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `base64.b64decode(s + "=" * (-len(s) % 4), validate=True)`.
fn b64_decode(literal: &str) -> Option<Vec<u8>> {
    let value = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let body = literal.trim_end_matches('=').as_bytes();
    let pads = literal.len() - body.len();
    let need = (4 - body.len() % 4) % 4;
    // Padding is topped up to a multiple of four, so only an exact count is valid.
    if body.len() % 4 == 1 || pads > 2 || (pads != 0 && pads != need) {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in body {
        acc = (acc << 6) | value(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// `base64.b32decode(s + "=" * (-len(s) % 8))`, uppercase alphabet only.
fn b32_decode(literal: &str) -> Option<Vec<u8>> {
    let padded_len = literal.len().div_ceil(8) * 8;
    let body = literal.trim_end_matches('=').as_bytes();
    let pads = padded_len - body.len();
    if !matches!(pads, 0 | 1 | 3 | 4 | 6) {
        return None;
    }
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u64, 0u32);
    for &c in body {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        acc = (acc << 5) | u64::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// `bytes.fromhex(literal[: len // 2 * 2])`.
fn hex_decode(literal: &str) -> Option<Vec<u8>> {
    let even = &literal.as_bytes()[..literal.len() / 2 * 2];
    even.chunks(2)
        .map(|p| {
            let s = std::str::from_utf8(p).ok()?;
            u8::from_str_radix(s, 16)
                .ok()
                .filter(|_| !s.starts_with('+'))
        })
        .collect()
}

/// `_decoded_shell_literal_payloads`: `(byte offset of the literal, decoded text)` in source order.
#[must_use]
pub fn decoded_shell_literal_payloads(content: &str) -> Vec<(usize, String)> {
    let c = &*COMPILED;
    let mut checksum_ok: Option<bool> = None;
    let mut out: Vec<(usize, String)> = Vec::new();
    for (pat, decoder_idx) in [(&c.piped, 4), (&c.here, 1)] {
        for hit in pat.find_iter(content) {
            if !c.sink.find_iter(&content[hit.end..]).is_empty() {
                let allowed = *checksum_ok.get_or_insert_with(|| {
                    shell_tokens(content).is_some_and(|tokens| {
                        !tokens.iter().any(|t| {
                            matches!(t.as_str(), "alias" | "function" | "eval" | "source" | ".")
                                || t.starts_with("sha256sum=")
                                || t.chars().any(|ch| is_space(ch) || ch == '(' || ch == ')')
                        })
                    })
                });
                if allowed {
                    continue;
                }
            }
            // Capture 3 is `literal` in both patterns; the decoder's index differs.
            let (Some(literal), Some(decoder), Some((start, _))) = (
                hit.group(content, 3),
                hit.group(content, decoder_idx),
                hit.groups.get(3).copied().flatten(),
            ) else {
                continue;
            };
            let decoder = decoder.to_lowercase();
            let payload = if decoder.starts_with("xxd") {
                hex_decode(literal)
            } else if decoder.starts_with("base32") {
                b32_decode(literal)
            } else {
                b64_decode(literal)
            };
            if let Some(payload) = payload {
                out.push((start, lossy(&payload)));
            }
        }
    }
    out.sort();
    out
}

/// `codecs.decode(key, "unicode_escape").encode("latin1")`; `None` where Python raises.
fn unicode_escape_latin1(key: &str) -> Option<Vec<u8>> {
    let bytes = key.as_bytes();
    let mut out: Vec<u32> = Vec::new();
    let mut i = 0;
    let hex = |s: &[u8]| -> Option<u32> {
        let t = std::str::from_utf8(s).ok()?;
        if t.starts_with('+') {
            return None;
        }
        u32::from_str_radix(t, 16).ok()
    };
    while i < bytes.len() {
        let b = bytes[i];
        i += 1;
        if b != b'\\' {
            out.push(u32::from(b));
            continue;
        }
        let e = *bytes.get(i)?;
        i += 1;
        match e {
            b'\n' => {}
            b'\\' | b'\'' | b'"' => out.push(u32::from(e)),
            b'a' => out.push(7),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'n' => out.push(10),
            b'r' => out.push(13),
            b't' => out.push(9),
            b'v' => out.push(11),
            b'0'..=b'7' => {
                let mut v = u32::from(e - b'0');
                for _ in 0..2 {
                    match bytes.get(i) {
                        Some(d @ b'0'..=b'7') => {
                            v = v * 8 + u32::from(d - b'0');
                            i += 1;
                        }
                        _ => break,
                    }
                }
                out.push(v);
            }
            b'x' | b'u' | b'U' => {
                let n = match e {
                    b'x' => 2,
                    b'u' => 4,
                    _ => 8,
                };
                let v = hex(bytes.get(i..i + n)?)?;
                i += n;
                if v > 0x0010_ffff {
                    return None;
                }
                out.push(v);
            }
            b'N' => return None,
            other => {
                out.push(u32::from(b'\\'));
                out.push(u32::from(other));
            }
        }
    }
    out.into_iter().map(|c| u8::try_from(c).ok()).collect()
}

/// `_decoded_literal_xor_calls`: `(line, command)` for literal byte arrays passed to a local XOR helper.
#[must_use]
pub fn decoded_literal_xor_calls(content: &str, index: &LineIndex) -> Vec<(u32, String)> {
    let c = &*COMPILED;
    let mut decoded = Vec::new();
    let mut closing: Option<usize> = None;
    let mut consumed_until = 0;
    for function in c.xor_function.find_iter(content) {
        if function.start < consumed_until {
            continue;
        }
        if closing.is_none_or(|p| p < function.end) {
            closing = content[function.end..].find(')').map(|p| p + function.end);
        }
        let Some(close) = closing else { break };
        if !content[close + 1..].starts_with(':') {
            continue;
        }
        let body_start = close + 2;
        let Some(body_hit) = c
            .xor_body
            .find_in(content, body_start, content.len())
            .into_iter()
            .next()
            .filter(|h| h.start == body_start)
        else {
            continue;
        };
        consumed_until = body_hit.end;
        let body = &content[body_hit.start..body_hit.end];
        let Some(key_hit) = c.xor_key.find_iter(body).into_iter().next() else {
            continue;
        };
        if !body.contains("bytes(") || !body.contains('^') || !body.contains(".decode(") {
            continue;
        }
        let Some(key) = key_hit.group(body, 2).and_then(unicode_escape_latin1) else {
            continue;
        };
        if key.is_empty() || key.len() > MAX_LITERAL_XOR_KEY_BYTES {
            continue;
        }
        let Some(name) = function.group(content, 1) else {
            continue;
        };
        let call = Pat::new(
            &format!(
                r"\b{}\(\s*\[(?P<values>[\d,\s]+)\]\s*\)",
                regex::escape(name)
            ),
            "",
        );
        for hit in call.find_iter(content) {
            let Some(values) = hit.group(content, 1) else {
                continue;
            };
            let parsed: Option<Vec<u16>> = values
                .split(',')
                .filter(|v| !v.trim().is_empty())
                .map(|v| v.trim().parse::<u16>().ok().filter(|n| *n <= 255))
                .collect();
            let Some(values) = parsed else { continue };
            if values.is_empty() || values.len() > MAX_LITERAL_XOR_VALUES {
                continue;
            }
            let bytes: Vec<u8> = values
                .iter()
                .enumerate()
                .map(|(i, v)| u8::try_from(*v).unwrap_or(0) ^ key[i % key.len()])
                .collect();
            if let Ok(command) = String::from_utf8(bytes) {
                decoded.push((index.line(hit.start), command));
            }
        }
    }
    decoded
}

#[cfg(test)]
/// Every SC3/decoder source with its flags, for the compile test.
pub fn all_sources() -> Vec<(String, &'static str)> {
    let mut v: Vec<(String, &'static str)> = SC3_CODE
        .iter()
        .chain(SC3_PROSE)
        .map(|(s, _)| ((*s).to_owned(), "im"))
        .collect();
    v.extend(shell_patterns().into_iter().map(|(s, _)| (s, "im")));
    v.push((piped_literal_src(), "i"));
    v.push((here_string_literal_src(), "i"));
    v.push((SHELL_DECODER.to_owned(), "i"));
    v.push((DATA_SINK.to_owned(), ""));
    v.extend(XOR_SOURCES.iter().map(|s| ((*s).to_owned(), "m")));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_python_strictness() {
        assert_eq!(b64_decode("aGk=").as_deref(), Some(&b"hi"[..]));
        assert_eq!(b64_decode("aGk").as_deref(), Some(&b"hi"[..]));
        assert_eq!(b64_decode("aA=="), Some(b"h".to_vec()));
        assert_eq!(b64_decode("aGk==="), None);
        assert_eq!(b64_decode("a"), None);
        assert_eq!(b64_decode("aG=k"), None);
    }

    #[test]
    fn base32_and_hex() {
        assert_eq!(b32_decode("NBUQ===="), Some(b"hi".to_vec()));
        assert_eq!(b32_decode("nbuq"), None);
        assert_eq!(hex_decode("6869a"), Some(b"hi".to_vec()));
        assert_eq!(hex_decode("zz"), None);
    }

    #[test]
    fn unicode_escape_keys() {
        assert_eq!(unicode_escape_latin1(r"\x01\n"), Some(vec![1, 10]));
        assert_eq!(unicode_escape_latin1(r"\u0100"), None);
        assert_eq!(unicode_escape_latin1(r"\x1"), None);
        assert_eq!(unicode_escape_latin1(r"\q"), Some(vec![b'\\', b'q']));
    }
}
