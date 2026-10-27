//! Shell tokenizer and command-range helpers shared by E1 (data_exfiltration), SC2 (supply_chain)
//! and tool_misuse. Literal port of the Python helpers in
//! `nodes/analyzers/static_patterns_{tool_misuse,data_exfiltration,supply_chain}.py`.
//!
//! # API
//!
//! Python indexes `str` by code point, and every bound in the tokenizer (8192-char command window,
//! 4096-char words, 256-char printf, ...) is a code-point count. The core therefore works on
//! `&[char]` with **char indices**; use [`Chars`] to convert at the boundary. Byte-offset
//! wrappers are provided for the analyzer modules, which hold `&str` and regex byte offsets.
//!
//! * **E1 ranges**: [`e1_shell_command_ranges`]`(content, file_type)` (`FileType::Shell` or
//!   `Markdown` get shell regions, every other type gets none) returns `(start_byte, Some(end_byte))`
//!   proved command ranges, or a final `(start_byte, None)` meaning "legacy open-ended matching from
//!   here". Feed them to the slice's own `_iter_e1_shell_matches` equivalent.
//! * **SC2 ranges**: [`sc2_shell_command_ranges`]`(content, file_type)` (`Markdown`/`Text` project
//!   Markdown fences first) returns the same shape, as a `Result` because the tokenizer error is
//!   uncaught in Python.
//! * **tool_misuse tokens**: [`bounded_shell_tokens`] (char indices) or
//!   [`bounded_shell_tokens_str`] (byte indices) return `(tokens, command_end, limited)` as
//!   [`BoundedTokens`]. [`ROOT_GLOB_COMMAND_CHARS`] is the 8192 window.
//! * [`markdown_shell_text_fences`] is `_markdown_shell_text(..., complete_context=False)`.
//!
//! # Deliberate scope limits
//!
//! * Runtime checks/deadlines and the parse-end caches are dropped (caches are `None` on every
//!   path reached from these three entry points; they only memoise).
//! * `_markdown_shell_text(complete_context=True)`, `_is_printf_substitution(check_command_context=True)`
//!   (the recursive destructive-root-glob probe), `_parse_shell_command_word` and the
//!   `_has_destructive_*` / `_static_brace_expansions` helpers are **not** ported: none of the three
//!   entry points reaches them. The tool_misuse slice needs them for its own rules.
//! * A Python lone surrogate (from `$'\ud800'`) cannot be a Rust `char`; it becomes U+FFFD.
//! * `$'\c<ch>'` where `ch.upper()` is not one character raises `TypeError` in Python; here it is
//!   [`ShellError::UpperNotSingleChar`]. E1 catches it (open-ended range), SC2 and the tokenizer
//!   propagate it.

mod destructive;
#[rustfmt::skip]
mod digit_table;
mod exhaustion;
mod expand;
mod json_spans;
mod markdown;
mod markdown_inline;
mod powershell;
mod printf;
mod ranges;
mod tokens;

pub use destructive::{
    CommandWord, destructive_command_words, has_destructive_root_glob, has_destructive_root_path,
    has_unsupported_brace_expansion, is_root_glob_documentation, parse_shell_command_word,
};
pub use exhaustion::{
    JsonQuotes, has_shell_command_word_exhaustion, has_shell_command_word_exhaustion_json,
};
pub use json_spans::validated_json_string_spans;
pub use markdown::{markdown_shell_text, markdown_shell_text_fences};
pub use ranges::{CharRange, e1_ranges_chars, sc2_ranges_chars};
pub use tokens::{ROOT_GLOB_COMMAND_CHARS, bounded_shell_tokens};

use crate::skill::FileType;

/// `_ShellToken`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellToken {
    pub text: String,
    pub root_glob: bool,
    pub glob_projection: String,
    pub has_quoted_content: bool,
    pub brace_expansion: bool,
    pub leading_tilde_unquoted: bool,
}

/// Result of `_bounded_shell_tokens`: `(tokens, command_end, limited)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedTokens {
    pub tokens: Vec<ShellToken>,
    pub end: usize,
    pub limited: bool,
}

/// An exception Python would raise inside the tokenizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellError {
    /// `ord(ch.upper())` on a character whose `upper()` has several characters (`TypeError`).
    UpperNotSingleChar,
}

/// A string as chars plus the char-index to byte-offset map.
#[derive(Debug, Clone)]
pub struct Chars {
    pub chars: Vec<char>,
    bytes: Vec<usize>,
}

impl Chars {
    #[must_use]
    pub fn new(text: &str) -> Self {
        let chars: Vec<char> = text.chars().collect();
        let mut bytes = Vec::with_capacity(chars.len() + 1);
        let mut at = 0;
        for c in &chars {
            bytes.push(at);
            at += c.len_utf8();
        }
        bytes.push(at);
        Self { chars, bytes }
    }

    /// Byte offset of a char index (`len` maps to the text length).
    #[must_use]
    pub fn byte_of(&self, char_index: usize) -> usize {
        self.bytes[char_index.min(self.chars.len())]
    }

    /// Char index of a byte offset (clamped to the nearest following char boundary).
    #[must_use]
    pub fn char_of(&self, byte: usize) -> usize {
        self.bytes.partition_point(|&b| b < byte)
    }
}

fn to_byte_ranges(c: &Chars, ranges: Vec<CharRange>) -> Vec<(usize, Option<usize>)> {
    ranges
        .into_iter()
        .map(|(s, e)| (c.byte_of(s), e.map(|e| c.byte_of(e))))
        .collect()
}

/// `_bounded_shell_tokens` over a `&str` with byte offsets; `end` is a byte offset.
///
/// # Errors
/// See [`ShellError`].
pub fn bounded_shell_tokens_str(
    content: &str,
    command_start: usize,
    body_start: usize,
) -> Result<BoundedTokens, ShellError> {
    let c = Chars::new(content);
    let mut out = bounded_shell_tokens(&c.chars, c.char_of(command_start), c.char_of(body_start))?;
    out.end = c.byte_of(out.end);
    Ok(out)
}

/// `_e1_shell_command_ranges(content, file_type)` with byte offsets.
#[must_use]
pub fn e1_shell_command_ranges(content: &str, file_type: FileType) -> Vec<(usize, Option<usize>)> {
    let c = Chars::new(content);
    let ranges = e1_ranges_chars(
        &c.chars,
        file_type == FileType::Shell,
        file_type == FileType::Markdown,
    );
    to_byte_ranges(&c, ranges)
}

/// `_sc2_shell_command_ranges(content, file_type)` with byte offsets.
///
/// # Errors
/// See [`ShellError`].
pub fn sc2_shell_command_ranges(
    content: &str,
    file_type: FileType,
) -> Result<Vec<(usize, Option<usize>)>, ShellError> {
    let c = Chars::new(content);
    let ranges = sc2_ranges_chars(
        &c.chars,
        matches!(file_type, FileType::Markdown | FileType::Text),
    )?;
    Ok(to_byte_ranges(&c, ranges))
}
