//! Parsed Python source shared by AST-based modules (`python_ast.py`), on `rustpython-parser`.
//!
//! Positions follow CPython: 1-based `\n`-only lines and UTF-8 byte columns ([`Pos`]). The
//! `character_column` / `source_segment` helpers reproduce SkillSpector's own conversion, which
//! indexes `str.splitlines()` lines (so form feeds and other exotic breaks shift its results);
//! that quirk is deliberate.

pub mod names;
pub mod scan;
pub mod syntax;
pub mod walk;

use crate::skill::{PySource, SourceFile};
use crate::text::{line_breaks, py_splitlines};
pub use names::{
    Aliases, apply_import_aliases, build_import_aliases, build_type_map,
    get_complete_source_segment, get_source_segment, resolve_call_name, resolve_call_name_typed,
    resolve_dotted_name, resolve_dynamic_import_call,
};
use rustpython_parser::Parse;
pub use rustpython_parser::ast;
use rustpython_parser::ast::{Ranged, Suite};
use rustpython_parser::text_size::TextRange;
pub use walk::{Node, calls, max_depth, walk};

/// `MAX_PYTHON_AST_SOURCE_CHARS`: larger files are not parsed.
pub const MAX_SOURCE_CHARS: usize = 1_000_000;

/// Deepest AST accepted: where CPython's `ast.parse` raises `RecursionError` (measured on 3.13 as
/// 9995 chained binary operators, which is depth 9996 here; the real limit shifts with the caller's
/// own stack depth).
const MAX_AST_DEPTH: usize = 9996;
/// Trees deeper than this are dropped on a big-stack thread (see `Drop for PyFile`).
const DEEP_TREE: usize = 400;
const DEEP_DROP_STACK: usize = 256 << 20;

/// A node's CPython-style position: 1-based lines, UTF-8 byte columns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pos {
    pub line: u32,
    pub col: u32,
    pub end_line: u32,
    pub end_col: u32,
}

/// A node's position with SkillSpector's character columns (`ParsedPythonFile.character_column`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CharPos {
    pub line: u32,
    pub col: Option<u32>,
    pub end_line: u32,
    pub end_col: Option<u32>,
}

/// One Python file's parse result (`ParsedPythonFile`).
#[derive(Debug)]
pub struct PyFile {
    /// Module body; `None` when parsing failed.
    pub tree: Option<Vec<ast::Stmt>>,
    pub import_aliases: Aliases,
    /// `content.splitlines()`.
    pub lines: Vec<String>,
    pub content: String,
    /// Byte offset of each `\n`-separated line (CPython's line numbering).
    nl_starts: Vec<usize>,
    /// `line_byte_starts` / `line_character_starts` over `splitlines()` lines.
    line_byte_starts: Vec<usize>,
    line_char_starts: Vec<usize>,
    /// Absolute byte offset just past each non-ASCII char, and cumulative extra bytes before it.
    non_ascii_ends: Vec<usize>,
    non_ascii_extra: Vec<usize>,
    /// The tree is deep enough that dropping it needs a big stack.
    deep: bool,
}

impl PyFile {
    /// `parse_python_source`: parses `content` unconditionally.
    #[must_use]
    pub fn parse(content: &str, path: &str) -> Self {
        let (tree, deep) = parse_tree(content, path);
        let import_aliases = tree
            .as_deref()
            .map(build_import_aliases)
            .unwrap_or_default();
        let mut file = Self::build(tree, import_aliases, content);
        file.deep = deep;
        file
    }

    /// The file's parse when an AST module should see one: Python or ambiguous source of at most
    /// [`MAX_SOURCE_CHARS`] characters. `None` means the module takes its non-AST fallback.
    #[must_use]
    pub fn for_file(file: &SourceFile) -> Option<Self> {
        let eligible = file.py != PySource::NonPython
            && file.text.chars().take(MAX_SOURCE_CHARS + 1).count() <= MAX_SOURCE_CHARS;
        eligible.then(|| Self::parse(&file.text, &file.rel))
    }

    fn build(tree: Option<Vec<ast::Stmt>>, import_aliases: Aliases, content: &str) -> Self {
        let mut nl_starts = vec![0];
        nl_starts.extend(content.match_indices('\n').map(|(i, _)| i + 1));

        let mut line_byte_starts = vec![0];
        line_byte_starts.extend(line_breaks(content).into_iter().map(|(_, e)| e));
        if !content.is_empty() && line_byte_starts.last() != Some(&content.len()) {
            line_byte_starts.push(content.len());
        }
        let mut line_char_starts = vec![0];
        let mut chars_before = 0;
        let mut at = 0;
        for &b in &line_byte_starts[1..] {
            chars_before += content[at..b].chars().count();
            at = b;
            line_char_starts.push(chars_before);
        }

        let mut non_ascii_ends = Vec::new();
        let mut non_ascii_extra = vec![0];
        if !content.is_ascii() {
            let mut extra = 0;
            for (i, c) in content.char_indices().filter(|(_, c)| !c.is_ascii()) {
                extra += c.len_utf8() - 1;
                non_ascii_ends.push(i + c.len_utf8());
                non_ascii_extra.push(extra);
            }
        }
        Self {
            tree,
            import_aliases,
            lines: py_splitlines(content)
                .into_iter()
                .map(str::to_owned)
                .collect(),
            content: content.to_owned(),
            nl_starts,
            line_byte_starts,
            line_char_starts,
            non_ascii_ends,
            non_ascii_extra,
            deep: false,
        }
    }

    /// `is_parseable`.
    #[must_use]
    pub fn is_parseable(&self) -> bool {
        self.tree.is_some()
    }

    fn line_col(&self, offset: usize) -> (u32, u32) {
        let idx = self.nl_starts.partition_point(|&s| s <= offset);
        let start = self
            .nl_starts
            .get(idx.wrapping_sub(1))
            .copied()
            .unwrap_or(0);
        (to_u32(idx), to_u32(offset - start))
    }

    /// CPython `lineno` / `col_offset` / `end_lineno` / `end_col_offset` for a node range.
    #[must_use]
    pub fn pos(&self, range: TextRange) -> Pos {
        let (line, col) = self.line_col(usize::from(range.start()));
        let (end_line, end_col) = self.line_col(usize::from(range.end()));
        Pos {
            line,
            col,
            end_line,
            end_col,
        }
    }

    /// [`Self::pos`] with SkillSpector's character columns.
    #[must_use]
    pub fn char_pos(&self, range: TextRange) -> CharPos {
        let p = self.pos(range);
        CharPos {
            line: p.line,
            col: self.character_column(p.line, p.col),
            end_line: p.end_line,
            end_col: self.character_column(p.end_line, p.end_col),
        }
    }

    /// `character_column(lineno, byte_column)`.
    #[must_use]
    pub fn character_column(&self, lineno: u32, byte_column: u32) -> Option<u32> {
        let idx = usize::try_from(lineno).ok()?.checked_sub(1)?;
        let abs_byte = self.line_byte_starts.get(idx)? + byte_column as usize;
        if abs_byte > self.content.len() {
            return None;
        }
        let count = self.non_ascii_ends.partition_point(|&e| e <= abs_byte);
        let abs_char = abs_byte - self.non_ascii_extra[count];
        // Python's int arithmetic would go negative here; that cannot happen (see module docs).
        u32::try_from(abs_char.saturating_sub(self.line_char_starts[idx])).ok()
    }

    /// `source_segment(node)`: the node's text via the `splitlines` line table.
    #[must_use]
    pub fn source_segment(&self, range: TextRange) -> Option<&str> {
        let p = self.pos(range);
        let start_idx = usize::try_from(p.line).ok()?.checked_sub(1)?;
        let end_idx = usize::try_from(p.end_line).ok()?.checked_sub(1)?;
        if end_idx < start_idx || end_idx >= self.line_byte_starts.len() {
            return None;
        }
        let start = self.line_byte_starts[start_idx] + p.col as usize;
        let end = self.line_byte_starts[end_idx] + p.end_col as usize;
        self.content.get(start..end)
    }

    /// Position of any node that has one.
    #[must_use]
    pub fn node_pos(&self, node: &Node) -> Option<Pos> {
        node.range().map(|r| self.pos(r))
    }

    /// `source_segment` for an AST node.
    #[must_use]
    pub fn node_segment(&self, node: &impl Ranged) -> Option<&str> {
        self.source_segment(node.range())
    }
}

fn to_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// `ast.parse(content)`: `None` on any syntax error, null byte, or CPython nesting limit. The flag
/// says the returned tree is deep (see [`DEEP_TREE`]).
fn parse_tree(content: &str, path: &str) -> (Option<Vec<ast::Stmt>>, bool) {
    if content.contains('\0') || scan::tokenizer_rejects(content) {
        return (None, false);
    }
    let parsed = std::panic::catch_unwind(|| Suite::parse(content, path));
    let Some(body) = parsed.ok().and_then(Result::ok) else {
        return (None, false);
    };
    let depth = max_depth(&body);
    if depth > MAX_AST_DEPTH {
        // CPython raises RecursionError; dropping a tree this deep could overflow any stack.
        std::mem::forget(body);
        return (None, false);
    }
    let deep = depth > DEEP_TREE;
    if syntax::has_invalid_target(&body, content) {
        if deep {
            std::mem::forget(body);
        }
        return (None, false);
    }
    (Some(body), deep)
}

impl Drop for PyFile {
    /// Rustpython's tree drops recursively: a deep one is torn down on a thread with a big stack.
    fn drop(&mut self) {
        if !self.deep {
            return;
        }
        let cell = std::sync::Mutex::new(self.tree.take());
        let spawned = std::thread::scope(|scope| {
            std::thread::Builder::new()
                .stack_size(DEEP_DROP_STACK)
                .spawn_scoped(scope, || drop(cell.lock().ok().and_then(|mut t| t.take())))
                .is_ok()
        });
        if !spawned {
            std::mem::forget(cell.into_inner());
        }
    }
}

#[cfg(test)]
mod tests;
