//! A cheap lexical pre-scan for inputs CPython's tokenizer rejects but rustpython-parser 0.4
//! accepts (or chokes on): more than 200 open brackets, more than 100 indentation levels, decimal
//! integer literals over 4300 digits, and emoji used as identifier characters. Strings and comments
//! are skipped; f-string replacement fields are not inspected.

use crate::unicode::category;

const MAX_BRACKET_DEPTH: usize = 200;
const MAX_INDENT_LEVELS: usize = 100;
/// `sys.int_info.default_max_str_digits`: longer decimal literals raise in `ast.parse`.
const MAX_INT_DIGITS: usize = 4300;

/// Characters rustpython accepts in identifiers but CPython rejects (emoji, category `So`), except
/// `U+212E`, which is `Other_ID_Start`.
fn invalid_identifier_char(c: char) -> bool {
    !c.is_ascii() && c != '\u{212e}' && category(c) == "So"
}

struct Scanner {
    cs: Vec<char>,
    i: usize,
}

impl Scanner {
    fn peek(&self, off: usize) -> Option<char> {
        self.cs.get(self.i + off).copied()
    }

    /// Skips a string whose opening quote(s) are at `self.i`.
    fn skip_string(&mut self) {
        let q = self.cs[self.i];
        let triple = self.peek(1) == Some(q) && self.peek(2) == Some(q);
        if !triple && self.peek(1) == Some(q) {
            self.i += 2; // empty string
            return;
        }
        self.i += if triple { 3 } else { 1 };
        while let Some(c) = self.peek(0) {
            self.i += 1;
            if c == '\\' {
                self.i += 1;
            } else if c == q {
                if !triple {
                    return;
                }
                if self.peek(0) == Some(q) && self.peek(1) == Some(q) {
                    self.i += 2;
                    return;
                }
            } else if c == '\n' && !triple {
                return;
            }
        }
    }

    /// Reads a decimal digit run at `self.i`; true when it is an over-long integer literal.
    fn long_int(&mut self) -> bool {
        let start = self.i;
        while self.peek(0).is_some_and(|c| c.is_ascii_digit() || c == '_') {
            self.i += 1;
        }
        let digits = self.cs[start..self.i].iter().filter(|c| **c != '_').count();
        let radix_prefix = self.cs[start] == '0'
            && self
                .peek(0)
                .is_some_and(|c| matches!(c, 'x' | 'X' | 'o' | 'O' | 'b' | 'B'));
        let is_float = self
            .peek(0)
            .is_some_and(|c| matches!(c, '.' | 'e' | 'E' | 'j' | 'J'));
        digits > MAX_INT_DIGITS && !radix_prefix && !is_float
    }

    /// Indentation of the logical line starting at `self.i`, consuming the leading whitespace.
    /// `None` for blank and comment-only lines.
    fn line_indent(&mut self) -> Option<usize> {
        let mut col = 0;
        while let Some(c) = self.peek(0) {
            match c {
                ' ' => col += 1,
                '\t' => col = (col / 8 + 1) * 8,
                '\x0c' => col = 0,
                _ => break,
            }
            self.i += 1;
        }
        (!matches!(self.peek(0), None | Some('\n' | '#' | '\r'))).then_some(col)
    }
}

/// True when CPython's tokenizer would reject `content` for one of the reasons in the module docs.
#[must_use]
pub fn tokenizer_rejects(content: &str) -> bool {
    let mut s = Scanner {
        cs: content.chars().collect(),
        i: 0,
    };
    let (mut depth, mut at_line_start, mut prev_ident) = (0usize, true, false);
    let mut indents = vec![0usize];
    while s.i < s.cs.len() {
        if at_line_start && depth == 0 {
            at_line_start = false;
            if let Some(col) = s.line_indent() {
                if col > indents.last().copied().unwrap_or(0) {
                    indents.push(col);
                }
                while col < indents.last().copied().unwrap_or(0) {
                    indents.pop();
                }
                if indents.len() > MAX_INDENT_LEVELS {
                    return true;
                }
            }
            if s.i >= s.cs.len() {
                break;
            }
        }
        let c = s.cs[s.i];
        let was_ident = std::mem::replace(&mut prev_ident, false);
        match c {
            '\'' | '"' => s.skip_string(),
            '#' => {
                while s.peek(0).is_some_and(|c| c != '\n') {
                    s.i += 1;
                }
            }
            '\\' => s.i += 2,
            '(' | '[' | '{' => {
                depth += 1;
                if depth > MAX_BRACKET_DEPTH {
                    return true;
                }
                s.i += 1;
            }
            ')' | ']' | '}' => {
                depth = depth.saturating_sub(1);
                s.i += 1;
            }
            '\n' => {
                at_line_start = depth == 0;
                s.i += 1;
            }
            c if c.is_ascii_digit() && !was_ident => {
                if s.long_int() {
                    return true;
                }
                prev_ident = true;
            }
            c => {
                if invalid_identifier_char(c) {
                    return true;
                }
                prev_ident = c.is_alphanumeric() || c == '_';
                s.i += 1;
            }
        }
    }
    false
}
