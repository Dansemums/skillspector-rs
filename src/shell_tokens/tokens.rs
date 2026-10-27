//! `_bounded_shell_tokens`: argument words of one security-view-bounded shell command.

use super::expand::{
    command_wrapper_quote, decode_ansi_c_escape, is_ifs_expansion, skip_ansi_c_quote_tail,
    skip_backtick_substitution, skip_command_substitution, skip_parameter_expansion,
};
use super::printf::{is_printf_substitution, static_printf_substitution};
use super::{BoundedTokens, ShellError, ShellToken};
use crate::unicode::is_space;

/// `_ROOT_GLOB_COMMAND_CHARS`.
pub const ROOT_GLOB_COMMAND_CHARS: usize = 8192;
const QUOTED_GLOB_SENTINEL: char = '\u{e000}';

#[derive(Default)]
struct Word {
    current: String,
    glob_projection: String,
    started: bool,
    is_argument: bool,
    has_unquoted_star: bool,
    can_collapse_to_root_glob: bool,
    has_quoted_content: bool,
    brace_open: bool,
    brace_close: bool,
    brace_comma: bool,
    leading_tilde_unquoted: bool,
}

struct State {
    tokens: Vec<ShellToken>,
    word: Word,
    source_word_has_content: bool,
    expect_redirection_target: bool,
}

#[derive(Default, Clone, Copy)]
struct Piece {
    unquoted: bool,
    dynamic_can_be_empty: bool,
    quoted: bool,
    unquoted_brace_syntax: bool,
}

impl State {
    fn new() -> Self {
        Self {
            tokens: Vec::new(),
            word: Word {
                is_argument: true,
                can_collapse_to_root_glob: true,
                ..Word::default()
            },
            source_word_has_content: false,
            expect_redirection_target: false,
        }
    }

    fn start_word(&mut self) {
        if !self.word.started {
            self.word.started = true;
            self.word.is_argument = !self.expect_redirection_target;
            self.expect_redirection_target = false;
        }
    }

    fn mark_quoted_word(&mut self) {
        self.start_word();
        self.word.has_quoted_content = true;
        self.source_word_has_content = true;
    }

    fn append(&mut self, piece: &str, flags: Piece) {
        self.start_word();
        self.source_word_has_content = true;
        let w = &mut self.word;
        w.current.push_str(piece);
        if flags.unquoted {
            w.glob_projection.push_str(piece);
        } else {
            w.glob_projection.extend(piece.chars().map(|c| {
                if c == '*' || c == '?' {
                    QUOTED_GLOB_SENTINEL
                } else {
                    c
                }
            }));
        }
        w.has_quoted_content = w.has_quoted_content || flags.quoted;
        if flags.unquoted_brace_syntax {
            w.brace_open = w.brace_open || piece.contains('{');
            w.brace_close = w.brace_close || piece.contains('}');
            w.brace_comma = w.brace_comma || piece.contains(',');
        }
        w.has_unquoted_star = w.has_unquoted_star || (flags.unquoted && piece.contains('*'));
        if !flags.dynamic_can_be_empty && !piece.is_empty() {
            w.can_collapse_to_root_glob = w.can_collapse_to_root_glob
                && flags.unquoted
                && piece.chars().all(|c| c == '*' || c == '?');
        }
    }

    fn append_plain(&mut self, piece: &str) {
        self.append(piece, Piece::default());
    }

    fn flush(&mut self, complete: bool) {
        if !self.word.started {
            return;
        }
        let w = &mut self.word;
        if complete && w.is_argument {
            self.tokens.push(ShellToken {
                text: std::mem::take(&mut w.current),
                root_glob: w.has_unquoted_star && w.can_collapse_to_root_glob,
                glob_projection: std::mem::take(&mut w.glob_projection),
                has_quoted_content: w.has_quoted_content,
                brace_expansion: w.brace_open && w.brace_close && w.brace_comma,
                leading_tilde_unquoted: w.leading_tilde_unquoted,
            });
        }
        w.current.clear();
        w.glob_projection.clear();
        w.started = false;
        w.has_unquoted_star = false;
        w.can_collapse_to_root_glob = true;
        w.has_quoted_content = false;
        w.brace_open = false;
        w.brace_close = false;
        w.brace_comma = false;
        w.leading_tilde_unquoted = false;
    }
}

fn is_quote_char(c: char) -> bool {
    c == '\'' || c == '"'
}

/// The text of a static printf value, or the dynamic placeholder with its flags.
fn substitution_piece(
    content: &[char],
    cursor: usize,
    end: usize,
    backtick: bool,
) -> Result<(String, bool, bool), ShellError> {
    // Returns (piece, is_static, parse_limited_increment).
    let value = static_printf_substitution(content, cursor, end, backtick)?;
    let limited = value.is_none() && is_printf_substitution(content, cursor, end, backtick)?;
    Ok(match value {
        Some(v) => (v, true, limited),
        None => ("$DYNAMIC".to_string(), false, limited),
    })
}

/// Port of `_bounded_shell_tokens(content, command_start, body_start)` (char indices).
///
/// # Errors
/// Propagates the Python `TypeError` of `\c` + a multi-character `upper()` ([`ShellError`]).
#[allow(clippy::too_many_lines)]
pub fn bounded_shell_tokens(
    content: &[char],
    command_start: usize,
    body_start: usize,
) -> Result<BoundedTokens, ShellError> {
    let mut st = State::new();
    let mut quote: Option<char> = None;
    let mut ansi_c_quote = false;
    let mut boundary_incomplete = false;
    let mut parse_limited = false;
    let mut cursor = body_start;
    let limit = content.len().min(body_start + ROOT_GLOB_COMMAND_CHARS);
    let wrapper_quote = command_wrapper_quote(content, command_start);
    let done = |st: &mut State, end: usize, limited: bool| -> BoundedTokens {
        BoundedTokens {
            tokens: std::mem::take(&mut st.tokens),
            end,
            limited,
        }
    };

    while cursor < limit {
        let character = content[cursor];
        if let Some(q) = quote {
            if character == q {
                quote = None;
                ansi_c_quote = false;
            } else if character == '\\' && ansi_c_quote {
                let (decoded, next) = decode_ansi_c_escape(content, cursor, limit)?;
                cursor = next;
                if decoded.contains('\0') {
                    match skip_ansi_c_quote_tail(content, cursor, limit) {
                        None => return Ok(done(&mut st, limit, true)),
                        Some(closing) => {
                            cursor = closing;
                            continue;
                        }
                    }
                }
                st.append(
                    &decoded,
                    Piece {
                        quoted: true,
                        ..Piece::default()
                    },
                );
                continue;
            } else if q == '"' && character == '$' && cursor + 1 < limit {
                let mut closed = false;
                if content[cursor + 1] == '(' {
                    let Some(end) = skip_command_substitution(content, cursor, limit)? else {
                        return Ok(done(&mut st, limit, true));
                    };
                    let (piece, is_static, lim) = substitution_piece(content, cursor, end, false)?;
                    parse_limited = parse_limited || lim;
                    st.append(
                        &piece,
                        Piece {
                            dynamic_can_be_empty: !is_static,
                            quoted: true,
                            ..Piece::default()
                        },
                    );
                    cursor = end;
                    continue;
                }
                if let Some(end) =
                    skip_parameter_expansion(content, cursor, limit, true, Some(&mut closed))?
                {
                    st.append(
                        "$DYNAMIC",
                        Piece {
                            dynamic_can_be_empty: true,
                            quoted: true,
                            ..Piece::default()
                        },
                    );
                    cursor = end;
                    if closed {
                        quote = None;
                        ansi_c_quote = false;
                    }
                    continue;
                }
                // A `$` that opens nothing is dropped; fall through to `cursor += 1`.
            } else if q == '"' && character == '`' {
                let Some(end) = skip_backtick_substitution(content, cursor, limit)? else {
                    return Ok(done(&mut st, limit, true));
                };
                let (piece, is_static, lim) = substitution_piece(content, cursor, end, true)?;
                parse_limited = parse_limited || lim;
                st.append(
                    &piece,
                    Piece {
                        dynamic_can_be_empty: !is_static,
                        quoted: true,
                        ..Piece::default()
                    },
                );
                cursor = end;
                continue;
            } else if character == '\\' && q == '"' && cursor + 1 < limit {
                let escaped = content[cursor + 1];
                if escaped == '\n' {
                    cursor += 2;
                    continue;
                }
                if escaped == '\r' && cursor + 2 < limit && content[cursor + 2] == '\n' {
                    cursor += 3;
                    continue;
                }
                let piece = if "$`\"\\".contains(escaped) {
                    escaped.to_string()
                } else {
                    format!("\\{escaped}")
                };
                st.append(
                    &piece,
                    Piece {
                        quoted: true,
                        ..Piece::default()
                    },
                );
                cursor += 2;
                continue;
            } else if character == '\\' && q == '"' {
                boundary_incomplete = true;
                cursor += 1;
                continue;
            } else {
                st.append(
                    &character.to_string(),
                    Piece {
                        quoted: true,
                        ..Piece::default()
                    },
                );
            }
            cursor += 1;
            continue;
        }
        if wrapper_quote == Some(character) {
            st.flush(true);
            return Ok(done(&mut st, cursor, parse_limited));
        }
        if character == '$' && cursor + 1 < limit && is_quote_char(content[cursor + 1]) {
            st.mark_quoted_word();
            let q = content[cursor + 1];
            quote = Some(q);
            ansi_c_quote = q == '\'';
            cursor += 2;
            continue;
        }
        if is_quote_char(character) {
            st.mark_quoted_word();
            quote = Some(character);
        } else if character == '`' {
            let Some(end) = skip_backtick_substitution(content, cursor, limit)? else {
                return Ok(done(&mut st, limit, true));
            };
            let (piece, is_static, lim) = substitution_piece(content, cursor, end, true)?;
            parse_limited = parse_limited || lim;
            st.append(
                &piece,
                Piece {
                    unquoted: is_static,
                    dynamic_can_be_empty: !is_static,
                    ..Piece::default()
                },
            );
            cursor = end;
            continue;
        } else if character == '$' && cursor + 1 < limit && content[cursor + 1] == '(' {
            let Some(end) = skip_command_substitution(content, cursor, limit)? else {
                return Ok(done(&mut st, limit, true));
            };
            let (piece, is_static, lim) = substitution_piece(content, cursor, end, false)?;
            parse_limited = parse_limited || lim;
            st.append(
                &piece,
                Piece {
                    unquoted: is_static,
                    dynamic_can_be_empty: !is_static,
                    ..Piece::default()
                },
            );
            cursor = end;
            continue;
        } else if character == '$' {
            if let Some(end) = skip_parameter_expansion(content, cursor, limit, false, None)? {
                if is_ifs_expansion(content, cursor, end) {
                    st.source_word_has_content = true;
                    st.flush(true);
                } else {
                    st.append(
                        "$DYNAMIC",
                        Piece {
                            dynamic_can_be_empty: true,
                            ..Piece::default()
                        },
                    );
                }
                cursor = end;
                continue;
            }
            if cursor + 1 == limit && limit < content.len() && content[limit] == '(' {
                boundary_incomplete = true;
            }
        } else if (character == '<' || character == '>')
            && cursor + 1 < limit
            && content[cursor + 1] == '('
        {
            let Some(end) = skip_command_substitution(content, cursor, limit)? else {
                return Ok(done(&mut st, limit, true));
            };
            st.append(
                &format!("{character}$DYNAMIC"),
                Piece {
                    dynamic_can_be_empty: true,
                    ..Piece::default()
                },
            );
            cursor = end;
            continue;
        } else if character == '\\' {
            if cursor + 1 >= limit {
                boundary_incomplete = true;
                cursor += 1;
                continue;
            }
            if content[cursor + 1] == '\n' {
                cursor += 2;
                continue;
            }
            if content[cursor + 1] == '\r' && cursor + 2 < limit && content[cursor + 2] == '\n' {
                cursor += 3;
                continue;
            }
            st.append_plain(&content[cursor + 1].to_string());
            cursor += 1;
        } else if character == '\n' {
            st.flush(true);
            return Ok(done(&mut st, cursor, parse_limited));
        } else if is_space(character) {
            st.flush(true);
            st.source_word_has_content = false;
        } else if character == '#' && !st.word.started {
            return Ok(done(&mut st, cursor, parse_limited));
        } else if character == '<' || character == '>' {
            st.flush(true);
            st.source_word_has_content = false;
            st.expect_redirection_target = true;
            if cursor + 1 < limit && content[cursor + 1] == character {
                cursor += 1;
            }
            if cursor + 1 < limit && (content[cursor + 1] == '&' || content[cursor + 1] == '|') {
                cursor += 1;
            }
        } else if character == '&'
            && cursor + 1 == limit
            && limit < content.len()
            && content[limit] == '>'
        {
            boundary_incomplete = true;
            cursor += 1;
            continue;
        } else if character == '&' && cursor + 1 < limit && content[cursor + 1] == '>' {
            st.flush(true);
            st.source_word_has_content = false;
            st.expect_redirection_target = true;
            cursor += 1;
            if cursor + 1 < limit && content[cursor + 1] == '>' {
                cursor += 1;
            }
        } else if ";|&()".contains(character) {
            st.flush(true);
            return Ok(done(&mut st, cursor, parse_limited));
        } else {
            if !st.source_word_has_content && character == '~' {
                st.word.leading_tilde_unquoted = true;
            }
            st.append(
                &character.to_string(),
                Piece {
                    unquoted: character == '*' || character == '?',
                    unquoted_brace_syntax: "{},".contains(character),
                    ..Piece::default()
                },
            );
        }
        cursor += 1;
    }
    let neutral_state = quote.is_none() && !boundary_incomplete && !st.expect_redirection_target;
    let known_terminator = limit < content.len()
        && neutral_state
        && ("\n;|&()".contains(content[limit])
            || wrapper_quote == Some(content[limit])
            || (content[limit] == '#' && !st.word.started));
    let complete =
        (limit == content.len() && neutral_state && wrapper_quote.is_none()) || known_terminator;
    st.flush(complete);
    Ok(done(&mut st, limit, !complete || parse_limited))
}
