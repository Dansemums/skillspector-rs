//! `has_bounded_parse_exhaustion`: did a destructive `rm` command exceed the parser's span contract?
//! The coverage slice (AE1) asks this per file.

use crate::shell_tokens::{
    Chars, JsonQuotes, bounded_shell_tokens, destructive_command_words,
    has_shell_command_word_exhaustion_json, has_unsupported_brace_expansion,
    is_root_glob_documentation, markdown_shell_text, markdown_shell_text_fences,
    validated_json_string_spans,
};
use crate::skill::FileType;
use std::collections::BTreeSet;

/// `has_bounded_parse_exhaustion(content, file_type=..., complete_context=...)`.
///
/// Returns `None` for the readings that are not ported, so the caller can fall back: Python and
/// Perl with `complete_context` (`_PythonSourceOwnership` token ownership, print-literal
/// projection). Markdown with `complete_context` is the lexical reading followed, when it limits,
/// by the possessive-apostrophe retry; without it the fence projection. Shell and every other type
/// use the plain reading.
#[must_use]
pub fn has_bounded_parse_exhaustion(
    content: &str,
    ft: FileType,
    complete_context: bool,
) -> Option<bool> {
    let chars = Chars::new(content);
    match ft {
        FileType::Python | FileType::Perl if complete_context => None,
        FileType::Markdown if complete_context => {
            let spans = validated_json_string_spans(&chars.chars);
            let lexical = markdown_shell_text(&chars.chars, true, false);
            if !exhausted(&lexical, &spans).unwrap_or(false) {
                return Some(false);
            }
            // The possessive-apostrophe retry can only resolve a limit of the lexical reading.
            let prose = markdown_shell_text(&chars.chars, true, true);
            Some(exhausted(&prose, &spans).unwrap_or(false))
        }
        FileType::Markdown => {
            let projected = markdown_shell_text_fences(&chars.chars);
            Some(exhausted(&projected, &[]).unwrap_or(false))
        }
        _ => Some(exhausted(&chars.chars, &[]).unwrap_or(false)),
    }
}

fn exhausted(
    text: &[char],
    json_spans: &[(usize, usize)],
) -> Result<bool, crate::shell_tokens::ShellError> {
    let openers: BTreeSet<usize> = json_spans.iter().map(|&(s, _)| s).collect();
    let closers: BTreeSet<usize> = json_spans.iter().map(|&(_, e)| e - 1).collect();
    let hints = (!json_spans.is_empty()).then_some(JsonQuotes {
        openers: &openers,
        closers: &closers,
    });
    if has_shell_command_word_exhaustion_json(text, 0, hints.as_ref())? {
        return Ok(true);
    }
    let mut covered_until = 0usize;
    for (command_start, body_start) in destructive_command_words(text)? {
        if command_start < covered_until
            || is_root_glob_documentation(text, command_start, body_start)
        {
            continue;
        }
        let parsed = bounded_shell_tokens(text, command_start, body_start)?;
        covered_until = covered_until.max(parsed.end);
        if parsed.limited || has_unsupported_brace_expansion(&parsed.tokens) {
            return Ok(true);
        }
    }
    // Each proven JSON string is checked on its own, so an earlier unmatched tick cannot consume it.
    for &(start, end) in json_spans {
        let slice = &text[start..end];
        let (o, c) = (BTreeSet::from([0usize]), BTreeSet::from([slice.len() - 1]));
        let own = JsonQuotes {
            openers: &o,
            closers: &c,
        };
        if has_shell_command_word_exhaustion_json(slice, 0, Some(&own))? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_rm_is_within_bounds() {
        assert_eq!(
            has_bounded_parse_exhaustion("rm -rf /tmp/x\n", FileType::Shell, true),
            Some(false)
        );
    }

    #[test]
    fn unsupported_brace_expansion_is_exhaustion() {
        let many = format!(
            "rm -rf {{{}}}/x\n",
            (0..9).map(|i| i.to_string()).collect::<Vec<_>>().join(",")
        );
        assert_eq!(
            has_bounded_parse_exhaustion(&many, FileType::Shell, true),
            Some(true)
        );
    }

    #[test]
    fn markdown_prose_is_within_bounds() {
        let md = "It doesn't matter.\n\nUse `rm -rf build` to clean.\n";
        assert_eq!(
            has_bounded_parse_exhaustion(md, FileType::Markdown, true),
            Some(false)
        );
    }

    #[test]
    fn unported_readings_say_so() {
        assert_eq!(
            has_bounded_parse_exhaustion("x", FileType::Python, true),
            None
        );
        assert!(has_bounded_parse_exhaustion("x", FileType::Markdown, false).is_some());
    }
}
