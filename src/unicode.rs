//! Python-compatible Unicode predicates (Unicode 15.1.0, from `unicode_tables`).

use crate::unicode_tables as t;

fn in_ranges(table: &[(u32, u32)], c: char) -> bool {
    let c = u32::from(c);
    table
        .binary_search_by(|&(lo, hi)| {
            if c < lo {
                std::cmp::Ordering::Greater
            } else if c > hi {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

fn map_lookup(table: &'static [(u32, &'static str)], c: char) -> Option<&'static str> {
    let c = u32::from(c);
    table
        .binary_search_by_key(&c, |&(k, _)| k)
        .ok()
        .map(|i| table[i].1)
}

/// `str.isalpha()` for one character.
#[must_use]
pub fn is_alpha(c: char) -> bool {
    in_ranges(t::ALPHA, c)
}

/// `str.isalnum()` for one character.
#[must_use]
pub fn is_alnum(c: char) -> bool {
    in_ranges(t::ALNUM, c)
}

/// `str.isspace()` for one character (note: includes U+001C..U+001F, unlike `char::is_whitespace`).
#[must_use]
pub fn is_space(c: char) -> bool {
    in_ranges(t::SPACE, c)
}

/// `str.isprintable()` for one character.
#[must_use]
pub fn is_printable(c: char) -> bool {
    in_ranges(t::PRINTABLE, c)
}

/// `unicodedata.category(c)`; unassigned code points are `"Cn"`.
#[must_use]
pub fn category(c: char) -> &'static str {
    let c = u32::from(c);
    t::CATEGORY
        .binary_search_by(|&(lo, hi, _)| {
            if c < lo {
                std::cmp::Ordering::Greater
            } else if c > hi {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .map_or("Cn", |i| t::CATEGORY_NAMES[usize::from(t::CATEGORY[i].2)])
}

/// `unicodedata.normalize("NFKC", c)` for one character, `None` when unchanged.
#[must_use]
pub fn nfkc(c: char) -> Option<&'static str> {
    map_lookup(t::NFKC, c)
}

/// `c.casefold()` for one character, `None` when unchanged.
#[must_use]
pub fn casefold_char(c: char) -> Option<&'static str> {
    map_lookup(t::CASEFOLD, c)
}

/// `Default_Ignorable_Code_Point` (Unicode 15.1.0).
#[must_use]
pub fn is_default_ignorable(c: char) -> bool {
    in_ranges(t::DEFAULT_IGNORABLE, c)
}

/// ASCII skeleton of a confusable character (UTS #39 subset).
#[must_use]
pub fn confusable(c: char) -> Option<&'static str> {
    map_lookup(t::CONFUSABLE, c)
}

/// `s.casefold()`.
#[must_use]
pub fn casefold(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match casefold_char(c) {
            Some(r) => out.push_str(r),
            None => out.push(c),
        }
    }
    out
}

/// `s.split()`: split on Python whitespace, dropping empty parts.
pub fn py_split(s: &str) -> impl Iterator<Item = &str> {
    s.split(is_space).filter(|p| !p.is_empty())
}

/// `" ".join(s.split())`.
#[must_use]
pub fn collapse_ws(s: &str) -> String {
    py_split(s).collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_pinned() {
        assert_eq!(t::UNIDATA_VERSION, "15.1.0");
    }

    #[test]
    fn predicates_match_python() {
        assert!(is_space('\x1c') && is_space('\u{85}') && is_space('\u{3000}') && !is_space('a'));
        assert!(is_alpha('é') && !is_alpha('1') && is_alnum('1'));
        assert!(is_printable('a') && !is_printable('\u{200b}') && !is_printable('\n'));
        assert_eq!(category('a'), "Ll");
        assert_eq!(category('\u{200b}'), "Cf");
        assert_eq!(nfkc('\u{fb01}'), Some("fi"));
        assert_eq!(casefold("Straße"), "strasse");
        assert!(is_default_ignorable('\u{ad}') && !is_default_ignorable('a'));
        assert_eq!(confusable('\u{c6}'), Some("AE"));
        assert_eq!(collapse_ws("  a \x1c b\n"), "a b");
    }
}
