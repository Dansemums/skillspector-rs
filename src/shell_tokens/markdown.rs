//! `_markdown_shell_text(content, check_runtime, complete_context=False)`: the Markdown line
//! state machine, reduced to what survives `complete_context=False` (fence delimiters are blanked;
//! inline backtick pairing and prose apostrophes are never applied). Char indices throughout.

use super::markdown_inline::Inline;
use super::powershell::ci;
use crate::unicode::is_space;

fn is_break(c: char) -> bool {
    matches!(
        c,
        '\r' | '\n'
            | '\x0b'
            | '\x0c'
            | '\x1c'
            | '\x1d'
            | '\x1e'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

/// `str.splitlines(keepends=True)` as `(start, end)` char ranges.
pub(super) fn split_keepends(chars: &[char]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < chars.len() {
        if is_break(chars[i]) {
            let end = if chars[i] == '\r' && chars.get(i + 1) == Some(&'\n') {
                i + 2
            } else {
                i + 1
            };
            out.push((start, end));
            start = end;
            i = end;
        } else {
            i += 1;
        }
    }
    if start < chars.len() {
        out.push((start, chars.len()));
    }
    out
}

fn rstrip_breaks(line: &[char]) -> &[char] {
    let mut end = line.len();
    while end > 0 && is_break(line[end - 1]) {
        end -= 1;
    }
    &line[..end]
}

fn is_blank_char(c: char) -> bool {
    c == ' ' || c == '\t'
}

fn lstrip_blanks(s: &[char]) -> usize {
    s.iter().take_while(|&&c| is_blank_char(c)).count()
}

fn block_separator(line: &[char]) -> bool {
    let a = lstrip_blanks(line);
    let b = line
        .iter()
        .rposition(|&c| !is_blank_char(c))
        .map_or(a, |i| i + 1);
    let line = &line[a..b.max(a)];
    let Some(&marker) = line.first() else {
        return false;
    };
    if !matches!(marker, '=' | '-' | '*' | '_') {
        return false;
    }
    let mut count = 0;
    let mut internal_gap = false;
    for &c in line {
        if c == marker {
            count += 1;
        } else if is_blank_char(c) && marker != '=' {
            internal_gap = true;
        } else {
            return false;
        }
    }
    count
        >= if internal_gap || matches!(marker, '*' | '_') {
            3
        } else {
            1
        }
}

fn table_cells(line: &[char], mut start: usize) -> Vec<(usize, usize)> {
    let mut end = line.len();
    while start < end && is_blank_char(line[start]) {
        start += 1;
    }
    while end > start && is_blank_char(line[end - 1]) {
        end -= 1;
    }
    if start == end {
        return Vec::new();
    }
    if line[start] == '|' {
        start += 1;
    }
    if end >= 1 && line[end - 1] == '|' && (end == 1 || line[end - 2] != '\\') {
        end -= 1;
    }
    if start > end {
        return Vec::new();
    }
    let mut cells = Vec::new();
    let mut cell_start = start;
    for cursor in start..end {
        if line[cursor] == '|' && (cursor == start || line[cursor - 1] != '\\') {
            cells.push((cell_start, cursor));
            cell_start = cursor + 1;
        }
    }
    cells.push((cell_start, end));
    cells
}

fn table_delimiter_columns(raw_line: &[char], minimum_indent: usize) -> Option<usize> {
    let line = rstrip_breaks(raw_line);
    let mut prefix = 0;
    let mut column = 0;
    while prefix < line.len() && is_blank_char(line[prefix]) {
        column += if line[prefix] == '\t' {
            4 - column % 4
        } else {
            1
        };
        prefix += 1;
    }
    if column < minimum_indent || column >= 4 || prefix == line.len() {
        return None;
    }
    if !matches!(line[prefix], '|' | ':' | '-') {
        return None;
    }
    if (line[prefix] == '-' && prefix + 1 < line.len() && is_blank_char(line[prefix + 1]))
        || block_separator(line)
    {
        return None;
    }
    let cells = table_cells(line, prefix);
    if cells.is_empty() {
        return None;
    }
    for &(mut start, mut end) in &cells {
        while start < end && is_blank_char(line[start]) {
            start += 1;
        }
        while end > start && is_blank_char(line[end - 1]) {
            end -= 1;
        }
        if start < end && line[start] == ':' {
            start += 1;
        }
        let hyphen_start = start;
        while start < end && line[start] == '-' {
            start += 1;
        }
        if start == hyphen_start {
            return None;
        }
        if start < end && line[start] == ':' {
            start += 1;
        }
        if start != end {
            return None;
        }
    }
    Some(cells.len())
}

/// `(?:[-+*]|[0-9]{1,9}[.)])`: end of a list marker at `pos`.
fn marker_end(s: &[char], pos: usize) -> Option<usize> {
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

/// `MARKDOWN_FENCE_OPEN.fullmatch(s)`: `(marker char, begin, end)` of group 1.
fn fence_open(s: &[char]) -> Option<(char, usize, usize)> {
    let spaces = s.iter().take_while(|&&c| c == ' ').count();
    if spaces > 3 {
        return None;
    }
    let marker = *s.get(spaces)?;
    if marker != '`' && marker != '~' {
        return None;
    }
    let run = s[spaces..].iter().take_while(|&&c| c == marker).count();
    if run < 3 {
        return None;
    }
    let end = spaces + run;
    if marker == '`' && s[end..].contains(&'`') {
        return None;
    }
    if s[end..].iter().any(|&c| c == '\r' || c == '\n') {
        return None;
    }
    Some((marker, spaces, end))
}

/// `MARKDOWN_FENCE_CLOSE.fullmatch(s)`: `(marker char, begin, end)` of group 1.
fn fence_close(s: &[char]) -> Option<(char, usize, usize)> {
    let spaces = s.iter().take_while(|&&c| c == ' ').count();
    if spaces > 3 {
        return None;
    }
    let marker = *s.get(spaces)?;
    if marker != '`' && marker != '~' {
        return None;
    }
    let run = s[spaces..].iter().take_while(|&&c| c == marker).count();
    if run < 3 {
        return None;
    }
    let end = spaces + run;
    s[end..]
        .iter()
        .all(|&c| is_blank_char(c))
        .then_some((marker, spaces, end))
}

fn html_open(leading: &[char]) -> bool {
    if leading.first() != Some(&'<') {
        return false;
    }
    match leading.get(1) {
        Some('!' | '?' | '/') => true,
        Some(c) if c.is_ascii_alphabetic() => {
            let mut i = 2;
            while i < leading.len() && (leading[i].is_ascii_alphanumeric() || leading[i] == '-') {
                i += 1;
            }
            leading
                .get(i)
                .is_none_or(|&c| is_space(c) || c == '/' || c == '>')
        }
        _ => false,
    }
}

/// The `html_end` terminator for an HTML-block opener line.
fn html_terminator(leading: &[char]) -> String {
    for tag in ["pre", "script", "style", "textarea"] {
        let mut i = 1;
        let mut ok = true;
        for t in tag.chars() {
            if leading.get(i).is_some_and(|&c| ci(c, t)) {
                i += 1;
            } else {
                ok = false;
                break;
            }
        }
        if ok
            && leading
                .get(i)
                .is_none_or(|&c| is_space(c) || c == '/' || c == '>')
            && leading.first() == Some(&'<')
        {
            let name: String = leading[1..i].iter().collect::<String>().to_lowercase();
            return format!("</{name}>");
        }
    }
    let text: String = leading.iter().collect();
    if text.starts_with("<!--") {
        "-->".to_string()
    } else if text.starts_with("<?") {
        "?>".to_string()
    } else if text.starts_with("<![CDATA[") {
        "]]>".to_string()
    } else if leading.get(1) == Some(&'!') && leading.get(2).is_some_and(char::is_ascii_uppercase) {
        ">".to_string()
    } else {
        String::new()
    }
}

fn is_heading(leading: &[char]) -> bool {
    let n = leading.iter().take_while(|&&c| c == '#').count();
    (1..=6).contains(&n) && leading.get(n).is_none_or(|&c| is_blank_char(c))
}

fn is_empty_list_item(leading: &[char]) -> bool {
    marker_end(leading, 0) == Some(leading.len())
}

struct Machine {
    fence: Option<(char, usize, usize)>,
    quoted_block: bool,
    html_end: Option<String>,
    paragraph_open: bool,
    paragraph_in_list: bool,
    paragraph_list_indent: usize,
    table_columns: Option<usize>,
    table_minimum_indent: usize,
    table_delimiter_line: Option<usize>,
    inline: Inline,
}

/// Port of `_markdown_shell_text(content, ..., complete_context=False)`.
#[must_use]
pub fn markdown_shell_text_fences(content: &[char]) -> Vec<char> {
    markdown_shell_text(content, false, false)
}

/// Port of `_markdown_shell_text(content, ..., complete_context, word_apostrophes)`.
#[must_use]
pub fn markdown_shell_text(content: &[char], complete: bool, word_apostrophes: bool) -> Vec<char> {
    let mut output = content.to_vec();
    let lines = split_keepends(content);
    let mut m = Machine {
        fence: None,
        quoted_block: false,
        html_end: None,
        paragraph_open: false,
        paragraph_in_list: false,
        paragraph_list_indent: 0,
        table_columns: None,
        table_minimum_indent: 0,
        table_delimiter_line: None,
        inline: Inline::new(complete, word_apostrophes),
    };
    for (line_index, &(line_start, line_end)) in lines.iter().enumerate() {
        step_line(
            &mut m,
            &mut output,
            content,
            &lines,
            line_index,
            line_start,
            line_end,
        );
    }
    m.inline.mask(content, &mut output);
    m.inline.finish(output)
}

#[allow(clippy::too_many_lines)]
fn step_line(
    m: &mut Machine,
    output: &mut [char],
    content: &[char],
    lines: &[(usize, usize)],
    line_index: usize,
    offset: usize,
    line_end: usize,
) {
    let stripped = rstrip_breaks(&content[offset..line_end]);
    let lead = lstrip_blanks(stripped);
    let mut indentation = 0;
    for &c in &stripped[..lead] {
        indentation += if c == '\t' { 4 - indentation % 4 } else { 1 };
    }
    let mut prefix = lead;
    let mut column = indentation;
    let mut leading: &[char] = &stripped[lead..];
    let mut list_indented = false;
    let mut has_list_marker = false;
    let mut list_markers = 0;
    if indentation < 4 {
        while let Some(end) = marker_end(stripped, prefix)
            && stripped.get(end).is_some_and(|&c| is_blank_char(c))
        {
            if !has_list_marker
                && m.paragraph_open
                && !m.paragraph_in_list
                && stripped[prefix].is_ascii_digit()
            {
                let digits: String = stripped[prefix..end - 1].iter().collect();
                if digits.parse::<u64>().unwrap_or(0) != 1 {
                    break;
                }
            }
            has_list_marker = true;
            list_markers += 1;
            column += end - prefix;
            prefix = end;
            let padding_start = column;
            while prefix < stripped.len() && is_blank_char(stripped[prefix]) {
                column += if stripped[prefix] == '\t' {
                    4 - column % 4
                } else {
                    1
                };
                prefix += 1;
            }
            if column - padding_start > 4 {
                list_indented = true;
                break;
            }
        }
        leading = &stripped[prefix..];
    }
    let quote_start = indentation < 4 && leading.first() == Some(&'>');
    let heading = indentation < 4 && is_heading(leading);
    let mut separator = indentation < 4 && block_separator(stripped);
    let rstripped_len = leading
        .iter()
        .rposition(|&c| !is_blank_char(c))
        .map_or(0, |i| i + 1);
    let setext_only =
        separator && (leading.first() == Some(&'=') || leading[..rstripped_len] == ['-', '-']);
    let empty_list_item = !m.paragraph_open && is_empty_list_item(leading);
    if m.table_columns.is_some() && setext_only {
        separator = false;
    }
    let is_html_open = html_open(leading);
    let mut continuing_paragraph = false;
    if m.table_columns.is_some()
        && (m.html_end.is_some()
            || m.fence.is_some()
            || quote_start
            || m.quoted_block
            || is_html_open
            || leading.is_empty()
            || indentation >= 4
            || indentation < m.table_minimum_indent
            || list_indented
            || has_list_marker
            || empty_list_item
            || heading
            || separator)
    {
        m.table_columns = None;
    }
    if let Some(end) = m.html_end.clone() {
        m.inline.mask(content, output);
        let lowered: String = leading.iter().collect::<String>().to_lowercase();
        if (!end.is_empty() && lowered.contains(&end)) || (end.is_empty() && leading.is_empty()) {
            m.html_end = None;
        }
    } else if let Some(fence) = m.fence {
        let body_lead = lstrip_blanks(stripped);
        let fence_body = &stripped[body_lead..];
        if let Some((marker, begin, end)) = fence_close(fence_body)
            && indentation >= fence.2
            && indentation - fence.2 <= 3
            && marker == fence.0
            && end - begin >= fence.1
        {
            let body_start = offset + body_lead;
            for slot in &mut output[body_start + begin..body_start + end] {
                *slot = ' ';
            }
            m.fence = None;
        }
    } else if quote_start || m.quoted_block {
        m.inline.mask(content, output);
        m.quoted_block = !leading.is_empty();
    } else if is_html_open {
        m.inline.mask(content, output);
        let terminator = html_terminator(leading);
        let lowered: String = leading.iter().collect::<String>().to_lowercase();
        m.html_end = if !terminator.is_empty() && lowered.contains(&terminator) {
            None
        } else {
            Some(terminator)
        };
    } else if leading.is_empty() || indentation >= 4 || list_indented {
        m.inline.mask(content, output);
    } else {
        if has_list_marker || heading || separator {
            m.inline.mask(content, output);
        }
        if let Some((marker, begin, end)) = fence_open(&stripped[prefix..]) {
            m.inline.mask(content, output);
            m.fence = Some((
                marker,
                end - begin,
                if has_list_marker { column } else { 0 },
            ));
            for slot in &mut output[offset + prefix + begin..offset + prefix + end] {
                *slot = ' ';
            }
        } else {
            let minimum_indent = if has_list_marker {
                column
            } else if m.paragraph_in_list {
                m.paragraph_list_indent
            } else {
                0
            };
            if m.table_columns.is_none()
                && !heading
                && !empty_list_item
                && (!separator || (setext_only && !m.paragraph_open))
                && list_markers <= 1
                && (has_list_marker || indentation >= minimum_indent)
                && line_index + 1 < lines.len()
            {
                let (next_start, next_end) = lines[line_index + 1];
                let columns =
                    table_delimiter_columns(&content[next_start..next_end], minimum_indent);
                if let Some(columns) = columns
                    && table_cells(stripped, prefix).len() == columns
                {
                    m.inline.mask(content, output);
                    separator = false;
                    m.table_columns = Some(columns);
                    m.table_minimum_indent = minimum_indent;
                    m.table_delimiter_line = Some(line_index + 1);
                }
            }
            if let Some(columns) = m.table_columns {
                m.inline.mask(content, output);
                if Some(line_index) != m.table_delimiter_line {
                    let cells = table_cells(stripped, prefix);
                    for (cell_index, &(cs, ce)) in cells.iter().enumerate() {
                        if cell_index >= columns {
                            break;
                        }
                        m.inline.add_runs(stripped, cs, ce, offset);
                        m.inline.mask(content, output);
                    }
                    if cells.is_empty() {
                        m.table_columns = None;
                    }
                }
            } else if !separator && !empty_list_item {
                let previous_ok = line_index == 0 || {
                    let (ps, pe) = lines[line_index - 1];
                    content[ps..pe].last() == Some(&'\n')
                        && rstrip_breaks(&content[ps..pe]).last() != Some(&'\\')
                };
                m.inline
                    .note_prose(leading, offset + prefix, heading, previous_ok);
                m.inline.add_runs(content, offset, line_end, 0);
                if heading {
                    m.inline.mask(content, output);
                } else {
                    continuing_paragraph = true;
                    m.paragraph_in_list = has_list_marker || m.paragraph_in_list;
                    if has_list_marker {
                        m.paragraph_list_indent = column;
                    }
                }
            }
        }
    }
    m.paragraph_open = continuing_paragraph;
    if !m.paragraph_open {
        m.paragraph_in_list = false;
        m.paragraph_list_indent = 0;
    }
}
