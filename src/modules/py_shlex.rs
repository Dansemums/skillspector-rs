//! `shlex.shlex(command, posix=True, punctuation_chars="|&;<>()")` with `whitespace_split = True`
//! and no comment characters, as `static_patterns_supply_chain._shell_tokens` configures it.

const PUNCT: &str = "|&;<>()";

fn is_ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

#[derive(Clone, Copy, PartialEq)]
enum State {
    Start,
    Word,
    Punct,
    Quote(char),
    Escape,
}

/// Splits `command` like the Python lexer; `None` when it raises `ValueError` (unclosed quote or
/// trailing backslash) or the command contains a backtick or `$`, which `_shell_tokens` rejects.
#[must_use]
pub fn shell_tokens(command: &str) -> Option<Vec<String>> {
    if command.contains(['`', '$']) {
        return None;
    }
    let mut input: Vec<char> = command.chars().rev().collect();
    let mut tokens = Vec::new();
    while let Some(tok) = read_token(&mut input)? {
        tokens.push(tok);
    }
    Some(tokens)
}

/// One `read_token` call. Outer `None` is a `ValueError`; inner `None` is end of input.
fn read_token(input: &mut Vec<char>) -> Option<Option<String>> {
    let mut state = State::Start;
    let mut escaped_state = State::Start;
    let mut token = String::new();
    let mut quoted = false;
    loop {
        let next = input.pop();
        match state {
            State::Start => match next {
                None => break,
                Some(c) if is_ws(c) => {
                    if !token.is_empty() || quoted {
                        break;
                    }
                }
                Some('\\') => {
                    escaped_state = State::Word;
                    state = State::Escape;
                }
                Some(c) if PUNCT.contains(c) => {
                    token.push(c);
                    state = State::Punct;
                }
                Some(c @ ('\'' | '"')) => state = State::Quote(c),
                Some(c) => {
                    token.push(c);
                    state = State::Word;
                }
            },
            State::Quote(q) => {
                quoted = true;
                match next {
                    None => return None,
                    Some(c) if c == q => state = State::Word,
                    Some('\\') if q == '"' => {
                        escaped_state = State::Quote(q);
                        state = State::Escape;
                    }
                    Some(c) => token.push(c),
                }
            }
            State::Escape => {
                let c = next?;
                if let State::Quote(q) = escaped_state
                    && c != q
                    && c != '\\'
                {
                    token.push('\\');
                }
                token.push(c);
                state = escaped_state;
            }
            State::Word | State::Punct => {
                let Some(c) = next else { break };
                if is_ws(c) {
                    state = State::Start;
                    if !token.is_empty() || quoted {
                        break;
                    }
                } else if state == State::Punct {
                    if PUNCT.contains(c) {
                        token.push(c);
                    } else {
                        input.push(c);
                        break;
                    }
                } else if c == '\'' || c == '"' {
                    state = State::Quote(c);
                } else if c == '\\' {
                    escaped_state = State::Word;
                    state = State::Escape;
                } else if PUNCT.contains(c) {
                    input.push(c);
                    state = State::Start;
                    if !token.is_empty() || quoted {
                        break;
                    }
                } else {
                    token.push(c);
                }
            }
        }
    }
    if token.is_empty() && !quoted {
        return Some(None);
    }
    Some(Some(token))
}

#[cfg(test)]
mod tests {
    use super::shell_tokens;

    fn toks(s: &str) -> Option<Vec<String>> {
        shell_tokens(s)
    }

    #[test]
    fn splits_words_and_punctuation() {
        assert_eq!(
            toks("curl -fsSL https://x.io|python3 -m json.tool"),
            Some(
                [
                    "curl",
                    "-fsSL",
                    "https://x.io",
                    "|",
                    "python3",
                    "-m",
                    "json.tool"
                ]
                .map(String::from)
                .to_vec()
            )
        );
        assert_eq!(
            toks("a && b ;"),
            Some(["a", "&&", "b", ";"].map(String::from).to_vec())
        );
    }

    #[test]
    fn quotes_and_escapes() {
        assert_eq!(
            toks(r#"python3 -c 'import json; print(1)'"#),
            Some(
                ["python3", "-c", "import json; print(1)"]
                    .map(String::from)
                    .to_vec()
            )
        );
        assert_eq!(
            toks(r#"echo "a\"b" c\ d"#),
            Some(["echo", "a\"b", "c d"].map(String::from).to_vec())
        );
        assert_eq!(
            toks(r#"echo """#),
            Some(["echo", ""].map(String::from).to_vec())
        );
    }

    #[test]
    fn errors_return_none() {
        assert_eq!(toks("echo 'open"), None);
        assert_eq!(toks("echo \\"), None);
        assert_eq!(toks("echo $(x)"), None);
        assert_eq!(toks("echo `x`"), None);
    }
}
