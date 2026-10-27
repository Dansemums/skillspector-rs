//! Pattern tables of `static_patterns_tool_misuse.py` (TM1-TM4) and the safe-idiom vetoes.
//!
//! Every entry is `(python source, confidence)`; prose entries run per paragraph. Patterns are
//! compiled once with `re.IGNORECASE | re.MULTILINE`.

use crate::matcher::Pat;
use std::sync::LazyLock;

pub const MAX_COMMAND_CHARS: usize = 8192;

/// `_SHELL_HORIZONTAL_OR_CONTINUED_GAP`.
const GAP: &str = r"(?>(?:\\\r?\n)*[ \t](?:[ \t]|\\\r?\n)*)";
/// `_BOUNDED_SHELL_CLAUSE_ATOM`.
const CLAUSE_ATOM: &str = r"(?:\\(?:\r?\n|[^\n])|[^\\\n|;&])";

pub const VARIABLE_ASSIGNMENT: &str = r"^\s*([A-Za-z_]\w*)\s*=\s*True\s*$\n";
/// `_VARIABLE_SHELL_FLAG_PATTERN`.
pub const VARIABLE_FLAG: &str = concat!(
    r"^\s*([A-Za-z_]\w*)\s*=\s*True\s*$\n",
    r"(?:[^\n]{0,240}\n){0,4}?[^\n]{0,240}",
    r"(?:subprocess\.\w+|Popen)\s*\([^)]*\bshell\s*=\s*\1\b"
);

/// `DIRECT_SHELL_TRUE_PATTERNS`.
pub const DIRECT_SHELL_TRUE: [(&str, f32); 2] = [
    (r"subprocess\.\w+\s*\([^)]*shell\s*=\s*True\b", 0.8),
    (r"Popen\s*\([^)]*shell\s*=\s*True\b", 0.8),
];

/// `TM1_CODE_PATTERNS[2:]` (the variable-shell flag pattern first), then `TM1_PROSE_PATTERNS`.
/// The `bool` is "prose".
pub fn tm1_ordinary() -> Vec<(String, f32, bool)> {
    let rm = format!(
        r"\b(?:rm|del|erase)\b{GAP}{CLAUSE_ATOM}{{0,{MAX_COMMAND_CHARS}}}(?:\\)?-(?:rf|fr|r){GAP}[/~]"
    );
    let mut v: Vec<(String, f32, bool)> =
        vec![(VARIABLE_FLAG.to_owned(), 0.8, false), (rm, 0.9, false)];
    for (p, c) in TM1_REST {
        v.push(((*p).to_owned(), *c, false));
    }
    v.push((TM1_PROSE.0.to_owned(), TM1_PROSE.1, true));
    v
}

const TM1_REST: &[(&str, f32)] = &[
    (r"--force\s+(?:delete|remove|push|reset|clean)", 0.7),
    (r"--no-?(?:check|validate|confirm|protect|safe)\b", 0.75),
    (
        r"--skip-?(?:validation|verification|checks?|auth|tests?)",
        0.7,
    ),
    (r"--allow-?(?:root|unrelated|unsafe)\b", 0.65),
    (
        r#"\brm\b\s+(?:-[A-Za-z]+\s+)*(?:--\s+)?(?:['"][^'"]*/[^'"]*['"]|[^\s|;&>]*/[^\s|;&>]*)"#,
        0.85,
    ),
    (r#"\bshutil\.rmtree\s*\(\s*['"]\s*/"#, 0.85),
    (
        r#"chmod\s+(?:-[\w=-]*[ \t]+)*["']?[+=]?0*[0-7]{2,3}[2367](?![0-9\w])["']?"#,
        0.8,
    ),
    (r"(?:chmod|chown)\s+[^|]*a\+rwx", 0.8),
    (r"git\s+push\s+[^|]*--force", 0.7),
    (r"git\s+reset\s+--hard", 0.65),
    (r"git\s+clean\s+-[fd]+x", 0.7),
    (
        r"\bgit\s+(?:am|commit|merge|push)\b[^\n|]*--no-verify\b",
        0.75,
    ),
    (r"curl\s+[^|]*-k\b", 0.6),
    (r"curl\s+[^|]*--insecure\b", 0.65),
    (r"wget\s+[^|]*--no-check-certificate", 0.65),
    (r#"\b(?:delete|remove)\s+['"]?/[^\s'"]{1,100}"#, 0.80),
    (
        r#"(?:execute|query)\s*\(\s*f?['"].*?\{.*?\}.*?\b(?:DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE)\b"#,
        0.85,
    ),
];

const TM1_PROSE: (&str, f32) = (
    r"(?:set|pass|use)\s+(?:the\s+)?(?:parameter|argument|flag|option)\s+(?:to\s+)?(?:shell\s*=\s*True|--force|-rf)\b",
    0.8,
);

pub const TM2_CODE: &[(&str, f32)] = &[
    (r"(?:&&|;)\s*\b(?:rm\b|del\b|erase\b)\s+-", 0.75),
    (r"(?:&&|;)\s*(?:curl|wget)\s+[^|]*\|\s*(?:ba)?sh", 0.9),
    (r"(?:&&|;)\s*(?:sudo|su\s+)", 0.75),
    (r"(?:&&|;)\s*(?:chmod|chown)\s+(?:777|666|a\+rwx|-R)", 0.75),
    (r"\|\s*(?:sudo|su)\s+", 0.75),
    (r"\|\s*(?:sh|bash|zsh|python|node|ruby|perl)\s*$", 0.7),
    (r"\|\s*(?:tee|xargs)\s+.*?\b(?:rm|del|sudo|curl)\b", 0.75),
];
pub const TM2_PROSE: &[(&str, f32)] = &[
    (
        r"(?:first|step\s+1)[^\n]{0,500}(?:then|step\s+2)[^\n]{0,500}(?:finally|step\s+3)[^\n]{0,200}\b(?:delete|remove|wipe|destroy|exfiltrate|send)\b",
        0.7,
    ),
    (
        r"(?:chain|combine|sequence|pipe)\s+(?:these\s+)?(?:tools?|commands?|actions?)\s+to\s+(?:bypass|circumvent|avoid|skip)\s+(?:the\s+)?(?:safety|security|check|restriction|limit)",
        0.9,
    ),
    (
        r"(?:use|call)\s+(?:tool\s+)?(?:A|one|the\s+first)\s+(?:to|and)[^\n]{0,300}(?:then\s+)?(?:use|call|pass\s+(?:the\s+)?(?:output|result)\s+to)\s+(?:tool\s+)?(?:B|two|another)",
        0.6,
    ),
    (
        r"(?:after|once)\s+(?:the\s+)?(?:first|initial)\s+(?:tool|command|action)\s+(?:succeeds|completes|runs)[^\n]{0,300}(?:immediately|then|next)\s+(?:run|execute|call|invoke)",
        0.6,
    ),
];

const UMASK_OCTAL: &str = r"[0-7]*[0145]\b";
const UMASK_NUMBER: &str =
    r"(?:0(?:o?[0-7]*[0145]\b)?\b|[1-9]\d*+(?<=[02468][014589]|[13579][2367]|\D[14589])\b)";

/// Role of a TM3 entry in `analyze()`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tm3Kind {
    Plain,
    Prose,
    /// `_TM3_UMASK`: replaced by the shell variant for shell files.
    Umask,
    /// `_TM3_UMASK_CALL`: skipped when its result is assigned.
    UmaskCall,
}

pub struct Tm3Entry {
    pub source: String,
    pub confidence: f32,
    pub kind: Tm3Kind,
}

/// `TM3_PATTERNS`, or `_TM3_SHELL_PATTERNS` when `shell`.
pub fn tm3_entries(shell: bool) -> Vec<Tm3Entry> {
    let umask = if shell {
        format!(r"umask(?:\s*=\s*|[ \t]+)(?:0o)?{UMASK_OCTAL}")
    } else {
        format!(r"umask(?:[ \t]+(?:0o)?{UMASK_OCTAL}|\s*=\s*{UMASK_NUMBER})")
    };
    let call = format!(r"(?<![\w.])(?:\w+\.)*umask\(\s*{UMASK_NUMBER}\s*\)");
    let mode = r#"(?:mode|permission)\s*=\s*(?:0?o?777|0?o?666)(?![ \t]*&[ \t]*~[ \t]*[\w.]*umask\b(?:\([^()\n]*\))?[ \t]*(?:[),;\]}]|(?:#[^\n]{0,240}|\r)?$(?!\n[ \t]*(?:[-+*/%|&^<>=?:.]|(?:and|or)\b))))"#;
    let mut v = Vec::new();
    let mut plain = |s: &str, c: f32| {
        v.push(Tm3Entry {
            source: s.to_owned(),
            confidence: c,
            kind: Tm3Kind::Plain,
        });
    };
    plain(r"verify\s*=\s*False", 0.75);
    plain(r"VERIFY_SSL\s*=\s*False", 0.8);
    plain(
        r"(?:ssl|tls)[_.]?verify\s*=\s*(?:False|false|0|off|no|disable)",
        0.8,
    );
    plain(
        r#"(?:REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE)\s*=\s*['"]['"]"#,
        0.75,
    );
    plain(r#"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?"#, 0.8);
    plain(
        r"(?:auth|authentication|authorization)\s*=\s*(?:None|False|false|disabled?|off|no)",
        0.75,
    );
    plain(
        r"(?:require[_-]?auth|auth[_-]?required|check[_-]?auth)\s*=\s*(?:False|false|0|no|off)",
        0.8,
    );
    plain(
        r"(?:allow[_-]?anonymous|anonymous[_-]?access)\s*=\s*(?:True|true|1|yes|on)",
        0.75,
    );
    plain(r#"(?:CORS|cors)[^=]*=\s*['"]?\*['"]?"#, 0.65);
    plain(
        r#"(?:allow|access)[_-]?(?:origin|hosts?)\s*=\s*['"]?\*['"]?"#,
        0.7,
    );
    plain(mode, 0.8);
    v.push(Tm3Entry {
        source: umask,
        confidence: 0.8,
        kind: Tm3Kind::Umask,
    });
    v.push(Tm3Entry {
        source: call,
        confidence: 0.8,
        kind: Tm3Kind::UmaskCall,
    });
    let mut plain = |s: &str, c: f32| {
        v.push(Tm3Entry {
            source: s.to_owned(),
            confidence: c,
            kind: Tm3Kind::Plain,
        });
    };
    plain(r"world[_-]?(?:readable|writable|executable)", 0.7);
    plain(
        r"(?:debug|dev|development)[_-]?mode\s*=\s*(?:True|true|1|on|yes|enable)",
        0.6,
    );
    plain(
        r#"(?:FLASK_ENV|NODE_ENV|RAILS_ENV|DJANGO_DEBUG)\s*=\s*['"]?(?:development|debug|true|1)['"]?"#,
        0.6,
    );
    plain(
        r"(?:disable|skip|ignore|bypass)[_-]?(?:security|auth|validation|sanitization|encoding|escaping)",
        0.8,
    );
    plain(
        r"(?:safe[_-]?mode|secure[_-]?mode|sandbox)\s*=\s*(?:False|false|0|off|no|disable)",
        0.8,
    );
    for (s, c) in TM3_PROSE {
        v.push(Tm3Entry {
            source: (*s).to_owned(),
            confidence: *c,
            kind: Tm3Kind::Prose,
        });
    }
    v
}

const TM3_PROSE: &[(&str, f32)] = &[
    (
        r"(?:allow|trust)\s+(?:all|any|every)\s+(?:origins?|hosts?|domains?|ips?)",
        0.7,
    ),
    (
        r"(?:by\s+default|default\s+to)\s+(?:allow|accept|trust)\s+(?:all|any|everything)",
        0.7,
    ),
    (
        r"(?:trust|accept|allow)\s+(?:all|any)\s+(?:input|connections?|certificates?|origins?)\s+(?:by\s+default)",
        0.7,
    ),
];

pub const TM4: &[(&str, f32)] = &[
    (r"privileged\s*:\s*true", 0.7),
    (r"hostPath\s*:", 0.55),
    (r"host(?:PID|Network|IPC)\s*:\s*true", 0.6),
    (r"kubectl\s+run\b[^\n]*--privileged", 0.7),
    (r"--set\b[^\n]*privileged\s*=\s*true", 0.6),
];

/// Compile `source` as `re.IGNORECASE | re.MULTILINE`.
pub fn compile(source: &str) -> Pat {
    Pat::new(source, "im")
}

pub static DIRECT_PATS: LazyLock<Vec<(Pat, f32)>> = LazyLock::new(|| {
    DIRECT_SHELL_TRUE
        .iter()
        .map(|(p, c)| (compile(p), *c))
        .collect()
});
pub static TM1_PATS: LazyLock<Vec<(Pat, f32, bool)>> = LazyLock::new(|| {
    tm1_ordinary()
        .into_iter()
        .map(|(p, c, prose)| (compile(&p), c, prose))
        .collect()
});
pub static TM2_PATS: LazyLock<Vec<(Pat, f32, bool)>> = LazyLock::new(|| {
    TM2_CODE
        .iter()
        .map(|(p, c)| (compile(p), *c, false))
        .chain(TM2_PROSE.iter().map(|(p, c)| (compile(p), *c, true)))
        .collect()
});
pub static TM4_PATS: LazyLock<Vec<(Pat, f32)>> =
    LazyLock::new(|| TM4.iter().map(|(p, c)| (compile(p), *c)).collect());

/// `_DIRECT_SHELL_TRUE_VALUE`.
pub static SHELL_TRUE_VALUE: LazyLock<Pat> = LazyLock::new(|| compile(r"shell\s*=\s*True\b"));
/// `_VARIABLE_SHELL_FLAG_RE` and its fullmatch twin (`\z`-anchored at the window end).
pub static VARIABLE_FLAG_RE: LazyLock<Pat> = LazyLock::new(|| compile(VARIABLE_FLAG));
pub static VARIABLE_FLAG_TAIL_RE: LazyLock<Pat> =
    LazyLock::new(|| compile(&format!("(?:{VARIABLE_FLAG})\\z")));
pub static VARIABLE_ASSIGNMENT_RE: LazyLock<Pat> = LazyLock::new(|| compile(VARIABLE_ASSIGNMENT));
pub static SHELL_NAME_ARGUMENT_RE: LazyLock<Pat> = LazyLock::new(|| compile(r"\bshell\s*=\s*\w+"));

static SAFE_CONTAINER: LazyLock<Vec<Pat>> = LazyLock::new(|| {
    [
        r"docker\s+run\s+.*--rm",
        r"docker\s+run\s+.*-it",
        r"docker\s+(?:build|compose|pull|push)\b",
        r"podman\s+run\b",
    ]
    .iter()
    .map(|p| Pat::new(p, "i"))
    .collect()
});
static SAFE_DOCKERFILE: LazyLock<Vec<Pat>> = LazyLock::new(|| {
    [
        r"rm\s+-rf\s+/var/lib/apt/lists",
        r"rm\s+-rf\s+/var/cache/apt",
        r"chown\s+-R\s+\w+:\w+\s+/",
        r"rm\s+-rf\s+/root/\.cache",
    ]
    .iter()
    .map(|p| Pat::new(p, "i"))
    .collect()
});
static CACHE_CLEANUP: LazyLock<Pat> = LazyLock::new(|| {
    Pat::new(
        r#"\A(?:\brm\s+-rf\s+(?P<quote>['"]?)(?P<path>(?:\$?\{?HOME\}?|~)/\.cache/[^\s;&|'"]+)(?P=quote)(?:\s*(?:$|[;&|])))\z"#,
        "i",
    )
});
static DOCKERFILE_CONTEXT: LazyLock<Pat> = LazyLock::new(|| {
    Pat::new(
        r"\b(?:FROM|RUN|WORKDIR|COPY|ADD|ENV|EXPOSE|ENTRYPOINT|CMD|USER|HEALTHCHECK|ARG)\s",
        "",
    )
});

fn any(pats: &[Pat], text: &str) -> bool {
    pats.iter().any(|p| !p.find_iter(text).is_empty())
}

/// `_is_safe_container_command`.
pub fn is_safe_container_command(text: &str) -> bool {
    any(&SAFE_CONTAINER, text)
}

/// `_is_safe_dockerfile_idiom`.
pub fn is_safe_dockerfile_idiom(context: &str, matched: &str) -> bool {
    if DOCKERFILE_CONTEXT.find_iter(context).is_empty() {
        return false;
    }
    SAFE_DOCKERFILE
        .iter()
        .any(|p| !p.find_iter(matched).is_empty() || !p.find_iter(context).is_empty())
}

/// `_is_safe_cache_cleanup`: scoped cleanup of a tool-owned user cache path.
pub fn is_safe_cache_cleanup(matched: &str) -> bool {
    let Some(hit) = CACHE_CLEANUP.find_iter(matched).into_iter().next() else {
        return false;
    };
    let Some(path) = hit.group(matched, 2) else {
        return false;
    };
    let parts: Vec<&str> = path.split('/').collect();
    let Some(cache_index) = parts.iter().position(|p| p.to_lowercase() == ".cache") else {
        return false;
    };
    let cache_parts = &parts[cache_index + 1..];
    !cache_parts.is_empty()
        && !cache_parts
            .iter()
            .any(|p| matches!(*p, "" | "." | "..") || p.contains('*'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_compile() {
        let mut sources: Vec<String> = Vec::new();
        sources.extend(DIRECT_SHELL_TRUE.iter().map(|(p, _)| (*p).to_owned()));
        sources.extend(tm1_ordinary().into_iter().map(|e| e.0));
        sources.extend(
            TM2_CODE
                .iter()
                .chain(TM2_PROSE)
                .map(|(p, _)| (*p).to_owned()),
        );
        sources.extend(tm3_entries(false).into_iter().map(|e| e.source));
        sources.extend(tm3_entries(true).into_iter().map(|e| e.source));
        sources.extend(TM4.iter().map(|(p, _)| (*p).to_owned()));
        sources.push(format!("(?:{VARIABLE_FLAG})\\z"));
        sources.push(VARIABLE_ASSIGNMENT.to_owned());
        for s in &sources {
            assert!(Pat::try_new(s, "im").is_ok(), "does not compile: {s}");
        }
        // Statics build their own patterns; force them.
        assert_eq!(DIRECT_PATS.len(), 2);
        assert!(TM1_PATS.len() > 10 && TM2_PATS.len() == 11 && TM4_PATS.len() == 5);
        for p in [
            &*SHELL_TRUE_VALUE,
            &*VARIABLE_FLAG_RE,
            &*CACHE_CLEANUP,
            &*DOCKERFILE_CONTEXT,
        ] {
            assert!(matches!(p, Pat::Fast(_) | Pat::Fancy(_)));
        }
    }

    #[test]
    fn no_pattern_silently_never_matches() {
        // `Pat::new` swallows compile errors; the rm pattern is the largest, check it fires.
        let rm = &TM1_PATS[1].0;
        assert_eq!(rm.find_iter("run rm -rf /tmp/x now").len(), 1);
        assert!(rm.find_iter("rmm -rf /").is_empty());
    }

    #[test]
    fn safe_idioms() {
        assert!(is_safe_container_command("docker run --rm -it ubuntu"));
        assert!(is_safe_dockerfile_idiom(
            "FROM x\nRUN rm -rf /var/lib/apt/lists/*",
            "rm -rf /"
        ));
        assert!(is_safe_cache_cleanup("rm -rf ~/.cache/pip"));
        assert!(!is_safe_cache_cleanup("rm -rf ~/.cache/*"));
        assert!(!is_safe_cache_cleanup("rm -rf ~/.cache/../x"));
    }

    #[test]
    fn umask_rules() {
        let e = tm3_entries(false);
        let p = |k: Tm3Kind| compile(e.iter().find(|x| x.kind == k).map_or("", |x| &x.source));
        assert_eq!(p(Tm3Kind::Umask).find_iter("umask 000").len(), 1);
        assert_eq!(p(Tm3Kind::Umask).find_iter("umask 022").len(), 0);
        assert_eq!(p(Tm3Kind::UmaskCall).find_iter("os.umask(0)").len(), 1);
        assert_eq!(p(Tm3Kind::UmaskCall).find_iter("os.umask(18)").len(), 0);
    }
}
