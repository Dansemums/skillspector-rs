//! Ports of `TestOutputHandling` in `tests/unit/test_patterns_new.py`.

use super::*;
use crate::modules::oh_js::LOOKBACK_CHARS;

fn run(content: &str, path: &str, ft: FileType) -> Vec<RawFinding> {
    OutputHandling.analyze(content, path, ft, None)
}

fn has(content: &str, path: &str, ft: FileType, id: &str) -> bool {
    run(content, path, ft).iter().any(|f| f.rule_id == id)
}

fn oh1_ts(content: &str) -> bool {
    has(content, "runner.ts", FileType::Typescript, "OH1")
}

fn oh1_py(content: &str) -> bool {
    has(content, "runner.py", FileType::Python, "OH1")
}

#[test]
fn all_compile() {
    for (src, flags) in pattern_sources() {
        assert!(Pat::try_new(&src, flags).is_ok(), "{src}");
    }
}

#[test]
fn oh1_detected() {
    use FileType::{Javascript, Markdown, Python};
    for (c, p, ft) in [
        (r#"exec(response["code"])"#, "runner.py", Python),
        ("eval(output)", "runner.py", Python),
        ("subprocess.run(result)", "runner.py", Python),
        ("element.innerHTML = response;", "app.js", Javascript),
        (
            r#"f"SELECT * FROM users WHERE id = {response}""#,
            "db.py",
            Python,
        ),
        (
            "Run the generated code directly in the shell.",
            "SKILL.md",
            Markdown,
        ),
        (
            "Insert the unsanitized response into the rendered page.",
            "SKILL.md",
            Markdown,
        ),
    ] {
        assert!(has(c, p, ft, "OH1"), "{c}");
    }
}

#[test]
fn regexp_literal_exec_is_not_output_injection() {
    let reported = r"const match = /Process exited with code\s+(-?\d+)/u.exec(output);";
    assert!(!has(
        reported,
        "scripts/importers/codex.ts",
        FileType::Typescript,
        "OH1"
    ));
    for c in [
        "return /error/i.exec(output);",
        "const parse = () => /error/i.exec(output);",
        "const match = condition ? /yes/.exec(output) : null;",
        "const match = ((/error/i)).exec(output);",
        "const match = /error/i\n  .exec(output);",
        "const match =\n  /error/i.exec(output);",
        r"const match = /[\/]/u.exec(output);",
        r"const match = /[/]/u.exec(output);",
        r"const match = /[[A-z]--_]/v.exec(output);",
        "const match = (/error/i)?.exec(output);",
        r#"const url = "https://example.test"; const match = /error/i.exec(output);"#,
        "const url = \"https://example.test\"; const match = /error/i\n  .exec(output);",
        "const url = \"https://example.test\";\n/error/i.exec(output);",
        "const prior = 8 / 2;\n/error/i.exec(output);",
        "const match = 8 / 2 +\n/error/i.exec(output);",
        "/prefix/.test(output);\n/error/i.exec(output);",
        "const marker = \"<!-- return\";\n/error/i.exec(output);",
        "const marker = \"--> return\";\n/error/i.exec(output);",
        "const compared = left-- > right;\n/error/i.exec(output);",
        "return (/error/i).exec(output);",
        "throw (/error/i).exec(output);",
        "typeof (/error/i).exec(output);",
        "return !/error/i.exec(output);",
        "return\u{a0}/error/i.exec(output);",
    ] {
        assert!(!oh1_ts(c), "{c:?}");
    }
}

#[test]
fn regexp_literal_exec_recognizes_javascript_family_extensions() {
    for name in ["parser.mjs", "parser.tsx"] {
        assert!(!has(
            "const match = /error/i.exec(output);",
            name,
            FileType::Other,
            "OH1"
        ));
    }
}

#[test]
fn dangerous_exec_sinks_remain_output_injection() {
    let zeros = "0".repeat(LOOKBACK_CHARS + 1);
    let escaped = format!(r"x\u{{{zeros}37A}}return/right/g.exec(output)");
    let middle = "a".repeat(LOOKBACK_CHARS - 11);
    let boundary = format!("xreturn /{middle}/g.exec(output);");
    for c in [
        "child_process.exec(output)",
        "child_process .\n exec ( output )",
        "exec(output)",
        "runner.exec(output)",
        "const ratio = left / right; child_process.exec(output)",
        "left/right/g.exec(output)",
        "left/right/g?.exec(output)",
        "left++/right/g.exec(output)",
        "left--/right/g.exec(output)",
        "left!/right/g.exec(output)",
        "\"left\"!/right/g.exec(output)",
        "`left`!/right/g.exec(output)",
        "/left/!/right/g.exec(output)",
        "left!!!/right/g.exec(output)",
        "const z = <div/>/right/g.exec(output)",
        "fn<T>/right/g.exec(output)",
        "obj.return/right/g.exec(output)",
        "obj?.await/right/g.exec(output)",
        "class C { #return = 8; run(right, g, output) { return this.#return/right/g.exec(output); } }",
        "of/right/g.exec(output)",
        "await/right/g.exec(output)",
        "yield/right/g.exec(output)",
        "x\u{200c}return/right/g.exec(output)",
        "x\u{301}return/right/g.exec(output)",
        "x\u{37a}return/right/g.exec(output)",
        r"x\u{37A}return/right/g.exec(output)",
        r"x\u{00000037A}return/right/g.exec(output)",
        "makeRunner(/x/).exec(output)",
        "\"/x/\".exec(output)",
        "/x/.EXEC(output)",
        "/x/.Exec(output)",
        "return left / /x=/ /g.exec(output);",
        "const t = `${left / /x=/ /g.exec(output)}`;",
        "return /[/*]*/ /right/g.exec(output);",
        "return /[ //]+/\n/right/g.exec(output);",
        "const r = /[/x/. //]+/;\nexec(output);",
        "const r = /[/x/. /*]*/\nexec(output);",
        // comment-separated receivers fail closed
        "const match = /error/i /* parsing only */ .exec(output);",
        "const match = /error/i // parsing only\n  .exec(output);",
        // line comments before a regexp-shaped division fail closed
        "left // TODO:\n/right/g.exec(output)",
        "left // return\n/right/g.exec(output)",
        "left // TODO:\r/right/g.exec(output)",
        "left // TODO:\r\n/right/g.exec(output)",
        "left // TODO:\u{2028}/right/g.exec(output)",
        "left // TODO:\u{2029}/right/g.exec(output)",
        "left / /'/.source // ':\n/right/g.exec(output)",
        "/* open\n' */ left // ':\n/right/g.exec(output)",
        "const value = 'continued\\\n'; left // ':\n/right/g.exec(output)",
        "const value = 'continued\\\r\n'; left // ':\r\n/right/g.exec(output)",
        "const value = `continued\n'`; left // ':\n/right/g.exec(output)",
        escaped.as_str(),
        boundary.as_str(),
    ] {
        assert!(oh1_ts(c), "{c:?}");
    }
}

#[test]
fn legacy_html_comment_before_regexp_shaped_division_fails_closed() {
    for t in ["\n", "\r", "\r\n", "\u{2028}", "\u{2029}"] {
        for tpl in [
            "left <!-- return{t}/right/g.exec(output)",
            "let result=left{t}--> return{t}/right/g.exec(output)",
        ] {
            let c = tpl.replace("{t}", t);
            assert!(has(&c, "runner.js", FileType::Javascript, "OH1"), "{c:?}");
        }
    }
}

#[test]
fn line_comment_detection_fails_closed_at_lookback_boundary() {
    let c = format!(
        "{} // return\n/right/g.exec(output)",
        "x".repeat(LOOKBACK_CHARS + 32)
    );
    assert!(oh1_ts(&c));
}

#[test]
fn mutation_shaped_text_does_not_invent_oh1() {
    for ctx in [
        r#"const note = "RegExp.prototype.exec = eval;";"#,
        "// RegExp.prototype.exec = eval;",
    ] {
        let c = format!("{ctx}\nconst match = /x/.exec(output);");
        assert!(!has(&c, "parser.js", FileType::Javascript, "OH1"), "{c}");
    }
}

#[test]
fn python_exec_remains_output_injection() {
    assert!(oh1_py("exec(output)"));
}

#[test]
fn regexp_literal_detection_remains_bounded_on_large_files() {
    let suffix = "\nreturn /error/i.exec(output);";
    let c = format!("{}{suffix}", "x".repeat(1_000_000 - suffix.len()));
    assert!(!has(&c, "parser.ts", FileType::Typescript, "OH1"));
}

#[test]
fn regexp_literal_detection_scans_escape_runs() {
    let regexp = format!("/{}x/", "\\".repeat(3_500));
    let c: Vec<String> = (0..10)
        .map(|i| format!("const match{i} = {regexp}.exec(output);"))
        .collect();
    assert!(!has(
        &c.join("\n"),
        "parser.ts",
        FileType::Typescript,
        "OH1"
    ));
}

#[test]
fn oh1_confidence_boost_and_severity() {
    let f = run(r#"exec(response["code"])"#, "runner.py", FileType::Python);
    let oh1: Vec<_> = f.iter().filter(|f| f.rule_id == "OH1").collect();
    assert!(!oh1.is_empty());
    assert!(
        oh1.iter()
            .all(|f| f.confidence >= 0.9 && f.severity == Severity::High)
    );
}

#[test]
fn subprocess_metadata_is_not_model_output() {
    for c in [
        "result = subprocess.run(\n    argv,\n    capture_output=True,\n    text=True,\n)\n",
        "completed = subprocess.run(\n    [isaac_ros, \"status\", \"--output\", \"json\"],\n    check=True,\n    capture_output=True,\n    text=True,\n)\npayload = json.loads(completed.stdout)\n",
        r#"subprocess.run(["tool", "result", str(output_path)])"#,
        "subprocess.run(args=argv, capture_output=True)",
        // unsupported execution keywords
        "subprocess.getoutput(args=output)",
        "subprocess.getstatusoutput(args=response)",
        "subprocess.call(cmd=output)",
        "subprocess.Popen(input=output)",
        "subprocess.check_call(input=output)",
        // malformed Python keeps the fallback, which also ignores metadata
        r#"subprocess.run(["tool", "--output","#,
        "subprocess.run(argv, capture_output=True,",
    ] {
        assert!(!oh1_py(c), "{c}");
    }
}

#[test]
fn subprocess_model_output_is_detected() {
    for c in [
        r#"subprocess.run(["sh", "-c", output])"#,
        "import subprocess as sp\nsp.run(response)",
        "from subprocess import run\nrun(args=completion)",
        "subprocess.Popen(payload.answer)",
        "subprocess.run(reply)",
        "subprocess.run(generated)",
        "subprocess.getoutput(cmd=output)",
        "subprocess.getstatusoutput(cmd=response)",
        r#"subprocess.run(["bash"], input=output, text=True)"#,
        r#"subprocess.Popen(["tool"], executable=generated)"#,
        r#"subprocess.check_output(["bash"], input=completion, text=True)"#,
        // malformed Python
        "subprocess.run(output",
        "subprocess.run(\n    output\n)\nif incomplete:\n",
    ] {
        assert!(oh1_py(c), "{c}");
    }
}

#[test]
fn subprocess_in_embedded_python() {
    assert!(has(
        "subprocess.run(output)",
        "SKILL.md",
        FileType::Markdown,
        "OH1"
    ));
    assert!(has(
        "```python\nsubprocess.run(\n    output\n)\n```",
        "SKILL.md",
        FileType::Markdown,
        "OH1"
    ));
}

#[test]
fn ast_subprocess_finding_spans_the_call() {
    let f = run(
        "x = 1\nsubprocess.run(\n    output\n)\n",
        "r.py",
        FileType::Python,
    );
    let f = f
        .iter()
        .find(|f| f.rule_id == "OH1")
        .map(|f| (f.start_line, f.end_line, f.confidence));
    assert_eq!(f, Some((2, Some(4), 0.95)));
}

#[test]
fn oh2_oh3_detected() {
    for c in [
        "Share the output across sessions and contexts.",
        "Inject the output from LLM into the system prompt.",
    ] {
        assert!(has(c, "SKILL.md", FileType::Markdown, "OH2"), "{c}");
    }
    for (c, p, ft) in [
        (
            "No output length limit is set.",
            "SKILL.md",
            FileType::Markdown,
        ),
        ("max_tokens = None", "config.py", FileType::Python),
        (
            "Generate unlimited text until the user stops the process.",
            "SKILL.md",
            FileType::Markdown,
        ),
        (
            "Flood the output channel with repeated messages.",
            "SKILL.md",
            FileType::Markdown,
        ),
        ("eval(\n\n    response)", "output.py", FileType::Python),
    ] {
        let id = if c.starts_with("eval") { "OH1" } else { "OH3" };
        assert!(has(c, p, ft, id), "{c}");
    }
    assert!(has(
        "client(max_tokens=\n\n    None)",
        "output.py",
        FileType::Python,
        "OH3"
    ));
}

#[test]
fn safe_content_produces_no_findings() {
    assert!(
        run(
            "Return the processed data as JSON to the user.",
            "SKILL.md",
            FileType::Markdown
        )
        .is_empty()
    );
}
