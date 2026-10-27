use super::*;

fn parse(src: &str) -> PyFile {
    PyFile::parse(src, "t.py")
}

fn names(src: &str) -> Vec<Option<String>> {
    let f = parse(src);
    let tree = f.tree.as_ref().expect("parses");
    let mut rows: Vec<_> = calls(tree)
        .into_iter()
        .map(|c| {
            (
                f.pos(ast::Ranged::range(c)),
                resolve_call_name(c, Some(&f.import_aliases)),
            )
        })
        .collect();
    rows.sort_by_key(|(p, _)| (p.line, p.col, p.end_line, p.end_col));
    rows.into_iter().map(|(_, n)| n).collect()
}

#[test]
fn aliases_resolve_calls() {
    let got = names("import os as o\nfrom subprocess import run as r\no.system(1)\nr(2)\nfoo()\n");
    assert_eq!(
        got,
        [
            Some("os.system".into()),
            Some("subprocess.run".into()),
            Some("foo".into())
        ]
    );
}

#[test]
fn builtins_prefix_is_collapsed_only_with_aliases() {
    let got = names("import builtins\nbuiltins.exec(1)\nbuiltins.a.b(2)\n");
    assert_eq!(got, [Some("exec".into()), Some("builtins.a.b".into())]);
    // No aliases at all (an empty dict is falsy in Python): no rewriting, builtins stay qualified.
    assert_eq!(names("builtins.exec(1)\n"), [Some("builtins.exec".into())]);
}

#[test]
fn later_import_wins_in_walk_order() {
    let f = parse("import a as x\ndef f():\n    import b as x\nimport c as x\n");
    // BFS: both top-level imports come before the nested one, which therefore wins.
    assert_eq!(f.import_aliases["x"], "b");
}

#[test]
fn relative_imports_ignore_the_level() {
    let f = parse("from . import a\nfrom ..m import b as c\nimport p.q\n");
    assert_eq!(f.import_aliases["a"], "a");
    assert_eq!(f.import_aliases["c"], "m.b");
    assert_eq!(f.import_aliases["p.q"], "p.q");
}

#[test]
fn dynamic_import_and_typed_names() {
    let f = parse(
        "import importlib\nimportlib.import_module('os').system(1)\ns = socket.socket()\ns.recv(1)\n",
    );
    let tree = f.tree.as_ref().expect("parses");
    let al = Some(&f.import_aliases);
    let types = build_type_map(tree, al);
    let all = calls(tree);
    let dynamic = all.iter().find_map(|c| resolve_dynamic_import_call(c, al));
    assert_eq!(dynamic.as_deref(), Some("os.system"));
    let typed: Vec<_> = all
        .iter()
        .filter_map(|c| resolve_call_name_typed(c, Some(&types), al))
        .collect();
    assert!(typed.contains(&"socket.socket.recv".to_owned()));
}

#[test]
fn character_columns_follow_the_splitlines_table() {
    let f = parse("s = 'é'; os.system(s)\n");
    let tree = f.tree.as_ref().expect("parses");
    let c = calls(tree)[0];
    let r = ast::Ranged::range(c);
    assert_eq!(f.pos(r).col, 10); // 'é' is two bytes
    assert_eq!(f.char_pos(r).col, Some(9));
    assert_eq!(f.source_segment(r), Some("os.system(s)"));
    // A form feed is a line break to splitlines() but not to the tokenizer: SkillSpector's
    // conversion is shifted by it, and so is ours.
    let g = parse("\x0cos.f(1)\n");
    let r = ast::Ranged::range(calls(g.tree.as_ref().expect("parses"))[0]);
    assert_eq!(g.pos(r).line, 1);
    assert_eq!(g.char_pos(r).col, Some(1));
}

#[test]
fn failures_and_limits() {
    assert!(!parse("print 'x'\n").is_parseable());
    assert!(!parse("a = 1\0\n").is_parseable());
    assert!(!parse("f() = 1\n").is_parseable());
    let deep = format!("x = {}1{}\n", "(".repeat(250), ")".repeat(250));
    assert!(!parse(&deep).is_parseable());
    let chain = format!("x = {}\n", vec!["1"; 50_000].join("+"));
    assert!(!parse(&chain).is_parseable());
    assert!(parse("# ((((((\nx = '((('\n").is_parseable());
}

#[test]
fn eligibility_follows_source_kind_and_size() {
    use crate::skill::Skill;
    let skill = Skill::from_memory(vec![
        ("a.py".into(), b"os.system(1)\n".to_vec()),
        ("b.md".into(), b"os.system(1)\n".to_vec()),
        (
            "run".into(),
            b"#!/usr/bin/env python3\nos.system(1)\n".to_vec(),
        ),
    ]);
    let got: Vec<_> = skill
        .files
        .iter()
        .map(|f| PyFile::for_file(f).is_some())
        .collect();
    assert_eq!(got, [true, false, true]);
}
