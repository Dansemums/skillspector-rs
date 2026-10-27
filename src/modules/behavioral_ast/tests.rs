use super::*;

fn run(code: &str) -> Vec<RawFinding> {
    let py = PyFile::parse(code, "script.py");
    analyze_python(&py, "script.py")
}

fn ids(code: &str) -> Vec<&'static str> {
    run(code).iter().map(|f| f.rule_id).collect()
}

#[test]
fn basic_rules() {
    assert_eq!(ids("exec(x)"), ["AST1"]);
    assert_eq!(ids("eval(x)"), ["AST2"]);
    assert_eq!(ids("__import__('os')"), ["AST3"]);
    assert_eq!(ids("compile(a, b, c)"), ["AST6"]);
    assert_eq!(ids("import subprocess\nsubprocess.run(x)"), ["AST4"]);
    assert_eq!(ids("import os\nos.system(x)"), ["AST5"]);
    assert_eq!(ids("from os import system\nsystem(x)"), ["AST5"]);
    assert_eq!(ids("import subprocess as sp\nsp.Popen(x)"), ["AST4"]);
    assert!(ids("x = 1\nprint(x)").is_empty());
    assert!(ids("def (:").is_empty());
}

#[test]
fn same_line_calls_have_distinct_columns() {
    let f = run("exec(\"first_payload_alpha\"); exec(\"second_payload_beta\")");
    assert_eq!(f.len(), 2);
    assert_ne!(f[0].fingerprint(), f[1].fingerprint());
    assert_eq!(f[1].start_column, Some(29));
}

#[test]
fn utf8_columns_are_characters() {
    let f = run("x = '\u{e9}\u{e9}'; exec(x)");
    assert_eq!(f[0].start_column, Some(10));
}

#[test]
fn getattr_rules() {
    assert_eq!(ids("getattr(o, name)"), ["AST7"]);
    assert!(ids("getattr(o, 'name')").is_empty());
    assert!(ids("getattr(o, 1)").is_empty());
    assert_eq!(ids("getattr(o, 'sys' + 'tem')"), ["AST7"]);
    assert_eq!(ids("import os\ngetattr(os, 'system')(c)"), ["AST9"]);
    assert_eq!(ids("getattr(b, ''.join(['ex','ec']))"), ["AST9"]);
    assert_eq!(ids("getattr(b, ''.join(['exe','cutor_long']))"), ["AST7"]);
    assert_eq!(ids("getattr(b, ''.join([''.join(['e']), 'x']))"), ["AST7"]);
}

#[test]
fn module_dict_access() {
    assert_eq!(ids("import os\nos.__dict__[k]"), ["AST7"]);
    assert_eq!(ids("import os\nos.__dict__['system']"), ["AST9"]);
    assert_eq!(ids("import os\nvars(os)[k]"), ["AST7"]);
    assert_eq!(ids("import os as o\no.__dict__[k]"), ["AST7"]);
    assert!(ids("self.__dict__[k]").is_empty());
    assert!(ids("import os\nos.__dict__['path']").is_empty());
    for m in ["get", "setdefault", "pop"] {
        assert_eq!(ids(&format!("import os\nos.__dict__.{m}(k)")), ["AST7"]);
        assert_eq!(
            ids(&format!("import os\nos.__dict__.{m}('eval')")),
            ["AST9"]
        );
        assert!(ids(&format!("self.__dict__.{m}(k)")).is_empty());
    }
    let f = run("import os\nos.__dict__.get(k)");
    assert_eq!(
        f[0].message,
        "Dynamic attribute access via os.__dict__.get()"
    );
}

#[test]
fn chains() {
    let f = run("exec(compile(s, 'f', 'exec'))");
    assert_eq!(
        f.iter().map(|f| f.rule_id).collect::<Vec<_>>(),
        ["AST8", "AST1", "AST6"]
    );
    assert_eq!(f[0].message, "Dangerous chain: exec() wrapping compile");
    assert_eq!(
        ids("import base64\neval(base64.b64decode(x))"),
        ["AST8", "AST2"]
    );
}

#[test]
fn deserialization() {
    assert_eq!(ids("import pickle\npickle.loads(x)"), ["AST10"]);
    assert_eq!(ids("import yaml\nyaml.load(x)"), ["AST10"]);
    assert!(ids("import yaml\nyaml.load(x, Loader=yaml.SafeLoader)").is_empty());
    assert!(ids("import yaml\nyaml.load(x, yaml.SafeLoader)").is_empty());
    assert_eq!(
        ids("import yaml\nyaml.load(x, Loader=yaml.FullLoader)"),
        ["AST10"]
    );
    assert_eq!(ids("import torch\ntorch.load(f)"), ["AST10"]);
    assert!(ids("import torch\ntorch.load(f, weights_only=True)").is_empty());
    assert_eq!(
        ids("import numpy\nnumpy.load(f, allow_pickle=True)"),
        ["AST10"]
    );
    assert_eq!(ids("import numpy\nnumpy.load(f, None, True)"), ["AST10"]);
    assert!(ids("import numpy\nnumpy.load(f)").is_empty());
}

#[test]
fn importlib_chain() {
    assert_eq!(
        ids("import importlib\nimportlib.import_module('os').system(c)"),
        ["AST5"]
    );
    assert!(ids("import importlib\nimportlib.import_module('json').dumps(c)").is_empty());
}
