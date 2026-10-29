//! Tests del binario: códigos de salida y formatos.
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ffi-review"))
}

fn demo() -> String {
    format!("{}/examples/demo-ffi", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn usage_errors_exit_2() {
    assert_eq!(bin().output().unwrap().status.code(), Some(2));
    assert_eq!(bin().args(["scan", "/no/existe"]).output().unwrap().status.code(), Some(2));
    assert_eq!(bin().args(["scan", &demo(), "--top", "x"]).output().unwrap().status.code(), Some(2));
}

#[test]
fn json_report_parses() {
    let o = bin().args(["scan", &demo(), "--json"]).output().unwrap();
    assert_eq!(o.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert!(v["report"]["findings"].as_array().unwrap().len() > 8);
    assert_eq!(v["report"]["exports"].as_array().unwrap().len(), 8);
    assert!(!v["ranking"].as_array().unwrap().is_empty());
}

#[test]
fn fail_on_high_exits_1() {
    let o = bin().args(["scan", &demo(), "--fail-on", "high"]).output().unwrap();
    assert_eq!(o.status.code(), Some(1));
}

#[test]
fn markdown_has_checklist() {
    let o = bin().args(["scan", &demo()]).output().unwrap();
    let s = String::from_utf8(o.stdout).unwrap();
    assert!(s.contains("buggy_sum"));
    assert!(s.to_lowercase().contains("null"));
}
