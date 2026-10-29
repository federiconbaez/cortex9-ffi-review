use ffi_review::{generate_tests, render_markdown, scan_dir_opts, Risk};
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage:
  ffi-review scan <crate-dir> [--json] [--top N] [--emit-tests FILE] [--fail-on high|medium] [--include-tests]

  --json         machine-readable report (findings, exports, ranking)
  --top N        functions shown in the ranking (default 20)
  --emit-tests   write an integration-test file that calls every exported
                 #[no_mangle] fn with NULL / 0 arguments (run it under miri/ASan)
  --include-tests  also analyse tests/, benches/, examples/, #[cfg(test)] and #[test] code
  --fail-on      exit 1 if any finding of that risk or higher exists

exit codes: 0 ok, 1 --fail-on threshold hit, 2 usage, 3 some files could not be parsed";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("scan") || args.len() < 2 {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let root = PathBuf::from(&args[1]);
    let (mut json, mut top, mut emit, mut fail_on, mut include_tests) = (false, 20usize, None, None, false);
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--include-tests" => include_tests = true,
            "--top" => {
                i += 1;
                top = match args.get(i).and_then(|v| v.parse().ok()) {
                    Some(v) => v,
                    None => {
                        eprintln!("{USAGE}");
                        return ExitCode::from(2);
                    }
                }
            }
            "--emit-tests" => {
                i += 1;
                emit = args.get(i).cloned();
            }
            "--fail-on" => {
                i += 1;
                fail_on = match args.get(i).map(String::as_str) {
                    Some("high") => Some(Risk::High),
                    Some("medium") => Some(Risk::Medium),
                    _ => {
                        eprintln!("{USAGE}");
                        return ExitCode::from(2);
                    }
                }
            }
            _ => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    if !root.is_dir() {
        eprintln!("not a directory: {}", root.display());
        return ExitCode::from(2);
    }
    let rep = scan_dir_opts(&root, include_tests);
    if json {
        let v = serde_json::json!({"report": &rep, "ranking": rep.ranking()});
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
    } else {
        print!("{}", render_markdown(&rep, top));
    }
    if let Some(path) = emit {
        let (src, skipped) = generate_tests(&rep);
        if let Err(e) = std::fs::write(&path, src) {
            eprintln!("cannot write {path}: {e}");
            return ExitCode::from(2);
        }
        eprintln!("wrote {path}; skipped exports: {}", skipped.len());
        for s in skipped {
            eprintln!("  skipped {s}");
        }
    }
    if !rep.parse_errors.is_empty() {
        eprintln!("{} file(s) could not be parsed; report is incomplete", rep.parse_errors.len());
        return ExitCode::from(3);
    }
    if let Some(t) = fail_on {
        if rep.findings.iter().any(|f| f.risk >= t) {
            return ExitCode::from(1);
        }
    }
    ExitCode::SUCCESS
}
