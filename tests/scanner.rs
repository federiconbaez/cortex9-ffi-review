//! Tests del escáner sobre fuentes chicas con patrones conocidos y sobre el crate demo.
use ffi_review::{generate_tests, scan_dir, scan_dir_opts, scan_source, Risk};
use std::path::Path;

fn kinds(src: &str) -> Vec<(&'static str, String)> {
    let (f, _) = scan_source("t.rs", src).expect("parse");
    f.into_iter().map(|f| (f.kind, f.function)).collect()
}

fn has(src: &str, kind: &str, func: &str) -> bool {
    kinds(src).iter().any(|(k, f)| *k == kind && f == func)
}

#[test]
fn export_without_null_check_is_high() {
    let src = r#"
        #[no_mangle]
        pub extern "C" fn sum(p: *const u8, n: usize) -> u64 {
            let s = unsafe { std::slice::from_raw_parts(p, n) };
            s.iter().map(|&b| b as u64).sum()
        }"#;
    let (f, e) = scan_source("t.rs", src).unwrap();
    assert!(f.iter().any(|f| f.kind == "no-null-check" && f.risk == Risk::High));
    assert!(f.iter().any(|f| f.kind == "raw-slice" && f.function == "sum"));
    assert!(f.iter().any(|f| f.kind == "panic-across-ffi"));
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].symbol, "sum");
    assert_eq!(e[0].params.len(), 2);
}

#[test]
fn null_check_suppresses_finding() {
    let src = r#"
        #[no_mangle]
        pub extern "C" fn sum(p: *const u8, n: usize) -> u64 {
            if p.is_null() { return 0; }
            let s = unsafe { std::slice::from_raw_parts(p, n) };
            s.len() as u64
        }"#;
    assert!(!has(src, "no-null-check", "sum"));
    assert!(has(src, "raw-slice", "sum"));
}

#[test]
fn catch_unwind_suppresses_panic_finding() {
    let src = r#"
        #[no_mangle]
        pub extern "C" fn f(x: i32) -> i32 {
            std::panic::catch_unwind(|| x.checked_add(1).unwrap()).unwrap_or(-1)
        }"#;
    assert!(!has(src, "panic-across-ffi", "f"));
    let unwind = r#"pub extern "C-unwind" fn g() { panic!() }"#;
    assert!(!has(unwind, "panic-across-ffi", "g"));
}

#[test]
fn panicky_export_is_high() {
    let src = r#"pub extern "C" fn f(v: i32) -> i32 { let a = [1, 2]; a[v as usize] }"#;
    let (f, _) = scan_source("t.rs", src).unwrap();
    let p = f.iter().find(|f| f.kind == "panic-across-ffi").unwrap();
    assert_eq!(p.risk, Risk::High);
}

#[test]
fn ownership_and_unsafe_ops_in_methods() {
    let src = r#"
        struct W { v: Vec<u8> }
        impl W {
            pub unsafe fn grow(&mut self, n: usize) { self.v.set_len(n); }
            pub fn take(p: *mut W) -> Box<W> { unsafe { Box::from_raw(p) } }
            pub fn give(self) -> *mut W { Box::into_raw(Box::new(self)) }
            pub fn cast(x: &u32) -> f32 { unsafe { std::mem::transmute(*x) } }
        }
        unsafe impl Send for W {}
        static mut COUNTER: u32 = 0;
    "#;
    assert!(has(src, "unsafe-fn", "W::grow"));
    assert!(has(src, "set-len", "W::grow"));
    assert!(has(src, "ownership-from-raw", "W::take"));
    assert!(has(src, "ownership-to-raw", "W::give"));
    assert!(has(src, "transmute", "W::cast"));
    assert!(kinds(src).iter().any(|(k, _)| *k == "unsafe-send-sync"));
    assert!(has(src, "static-mut", "<module>"));
}

#[test]
fn calls_outside_unsafe_are_not_reported() {
    // transmute fuera de unsafe no compila; el escáner solo reporta dentro de unsafe
    let src = r#"fn f() { let v: Vec<u8> = Vec::new(); let _ = v.len(); }"#;
    assert!(kinds(src).is_empty());
}

#[test]
fn dangling_cstring_and_const_to_mut() {
    let src = r#"
        extern "C" { fn puts(s: *const std::ffi::c_char) -> i32; }
        fn f() {
            let p = std::ffi::CString::new("x").unwrap().as_ptr();
            unsafe { puts(p); }
            let v = vec![1u8];
            let m = v.as_ptr() as *mut u8;
            let _ = m;
        }"#;
    assert!(has(src, "dangling-cstring", "f"));
    assert!(has(src, "const-to-mut", "f"));
    assert!(has(src, "extern-import", "puts"));
}

#[test]
fn test_code_skipped_unless_requested() {
    let src = r#"
        #[cfg(test)]
        mod tests { fn t() { unsafe { std::ptr::read(0 as *const u8); } } }
        #[test]
        fn t2() { unsafe { std::ptr::read(0 as *const u8); } }
    "#;
    assert!(kinds(src).is_empty());
    let (f, _) = ffi_review::scan_source_opts("t.rs", src, true).unwrap();
    assert!(f.iter().any(|f| f.kind == "ptr-read-write"));
}

#[test]
fn parse_error_is_reported_not_hidden() {
    assert!(scan_source("bad.rs", "fn (").is_err());
}

#[test]
fn ranking_orders_by_summed_risk() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/demo-ffi");
    let rep = scan_dir(&dir);
    assert!(rep.parse_errors.is_empty(), "{:?}", rep.parse_errors);
    let r = rep.ranking();
    assert!(!r.is_empty());
    for w in r.windows(2) {
        assert!(w[0].score >= w[1].score);
    }
}

#[test]
fn demo_buggy_exports_flagged_fixed_not() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/demo-ffi");
    let rep = scan_dir_opts(&dir, false);
    let nn: Vec<&str> = rep.findings.iter().filter(|f| f.kind == "no-null-check").map(|f| f.function.as_str()).collect();
    for b in ["buggy_sum", "buggy_strlen", "buggy_store", "buggy_copy"] {
        assert!(nn.contains(&b), "{b} sin no-null-check: {nn:?}");
    }
    for f in ["fixed_sum", "fixed_strlen", "fixed_store", "fixed_copy"] {
        assert!(!nn.contains(&f), "{f} marcado por error");
    }
    assert_eq!(rep.exports.len(), 8);
}

#[test]
fn generated_tests_cover_every_simple_export() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/demo-ffi");
    let rep = scan_dir(&dir);
    let (src, skipped) = generate_tests(&rep);
    assert!(skipped.is_empty(), "{skipped:?}");
    for e in &rep.exports {
        assert!(src.contains(&format!("fn {}(", e.symbol)), "falta declaración de {}", e.symbol);
        assert!(src.contains(&format!("ffi_review_{}_", e.symbol)), "falta test de {}", e.symbol);
    }
    assert!(syn::parse_file(&src).is_ok(), "el archivo generado no parsea");
}
