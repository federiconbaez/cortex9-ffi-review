# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-11-06

First tagged release. Version as declared in `Cargo.toml`.

### Added
- `ffi-review scan <dir>`: report of FFI boundaries and unsafe operations of a Rust
  crate (each `extern fn`, `#[no_mangle]` export, `unsafe` block and pointer cast),
  with a per-function risk ranking and a review checklist per finding. Output as
  Markdown or `--json`; `--top N`; `--fail-on <level>` for CI.
- 20 syntactic patterns (`syn`), e.g. exports without a `NULL` check,
  `extern "C"` bodies that can panic without `catch_unwind`, `slice::from_raw_parts`,
  `Box`/`CString::from_raw`, `transmute`, `set_len`, dangling `CString` pointers,
  `as_ptr() as *mut`, `unsafe impl Send/Sync`, `static mut`, pointer arithmetic.
- `--emit-tests`: generated tests that call each export with `NULL`/0, meant to run
  under miri or AddressSanitizer.
- 16 tests (scanner and CLI), a pre-registered lab with a development corpus of 20
  RUSTSEC advisories and a held-out corpus of 10, and miri on a demo crate in CI.
  Results and limits are in the README.

### Project infrastructure (added before tagging)
*Added:*
- `SECURITY.md`, `CONTRIBUTING.md`, this changelog and an English README
  (`README.en.md`).
- CI `lint` job (`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`)
  and a `cargo audit` step on `Cargo.lock`.
- CI self-scan: `ffi-review scan . --fail-on medium` on the tool's own source.

*Changed:*
- Source formatted with `rustfmt` (no behavior change; the generated demo test file
  is byte-identical).

### Security
- No known vulnerabilities fixed in this version.
