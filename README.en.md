# ffi-review (English)

*Spanish original: [README.md](README.md). If the two disagree, the Spanish README and
the files under `results/` are the reference.*

Review report for the `unsafe`/FFI boundaries of a Rust crate: every `extern fn`,
every `#[no_mangle]` export, every `unsafe` block and every pointer cast, with a
**per-function risk ranking**, a **review checklist per finding** and **generated
tests** that call each export with `NULL`/0 so they can run under miri or ASan.

`cargo-geiger` counts `unsafe`; `cargo-vet`/`cargo-crev` record trust; miri runs the
tests that already exist. None of them says *where* to look first or generates
boundary tests. This repository is the one-day MVP of idea #53. The absence of an
equivalent tool has not been checked exhaustively.

## Usage

```bash
cargo build --release
target/release/ffi-review scan <crate-dir>                    # markdown report
target/release/ffi-review scan <dir> --json --top 30          # JSON: findings, exports, ranking
target/release/ffi-review scan <dir> --emit-tests tests/ffi_null.rs   # tests for miri/ASan
target/release/ffi-review scan <dir> --fail-on high           # exit 1 on high findings (CI)
```

Exit codes: 0 ok, 1 `--fail-on` threshold reached, 2 usage error, 3 some file could not
be parsed.

## What it detects

20 patterns, among them: an export without a `NULL` check on a pointer parameter
(`no-null-check`, high), `extern "C"` without `catch_unwind` whose body can panic
(`panic-across-ffi`), `slice::from_raw_parts`, `Box/CString::from_raw`, `transmute`,
`set_len`, `CString::new(..).unwrap().as_ptr()` (dangling pointer),
`as_ptr() as *mut`, `unsafe impl Send/Sync`, `static mut`, pointer arithmetic.
Syntactic analysis only, with `syn`: no type information and no macro expansion.

## Results

Pre-registration and provenance: [`lab/PREREGISTRO.md`](lab/PREREGISTRO.md) (Spanish).
Raw JSON in [`results/`](results/). Reproduce with
`cargo build --release && python -m lab.measure` and
`python -m lab.measure --corpus lab/advisories-holdout.json`.

| Measure | Threshold | Measured | Verdict |
|---|---|---|---|
| 20 RUSTSEC advisories (development corpus): a finding inside the vulnerable function | ≥ 15/20 | 17/20 | met |
| 10 held-out advisories (fixed before running) | ≥ 75% | 8/10 | met |
| Noise in medium/high findings on 5 clean crates | ≤ 30% | 7/44 = 16%, 0 unlabeled | met |
| Generated tests under miri on the demo crate (CI) | every `buggy_*` gives UB, no `fixed_*` fails | 4/4 `buggy_*` exports with UB (6 of 7 tests); 7/7 `fixed_*` tests pass | met, **by construction** |

The demo crate, its seeded bugs and the generator have the same author: miri flagging
them shows that the generated tests exercise the boundary, not that they find other
people's bugs.

**Honest reading of the hit rate.** The pre-registered criterion counts *any* finding
inside the vulnerable function as a hit, including a low-risk one. With stricter
criteria:

| Corpus | Hit with a medium/high finding | Vulnerable function in the ranking top 10 |
|---|---|---|
| Development (20) | 9/20 | 7/20 |
| Held-out (10) | 7/10 | 3/10 |

In large crates the vulnerable function ranks far down (for example 434 of 630 in pyo3
0.28.3 and 308 of 1117 in openssl 0.10.71). The report helps not to skip boundaries; it
does not find the bug first.

## Provenance and declared biases

- The scanner, the 20-advisory corpus and the noise labels were left by a previous
  author **without commits**. There is no proof that the criteria preceded runs on that
  corpus; that is why it is called the "development corpus" and a held-out corpus was
  added.
- The noise labels of the clean crates are manual and from the same origin; they were
  not re-labeled.
- Before measuring, a scanner bug found by the new tests (`as_ptr() as *mut` was never
  flagged) and a harness bug that left the clean crates out (it reported 0/0) were
  fixed. Both are in the history.

## Not verified

- The base rate (fraction of functions per crate with any finding) was not measured,
  so 17/20 cannot be compared against flagging functions at random.
- Generated tests were not run under AddressSanitizer; miri only on the demo crate and
  only in CI.
- No generated tests were run under miri on the advisory crates.
- Syntactic analysis: macro-generated code and `#[cfg]` for other platforms can be
  missed or over-counted.
- No formal verification and no guarantee of absence of bugs.
- No user validation, and no paid demand specific to Rust/FFI was found.

## Tests

```bash
cargo test --release      # 16 tests: scanner (12) and CLI (4)
python3 lab/miri_demo.py  # needs nightly + miri
```

## Contributing, bugs and security

- Bugs and feature requests: <https://github.com/federiconbaez/cortex9-ffi-review/issues>
- How to contribute: [CONTRIBUTING.md](CONTRIBUTING.md)
- Vulnerabilities (private): [SECURITY.md](SECURITY.md)
- Changes per version: [CHANGELOG.md](CHANGELOG.md)

## License

Apache-2.0 ([LICENSE](LICENSE)).
