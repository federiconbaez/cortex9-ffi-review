# Contributing

Thanks for your interest. Issues and pull requests are welcome in **English or
Spanish**.

## Getting the software

```sh
git clone https://github.com/federiconbaez/cortex9-ffi-review.git
```

See [README.md](README.md) for usage.

## Reporting bugs and requesting features

- Bugs and enhancement requests: open an issue at <https://github.com/federiconbaez/cortex9-ffi-review/issues>.
  Include the commit or version, your OS and toolchain version, the exact command,
  and the output you got versus what you expected.
- Security problems: follow [SECURITY.md](SECURITY.md) and do not post exploit details publicly.

## Contribution process

1. Fork the repository and create a branch from `main`.
2. Make your change, with tests (see below).
3. Run the local checks listed below; all of them must pass.
4. Open a pull request against `main` describing what changed and why.
5. The maintainer reviews it. CI must be green before merging. Merges are done as
   fast-forward when possible so history stays linear.

## Requirements for acceptable contributions

Run these before opening a pull request (the same commands run in CI):

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked --release
# the committed generated file must match the current generator output
cargo run --release --locked -- scan examples/demo-ffi --emit-tests regen.rs > /dev/null
diff -u examples/demo-ffi/tests/generated.rs regen.rs
```

Optional, needs nightly + miri: `python3 lab/miri_demo.py`. Changes to the scanner
that affect measured results must re-run `python -m lab.measure` (see
[lab/PREREGISTRO.md](lab/PREREGISTRO.md)) and update the README with the new numbers.

General rules:

- **New functionality must come with automated tests** in the existing test suite,
  and bug fixes should add a regression test. A skipped test counts as a failure.
- **Documentation must stay honest:** the README separates what is tested from what
  is not. Do not add numbers or claims that were not measured; if you add a
  measurement, document how to reproduce it.
- Do not commit secrets, private keys, real IP addresses, host paths or personal data.
- By contributing you agree that your contribution is licensed under the
  [Apache License 2.0](LICENSE), the same license as the project.

## Commit message format

Commits follow this format (type and scope as in Conventional Commits):

```
type(scope): short title

Body explaining the change.

Cambios:
- ...

Problemas detectados:
- ...

Ref: CX9-<digits>

License: Apache-2.0
```

`type` is one of `feat`, `fix`, `docs`, `test`, `ci`, `chore`, `refactor`, `perf`.
External contributors may write a plain descriptive message; the maintainer can
adjust it when merging.

## Versioning and releases

- Versions follow [Semantic Versioning](https://semver.org/). The version lives in the
  package manifest and every release is tagged in git as `vX.Y.Z`.
- Every release gets a human-written entry in [CHANGELOG.md](CHANGELOG.md) (not a raw
  `git log`) and a GitHub release with the same notes. The entry lists every fixed
  vulnerability that has a public identifier (CVE, GHSA, RUSTSEC).
- Release steps: update the version and CHANGELOG in a pull request, merge it with
  CI green, tag the merge commit `vX.Y.Z`, push the tag, and create the GitHub
  release from that tag.
