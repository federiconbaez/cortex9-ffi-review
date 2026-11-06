# Security policy

## Supported versions

Only the latest commit on `main` (currently the 0.1.x line) receives security fixes.
There are no older maintained branches.

## Reporting a vulnerability

**There is currently no private reporting channel for this repository**: GitHub
private vulnerability reporting is not enabled, and the project does not publish an
email address. The process is:

1. If the problem can be described without giving away how to exploit it (for
   example a crash on malformed input, or a dependency advisory), open an issue at
   <https://github.com/federiconbaez/cortex9-ffi-review/issues> with the affected commit or version and steps to reproduce.
2. If describing it would expose users before a fix exists, open an issue titled
   **"Security contact request"** that contains **no technical details**. The
   maintainer will answer in that issue to agree on a private way to receive the
   details before you share them.

Please do not publish exploit details in issues, pull requests or elsewhere before a
fix is available.

## What to expect

- The maintainer aims to acknowledge every report within **14 days**. This is a
  target, not a track record: no vulnerability report has been received so far.
- Confirmed vulnerabilities are fixed on `main`, released with a new version, and
  disclosed with credit to the reporter (unless they prefer to stay anonymous).
- Release notes in [CHANGELOG.md](CHANGELOG.md) list every fixed vulnerability that
  has a CVE, GHSA or RUSTSEC identifier.

## Scope

ffi-review is an offline, read-only static analyzer: it parses Rust source files
with `syn` and writes a report or a generated test file. Relevant issues include
crashes or hangs on crafted source input, writing outside the requested output path,
and generated tests that could be harmful to run. Note that the `lab/` scripts
download crates from crates.io over HTTPS to measure the scanner; they are a
measurement harness, not part of the tool.

A finding that ffi-review *misses* in some crate (a false negative) is a regular
bug, not a vulnerability: please open a normal issue.
