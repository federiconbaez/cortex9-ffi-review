# Security policy

## Supported versions

Only the latest commit on `main` (currently the 0.1.x line) receives security fixes.
There are no older maintained branches.

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub private vulnerability
reporting:

- Go to <https://github.com/federiconbaez/cortex9-ffi-review/security/advisories/new>
  (repository **Security** tab -> **Report a vulnerability**).
- Include the affected commit or version, steps to reproduce, and the impact you expect.

Do **not** open a public issue, pull request or discussion for a suspected
vulnerability. The report stays visible only to you and the maintainer until an
advisory is published.

## What to expect

- The maintainer aims to acknowledge every report within **14 days**.
- If the report is confirmed, the fix is developed in a private fork of the
  advisory, released, and the advisory is published with credit to the reporter
  (unless they prefer to stay anonymous).
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
