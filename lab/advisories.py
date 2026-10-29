"""Pick the RUSTSEC advisories for the lab with a rule fixed before running.

    python -m lab.advisories --db lab/cache/advisory-db > lab/advisories.json

Rule (applied in this order, newest advisory id first, stop at 20):
  1. not withdrawn, informational field absent (a real vulnerability);
  2. categories include memory-corruption or memory-exposure;
  3. [affected.functions] lists at least one function path;
  4. a vulnerable version exists on crates.io (newest non-yanked version that
     is not covered by `patched` / `unaffected`), downloadable as .crate.
Nothing about the scanner is used to pick advisories."""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import tomllib
import urllib.request

UA = {"User-Agent": "ffi-review-lab (https://github.com/federiconbaez)"}


def parse_ver(v: str):
    v = v.split("+")[0]
    core, _, pre = v.partition("-")
    parts = [int(x) for x in (core.split(".") + ["0", "0"])[:3]]
    return (parts[0], parts[1], parts[2], 0 if pre else 1, pre)


def matches(req: str, ver: str) -> bool:
    """Minimal semver requirement matcher for RustSec ranges (comma = AND)."""
    v = parse_ver(ver)
    for clause in req.split(","):
        c = clause.strip()
        m = re.match(r"^(>=|<=|>|<|=|\^|~)?\s*(.+)$", c)
        op, rv = m.group(1) or "^", m.group(2)
        r = parse_ver(rv)
        nparts = len(rv.split("-")[0].split("."))
        if op == ">=" and not v >= r: return False
        if op == ">" and not v > r: return False
        if op == "<=" and not v <= r: return False
        if op == "<" and not v < r: return False
        if op == "=" and v[:3] != r[:3]: return False
        if op == "^":
            if not v >= r: return False
            if r[0] > 0: upper = (r[0] + 1, 0, 0)
            elif r[1] > 0 or nparts < 3: upper = (0, r[1] + 1, 0)
            else: upper = (0, 0, r[2] + 1)
            if not v[:3] < upper: return False
        if op == "~":
            if not v >= r: return False
            upper = (r[0], r[1] + 1, 0) if nparts >= 2 else (r[0] + 1, 0, 0)
            if not v[:3] < upper: return False
    return True


def front_matter(path: pathlib.Path):
    txt = path.read_text()
    m = re.search(r"```toml\n(.*?)\n```", txt, re.S)
    return tomllib.loads(m.group(1)) if m else None


def crate_versions(name: str):
    req = urllib.request.Request(f"https://crates.io/api/v1/crates/{name}/versions", headers=UA)
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.load(r)
    return [(v["num"], v["yanked"]) for v in data["versions"]]


def vulnerable_version(adv, versions):
    vers = adv.get("versions", {})
    safe = vers.get("patched", []) + vers.get("unaffected", [])
    cands = [v for v, yanked in versions if not yanked and "-" not in v and not any(matches(s, v) for s in safe)]
    if not cands:
        return None
    return max(cands, key=parse_ver)


def adv_key(a):
    m = re.match(r"RUSTSEC-(\d+)-(\d+)", a["id"])
    return (int(m.group(1)), int(m.group(2)))


def select(db: pathlib.Path, n=20, log=sys.stderr):
    advs = []
    for p in sorted((db / "crates").glob("*/*.md")):
        fm = front_matter(p)
        if not fm:
            continue
        a = fm["advisory"]
        if a.get("withdrawn") or a.get("informational"):
            continue
        if not set(a.get("categories", [])) & {"memory-corruption", "memory-exposure"}:
            continue
        funcs = fm.get("affected", {}).get("functions", {})
        if not funcs:
            continue
        advs.append({"id": a["id"], "crate": a["package"], "functions": sorted(funcs), "versions": fm.get("versions", {}),
                     "categories": a.get("categories", []), "title": a.get("title", "")})
    advs.sort(key=adv_key, reverse=True)
    out = []
    for a in advs:
        try:
            vv = crate_versions(a["crate"])
        except Exception as e:  # noqa: BLE001
            print(f"skip {a['id']} {a['crate']}: crates.io {e}", file=log)
            continue
        v = vulnerable_version(a, vv)
        if not v:
            print(f"skip {a['id']} {a['crate']}: no vulnerable non-yanked version", file=log)
            continue
        a["vulnerable_version"] = v
        out.append(a)
        print(f"take {a['id']} {a['crate']} {v} {a['functions']}", file=log)
        if len(out) == n:
            break
    return out, len(advs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="lab/cache/advisory-db")
    ap.add_argument("-n", type=int, default=20)
    a = ap.parse_args()
    sel, pool = select(pathlib.Path(a.db), a.n)
    print(json.dumps({"rule": __doc__.split("Rule")[1].strip(), "eligible_pool": pool, "advisories": sel}, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
