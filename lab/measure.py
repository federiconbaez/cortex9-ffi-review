"""Measure ffi-review on RUSTSEC advisories and on clean crates.

    cargo build --release
    python -m lab.measure                 # 20 advisories + 5 clean crates
    python -m lab.measure --json

Criteria fixed before running (idea #53):
  * on the 20 advisories in lab/advisories.json (vulnerable version, picked by
    the rule in lab/advisories.py), at least one finding falls inside one of
    the functions the advisory names: >= 15/20;
  * on 5 clean crates (no RustSec advisory), <= 30% of medium/high findings
    are noise according to the manual labels in lab/clean_labels.json.
A crate that cannot be downloaded or parsed counts as a miss, never a skip."""
from __future__ import annotations

import argparse
import io
import json
import pathlib
import subprocess
import sys
import tarfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
CACHE = ROOT / "lab" / "cache" / "crates"
BIN = ROOT / "target" / "release" / "ffi-review"
UA = {"User-Agent": "ffi-review-lab (https://github.com/federiconbaez)"}
CLEAN = [("errno", "0.3.14"), ("libloading", "0.9.0"), ("region", "3.0.2"), ("page_size", "0.6.0"), ("hostname", "0.4.1")]


def fetch(name: str, version: str) -> pathlib.Path:
    dest = CACHE / f"{name}-{version}"
    if dest.is_dir():
        return dest
    CACHE.mkdir(parents=True, exist_ok=True)
    url = f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
        data = r.read()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        t.extractall(CACHE, filter="data")
    return dest


def scan(path: pathlib.Path) -> dict:
    p = subprocess.run([str(BIN), "scan", str(path), "--json"], capture_output=True, text=True)
    if p.returncode not in (0, 3):
        raise RuntimeError(p.stderr)
    return json.loads(p.stdout)


def target_names(fn_path: str):
    """`crate::mod::Type::method` -> ('Type::method', True); `crate::mod::f` -> ('f', False)."""
    segs = fn_path.split("::")[1:]
    if len(segs) >= 2 and segs[-2][:1].isupper():
        return f"{segs[-2]}::{segs[-1]}", True
    return segs[-1], False


def advisory_hit(adv: dict, rep: dict):
    findings = rep["report"]["findings"]
    ranking = [r["function"] for r in rep["ranking"]]
    best = None
    for fp in adv["functions"]:
        name, is_method = target_names(fp)
        hits = [f for f in findings if f["function"] == name]
        if hits:
            rank = ranking.index(name) + 1 if name in ranking else None
            cand = {"function": fp, "matched": name, "findings": len(hits),
                    "kinds": sorted({f["kind"] for f in hits}), "max_risk": max(hits, key=lambda f: ["low", "medium", "high"].index(f["risk"]))["risk"],
                    "rank": rank}
            if best is None or (rank or 10**9) < (best["rank"] or 10**9):
                best = cand
    return best


def run(verbose=True, corpus=None, clean=True):
    advs = json.loads(pathlib.Path(corpus or ROOT / "lab" / "advisories.json").read_text())["advisories"]
    rows = []
    for a in advs:
        row = {"id": a["id"], "crate": a["crate"], "version": a["vulnerable_version"], "functions": a["functions"]}
        try:
            rep = scan(fetch(a["crate"], a["vulnerable_version"]))
            row["parse_errors"] = len(rep["report"]["parse_errors"])
            row["functions_ranked"] = len(rep["ranking"])
            row["hit"] = advisory_hit(a, rep)
        except Exception as e:  # noqa: BLE001  a failure is a miss
            row["error"] = str(e)[:300]
            row["hit"] = None
        rows.append(row)
        if verbose:
            h = row["hit"]
            msg = f"HIT  {h['matched']} rank {h['rank']}/{row.get('functions_ranked')} kinds={h['kinds']}" if h else f"MISS {row.get('error', '')}"
            print(f"{a['id']} {a['crate']} {a['vulnerable_version']}: {msg}", flush=True)
    hits = sum(1 for r in rows if r["hit"])
    strict = sum(1 for r in rows if r["hit"] and r["hit"]["max_risk"] in ("medium", "high"))
    top10 = sum(1 for r in rows if r["hit"] and r["hit"]["rank"] and r["hit"]["rank"] <= 10)

    labels = json.loads((ROOT / "lab" / "clean_labels.json").read_text())
    clean = []
    for name, ver in (CLEAN if clean else []):
        rep = scan(fetch(name, ver))
        mh = [f for f in rep["report"]["findings"] if f["risk"] in ("medium", "high")]
        lab = labels.get(f"{name}-{ver}", {})
        unlabeled, noise = 0, 0
        for f in mh:
            k = f"{f['file']}:{f['line']}:{f['kind']}"
            if k not in lab:
                unlabeled += 1
            elif lab[k]["label"] == "noise":
                noise += 1
        clean.append({"crate": f"{name}-{ver}", "medium_high": len(mh), "noise": noise, "unlabeled": unlabeled,
                      "parse_errors": len(rep["report"]["parse_errors"])})
        if verbose:
            print(f"clean {name}-{ver}: medium/high findings {len(mh)}, noise {noise}, unlabeled {unlabeled}", flush=True)
    total = sum(c["medium_high"] for c in clean)
    noise = sum(c["noise"] for c in clean)
    unl = sum(c["unlabeled"] for c in clean)
    noise_rate = noise / total if total else 0.0
    return {"advisories": rows, "hits": hits, "hits_top10": top10, "hits_medium_high": strict, "total": len(rows), "clean": clean,
            "clean_findings": total, "clean_noise": noise, "clean_unlabeled": unl, "noise_rate": round(noise_rate, 3),
            "criterion_met": (hits >= 15 and noise_rate <= 0.30 and unl == 0) if clean else hits * 4 >= 3 * len(rows)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--corpus", help="archivo de advisories alternativo (corpus retenido: sin crates limpios, umbral 75%%)")
    a = ap.parse_args()
    if not BIN.exists():
        print("build first: cargo build --release", file=sys.stderr)
        return 2
    res = run(verbose=not a.json, corpus=a.corpus, clean=a.corpus is None)
    if a.json:
        print(json.dumps(res, indent=1))
    print(f"advisories flagged: {res['hits']}/{res['total']} (with a medium/high finding: {res['hits_medium_high']}/{res['total']}; in top 10 of ranking: {res['hits_top10']}/{res['total']}); "
          f"clean-crate noise: {res['clean_noise']}/{res['clean_findings']} = {res['noise_rate']:.0%} (unlabeled {res['clean_unlabeled']}); "
          f"criterion met: {res['criterion_met']}", file=sys.stderr if a.json else sys.stdout)
    return 0 if res["criterion_met"] else 1


if __name__ == "__main__":
    sys.exit(main())
