"""Corre los tests generados del crate demo bajo miri, uno por proceso.

Criterio: cada export buggy_* tiene al menos un test generado que miri marca como UB,
y ningún test de fixed_* falla. Sale con 1 si no se cumple o si miri no corre.
Requiere: rustup toolchain nightly con el componente miri.
"""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "demo-ffi"


def main() -> int:
    gen = (DEMO / "tests" / "generated.rs").read_text()
    names = re.findall(r"fn (ffi_review_[a-z0-9_]+)\(", gen)
    if not names:
        print("FALLA: no hay tests generados")
        return 1
    subprocess.run(["cargo", "+nightly", "miri", "setup"], cwd=DEMO, check=True)
    res = {}
    for n in names:
        p = subprocess.run(["cargo", "+nightly", "miri", "test", "--test", "generated", "--", "--exact", n],
                           cwd=DEMO, capture_output=True, text=True)
        out = p.stdout + p.stderr
        if p.returncode == 0 and "1 passed" in out:
            res[n] = "pass"
        elif "Undefined Behavior" in out:
            res[n] = "ub"
        else:
            print(out[-3000:])
            res[n] = "error"
        print(f"{n}: {res[n]}", flush=True)
    funcs = sorted({re.match(r"ffi_review_((?:buggy|fixed)_[a-z]+)_", n).group(1) for n in names})
    ok = True
    summary = {}
    for f in funcs:
        mine = {n: r for n, r in res.items() if n.startswith(f"ffi_review_{f}_")}
        if f.startswith("buggy_"):
            good = any(r == "ub" for r in mine.values()) and "error" not in mine.values()
        else:
            good = all(r == "pass" for r in mine.values())
        summary[f] = {"tests": mine, "ok": good}
        ok &= good
    print(json.dumps(summary, indent=1))
    print("CRITERIO miri demo:", "cumplido" if ok else "NO cumplido")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
