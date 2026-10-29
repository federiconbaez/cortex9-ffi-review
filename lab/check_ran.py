"""Falla si una corrida del laboratorio no produjo resultados completos (no evalúa umbrales)."""
import json
import sys

for path in sys.argv[1:]:
    d = json.load(open(path))
    assert d["total"] == len(d["advisories"]) and d["total"] > 0, f"{path}: corpus vacío"
    errs = [r for r in d["advisories"] if "error" in r]
    print(f"{path}: {d['hits']}/{d['total']} aciertos, {len(errs)} advisories con error (cuentan como fallo), "
          f"ruido limpios {d['clean_noise']}/{d['clean_findings']}, criterio {d['criterion_met']}")
