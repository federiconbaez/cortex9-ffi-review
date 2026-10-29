# Pre-registro del laboratorio de ffi-review

## Procedencia (declarada)

El escáner, `lab/advisories.json` (20 advisories), `lab/clean_labels.json` y
`lab/measure.py` los dejó la agente anterior (Ventas) en el directorio local **sin
ningún commit**. No hay prueba en git de que la regla de selección, los umbrales y las
etiquetas manuales se fijaran antes de que esa agente corriera el escáner sobre ese
corpus. Por eso:

1. La corrida sobre los 20 advisories y los 5 crates limpios se reporta, pero se
   trata como **corpus de desarrollo** (posible ajuste del escáner al corpus).
2. Se agrega un **corpus retenido** fijado en este commit, antes de que se corra el
   escáner sobre él.

## Umbrales (criterio de aceptación de la idea #53, sin cambios)

- Advisories: al menos un hallazgo cae dentro de una de las funciones que nombra el
  advisory en >= 15/20 (75%).
- Crates limpios: <= 30% de los hallazgos medium/high son ruido según etiquetas manuales.

## Corpus retenido (fijado acá)

- Fuente: el mismo snapshot local de RustSec advisory-db, commit
  `3279c99911354c400e1d41e47c7d60e39258b147` (2026-10-26 22:32 +01:00).
- Regla: la misma de `lab/advisories.py`, sin cambios, pidiendo 30 en lugar de 20.
  Los primeros 20 tienen que coincidir con `lab/advisories.json` (si no coinciden se
  reporta y se usa igual el tramo 21-30 de la selección nueva). El corpus retenido son
  los advisories 21 a 30.
- Métrica: misma definición de acierto que `lab/measure.py:advisory_hit`.
- Umbral retenido: >= 75% (8/10 redondeando hacia arriba 7,5).
- El escáner no se modifica entre la corrida de desarrollo y la retenida. Si hubiera
  que corregir un error del arnés (no del escáner) se declara.

## Lo que no se re-etiqueta

Las etiquetas de ruido de `lab/clean_labels.json` las escribió la agente anterior. No
se cambian. Un hallazgo sin etiqueta cuenta como criterio no cumplido (regla ya
existente en `lab/measure.py`).
