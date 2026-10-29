# ffi-review

Informe de revisión de las fronteras `unsafe`/FFI de un crate Rust: cada `extern fn`,
cada export `#[no_mangle]`, cada bloque `unsafe` y cada conversión de puntero, con
**ranking de funciones por riesgo**, **checklist de revisión por hallazgo** y **tests
generados** que llaman cada export con `NULL`/0 para correrlos bajo miri o ASan.

`cargo-geiger` cuenta `unsafe`; `cargo-vet`/`cargo-crev` registran confianza; miri
corre los tests que ya existen. Ninguno dice *dónde* mirar primero ni genera tests de
frontera. Este repo es el MVP de un día de la idea #53. La ausencia de una herramienta
equivalente no está verificada exhaustivamente.

## Uso

```bash
cargo build --release
target/release/ffi-review scan <dir-del-crate>             # informe markdown
target/release/ffi-review scan <dir> --json --top 30        # JSON: hallazgos, exports, ranking
target/release/ffi-review scan <dir> --emit-tests tests/ffi_null.rs   # tests para miri/ASan
target/release/ffi-review scan <dir> --fail-on high         # exit 1 si hay hallazgos high (CI)
```

Códigos de salida: 0 ok, 1 umbral `--fail-on`, 2 uso, 3 algún archivo no se pudo parsear.

## Qué detecta

20 patrones, entre ellos: export sin chequeo de `NULL` sobre un parámetro puntero
(`no-null-check`, high), `extern "C"` sin `catch_unwind` con cuerpo que puede entrar en
pánico (`panic-across-ffi`), `slice::from_raw_parts`, `Box/CString::from_raw`,
`transmute`, `set_len`, `CString::new(..).unwrap().as_ptr()` (puntero colgante),
`as_ptr() as *mut`, `unsafe impl Send/Sync`, `static mut`, aritmética de punteros.
Solo análisis sintáctico con `syn`: sin tipos ni expansión de macros.

## Resultados

Pre-registro y procedencia en [`lab/PREREGISTRO.md`](lab/PREREGISTRO.md). Corridas en
la box el 29/10/2026 cerca de las 10:50 ART; JSON en [`results/`](results/).
Reproducir: `cargo build --release && python -m lab.measure` y
`python -m lab.measure --corpus lab/advisories-holdout.json`.

| Medida | Umbral | Medido | Veredicto |
|---|---|---|---|
| 20 advisories RUSTSEC (corpus de desarrollo): hallazgo dentro de la función vulnerable | ≥ 15/20 | 17/20 | cumplido |
| 10 advisories retenidos (fijados antes de correr) | ≥ 75% | 8/10 | cumplido |
| Ruido en hallazgos medium/high de 5 crates limpios | ≤ 30% | 7/44 = 16%, 0 sin etiqueta | cumplido |
| Tests generados bajo miri en el crate demo | cada `buggy_*` da UB, ningún `fixed_*` falla | job `miri` de CI | ver CI |

**Lectura honesta del acierto.** El criterio pre-fijado cuenta como acierto *cualquier*
hallazgo dentro de la función vulnerable, incluido uno de riesgo bajo. Con criterios
más estrictos:

| Corpus | Acierto con hallazgo medium/high | Función vulnerable en el top 10 del ranking |
|---|---|---|
| Desarrollo (20) | 9/20 | 7/20 |
| Retenido (10) | 7/10 | 3/10 |

En crates grandes la función vulnerable queda lejos en el ranking (por ejemplo, puesto
434 de 630 en pyo3 0.28.3 y 308 de 1117 en openssl 0.10.71). El informe sirve para no
saltearse fronteras, no para encontrar el bug primero.

Fallos: zstd 0.14.2, lz4_flex 0.10.0 y fast-able 1.13.6 (desarrollo); scratchpad 1.3.1
y grcov 0.8.20 (retenido).

## Procedencia y sesgos declarados

- El escáner, el corpus de 20 advisories y las etiquetas de ruido los dejó la agente
  anterior **sin commits**. No hay prueba de que los criterios precedieran a corridas
  suyas sobre ese corpus: por eso es "corpus de desarrollo" y se agregó el retenido.
- Las etiquetas de ruido de los crates limpios son manuales y del mismo origen; no se
  re-etiquetaron.
- Antes de medir se corrigió un bug del escáner que encontraron los tests nuevos
  (`as_ptr() as *mut` nunca se marcaba) y un bug del arnés que dejaba los crates
  limpios afuera (se vio antes de reportar: daba 0/0). Ambos en el historial.

## Alcance: lo que NO está verificado

- No se midió la tasa base: qué fracción de las funciones de cada crate tiene algún
  hallazgo. Sin ese número, 17/20 no se puede comparar contra marcar funciones al azar.
- No se probaron los tests generados con AddressSanitizer; miri solo sobre el crate demo
  y solo en CI (la box no tiene miri).
- No se generaron ni corrieron tests bajo miri sobre los crates de los advisories.
- Análisis sintáctico: código generado por macros (`macro_rules!`, proc-macros) y
  `#[cfg]` de otras plataformas pueden quedar fuera o contarse de más.
- Sin verificación formal ni garantía de ausencia de bugs.
- Sin validación con usuarios ni demanda pagada específica de Rust/FFI encontrada.

## Tests

```bash
cargo test --release      # 16 tests: escáner (12) y CLI (4)
python3 lab/miri_demo.py  # requiere nightly + miri
```

CI: tests, chequeo de que `examples/demo-ffi/tests/generated.rs` coincide con la salida
actual, miri sobre el demo y el laboratorio completo con artefacto `lab-results`.

## Licencia

Apache-2.0.
