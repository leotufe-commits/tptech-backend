# Harness de medición — Factura de Ventas (Etapa 2)

Medir antes de optimizar. Estos scripts NO cambian comportamiento de la app:
solo miden, perfilan y siembran datos de prueba. No tocan pricing-engine,
cálculos ni snapshots.

## Scripts

| Script | Qué hace | ¿Escribe en la DB? |
|---|---|---|
| `bench-search.ts` | Conteo de filas + `EXPLAIN ANALYZE` de las búsquedas de cliente y artículo | **No** (read-only) |
| `perf-seed.ts` | Genera N clientes + M artículos con marcador `PERF-` (y `--clean` para borrarlos) | **Sí** (gateado) |

## Flujo recomendado (en una DB descartable)

```powershell
# 1. Sembrar escala grande (DB descartable / staging, NO producción)
$env:PERF_SEED_CONFIRM="yes"; $env:CLIENTS="10000"; $env:ARTICLES="50000"
npx tsx scripts/perf/perf-seed.ts

# 2. Medir el plan real de las búsquedas a esa escala
npx tsx scripts/perf/bench-search.ts ros     # término con selectividad media

# 3. Limpiar lo sembrado
$env:PERF_SEED_CONFIRM="yes"; npx tsx scripts/perf/perf-seed.ts --clean
```

## Cómo leer el EXPLAIN

- **`Index Scan` / `Bitmap Index Scan`** → usa índice, escala bien.
- **`Seq Scan` con `rows` alto** → escaneo completo; no escala con 50k.
- **`Rows Removed by Filter` alto** → el índice acotó (ej. por `jewelryId`) pero
  el `ILIKE '%texto%'` se aplica como filtro fila por fila sobre lo acotado.
- **`Execution Time`** → el número que importa. Sub-ms = sano; decenas/cientos
  de ms por keystroke = cuello.

### Por qué un índice btree NO arregla la búsqueda por texto

Las búsquedas usan `ILIKE '%texto%'` (subcadena, case-insensitive). Un índice
btree `[jewelryId, displayName]` solo acelera el filtro por `jewelryId` y los
matches por **prefijo** (`texto%`), nunca por subcadena. Para que la búsqueda
por subcadena escale a 50k, las opciones reales son:

- **`pg_trgm` (índice GIN trigram)** sobre las columnas buscadas → acelera `ILIKE '%x%'`.
- **Búsqueda por prefijo** (`x%`) + índice btree/`text_pattern_ops`.
- **Full-text search** (`tsvector` + GIN) si se quiere relevancia.

Decisión que se toma **con las mediciones del bench a 50k**, no antes.

## Medición que NO necesita seed (ya hecha por código)

### Preview — N+1 de `metalVariant`

`enrichCostMetalSteps` (`pricing-engine.cost.ts:532`) hace **1 query
`metalVariant.findMany` por línea con metal** (se llama dentro de
`resolveFinalSalePrice`, una vez por línea — `pricing-engine.sale.ts:1270`).
Batchea las variantes *dentro* de una línea, no *entre* líneas.

→ Preview de N líneas con metal = **N queries** de metalVariant (+ las queries
batcheadas O(1): artículos, variantes, grupos, contexto de costo, cliente).
Tabla chica e indexada por PK ⇒ impacto bajo por query, pero crece lineal con
las líneas. Optimización (batch entre líneas) vive DENTRO del pricing-engine ⇒
requiere test de paridad preview↔confirm. No tocar sin medir el peso real.

### Contar queries reales de un preview (sin tocar app)

Usar `pg_stat_statements` o el log de Postgres alrededor de UN preview:

```sql
-- una sola vez
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
SELECT pg_stat_statements_reset();
-- ...ejecutar UN preview desde la UI/endpoint...
SELECT calls, total_exec_time, query
FROM pg_stat_statements
ORDER BY calls DESC LIMIT 20;
```

`calls` por statement revela el N+1 (un statement de `MetalVariant` con
`calls = nº de líneas`).

## Medición del frontend (manual, sin código nuevo)

1. **Requests + payloads**: Chrome DevTools → Network. Editar una factura de
   10 / 50 / 100 líneas y observar:
   - cuántos `POST /api/sales/preview` por edición (debe ser 1 por cambio, con
     debounce 200 ms),
   - tamaño del payload (crece lineal con líneas — esperado),
   - tamaño de la respuesta (snapshots).
2. **Render del editor**: React DevTools → Profiler. Grabar mientras se cambia
   una cantidad con 10 / 50 / 100 líneas. Mirar:
   - cuántos componentes re-renderizan por cambio de una celda,
   - si `SaleCompositionEditableGrid` / filas se re-renderean de más
     (la fila usa `React.memo`; el cuello sería el padre recreando arrays).
3. **Memoria/imágenes**: Network → Img. El combo de artículo carga thumbnails
   solo de los ~30 resultados visibles (no todo el catálogo).

## Escenarios objetivo a cubrir

- 1.000 / 10.000 clientes → búsqueda de cliente.
- 50.000 artículos / variantes → búsqueda de artículo.
- Facturas de 10 / 50 / 100 líneas → preview (N+1 metalVariant) + render editor.
