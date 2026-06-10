# LEDGER DE TRAZABILIDAD — ROADMAP MAESTRO DE EVOLUCIÓN TPTECH

> **Registro operativo de pasos validados.** Acompaña al
> [`CONTRATO-FUNCIONAL.md`](./CONTRATO-FUNCIONAL.md) y sus companions
> (`-consumo.md`, `-emision.md`).
>
> **Propósito:** dejar trazabilidad de cambios **validados pero NO commiteados
> de forma aislada** por estado del working tree (fallback documentado en la
> Metodología Operativa Oficial de la Etapa 2). Cada entrada describe qué
> cambió, dónde, por qué, cómo se validó, y la condición para su commit limpio.
>
> **Alcance:** registra pasos tanto de frontend como de backend del programa de
> evolución. No es un contrato de dominio — es bitácora de proceso.
>
> **Regla:** una entrada en este ledger NO sustituye un commit; lo **difiere**
> de forma trazable hasta que el working tree permita aislar el hunk.

---

## Entrada — Etapa 2 / Ciclo 1 / Paso 2.2

| Campo | Valor |
|---|---|
| **Etapa** | 2 |
| **Ciclo** | 1 |
| **Paso** | 2.2 |
| **Archivo** | `tptech-frontend/src/components/sales/TotalDelComprobanteCard/helpers.ts` |
| **Helper** | `sumLineCommercialMonetaryRoundingImpact` |
| **Cambio realizado** | Orden de lectura del impacto monetario del redondeo comercial por línea: **C-FASE1 → B → C-FASE0** (antes era B → C-FASE0; ahora antepone `lineCommercialDisplaySummary.monetary.roundingImpact`). |
| **Motivo** | Alinear el Footer monetario con el Contrato de Consumo (C-FASE1 como fuente canónica per-línea) y con su helper gemelo de metal (`sumLineCommercialMetalRoundingImpact`), que ya lee C-FASE1 primero. Elimina la última lectura per-línea B-first del Footer. |
| **Naturaleza** | Display-only. Near-no-op numérico: C-FASE1 y B provienen del mismo primitivo autónomo (`computeLineAutonomousCommercialMoney`) → equivalentes para líneas frescas; fallback a B→C-FASE0 para líneas sin C-FASE1 (histórico). |
| **Validación** | **368/368 tests verdes** (29 archivos del Footer + guard Paso 3) + **`tsc --noEmit` 0 errores**. |
| **Núcleo** | Motor, `Sale.total`, snapshots, pipeline y FIX MIXED: **intactos** (no tocados). |
| **Estado** | ✅ Validado — ❌ **NO commiteado de forma aislada**. |
| **Motivo de no-commit** | `helpers.ts` contiene **602 inserciones preexistentes sin commitear** (la familia `lineCommercial*` completa es nueva vs HEAD; último commit del archivo: `b47d2ae`, anterior a esa familia). El hunk del Paso 2.2 **modifica código que en sí mismo no está en HEAD** → no es aislable con `git add -p` sin arrastrar trabajo ajeno a la Etapa 2. |
| **Riesgo** | **Operativo / git** (atribución de commit), **NO funcional**. El cambio es correcto, validado y reversible. |
| **Reversibilidad** | Total — restaurar el bloque de lectura del helper a `B → C-FASE0`. |
| **Condición para commit limpio** | (a) Commitear primero el backlog previo de `helpers.ts` (trabajo `commercial summary…` ya en el árbol) como su propio commit → luego el Paso 2.2 y siguientes commitean limpio; **o** (b) mantener este ledger hasta ordenar el working tree. |
| **Decisión vigente** | Opción 1 (ledger). No se commitea `helpers.ts`; no se hace commit pragmático; no se stagea el archivo completo. |

### Referencia rápida del cambio (para reconstrucción/auditoría)
Bloque de lectura dentro de `sumLineCommercialMonetaryRoundingImpact`:
```
1) lineCommercialDisplaySummary.monetary.roundingImpact   (C-FASE1)  ← nuevo #1
2) lineOwnHechuraRoundingMonetaryImpact                   (B)
3) lineCommercialSummary.monetary.roundingImpact          (C-FASE0)
→ null (la fila "Redondeo comercial monetario" se oculta)
```

---

## Estado del Ciclo 1 (Etapa 2)
- **Código:** completo y validado (Paso 2.2).
- **Operativo:** trazado en este ledger; **commit aislado diferido** por dirty working tree.
- **Ciclo 2:** NO iniciado (precondición: resolver la situación de git o sostener el ledger).

---

## Entrada de conocimiento — Dominio MIXED (Hito especial)

| Campo | Valor |
|---|---|
| **Tipo** | Conocimiento arquitectónico consolidado (no es un cambio de código). |
| **Contexto** | Auditoría funcional + formalización del régimen MIXED (Ciclo 1, Etapa 2). |
| **Descubrimiento** | MIXED no es un modelo comercial independiente: es un **régimen de fallback** para comprobantes con líneas de **listas de precios distintas**. |
| **Alcance** | Redondeo comercial por línea cuando no hay política comercial única del documento. No afecta el núcleo (`Sale.total`, snapshots, motor). |
| **Estado** | Conocimiento consolidado por evidencia de código; con hipótesis abiertas explícitas (abajo). |

### HECHOS DEMOSTRADOS (respaldados por el código auditado)
1. **MIXED se activa con listas heterogéneas** — líneas que usan listas de precios distintas (`resolveDocumentCommercialContextForSale` → `MIXED_LIST_FALLBACK`).
2. **MIXED es un régimen de fallback**, no un modelo comercial propio (lo declara su estructura y nombre).
3. **La consolidación en MIXED es `Σ round(línea)`**, idéntica a PER_DOCUMENT.
4. **MIXED resuelve la configuración de redondeo por línea** (cada línea con su propia lista; `resolvePerLineCommercialConfigs` / `hechuraCfgByLineIdx`).
5. **B (`lineOwn*`) y C-FASE1 (`lineCommercialDisplaySummary`) derivan del mismo primitivo** (`computeLineAutonomousCommercialMoney`); B usa inputs doc-level (margen POST + refValue agregado) y **puede diluir en MIXED**, mientras C-FASE1 es line-local (margen PRE, sin dilución).
6. **El FIX MIXED actúa como mecanismo de compensación** de la divergencia de B (display), no como regla de dominio.
7. **`Sale.total` permanece como autoridad** y **`Σ round(línea)` como frontera funcional**, también en MIXED.

### HIPÓTESIS ABIERTAS (requieren evidencia futura — prueba numérica)
1. **Equivalencia completa de C-FASE1 en TODOS los escenarios MIXED** (hoy razonada por construcción, no verificada caso por caso).
2. **Eliminabilidad futura del FIX MIXED** sin regresión (depende de la #1).
3. **Magnitud/frecuencia real de la divergencia B vs C-FASE1** en datos productivos.
4. **Peso cuantitativo de las fuentes de complejidad** (la estimación ~85% no-dominio es razonamiento, no medición).

### RELACIÓN CON EL CONTRATO FUNCIONAL
**Este descubrimiento NO modifica el Contrato Funcional Oficial.** Es coherente con los tres contratos (Funcional, Consumo, Emisión): la línea sigue siendo autónoma, el documento consolida `Σ round(línea)` y `Sale.total` es autoridad. La única tensión es un **rezago de implementación** (MIXED aún se apoya en B+parches mientras C-FASE1 es la fuente canónica) — lo que la Etapa 2 viene a cerrar, sin cambiar el contrato.

### IMPACTO SOBRE EL ROADMAP
- **No cambia:** las etapas, el orden, ni el tratamiento de FIX MIXED como **hito especial con prueba numérica previa**.
- **Aporta:** evidencia de que el "nudo MIXED" es mayormente deuda de convivencia + representación (no riqueza de negocio), lo que **confirma** la dirección del roadmap (converger a C-FASE1) sin alterarla.

### CONOCIMIENTO ARQUITECTÓNICO CONSOLIDADO (reglas permanentes)
- MIXED = **fallback para listas heterogéneas**; kernel de dominio **delgado**.
- `Σ round(línea)` y `Sale.total` se mantienen **idénticos** en MIXED.
- B y C-FASE1 son **el mismo primitivo**; C-FASE1 es el refinamiento line-local; B diluye en MIXED.
- Los parches FIX MIXED son **compensación**, no dominio.

### LIMITACIONES DEL DESCUBRIMIENTO
No puede concluirse todavía (sin prueba numérica): que C-FASE1 sea correcta en **todo** MIXED, que el FIX MIXED sea **removible** sin regresión, ni el **peso exacto** de cada fuente de complejidad. Estas quedan como hipótesis abiertas, no como hechos.

### VALIDACIÓN ARQUITECTÓNICA
> *"Este descubrimiento NO modifica el Contrato Funcional Oficial de TPTech. Consolida conocimiento arquitectónico obtenido mediante auditoría del comportamiento existente."*

**Confirmado correcto:** la afirmación es exacta. El trabajo fue auditoría read-only + formalización; no se tocó código de cálculo, contrato, motor, `Sale.total` ni snapshots.

### CONCLUSIÓN
MIXED queda registrado oficialmente como **régimen de fallback con kernel de dominio reducido**, con sus hechos separados de sus hipótesis. El contrato permanece inalterado; el roadmap, confirmado.

---

## Entrada — Etapa 2 / Evolución Controlada / Trabajo #2

| Campo | Valor |
|---|---|
| **Trabajo** | #2 del Backlog — Card impacto monetario → C-FASE1-first. |
| **Archivo afectado** | `tptech-frontend/src/components/ui/TPDocumentLineAdvancedEditor.tsx`. |
| **Bloque** | `desglosadoImpact` (dentro del bloque `compositionDetailOpen`; descomposición monetaria expandida del Card). |
| **Cambio realizado** | Orden de lectura del impacto monetario del redondeo comercial per-línea: **B-first → C-FASE1-first**. Nuevo orden: (1) `lineSummary.monetary.roundingImpact` (C-FASE1, `lineSummary = lineCommercialDisplaySummary ?? lineCommercialSummary`) → (2) `lineOwnHechuraRoundingMonetaryImpact` (B) → (3) `resolveCommercialHechuraImpact` (legacy). |
| **Motivo arquitectónico** | Alinear el Card con el Contrato de Consumo (C-FASE1 fuente canónica per-línea), con el Footer (Paso 2.2) y con la cadena de impacto **metal** del propio Card. Elimina la última lectura monetaria B-first del Card. |
| **Naturaleza** | Display-only (sub-línea expandida); near-no-op numérico (C-FASE1 y B = mismo primitivo autónomo → equivalentes en líneas frescas). **Rama UNIFICADA preservada byte-equivalente.** |
| **Validaciones realizadas** | Tests render del Card + helpers de display + red de paridad Card↔Footer (#3) + guard `no-family-a-in-line-surfaces` + `tsc --noEmit`. |
| **Resultado de tests** | **9 archivos / 68 tests verdes; `tsc --noEmit` 0 errores.** |
| **Impacto sobre núcleo** | **NULO** sobre `Sale.total`, snapshots, motor y FIX MIXED (bloque del total `:5017-5023` intacto). No se tocó Footer ni `helpers.ts`. |
| **Estado** | ✅ Validado — ❌ **NO commiteado de forma aislada**. |
| **Motivo de no-commit aislado** | `TPDocumentLineAdvancedEditor.tsx` contiene **cambios previos sin commitear** (584 ins / 189 del vs HEAD, ajenos a la Etapa 2). El hunk del Trabajo #2 modifica código que no está en HEAD → no es aislable con `git add <archivo>` sin arrastrar trabajo ajeno. Misma situación que el Paso 2.2. |
| **Riesgo** | **Operativo / git** (atribución), **NO funcional**. Reversible (restaurar el bloque `desglosadoImpact` al orden B-first). |
| **Condición para commit limpio** | (a) Commitear primero el backlog previo de `TPDocumentLineAdvancedEditor.tsx` como su propio commit → luego este cambio y siguientes commitean limpio; **o** (b) sostener este ledger hasta ordenar el working tree. |
| **Decisión vigente** | Opción Ledger (igual que Paso 2.2). No se commitea el Card; no se hace commit parcial. |

### Referencia rápida del cambio (para reconstrucción/auditoría)
Bloque `desglosadoImpact` (DESGLOSADA):
```
1) lineSummary.monetary.roundingImpact          (C-FASE1)  ← nuevo #1
2) lineOwnHechuraRoundingMonetaryImpact          (B)
3) resolveCommercialHechuraImpact(...)           (legacy)
UNIFICADA: lineSummary ? 0 : resolveCommercialHechuraImpact(...)   (sin cambios)
```

### Estado consolidado del Footer y el Card (impacto monetario)
Tras Paso 2.2 (Footer) + Trabajo #2 (Card), **ambas superficies leen el impacto monetario C-FASE1-first** — simetría completa. Ambos cambios quedan validados y trazados en ledger, sin commit aislado por dirty working tree.

---

## Entrada — Etapa 2 / Evolución Controlada / Trabajo #1

| Campo | Valor |
|---|---|
| **Trabajo** | #1 del Backlog — Footer gramos → C-FASE1-first. |
| **Archivo afectado** | `tptech-frontend/src/components/sales/TotalDelComprobanteCard/helpers.ts`. |
| **Bloque** | `buildVisibleGramsByParent` (resolución de `byParent` para los gramos por metal padre del Footer). |
| **Cambio realizado** | Orden de lectura del `byParent` de gramos: **FASE0-only → C-FASE1-first**. Nuevo: `byParent = display?.metals?.byParent ?? summary?.metals?.byParent ?? null` (display = `lineCommercialDisplaySummary`, summary = `lineCommercialSummary`). Era `summary?.metals?.byParent ?? null`. |
| **Motivo arquitectónico** | Alinear el último helper de gramos del Footer con su gemelo `groupLineCommercialMetalRoundingByParent` (que ya lee `display ?? summary`) y con el Contrato de Consumo (C-FASE1 fuente canónica per-línea). |
| **Naturaleza** | Display-only (gramos del bloque METALES del Footer); near-no-op numérico (FASE1==FASE0 visibleGrams en líneas frescas; FASE1 más correcto line-local en MIXED). |
| **Preservado** | Match por `metalParentName`; consolidación Σ por nombre; fallback a `gramsEquivLine`; lectura defensiva desde `pricingMeta`; retorno `{}` sin líneas/metales. |
| **Validaciones realizadas** | Red de paridad Card↔Footer (#3) + tests del Footer + guard `no-family-a-in-line-surfaces` + `tsc --noEmit`. |
| **Resultado de tests** | **30 archivos / 384 tests verdes; `tsc --noEmit` 0 errores.** |
| **Impacto sobre núcleo** | **NULO** sobre `Sale.total`, snapshots, motor y FIX MIXED. No se tocó el Card ni otros helpers (`sumLineCommercial*` intactos). |
| **Estado** | ✅ Validado — ❌ **NO commiteado de forma aislada**. |
| **Motivo de no-commit aislado** | `helpers.ts` contiene cambios previos sin commitear (Paso 2.2 + backlog ~611 ins vs HEAD); el hunk no es aislable con `git add <archivo>`. Misma situación que Paso 2.2 / Trabajo #2. |
| **Riesgo** | **Operativo / git** (atribución), **NO funcional**. Reversible (restaurar `byParent` a FASE0-only). |
| **Condición para commit limpio** | (a) Commitear primero el backlog previo de `helpers.ts` → luego este cambio commitea limpio; **o** (b) sostener este ledger hasta ordenar el working tree. |
| **Decisión vigente** | Opción Ledger (igual que Paso 2.2 y Trabajo #2). |

### Estado consolidado del Footer (post Trabajo #1)
Las **tres** lecturas per-línea del Footer (gramos, impacto metal, impacto monetario) son ahora **C-FASE1-first**. El Footer quedó **plenamente convergido a C-FASE1** como fuente primaria, con fallbacks B/FASE0/legacy intactos para datos históricos. Cambios de código validados pero **no commiteados aisladamente** (dirty tree): Paso 2.2, Trabajo #2, Trabajo #1.
