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
