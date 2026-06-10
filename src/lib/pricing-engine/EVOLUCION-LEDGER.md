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
