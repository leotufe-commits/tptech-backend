# CONTRATO FUNCIONAL — GUÍA DE CONSUMO PER-LÍNEA (Etapa 1)

> **Documento companion de [`CONTRATO-FUNCIONAL.md`](./CONTRATO-FUNCIONAL.md).**
> Mientras el contrato define el *modelo de dominio* (qué debe ser verdad), esta
> guía traduce ese modelo a una **regla operativa de lectura** para desarrolladores:
> **¿qué fuente per-línea debe leer una superficie nueva?**
>
> **Naturaleza:** fotografía del estado de consumo al cerrar la **Etapa 1** del
> Roadmap Maestro de Evolución. La fuente viva sigue siendo el código + las
> auditorías; este documento fija la *intención canónica*, no reemplaza al código.
>
> **Alcance de la Etapa 1:** consolidación del **contrato de lectura**, NO del motor.
> Esta guía **no elimina** ninguna familia, **no toca** el SSOT, `Sale.total`,
> snapshots ni el pipeline. Solo declara qué leer de ahora en adelante.

---

## 1. Mapa A / B / C

El redondeo comercial per-línea hoy se expresa en **tres familias de campos**, todas
emitidas por el backend y propagadas al frontend por `applySalePreviewToDraft`
(passthrough puro). Las tres son **representaciones del mismo redondeo comercial ya
aplicado por el motor** — ninguna mueve `Sale.total`.

| Familia | Campos representativos | Qué es |
|---|---|---|
| **A — Documental prorrateada** | `metalRoundingMonetaryImpact`, `hechuraRoundingMonetaryImpact`, `lineMonetarySaldoPostCommercialRounding`, `lineTotalWithTaxPostCommercialRounding` | Reparto a cada línea del redondeo **del documento**. **Depende de las otras líneas** (cambia al editar otra línea). |
| **B — Autónoma per-línea** | `lineOwnMetalRoundingMonetaryImpact`, `lineOwnHechuraRoundingMonetaryImpact`, `lineOwnMonetarySaldoPostCommercialRounding`, `lineOwnTotalWithTaxPostCommercialRounding` | Cada línea redondeada en aislamiento. **Inmune a las otras líneas.** |
| **C — Contrato / builder** | `lineCommercialSummary` (FASE 0), `lineCommercialDisplaySummary` (FASE 1) | Objeto autosuficiente por línea que unifica metal + monetario + total en un solo shape. |

> ⚠️ **Distinción crítica.** "Familia B" como **campos expuestos** (`lineOwn*`,
> display) es distinto del **primitivo** `computeLineAutonomousCommercialMoney`, que
> alimenta la consolidación `Σ round(línea)` del SSOT. Esta guía habla de los
> **campos de lectura**; el primitivo es parte del motor y **no se toca**.

---

## 2. Declaración canónica

> **La Familia C (`lineCommercialSummary`) es el contrato canónico de lectura
> per-línea de TPTech.**

Toda superficie que muestre el resultado comercial de una línea —gramos, valor
metal, redondeo metal, monetario/hechura, redondeo monetario, total de línea— debe
leerlo de **C**, sin elegir entre fuentes ni conocer cómo se calculó.

Las familias A y B **siguen existiendo y emitiéndose** (insumo interno + fallback de
lectura + compatibilidad de snapshots históricos). **No se eliminan en la Etapa 1.**

---

## 3. Variante canónica de C: FASE 1

La Familia C tiene dos variantes:

- **FASE 0 — `lineCommercialSummary`:** adapter que ensambla A (metales) + B (dinero)
  en el shape de contrato.
- **FASE 1 — `lineCommercialDisplaySummary`:** recálculo **line-local** (como si la
  línea estuviera sola), **inmune a las otras líneas**.

> **La variante canónica es C FASE 1 / `lineCommercialDisplaySummary`.**

Es la que cumple el invariante del contrato **"la línea es autónoma"** (Cap. 5 y 9
del contrato) y la que el Card ya prioriza. FASE 0 permanece como representación
compatible; los consumidores nuevos deben preferir FASE 1.

---

## 4. Mapa de consumidores actuales (fotografía Etapa 1)

| Superficie / consumidor | Qué lee hoy | Estado |
|---|---|---|
| **Card** (`TPDocumentLineAdvancedEditor`) | C (prioridad) → B (`lineOwn*`, fallback) → legacy PER_LINE. **Prohíbe A.** | ✅ ya prioriza C |
| **Footer — gramos** (`buildVisibleGramsByParent`) | C (`metals.byParent[].visibleGrams`) — los mismos gramos que el Card | ✅ ya en C |
| **Footer — impacto $ comercial** (`sum*RoundingImpact`) | B (`lineOwn*`, prioridad) → C | ⏳ prioriza B; converge a C |
| **Footer — reconciliación documental** | snapshot **del comprobante** (`commercialDocumentRoundingSnapshot`, financiero, manual) | ✅ nivel documento (ver §6) |
| **`applySalePreviewToDraft`** | A + B + C (passthrough puro de todas) | ✅ sin cambio (pasa todo) |
| **PDF / snapshots persistidos** | `pricingSnapshot` (incluye A, B y C congeladas) | ✅ inmutable, no migra |

Las celdas "⏳" son consumos que aún caen a B/A como fallback. **En la Etapa 1 NO se
modifican** — solo se congela que ningún desarrollo *nuevo* lea A o `lineOwn*`
directamente. Su unificación es trabajo de la Etapa 2.

---

## 5. Regla para desarrollos nuevos

> **A nivel línea, leer únicamente la Familia C (preferentemente FASE 1).**

- ✅ **Hacer:** leer `lineCommercialSummary` / `lineCommercialDisplaySummary`.
- ❌ **No hacer:** leer A (`metalRoundingMonetaryImpact`, `hechuraRoundingMonetaryImpact`,
  `lineMonetarySaldoPostCommercialRounding`, `lineTotalWithTaxPostCommercialRounding`)
  ni los campos `lineOwn*` de B en una superficie per-línea nueva.
- ❌ **No hacer:** recalcular, inferir o reconstruir un valor comercial en el
  frontend (el motor es la única autoridad — Cap. 7 y 9 del contrato).

A y B permanecen disponibles **solo** como (a) insumo interno del motor/builders,
(b) fallback de los consumidores existentes, (c) lectura de snapshots históricos.

---

## 6. Footer: línea vs documento (aclaración obligatoria)

El Footer tiene **dos planos de lectura distintos** que NO deben confundirse:

- **Plano LÍNEA → usa C.** Para representar a las líneas (gramos, valores, impacto
  comercial agregado), el Footer lee/agrega la Familia C — los mismos números que el
  Card. Esto garantiza el invariante **"footer = suma visual de las líneas"**.
- **Plano DOCUMENTO → usa el snapshot del comprobante.** Para reconciliar con el
  cobro final (redondeo financiero, ajuste manual, total), el Footer lee los
  **snapshots documentales** (`commercialDocumentRoundingSnapshot`,
  `documentRoundingSnapshot`, `manualAdjustmentSnapshot`) y muestra `Sale.total`.

> **La Familia C NO reemplaza el snapshot documental.** C es la verdad **per-línea**;
> el snapshot del comprobante es la verdad **documental** que cuadra con `Sale.total`.
> Confundirlos (querer reconstruir el total documental desde C, o mostrar el
> prorrateo documental en una superficie per-línea) es exactamente el tipo de error
> que esta guía previene.

---

## 7. Validación del paso

Este documento es **puramente aditivo**:

- No modifica archivos existentes.
- No toca código, motor, `Sale.total`, snapshots ni pipeline.
- No elimina A ni B.
- No cambia ningún comportamiento.

`git status` atribuible a este paso (aislado): **un único archivo nuevo**

```
?? tptech-backend/src/lib/pricing-engine/CONTRATO-FUNCIONAL-consumo.md
```
