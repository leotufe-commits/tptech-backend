// src/modules/sales/__tests__/mixed-list-metal-no-dilution.test.ts
// =============================================================================
// REGLA (2026-06-05): en MIXED_LIST cada línea debe comportarse igual que si
// estuviera sola con su propia lista.
//
//   · Una línea METAL_HECHURA / Desglosada conserva su redondeo comercial de
//     metal autónomo aunque coexista con una línea Unificada.
//   · La línea MARGIN_TOTAL / Unificada NO debe aportar ni DILUIR el redondeo
//     físico del metal de la Desglosada.
//
// BUG raíz (auditado en runtime): `refValueByParent` es POR metal padre y, en el
// path MIXTO, se tomaba del agregado COMPARTIDO (`metalPricePerGram` = promedio
// ponderado entre TODAS las líneas que comparten metal padre, incluida la
// Unificada). Cuando el metal NO tiene `referenceValue`, ese promedio diluido
// contaminaba la monetización del Δgramos de la Desglosada (ej. 5.300 → 1.325).
//
// FIX: `sales.service` re-agrega usando SOLO las líneas Desglosadas (las demás
// con `metals: []`, conservando índices) antes de derivar `refValueByParent` y
// los gramos por línea. Este test reproduce esa lógica y prueba la autonomía.
// =============================================================================

import { describe, it, expect } from "vitest";
import {
  aggregateMetalsForCommercialDocRounding,
  computeLineCommercialRoundingMetals,
  computeLineAutonomousCommercialMoney,
  consolidateCommercialDocFromPerLine,
  buildLineCommercialSummary,
  type ResolvedLineForCommercialAgg,
} from "../commercial-doc-rounding-wiring.js";
import type { CommercialDocRoundingPartConfig } from "../../../lib/pricing-engine/commercial-document-rounding.js";

const ORO = "metal-oro-id";
const CFG: CommercialDocRoundingPartConfig = { mode: "DECIMAL_1", direction: "NEAREST" };
const NONE: CommercialDocRoundingPartConfig = { mode: "NONE", direction: "NEAREST" };

// Metal SIN referenceValue → refValue cae a `metalPricePerGram` (promedio): es el
// escenario donde la dilución ocurría.
const GU = 1.2375;     // gramos finos por unidad (post pureza + merma)
const PRICE = 200000;  // cotización por gramo (quotePriceSnapshot)
const MARGIN = 1.10;

function lineInput(quantity: number, price = PRICE): ResolvedLineForCommercialAgg {
  return {
    quantity,
    metals: [{
      metalParentId: ORO, metalParentName: "Oro Fino",
      appliedGramsPerUnit: GU, quotePriceSnapshot: price,
      metalReferenceValue: null,   // sin referenceValue → usa promedio (refValue diluible)
    }],
  };
}

function refMapFrom(agg: ReturnType<typeof aggregateMetalsForCommercialDocRounding>) {
  return new Map(agg.metalsByParent.map((m) => [
    m.metalParentId,
    (typeof m.metalReferenceValue === "number" && m.metalReferenceValue > 0) ? m.metalReferenceValue : m.metalPricePerGram,
  ]));
}

/** roundingImpact autónomo de la línea `idx` dado un agregado + config per-línea. */
function lineRoundingImpact(
  agg: ReturnType<typeof aggregateMetalsForCommercialDocRounding>,
  opts: {
    marginByIdx: Map<number, number>;
    metalCfgByLineIdx?: Map<number, CommercialDocRoundingPartConfig>;
    lineCount: number;
    idx: number;
  },
): number {
  const ref = refMapFrom(agg);
  const metals = computeLineCommercialRoundingMetals({
    gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
    metalNameById: new Map([[ORO, "Oro Fino"]]),
    refValueByParent: ref,
    marginFactorByLineIdx: opts.marginByIdx,
    metalCfg: opts.metalCfgByLineIdx ? NONE : CFG,
    metalCfgByLineIdx: opts.metalCfgByLineIdx,
    lineCount: opts.lineCount,
  });
  const money = computeLineAutonomousCommercialMoney({
    lineCommercialRoundingMetals: metals,
    refValueByParent: ref,
    lineTotalWithTaxByIdx: new Map(Array.from({ length: opts.lineCount }, (_, i) => [i, 1_000_000])),
    metalSaleSumByIdx: new Map(Array.from({ length: opts.lineCount }, (_, i) => [i, 600_000])),
    hechuraCfg: opts.metalCfgByLineIdx ? NONE : CFG,
    lineCount: opts.lineCount,
  });
  return money.get(opts.idx)!.metalRoundingMonetaryImpact;
}

describe("MIXED_LIST — el redondeo comercial de metal de la Desglosada NO se diluye", () => {
  // ── 1) Línea Desglosada qty 2 SOLA → valor de referencia autónomo. ──────────
  const aggSolo = aggregateMetalsForCommercialDocRounding([lineInput(2)]);
  const SOLO_IMPACT = lineRoundingImpact(aggSolo, {
    marginByIdx: new Map([[0, MARGIN]]),
    lineCount: 1, idx: 0,
  });

  it("1) desglosada qty 2 sola: emite un redondeo de metal autónomo no trivial", () => {
    expect(Number.isFinite(SOLO_IMPACT)).toBe(true);
    expect(Math.abs(SOLO_IMPACT)).toBeGreaterThan(0); // hay redondeo real
  });

  // ── Inputs MIXTOS: línea 0 Desglosada qty 2 + línea 1 Unificada qty 1. ──────
  const mixedInputs: ResolvedLineForCommercialAgg[] = [lineInput(2), lineInput(1)];
  const breakdownIdx = new Set<number>([0]); // solo la línea 0 es Desglosada

  it("2) MIXTO con el FIX (agregado solo-Desglosadas): la qty 2 conserva su valor", () => {
    // FIX: re-agregar con las NO-Desglosadas vaciadas (índices intactos).
    const breakdownAgg = aggregateMetalsForCommercialDocRounding(
      mixedInputs.map((l, i) => (breakdownIdx.has(i) ? l : { ...l, metals: [] })),
    );
    const fixedImpact = lineRoundingImpact(breakdownAgg, {
      marginByIdx: new Map([[0, MARGIN], [1, MARGIN]]),
      metalCfgByLineIdx: new Map([[0, CFG]]), // solo la desglosada redondea
      lineCount: 2, idx: 0,
    });
    expect(fixedImpact).toBe(SOLO_IMPACT); // idéntico a estar sola
  });

  it("REGRESIÓN: el agregado COMPARTIDO (bug) sí diluía el valor de la qty 2", () => {
    // Sin el fix: agregado con TODAS las líneas → metalPricePerGram promediado.
    const sharedAgg = aggregateMetalsForCommercialDocRounding(mixedInputs);
    const dilutedImpact = lineRoundingImpact(sharedAgg, {
      marginByIdx: new Map([[0, MARGIN], [1, MARGIN]]),
      metalCfgByLineIdx: new Map([[0, CFG]]),
      lineCount: 2, idx: 0,
    });
    // Con precios iguales en ambas líneas el promedio coincide → para forzar la
    // dilución, la Unificada aporta una cotización distinta (caso real: la
    // Unificada no expone quote de metal y baja el promedio).
    const sharedAggDiluting = aggregateMetalsForCommercialDocRounding([
      lineInput(2), lineInput(1, PRICE / 4),
    ]);
    const dilutedImpact2 = lineRoundingImpact(sharedAggDiluting, {
      marginByIdx: new Map([[0, MARGIN], [1, MARGIN]]),
      metalCfgByLineIdx: new Map([[0, CFG]]),
      lineCount: 2, idx: 0,
    });
    // El bug: la qty 2 cambia su redondeo por culpa de la otra línea.
    expect(dilutedImpact2).not.toBe(SOLO_IMPACT);
    // (con precios iguales, el promedio no cambia → coincide; documenta el límite)
    expect(dilutedImpact).toBe(SOLO_IMPACT);
  });

  // ── CASO REAL del operador (2026-06-05) ─────────────────────────────────────
  // Línea 1 Desglosada qty 1: preGrams 2,2894 → postGrams 2,3 (DECIMAL_1) →
  // delta 0,0106 × refValue 250.000 = 2.650. Línea 2 Unificada qty 1 (mismo
  // artículo) NO debe aportar ni diluir. Resultado OBLIGATORIO:
  // lineCommercialSummary.metals.roundingImpact = 2.650.
  it("CASO REAL: desglosada qty1 (2,2894→2,3) + unificada qty1 ⇒ summary.roundingImpact = 2650", () => {
    const REF = 250000;
    // appliedGramsPerUnit = 2,2894 con margen 1,0 ⇒ preGrams 2,2894.
    const realLine = (qty: number): ResolvedLineForCommercialAgg => ({
      quantity: qty,
      metals: [{
        metalParentId: ORO, metalParentName: "Oro Fino",
        appliedGramsPerUnit: 2.2894, quotePriceSnapshot: 100,
        metalReferenceValue: REF,
      }],
    });
    const inputs: ResolvedLineForCommercialAgg[] = [realLine(1), realLine(1)];
    const bIdx = new Set<number>([0]); // línea 0 Desglosada; línea 1 Unificada

    // Path MIXTO con el FIX (agregado solo-Desglosadas, índices intactos).
    const breakdownAgg = aggregateMetalsForCommercialDocRounding(
      inputs.map((l, i) => (bIdx.has(i) ? l : { ...l, metals: [] })),
    );
    const ref = refMapFrom(breakdownAgg);
    const metals = computeLineCommercialRoundingMetals({
      gramsPureByParentByLineIdx: breakdownAgg.gramsPureByParentByLineIdx,
      metalNameById: new Map([[ORO, "Oro Fino"]]),
      refValueByParent: ref,
      marginFactorByLineIdx: new Map([[0, 1.0], [1, 1.0]]),
      metalCfg: NONE,
      metalCfgByLineIdx: new Map([[0, CFG]]),
      lineCount: 2,
    });
    // Gramos físicos de la línea 0: pre 2,2894 → post 2,3 → delta 0,0106.
    const m0 = metals.get(0)![0];
    expect(m0.preGrams).toBeCloseTo(2.2894, 4);
    expect(m0.postGrams).toBeCloseTo(2.3, 4);
    expect(m0.deltaGrams).toBeCloseTo(0.0106, 4);

    const money = computeLineAutonomousCommercialMoney({
      lineCommercialRoundingMetals: metals,
      refValueByParent: ref,
      lineTotalWithTaxByIdx: new Map([[0, 1_000_000], [1, 500_000]]),
      metalSaleSumByIdx: new Map([[0, 600_000], [1, 300_000]]),
      hechuraCfg: NONE,
      hechuraCfgByLineIdx: new Map([[0, CFG]]),
      lineCount: 2,
    });
    const summary = buildLineCommercialSummary({
      mode: "BREAKDOWN",
      lineTotalWithTax: 1_000_000,
      money: money.get(0)!,
      metals: metals.get(0)!,
      source: { strategy: "PER_LINE", appliedListMode: "METAL_HECHURA", appliedPriceListId: "pl-d", documentContext: "MIXED_LIST" },
    });

    // RESULTADO OBLIGATORIO.
    expect(summary.metals!.roundingImpact).toBe(2650);
    expect(money.get(0)!.metalRoundingMonetaryImpact).toBe(2650);
  });

  // ── CASO REAL qty2 (evidencia runtime 2026-06-06) ───────────────────────────
  // Desglosada qty2: gramsFineEquiv/u = 1,5 × 0,75 × 1,10 = 1,2375 ; margen 1,85 ;
  // cotización 250.000. Agregado qty2 = 2,475 g → ×1,85 = 4,5788 → DECIMAL_1 4,6
  // → delta 0,0212 g × 250.000 = 5.300. El backend en ejecución devolvía 1.325
  // (diluido). Guard: Desglosada SOLA == Desglosada en MIXTO, ambas = 5.300, en
  // summary.metals.roundingImpact Y lineOwnMetalRoundingMonetaryImpact.
  it("CASO REAL qty2: Desglosada sola == Desglosada en MIXTO ⇒ summary y lineOwn = 5300", () => {
    const REF = 250000;
    const M = 1.85;
    const real = (qty: number): ResolvedLineForCommercialAgg => ({
      quantity: qty,
      metals: [{
        metalParentId: ORO, metalParentName: "Oro Fino",
        appliedGramsPerUnit: 1.2375, quotePriceSnapshot: 100,
        metalReferenceValue: REF,
      }],
    });

    // Helper: arma summary + lineOwn de la línea idx vía el path con FIX
    // (agregado solo-Desglosadas), espejo de sales.service MIXED.
    const computeLine = (
      inputs: ResolvedLineForCommercialAgg[],
      breakdownIdx: Set<number>,
      idx: number,
    ) => {
      const agg = aggregateMetalsForCommercialDocRounding(
        inputs.map((l, i) => (breakdownIdx.has(i) ? l : { ...l, metals: [] })),
      );
      const ref = refMapFrom(agg);
      const metals = computeLineCommercialRoundingMetals({
        gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
        metalNameById: new Map([[ORO, "Oro Fino"]]),
        refValueByParent: ref,
        marginFactorByLineIdx: new Map(inputs.map((_, i) => [i, M])),
        metalCfg: NONE,
        metalCfgByLineIdx: new Map([...breakdownIdx].map((i) => [i, CFG])),
        lineCount: inputs.length,
      });
      const money = computeLineAutonomousCommercialMoney({
        lineCommercialRoundingMetals: metals,
        refValueByParent: ref,
        lineTotalWithTaxByIdx: new Map(inputs.map((_, i) => [i, 2_000_000])),
        metalSaleSumByIdx: new Map(inputs.map((_, i) => [i, 1_200_000])),
        hechuraCfg: NONE,
        hechuraCfgByLineIdx: new Map([...breakdownIdx].map((i) => [i, CFG])),
        lineCount: inputs.length,
      });
      const summary = buildLineCommercialSummary({
        mode: "BREAKDOWN", lineTotalWithTax: 2_000_000,
        money: money.get(idx)!, metals: metals.get(idx)!,
        source: { strategy: "PER_LINE", appliedListMode: "METAL_HECHURA", appliedPriceListId: "pl-d", documentContext: "MIXED_LIST" },
      });
      return {
        roundingImpact: summary.metals!.roundingImpact,
        lineOwn: money.get(idx)!.metalRoundingMonetaryImpact,
      };
    };

    // Desglosada SOLA (qty2).
    const sola = computeLine([real(2)], new Set([0]), 0);
    // Desglosada (qty2, idx0) + Unificada (qty1, idx1) — Unificada NO en breakdownIdx.
    const mixto = computeLine([real(2), real(1)], new Set([0]), 0);

    expect(sola.roundingImpact).toBe(5300);
    expect(sola.lineOwn).toBe(5300);
    // Autonomía: la Unificada no diluye ni contamina.
    expect(mixto.roundingImpact).toBe(sola.roundingImpact);
    expect(mixto.lineOwn).toBe(sola.lineOwn);
    expect(mixto.roundingImpact).toBe(5300);
    // NO el valor diluido que devolvía el backend en ejecución.
    expect(mixto.roundingImpact).not.toBe(1325);
  });

  it("3) la línea Unificada mantiene mode UNIFIED y NO muestra redondeo de metal", () => {
    const breakdownAgg = aggregateMetalsForCommercialDocRounding(
      mixedInputs.map((l, i) => (breakdownIdx.has(i) ? l : { ...l, metals: [] })),
    );
    const ref = refMapFrom(breakdownAgg);
    const metals = computeLineCommercialRoundingMetals({
      gramsPureByParentByLineIdx: breakdownAgg.gramsPureByParentByLineIdx,
      metalNameById: new Map([[ORO, "Oro Fino"]]),
      refValueByParent: ref,
      marginFactorByLineIdx: new Map([[0, MARGIN], [1, MARGIN]]),
      metalCfg: NONE,
      metalCfgByLineIdx: new Map([[0, CFG]]),
      lineCount: 2,
    });
    // La línea Unificada (idx 1) no está en breakdownIdx → su summary es UNIFIED
    // y sin bloque de metales (igual que en sales.service: isBd=false).
    const unifiedSummary = buildLineCommercialSummary({
      mode: "UNIFIED",
      lineTotalWithTax: 500_000,
      money: null,
      metals: null,
      source: { strategy: "NONE", appliedListMode: "MARGIN_TOTAL", appliedPriceListId: "pl-u", documentContext: "MIXED_LIST" },
    });
    expect(unifiedSummary.mode).toBe("UNIFIED");
    expect(unifiedSummary.metals).toBeNull();
    // La línea Unificada NO aporta gramos al redondeo (no se emite para idx 1
    // en el wiring real); su entrada autónoma de metal queda vacía.
    expect(metals.get(1)).toEqual([]);
  });

  // ── Fix leak repriceLineClean (2026-06) — raíz: margin PROPIO vs clean ──────
  // El resumen comercial visible por línea debe usar el `metalSale` PROPIO
  // (`metalSalePreRounding/metalCost` = 1,85), no el `clean` que `repriceLineClean`
  // produce para el snapshot/Sale.total (= 1,8564). Con `postGrams` pineado en
  // 2,30, el delta es hipersensible: 1,85 → 0,0106 → 2.650 ; 1,8564 → 0,0027 → 675.
  it("MIXED: margin PROPIO (1,85) da 2.650 ; el clean (1,8564) da 675 — el resumen usa el propio", () => {
    const ORO2 = "metal-oro-id";
    const refValueByParent = new Map([[ORO2, 250000]]);                    // = cotización/pureza
    const gramsPureByParentByLineIdx = new Map([[ORO2, new Map([[0, 1.2375]])]]); // 1,50×0,75×1,10
    const metalNameById = new Map([[ORO2, "Oro"]]);
    const DEC1: CommercialDocRoundingPartConfig = { mode: "DECIMAL_1", direction: "NEAREST" };
    const impactFor = (marginFactor: number): number => {
      const m = computeLineCommercialRoundingMetals({
        gramsPureByParentByLineIdx,
        metalNameById,
        refValueByParent,
        marginFactorByLineIdx: new Map([[0, marginFactor]]),
        metalCfg: DEC1,
        lineCount: 1,
      });
      return m.get(0)![0].monetaryImpact;
    };
    // PROPIO = metalSalePreRounding(572.343,75)/metalCost(309.375)
    expect(impactFor(572343.75 / 309375)).toBe(2650);
    // CLEAN = repriceLineClean metalSale(574.331,25)/metalCost(309.375) — NO debe usarse en el resumen
    expect(impactFor(574331.25 / 309375)).toBe(675);
  });

  // ── Opción B (2026-06) — consolidación documental = Σ redondeo REAL por línea ─
  // El snapshot documental se arma desde los valores PROPIOS por línea:
  //   metal = Σ monetaryImpact real (desglosada 2.650, unificada 0)
  //   hechura = Σ hechuraRoundingMonetaryImpact (desg saldo −49,19 + deferred unif +19,86)
  // → metal 2.650 · hechura −29,33 · totalAdjustment 2.620,67. Una sola verdad.
  it("Opción B: consolidación documental = metal 2.650 + hechura −29,33 (deferred unif foldeado)", () => {
    const ORO2 = "metal-oro-id";
    const NONE2: CommercialDocRoundingPartConfig = { mode: "NONE", direction: "NEAREST" };
    const DEC1:  CommercialDocRoundingPartConfig = { mode: "DECIMAL_1", direction: "NEAREST" };
    // Línea 0 (desglosada): metal con margin PROPIO 1,85 → 2.650.
    const metals = computeLineCommercialRoundingMetals({
      gramsPureByParentByLineIdx: new Map([[ORO2, new Map([[0, 1.2375]])]]),
      metalNameById:              new Map([[ORO2, "Oro"]]),
      refValueByParent:           new Map([[ORO2, 250000]]),
      marginFactorByLineIdx:      new Map([[0, 572343.75 / 309375]]),
      metalCfg:                   DEC1,
      lineCount:                  2,
    });
    // Money autónomo: línea 0 saldo HUNDRED (−49,19), línea 1 unificada (0).
    const money = computeLineAutonomousCommercialMoney({
      lineCommercialRoundingMetals: metals,
      refValueByParent:             new Map([[ORO2, 250000]]),
      lineTotalWithTaxByIdx:        new Map([[0, 757680.81], [1, 814700]]),
      metalSaleSumByIdx:            new Map([[0, 572343.75], [1, 572343.75]]),
      hechuraCfg:                   NONE2,
      hechuraCfgByLineIdx:          new Map([[0, { mode: "HUNDRED", direction: "NEAREST" }]]),
      lineCount:                    2,
    });
    // FOLD del deferred unificado (+19,86) en la hechura de la línea 1.
    const m1 = money.get(1)!;
    m1.hechuraRoundingMonetaryImpact           = Math.round((m1.hechuraRoundingMonetaryImpact + 19.86) * 100) / 100;
    m1.lineMonetarySaldoPostCommercialRounding = Math.round((m1.lineMonetarySaldoPostCommercialRounding + 19.86) * 100) / 100;

    const snap = consolidateCommercialDocFromPerLine({
      lineCommercialRoundingMetals: metals,
      lineMoney:                    money,
      metalNameById:                new Map([[ORO2, "Oro"]]),
      refValueByParent:             new Map([[ORO2, 250000]]),
      metalCfg:                     NONE2,
      hechuraCfg:                   NONE2,
      lineCount:                    2,
    })!;
    expect(snap.breakdown!.metalMonetaryEquivalent).toBe(2650);
    const hechuraDelta = snap.breakdown!.hechura.deltaSaldoMonetario;
    // hechura = saldo HUNDRED de la desglosada + deferred unif (+19,86); incluye el +19,86.
    expect(Math.round((hechuraDelta - 19.86) * 100) / 100).toBe(
      Math.round(money.get(0)!.hechuraRoundingMonetaryImpact * 100) / 100,
    );
    // totalAdjustment = metal + hechura (Σ real).
    expect(snap.totalAdjustment).toBe(Math.round((2650 + hechuraDelta) * 100) / 100);
  });
});
