// src/modules/sales/__tests__/buildLineCommercialSummary.test.ts
// =============================================================================
// FASE 0 (2026-06-03) — Contrato único por línea `lineCommercialSummary`.
//
// Verifica el ensamblador PURO `buildLineCommercialSummary` y sus invariantes:
//   1. metals.monetaryAmount + monetary.amount === totalLineAmount
//   2. metals.visibleGrams === Σ metals.byParent[].visibleGrams
//   3. redondeo de metal SOLO en metals.roundingImpact
//   4. redondeo monetario SOLO en monetary.roundingImpact
//
// Escenarios: unificada, desglosada, multi metal padre, con/sin redondeo,
// cantidad>1 (los inputs ya vienen × qty). La paridad preview=confirm la
// garantiza el caller (mismos inputs en ambos paths).
// =============================================================================

import { describe, it, expect } from "vitest";
import {
  buildLineCommercialSummary,
  aggregateMetalsForCommercialDocRounding,
  computeLineCommercialRoundingMetals,
  computeLineAutonomousCommercialMoney,
  type LineAutonomousCommercialMoney,
  type LineCommercialRoundingMetal,
} from "../commercial-doc-rounding-wiring.js";
import type { CommercialDocRoundingPartConfig } from "../../../lib/pricing-engine/commercial-document-rounding.js";

const round2 = (n: number) => Math.round(n * 100) / 100;
const round4 = (n: number) => Math.round(n * 10000) / 10000;
const SRC = {
  strategy: "PER_DOCUMENT" as const,
  appliedListMode: "METAL_HECHURA",
  appliedPriceListId: "pl-1",
  documentContext: "SHARED_LIST" as const,
};

function money(over: Partial<LineAutonomousCommercialMoney>): LineAutonomousCommercialMoney {
  return {
    metalRoundingMonetaryImpact:             0,
    lineMonetarySaldoPreCommercialRounding:  0,
    lineMonetarySaldoPostCommercialRounding: 0,
    hechuraRoundingMonetaryImpact:           0,
    lineTotalWithTaxPostCommercialRounding:  0,
    ...over,
  };
}

function metal(id: string, name: string, pre: number, post: number, ref: number): LineCommercialRoundingMetal {
  const delta = round4(post - pre);
  return {
    metalParentId:       id,
    metalParentName:     name,
    preGrams:            pre,
    postGrams:           post,
    deltaGrams:          delta,
    metalReferenceValue: ref,
    monetaryImpact:      round2(delta * ref),
  };
}

describe("buildLineCommercialSummary — contrato único por línea", () => {
  it("línea UNIFICADA: metals null, Total = monetario, sin redondeo", () => {
    const s = buildLineCommercialSummary({
      mode: "UNIFIED",
      lineTotalWithTax: 200000,
      money: null,
      metals: null,
      source: { ...SRC, strategy: "NONE", appliedListMode: "MARGIN_TOTAL", documentContext: "SHARED_LIST" },
    });
    expect(s.mode).toBe("UNIFIED");
    expect(s.metals).toBeNull();
    expect(s.monetary.amount).toBe(200000);
    expect(s.monetary.roundingImpact).toBe(0);
    expect(s.totalLineAmount).toBe(200000);
    // Invariante 1 (metals null ⇒ 0).
    expect(0 + s.monetary.amount).toBe(s.totalLineAmount);
    expect(s.source.generatedBy).toBe("buildLineCommercialSummary@v1");
  });

  it("línea DESGLOSADA con redondeo (1 metal): invariantes 1-4", () => {
    const s = buildLineCommercialSummary({
      mode: "BREAKDOWN",
      lineTotalWithTax: 518756.46,
      money: money({
        metalRoundingMonetaryImpact:             3.88,    // redondeo de gramos
        lineMonetarySaldoPreCommercialRounding:  185475.21,
        lineMonetarySaldoPostCommercialRounding: 185500,  // saldo post HUNDRED
        hechuraRoundingMonetaryImpact:           24.79,   // redondeo del saldo
        lineTotalWithTaxPostCommercialRounding:  518785.13,
      }),
      metals: [metal("oro", "Oro Fino", 1.36125, 1.4, 100)],
      source: SRC,
    });
    expect(s.mode).toBe("BREAKDOWN");
    expect(s.monetary.amount).toBe(185500);
    expect(s.totalLineAmount).toBe(518785.13);
    // Inv 1 — EXACTA (metals.monetaryAmount derivado).
    expect(round2(s.metals!.monetaryAmount + s.monetary.amount)).toBe(s.totalLineAmount);
    expect(s.metals!.monetaryAmount).toBe(round2(518785.13 - 185500));
    // Inv 2 — visibleGrams = Σ byParent.
    expect(s.metals!.visibleGrams).toBe(1.4);
    expect(s.metals!.byParent).toHaveLength(1);
    expect(s.metals!.byParent[0].visibleGrams).toBe(1.4);
    // Inv 3 — redondeo de metal SOLO en metals.roundingImpact.
    expect(s.metals!.roundingImpact).toBe(3.88);
    // Inv 4 — redondeo monetario SOLO en monetary.roundingImpact.
    expect(s.monetary.roundingImpact).toBe(24.79);
    // byParent monetario = postGrams × refValue.
    expect(s.metals!.byParent[0].monetaryAmount).toBe(round2(1.4 * 100));
  });

  it("multi metal padre (Oro + Plata): visibleGrams = Σ byParent (inv 2)", () => {
    const s = buildLineCommercialSummary({
      mode: "BREAKDOWN",
      lineTotalWithTax: 100000,
      money: money({
        metalRoundingMonetaryImpact:             5,
        lineMonetarySaldoPreCommercialRounding:  60000,
        lineMonetarySaldoPostCommercialRounding: 60000,
        hechuraRoundingMonetaryImpact:           0,
        lineTotalWithTaxPostCommercialRounding:  100005,
      }),
      metals: [
        metal("oro",   "Oro Fino", 1.36, 1.40, 100),
        metal("plata", "Plata",    2.09, 2.10, 10),
      ],
      source: SRC,
    });
    expect(s.metals!.byParent).toHaveLength(2);
    expect(s.metals!.visibleGrams).toBe(round4(1.40 + 2.10));  // 3,50
    expect(s.metals!.byParent.find((p) => p.metalParentId === "oro")!.visibleGrams).toBe(1.4);
    expect(s.metals!.byParent.find((p) => p.metalParentId === "plata")!.visibleGrams).toBe(2.1);
    // Inv 1 exacta.
    expect(round2(s.metals!.monetaryAmount + s.monetary.amount)).toBe(s.totalLineAmount);
  });

  it("DESGLOSADA SIN redondeo comercial: roundingImpact 0, gramos exactos", () => {
    const s = buildLineCommercialSummary({
      mode: "BREAKDOWN",
      lineTotalWithTax: 200000,
      money: money({
        metalRoundingMonetaryImpact:             0,
        lineMonetarySaldoPreCommercialRounding:  136125,
        lineMonetarySaldoPostCommercialRounding: 136125,  // sin redondeo
        hechuraRoundingMonetaryImpact:           0,
        lineTotalWithTaxPostCommercialRounding:  200000,
      }),
      metals: [metal("oro", "Oro Fino", 1.36125, 1.36125, 100)], // delta 0
      source: { ...SRC, strategy: "PER_DOCUMENT" },
    });
    expect(s.metals!.roundingImpact).toBe(0);
    expect(s.monetary.roundingImpact).toBe(0);
    expect(s.metals!.byParent[0].visibleGrams).toBe(1.3613);     // exacto (round4 del pre)
    expect(round2(s.metals!.monetaryAmount + s.monetary.amount)).toBe(s.totalLineAmount);
  });

  it("línea DESGLOSADA sin metales (producto en lista BREAKDOWN): metals null, cierre OK", () => {
    const s = buildLineCommercialSummary({
      mode: "BREAKDOWN",
      lineTotalWithTax: 50000,
      money: money({
        lineMonetarySaldoPreCommercialRounding:  50000,
        lineMonetarySaldoPostCommercialRounding: 50000,
        lineTotalWithTaxPostCommercialRounding:  50000,
      }),
      metals: [],
      source: SRC,
    });
    expect(s.metals).toBeNull();
    expect(s.monetary.amount).toBe(50000);
    expect(s.totalLineAmount).toBe(50000);
    expect(0 + s.monetary.amount).toBe(s.totalLineAmount); // inv 1 (metals null)
  });

  it("cantidad>1: los inputs ya vienen × qty → el summary los refleja tal cual", () => {
    // qty=10: la línea aporta gramos/saldo ya escalados; el ensamblador no
    // re-escala (passthrough). visibleGrams = postGrams agregado de la línea.
    const s = buildLineCommercialSummary({
      mode: "BREAKDOWN",
      lineTotalWithTax: 1400000,
      money: money({
        metalRoundingMonetaryImpact:             4,       // 0,04 g × 100
        lineMonetarySaldoPreCommercialRounding:  10000,
        lineMonetarySaldoPostCommercialRounding: 10000,
        hechuraRoundingMonetaryImpact:           0,
        lineTotalWithTaxPostCommercialRounding:  1400004,
      }),
      metals: [metal("oro", "Oro Fino", 13.96, 14.0, 100)], // 1,396×10 → 14,00
      source: SRC,
    });
    expect(s.metals!.visibleGrams).toBe(14.0);
    expect(s.metals!.roundingImpact).toBe(4);  // 0,04 × 100
    expect(round2(s.metals!.monetaryAmount + s.monetary.amount)).toBe(s.totalLineAmount);
  });

  it("source: refleja strategy / appliedListMode / documentContext del caller", () => {
    const s = buildLineCommercialSummary({
      mode: "BREAKDOWN",
      lineTotalWithTax: 1,
      money: money({ lineTotalWithTaxPostCommercialRounding: 1, lineMonetarySaldoPostCommercialRounding: 1 }),
      metals: [],
      source: { strategy: "PER_LINE", appliedListMode: "METAL_HECHURA", appliedPriceListId: "pl-X", documentContext: "MIXED_LIST" },
    });
    expect(s.source.strategy).toBe("PER_LINE");
    expect(s.source.documentContext).toBe("MIXED_LIST");
    expect(s.source.appliedPriceListId).toBe("pl-X");
  });

  // ── Redondeo comercial UNIFICADO (applyOn=TOTAL) — delta per-línea ────────
  it("UNIFICADA con redondeo diferido TOTAL: roundingImpact = delta (no 0)", () => {
    // Caso real: lineTotalWithTax 814.680,14 → 814.700,00 (HUNDRED) ⇒ +19,86.
    // El caller ya aplicó el gate applyOn=TOTAL y pasó el delta × qty.
    const s = buildLineCommercialSummary({
      mode: "UNIFIED",
      lineTotalWithTax: 814700,          // post-redondeo (ya redondeado por el motor)
      money: null,
      metals: null,
      unifiedRoundingImpact: 19.86,      // (814.700 − 814.680,14) × 1
      source: { ...SRC, strategy: "NONE", appliedListMode: "MARGIN_TOTAL", documentContext: "MIXED_LIST" },
    });
    expect(s.mode).toBe("UNIFIED");
    expect(s.metals).toBeNull();
    expect(s.monetary.amount).toBe(814700);
    expect(s.monetary.roundingImpact).toBe(19.86);   // ← ya NO es 0
    expect(s.totalLineAmount).toBe(814700);
  });

  it("UNIFICADA sin delta (suppress / sin redondeo): roundingImpact 0", () => {
    // suppressListDeferredRounding=true ⇒ appliedRounding null ⇒ caller pasa 0.
    const s = buildLineCommercialSummary({
      mode: "UNIFIED",
      lineTotalWithTax: 200000,
      money: null,
      metals: null,
      unifiedRoundingImpact: 0,
      source: { ...SRC, strategy: "NONE", appliedListMode: "MARGIN_TOTAL", documentContext: "SHARED_LIST" },
    });
    expect(s.monetary.roundingImpact).toBe(0);
  });

  it("UNIFICADA sin arg (back-compat): roundingImpact 0", () => {
    const s = buildLineCommercialSummary({
      mode: "UNIFIED",
      lineTotalWithTax: 200000,
      money: null,
      metals: null,
      source: { ...SRC, strategy: "NONE", appliedListMode: "MARGIN_TOTAL", documentContext: "SHARED_LIST" },
    });
    expect(s.monetary.roundingImpact).toBe(0);
  });

  it("UNIFICADA con delta NEGATIVO (redondeo hacia abajo): conserva signo, sin clamp", () => {
    const s = buildLineCommercialSummary({
      mode: "UNIFIED",
      lineTotalWithTax: 814600,
      money: null,
      metals: null,
      unifiedRoundingImpact: -80.14,     // 814.680,14 → 814.600 (DOWN)
      source: { ...SRC, strategy: "NONE", appliedListMode: "MARGIN_TOTAL", documentContext: "MIXED_LIST" },
    });
    expect(s.monetary.roundingImpact).toBe(-80.14);  // negativo preservado
  });

  // ── Integración con la cadena real de helpers ────────────────────────────
  it("integración: aggregate → metals → money → summary (1 línea desglosada)", () => {
    const DECIMAL_1: CommercialDocRoundingPartConfig = { mode: "DECIMAL_1", direction: "NEAREST" };
    const HUNDRED:   CommercialDocRoundingPartConfig = { mode: "HUNDRED", direction: "NEAREST" };
    const agg = aggregateMetalsForCommercialDocRounding([
      { quantity: 1, metals: [{ metalParentId: "oro", metalParentName: "Oro Fino", appliedGramsPerUnit: 1.2375, quotePriceSnapshot: 100, metalReferenceValue: 100 }] },
    ]);
    const refValueByParent = new Map([["oro", 100]]);
    const lineMetals = computeLineCommercialRoundingMetals({
      gramsPureByParentByLineIdx: agg.gramsPureByParentByLineIdx,
      metalNameById:              new Map([["oro", "Oro Fino"]]),
      refValueByParent,
      marginFactorByLineIdx:      new Map([[0, 1.10]]),
      metalCfg:                   DECIMAL_1,
      lineCount:                  1,
    });
    const moneyMap = computeLineAutonomousCommercialMoney({
      lineCommercialRoundingMetals: lineMetals,
      refValueByParent,
      lineTotalWithTaxByIdx: new Map([[0, 200000]]),
      metalSaleSumByIdx:     new Map([[0, 136.13]]),
      hechuraCfg:            HUNDRED,
      lineCount:             1,
    });
    const s = buildLineCommercialSummary({
      mode: "BREAKDOWN",
      lineTotalWithTax: 200000,
      money: moneyMap.get(0)!,
      metals: lineMetals.get(0)!,
      source: SRC,
    });
    expect(s.metals!.byParent[0].visibleGrams).toBe(1.4);          // 1,2375×1,10 → 1,40
    expect(round2(s.metals!.monetaryAmount + s.monetary.amount)).toBe(s.totalLineAmount); // inv 1
  });
});
