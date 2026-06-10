// src/modules/sales/__tests__/mixed-list-wiring-integration.test.ts
// =============================================================================
// INTEGRACIÓN — Wiring comercial MIXTO (Opción α).
//
// Valida el CONTRATO DE SALIDA del wiring MIXTO contra el MOTOR REAL
// (`computeSaleDocumentTotals`) y los helpers REALES de consolidación. NO
// mockea la matemática: prueba que la salida que el wiring DEBE producir
// (commercialDocPrecomputed + inputs de línea limpios) hace que `Sale.total`
// sea el correcto, y que la salida ACTUAL (null + inputs contaminados) lo
// rompe.
//
// Escenario (modelo a escala de 185.500 vs 186.100):
//   Línea 0 — Unificada, hechura NONE  → lineTotal 1000, tax 30% (300) → 1300
//   Línea 1 — Desglosada, hechura HUNDRED:
//        · LIMPIO  (α): hechura 1560, tax 468 → lineTotalWithTax 2028
//                       saldo post-tax round100(2028) = 2000
//        · CONTAMINADO (actual): hechura redondeada pre-tax 1600, tax 480 → 2080
//
//   Sale.total OBJETIVO  (α): 1300 + 2000 = 3300
//   Sale.total ACTUAL  (roto): 1300 + 2080 = 3380
//
// =============================================================================

import { describe, it, expect } from "vitest";
import { computeSaleDocumentTotals } from "../../../lib/pricing-engine/pricing-engine.js";
import {
  computeLineAutonomousCommercialMoney,
  consolidateCommercialDocFromPerLine,
} from "../commercial-doc-rounding-wiring.js";
import type { CommercialDocRoundingPartConfig } from "../../../lib/pricing-engine/commercial-document-rounding.js";

const HUNDRED: CommercialDocRoundingPartConfig = { mode: "HUNDRED", direction: "NEAREST" };
const NONE:    CommercialDocRoundingPartConfig = { mode: "NONE",    direction: "NEAREST" };

// Línea Unificada (idx 0) — sin redondeo de hechura.
const LINE0 = { lineTotal: 1000, lineTaxAmount: 300, lineTotalWithTax: 1300 };
// Línea Desglosada (idx 1) — hechura HUNDRED.
const LINE1_CLEAN        = { lineTotal: 1560, lineTaxAmount: 468, lineTotalWithTax: 2028 };
const LINE1_CONTAMINATED = { lineTotal: 1600, lineTaxAmount: 480, lineTotalWithTax: 2080 };

const SALE_TOTAL_TARGET = 3300; // α — un solo redondeo post-tax
const SALE_TOTAL_BUGGY  = 3380; // actual — doble redondeo / sin consolidar

/** Construye los inputs de línea para `computeSaleDocumentTotals`. */
function docLines(line1: { lineTotal: number; lineTaxAmount: number }) {
  return [
    {
      quantity: 1, basePrice: LINE0.lineTotal, unitPrice: LINE0.lineTotal,
      lineTotal: LINE0.lineTotal, lineTaxAmount: LINE0.lineTaxAmount,
      metalCost: 0, hechuraCost: LINE0.lineTotal, metalSale: 0, hechuraSale: LINE0.lineTotal,
    },
    {
      quantity: 1, basePrice: line1.lineTotal, unitPrice: line1.lineTotal,
      lineTotal: line1.lineTotal, lineTaxAmount: line1.lineTaxAmount,
      metalCost: 0, hechuraCost: line1.lineTotal, metalSale: 0, hechuraSale: line1.lineTotal,
    },
  ] as any;
}

/** Llama al motor REAL con/ sin snapshot comercial precomputado. */
function runEngine(line1: { lineTotal: number; lineTaxAmount: number }, precomputed: any) {
  return computeSaleDocumentTotals({
    lines:                                  docLines(line1),
    channel:                                null,
    coupon:                                 null,
    paymentAdjustmentAmount:                0,
    shippingAmount:                         0,
    globalDiscountAmount:                   0,
    roundingAdjustment:                     0,
    documentRounding:                       null,
    commercialDocumentRounding:             null,
    metalsByParentForCommercialRounding:    [],
    metalValuationSumForCommercialRounding: 0,
    commercialDocumentRoundingPrecomputed:  precomputed,
  } as any);
}

describe("Wiring MIXTO — Capa A: contrato contra el motor REAL", () => {
  // ───────────────────────────────────────────────────────────────────────────
  // El wiring α debe producir esta salida per-línea (saldo post-tax único).
  // ───────────────────────────────────────────────────────────────────────────
  function buildPerLineMoneyClean() {
    return computeLineAutonomousCommercialMoney({
      lineCommercialRoundingMetals: new Map(),
      refValueByParent:             new Map(),
      lineTotalWithTaxByIdx:        new Map([[0, LINE0.lineTotalWithTax], [1, LINE1_CLEAN.lineTotalWithTax]]),
      metalSaleSumByIdx:            new Map([[0, 0], [1, 0]]),
      hechuraCfg:                   NONE,
      hechuraCfgByLineIdx:          new Map([[0, NONE], [1, HUNDRED]]), // config REAL por línea
      lineCount:                    2,
    });
  }

  it("la línea Desglosada cierra en 2000 (post-tax único) — display per-línea", () => {
    const money = buildPerLineMoneyClean();
    expect(money.get(1)!.lineMonetarySaldoPostCommercialRounding).toBe(2000);
    expect(money.get(1)!.lineTotalWithTaxPostCommercialRounding).toBe(2000);
    // La Unificada NO se fuerza a HUNDRED — conserva su valor.
    expect(money.get(0)!.lineTotalWithTaxPostCommercialRounding).toBe(LINE0.lineTotalWithTax);
  });

  it("commercialDocPrecomputed consolida Σ DELTA (no Σ saldoPost) → totalAdjustment = -28", () => {
    const money = buildPerLineMoneyClean();
    const precomputed = consolidateCommercialDocFromPerLine({
      lineCommercialRoundingMetals: new Map(),
      lineMoney:                    money,
      metalNameById:                new Map(),
      refValueByParent:             new Map(),
      metalCfg:                     NONE,
      hechuraCfg:                   HUNDRED,
      lineCount:                    2,
    });
    // delta línea 1 = 2000 − 2028 = −28 ; línea 0 (NONE) = 0.
    expect(precomputed).not.toBeNull();
    expect(precomputed!.totalAdjustment).toBe(-28);
  });

  it("OBJETIVO: motor REAL con (precomputed + línea limpia) → Sale.total = 3300", () => {
    const money = buildPerLineMoneyClean();
    const precomputed = consolidateCommercialDocFromPerLine({
      lineCommercialRoundingMetals: new Map(),
      lineMoney:                    money,
      metalNameById:                new Map(),
      refValueByParent:             new Map(),
      metalCfg:                     NONE,
      hechuraCfg:                   HUNDRED,
      lineCount:                    2,
    });
    const totals = runEngine(LINE1_CLEAN, precomputed);
    // taxableBase+tax = (1000+1560)+(300+468) = 3328 ; + (−28) = 3300.
    expect(totals.total).toBe(SALE_TOTAL_TARGET);

    // display (Σ totalPost) === Sale.total
    const sumTotalPost =
      money.get(0)!.lineTotalWithTaxPostCommercialRounding +
      money.get(1)!.lineTotalWithTaxPostCommercialRounding;
    expect(sumTotalPost).toBe(totals.total);
  });

  it("ACTUAL (roto): motor REAL con (null + línea contaminada) → Sale.total = 3380 ≠ 3300", () => {
    const totals = runEngine(LINE1_CONTAMINATED, null);
    expect(totals.total).toBe(SALE_TOTAL_BUGGY);
    expect(totals.total).not.toBe(SALE_TOTAL_TARGET);
  });

  it("GUARD anti-83.059,70: el total objetivo es múltiplo de 100 (sin centavos cruzados)", () => {
    const money = buildPerLineMoneyClean();
    const precomputed = consolidateCommercialDocFromPerLine({
      lineCommercialRoundingMetals: new Map(),
      lineMoney:                    money,
      metalNameById:                new Map(),
      refValueByParent:             new Map(),
      metalCfg:                     NONE,
      hechuraCfg:                   HUNDRED,
      lineCount:                    2,
    });
    const totals = runEngine(LINE1_CLEAN, precomputed);
    // Línea Unificada redonda (1300) + Desglosada (2000) → sin residuo de centavos.
    expect(totals.total % 100).toBe(0);
  });
});
