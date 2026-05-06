// src/lib/__tests__/pricing-currency-display.test.ts
// ============================================================================
// Tests de simetría de moneda entre los dos endpoints de pricing.
//
// Caso real que motivó estos tests: `convertArticlePreviewResponseInPlace`
// omitía la conversión de `res.documentTotals` (que articles popula desde
// Fase 4 con el mismo shape que sales). Resultado: en multimoneda, los
// campos de `documentTotals` quedaban en moneda BASE en articles mientras
// sales los devolvía CONVERTIDOS → diferencias gigantes en el comparador.
//
// Estos tests fijan el contrato:
//   1. articles convierte TODOS los campos numéricos de documentTotals.
//   2. articles y sales producen el MISMO valor convertido para el mismo input.
// ============================================================================

import { describe, it, expect } from "vitest";
import {
  convertArticlePreviewResponseInPlace,
  convertSalesPreviewResponseInPlace,
} from "../pricing-currency-display.js";

// `convertFromBase` divide por `rate`. Para tener números exactos en el test,
// usamos rate = 100 → cada valor convertido = original / 100.
const RATE = 100;

/** Shape mínimo de `documentTotals` con un valor por cada campo numérico
 *  documentado en `convertSaleDocumentTotalsInPlace`. Los valores son
 *  múltiplos de RATE para que la comparación post-conversión sea exacta
 *  (sin drift por redondeo a 4 decimales). */
function makeSyntheticDocumentTotals() {
  return {
    subtotalBeforeDiscounts:    1000,
    lineDiscountAmount:         200,
    subtotalAfterLineDiscounts: 800,
    channelAdjustmentAmount:    50,
    couponDiscountAmount:       30,
    paymentAdjustmentAmount:    25,
    shippingAmount:             100,
    globalDiscountAmount:       40,
    taxableBase:                705,
    taxAmount:                  148,
    roundingAdjustment:         3,
    totalBeforeTax:             705,
    totalWithTax:               853,
    total:                      856,
    legacyCouponOnlyDiscount:   30,
    // FASE 2 — agregados Metal/Hechura a nivel documento.
    metalCostSubtotal:          500,
    hechuraCostSubtotal:        100,
    metalSaleSubtotal:          600,
    hechuraSaleSubtotal:        200,
    breakdownEstimated:         false,
    // Subobjeto `documentRoundingApplied` (modo UNIFIED).
    documentRoundingApplied: {
      source: "TENANT_POLICY", applyOn: "DOC_TOTAL",
      mode: "TEN", direction: "NEAREST",
      preRounding: 856, postRounding: 860, adjustment: 4,
    },
    // Campos que NO deben convertirse:
    sourceTrace:        [{ step: "channel", amount: 50, note: "test" }],
    roundingInfo:       { source: "PRICE_LIST", mode: "TEN", direction: "NEAREST", applyOn: "TOTAL" },
  };
}

const NUMERIC_FIELDS = [
  "subtotalBeforeDiscounts",
  "lineDiscountAmount",
  "subtotalAfterLineDiscounts",
  "channelAdjustmentAmount",
  "couponDiscountAmount",
  "paymentAdjustmentAmount",
  "shippingAmount",
  "globalDiscountAmount",
  "taxableBase",
  "taxAmount",
  "roundingAdjustment",
  "totalBeforeTax",
  "totalWithTax",
  "total",
  "legacyCouponOnlyDiscount",
  "metalCostSubtotal",
  "hechuraCostSubtotal",
  "metalSaleSubtotal",
  "hechuraSaleSubtotal",
] as const;

describe("pricing-currency-display — simetría de moneda articles vs sales", () => {
  it("articles preview convierte TODOS los campos numéricos de documentTotals", () => {
    const original = makeSyntheticDocumentTotals();
    const res: any = {
      // Articles tiene campos top-level distintos a sales, pero acá solo
      // chequeamos `documentTotals` para aislar el contrato.
      unitPrice: "1000.0000",
      basePrice: "1000.0000",
      taxAmount: "148.0000",
      totalWithTax: "1148.0000",
      documentTotals: { ...original },
    };

    convertArticlePreviewResponseInPlace(res, RATE);

    for (const f of NUMERIC_FIELDS) {
      const before = (original as any)[f];
      const after  = res.documentTotals[f];
      expect(after).toBeCloseTo(before / RATE, 4);
    }
  });

  it("articles preview NO toca `roundingInfo` ni los strings de `sourceTrace[].note`", () => {
    const res: any = {
      documentTotals: makeSyntheticDocumentTotals(),
    };
    convertArticlePreviewResponseInPlace(res, RATE);

    expect(res.documentTotals.roundingInfo).toEqual({
      source: "PRICE_LIST", mode: "TEN", direction: "NEAREST", applyOn: "TOTAL",
    });
    // sourceTrace[].amount SÍ se convierte; `step` y `note` quedan como están.
    expect(res.documentTotals.sourceTrace[0].step).toBe("channel");
    expect(res.documentTotals.sourceTrace[0].note).toBe("test");
    expect(res.documentTotals.sourceTrace[0].amount).toBeCloseTo(50 / RATE, 4);
  });

  it("convierte `documentRoundingApplied` (preRounding/postRounding/adjustment)", () => {
    const res: any = { documentTotals: makeSyntheticDocumentTotals() };
    convertArticlePreviewResponseInPlace(res, RATE);

    const dra = res.documentTotals.documentRoundingApplied;
    expect(dra.preRounding ).toBeCloseTo(856 / RATE, 4);
    expect(dra.postRounding).toBeCloseTo(860 / RATE, 4);
    expect(dra.adjustment  ).toBeCloseTo(4   / RATE, 4);
    // Texto NO se toca.
    expect(dra.source).toBe("TENANT_POLICY");
    expect(dra.applyOn).toBe("DOC_TOTAL");
    expect(dra.mode).toBe("TEN");
    expect(dra.direction).toBe("NEAREST");
  });

  it("`breakdownEstimated` (boolean) NO se convierte", () => {
    const dt = makeSyntheticDocumentTotals();
    dt.breakdownEstimated = true;
    const res: any = { documentTotals: dt };
    convertArticlePreviewResponseInPlace(res, RATE);
    expect(res.documentTotals.breakdownEstimated).toBe(true);
  });

  it("PARIDAD: articles y sales producen exactamente los mismos documentTotals convertidos", () => {
    // Mismo input por ambos lados. Si después de aplicar cada conversor con
    // el mismo rate los valores no coinciden, hay asimetría.
    const articleRes: any = { documentTotals: makeSyntheticDocumentTotals() };
    const salesRes:   any = { documentTotals: makeSyntheticDocumentTotals(), lines: [] };

    convertArticlePreviewResponseInPlace(articleRes, RATE);
    convertSalesPreviewResponseInPlace(salesRes,   RATE);

    for (const f of NUMERIC_FIELDS) {
      expect(articleRes.documentTotals[f]).toBeCloseTo(salesRes.documentTotals[f], 4);
    }
  });

  it("rate === 1 → no-op en ambos endpoints (sin conversión real)", () => {
    const articleRes: any = { documentTotals: makeSyntheticDocumentTotals() };
    const salesRes:   any = { documentTotals: makeSyntheticDocumentTotals(), lines: [] };

    convertArticlePreviewResponseInPlace(articleRes, 1);
    convertSalesPreviewResponseInPlace(salesRes,   1);

    for (const f of NUMERIC_FIELDS) {
      expect(articleRes.documentTotals[f]).toBe((makeSyntheticDocumentTotals() as any)[f]);
      expect(salesRes.documentTotals[f]).toBe((makeSyntheticDocumentTotals() as any)[f]);
    }
  });

  it("documentTotals undefined → no rompe (defensivo)", () => {
    const res: any = { unitPrice: "1000.0000" };
    expect(() => convertArticlePreviewResponseInPlace(res, RATE)).not.toThrow();
    // unitPrice top-level sí se convierte, pero documentTotals no existe.
    expect(res.documentTotals).toBeUndefined();
  });
});
