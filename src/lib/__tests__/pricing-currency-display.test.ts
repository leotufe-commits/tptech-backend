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

// ============================================================================
// FIX moneda cruzada — `composition[].lineSale` DEBE convertirse igual que
// `lineCost`. Bug observado: documento en USD (base ARS) → márgenes absurdos
// (+295.900%) en "Composición del costo del artículo" porque `lineCost`
// venía convertido y `lineSale` quedaba en BASE → margen mezcla USD/ARS.
// ============================================================================

/** Línea de venta sintética con composición. Invariantes del contrato:
 *   · Σ metals[].lineSale            === metalHechuraBreakdown.metalSale
 *   · Σ (hechuras+products+services).lineSale === metalHechuraBreakdown.hechuraSale
 *  Valores múltiplos de RATE para comparación exacta tras /RATE. */
function makeSalesLineWithComposition() {
  return {
    unitCost: 800, unitMargin: 200, marginPercent: 25, basePrice: 1000,
    metalHechuraBreakdown: {
      metalCost: 500, metalSale: 600, metalMarginPct: 20,
      hechuraCost: 220, hechuraSale: 315, hechuraMarginPct: 43.18,
    },
    composition: {
      metals: [
        { lineCost: 300, lineSale: 360, quotePrice: 50, appliedGrams: 6, appliedMermaPct: 0 },
        { lineCost: 200, lineSale: 240, quotePrice: 40, appliedGrams: 5, appliedMermaPct: 0 },
      ],
      hechuras: [
        { lineCost: 100, lineSale: 200, appliedAmount: 100, lineLabel: "Hechura" },
      ],
      products: [
        { catalogItemName: "P", quantity: 1, unitValue: 80, totalValue: 80, lineSale: 90,
          lineAdjKind: null, lineAdjType: null, lineAdjValue: null, lineAdjAmount: null },
      ],
      services: [
        { catalogItemName: "S", quantity: 1, unitValue: 20, totalValue: 20, lineSale: 25,
          lineAdjKind: null, lineAdjType: null, lineAdjValue: null, lineAdjAmount: null },
      ],
    },
  };
}

describe("pricing-currency-display — composition[].lineSale en multimoneda", () => {
  it("documento moneda base (rate=1) → noop: lineSale/lineCost intactos (Caso A: ARS+ARS)", () => {
    const res: any = { lines: [makeSalesLineWithComposition()] };
    convertSalesPreviewResponseInPlace(res, 1);
    const c = res.lines[0].composition;
    expect(c.metals[0].lineSale).toBe(360);
    expect(c.metals[0].lineCost).toBe(300);
    expect(c.hechuras[0].lineSale).toBe(200);
    expect(c.products[0].lineSale).toBe(90);
    expect(c.services[0].lineSale).toBe(25);
  });

  it("documento NO base (rate≠1) → lineSale se convierte igual que lineCost (Casos B/C/D)", () => {
    const res: any = { lines: [makeSalesLineWithComposition()] };
    convertSalesPreviewResponseInPlace(res, RATE);
    const c = res.lines[0].composition;
    // metals[]
    expect(c.metals[0].lineSale).toBeCloseTo(360 / RATE, 4);
    expect(c.metals[1].lineSale).toBeCloseTo(240 / RATE, 4);
    // hechuras[] / products[] / services[]
    expect(c.hechuras[0].lineSale).toBeCloseTo(200 / RATE, 4);
    expect(c.products[0].lineSale).toBeCloseTo(90  / RATE, 4);
    expect(c.services[0].lineSale).toBeCloseTo(25  / RATE, 4);
  });

  it("invariante Σ metals[].lineSale === metalHechuraBreakdown.metalSale (post-conversión)", () => {
    const res: any = { lines: [makeSalesLineWithComposition()] };
    convertSalesPreviewResponseInPlace(res, RATE);
    const l = res.lines[0];
    const sumMetalSale = l.composition.metals.reduce((a: number, m: any) => a + m.lineSale, 0);
    expect(sumMetalSale).toBeCloseTo(l.metalHechuraBreakdown.metalSale, 4);
    const sumHechuraSale =
      l.composition.hechuras.reduce((a: number, h: any) => a + h.lineSale, 0) +
      l.composition.products.reduce((a: number, p: any) => a + p.lineSale, 0) +
      l.composition.services.reduce((a: number, s: any) => a + s.lineSale, 0);
    expect(sumHechuraSale).toBeCloseTo(l.metalHechuraBreakdown.hechuraSale, 4);
  });

  it("margen % por fila NO es absurdo: ratio lineSale/lineCost invariante a la conversión", () => {
    const before = makeSalesLineWithComposition();
    const res: any = { lines: [makeSalesLineWithComposition()] };
    convertSalesPreviewResponseInPlace(res, RATE);
    const m0b = before.composition.metals[0];
    const m0a = res.lines[0].composition.metals[0];
    const pctBefore = ((m0b.lineSale - m0b.lineCost) / m0b.lineCost) * 100; // 20%
    const pctAfter  = ((m0a.lineSale - m0a.lineCost) / m0a.lineCost) * 100;
    expect(pctAfter).toBeCloseTo(pctBefore, 6); // mismo % — sin mezcla de monedas
    expect(Math.abs(pctAfter)).toBeLessThan(1000); // jamás +295.900%
  });

  it("marginPercent por línea NO se convierte (es un %, no moneda)", () => {
    const res: any = { lines: [makeSalesLineWithComposition()] };
    convertSalesPreviewResponseInPlace(res, RATE);
    expect(res.lines[0].marginPercent).toBe(25);
    expect(res.lines[0].metalHechuraBreakdown.metalMarginPct).toBe(20);
  });
});
