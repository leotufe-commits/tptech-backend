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
  convertSalesLineInPlace,
  convertToBase,
  convertFromBase,
  convertSalesPreviewInputInPlace,
} from "../pricing-currency-display.js";
import { cloneLineCommercialSummary } from "../../modules/sales/commercial-doc-rounding-wiring.js";

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
    // Subobjeto `documentRoundingApplied` (Etapa 1B — shape discriminado).
    documentRoundingApplied: {
      source:  "TENANT_POLICY",
      scope:   "UNIFIED",
      applyOn: "DOC_TOTAL",
      totalAdjustment: 4,
      unified: {
        applyOn:      "DOC_TOTAL",
        mode:         "TEN",
        direction:    "NEAREST",
        preRounding:  856,
        postRounding: 860,
        adjustment:   4,
      },
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

  it("convierte `documentRoundingApplied.unified` y `totalAdjustment` (Etapa 1B)", () => {
    const res: any = { documentTotals: makeSyntheticDocumentTotals() };
    convertArticlePreviewResponseInPlace(res, RATE);

    const dra = res.documentTotals.documentRoundingApplied;
    // Montos de la capa unified se convierten.
    expect(dra.unified.preRounding ).toBeCloseTo(856 / RATE, 4);
    expect(dra.unified.postRounding).toBeCloseTo(860 / RATE, 4);
    expect(dra.unified.adjustment  ).toBeCloseTo(4   / RATE, 4);
    expect(dra.totalAdjustment).toBeCloseTo(4 / RATE, 4);
    // Texto NO se toca (scope, source, applyOn, mode, direction).
    expect(dra.scope).toBe("UNIFIED");
    expect(dra.source).toBe("TENANT_POLICY");
    expect(dra.applyOn).toBe("DOC_TOTAL");
    expect(dra.unified.mode).toBe("TEN");
    expect(dra.unified.direction).toBe("NEAREST");
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

// ============================================================================
// Simetría de INPUTS: convertToBase / convertSalesPreviewInputInPlace.
//
// Bug real: bonificación por MONTO FIJO (AMOUNT). El operador tipea "20" en
// la moneda del documento (p.ej. USD). El motor trabaja en BASE; sin
// convertir el input, aplicaba "20" como base (ARS) y el response volvía
// como ~"0,01" tras dividir por la tasa. PERCENT funcionaba porque es
// adimensional. Estos tests fijan: AMOUNT se convierte display→base con la
// MISMA tasa que el response base→display (round-trip = identidad); los
// porcentajes y cantidades físicas NO se tocan.
// ============================================================================

describe("convertToBase — inversa exacta de convertFromBase", () => {
  // 1 USD = 1000 ARS → rate = 1000.
  const RATE_USD = 1000;

  it("convertToBase multiplica por rate (display→base)", () => {
    expect(convertToBase(20, RATE_USD)).toBe(20000);
  });

  it("round-trip: display → base → display = identidad (no aparece 0,01)", () => {
    const display = 20;
    const base = convertToBase(display, RATE_USD)!;       // 20000 (ARS)
    const back = convertFromBase(base, RATE_USD)!;        // 20 (USD)
    expect(base).toBe(20000);
    expect(back).toBe(20);
    expect(back).not.toBeCloseTo(0.01, 2);
  });

  it("rate = 1 (moneda base, p.ej. ARS) → no-op", () => {
    expect(convertToBase(20, 1)).toBe(20);
  });

  it("null / rate inválido → null (sin romper)", () => {
    expect(convertToBase(null, RATE_USD)).toBeNull();
    expect(convertToBase(20, 0)).toBeNull();
    expect(convertToBase(undefined, RATE_USD)).toBeNull();
  });
});

describe("convertSalesPreviewInputInPlace — display→base antes del motor", () => {
  const RATE_USD = 1000; // 1 USD = 1000 ARS

  function makeInput() {
    return {
      lines: [
        {
          manualPriceOverride: 234.86,
          manualDiscountOverride: { mode: "AMOUNT" as const, value: 20 },
          taxOverride: null as null | { mode: "PERCENT" | "AMOUNT"; value: number },
        },
        {
          manualPriceOverride: null as number | null,
          manualDiscountOverride: { mode: "PERCENT" as const, value: 10 },
          taxOverride: { mode: "AMOUNT" as const, value: 5 },
        },
      ],
      shippingAmount: 7,
      shipping: { mode: "FIXED" as const, value: 7, weight: null },
      globalDiscount: { type: "AMOUNT" as const, value: 50 },
      globalDiscountAmount: 50,
    };
  }

  it("bonif. AMOUNT se convierte (20 USD → 20000 base); PERCENT NO se toca", () => {
    const input = makeInput();
    convertSalesPreviewInputInPlace(input, RATE_USD);
    expect(input.lines[0].manualDiscountOverride.value).toBe(20000); // AMOUNT → base
    expect(input.lines[1].manualDiscountOverride.value).toBe(10);    // PERCENT intacto
  });

  it("manualPriceOverride se convierte; null queda null", () => {
    const input = makeInput();
    convertSalesPreviewInputInPlace(input, RATE_USD);
    expect(input.lines[0].manualPriceOverride).toBe(234860); // 234.86 × 1000
    expect(input.lines[1].manualPriceOverride).toBeNull();
  });

  it("taxOverride AMOUNT se convierte; PERCENT NO", () => {
    const input = makeInput();
    input.lines[0].taxOverride = { mode: "PERCENT", value: 10 };
    convertSalesPreviewInputInPlace(input, RATE_USD);
    expect(input.lines[0].taxOverride!.value).toBe(10);  // PERCENT intacto
    expect(input.lines[1].taxOverride!.value).toBe(5000); // AMOUNT → base
  });

  it("globalDiscount AMOUNT, globalDiscountAmount y shipping FIXED se convierten", () => {
    const input = makeInput();
    convertSalesPreviewInputInPlace(input, RATE_USD);
    expect(input.globalDiscount.value).toBe(50000);
    expect(input.globalDiscountAmount).toBe(50000);
    expect(input.shippingAmount).toBe(7000);
    expect(input.shipping.value).toBe(7000);
  });

  it("moneda BASE (rate = 1, p.ej. ARS) → no-op total: AMOUNT funciona igual", () => {
    const input = makeInput();
    convertSalesPreviewInputInPlace(input, 1);
    expect(input.lines[0].manualDiscountOverride.value).toBe(20);
    expect(input.lines[0].manualPriceOverride).toBe(234.86);
    expect(input.globalDiscount.value).toBe(50);
  });

  it("simetría input↔response: precio 234.86 − bonif. 20 (AMOUNT) en USD", () => {
    // Tras convertir el input a base, el motor aplica el descuento real:
    //   base precio  = 234.86 × 1000 = 234860
    //   base bonif.  =  20.00 × 1000 =  20000
    //   base neto    = 234860 − 20000 = 214860
    // El response se devuelve dividiendo por rate → display:
    //   neto display = 214860 / 1000 = 214.86  (NO 234.85)
    //   bonif display = 20000 / 1000 = 20.00   (NO 0.01)
    const input = makeInput();
    convertSalesPreviewInputInPlace(input, RATE_USD);
    const basePrice  = input.lines[0].manualPriceOverride!;            // 234860
    const baseBonif  = input.lines[0].manualDiscountOverride.value;    // 20000
    const baseNet    = basePrice - baseBonif;                          // 214860
    expect(convertFromBase(baseBonif, RATE_USD)).toBe(20);             // label −US$ 20,00
    expect(convertFromBase(baseNet,   RATE_USD)).toBe(214.86);         // neto correcto
    // Impuesto 10% sobre base descontada (se calcula en el motor en base):
    const baseTax = Math.round(baseNet * 0.10 * 10000) / 10000;        // 21486
    expect(convertFromBase(baseTax, RATE_USD)).toBeCloseTo(21.49, 2);  // ≈ US$ 21,49
    const baseTotal = baseNet + baseTax;                               // 236346
    expect(convertFromBase(baseTotal, RATE_USD)).toBeCloseTo(236.35, 2); // ≈ US$ 236,35
  });
});

// ============================================================================
// T42 — Bug FX en `pricingSteps`: el card contextual de Bonificación/Recargo
// (frontend SaleLineDiscountSummary) lee `pricingSteps[i].meta.discountBase`
// y `discountAmount` para mostrar el detalle paso a paso. Antes NO se
// convertían: con documento USD y datos del motor en ARS, el card mostraba
// "US$ 400.062,50" en lugar de "US$ 100,02".
//
// `convertPricingStepsInPlace` (interno) convierte:
//   · step.value
//   · step.meta.discountBase
//   · step.meta.discountAmount
// Sin tocar campos NO monetarios (type, valueType, applyOn, promoName, etc).
// ============================================================================

/** Pipeline sintético con un step de PROMOCION + uno de DESCUENTO POR CANTIDAD,
 *  cada uno con base/amount monetarios + meta no-monetario. */
function makeSyntheticPricingSteps() {
  return [
    {
      key:    "PRICE_LIST",
      label:  "Lista de precios",
      status: "ok",
      value:  1000, // subtotal resultante (monetario)
      meta:   { listId: "list-1", listName: "Lista A" },
    },
    {
      key:    "PROMOTION",
      label:  "Promo Verano",
      status: "ok",
      value:  900, // subtotal post-promo
      meta:   {
        discountBase:   1000, // base de cálculo (monetario)
        discountAmount: 100,  // monto del descuento (monetario)
        value:          10,   // % de descuento (NO monetario)
        type:           "PERCENTAGE", // discriminador (NO se convierte)
        applyOn:        "TOTAL",
        promoName:      "Verano",
      },
    },
    {
      key:    "QUANTITY_DISCOUNT",
      label:  "Desc. cantidad",
      status: "ok",
      value:  800,
      meta:   {
        discountBase:   900,
        discountAmount: 100,
        value:          11.11,
        type:           "PERCENTAGE",
      },
    },
  ];
}

describe("T42 — convertSalesLineInPlace convierte pricingSteps[].meta + .value", () => {
  it("convierte step.value, meta.discountBase y meta.discountAmount con RATE", () => {
    const line: any = { pricingSteps: makeSyntheticPricingSteps() };
    convertSalesLineInPlace(line, RATE);
    // step[0] PRICE_LIST: value monetario
    expect(line.pricingSteps[0].value).toBeCloseTo(1000 / RATE, 4);
    // step[1] PROMOTION: value + meta.discountBase + meta.discountAmount
    expect(line.pricingSteps[1].value                ).toBeCloseTo(900  / RATE, 4);
    expect(line.pricingSteps[1].meta.discountBase    ).toBeCloseTo(1000 / RATE, 4);
    expect(line.pricingSteps[1].meta.discountAmount  ).toBeCloseTo(100  / RATE, 4);
    // step[2] QUANTITY_DISCOUNT
    expect(line.pricingSteps[2].value                ).toBeCloseTo(800  / RATE, 4);
    expect(line.pricingSteps[2].meta.discountBase    ).toBeCloseTo(900  / RATE, 4);
    expect(line.pricingSteps[2].meta.discountAmount  ).toBeCloseTo(100  / RATE, 4);
  });

  it("NO toca meta.value (porcentaje), meta.type, applyOn, promoName, listName, listId", () => {
    const line: any = { pricingSteps: makeSyntheticPricingSteps() };
    convertSalesLineInPlace(line, RATE);
    // PROMOTION: el % y el discriminador siguen intactos.
    expect(line.pricingSteps[1].meta.value    ).toBe(10);
    expect(line.pricingSteps[1].meta.type     ).toBe("PERCENTAGE");
    expect(line.pricingSteps[1].meta.applyOn  ).toBe("TOTAL");
    expect(line.pricingSteps[1].meta.promoName).toBe("Verano");
    // PRICE_LIST: ids y nombres intactos.
    expect(line.pricingSteps[0].meta.listId  ).toBe("list-1");
    expect(line.pricingSteps[0].meta.listName).toBe("Lista A");
  });

  it("rate === 1 → no-op (pipeline queda en BASE)", () => {
    const original = makeSyntheticPricingSteps();
    const line: any = { pricingSteps: makeSyntheticPricingSteps() };
    convertSalesLineInPlace(line, 1);
    expect(line.pricingSteps[1].value              ).toBe(original[1].value);
    expect(line.pricingSteps[1].meta.discountBase  ).toBe(original[1].meta.discountBase);
    expect(line.pricingSteps[1].meta.discountAmount).toBe(original[1].meta.discountAmount);
  });

  it("pricingSteps undefined / vacío → no rompe (defensivo)", () => {
    expect(() => convertSalesLineInPlace({} as any, RATE)).not.toThrow();
    expect(() => convertSalesLineInPlace({ pricingSteps: null } as any, RATE)).not.toThrow();
    expect(() => convertSalesLineInPlace({ pricingSteps: [] } as any, RATE)).not.toThrow();
  });

  it("step sin meta o sin campos monetarios → no rompe", () => {
    const line: any = {
      pricingSteps: [
        { key: "NO_META", label: "x", status: "ok", value: 500 },
        { key: "EMPTY_META", label: "y", status: "ok", value: 250, meta: {} },
        null,
      ],
    };
    expect(() => convertSalesLineInPlace(line, RATE)).not.toThrow();
    expect(line.pricingSteps[0].value).toBeCloseTo(500 / RATE, 4);
    expect(line.pricingSteps[1].value).toBeCloseTo(250 / RATE, 4);
  });

  // PARIDAD: el bug reportado fue en sales/preview, pero el simulador usa
  // articles/pricing-preview con el mismo shape de pipeline. Si ambos endpoints
  // no convirtieran igual, simulador y factura mostrarían el card con
  // magnitudes distintas — paridad rota.
  it("PARIDAD articles ↔ sales: pricingSteps se convierten con el mismo rate", () => {
    const articleRes: any = { pricingSteps: makeSyntheticPricingSteps() };
    const salesRes:   any = { lines: [{ pricingSteps: makeSyntheticPricingSteps() }] };
    convertArticlePreviewResponseInPlace(articleRes, RATE);
    convertSalesPreviewResponseInPlace(salesRes, RATE);
    const a = articleRes.pricingSteps[1];
    const s = salesRes.lines[0].pricingSteps[1];
    expect(a.value).toBeCloseTo(s.value, 4);
    expect(a.meta.discountBase  ).toBeCloseTo(s.meta.discountBase,   4);
    expect(a.meta.discountAmount).toBeCloseTo(s.meta.discountAmount, 4);
  });
});

// ============================================================================
// COMBO comercial — Bug FX: la columna "Venta total" y los "Totales" del combo
// en "Composición del costo del artículo" leen `pricingSteps[COMBO_PRICE].meta`
// (`finalPrice`/`subtotal`/`adjustmentAmount` vía `extractComboPriceMeta`), NO
// `step.value`. Esos campos son monetarios en BASE; sin convertir quedaban en
// moneda base con símbolo de display al actualizar la cotización.
//
// `convertPricingStepsInPlace` ahora convierte, SOLO para el step COMBO_PRICE:
//   · meta.subtotal · meta.finalPrice · meta.adjustmentAmount
//   · meta.adjustmentValue → SOLO cuando adjustmentKind === "DISCOUNT_FIXED"
// Sin tocar adjustmentKind ni los contadores componentsWithPrice/MissingPrice.
// ============================================================================

/** Step COMBO_PRICE sintético. `kind` controla si adjustmentValue es monetario
 *  (DISCOUNT_FIXED) o porcentaje (DISCOUNT_PERCENT / SURCHARGE_PERCENT). */
function makeComboPriceStep(kind: string, adjustmentValue: number) {
  return {
    key:    "COMBO_PRICE",
    label:  "Precio del combo (suma de componentes)",
    status: "ok",
    value:  900, // = finalPrice (comboDerivedPrice) — ya cubierto por step.value
    meta:   {
      subtotal:            1000,   // Σ componentes (monetario)
      adjustmentKind:      kind,   // discriminador (NO se convierte)
      adjustmentValue,             // % o monto según kind
      adjustmentAmount:    100,    // magnitud del ajuste (monetario)
      finalPrice:          900,    // precio POST-ajuste (monetario)
      componentsWithPrice: 2,      // contador (NO monetario)
    },
  };
}

describe("COMBO_PRICE — convertSalesLineInPlace convierte la meta del combo", () => {
  it("convierte meta.subtotal, finalPrice y adjustmentAmount con RATE", () => {
    const line: any = { pricingSteps: [makeComboPriceStep("SURCHARGE_PERCENT", 10)] };
    convertSalesLineInPlace(line, RATE);
    const m = line.pricingSteps[0].meta;
    expect(m.subtotal        ).toBeCloseTo(1000 / RATE, 4);
    expect(m.finalPrice      ).toBeCloseTo(900  / RATE, 4);
    expect(m.adjustmentAmount).toBeCloseTo(100  / RATE, 4);
    // step.value también (= finalPrice) — ya cubierto por la conversión general.
    expect(line.pricingSteps[0].value).toBeCloseTo(900 / RATE, 4);
  });

  it("adjustmentValue: convierte SOLO en DISCOUNT_FIXED (monto); NO en % kinds", () => {
    // DISCOUNT_FIXED → adjustmentValue es monto → se convierte.
    const fixed: any = { pricingSteps: [makeComboPriceStep("DISCOUNT_FIXED", 100)] };
    convertSalesLineInPlace(fixed, RATE);
    expect(fixed.pricingSteps[0].meta.adjustmentValue).toBeCloseTo(100 / RATE, 4);

    // SURCHARGE_PERCENT → adjustmentValue es % → NO se convierte.
    const pct: any = { pricingSteps: [makeComboPriceStep("SURCHARGE_PERCENT", 10)] };
    convertSalesLineInPlace(pct, RATE);
    expect(pct.pricingSteps[0].meta.adjustmentValue).toBe(10);

    // DISCOUNT_PERCENT → % → NO se convierte.
    const pctD: any = { pricingSteps: [makeComboPriceStep("DISCOUNT_PERCENT", 5)] };
    convertSalesLineInPlace(pctD, RATE);
    expect(pctD.pricingSteps[0].meta.adjustmentValue).toBe(5);
  });

  it("NO toca adjustmentKind ni los contadores componentsWithPrice", () => {
    const line: any = { pricingSteps: [makeComboPriceStep("DISCOUNT_FIXED", 100)] };
    convertSalesLineInPlace(line, RATE);
    expect(line.pricingSteps[0].meta.adjustmentKind).toBe("DISCOUNT_FIXED");
    expect(line.pricingSteps[0].meta.componentsWithPrice).toBe(2);
  });

  it("rate === 1 → no-op (combo queda en BASE)", () => {
    const line: any = { pricingSteps: [makeComboPriceStep("DISCOUNT_FIXED", 100)] };
    convertSalesLineInPlace(line, 1);
    const m = line.pricingSteps[0].meta;
    expect(m.subtotal).toBe(1000);
    expect(m.finalPrice).toBe(900);
    expect(m.adjustmentAmount).toBe(100);
    expect(m.adjustmentValue).toBe(100);
  });

  it("PARIDAD articles ↔ sales: la meta del COMBO_PRICE se convierte igual", () => {
    const articleRes: any = { pricingSteps: [makeComboPriceStep("DISCOUNT_FIXED", 100)] };
    const salesRes:   any = { lines: [{ pricingSteps: [makeComboPriceStep("DISCOUNT_FIXED", 100)] }] };
    convertArticlePreviewResponseInPlace(articleRes, RATE);
    convertSalesPreviewResponseInPlace(salesRes, RATE);
    const a = articleRes.pricingSteps[0].meta;
    const s = salesRes.lines[0].pricingSteps[0].meta;
    expect(a.finalPrice      ).toBeCloseTo(s.finalPrice,       4);
    expect(a.subtotal        ).toBeCloseTo(s.subtotal,         4);
    expect(a.adjustmentAmount).toBeCloseTo(s.adjustmentAmount, 4);
    expect(a.adjustmentValue ).toBeCloseTo(s.adjustmentValue,  4);
  });
});

describe("Descuentos qty/promo/cliente — bases y montos en multimoneda", () => {
  it("convierte montos y bases; VALUE solo si FIXED_AMOUNT; % y discriminadores intactos", () => {
    const line: any = {
      quantityDiscountAmount:     100,
      promotionDiscountAmount:    50,
      customerDiscountAmount:     30,
      quantityDiscountBase:       1000,
      promotionDiscountBase:      2000,
      customerDiscountBase:       3000,
      quantityDiscountValue:      80,           // FIXED_AMOUNT → se convierte
      quantityDiscountValueType:  "FIXED_AMOUNT",
      promotionDiscountValue:     10,           // PERCENTAGE → NO se convierte
      promotionDiscountValueType: "PERCENTAGE",
    };
    convertSalesLineInPlace(line, RATE);
    // Montos (todos monetarios → divididos por RATE).
    expect(line.quantityDiscountAmount ).toBeCloseTo(100 / RATE, 4);
    expect(line.promotionDiscountAmount).toBeCloseTo(50  / RATE, 4);
    expect(line.customerDiscountAmount ).toBeCloseTo(30  / RATE, 4);
    // Bases (siempre monetarias).
    expect(line.quantityDiscountBase ).toBeCloseTo(1000 / RATE, 4);
    expect(line.promotionDiscountBase).toBeCloseTo(2000 / RATE, 4);
    expect(line.customerDiscountBase ).toBeCloseTo(3000 / RATE, 4);
    // VALUE: FIXED_AMOUNT convertido; PERCENTAGE intacto (es un %, no un monto).
    expect(line.quantityDiscountValue ).toBeCloseTo(80 / RATE, 4);
    expect(line.promotionDiscountValue).toBe(10);
    // Discriminadores no se tocan.
    expect(line.quantityDiscountValueType ).toBe("FIXED_AMOUNT");
    expect(line.promotionDiscountValueType).toBe("PERCENTAGE");
  });

  it("rate === 1 → no-op (queda en BASE)", () => {
    const line: any = { quantityDiscountBase: 1000, customerDiscountAmount: 30 };
    convertSalesLineInPlace(line, 1);
    expect(line.quantityDiscountBase).toBe(1000);
    expect(line.customerDiscountAmount).toBe(30);
  });

  it("campos ausentes / null → no rompe (defensivo)", () => {
    expect(() => convertSalesLineInPlace({ quantityDiscountBase: null } as any, RATE)).not.toThrow();
    expect(() => convertSalesLineInPlace({} as any, RATE)).not.toThrow();
  });
});

describe("lineCommercialDisplaySummary — fix doble conversión (deep clone)", () => {
  // Reproduce el bug real: el display summary se derivaba con spread superficial
  // `{ ...summary }`, compartiendo `metals`/`monetary` por referencia. La
  // conversión convertía AMBOS resúmenes → el sub-objeto compartido quedaba
  // ÷rate². En moneda no-base el redondeo del metal se iba a ~0.
  it("display summary clonado se convierte UNA sola vez (no ÷rate²)", () => {
    const summary: any = {
      mode: "BREAKDOWN",
      metals: {
        visibleGrams:   2.3,
        monetaryAmount: 343.41 * RATE,    // BASE
        roundingImpact: 1.7667 * RATE,    // BASE — el campo del bug
        byParent: [{
          metalParentId: "oro", metalParentName: "Oro",
          visibleGrams: 2.3, monetaryAmount: 343.41 * RATE, roundingImpact: 1.7667 * RATE,
        }],
      },
      monetary:        { amount: 133.93 * RATE, roundingImpact: 0 },
      totalLineAmount: 479.11 * RATE,
      source:          { generatedBy: "test" },
    };
    const line: any = {
      lineCommercialSummary:        summary,
      lineCommercialDisplaySummary: cloneLineCommercialSummary(summary, { strategy: "PER_LINE" }),
    };
    convertSalesLineInPlace(line, RATE);
    // Cada resumen ÷rate UNA vez (no ÷rate²). El redondeo del metal queda en su
    // valor display real, no en ~0.
    expect(line.lineCommercialSummary.metals.roundingImpact).toBeCloseTo(1.7667, 3);
    expect(line.lineCommercialDisplaySummary.metals.roundingImpact).toBeCloseTo(1.7667, 3);
    expect(line.lineCommercialDisplaySummary.metals.byParent[0].roundingImpact).toBeCloseTo(1.7667, 3);
    // Guard explícito contra la regresión del ÷rate² (daría ~0.0118 con RATE=100).
    expect(line.lineCommercialDisplaySummary.metals.roundingImpact).toBeGreaterThan(1);
  });

  it("cloneLineCommercialSummary NO comparte sub-objetos anidados con el original", () => {
    const summary: any = {
      mode: "BREAKDOWN",
      metals: { roundingImpact: 10, byParent: [{ roundingImpact: 10 }] },
      monetary: { amount: 5 },
      source: {},
    };
    const clone = cloneLineCommercialSummary(summary, { strategy: "PER_LINE" });
    expect(clone.metals).not.toBe(summary.metals);
    expect(clone.monetary).not.toBe(summary.monetary);
    expect(clone.metals.byParent).not.toBe(summary.metals.byParent);
    expect(clone.metals.byParent[0]).not.toBe(summary.metals.byParent[0]);
    expect(clone.source.strategy).toBe("PER_LINE");
    // Mutar el clon no afecta al original.
    clone.metals.roundingImpact = 999;
    expect(summary.metals.roundingImpact).toBe(10);
  });

  it("clone defensivo: null / metals null / sin byParent → no rompe", () => {
    expect(cloneLineCommercialSummary(null)).toBeNull();
    expect(cloneLineCommercialSummary({ mode: "UNIFIED", metals: null, monetary: { amount: 1 }, source: {} }).metals).toBeNull();
    const noByParent = cloneLineCommercialSummary({ mode: "BREAKDOWN", metals: { roundingImpact: 1 }, source: {} });
    expect(noByParent.metals.roundingImpact).toBe(1);
  });
});
