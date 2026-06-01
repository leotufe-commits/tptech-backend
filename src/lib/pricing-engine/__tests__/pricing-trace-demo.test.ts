// src/lib/pricing-engine/__tests__/pricing-trace-demo.test.ts
//
// DEMO TEMPORAL — caso 182.091 → 182.100 con trace completo de las 15 capas.
// Activa PRICING_TRACE=console y corre el pipeline completo (líneas L01..L05
// simuladas como si vinieran de resolveFinalSalePrice + computeSaleDocumentTotals
// real con L06..L13 + buildManualAdjustmentSnapshot real con L14..L15).
//
// Para correrlo:
//   npx vitest run src/lib/pricing-engine/__tests__/pricing-trace-demo.test.ts
//
// Borrar este archivo cuando termine la auditoría de trazabilidad.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  computeSaleDocumentTotals,
  type DocumentRoundingInput,
} from "../pricing-engine.js";
import { buildManualAdjustmentSnapshot } from "../../manual-adjustment/index.js";
import {
  runWithTrace,
  traceLine,
  __resetPricingTraceModeCache,
} from "../pricing-trace.js";

describe("pricing-trace DEMO — 182.091 → 182.100", () => {
  const prevEnv = process.env.PRICING_TRACE;

  beforeAll(() => {
    process.env.PRICING_TRACE = "console";
    __resetPricingTraceModeCache();
  });

  afterAll(() => {
    process.env.PRICING_TRACE = prevEnv;
    __resetPricingTraceModeCache();
  });

  it("muestra la traza completa de las 15 capas para un total 182.091 → 182.100", async () => {
    // Caso construido para producir engineTotal preRedondeo = 182.091.
    // 1 línea, basePrice=150.075, qty=1, sin descuento línea, tax 21% =
    // 31.516 (sin redondear) → lineTotal+tax = 181.591 → con $0.50 de envío
    // = 182.091. Política financiera UNIFIED DECIMAL_1 NEAREST redondea
    // 182.091 → 182.1 (delta +0.009).
    const basePrice  = 150.075;
    const lineTax    = 31.516;       // 21 % de 150.075
    const shipping   = 0.5;
    const expectedPreRoundingTotal = basePrice + lineTax + shipping; // 182.091

    const docRounding: DocumentRoundingInput = {
      scope:     "UNIFIED",
      mode:      "DECIMAL_1",
      direction: "NEAREST",
    };

    const { result, trace } = await runWithTrace("DEMO_182.091_TO_182.100", async () => {
      // ── Simulación de L01..L05 (capa por línea) ────────────────────────
      // En producción esto lo emite `resolveFinalSalePrice` automáticamente.
      // Acá lo emitimos a mano para mostrar el shape end-to-end sin tocar DB.
      const lineKey = "ARTICLE_DEMO/no-variant";
      traceLine("L01_PRICE_LIST_BASE", lineKey, {
        basePrice,
        priceSource:   "PRICE_LIST",
        priceListId:   "PL_DEMO",
        priceListName: "Lista General",
        priceListMode: "MARGIN_TOTAL",
        quantity:      1,
      });
      traceLine("L02_LINE_DISCOUNT", lineKey, {
        quantityDiscount:   0,
        promotionDiscount:  0,
        customerDiscount:   0,
        totalDiscount:      0,
        finalPricePostDisc: basePrice,
      });
      traceLine("L03_LINE_TAX", lineKey, {
        taxAmount:      lineTax,
        taxItems:       1,
        totalWithTax:   basePrice + lineTax,
        exemptByEntity: false,
      });
      traceLine("L04_LINE_TOTAL_BEFORE_COMM_ROUND", lineKey, {
        lineTotalPreCommRounding: basePrice + lineTax,
      });
      traceLine("L05_COMMERCIAL_ROUNDING", lineKey, {
        applied:   false,
        pre:       null,
        post:      null,
        delta:     0,
        mode:      null,
        direction: null,
        applyOn:   null,
        source:    null,
      });

      // ── L06..L13 — computeSaleDocumentTotals REAL (emite los traces) ──
      const totals = computeSaleDocumentTotals({
        lines: [
          {
            quantity:      1,
            basePrice,
            unitPrice:     basePrice,
            lineTotal:     basePrice,
            lineTaxAmount: lineTax,
          },
        ],
        channel:          null,
        coupon:           null,
        shippingAmount:   shipping,
        documentRounding: docRounding,
      });

      // ── L14..L15 — buildManualAdjustmentSnapshot REAL (emite los traces)
      const adj = buildManualAdjustmentSnapshot({
        engineTotal: totals.total,
        input:       null,                // sin ajuste manual
        audit:       null,
      });

      return { totals, adj };
    });

    // ── Asserts del caso de negocio ─────────────────────────────────────
    // Input "puro" = 182.091. El motor pasa todos los amounts por round2 a
    // 2 decimales antes del redondeo financiero, así que el preRounding real
    // que el motor ve es 182.09 (no 182.091). Hallazgo de auditoría: cualquier
    // contrato nuevo de redondeo tiene que tener presente que el step más
    // fino del motor es 0.01.
    expect(Math.round(expectedPreRoundingTotal * 1000) / 1000).toBe(182.091);
    expect(result.totals.total).toBe(182.1);
    expect(result.totals.roundingAdjustment).toBeCloseTo(0.01, 2);
    expect(result.adj.finalTotal).toBe(182.1);

    // ── Asserts de presencia de las 15 capas en el snapshot ─────────────
    expect(trace).not.toBeNull();
    const expectedLayers = [
      "L01_PRICE_LIST_BASE",
      "L02_LINE_DISCOUNT",
      "L03_LINE_TAX",
      "L04_LINE_TOTAL_BEFORE_COMM_ROUND",
      "L05_COMMERCIAL_ROUNDING",
      "L06_CHANNEL",
      "L07_COUPON",
      "L08_GLOBAL_DISCOUNT",
      "L09_SHIPPING",
      "L10_PAYMENT",
      "L11_TOTAL_BEFORE_FIN_ROUND",
      "L12_FINANCIAL_ROUNDING",
      "L13_ENGINE_TOTAL",
      "L14_MANUAL_ADJUSTMENT",
      "L15_FINAL_TOTAL",
    ];
    const seen = new Set<string>();
    for (const ev of trace!.lines)    seen.add(ev.layer);
    for (const ev of trace!.document) seen.add(ev.layer);
    for (const layer of expectedLayers) {
      expect(seen.has(layer), `Falta capa ${layer} en la traza`).toBe(true);
    }
  });
});
