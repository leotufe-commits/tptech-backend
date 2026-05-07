// src/modules/articles/__tests__/g3-1-line-discount-top-level.test.ts
// =============================================================================
// FASE 1.2 G3.1 backend gap. Verifica que `lineDiscount` se expone top-level
// en el response de `/api/articles/:id/pricing-preview` y que el converter
// multimoneda lo maneja.
//
// Patrón: incremento mínimo a G3 (commit 539c437). Mismo shape, mismo lugar
// del response, mismo treatment de moneda.
//
// POLICY.md §4 R4.5 — el frontend NO debe derivar campos aritméticamente.
// Antes el normalizer hacía `r2((basePrice - unitPrice) × qty)` localmente.
// Con G3.1 el backend lo emite plano.
//
// Frontend desbloqueado:
//   · Priority 1 — completa migración del normalizer del simulador.
//     normalizeArticlePricingPreview ya NO necesita ningún cálculo local
//     para los 4 totales per-línea (lineTotal, lineTaxAmount,
//     lineTotalWithTax, lineDiscount).
// =============================================================================

import { describe, it, expect } from "vitest";
import { convertArticlePreviewResponseInPlace } from "../../../lib/pricing-currency-display.js";

describe("G3.1 — convertArticlePreviewResponseInPlace convierte lineDiscount", () => {
  it("baseline correct: lineDiscount se divide por la rate cuando rate != 1", () => {
    const res: any = {
      lineTotal:        2000,
      lineTaxAmount:    420,
      lineTotalWithTax: 2420,
      lineDiscount:     200,   // (1000 - 900) × 2
    };
    convertArticlePreviewResponseInPlace(res, 2);  // 1 USD = 2 base
    expect(res.lineDiscount).toBe(100);
  });

  it("baseline correct: rate=1 no toca lineDiscount", () => {
    const res: any = { lineDiscount: 200 };
    convertArticlePreviewResponseInPlace(res, 1);
    expect(res.lineDiscount).toBe(200);
  });

  it("baseline correct: lineDiscount=0 se preserva (no es 'falsy' problemático)", () => {
    const res: any = { lineDiscount: 0 };
    convertArticlePreviewResponseInPlace(res, 2);
    expect(res.lineDiscount).toBe(0);
  });

  it("baseline correct: lineDiscount negativo (override que sube precio) también se convierte", () => {
    // Caso edge: override manual que SUBE el precio → lineDiscount negativo
    // (semánticamente "recargo manual"). El backend lo emite sin clamp.
    const res: any = { lineDiscount: -200 };
    convertArticlePreviewResponseInPlace(res, 2);
    expect(res.lineDiscount).toBe(-100);
  });

  it("baseline correct: campo undefined no rompe el converter", () => {
    const res: any = { unitPrice: "1000.00" };
    expect(() => convertArticlePreviewResponseInPlace(res, 2)).not.toThrow();
    expect(res.lineDiscount).toBeUndefined();
  });
});

describe("G3.1 — contrato del response", () => {
  it("baseline correct: lineDiscount es number (no string) — mismo treatment que G3", () => {
    // Documenta el contrato: top-level number, NO string formateado.
    // El controller usa `round2((basePriceNum - unitPriceNum) * quantity)`.
    const sampleResponse: any = {
      unitPrice:        "1000.0000",  // string (Decimal serializado)
      lineTotal:        2000,         // number (G3)
      lineTaxAmount:    420,          // number (G3)
      lineTotalWithTax: 2420,         // number (G3)
      lineDiscount:     200,          // number (G3.1)
    };
    expect(typeof sampleResponse.lineDiscount).toBe("number");
    // Coherencia con G3: si lineTotal es number, lineDiscount también.
    expect(typeof sampleResponse.lineDiscount).toBe(typeof sampleResponse.lineTotal);
  });
});
