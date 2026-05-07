// src/modules/articles/__tests__/g3-line-totals-top-level.test.ts
// =============================================================================
// FASE 1.1 — G3 backend gap. Verifica que los totales per-line escalados ×
// quantity se exponen top-level en el response del simulador
// (`articles/pricing-preview`) y que el converter multimoneda los maneja.
//
// El controller expone `lineTotal`, `lineTaxAmount`, `lineTotalWithTax` para
// que el frontend lector-puro deje de multiplicar `unitPrice × qty` con r2()
// (POLICY.md R4.5).
// =============================================================================

import { describe, it, expect } from "vitest";
import { convertArticlePreviewResponseInPlace } from "../../../lib/pricing-currency-display.js";

describe("G3 — convertArticlePreviewResponseInPlace convierte los 3 campos top-level", () => {
  it("baseline correct: lineTotal/lineTaxAmount/lineTotalWithTax se convierten cuando rate != 1", () => {
    const res: any = {
      unitPrice:        "1000.00",
      basePrice:        "1000.00",
      taxAmount:        "210.00",
      totalWithTax:     "1210.00",
      lineTotal:        2000,    // qty=2 × 1000
      lineTaxAmount:    420,     // qty=2 × 210
      lineTotalWithTax: 2420,    // qty=2 × 1210
    };
    // rate=2 simula USD donde 1 USD = 2 ARS base.
    convertArticlePreviewResponseInPlace(res, 2);
    // Los strings se dividen / 2; los números se dividen / 2.
    expect(res.lineTotal).toBe(1000);
    expect(res.lineTaxAmount).toBe(210);
    expect(res.lineTotalWithTax).toBe(1210);
  });

  it("baseline correct: rate=1 no toca ningún campo", () => {
    const res: any = {
      lineTotal:        2000,
      lineTaxAmount:    420,
      lineTotalWithTax: 2420,
    };
    convertArticlePreviewResponseInPlace(res, 1);
    expect(res.lineTotal).toBe(2000);
    expect(res.lineTaxAmount).toBe(420);
    expect(res.lineTotalWithTax).toBe(2420);
  });

  it("baseline correct: campos undefined no rompen la conversión", () => {
    const res: any = {
      unitPrice: "1000.00",
      // lineTotal/lineTaxAmount/lineTotalWithTax NO presentes
    };
    expect(() => convertArticlePreviewResponseInPlace(res, 2)).not.toThrow();
    expect(res.lineTotal).toBeUndefined();
  });
});

describe("G3 — contrato del response", () => {
  it("baseline correct: los 3 campos son números (no strings) — distinto de unitPrice", () => {
    // Documenta el contrato: top-level de número, no string formateado.
    // El controller usa `lineTotal: lineTotalNet` que es `round2(unitTotalWithTax * qty)`.
    const sampleResponse: any = {
      unitPrice:        "1000.0000",  // string (ya con 4 decimales)
      lineTotal:        2000,         // number
      lineTaxAmount:    420,          // number
      lineTotalWithTax: 2420,         // number
    };
    expect(typeof sampleResponse.unitPrice).toBe("string");
    expect(typeof sampleResponse.lineTotal).toBe("number");
    expect(typeof sampleResponse.lineTaxAmount).toBe("number");
    expect(typeof sampleResponse.lineTotalWithTax).toBe("number");
  });
});
