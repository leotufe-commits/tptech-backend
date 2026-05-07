// src/lib/pricing-engine/__tests__/g1-manual-line-price-source.test.ts
// =============================================================================
// FASE 1.1 — G1 backend gap. Verifica que `PriceSource` incluye "MANUAL_LINE"
// como valor válido del union (POLICY.md §3 R3.6 — líneas manuales).
//
// Antes de este gap, sales.service.ts:2349-2435 producía snapshots con
// priceSource:"MANUAL_LINE" usando `as any` porque el union no lo declaraba.
// El cast escondía el contrato real al consumer.
// =============================================================================

import { describe, it, expect } from "vitest";
import type { PriceSource } from "../pricing-engine.types.js";

describe("G1 — PriceSource incluye MANUAL_LINE", () => {
  it("baseline correct: 'MANUAL_LINE' es asignable a PriceSource", () => {
    // Type assertion: si el union no incluye MANUAL_LINE, este archivo no
    // compila. El test es TS-level, pero también verificamos en runtime.
    const value: PriceSource = "MANUAL_LINE";
    expect(value).toBe("MANUAL_LINE");
  });

  it("baseline correct: union incluye los demás valores conocidos", () => {
    // Smoke check de regresión — si alguien borra un valor, falla.
    const valid: PriceSource[] = [
      "PROMOTION",
      "MANUAL_OVERRIDE",
      "QUANTITY_DISCOUNT",
      "PRICE_LIST",
      "MANUAL_FALLBACK",
      "MANUAL_LINE",
      "NONE",
    ];
    expect(valid).toHaveLength(7);
  });

  it("baseline correct: PriceSource permite asignación discriminada en switch", () => {
    function describeSource(s: PriceSource): string {
      switch (s) {
        case "PROMOTION":         return "promo";
        case "MANUAL_OVERRIDE":   return "override";
        case "QUANTITY_DISCOUNT": return "qty-discount";
        case "PRICE_LIST":        return "price-list";
        case "MANUAL_FALLBACK":   return "fallback";
        case "MANUAL_LINE":       return "manual-line";
        case "NONE":              return "none";
      }
    }
    expect(describeSource("MANUAL_LINE")).toBe("manual-line");
  });
});
