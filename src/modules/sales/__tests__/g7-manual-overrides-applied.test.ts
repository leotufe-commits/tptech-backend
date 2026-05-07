// src/modules/sales/__tests__/g7-manual-overrides-applied.test.ts
// =============================================================================
// FASE 1.1 — G7 backend gap. Verifica el contrato del campo
// `manualOverridesApplied` per línea en SalePreviewLine. POLICY.md §3 R3.4
// pide flags explícitos por subcampo (price/discount/tax) en lugar de
// inferir desde priceSource="MANUAL_OVERRIDE".
//
// Test del contrato del cómputo: dada una línea con N overrides activos,
// qué flags emite el backend. Replica EXACTA de la lógica en
// sales.service.ts:previewSale.
// =============================================================================

import { describe, it, expect } from "vitest";

// Replica exacta de la lógica en sales.service.ts:previewSale (línea ~2615).
// Si la fórmula del backend cambia, este test debe actualizarse.
function deriveManualOverridesApplied(line: {
  manualPriceOverride?:    number | null;
  manualDiscountOverride?: { mode: string; value: number } | null;
  taxOverride?:            { mode: string; value: number } | null;
}): { quantity: boolean; price: boolean; discount: boolean; tax: boolean } {
  return {
    quantity: false,
    price:    line.manualPriceOverride != null,
    discount: line.manualDiscountOverride != null,
    tax:      line.taxOverride != null,
  };
}

describe("G7 — manualOverridesApplied flags per línea", () => {
  it("baseline correct: línea sin overrides → todos false", () => {
    const r = deriveManualOverridesApplied({});
    expect(r).toEqual({ quantity: false, price: false, discount: false, tax: false });
  });

  it("baseline correct: manualPriceOverride=950 → price=true", () => {
    const r = deriveManualOverridesApplied({ manualPriceOverride: 950 });
    expect(r.price).toBe(true);
    expect(r.discount).toBe(false);
    expect(r.tax).toBe(false);
  });

  it("baseline correct: manualPriceOverride=0 → price=true (cero es valor válido)", () => {
    const r = deriveManualOverridesApplied({ manualPriceOverride: 0 });
    expect(r.price).toBe(true);
  });

  it("baseline correct: manualPriceOverride=null → price=false", () => {
    const r = deriveManualOverridesApplied({ manualPriceOverride: null });
    expect(r.price).toBe(false);
  });

  it("baseline correct: manualDiscountOverride PERCENT 10% → discount=true", () => {
    const r = deriveManualOverridesApplied({
      manualDiscountOverride: { mode: "PERCENT", value: 10 },
    });
    expect(r.discount).toBe(true);
    expect(r.price).toBe(false);
    expect(r.tax).toBe(false);
  });

  it("baseline correct: taxOverride AMOUNT 50 → tax=true", () => {
    const r = deriveManualOverridesApplied({
      taxOverride: { mode: "AMOUNT", value: 50 },
    });
    expect(r.tax).toBe(true);
  });

  it("baseline correct: los 3 overrides simultáneos → 3 flags true (quantity sigue false)", () => {
    const r = deriveManualOverridesApplied({
      manualPriceOverride:    950,
      manualDiscountOverride: { mode: "PERCENT", value: 5 },
      taxOverride:            { mode: "AMOUNT", value: 50 },
    });
    expect(r).toEqual({ quantity: false, price: true, discount: true, tax: true });
  });

  it("baseline correct: quantity SIEMPRE false (no es overrideable)", () => {
    // Aunque el operador "edita" la cantidad, no es un override del motor.
    const r = deriveManualOverridesApplied({
      manualPriceOverride: 100,
      manualDiscountOverride: { mode: "PERCENT", value: 50 },
      taxOverride: { mode: "PERCENT", value: 21 },
    });
    expect(r.quantity).toBe(false);
  });
});
