// src/modules/articles/__tests__/g6-cost-preview-currency.test.ts
// =============================================================================
// FASE 1.1 — G6 backend gap. Verifica que el converter de cost-lines/preview
// convierte los campos monetarios cuando se pide moneda distinta a la base.
//
// Regla: campos en moneda (value/metalCost/hechuraCost + costBase/etc) se
// dividen por rate; gramos y purity NO se convierten.
// =============================================================================

import { describe, it, expect } from "vitest";
import { convertCostPreviewResponseInPlace } from "../../../lib/pricing-currency-display.js";

describe("G6 — convertCostPreviewResponseInPlace", () => {
  it("baseline correct: divide value/metalCost/hechuraCost por la rate", () => {
    const res: any = {
      cost: {
        value:               "1000.0000",
        metalCost:           "800.0000",
        hechuraCost:         "200.0000",
        totalGrams:          "5.0000",
        metalGramsWithMerma: "5.5000",
        metalPurity:         "0.7500",
        partial:             false,
        mode:                "COST_LINES",
      },
      purchaseTaxes: {
        costBase:         "1000.0000",
        costTaxAmount:    "0.0000",
        costWithTax:      "1000.0000",
        costTaxBreakdown: [],
      },
    };
    convertCostPreviewResponseInPlace(res, 2); // 1 USD = 2 base
    expect(res.cost.value).toBe("500.0000");
    expect(res.cost.metalCost).toBe("400.0000");
    expect(res.cost.hechuraCost).toBe("100.0000");
    // gramos y purity NO se convierten
    expect(res.cost.totalGrams).toBe("5.0000");
    expect(res.cost.metalGramsWithMerma).toBe("5.5000");
    expect(res.cost.metalPurity).toBe("0.7500");
    // purchaseTaxes sí se convierten
    expect(res.purchaseTaxes.costBase).toBe("500.0000");
    expect(res.purchaseTaxes.costWithTax).toBe("500.0000");
  });

  it("baseline correct: rate=1 no toca nada", () => {
    const res: any = {
      cost: { value: "1000.0000", metalCost: "800.0000" },
      purchaseTaxes: { costBase: "1000.0000" },
    };
    convertCostPreviewResponseInPlace(res, 1);
    expect(res.cost.value).toBe("1000.0000");
    expect(res.cost.metalCost).toBe("800.0000");
    expect(res.purchaseTaxes.costBase).toBe("1000.0000");
  });

  it("baseline correct: response sin cost o sin purchaseTaxes no rompe", () => {
    const r1: any = { purchaseTaxes: { costBase: "100.0000" } };
    expect(() => convertCostPreviewResponseInPlace(r1, 2)).not.toThrow();
    expect(r1.purchaseTaxes.costBase).toBe("50.0000");

    const r2: any = { cost: { value: "100.0000" } };
    expect(() => convertCostPreviewResponseInPlace(r2, 2)).not.toThrow();
    expect(r2.cost.value).toBe("50.0000");
  });

  it("baseline correct: convierte items del costTaxBreakdown", () => {
    const res: any = {
      cost: {},
      purchaseTaxes: {
        costBase:         "1000.0000",
        costTaxAmount:    "100.0000",
        costWithTax:      "1100.0000",
        costTaxBreakdown: [
          { taxId: "t1", name: "IVA", rate: 0.105, fixedAmount: 0, taxAmount: 100 },
        ],
      },
    };
    convertCostPreviewResponseInPlace(res, 2);
    expect(res.purchaseTaxes.costBase).toBe("500.0000");
    expect(res.purchaseTaxes.costTaxBreakdown[0].taxAmount).toBe(50);
    // rate (% del impuesto) NO se convierte
    expect(res.purchaseTaxes.costTaxBreakdown[0].rate).toBe(0.105);
  });

  it("baseline correct: campos undefined no rompen", () => {
    const res: any = { cost: {}, purchaseTaxes: {} };
    expect(() => convertCostPreviewResponseInPlace(res, 2)).not.toThrow();
  });
});
