// src/lib/pricing-engine/__tests__/balance.test.ts
// Tests del sistema de cuenta corriente con saldo BREAKDOWN (metal + hechura)

import { describe, it, expect } from "vitest";
import { buildBalanceBreakdownFromPrice } from "../pricing-engine.balance.js";
import { aggregateEntityBalance } from "../../../modules/commercial-entities/balance.utils.js";
import type { PriceBreakdown } from "../pricing-engine.types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeBreakdown(overrides?: Partial<PriceBreakdown>): PriceBreakdown {
  return {
    mode: "COST_LINES",
    metal: {
      items: [
        {
          metalId:       "metal-gold",
          variantId:     "variant-18k",
          gramsOriginal: 10,
          purity:        0.75,
          gramsPure:     7.5,
          unitValue:     5000,
          totalValue:    37500,
        },
      ],
      total: 37500,
    },
    hechura: {
      base:        3000,
      adjustments: [],
      total:       3000,
    },
    totals: {
      metal:   37500,
      hechura: 3000,
      unified: 40500,
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// 1. buildBalanceBreakdownFromPrice — conversión básica
// ---------------------------------------------------------------------------

describe("buildBalanceBreakdownFromPrice", () => {
  it("convierte un PriceBreakdown con un metal a BalanceBreakdown", () => {
    const bd = buildBalanceBreakdownFromPrice(makeBreakdown());
    expect(bd.metals).toHaveLength(1);
    expect(bd.metals[0].metalId).toBe("metal-gold");
    expect(bd.metals[0].variantId).toBe("variant-18k");
    expect(bd.metals[0].gramsPure).toBe(7.5);
    expect(bd.hechura.amount).toBe(3000);
    expect(bd.hechura.currency).toBe("BASE");
  });

  it("excluye ítems sin metalId o sin gramsPure", () => {
    const bd = buildBalanceBreakdownFromPrice(makeBreakdown({
      metal: {
        items: [
          { metalId: null, variantId: "v1", gramsOriginal: 5, purity: 0.75, gramsPure: 3.75, unitValue: 100, totalValue: 375 },
          { metalId: "metal-silver", variantId: null, gramsOriginal: 3, purity: 0.925, gramsPure: 2.775, unitValue: 50, totalValue: 138.75 },
          { metalId: "metal-gold", variantId: "variant-24k", gramsOriginal: 2, purity: 1, gramsPure: 0, unitValue: 6000, totalValue: 0 },
        ],
        total: 513.75,
      },
      totals: { metal: 513.75, hechura: 500, unified: 1013.75 },
    }));
    expect(bd.metals).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 2. aggregateEntityBalance — modo UNIFIED
// ---------------------------------------------------------------------------

describe("aggregateEntityBalance (UNIFIED)", () => {
  it("suma correctamente múltiples entradas UNIFIED", () => {
    const entries = [
      { amount: { toString: () => "1000.00" }, voidedAt: null, breakdownSnapshot: null },
      { amount: { toString: () => "2500.50" }, voidedAt: null, breakdownSnapshot: null },
      { amount: { toString: () => "500.00" },  voidedAt: null, breakdownSnapshot: null },
    ];
    const result = aggregateEntityBalance(entries, "UNIFIED");
    expect(result.mode).toBe("UNIFIED");
    if (result.mode === "UNIFIED") {
      expect(result.amount).toBeCloseTo(4000.5);
    }
  });

  it("excluye entradas anuladas", () => {
    const entries = [
      { amount: { toString: () => "1000.00" }, voidedAt: null,      breakdownSnapshot: null },
      { amount: { toString: () => "9999.00" }, voidedAt: new Date(), breakdownSnapshot: null }, // anulada
    ];
    const result = aggregateEntityBalance(entries, "UNIFIED");
    if (result.mode === "UNIFIED") {
      expect(result.amount).toBeCloseTo(1000);
    }
  });
});

// ---------------------------------------------------------------------------
// 3. aggregateEntityBalance — modo BREAKDOWN con múltiples ventas
// ---------------------------------------------------------------------------

describe("aggregateEntityBalance (BREAKDOWN)", () => {
  it("acumula gramos puros de múltiples ventas del mismo metal", () => {
    const snap1 = buildBalanceBreakdownFromPrice(makeBreakdown({
      metal: { items: [{ metalId: "metal-gold", variantId: "v1", gramsOriginal: 10, purity: 0.75, gramsPure: 7.5, unitValue: 5000, totalValue: 37500 }], total: 37500 },
      totals: { metal: 37500, hechura: 3000, unified: 40500 },
    }));
    const snap2 = buildBalanceBreakdownFromPrice(makeBreakdown({
      metal: { items: [{ metalId: "metal-gold", variantId: "v1", gramsOriginal: 5, purity: 0.75, gramsPure: 3.75, unitValue: 5000, totalValue: 18750 }], total: 18750 },
      totals: { metal: 18750, hechura: 1500, unified: 20250 },
    }));

    const entries = [
      { amount: { toString: () => "0" }, voidedAt: null, breakdownSnapshot: snap1 },
      { amount: { toString: () => "0" }, voidedAt: null, breakdownSnapshot: snap2 },
    ];
    const result = aggregateEntityBalance(entries, "BREAKDOWN");
    expect(result.mode).toBe("BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      const gold = result.metals.find(m => m.metalId === "metal-gold");
      expect(gold?.gramsPure).toBeCloseTo(11.25); // 7.5 + 3.75
      expect(result.hechura.byCurrency["BASE"] ?? 0).toBeCloseTo(4500); // 3000 + 1500
    }
  });

  it("acumula gramos de múltiples metales por separado", () => {
    const snap = buildBalanceBreakdownFromPrice({
      mode: "COST_LINES",
      metal: {
        items: [
          { metalId: "metal-gold",   variantId: "v-gold",   gramsOriginal: 10, purity: 0.75, gramsPure: 7.5,   unitValue: 5000, totalValue: 37500 },
          { metalId: "metal-silver", variantId: "v-silver", gramsOriginal: 20, purity: 0.925, gramsPure: 18.5, unitValue: 100,  totalValue: 1850  },
        ],
        total: 39350,
      },
      hechura: { base: 2000, adjustments: [], total: 2000 },
      totals: { metal: 39350, hechura: 2000, unified: 41350 },
    });
    const entries = [
      { amount: { toString: () => "0" }, voidedAt: null, breakdownSnapshot: snap },
    ];
    const result = aggregateEntityBalance(entries, "BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      const gold   = result.metals.find(m => m.metalId === "metal-gold");
      const silver = result.metals.find(m => m.metalId === "metal-silver");
      expect(gold?.gramsPure).toBeCloseTo(7.5);
      expect(silver?.gramsPure).toBeCloseTo(18.5);
    }
  });

  it("solo hechura — sin metales", () => {
    const snap = buildBalanceBreakdownFromPrice({
      mode: "MANUAL",
      metal: { items: [], total: 0 },
      hechura: { base: 5000, adjustments: [], total: 5000 },
      totals: { metal: 0, hechura: 5000, unified: 5000 },
    });
    const entries = [
      { amount: { toString: () => "0" }, voidedAt: null, breakdownSnapshot: snap },
    ];
    const result = aggregateEntityBalance(entries, "BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      expect(result.metals).toHaveLength(0);
      expect(result.hechura.byCurrency["BASE"] ?? 0).toBeCloseTo(5000);
    }
  });

  it("mezcla de UNIFIED y BREAKDOWN — UNIFIED se acumula como hechura", () => {
    const snap = buildBalanceBreakdownFromPrice(makeBreakdown());
    const entries = [
      { amount: { toString: () => "0" },       voidedAt: null, breakdownSnapshot: snap },
      { amount: { toString: () => "1000.00" },  voidedAt: null, breakdownSnapshot: null }, // UNIFIED legacy
    ];
    const result = aggregateEntityBalance(entries, "BREAKDOWN");
    if (result.mode === "BREAKDOWN") {
      const gold = result.metals.find(m => m.metalId === "metal-gold");
      expect(gold?.gramsPure).toBeCloseTo(7.5);
      expect(result.hechura.byCurrency["BASE"] ?? 0).toBeCloseTo(4000); // 3000 breakdown + 1000 unified
    }
  });
});
