import { describe, it, expect } from "vitest";
import { calculateLineCommission } from "../seller-commission.js";
import type { LineCommissionInput } from "../seller-commission.js";

const baseBreakdown = {
  mode: "METAL_MERMA_HECHURA",
  metal:   { items: [], total: 500 },
  hechura: { base: 200, adjustments: [], total: 200 },
  totals:  { metal: 500, hechura: 200, unified: 700 },
} as any;

function input(overrides: Partial<LineCommissionInput>): LineCommissionInput {
  return {
    commissionType:    "PERCENTAGE",
    commissionValue:   10,
    commissionBase:    "TOTAL",
    lineTotal:         1000,
    breakdownSnapshot: baseBreakdown,
    quantity:          1,
    ...overrides,
  };
}

describe("calculateLineCommission", () => {
  it("NONE → amount 0, base null", () => {
    const r = calculateLineCommission(input({ commissionType: "NONE" }));
    expect(r.amount).toBe(0);
    expect(r.base).toBeNull();
  });

  it("FIXED_AMOUNT → amount 0 per line, base null", () => {
    const r = calculateLineCommission(input({ commissionType: "FIXED_AMOUNT", commissionValue: 500 }));
    expect(r.amount).toBe(0);
    expect(r.base).toBeNull();
  });

  it("PERCENTAGE + TOTAL: 10% de 1000 = 100", () => {
    const r = calculateLineCommission(input({ commissionBase: "TOTAL", lineTotal: 1000 }));
    expect(r.base).toBe(1000);
    expect(r.amount).toBe(100);
  });

  it("PERCENTAGE + METAL: 10% de metal(500) × qty(2) = 100", () => {
    const r = calculateLineCommission(input({ commissionBase: "METAL", quantity: 2, lineTotal: 2000 }));
    expect(r.base).toBe(1000); // 500 * 2
    expect(r.amount).toBe(100);
  });

  it("PERCENTAGE + HECHURA: 10% de hechura(200) × qty(3) = 60", () => {
    const r = calculateLineCommission(input({ commissionBase: "HECHURA", quantity: 3, lineTotal: 3000 }));
    expect(r.base).toBe(600); // 200 * 3
    expect(r.amount).toBe(60);
  });

  it("PERCENTAGE + METAL_Y_HECHURA: 10% de (500+200) × qty(1) = 70", () => {
    const r = calculateLineCommission(input({ commissionBase: "METAL_Y_HECHURA", quantity: 1 }));
    expect(r.base).toBe(700);
    expect(r.amount).toBe(70);
  });

  it("Sin breakdown → METAL base = 0, amount = 0", () => {
    const r = calculateLineCommission(input({ commissionBase: "METAL", breakdownSnapshot: null }));
    expect(r.base).toBe(0);
    expect(r.amount).toBe(0);
  });

  it("commissionValue null → amount 0", () => {
    const r = calculateLineCommission(input({ commissionValue: null }));
    expect(r.amount).toBe(0);
    expect(r.base).toBeNull();
  });

  it("Redondeo: 10% de 33.33 = 3.33", () => {
    const r = calculateLineCommission(input({ commissionBase: "TOTAL", lineTotal: 33.33 }));
    expect(r.base).toBe(33.33);
    expect(r.amount).toBe(3.33);
  });

  // ── TOTAL_AFTER_DISCOUNTS ──────────────────────────────────────────────────
  it("TOTAL_AFTER_DISCOUNTS sin factor (factor=1): igual que TOTAL", () => {
    const r = calculateLineCommission(input({ commissionBase: "TOTAL_AFTER_DISCOUNTS", lineDiscountFactor: 1 }));
    expect(r.base).toBe(1000);
    expect(r.amount).toBe(100);
  });

  it("TOTAL_AFTER_DISCOUNTS con cupón 10% (factor=0.9): 10% de 900 = 90", () => {
    const r = calculateLineCommission(input({ commissionBase: "TOTAL_AFTER_DISCOUNTS", lineTotal: 1000, lineDiscountFactor: 0.9 }));
    expect(r.base).toBe(900);
    expect(r.amount).toBe(90);
  });

  it("TOTAL_AFTER_DISCOUNTS factor default 1 cuando no se pasa", () => {
    const r = calculateLineCommission(input({ commissionBase: "TOTAL_AFTER_DISCOUNTS" }));
    expect(r.base).toBe(1000);
    expect(r.amount).toBe(100);
  });

  // ── HECHURA_AFTER_DISCOUNTS ────────────────────────────────────────────────
  it("HECHURA_AFTER_DISCOUNTS con cupón 20% (factor=0.8): 10% de hechura(200)×0.8 = 16", () => {
    const r = calculateLineCommission(input({ commissionBase: "HECHURA_AFTER_DISCOUNTS", quantity: 1, lineDiscountFactor: 0.8 }));
    expect(r.base).toBe(160); // 200 * 0.8
    expect(r.amount).toBe(16);
  });

  it("HECHURA_AFTER_DISCOUNTS sin breakdown → base 0, amount 0", () => {
    const r = calculateLineCommission(input({ commissionBase: "HECHURA_AFTER_DISCOUNTS", breakdownSnapshot: null, lineDiscountFactor: 0.9 }));
    expect(r.base).toBe(0);
    expect(r.amount).toBe(0);
  });

  // ── TOTAL_AFTER_PAYMENT ────────────────────────────────────────────────────
  it("TOTAL_AFTER_PAYMENT sin factor (provisional = TOTAL_AFTER_DISCOUNTS): 10% de 1000 = 100", () => {
    const r = calculateLineCommission(input({ commissionBase: "TOTAL_AFTER_PAYMENT" }));
    expect(r.base).toBe(1000);
    expect(r.amount).toBe(100);
  });

  it("TOTAL_AFTER_PAYMENT con factor canal+cupón 0.9: 10% de 900 = 90", () => {
    const r = calculateLineCommission(input({ commissionBase: "TOTAL_AFTER_PAYMENT", lineTotal: 1000, lineDiscountFactor: 0.9 }));
    expect(r.base).toBe(900);
    expect(r.amount).toBe(90);
  });

  it("TOTAL_AFTER_PAYMENT con recargo de pago 5% (factor=1.05): 10% de 1050 = 105", () => {
    const r = calculateLineCommission(input({ commissionBase: "TOTAL_AFTER_PAYMENT", lineTotal: 1000, lineDiscountFactor: 1.05 }));
    expect(r.base).toBe(1050);
    expect(r.amount).toBe(105);
  });

  it("HECHURA_AFTER_DISCOUNTS factor default 1: igual que HECHURA", () => {
    const r = calculateLineCommission(input({ commissionBase: "HECHURA_AFTER_DISCOUNTS" }));
    expect(r.base).toBe(200);
    expect(r.amount).toBe(20);
  });
});
