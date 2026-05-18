// src/lib/pricing-engine/__tests__/metal-cost-base.test.ts
// =============================================================================
// FASE F3 — lineCostBase y metalCostBase (costo del metal SIN merma).
//
// Fórmula:
//   lineCostBase[i] = appliedGrams[i] × quotePrice[i]
//   metalCostBase   = Σ lineCostBase[i]
//
// Reglas:
//   1) Si todas las líneas METAL tienen `appliedGrams` y `quotePrice` → suma.
//   2) Si alguna línea no tiene `quotePrice` (snapshot legacy) → null.
//   3) `lineCost` (con merma) sigue intacto: no se toca el cálculo existente.
// =============================================================================

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Prisma } from "@prisma/client";

const mockPrisma = vi.hoisted(() => ({
  currency:     { findFirst:  vi.fn() },
  currencyRate: { findFirst:  vi.fn() },
  metalQuote:   { findFirst:  vi.fn(), findMany: vi.fn() },
  metalVariant: { findMany:   vi.fn() },
  jewelry:      { findUnique: vi.fn() },
}));

vi.mock("../../prisma.js", () => ({ prisma: mockPrisma }));

import { calculateCostFromLines } from "../pricing-engine.cost.js";
import { extractCompositionMetals } from "../../pricing-composition.js";

beforeEach(() => {
  mockPrisma.currency.findFirst.mockResolvedValue({ id: "ARS" });
  mockPrisma.metalVariant.findMany.mockResolvedValue([
    { id: "v1", saleFactor: new Prisma.Decimal("1") },
    { id: "v2", saleFactor: new Prisma.Decimal("1") },
  ]);
  mockPrisma.metalQuote.findMany.mockResolvedValue([
    { variantId: "v1", price: new Prisma.Decimal("120") },
    { variantId: "v2", price: new Prisma.Decimal("80") },
  ]);
});

describe("FASE F3 — lineCostBase y metalCostBase", () => {
  it("emite lineCostBase = appliedGrams × quotePrice (sin merma)", async () => {
    const lines = [
      { id: "cl-m1", type: "METAL", quantity: "1.5", unitValue: "0", currencyId: null, mermaPercent: "10", metalVariantId: "v1" },
    ];
    const res = await calculateCostFromLines("j1", lines as any);
    const items = extractCompositionMetals(res.steps);
    // appliedGrams = 1.5, quotePrice = 120, merma = 10% → lineCost = 1.5×1.10×120 = 198
    // lineCostBase = 1.5 × 120 = 180 (SIN merma)
    expect(items[0].appliedGrams).toBeCloseTo(1.5);
    expect(items[0].appliedMermaPct).toBeCloseTo(10);
    expect(items[0].quotePrice).toBeCloseTo(120);
    expect(items[0].lineCost).toBeCloseTo(198);
    expect(items[0].lineCostBase).toBeCloseTo(180);
  });

  it("merma=0 → lineCostBase === lineCost", async () => {
    const lines = [
      { id: "cl-m1", type: "METAL", quantity: "2", unitValue: "0", currencyId: null, mermaPercent: "0", metalVariantId: "v1" },
    ];
    const res = await calculateCostFromLines("j1", lines as any);
    const items = extractCompositionMetals(res.steps);
    expect(items[0].lineCost).toBeCloseTo(240);
    expect(items[0].lineCostBase).toBeCloseTo(240);
  });

  it("snapshot legacy sin quotePrice en step → lineCostBase = null", () => {
    // Simulamos directamente un step "viejo" (sin meta.quotePrice).
    const steps = [
      {
        key: "COST_LINES_METAL",
        status: "ok" as const,
        label: "Línea de metal",
        value: 100,
        meta: { variantId: "v1", qty: "1", merma: 5 /* sin quotePrice */ },
      },
    ];
    const items = extractCompositionMetals(steps as any);
    expect(items[0].quotePrice).toBeNull();
    expect(items[0].lineCostBase).toBeNull();
  });

  it("múltiples líneas METAL → suma de lineCostBase es metalCostBase implícito", async () => {
    const lines = [
      { id: "cl-m1", type: "METAL", quantity: "1", unitValue: "0", currencyId: null, mermaPercent: "10", metalVariantId: "v1" },
      { id: "cl-m2", type: "METAL", quantity: "2", unitValue: "0", currencyId: null, mermaPercent: "5",  metalVariantId: "v2" },
    ];
    const res = await calculateCostFromLines("j1", lines as any);
    const items = extractCompositionMetals(res.steps);
    // v1: 1 × 120 = 120 (base) ; 1 × 1.10 × 120 = 132 (con merma)
    // v2: 2 × 80  = 160 (base) ; 2 × 1.05 × 80  = 168 (con merma)
    expect(items[0].lineCostBase).toBeCloseTo(120);
    expect(items[1].lineCostBase).toBeCloseTo(160);
    const sumBase = items.reduce((s, it) => s + (it.lineCostBase ?? 0), 0);
    expect(sumBase).toBeCloseTo(280);
    const sumCost = items.reduce((s, it) => s + (it.lineCost ?? 0), 0);
    expect(sumCost).toBeCloseTo(300);
  });
});
